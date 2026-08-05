#!/usr/bin/env python3
"""以只读方式审计《知势》数据资产的质量与时间语义。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


AUDIT_VERSION = "1.0"
RULE_VERSION = "dq-rules-1.0"
CURRENT_TARGETS = ("BTC", "ETH")
ALLOWED_ROOTS = (
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
)
DISCOVERY_ALLOWED_ROOTS = ALLOWED_ROOTS + ("/var/lib/mysql",)
SUPPORTED_FILE_FORMATS = {"CSV", "JSONL", "NDJSON", "SQLite"}
INVENTORY_COLUMNS = (
    "发现批次",
    "资产编号",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
)
QUALITY_COLUMNS = (
    "审计批次",
    "规则版本",
    "规则指纹",
    "清单指纹",
    "资产编号",
    "资产类型",
    "服务或项目",
    "位置",
    "格式",
    "候选标的范围",
    "扫描状态",
    "扫描完整性",
    "记录数",
    "字段数",
    "结构缺失数",
    "结构缺失率",
    "重复状态",
    "精确重复数",
    "事件时间状态",
    "事件时间候选字段",
    "到达时间状态",
    "到达时间候选字段",
    "采集时间状态",
    "采集时间候选字段",
    "延迟状态",
    "乱序状态",
    "实际覆盖范围",
    "可用性结论",
    "依据",
    "限制",
    "解除条件",
    "证据指纹",
)
GAP_COLUMNS = (
    "审计批次",
    "规则版本",
    "规则指纹",
    "清单指纹",
    "资产编号",
    "候选标的范围",
    "断档状态",
    "预期频率",
    "事件时间字段",
    "断档数",
    "断档范围",
    "原因",
    "解除条件",
)
ANOMALY_COLUMNS = (
    "审计批次",
    "规则版本",
    "规则指纹",
    "清单指纹",
    "资产编号",
    "候选标的范围",
    "规则编号",
    "异常类型",
    "异常数量",
    "异常比例",
    "严重度",
    "规则状态",
    "证据",
    "处置",
)
SSH_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
ALLOWED_SSH_TARGETS = {"ubuntu"}
ASSET_ID_PATTERN = re.compile(r"^DS-\d{6}$")
MYSQL_LOCATION_PATTERN = re.compile(r"^MySQL/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)$")
IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]+"
)
TOKEN_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", re.IGNORECASE
)
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
TIME_CANDIDATES = {
    "event": {
        "event_time",
        "event_ts",
        "exchange_time",
        "trade_time",
        "open_time",
        "close_time",
        "timestamp",
        "ts",
    },
    "arrival": {
        "arrival_time",
        "arrived_at",
        "received_at",
        "receive_time",
        "ingestion_time",
        "ingested_at",
    },
    "collection": {
        "collection_time",
        "collected_at",
        "collected_time",
        "persisted_at",
        "created_at",
    },
}
ERROR_REASONS = {
    "identity_changed_before_scan": "结构阶段与质量阶段之间文件身份变化，未执行内容统计",
    "identity_changed_during_scan": "内容扫描期间文件身份变化，结果不完整",
    "schema_changed_between_phases": "两阶段数据库元数据结构不一致，未形成质量结论",
    "sensitive_system_log_excluded": "敏感系统日志按安全边界排除正文读取",
    "object_timeout": "单对象只读扫描超时",
    "quality_read_failed": "只读质量扫描失败",
    "csv_header_parse_failed": "CSV表头严格解析失败，未执行内容统计",
    "csv_body_parse_failed": "CSV正文严格解析失败，仅保留部分统计且不形成重复结论",
    "mysql_metadata_unavailable": "MySQL元数据不可用",
    "mysql_object_not_found": "MySQL元数据对象未发现",
    "unsupported_format": "格式不在审计支持范围",
}


REMOTE_AUDIT_PROGRAM = textwrap.dedent(
    r'''
    import csv
    import hashlib
    import json
    import math
    import os
    import platform
    import resource
    import re
    import signal
    import sqlite3
    import subprocess
    import sys
    from pathlib import PurePosixPath
    from urllib.parse import quote

    AUDIT_VERSION = "1.0"
    ALLOWED_ROOTS = (
        "/opt/binance-event",
        "/opt/celueqing",
        "/opt/crypto-radar",
        "/opt/event-prob-lab",
        "/opt/orderbook-intelligence-service",
    )
    MYSQL_LOCATION_PATTERN = re.compile(
        r"^MySQL/([A-Za-z0-9_]+)/([A-Za-z0-9_]+)$"
    )
    SAFE_ENV = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent",
        "MYSQL_TEST_LOGIN_FILE": "/nonexistent/.mylogin.cnf",
    }

    class ObjectTimeout(Exception):
        pass

    def timeout_handler(signum, frame):
        del signum, frame
        raise ObjectTimeout()

    def canonical(value):
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )

    def stat_identity(path, include_sqlite_companions=False):
        stat_result = os.lstat(path)
        identity = {
            "size": int(stat_result.st_size),
            "mtime_ns": int(stat_result.st_mtime_ns),
        }
        if include_sqlite_companions:
            companions = {}
            for suffix in ("-wal", "-shm"):
                companion = path + suffix
                try:
                    companion_stat = os.lstat(companion)
                except FileNotFoundError:
                    companions[suffix] = None
                else:
                    companions[suffix] = {
                        "size": int(companion_stat.st_size),
                        "mtime_ns": int(companion_stat.st_mtime_ns),
                    }
            identity["companions"] = companions
        return identity

    def file_identity(path, data_format):
        return stat_identity(path, data_format == "SQLite")

    def validate_file_path(path):
        parsed = PurePosixPath(path)
        if not parsed.is_absolute() or ".." in parsed.parts:
            raise ValueError("path_outside_allowlist")
        normalized = str(parsed)
        if not any(normalized.startswith(root + "/") for root in ALLOWED_ROOTS):
            raise ValueError("path_outside_allowlist")
        if os.path.islink(normalized) or os.path.realpath(normalized) != normalized:
            raise ValueError("symlink_rejected")
        return normalized

    def open_sqlite_read_only(path):
        uri = "file:" + quote(path, safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only=ON")
        return connection

    def quoted(identifier):
        return '"' + identifier.replace('"', '""') + '"'

    def base_object(unit):
        return {
            "asset_id": unit["asset_id"],
            "status": "无法判定",
            "fields": [],
            "types": {},
            "primary_key": [],
            "identity": {},
        }

    def schema_csv(path, result):
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                fields = next(reader)
            except StopIteration:
                fields = []
        result.update(
            status="已发现结构",
            fields=[str(field) for field in fields],
            types={str(field): "文本或未声明" for field in fields},
        )

    def schema_jsonl(path, result):
        fields = set()
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except (TypeError, ValueError):
                    continue
                if isinstance(value, dict):
                    fields.update(str(field) for field in value)
        result.update(
            status="已发现结构",
            fields=sorted(fields),
            types={field: "JSON动态类型" for field in sorted(fields)},
        )

    def schema_sqlite(path, result):
        connection = open_sqlite_read_only(path)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            fields = []
            types = {}
            primary_key = []
            for (table,) in tables:
                columns = connection.execute(
                    "PRAGMA table_info(" + quoted(str(table)) + ")"
                ).fetchall()
                for column in columns:
                    field = str(table) + "." + str(column[1])
                    fields.append(field)
                    types[field] = str(column[2] or "未声明")
                ordered_primary = sorted(
                    (column for column in columns if int(column[5])),
                    key=lambda column: int(column[5]),
                )
                primary_key.extend(
                    str(table) + "." + str(column[1])
                    for column in ordered_primary
                )
            result.update(
                status="已发现结构",
                fields=fields,
                types=types,
                primary_key=primary_key,
            )
        finally:
            connection.close()

    def inspect_file_schema(unit):
        result = base_object(unit)
        try:
            path = validate_file_path(unit["location"])
            result["identity"] = file_identity(path, unit["format"])
            data_format = unit["format"]
            if data_format == "CSV":
                schema_csv(path, result)
            elif data_format in ("JSONL", "NDJSON"):
                schema_jsonl(path, result)
            elif data_format == "SQLite":
                schema_sqlite(path, result)
            else:
                result.update(status="无法判定", error_code="unsupported_format")
        except ObjectTimeout:
            result.update(status="无法判定", error_code="object_timeout")
        except (OSError, ValueError, sqlite3.Error, csv.Error):
            result.update(status="无法判定", error_code="schema_read_failed")
        return result

    def mysql_metadata(units, object_timeout):
        results = {unit["asset_id"]: base_object(unit) for unit in units}
        locations = []
        by_location = {}
        for unit in units:
            match = MYSQL_LOCATION_PATTERN.fullmatch(unit["location"])
            if match is None:
                results[unit["asset_id"]]["error_code"] = "invalid_mysql_location"
                continue
            location = (match.group(1), match.group(2))
            locations.append(location)
            by_location[location] = unit["asset_id"]
        if not locations:
            return list(results.values())
        conditions = [
            "(C.TABLE_SCHEMA='" + database + "' AND C.TABLE_NAME='" + table + "')"
            for database, table in sorted(set(locations))
        ]
        query = (
            "SELECT C.TABLE_SCHEMA,C.TABLE_NAME,C.COLUMN_NAME,C.COLUMN_TYPE,"
            "C.COLUMN_KEY,C.ORDINAL_POSITION,T.TABLE_ROWS "
            "FROM information_schema.COLUMNS C JOIN information_schema.TABLES T "
            "ON C.TABLE_SCHEMA=T.TABLE_SCHEMA AND C.TABLE_NAME=T.TABLE_NAME WHERE "
            + " OR ".join(conditions)
            + " ORDER BY C.TABLE_SCHEMA,C.TABLE_NAME,C.ORDINAL_POSITION"
        )
        completed = subprocess.run(
            [
                "mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names",
                "--execute", query,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=object_timeout,
            env=SAFE_ENV,
        )
        if completed.returncode != 0:
            for result in results.values():
                result.update(status="无法判定", error_code="mysql_metadata_unavailable")
            return list(results.values())
        for line in completed.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 7:
                continue
            database, table, column, column_type, column_key, _, table_rows = parts
            asset_id = by_location.get((database, table))
            if asset_id is None:
                continue
            result = results[asset_id]
            result["status"] = "已发现结构"
            result["fields"].append(column)
            result["types"][column] = column_type
            if column_key == "PRI":
                result["primary_key"].append(column)
            result["row_estimate"] = table_rows if table_rows != "NULL" else "无法判定"
        for result in results.values():
            if result["status"] != "已发现结构" and "error_code" not in result:
                result["error_code"] = "mysql_object_not_found"
        return list(results.values())

    def empty_quality(asset_id):
        return {
            "asset_id": asset_id,
            "status": "完成",
            "scan_completeness": "完整",
            "record_count": 0,
            "field_count": 0,
            "missing_count": 0,
            "cell_count": 0,
            "duplicate_status": "已量化（规范记录完全一致）",
            "exact_duplicate_count": 0,
            "row_width_error_count": 0,
            "empty_line_count": 0,
            "invalid_json_count": 0,
            "non_object_count": 0,
            "non_finite_number_count": 0,
            "csv_parse_error_count": 0,
            "fields": [],
            "primary_key": [],
        }

    def mark_not_executed(result, status, error_code):
        result.update(
            status=status,
            scan_completeness="未执行",
            record_count="无法判定",
            field_count="无法判定",
            missing_count="无法判定",
            cell_count="无法判定",
            duplicate_status="无法判定（内容统计未执行）",
            exact_duplicate_count="无法判定",
            row_width_error_count="无法判定",
            empty_line_count="无法判定",
            invalid_json_count="无法判定",
            non_object_count="无法判定",
            non_finite_number_count="无法判定",
            csv_parse_error_count="无法判定",
            coverage="无法判定",
            error_code=error_code,
        )
        return result

    def count_non_finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            return 1
        if isinstance(value, dict):
            return sum(count_non_finite(item) for item in value.values())
        if isinstance(value, list):
            return sum(count_non_finite(item) for item in value)
        return 0

    def quality_csv(path, asset_id, duplicate_limit):
        result = empty_quality(asset_id)
        seen = set()
        duplicate_complete = True
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                fields = next(reader)
            except StopIteration:
                result["status"] = "空文件"
                return result
            except csv.Error:
                mark_not_executed(
                    result, "CSV解析失败", "csv_header_parse_failed"
                )
                result["csv_parse_error_count"] = 1
                return result
            result["fields"] = fields
            result["field_count"] = len(fields)
            try:
                for row in reader:
                    result["record_count"] += 1
                    if len(row) != len(fields):
                        result["row_width_error_count"] += 1
                    normalized = row[:len(fields)] + [""] * max(0, len(fields) - len(row))
                    result["missing_count"] += sum(
                        1 for value in normalized if not value.strip()
                    )
                    if duplicate_complete:
                        digest = hashlib.sha256(canonical(row).encode("utf-8")).digest()
                        if digest in seen:
                            result["exact_duplicate_count"] += 1
                        elif len(seen) < duplicate_limit:
                            seen.add(digest)
                        else:
                            duplicate_complete = False
            except csv.Error:
                result.update(
                    status="CSV解析失败",
                    scan_completeness="未完整",
                    csv_parse_error_count=1,
                    duplicate_status="无法判定（CSV扫描未完整）",
                    exact_duplicate_count="无法判定",
                    coverage="部分范围，无法判定",
                    error_code="csv_body_parse_failed",
                )
            result["cell_count"] = result["record_count"] * result["field_count"]
        if not duplicate_complete:
            result["duplicate_status"] = "无法判定（超过重复集合上限）"
            result["exact_duplicate_count"] = "无法判定"
        return result

    def quality_jsonl(path, asset_id, duplicate_limit):
        result = empty_quality(asset_id)
        seen = set()
        duplicate_complete = True
        fields = set()
        missing_by_field = {}
        object_count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    result["empty_line_count"] += 1
                    continue
                try:
                    value = json.loads(line)
                except (TypeError, ValueError):
                    result["invalid_json_count"] += 1
                    continue
                if not isinstance(value, dict):
                    result["non_object_count"] += 1
                    continue
                current = {str(field) for field in value}
                for field in current - fields:
                    missing_by_field[field] = object_count
                fields.update(current)
                for field in fields:
                    if field not in value or value[field] is None or (
                        isinstance(value[field], str) and not value[field].strip()
                    ):
                        missing_by_field[field] += 1
                object_count += 1
                result["record_count"] = object_count
                result["non_finite_number_count"] += count_non_finite(value)
                if duplicate_complete:
                    digest = hashlib.sha256(canonical(value).encode("utf-8")).digest()
                    if digest in seen:
                        result["exact_duplicate_count"] += 1
                    elif len(seen) < duplicate_limit:
                        seen.add(digest)
                    else:
                        duplicate_complete = False
        result["fields"] = sorted(fields)
        result["field_count"] = len(fields)
        result["cell_count"] = result["record_count"] * result["field_count"]
        result["missing_count"] = sum(missing_by_field.values())
        if not duplicate_complete:
            result["duplicate_status"] = "无法判定（超过重复集合上限）"
            result["exact_duplicate_count"] = "无法判定"
        return result

    def quality_sqlite(path, asset_id):
        result = empty_quality(asset_id)
        connection = open_sqlite_read_only(path)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            duplicate_proven = True
            for (table,) in tables:
                columns = connection.execute(
                    "PRAGMA table_info(" + quoted(str(table)) + ")"
                ).fetchall()
                names = [str(column[1]) for column in columns]
                result["fields"].extend(str(table) + "." + name for name in names)
                primary = sorted(
                    (column for column in columns if int(column[5])),
                    key=lambda column: int(column[5]),
                )
                result["primary_key"].extend(
                    str(table) + "." + str(column[1]) for column in primary
                )
                if not primary:
                    duplicate_proven = False
                if not names:
                    continue
                expressions = ["COUNT(*)"] + [
                    "SUM(CASE WHEN " + quoted(name) + " IS NULL OR (typeof("
                    + quoted(name) + ")='text' AND trim(" + quoted(name)
                    + ")='') THEN 1 ELSE 0 END)" for name in names
                ]
                values = connection.execute(
                    "SELECT " + ", ".join(expressions) + " FROM " + quoted(str(table))
                ).fetchone()
                if values:
                    table_record_count = int(values[0] or 0)
                    result["record_count"] += table_record_count
                    result["cell_count"] += table_record_count * len(names)
                    result["missing_count"] += sum(int(value or 0) for value in values[1:])
            result["field_count"] = len(result["fields"])
            if duplicate_proven:
                result["duplicate_status"] = "已量化（SQLite声明主键）"
            else:
                result["duplicate_status"] = "无法判定（部分表未声明主键）"
                result["exact_duplicate_count"] = "无法判定"
            return result
        finally:
            connection.close()

    def inspect_file_quality(unit, rule, duplicate_limit):
        asset_id = unit["asset_id"]
        result = empty_quality(asset_id)
        try:
            path = validate_file_path(unit["location"])
            before = file_identity(path, unit["format"])
            if rule.get("identity") and before != rule["identity"]:
                return mark_not_executed(
                    result, "输入漂移", "identity_changed_before_scan"
                )
            if unit["format"] == "CSV":
                result = quality_csv(path, asset_id, duplicate_limit)
            elif unit["format"] in ("JSONL", "NDJSON"):
                result = quality_jsonl(path, asset_id, duplicate_limit)
            elif unit["format"] == "SQLite":
                result = quality_sqlite(path, asset_id)
            else:
                return mark_not_executed(result, "无法判定", "unsupported_format")
            after = file_identity(path, unit["format"])
            if before != after:
                result.update(
                    status="输入漂移",
                    scan_completeness="未完整",
                    duplicate_status="无法判定（扫描期间输入漂移）",
                    exact_duplicate_count="无法判定",
                    error_code="identity_changed_during_scan",
                )
            result["identity_before"] = before
            result["identity_after"] = after
            return result
        except ObjectTimeout:
            return mark_not_executed(result, "超时", "object_timeout")
        except (OSError, ValueError, sqlite3.Error, csv.Error):
            return mark_not_executed(result, "无法判定", "quality_read_failed")
        return result

    def schema_fingerprint(schema):
        contract = {
            "status": schema.get("status", "无法判定"),
            "fields": sorted(str(field) for field in schema.get("fields", [])),
            "types": {
                str(key): str(value)
                for key, value in sorted(schema.get("types", {}).items())
            },
            "primary_key": sorted(
                str(field) for field in schema.get("primary_key", [])
            ),
        }
        return hashlib.sha256(canonical(contract).encode("utf-8")).hexdigest()

    def quality_mysql(schema_results, rules):
        converted = []
        for schema in schema_results:
            result = empty_quality(schema["asset_id"])
            result.update(
                status="仅元数据",
                scan_completeness="元数据范围",
                record_count=schema.get("row_estimate", "无法判定"),
                field_count=len(schema.get("fields", [])),
                missing_count="无法判定",
                duplicate_status="无法判定（未读取业务记录）",
                exact_duplicate_count="无法判定",
                fields=schema.get("fields", []),
                primary_key=schema.get("primary_key", []),
            )
            rule = rules.get(schema["asset_id"], {})
            if rule.get("schema_fingerprint") != schema_fingerprint(schema):
                mark_not_executed(
                    result, "输入漂移", "schema_changed_between_phases"
                )
            if schema.get("status") != "已发现结构":
                mark_not_executed(
                    result,
                    "无法判定",
                    schema.get("error_code", "mysql_metadata_unavailable"),
                )
            converted.append(result)
        return converted

    def excluded_result(unit, phase):
        if phase == "schema":
            result = base_object(unit)
            result.update(
                status="未执行",
                error_code="sensitive_system_log_excluded",
            )
            return result
        result = empty_quality(unit["asset_id"])
        mark_not_executed(
            result, "未执行", "sensitive_system_log_excluded"
        )
        result["duplicate_status"] = "无法判定（敏感系统日志排除）"
        return result

    def main():
        try:
            if "REMOTE_REQUEST_JSON" in globals():
                request = json.loads(REMOTE_REQUEST_JSON)
            else:
                request = json.load(sys.stdin)
            if request.get("audit_version") != AUDIT_VERSION:
                raise ValueError("version")
            phase = request.get("phase")
            if phase not in ("schema", "quality"):
                raise ValueError("phase")
            units = request.get("objects")
            if not isinstance(units, list):
                raise ValueError("objects")
            duplicate_limit = int(request.get("duplicate_limit", 500000))
            object_timeout = int(request.get("object_timeout", 90))
            memory_limit_bytes = int(request.get("memory_limit_bytes") or 0)
            if memory_limit_bytes:
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (memory_limit_bytes, memory_limit_bytes),
                )
            signal.signal(signal.SIGALRM, timeout_handler)
            excluded = [unit for unit in units if unit.get("excluded_reason")]
            files = [
                unit for unit in units
                if unit.get("asset_type") == "候选数据文件"
                and not unit.get("excluded_reason")
            ]
            databases = [unit for unit in units if unit.get("asset_type") == "数据库元数据"]
            results = [excluded_result(unit, phase) for unit in excluded]
            if phase == "schema":
                for unit in files:
                    print("audit:" + str(unit.get("asset_id", "unknown")), file=sys.stderr)
                    signal.alarm(object_timeout)
                    try:
                        results.append(inspect_file_schema(unit))
                    finally:
                        signal.alarm(0)
                results.extend(mysql_metadata(databases, object_timeout))
            else:
                rules = {
                    item["asset_id"]: item for item in request.get("rules", {}).get("objects", [])
                }
                for unit in files:
                    print("audit:" + str(unit.get("asset_id", "unknown")), file=sys.stderr)
                    signal.alarm(object_timeout)
                    try:
                        results.append(
                            inspect_file_quality(
                                unit, rules.get(unit["asset_id"], {}), duplicate_limit
                            )
                        )
                    finally:
                        signal.alarm(0)
                results.extend(quality_mysql(mysql_metadata(databases, object_timeout), rules))
            payload = {
                "audit_version": AUDIT_VERSION,
                "phase": phase,
                "runtime": {
                    "python": platform.python_version(),
                    "platform": platform.system() + "-" + platform.machine(),
                },
                "objects": sorted(results, key=lambda item: item["asset_id"]),
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True)
        except Exception as error:
            print("remote_audit_failed:" + type(error).__name__, file=sys.stderr)
            raise SystemExit(2)

    if __name__ == "__main__":
        main()
    '''
)


def redact(value: object) -> str:
    """移除交付物中不应出现的地址与凭据模式。"""

    text = str(value)
    text = PRIVATE_KEY_PATTERN.sub("[已脱敏私钥]", text)
    text = TOKEN_PATTERN.sub("[已脱敏令牌]", text)
    text = CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}=[已脱敏]", text)
    return IPV4_PATTERN.sub("[已脱敏地址]", text)


def safe_csv_cell(value: object) -> str:
    text = redact(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def validate_ssh_target(target: str) -> str:
    if not target or not SSH_TARGET_PATTERN.fullmatch(target):
        raise ValueError("SSH目标别名不安全")
    if target not in ALLOWED_SSH_TARGETS:
        raise ValueError("SSH目标不在任务固定白名单")
    return target


def inventory_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_inventory(path: Path) -> list[dict[str, str]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("资产清单必须是普通文件")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INVENTORY_COLUMNS:
            raise ValueError("资产清单列与任务-000003合同不一致")
        rows = [{key: value or "" for key, value in row.items()} for row in reader]
    if not rows:
        raise ValueError("资产清单为空")
    batches = {row["发现批次"] for row in rows}
    if len(batches) != 1 or "" in batches:
        raise ValueError("资产清单发现批次不唯一")
    ids = [row["资产编号"] for row in rows]
    if len(ids) != len(set(ids)) or any(not ASSET_ID_PATTERN.fullmatch(item) for item in ids):
        raise ValueError("资产编号重复或非法")
    return sorted(rows, key=lambda row: row["资产编号"])


def _validate_file_location(location: str) -> str:
    path = PurePosixPath(location)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("候选文件路径不在白名单")
    normalized = str(path)
    if not any(normalized.startswith(root + "/") for root in DISCOVERY_ALLOWED_ROOTS):
        raise ValueError("候选文件路径不在白名单")
    return normalized


def build_validation_units(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    units = []
    for row in rows:
        asset_type = row["资产类型"]
        if asset_type == "候选数据文件":
            if row["格式"] not in SUPPORTED_FILE_FORMATS:
                raise ValueError(f"不支持的候选文件格式：{row['格式']}")
            location = _validate_file_location(row["位置"])
            exclusion = ""
            if location.startswith("/var/lib/mysql/"):
                exclusion = "MySQL系统日志可能包含敏感查询文本，仅保留覆盖记录，不读取内容"
            units.append({**row, "位置": location, "审计排除原因": exclusion})
        elif asset_type == "数据库元数据":
            if row["格式"] != "InnoDB" or not MYSQL_LOCATION_PATTERN.fullmatch(row["位置"]):
                raise ValueError("数据库元数据位置或格式非法")
            units.append(dict(row))
    return sorted(units, key=lambda row: row["资产编号"])


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _time_candidates(fields: Iterable[str], kind: str) -> list[str]:
    aliases = TIME_CANDIDATES[kind]
    return sorted(
        field
        for field in fields
        if field.strip().lower().rsplit(".", 1)[-1] in aliases
    )


def _schema_contract(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "status": str(item.get("status", "无法判定")),
        "fields": sorted(str(field) for field in item.get("fields", [])),
        "types": {
            str(key): str(value)
            for key, value in sorted(dict(item.get("types", {})).items())
        },
        "primary_key": sorted(str(field) for field in item.get("primary_key", [])),
    }


def freeze_rules(schema_payload: Mapping[str, object]) -> tuple[dict[str, object], str]:
    if schema_payload.get("audit_version", AUDIT_VERSION) != AUDIT_VERSION:
        raise ValueError("结构探针版本不一致")
    objects = schema_payload.get("objects")
    if not isinstance(objects, list):
        raise ValueError("结构探针objects必须是列表")
    frozen_objects = []
    seen = set()
    for item in sorted(objects, key=lambda value: str(value.get("asset_id", ""))):
        if not isinstance(item, dict):
            raise ValueError("结构探针对象非法")
        asset_id = str(item.get("asset_id", ""))
        if not ASSET_ID_PATTERN.fullmatch(asset_id) or asset_id in seen:
            raise ValueError("结构探针资产编号重复或非法")
        seen.add(asset_id)
        fields = sorted({str(field) for field in item.get("fields", [])})
        frozen_objects.append(
            {
                "asset_id": asset_id,
                "schema_status": str(item.get("status", "无法判定")),
                "identity": dict(item.get("identity", {})),
                "schema_fingerprint": _fingerprint(_schema_contract(item)),
                "primary_key": sorted(str(field) for field in item.get("primary_key", [])),
                "event_time_status": "无法判定",
                "event_time_candidates": _time_candidates(fields, "event"),
                "arrival_time_status": "无法判定",
                "arrival_time_candidates": _time_candidates(fields, "arrival"),
                "collection_time_status": "无法判定",
                "collection_time_candidates": _time_candidates(fields, "collection"),
                "gap_status": "无法判定",
                "expected_frequency": "未提供正式频率合同",
                "anomaly_scope": "仅结构异常；未设置业务数值阈值",
            }
        )
    rules = {"rule_version": RULE_VERSION, "objects": frozen_objects}
    return rules, _fingerprint(rules)


def _remote_units(units: list[dict[str, str]]) -> list[dict[str, str]]:
    payload = []
    for unit in units:
        payload.append(
            {
                "asset_id": unit["资产编号"],
                "asset_type": unit["资产类型"],
                "location": unit["位置"],
                "format": unit["格式"],
                "inventory_size": unit["字节数"],
                "inventory_modified_at": unit["最后修改时间"],
                "excluded_reason": unit.get("审计排除原因", ""),
            }
        )
    return payload


def validate_remote_payload(
    payload: object,
    phase: str,
    units: list[dict[str, str]],
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("远端结果不是对象")
    if payload.get("audit_version") != AUDIT_VERSION or payload.get("phase") != phase:
        raise ValueError("远端结果版本或阶段不一致")
    objects = payload.get("objects")
    if not isinstance(objects, list) or any(not isinstance(item, dict) for item in objects):
        raise ValueError("远端结果objects非法")
    expected = {unit["资产编号"] for unit in units}
    actual = [str(item.get("asset_id", "")) for item in objects]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError("远端结果未覆盖全部验证单元或包含重复")
    runtime = payload.get("runtime", {})
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "audit_version": AUDIT_VERSION,
        "phase": phase,
        "runtime": {
            "python": redact(runtime.get("python", "未记录")),
            "platform": redact(runtime.get("platform", "未记录")),
        },
        "objects": sorted(objects, key=lambda item: str(item["asset_id"])),
    }


def run_remote_phase(
    target: str,
    phase: str,
    units: list[dict[str, str]],
    rules: Mapping[str, object] | None,
    ssh_bin: str,
    timeout: int,
    member_timeout: int | None = None,
    memory_limit_bytes: int | None = None,
) -> dict[str, object]:
    validate_ssh_target(target)
    if phase not in {"schema", "quality"}:
        raise ValueError("远端审计阶段非法")
    if timeout < 10 or timeout > 7200:
        raise ValueError("远端审计超时必须在10至7200秒之间")
    if member_timeout is None:
        member_timeout = min(300, max(30, timeout // max(1, len(units))))
    if member_timeout < 10 or member_timeout > 300:
        raise ValueError("单成员超时必须在10至300秒之间")
    if memory_limit_bytes is not None and not 64 * 1024 * 1024 <= memory_limit_bytes <= 2 * 1024 * 1024 * 1024:
        raise ValueError("内存上限必须在64MiB至2GiB之间")
    request = {
        "audit_version": AUDIT_VERSION,
        "phase": phase,
        "objects": _remote_units(units),
        "rules": rules,
        "duplicate_limit": 500_000,
        "object_timeout": member_timeout,
        "memory_limit_bytes": memory_limit_bytes,
    }
    command = [
        ssh_bin,
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={min(30, timeout)}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        target,
        "python3",
        "-",
    ]
    remote_input = (
        "REMOTE_REQUEST_JSON = "
        + repr(_canonical_json(request))
        + "\n"
        + REMOTE_AUDIT_PROGRAM
    )
    try:
        completed = subprocess.run(
            command,
            input=remote_input,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("SSH远端审计失败：命令不可用或总体超时") from error
    if completed.returncode != 0:
        category_match = re.search(
            r"remote_audit_failed:([A-Za-z][A-Za-z0-9_]*)", completed.stderr
        )
        category = f"（{category_match.group(1)}）" if category_match else ""
        raise RuntimeError(f"SSH远端审计失败：远端返回非零状态{category}")
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("SSH远端审计失败：返回结构不是合法JSON") from error
    return validate_remote_payload(payload, phase, units)


def _index_by_asset(items: object) -> dict[str, dict[str, object]]:
    if not isinstance(items, list):
        return {}
    return {
        str(item.get("asset_id", "")): item
        for item in items
        if isinstance(item, dict) and item.get("asset_id")
    }


def _ratio(numerator: object, denominator: object) -> str:
    try:
        numerator_value = int(numerator)
        denominator_value = int(denominator)
    except (TypeError, ValueError):
        return "无法判定"
    if denominator_value <= 0:
        return "0.000000"
    return f"{numerator_value / denominator_value:.6f}"


def build_output_rows(
    units: list[dict[str, str]],
    schema_payload: Mapping[str, object],
    quality_payload: Mapping[str, object],
    rules: Mapping[str, object],
    metadata: Mapping[str, object],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    schemas = _index_by_asset(schema_payload.get("objects"))
    results = _index_by_asset(quality_payload.get("objects"))
    rule_items = _index_by_asset(rules.get("objects"))
    quality_rows = []
    gap_rows = []
    anomaly_rows = []
    for unit in sorted(units, key=lambda item: item["资产编号"]):
        asset_id = unit["资产编号"]
        schema = schemas.get(asset_id, {})
        result = results.get(asset_id, {})
        rule = rule_items.get(asset_id, {})
        record_count = result.get("record_count", "无法判定")
        field_count = result.get("field_count", len(schema.get("fields", [])))
        missing_count = result.get("missing_count", "无法判定")
        denominator = result.get("cell_count", "无法判定")
        evidence = _fingerprint(
            {"schema": schema, "quality": result, "rule": rule}
        )
        limitation = (
            "缺少已证明的标的、市场、三类时间、频率、重放和闭环合同；"
            "本结果不得用于预测性研究或交易许可"
        )
        error_code = str(result.get("error_code", schema.get("error_code", "")))
        status_reason = ERROR_REASONS.get(error_code, "")
        evidence_basis = f"结构与质量证据{evidence}"
        if status_reason:
            evidence_basis += f"；{status_reason}"
        quality_rows.append(
            {
                "审计批次": str(metadata["audit_batch"]),
                "规则版本": RULE_VERSION,
                "规则指纹": str(metadata["rules_fingerprint"]),
                "清单指纹": str(metadata["inventory_fingerprint"]),
                "资产编号": asset_id,
                "资产类型": unit["资产类型"],
                "服务或项目": unit["服务或项目"],
                "位置": unit["位置"],
                "格式": unit["格式"],
                "候选标的范围": unit["标的范围"],
                "扫描状态": str(result.get("status", schema.get("status", "无法判定"))),
                "扫描完整性": str(result.get("scan_completeness", "无法判定")),
                "记录数": str(record_count),
                "字段数": str(field_count),
                "结构缺失数": str(missing_count),
                "结构缺失率": _ratio(missing_count, denominator),
                "重复状态": str(result.get("duplicate_status", "无法判定")),
                "精确重复数": str(result.get("exact_duplicate_count", "无法判定")),
                "事件时间状态": str(rule.get("event_time_status", "无法判定")),
                "事件时间候选字段": "、".join(rule.get("event_time_candidates", [])) or "无",
                "到达时间状态": str(rule.get("arrival_time_status", "无法判定")),
                "到达时间候选字段": "、".join(rule.get("arrival_time_candidates", [])) or "无",
                "采集时间状态": str(rule.get("collection_time_status", "无法判定")),
                "采集时间候选字段": "、".join(rule.get("collection_time_candidates", [])) or "无",
                "延迟状态": "无法判定（缺少已证明的事件时间与到达时间）",
                "乱序状态": "无法判定（缺少已证明的事件时间与排序合同）",
                "实际覆盖范围": str(result.get("coverage", "无法判定")),
                "可用性结论": "无法判定",
                "依据": evidence_basis,
                "限制": limitation,
                "解除条件": "补齐来源、市场、标的、字段、三类时间、频率合同并完成重放与闭环验证",
                "证据指纹": evidence,
            }
        )
        gap_rows.append(
            {
                "审计批次": str(metadata["audit_batch"]),
                "规则版本": RULE_VERSION,
                "规则指纹": str(metadata["rules_fingerprint"]),
                "清单指纹": str(metadata["inventory_fingerprint"]),
                "资产编号": asset_id,
                "候选标的范围": unit["标的范围"],
                "断档状态": str(rule.get("gap_status", "无法判定")),
                "预期频率": str(rule.get("expected_frequency", "未提供正式频率合同")),
                "事件时间字段": "、".join(rule.get("event_time_candidates", [])) or "无已证明字段",
                "断档数": "无法判定",
                "断档范围": "无法判定",
                "原因": "事件时间语义、时区或预期频率未形成可验证合同",
                "解除条件": "冻结事件时间字段、时区、边界规则和预期频率后创建新审计批次",
            }
        )
        scan_completeness = str(result.get("scan_completeness", "无法判定"))
        if scan_completeness == "完整":
            anomaly_count: object = sum(
                int(result.get(key, 0) or 0)
                for key in (
                    "row_width_error_count",
                    "empty_line_count",
                    "invalid_json_count",
                    "non_object_count",
                    "non_finite_number_count",
                    "csv_parse_error_count",
                )
                if str(result.get(key, 0)).isdigit()
            )
            anomaly_ratio = _ratio(anomaly_count, record_count)
            severity = "高" if anomaly_count else "低"
            rule_status = "已执行"
        elif scan_completeness == "元数据范围":
            anomaly_count = "无法判定"
            anomaly_ratio = "无法判定"
            severity = "无法判定"
            rule_status = "仅元数据，未执行内容异常规则"
        else:
            anomaly_count = "无法判定"
            anomaly_ratio = "无法判定"
            severity = "无法判定"
            rule_status = "未完整" if scan_completeness == "未完整" else "未执行"
        anomaly_rows.append(
            {
                "审计批次": str(metadata["audit_batch"]),
                "规则版本": RULE_VERSION,
                "规则指纹": str(metadata["rules_fingerprint"]),
                "清单指纹": str(metadata["inventory_fingerprint"]),
                "资产编号": asset_id,
                "候选标的范围": unit["标的范围"],
                "规则编号": "DQ-STRUCT-001",
                "异常类型": "结构解析异常汇总",
                "异常数量": str(anomaly_count),
                "异常比例": anomaly_ratio,
                "严重度": severity,
                "规则状态": rule_status,
                "证据": evidence,
                "处置": "仅记录，不修改原始数据",
            }
        )
    return quality_rows, gap_rows, anomaly_rows


def render_csv(columns: Sequence[str], rows: list[dict[str, str]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(columns), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: safe_csv_cell(row.get(column, "")) for column in columns})
    return buffer.getvalue()


def render_report(
    quality_rows: list[dict[str, str]],
    gap_rows: list[dict[str, str]],
    anomaly_rows: list[dict[str, str]],
    metadata: Mapping[str, object],
) -> str:
    complete = sum(row.get("扫描完整性") == "完整" for row in quality_rows)
    unresolved = sum(row.get("可用性结论") == "无法判定" for row in quality_rows)
    complete_files = [
        row
        for row in quality_rows
        if row.get("资产类型") == "候选数据文件"
        and row.get("扫描完整性") == "完整"
    ]
    file_records = sum(
        int(row["记录数"])
        for row in complete_files
        if str(row.get("记录数", "")).isdigit()
    )
    structural_missing = sum(
        int(row["结构缺失数"])
        for row in complete_files
        if str(row.get("结构缺失数", "")).isdigit()
    )
    quantified_duplicates = [
        row
        for row in quality_rows
        if str(row.get("重复状态", "")).startswith("已量化")
    ]
    exact_duplicates = sum(
        int(row["精确重复数"])
        for row in quantified_duplicates
        if str(row.get("精确重复数", "")).isdigit()
    )
    unquantified_duplicates = len(quality_rows) - len(quantified_duplicates)
    metadata_only = sum(row.get("扫描完整性") == "元数据范围" for row in quality_rows)
    not_executed = sum(row.get("扫描完整性") == "未执行" for row in quality_rows)
    sensitive_excluded = sum(
        row.get("扫描完整性") == "未执行"
        and str(row.get("位置", "")).startswith("/var/lib/mysql/mysql/")
        for row in quality_rows
    )
    input_drift = sum(row.get("扫描状态") == "输入漂移" for row in quality_rows)
    event_candidates = sum(
        row.get("事件时间候选字段", "无") != "无" for row in quality_rows
    )
    arrival_candidates = sum(
        row.get("到达时间候选字段", "无") != "无" for row in quality_rows
    )
    collection_candidates = sum(
        row.get("采集时间候选字段", "无") != "无" for row in quality_rows
    )
    anomaly_total = sum(
        int(row["异常数量"])
        for row in anomaly_rows
        if row.get("规则状态") == "已执行"
        and str(row.get("异常数量", "")).isdigit()
    )
    anomaly_executed = sum(row.get("规则状态") == "已执行" for row in anomaly_rows)
    anomaly_not_executed = len(anomaly_rows) - anomaly_executed
    symbol_counts = {
        symbol: sum(
            symbol
            in {
                part.strip()
                for part in str(row.get("候选标的范围", "")).split("、")
            }
            for row in quality_rows
        )
        for symbol in CURRENT_TARGETS
    }
    lines = [
        "# 《知势》数据质量审计报告",
        "",
        "<!-- markdownlint-disable MD013 -->",
        "",
        f"- 报告版本：`{AUDIT_VERSION}`",
        f"- 审计批次：`{redact(metadata['audit_batch'])}`",
        f"- 数据截止时间：`{redact(metadata['cutoff_time'])}`",
        f"- 资产清单SHA-256：`{redact(metadata['inventory_fingerprint'])}`",
        f"- 规则版本：`{RULE_VERSION}`",
        f"- 规则SHA-256：`{redact(metadata['rules_fingerprint'])}`",
        f"- 结构SHA-256：`{redact(metadata.get('schema_fingerprint', '未记录'))}`",
        f"- 规则冻结时间：`{redact(metadata.get('rules_frozen_at', metadata['cutoff_time']))}`",
        f"- 脚本与本地环境：`{AUDIT_VERSION}` / `{redact(metadata.get('local_runtime', '未记录'))}`",
        f"- 远端逻辑环境：`{redact(metadata.get('ssh_target', '未记录'))}` / `{redact(metadata.get('remote_runtime', '未记录'))}`",
        "- 执行方式：固定白名单、远端无落盘、文件与SQLite只读、MySQL仅元数据",
        "",
        "## 技术摘要",
        "",
        f"- **结论：BTC、ETH均为无法判定。** {unresolved}个验证单元没有一个具备已证明的标的身份、三类时间、频率、重放和最小闭环证据。",
        f"- **文件结构质量已形成部分可重算证据。** {complete}个文件完整扫描，共{file_records}条记录、{structural_missing}项空值或空文本；已量化{exact_duplicates}条规范记录重复。",
        f"- **时间与断档硬门仍未建立。** 只有{arrival_candidates}个验证单元出现到达时间候选字段，且候选字段均未获得业务语义证明；全部断档结果保持无法判定。",
        f"- **审计保持只读。** {metadata_only}个MySQL对象仅查询元数据，{sensitive_excluded}个敏感系统日志保留覆盖记录但未读取正文；{input_drift}个动态文件因两阶段身份漂移未形成内容结论。",
        "",
        "## 全部验证单元均未达到可用性证据门槛",
        "",
        f"- 验证单元：{len(quality_rows)}个。",
        f"- 完整扫描：{complete}个；未完整或无法执行：{len(quality_rows) - complete}个。",
        f"- 完整扫描文件记录：{file_records}条；结构空值或空文本：{structural_missing}项。",
        f"- 已量化的规范记录重复：{exact_duplicates}条；重复仍无法完整量化：{unquantified_duplicates}个验证单元。",
        f"- MySQL仅元数据：{metadata_only}个；未执行：{not_executed}个（敏感系统日志{sensitive_excluded}个、输入漂移{input_drift}个）。",
        f"- 结构解析异常规则在{anomaly_executed}个完整扫描对象执行，发现{anomaly_total}项；{anomaly_not_executed}个仅元数据、未完整或未执行对象不进入零异常分母。该数字不包含未定义的业务异常。",
        f"- 可用性仍无法判定的验证单元：{unresolved}个。",
        f"- 事件时间候选字段：{event_candidates}个验证单元；到达时间候选字段：{arrival_candidates}个；采集时间候选字段：{collection_candidates}个。候选不构成时间语义证明。",
        "- 字段名称只被记录为时间候选，没有被自动认定为事件、到达或采集时间。",
        "- 没有正式频率合同的验证单元未计算断档。",
        "",
        "## 作用域与指标定义",
        "",
        "- **验证单元：** 任务-000003清单中的一个候选文件或一个MySQL表元数据对象。",
        "- **完整扫描：** 文件在结构与质量阶段身份一致，且内容统计未超时或失败。",
        "- **结构缺失：** CSV单元格、JSON对象字段、SQLite值中的空值或空文本；不代表已证明的业务必填违约。",
        "- **规范记录重复：** 同一文件内整条CSV记录或规范化JSON对象内容一致，或SQLite声明主键保证唯一；不等同于业务去重键。",
        "- **结构解析异常：** 列宽错误、空JSONL行、非法JSON、非对象JSON或非有限数值；未定义的价格、数量和收益异常不在该指标内。",
        "- **候选时间字段：** 名称匹配时间别名的字段，仅用于列出待确认合同，不证明事件、到达或采集时间。",
        "",
        "## 方法与稳健性检查",
        "",
        "1. 以任务-000003资产清单SHA-256冻结验证单元，拒绝白名单外路径和重复资产编号。",
        "2. 结构阶段只取得字段、类型、SQLite主键与MySQL元数据，再冻结规则指纹。",
        "3. 质量阶段流式扫描CSV和JSONL，以只读URI扫描SQLite；MySQL不读取业务记录。",
        "4. 文件在两阶段之间或扫描过程中身份变化时标记输入漂移，不混合版本。",
        "5. 重复集合超过固定上限时保留记录与缺失统计，但重复结论降级为无法判定。",
        "6. 三份逐对象CSV用于精确复算；未绘制图表，因为审计明细和不可比口径更适合表格查验。",
        "",
        "## BTC、ETH均无法判定",
        "",
        "| 标的 | 结论 | 精确作用域 | 主要依据 | 限制与解除条件 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for symbol in CURRENT_TARGETS:
        count = symbol_counts[symbol]
        if count:
            scope = (
                f"{count}个已登记候选验证单元；候选映射未证明精确标的、市场、合约或时间尺度"
            )
            basis = "存在候选映射，但缺少正式标的身份、三类时间、频率、重放和最小闭环证据"
        else:
            scope = f"0个已登记候选验证单元；清单未发现{symbol}候选证据"
            basis = "没有该标的候选覆盖，且缺少正式数据合同与完整性证据"
        lines.append(
            f"| {symbol} | 无法判定 | {scope} | {basis} | "
            "禁止预测性研究与交易许可；补齐合同后创建新审计批次 |"
        )
    lines.extend(
        [
            "",
            "本任务不能独立给出`可用`结论。任务-000005的历史重放与任务-000006的最小",
            "数据闭环尚未完成，任何文件名、列名或其他标的结果均不能补偿这些硬门。",
            "",
            "## 审计证据可逐对象重算",
            "",
            "- 逐对象质量证据：`数据质量结果.csv`（与本报告同目录）。",
            "- 逐对象断档证据：`数据断档结果.csv`（与本报告同目录）。",
            "- 逐对象异常证据：`数据异常结果.csv`（与本报告同目录）。",
            "- 三份CSV与本报告共享审计批次、清单指纹和规则指纹。",
            "",
            "## 推荐的解除路径",
            "",
            "1. 为候选数据对象补齐来源、市场、合约、字段中文映射、类型、单位和精度合同。",
            "2. 明确事件时间、到达时间、采集时间、时区、预期频率和修订行为后重新审计。",
            "3. 任务-000005验证当时可见集合和未来数据拒绝；任务-000006验证最小闭环。",
            "4. 在三类时间、重放和闭环通过前，不进入正式回测、模型训练或交易许可。",
            "",
            "## 仍需回答的问题",
            "",
            "1. 哪些候选对象具有可验证的来源、市场、合约和标的身份合同？",
            "2. 哪些字段分别表示事件时间、到达时间和采集时间，其时区与可见性语义是什么？",
            "3. 各对象的预期频率、迟到、补录、修订和去重规则由哪个版本化合同定义？",
            "4. MySQL业务记录是否应在新的授权与资源预算下建立独立只读质量审计？",
            "",
            "## 限制、不确定性与安全影响",
            "",
            "- MySQL只审计元数据，不扫描业务记录，记录数为元数据估计或无法判定。",
            "- 结构缺失是空值或空文本统计，不等同于业务必填字段违约。",
            "- 精确重复只表示规范记录内容一致，不等同于业务主键重复。",
            "- 未定义业务异常阈值，因此不评价价格、数量、收益或盘口数值是否异常。",
            "- 审计未修改服务器、数据库、服务、权限、防火墙或原始数据；仓库仅保存汇总统计、规则和指纹，不保存原始记录、未脱敏样本或凭据。",
        ]
    )
    return "\n".join(lines) + "\n"


def publish_outputs(outputs: Mapping[Path, str]) -> None:
    """本地预检全部目标后发布；可捕获失败时恢复旧内容。"""

    if not outputs:
        raise ValueError("没有待发布产物")
    normalized: dict[Path, str] = {}
    for raw_path, content in outputs.items():
        path = Path(raw_path)
        if path.is_symlink():
            raise ValueError(f"输出目标不得是符号链接：{path}")
        if path.exists() and not path.is_file():
            raise ValueError(f"输出目标必须是普通文件：{path}")
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise ValueError(f"输出目录必须存在且不是符号链接：{path.parent}")
        if path.suffix not in {".csv", ".md"}:
            raise ValueError(f"输出扩展名必须是.csv或.md：{path}")
        serialized = str(content)
        if any(
            pattern.search(serialized)
            for pattern in (
                IPV4_PATTERN,
                CREDENTIAL_PATTERN,
                TOKEN_PATTERN,
                PRIVATE_KEY_PATTERN,
            )
        ):
            raise ValueError(f"输出内容命中敏感信息模式，拒绝发布：{path}")
        normalized[path] = serialized

    temporary: dict[Path, Path] = {}
    previous: dict[Path, bytes | None] = {}
    replaced: list[Path] = []
    try:
        for path, content in normalized.items():
            previous[path] = path.read_bytes() if path.exists() else None
            descriptor, temp_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            temp_path = Path(temp_name)
            temporary[path] = temp_path
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        for path in sorted(normalized, key=lambda item: str(item)):
            os.replace(temporary[path], path)
            replaced.append(path)
    except Exception:
        for path in reversed(replaced):
            old_content = previous[path]
            if old_content is None:
                try:
                    path.unlink()
                except OSError:
                    pass
                continue
            descriptor, restore_name = tempfile.mkstemp(
                prefix=f".{path.name}.restore.", suffix=".tmp", dir=path.parent
            )
            restore_path = Path(restore_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(old_content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(restore_path, path)
            finally:
                if restore_path.exists():
                    restore_path.unlink()
        raise
    finally:
        for temp_path in temporary.values():
            if temp_path.exists():
                temp_path.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="只读审计《知势》数据质量")
    parser.add_argument("--inventory", type=Path, required=True, help="任务-000003资产清单")
    parser.add_argument("--ssh-target", required=True, help="固定SSH逻辑别名")
    parser.add_argument("--ssh-bin", default="ssh", help="SSH客户端路径")
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="每个远端阶段总体超时秒数，范围10至7200",
    )
    parser.add_argument(
        "--member-timeout",
        type=int,
        default=None,
        help="每个成员的远端只读超时秒数，范围10至300",
    )
    parser.add_argument(
        "--memory-limit-bytes",
        type=int,
        default=None,
        help="远端只读审计地址空间上限，范围64MiB至2GiB",
    )
    parser.add_argument("--output-dir", type=Path, required=True, help="三份CSV输出目录")
    parser.add_argument("--report", type=Path, required=True, help="Markdown报告路径")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        validate_ssh_target(arguments.ssh_target)
        if arguments.timeout < 10 or arguments.timeout > 7200:
            raise ValueError("超时必须在10至7200秒之间")
        if arguments.member_timeout is not None and not 10 <= arguments.member_timeout <= 300:
            raise ValueError("单成员超时必须在10至300秒之间")
        if arguments.memory_limit_bytes is not None and not 64 * 1024 * 1024 <= arguments.memory_limit_bytes <= 2 * 1024 * 1024 * 1024:
            raise ValueError("内存上限必须在64MiB至2GiB之间")
        rows = load_inventory(arguments.inventory)
        units = build_validation_units(rows)
        if not units:
            raise ValueError("资产清单没有可审计验证单元")
        cutoff = dt.datetime.now().astimezone()
        audit_batch = "audit-" + cutoff.strftime("%Y%m%dT%H%M%S%z")
        inventory_sha256 = inventory_fingerprint(arguments.inventory)

        print(f"结构阶段：{len(units)}个验证单元", file=sys.stderr, flush=True)
        schema_payload = run_remote_phase(
            arguments.ssh_target,
            "schema",
            units,
            None,
            arguments.ssh_bin,
            arguments.timeout,
            arguments.member_timeout,
            arguments.memory_limit_bytes,
        )
        rules, rules_sha256 = freeze_rules(schema_payload)
        schema_sha256 = _fingerprint(schema_payload)
        rules_frozen_at = dt.datetime.now().astimezone()

        print("质量阶段：规则已冻结，开始只读统计", file=sys.stderr, flush=True)
        quality_payload = run_remote_phase(
            arguments.ssh_target,
            "quality",
            units,
            rules,
            arguments.ssh_bin,
            arguments.timeout,
            arguments.member_timeout,
            arguments.memory_limit_bytes,
        )
        metadata = {
            "audit_batch": audit_batch,
            "inventory_fingerprint": inventory_sha256,
            "schema_fingerprint": schema_sha256,
            "rules_fingerprint": rules_sha256,
            "cutoff_time": cutoff.isoformat(timespec="seconds"),
            "rules_frozen_at": rules_frozen_at.isoformat(timespec="seconds"),
            "unit_count": len(units),
            "local_runtime": f"Python {platform.python_version()} / {platform.system()}-{platform.machine()}",
            "ssh_target": arguments.ssh_target,
            "remote_runtime": (
                f"Python {schema_payload.get('runtime', {}).get('python', '未记录')} / "
                f"{schema_payload.get('runtime', {}).get('platform', '未记录')}"
            ),
        }
        quality_rows, gap_rows, anomaly_rows = build_output_rows(
            units, schema_payload, quality_payload, rules, metadata
        )
        output_dir = arguments.output_dir
        outputs = {
            output_dir / "数据质量结果.csv": render_csv(QUALITY_COLUMNS, quality_rows),
            output_dir / "数据断档结果.csv": render_csv(GAP_COLUMNS, gap_rows),
            output_dir / "数据异常结果.csv": render_csv(ANOMALY_COLUMNS, anomaly_rows),
            arguments.report: render_report(
                quality_rows, gap_rows, anomaly_rows, metadata
            ),
        }
        publish_outputs(outputs)
        print(
            f"审计批次={audit_batch} 验证单元={len(units)} 规则指纹={rules_sha256}",
            flush=True,
        )
        return 0
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"数据质量审计失败：{redact(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
