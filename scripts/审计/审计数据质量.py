#!/usr/bin/env python3
"""以只读方式审计《知势》数据资产的质量与时间语义。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence
from urllib.parse import quote


AUDIT_VERSION = "1.0"
RULE_VERSION = "dq-rules-1.0"
ALLOWED_ROOTS = (
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
)
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


REMOTE_AUDIT_PROGRAM = textwrap.dedent(
    r'''
    import csv
    import hashlib
    import json
    import math
    import os
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

    def stat_identity(path):
        stat_result = os.lstat(path)
        return {
            "size": int(stat_result.st_size),
            "mtime_ns": int(stat_result.st_mtime_ns),
        }

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
            reader = csv.reader(handle)
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
        valid_objects = 0
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
                    valid_objects += 1
                    if valid_objects >= 1000:
                        break
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
            result["identity"] = stat_identity(path)
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
        except (OSError, ValueError, sqlite3.Error):
            result.update(status="无法判定", error_code="schema_read_failed")
        return result

    def mysql_metadata(units):
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
            timeout=60,
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
            "duplicate_status": "已量化（规范记录完全一致）",
            "exact_duplicate_count": 0,
            "row_width_error_count": 0,
            "empty_line_count": 0,
            "invalid_json_count": 0,
            "non_object_count": 0,
            "non_finite_number_count": 0,
            "fields": [],
            "primary_key": [],
        }

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
            reader = csv.reader(handle)
            try:
                fields = next(reader)
            except StopIteration:
                result["status"] = "空文件"
                return result
            result["fields"] = fields
            result["field_count"] = len(fields)
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
                    result["record_count"] += int(values[0] or 0)
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
            before = stat_identity(path)
            if rule.get("identity") and before != rule["identity"]:
                result.update(
                    status="输入漂移",
                    scan_completeness="未执行",
                    error_code="identity_changed_before_scan",
                )
                return result
            if unit["format"] == "CSV":
                result = quality_csv(path, asset_id, duplicate_limit)
            elif unit["format"] in ("JSONL", "NDJSON"):
                result = quality_jsonl(path, asset_id, duplicate_limit)
            elif unit["format"] == "SQLite":
                result = quality_sqlite(path, asset_id)
            else:
                result.update(
                    status="无法判定", scan_completeness="未执行",
                    error_code="unsupported_format",
                )
                return result
            after = stat_identity(path)
            if before != after:
                result.update(
                    status="输入漂移",
                    scan_completeness="未完整",
                    error_code="identity_changed_during_scan",
                )
            result["identity_before"] = before
            result["identity_after"] = after
            return result
        except ObjectTimeout:
            result.update(
                status="超时", scan_completeness="未完整", error_code="object_timeout"
            )
        except (OSError, ValueError, sqlite3.Error, csv.Error):
            result.update(
                status="无法判定", scan_completeness="未执行",
                error_code="quality_read_failed",
            )
        return result

    def quality_mysql(schema_results):
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
            if schema.get("status") != "已发现结构":
                result.update(
                    status="无法判定", scan_completeness="未执行",
                    error_code=schema.get("error_code", "mysql_metadata_unavailable"),
                )
            converted.append(result)
        return converted

    def main():
        try:
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
            signal.signal(signal.SIGALRM, timeout_handler)
            files = [unit for unit in units if unit.get("asset_type") == "候选数据文件"]
            databases = [unit for unit in units if unit.get("asset_type") == "数据库元数据"]
            results = []
            if phase == "schema":
                for unit in files:
                    print("audit:" + str(unit.get("asset_id", "unknown")), file=sys.stderr)
                    signal.alarm(object_timeout)
                    try:
                        results.append(inspect_file_schema(unit))
                    finally:
                        signal.alarm(0)
                results.extend(mysql_metadata(databases))
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
                results.extend(quality_mysql(mysql_metadata(databases)))
            payload = {
                "audit_version": AUDIT_VERSION,
                "phase": phase,
                "objects": sorted(results, key=lambda item: item["asset_id"]),
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, sort_keys=True)
        except (ValueError, TypeError, KeyError, subprocess.SubprocessError):
            print("remote_audit_failed", file=sys.stderr)
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
    if not any(normalized.startswith(root + "/") for root in ALLOWED_ROOTS):
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
            units.append({**row, "位置": location})
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
    return sorted(field for field in fields if field.strip().lower() in aliases)


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
    return {
        "audit_version": AUDIT_VERSION,
        "phase": phase,
        "objects": sorted(objects, key=lambda item: str(item["asset_id"])),
    }


def run_remote_phase(
    target: str,
    phase: str,
    units: list[dict[str, str]],
    rules: Mapping[str, object] | None,
    ssh_bin: str,
    timeout: int,
) -> dict[str, object]:
    validate_ssh_target(target)
    if phase not in {"schema", "quality"}:
        raise ValueError("远端审计阶段非法")
    if timeout < 10 or timeout > 7200:
        raise ValueError("远端审计超时必须在10至7200秒之间")
    request = {
        "audit_version": AUDIT_VERSION,
        "phase": phase,
        "objects": _remote_units(units),
        "rules": rules,
        "duplicate_limit": 500_000,
        "object_timeout": min(300, max(30, timeout // max(1, len(units)))),
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
        "-c",
        REMOTE_AUDIT_PROGRAM,
    ]
    try:
        completed = subprocess.run(
            command,
            input=_canonical_json(request),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("SSH远端审计失败：命令不可用或总体超时") from error
    if completed.returncode != 0:
        raise RuntimeError("SSH远端审计失败：远端返回非零状态")
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("SSH远端审计失败：返回结构不是合法JSON") from error
    return validate_remote_payload(payload, phase, units)


def _empty_result() -> dict[str, object]:
    return {
        "status": "完成",
        "scan_completeness": "完整",
        "record_count": 0,
        "field_count": 0,
        "missing_count": 0,
        "duplicate_status": "已量化（规范记录完全一致）",
        "exact_duplicate_count": 0,
        "row_width_error_count": 0,
        "empty_line_count": 0,
        "invalid_json_count": 0,
        "non_object_count": 0,
        "non_finite_number_count": 0,
        "primary_key": [],
        "fields": [],
    }


def audit_csv_file(path: Path, duplicate_limit: int = 500_000) -> dict[str, object]:
    result = _empty_result()
    seen: set[bytes] = set()
    duplicate_complete = True
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            result["status"] = "空文件"
            return result
        result["fields"] = [str(field) for field in header]
        result["field_count"] = len(header)
        for row in reader:
            result["record_count"] = int(result["record_count"]) + 1
            expected = len(header)
            if len(row) != expected:
                result["row_width_error_count"] = int(result["row_width_error_count"]) + 1
            normalized = list(row[:expected]) + [""] * max(0, expected - len(row))
            result["missing_count"] = int(result["missing_count"]) + sum(
                1 for value in normalized if not value.strip()
            )
            if duplicate_complete:
                digest = hashlib.sha256(_canonical_json(row).encode("utf-8")).digest()
                if digest in seen:
                    result["exact_duplicate_count"] = int(result["exact_duplicate_count"]) + 1
                elif len(seen) < duplicate_limit:
                    seen.add(digest)
                else:
                    duplicate_complete = False
    if not duplicate_complete:
        result["duplicate_status"] = "无法判定（超过重复集合上限）"
        result["exact_duplicate_count"] = "无法判定"
    return result


def _count_non_finite(value: object) -> int:
    if isinstance(value, float) and not math.isfinite(value):
        return 1
    if isinstance(value, dict):
        return sum(_count_non_finite(item) for item in value.values())
    if isinstance(value, list):
        return sum(_count_non_finite(item) for item in value)
    return 0


def audit_jsonl_file(path: Path, duplicate_limit: int = 500_000) -> dict[str, object]:
    result = _empty_result()
    seen: set[bytes] = set()
    duplicate_complete = True
    fields: set[str] = set()
    missing_by_field: dict[str, int] = {}
    object_count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                result["empty_line_count"] = int(result["empty_line_count"]) + 1
                continue
            try:
                value = json.loads(line)
            except (TypeError, ValueError):
                result["invalid_json_count"] = int(result["invalid_json_count"]) + 1
                continue
            if not isinstance(value, dict):
                result["non_object_count"] = int(result["non_object_count"]) + 1
                continue
            current_fields = {str(field) for field in value}
            for field in current_fields - fields:
                missing_by_field[field] = object_count
            fields.update(current_fields)
            for field in fields:
                if field not in value or value[field] is None or (
                    isinstance(value[field], str) and not value[field].strip()
                ):
                    missing_by_field[field] += 1
            object_count += 1
            result["record_count"] = object_count
            result["non_finite_number_count"] = int(
                result["non_finite_number_count"]
            ) + _count_non_finite(value)
            if duplicate_complete:
                digest = hashlib.sha256(_canonical_json(value).encode("utf-8")).digest()
                if digest in seen:
                    result["exact_duplicate_count"] = int(result["exact_duplicate_count"]) + 1
                elif len(seen) < duplicate_limit:
                    seen.add(digest)
                else:
                    duplicate_complete = False
    result["fields"] = sorted(fields)
    result["field_count"] = len(fields)
    result["missing_count"] = sum(missing_by_field.values())
    if not duplicate_complete:
        result["duplicate_status"] = "无法判定（超过重复集合上限）"
        result["exact_duplicate_count"] = "无法判定"
    return result


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def audit_sqlite_file(path: Path) -> dict[str, object]:
    result = _empty_result()
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        all_fields = []
        primary_key = []
        duplicate_proven = True
        for (table,) in table_rows:
            quoted_table = _quote_identifier(str(table))
            columns = connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            column_names = [str(column[1]) for column in columns]
            all_fields.extend(f"{table}.{column}" for column in column_names)
            table_primary = [
                str(column[1]) for column in sorted(columns, key=lambda item: int(item[5])) if int(column[5])
            ]
            primary_key.extend(f"{table}.{column}" for column in table_primary)
            if not table_primary:
                duplicate_proven = False
            if not column_names:
                continue
            expressions = ["COUNT(*)"] + [
                "SUM(CASE WHEN "
                + _quote_identifier(column)
                + " IS NULL OR (typeof("
                + _quote_identifier(column)
                + ")='text' AND trim("
                + _quote_identifier(column)
                + ")='') THEN 1 ELSE 0 END)"
                for column in column_names
            ]
            values = connection.execute(
                f"SELECT {', '.join(expressions)} FROM {quoted_table}"
            ).fetchone()
            if values:
                result["record_count"] = int(result["record_count"]) + int(values[0] or 0)
                result["missing_count"] = int(result["missing_count"]) + sum(
                    int(value or 0) for value in values[1:]
                )
        result["fields"] = all_fields
        result["field_count"] = len(all_fields)
        result["primary_key"] = primary_key
        if duplicate_proven:
            result["duplicate_status"] = "已量化（SQLite声明主键）"
        else:
            result["duplicate_status"] = "无法判定（部分表未声明主键）"
            result["exact_duplicate_count"] = "无法判定"
        return result
    finally:
        connection.close()


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
        denominator = (
            int(record_count) * int(field_count)
            if str(record_count).isdigit() and str(field_count).isdigit()
            else "无法判定"
        )
        evidence = _fingerprint(
            {"schema": schema, "quality": result, "rule": rule}
        )
        limitation = (
            "缺少已证明的标的、市场、三类时间、频率、重放和闭环合同；"
            "本结果不得用于预测性研究或交易许可"
        )
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
                "依据": f"结构与质量证据{evidence}",
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
        anomaly_count = sum(
            int(result.get(key, 0) or 0)
            for key in (
                "row_width_error_count",
                "empty_line_count",
                "invalid_json_count",
                "non_object_count",
                "non_finite_number_count",
            )
            if str(result.get(key, 0)).isdigit()
        )
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
                "异常比例": _ratio(anomaly_count, record_count),
                "严重度": "高" if anomaly_count else "低",
                "规则状态": "已执行" if result else "无法判定",
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
    anomaly_total = sum(
        int(row["异常数量"])
        for row in anomaly_rows
        if str(row.get("异常数量", "")).isdigit()
    )
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
        "- 执行方式：固定白名单、远端无落盘、文件与SQLite只读、MySQL仅元数据",
        "",
        "## 事实",
        "",
        f"- 验证单元：{len(quality_rows)}个。",
        f"- 完整扫描：{complete}个；未完整或无法执行：{len(quality_rows) - complete}个。",
        f"- 结构解析异常合计：{anomaly_total}项；该数字不包含未定义的业务异常。",
        f"- 可用性仍无法判定的验证单元：{unresolved}个。",
        "- 字段名称只被记录为时间候选，没有被自动认定为事件、到达或采集时间。",
        "- 没有正式频率合同的验证单元未计算断档。",
        "",
        "## 判定",
        "",
        "| 标的 | 结论 | 精确作用域 | 主要依据 | 限制与解除条件 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for symbol in ("BTC", "ETH", "SOL"):
        lines.append(
            f"| {symbol} | 无法判定 | 任务-000003清单中的{symbol}候选资产，未证明市场、合约和时间尺度 | "
            "缺少正式标的身份、三类时间、频率、重放和最小闭环证据 | "
            "禁止预测性研究与交易许可；补齐合同后创建新审计批次 |"
        )
    lines.extend(
        [
            "",
            "本任务不能独立给出`可用`结论。任务-000005的历史重放与任务-000006的最小",
            "数据闭环尚未完成，任何文件名、列名或其他标的结果均不能补偿这些硬门。",
            "",
            "## 质量与断档证据",
            "",
            "- 逐对象质量证据：`artifacts/审计/数据质量结果.csv`。",
            "- 逐对象断档证据：`artifacts/审计/数据断档结果.csv`。",
            "- 逐对象异常证据：`artifacts/审计/数据异常结果.csv`。",
            "- 三份CSV与本报告共享审计批次、清单指纹和规则指纹。",
            "",
            "## 建议",
            "",
            "1. 为候选数据对象补齐来源、市场、合约、字段中文映射、类型、单位和精度合同。",
            "2. 明确事件时间、到达时间、采集时间、时区、预期频率和修订行为后重新审计。",
            "3. 任务-000005验证当时可见集合和未来数据拒绝；任务-000006验证最小闭环。",
            "4. 在三类时间、重放和闭环通过前，不进入正式回测、模型训练或交易许可。",
            "",
            "## 已知限制",
            "",
            "- MySQL只审计元数据，不扫描业务记录，记录数为元数据估计或无法判定。",
            "- 结构缺失是空值或空文本统计，不等同于业务必填字段违约。",
            "- 精确重复只表示规范记录内容一致，不等同于业务主键重复。",
            "- 未定义业务异常阈值，因此不评价价格、数量、收益或盘口数值是否异常。",
            "",
            "## 数据与安全影响",
            "",
            "审计未修改服务器、数据库、服务、权限、防火墙或原始数据；仓库仅保存汇总",
            "统计、规则和指纹，不保存原始记录、未脱敏样本或凭据。",
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
        normalized[path] = str(content)

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
        )
        rules, rules_sha256 = freeze_rules(schema_payload)
        schema_sha256 = _fingerprint(schema_payload)

        print("质量阶段：规则已冻结，开始只读统计", file=sys.stderr, flush=True)
        quality_payload = run_remote_phase(
            arguments.ssh_target,
            "quality",
            units,
            rules,
            arguments.ssh_bin,
            arguments.timeout,
        )
        metadata = {
            "audit_batch": audit_batch,
            "inventory_fingerprint": inventory_sha256,
            "schema_fingerprint": schema_sha256,
            "rules_fingerprint": rules_sha256,
            "cutoff_time": cutoff.isoformat(timespec="seconds"),
            "unit_count": len(units),
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
