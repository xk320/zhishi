#!/usr/bin/env python3
"""任务-000066：按冻结白名单执行失败安全的正文质量复验。

数据库只允许通过已证明使用索引的有界时间字段样本；不执行 COUNT/MIN/MAX
等无界聚合。远端只返回脱敏聚合值、指纹和资源事实，原始正文永不进入本地产物。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "artifacts/审计/数据质量增量复验/任务-000063范围绑定/覆盖矩阵.csv"
CONTRACT = ROOT / "docs/superpowers/specs/phase1-incomplete-scan-authorization-v1-design.md"

# 这些值是已批准合同的脱敏指纹，不是账户名、路径或凭据。
EXPECTED_MATRIX_FP = "6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79"
EXPECTED_CONTRACT_FP = "0acd47b2f1396dc1aadd604d20386fb8b0e6ff346101571f5352424091884d8d"
EXPECTED_BODY_PROTOCOL = "zhishi-ro/2"
EXPECTED_BODY_WRAPPER_VERSION = "zhishi-ro-body-audit-1.0"
EXPECTED_BODY_WRAPPER_FP = "5252f264a443e30177bbebee5f4bc32d8b9900362f120442bb9777491376d7d8"
EXPECTED_BODY_TARGETS_FP = "1c8adccb082d30ff37ff456b139c5560a716f55e208450e8945ddfabce11e187"
EXPECTED_DB_SESSION_FP = "2e642610c2d0f286f489b5226081f23077a8674bffb0e255c8cea98825601943"
EXPECTED_DB_GRANTS_FP = "ad26cec63d094b7a68f4229ca4668a36eaa9aee7343970d8dfc6e8f9c6631a2e"
EXPECTED_BODY_KEY_FP = "SHA256:sAHa0lV+dd9ZGdcnc/JuQ1yNgqvhHE1sQmCKuW2xB3k"
DEFAULT_BODY_KEY_PATH = "/Users/luweiming/.ssh/zhishi_body_ro_ed25519"
EXPECTED_LOG_TARGET_FP = "3aec10efd62c05a4ccf4c23022bfdd1ba987c08d6764792047decc241297953d"
EXPECTED_LOG_KEY_FP = "SHA256:oq45bCRm3+qAuQr/CVmB6P27cq2u1Z+3f0vrzi8GvyI"
EXPECTED_LOG_WRAPPER_FP = "d63540742cc71bc07908c0d31d09e7e95c1ed8d89fc43c00d848277a62b6cbc3"
EXPECTED_LOG_ENTRY_PROOF_FP = "cd2b318e10b970eb3ac171d85e3a38e59f009c2a4f510c83f63b5d33b903a74a"
EXPECTED_LOG_ORDER = (
    "3b4c1660ead1953f8be41667c435478438c247ac9b13b4b5876a186b93ae6d78",
    "8abea0a4395c1db90828ad1b8edd7e9378f0d622b2a8517f0882545963a053ef",
)
EXPECTED_LOG_ASSETS = ("DS-000222", "DS-000223")

FROZEN_DATA_CUTOFF = "2026-08-06T12:00:00+08:00"
AUTHORIZATION_DEADLINE = "2026-08-07T00:00:00+08:00"
ALLOWED_STATUSES = {"通过", "拒绝", "无法判定", "失败", "未成熟", "失效", "未执行"}
RESOURCE_CONTRACT = {
    "数据库单对象最大读取字节": 65536,
    "数据库单对象最大耗时秒": 30,
    "数据库批次最大耗时秒": 600,
    "数据库批次最大输出字节": 8388608,
    "数据库最大并发": 1,
    "数据库样本最大行数": 64,
    "日志单对象最大读取字节": 32768,
    "日志批次最大读取字节": 65536,
    "日志批次最大耗时秒": 30,
    "最大内存字节": 536870912,
    "远端临时写入": False,
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_targets() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if sha256_bytes(MATRIX.read_bytes()) != EXPECTED_MATRIX_FP:
        raise RuntimeError("覆盖矩阵指纹漂移，安全停止")
    with MATRIX.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    database: list[dict[str, str]] = []
    logs: list[dict[str, str]] = []
    for row in rows:
        if row["资产类型"] == "数据库元数据":
            parts = row["位置"].split("/")
            if len(parts) != 3 or parts[0] != "MySQL":
                raise ValueError("数据库位置格式错误")
            database.append({"资产编号": row["资产编号"], "数据库": parts[1], "表": parts[2]})
        elif row["任务-000063复验层"] == "敏感系统日志":
            logs.append({"资产编号": row["资产编号"], "位置": row["位置"]})
    if len(database) != 92 or len(logs) != 2:
        raise ValueError("任务-000063目标必须是92个数据库对象和2个敏感系统日志")
    if len({(item["数据库"], item["表"]) for item in database}) != 92:
        raise ValueError("数据库对象存在重复")
    if tuple(item["资产编号"] for item in logs) != EXPECTED_LOG_ASSETS:
        raise ValueError("敏感日志对象顺序或身份漂移")
    return database, logs


def make_remote_script(
    database: list[dict[str, str]],
    cutoff: str,
    script_fingerprint: str,
    db_config_path: str,
) -> str:
    payload = json.dumps(database, ensure_ascii=False, sort_keys=True)
    template = r'''import datetime as _dt
import hashlib as _hashlib
import json as _json
import resource as _resource
import signal as _signal
import subprocess as _subprocess
import time as _time

_TABLES = _json.loads(__PAYLOAD__)
_CUTOFF = _dt.datetime.fromisoformat(__CUTOFF__)
_SCRIPT_FP = __SCRIPT_FP__
_EXPECTED_SESSION_FP = __EXPECTED_SESSION_FP__
_EXPECTED_GRANTS_FP = __EXPECTED_GRANTS_FP__
_MAX_BYTES = 65536
_MAX_SECONDS = 30
_MAX_SAMPLE_ROWS = 64
_MAX_BATCH_SECONDS = 600
_MAX_BATCH_OUTPUT = 8388608
_START = _time.monotonic()
_resource.setrlimit(_resource.RLIMIT_AS, (536870912, 536870912))
_resource.setrlimit(_resource.RLIMIT_CPU, (600, 600))

def _timeout(_signum, _frame):
    raise TimeoutError("batch_timeout")

_signal.signal(_signal.SIGALRM, _timeout)
_signal.alarm(_MAX_BATCH_SECONDS)

def _fp(value):
    return _hashlib.sha256(value.encode("utf-8")).hexdigest()

def _ident(value):
    if not value or not value.replace("_", "").isalnum():
        raise ValueError("identifier_rejected")
    return "`" + value.replace("`", "``") + "`"

def _lit(value):
    if "'" in value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("literal_rejected")
    return "'" + value + "'"

def _mysql(sql, deadline=None):
    command = [
        "mysql", "--defaults-extra-file=__DB_CONFIG__", "--batch", "--raw",
        "--skip-column-names", "--quick", "--connect-timeout=5",
        "--init-command=SET SESSION max_execution_time=25000", "-e", sql,
    ]
    timeout = 25
    if deadline is not None:
        timeout = min(timeout, deadline - _time.monotonic())
        if timeout <= 0:
            return {"ok": False, "error": "object_timeout", "bytes": 0}
    try:
        result = _subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except _subprocess.TimeoutExpired:
        return {"ok": False, "error": "query_timeout", "bytes": 0}
    stdout = result.stdout.encode("utf-8", errors="replace")
    if len(stdout) > _MAX_BYTES:
        return {"ok": False, "error": "query_output_over_limit", "bytes": len(stdout)}
    if result.returncode != 0:
        return {"ok": False, "error": "query_failed", "bytes": len(stdout)}
    return {"ok": True, "stdout": result.stdout, "bytes": len(stdout)}

def _parse_iso(value):
    if not value or value == "NULL":
        return None
    value = value.strip().replace("Z", "+00:00")
    try:
        parsed = _dt.datetime.fromisoformat(value.replace(" ", "T"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed

def _result(item):
    return {
        "资产编号": item["资产编号"],
        "对象指纹": _fp("MySQL/" + item["数据库"] + "/" + item["表"]),
        "状态": "失败", "记录数": None, "已观察记录数": None,
        "时间字段指纹": None, "时间可解析记录数": None, "时间空值记录数": None,
        "未来记录": None, "Schema指纹": None, "读取字节数": 0,
        "耗时毫秒": 0, "错误类别": None,
    }

def _one(item):
    started = _time.monotonic()
    deadline = started + _MAX_SECONDS
    result = _result(item)
    try:
        db, table = item["数据库"], item["表"]
        metadata = _mysql(
            "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=" + _lit(db) + " AND TABLE_NAME=" + _lit(table) +
            " ORDER BY ORDINAL_POSITION;", deadline
        )
        result["读取字节数"] += metadata.get("bytes", 0)
        if not metadata["ok"]:
            result["错误类别"] = metadata["error"]
            return result
        columns = []
        for line in metadata["stdout"].splitlines():
            fields = line.split(chr(9))
            if len(fields) == 2:
                columns.append((fields[0], fields[1].lower()))
        result["Schema指纹"] = _fp("|".join(name + ":" + kind for name, kind in columns))
        candidates = [
            (name, kind) for name, kind in columns
            if kind in {"date", "datetime", "timestamp", "bigint", "int", "integer", "decimal"}
            and any(token in name.lower() for token in (
                "time", "date", "timestamp", "created", "updated", "event", "occurred",
                "received", "arrived", "start", "end"))
        ]
        candidates.sort(key=lambda value: columns.index(value))
        if not candidates:
            result["状态"] = "无法判定"
            result["错误类别"] = "no_freezable_time_field"
            return result
        stats = _mysql(
            "SELECT COLUMN_NAME, INDEX_NAME FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA=" + _lit(db) + " AND TABLE_NAME=" + _lit(table) +
            " ORDER BY SEQ_IN_INDEX;", deadline
        )
        result["读取字节数"] += stats.get("bytes", 0)
        if not stats["ok"]:
            result["错误类别"] = stats["error"]
            return result
        indexed = set()
        for line in stats["stdout"].splitlines():
            fields = line.split(chr(9))
            if len(fields) == 2:
                indexed.add(fields[0])
        chosen = next((value for value in candidates if value[0] in indexed), None)
        if chosen is None:
            result["状态"] = "无法判定"
            result["错误类别"] = "time_field_not_indexed"
            return result
        field, _kind = chosen
        result["时间字段指纹"] = _fp(field)
        ref = _mysql(
            "EXPLAIN SELECT " + _ident(field) + " FROM " + _ident(db) + "." + _ident(table) +
            " ORDER BY " + _ident(field) + " DESC LIMIT 64;", deadline
        )
        result["读取字节数"] += ref.get("bytes", 0)
        if not ref["ok"]:
            result["错误类别"] = ref["error"]
            return result
        plan = ref["stdout"].strip().split(chr(9))
        if len(plan) < 7 or plan[4].upper() == "ALL" or plan[6] in {"", "NULL"}:
            result["状态"] = "无法判定"
            result["错误类别"] = "bounded_index_not_proven"
            return result
        sample = _mysql(
            "SELECT " + _ident(field) + " FROM " + _ident(db) + "." + _ident(table) +
            " ORDER BY " + _ident(field) + " DESC LIMIT 64;", deadline
        )
        result["读取字节数"] += sample.get("bytes", 0)
        if result["读取字节数"] > _MAX_BYTES:
            result["错误类别"] = "object_output_over_limit"
            return result
        if not sample["ok"]:
            result["错误类别"] = sample["error"]
            return result
        values = [line.strip() for line in sample["stdout"].splitlines() if line.strip()]
        result["已观察记录数"] = len(values)
        if not values:
            result["状态"] = "无法判定"
            result["错误类别"] = "empty_sample_not_maturity"
            return result
        parsed = [_parse_iso(value) for value in values]
        result["时间可解析记录数"] = sum(value is not None for value in parsed)
        result["时间空值记录数"] = len(values) - result["时间可解析记录数"]
        maximum = next((value for value in parsed if value is not None), None)
        result["未来记录"] = bool(maximum is not None and maximum > _CUTOFF)
        if result["未来记录"]:
            result["状态"] = "失败"
            result["错误类别"] = "future_timestamp_detected"
        else:
            result["状态"] = "无法判定"
            result["错误类别"] = "bounded_sample_only"
    except (ValueError, TypeError, TimeoutError):
        result["错误类别"] = "safe_parser_failure"
    finally:
        result["耗时毫秒"] = int((_time.monotonic() - started) * 1000)
        if result["耗时毫秒"] > _MAX_SECONDS * 1000:
            result["状态"] = "失败"
            result["错误类别"] = "object_timeout"
    return result

_session = _mysql("SELECT CURRENT_USER();")
if not _session.get("ok") or _fp(_session.get("stdout", "")) != _EXPECTED_SESSION_FP:
    raise RuntimeError("readonly_session_identity_mismatch")
_grants = _mysql("SHOW GRANTS;")
if not _grants.get("ok") or _fp(_grants.get("stdout", "")) != _EXPECTED_GRANTS_FP:
    raise RuntimeError("readonly_grants_fingerprint_mismatch")
_results = []
for _item in _TABLES:
    if _time.monotonic() - _START > _MAX_BATCH_SECONDS - 10:
        _results.append({"资产编号": _item["资产编号"], "对象指纹": _fp("MySQL/" + _item["数据库"] + "/" + _item["表"]), "状态": "失败", "错误类别": "batch_timeout", "读取字节数": 0, "耗时毫秒": 0})
        continue
    _results.append(_one(_item))
_document = {
    "规则脚本指纹": _SCRIPT_FP,
    "授权会话指纹": _fp(_session.get("stdout", "")),
    "授权权限快照指纹": _fp(_grants.get("stdout", "")),
    "对象结果": _results,
    "资源上限": {"单对象字节": _MAX_BYTES, "单对象秒": _MAX_SECONDS, "批次秒": _MAX_BATCH_SECONDS, "批次输出字节": _MAX_BATCH_OUTPUT, "样本行数": _MAX_SAMPLE_ROWS, "内存字节": 536870912, "远端临时写入": False},
}
_encoded = _json.dumps(_document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
if len(_encoded.encode("utf-8")) > _MAX_BATCH_OUTPUT:
    raise RuntimeError("batch_output_over_limit")
print(_encoded)
'''
    return (
        template.replace("__PAYLOAD__", repr(payload))
        .replace("__CUTOFF__", repr(cutoff))
        .replace("__SCRIPT_FP__", repr(script_fingerprint))
        .replace("__EXPECTED_SESSION_FP__", repr(EXPECTED_DB_SESSION_FP))
        .replace("__EXPECTED_GRANTS_FP__", repr(EXPECTED_DB_GRANTS_FP))
        .replace("__DB_CONFIG__", db_config_path)
    )


def run_remote_database(database: list[dict[str, str]], cutoff: str, script_fingerprint: str, body_key: Path) -> tuple[dict[str, Any], str]:
    """通过专用密钥调用远端root-owned固定正文入口。

    不接受远程命令或脚本；stdin只发送任务-000070版本化请求，远端入口负责
    白名单、数据库身份、资源上限和脱敏输出。数据库配置文件永远不离开Ubuntu。
    """
    if _key_fingerprint(body_key) != EXPECTED_BODY_KEY_FP:
        raise RuntimeError("正文复采专用密钥指纹不匹配")
    request = {
        "protocol": EXPECTED_BODY_PROTOCOL,
        "operation": "body-audit",
        "payload": {
            "合同版本": "task-000070",
            "覆盖矩阵指纹": EXPECTED_MATRIX_FP,
            "数据截止": cutoff,
            "规则脚本指纹": script_fingerprint,
        },
    }
    command = [
        "ssh", "-i", str(body_key),
        "-o", "User=zhishi_ro",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
        "-o", "PasswordAuthentication=no",
        "-o", "RequestTTY=no",
        "ubuntu",
    ]
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n",
            text=True,
            capture_output=True,
            timeout=650,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("数据库批次超过650秒外部超时") from error
    if completed.returncode != 0:
        raise RuntimeError("数据库只读批次失败关闭")
    if len(completed.stdout.encode("utf-8")) > RESOURCE_CONTRACT["数据库批次最大输出字节"]:
        raise RuntimeError("数据库批次输出超过合同上限")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("数据库只读批次输出不是结构化JSON") from error
    expected_document_keys = {
        "protocol", "wrapper_version", "wrapper_sha256", "operation", "合同版本",
        "覆盖矩阵指纹", "规则脚本指纹", "授权会话指纹", "授权权限快照指纹",
        "对象结果", "资源上限", "远端临时写入",
    }
    if not isinstance(document, dict) or set(document) != expected_document_keys or len(document.get("对象结果", [])) != 92:
        raise RuntimeError("数据库固定入口输出对象数或字段不匹配")
    if (
        document.get("protocol") != EXPECTED_BODY_PROTOCOL
        or document.get("wrapper_version") != EXPECTED_BODY_WRAPPER_VERSION
        or document.get("wrapper_sha256") != EXPECTED_BODY_WRAPPER_FP
        or document.get("operation") != "body-audit"
        or document.get("合同版本") != "task-000070"
        or document.get("覆盖矩阵指纹") != EXPECTED_MATRIX_FP
        or document.get("规则脚本指纹") != script_fingerprint
        or document.get("远端临时写入") is not False
    ):
        raise RuntimeError("数据库固定入口协议或规则指纹漂移")
    if document.get("授权会话指纹") != EXPECTED_DB_SESSION_FP or document.get("授权权限快照指纹") != EXPECTED_DB_GRANTS_FP:
        raise RuntimeError("数据库只读授权指纹不匹配")
    if document.get("资源上限") != {
        "数据库单对象最大读取字节": 65536,
        "数据库单对象最大耗时秒": 30,
        "数据库批次最大耗时秒": 600,
        "数据库批次最大输出字节": 8388608,
        "数据库最大并发": 1,
        "数据库样本最大行数": 64,
        "最大内存字节": 536870912,
        "远端临时写入": False,
    }:
        raise RuntimeError("数据库资源合同漂移")
    expected_keys = {"资产编号", "对象指纹", "状态", "记录数", "已观察记录数", "时间字段指纹", "时间可解析记录数", "时间空值记录数", "未来记录", "Schema指纹", "读取字节数", "耗时毫秒", "错误类别"}
    expected_assets = [item["资产编号"] for item in database]
    for index, item in enumerate(document["对象结果"]):
        if set(item) != expected_keys or item.get("资产编号") != expected_assets[index]:
            raise RuntimeError("数据库对象身份或字段漂移")
        expected_object_fp = sha256_text("MySQL/" + database[index]["数据库"] + "/" + database[index]["表"])
        if item.get("对象指纹") != expected_object_fp or item.get("状态") not in ALLOWED_STATUSES:
            raise RuntimeError("数据库对象指纹或状态漂移")
        if not isinstance(item.get("读取字节数"), int) or not 0 <= item["读取字节数"] <= RESOURCE_CONTRACT["数据库单对象最大读取字节"]:
            raise RuntimeError("数据库对象读取预算漂移")
        if not isinstance(item.get("耗时毫秒"), int) or not 0 <= item["耗时毫秒"] <= RESOURCE_CONTRACT["数据库单对象最大耗时秒"] * 1000:
            raise RuntimeError("数据库对象耗时预算漂移")
        if item.get("已观察记录数") is not None and (not isinstance(item["已观察记录数"], int) or not 0 <= item["已观察记录数"] <= RESOURCE_CONTRACT["数据库样本最大行数"]):
            raise RuntimeError("数据库样本行数漂移")
    return document, completed.stdout


def _key_fingerprint(path: Path) -> str:
    if not path.exists() or not path.is_file():
        raise RuntimeError("日志只读密钥不存在")
    result = subprocess.run(["ssh-keygen", "-lf", str(path), "-E", "sha256"], text=True, capture_output=True, timeout=5, check=False)
    if result.returncode != 0:
        raise RuntimeError("日志只读密钥指纹无法验证")
    fields = result.stdout.split()
    if len(fields) < 2:
        raise RuntimeError("日志只读密钥指纹格式错误")
    return fields[1]


def _validate_log_document(document: Any) -> None:
    if not isinstance(document, dict):
        raise RuntimeError("敏感日志输出结构错误")
    required = {"合同版本", "强制入口指纹", "对象结果", "对象顺序", "批次耗时毫秒", "最大内存字节数", "最大单对象字节数", "最大总读取字节数", "最大耗时秒", "脱敏规则", "远端临时写入"}
    if set(document) != required or document["合同版本"] != "task-000064-log-readonly-v1":
        raise RuntimeError("敏感日志合同或字段漂移")
    if document["对象顺序"] != list(EXPECTED_LOG_ORDER) or document["最大单对象字节数"] != 32768 or document["最大总读取字节数"] != 65536 or document["最大耗时秒"] != 30 or document["最大内存字节数"] != 536870912 or document["远端临时写入"] is not False or document["脱敏规则"] != "仅输出指纹、计数、状态、资源与错误类别；不输出日志字段值":
        raise RuntimeError("敏感日志资源或脱敏合同漂移")
    if document["强制入口指纹"] != EXPECTED_LOG_WRAPPER_FP:
        raise RuntimeError("敏感日志远端包装器指纹漂移")
    entry_proof = sha256_text("|".join((EXPECTED_LOG_TARGET_FP, EXPECTED_LOG_KEY_FP, document["强制入口指纹"], document["合同版本"], document["脱敏规则"])))
    if entry_proof != EXPECTED_LOG_ENTRY_PROOF_FP:
        raise RuntimeError("敏感日志固定强制入口指纹证明不匹配")
    if not isinstance(document["批次耗时毫秒"], int) or not 0 <= document["批次耗时毫秒"] <= 30000:
        raise RuntimeError("敏感日志批次耗时超过合同上限")
    item_keys = {"内容指纹", "文件字节数", "时间字段可解析记录数", "状态", "结构异常记录数", "耗时毫秒", "记录数", "读取字节数", "路径指纹", "错误类别"}
    items = document["对象结果"]
    if not isinstance(items, list) or len(items) != 2:
        raise RuntimeError("敏感日志对象数不是2")
    total_read = 0
    for index, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != item_keys or item["路径指纹"] != EXPECTED_LOG_ORDER[index] or item["状态"] not in ALLOWED_STATUSES:
            raise RuntimeError("敏感日志对象字段或路径指纹漂移")
        if not isinstance(item["内容指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["内容指纹"]):
            raise RuntimeError("敏感日志内容指纹格式错误")
        for key in ("文件字节数", "时间字段可解析记录数", "结构异常记录数", "耗时毫秒", "记录数", "读取字节数"):
            if not isinstance(item[key], int) or item[key] < 0:
                raise RuntimeError("敏感日志计数字段错误")
        if item["文件字节数"] > 32768 or item["读取字节数"] > 32768:
            raise RuntimeError("敏感日志对象超过读取上限")
        total_read += item["读取字节数"]
        if not (item["错误类别"] is None or isinstance(item["错误类别"], str)):
            raise RuntimeError("敏感日志错误字段错误")
    if total_read > 65536:
        raise RuntimeError("敏感日志批次读取超过合同上限")


def run_remote_logs(log_target: str, log_key: Path) -> tuple[dict[str, Any], str]:
    if sha256_text(log_target) != EXPECTED_LOG_TARGET_FP or _key_fingerprint(log_key) != EXPECTED_LOG_KEY_FP:
        raise RuntimeError("敏感日志固定入口或密钥指纹不匹配")
    command = ["ssh", "-i", str(log_key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o", "PasswordAuthentication=no", log_target]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=40, check=False)
    if completed.returncode != 0:
        raise RuntimeError("敏感日志固定入口失败关闭")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("敏感日志输出不是结构化JSON") from error
    _validate_log_document(document)
    return document, completed.stdout


def stable_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def write_json(path: Path, document: Any) -> None:
    path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build_report(batch_id: str, metadata: dict[str, Any], summary: dict[str, int], results: list[dict[str, Any]]) -> str:
    lines = [
        "# Ubuntu未完整扫描对象正文质量复验报告", "", "<!-- markdownlint-disable MD013 MD024 MD025 -->", "",
        f"- 审计批次：`{batch_id}`", f"- 合同版本指纹：`{metadata['合同版本指纹']}`", f"- 覆盖矩阵指纹：`{metadata['覆盖矩阵指纹']}`", f"- 规则脚本指纹：`{metadata['规则脚本指纹']}`",
        f"- 数据库对象：92；敏感日志文件：2；合同授权截止：`{metadata['合同授权截止']}`；本批次数据截止：`{metadata['数据截止']}`",
        "- 远端入口：仅使用白名单逻辑别名的固定指纹；不写入远端临时文件，不输出用户名、原始日志或业务字段值。", "",
        "## 状态摘要", "", "| 状态 | 对象数 |", "| --- | ---: |",
    ]
    for status in ("通过", "拒绝", "无法判定", "失败", "未成熟", "失效", "未执行"):
        lines.append(f"| {status} | {summary.get(status, 0)} |")
    lines += [
        f"| 合计 | {sum(summary.values())} |", "", "## 资源与安全", "",
        "- 数据库仅在EXPLAIN证明可使用索引后读取单个时间字段的最多64行；每个对象输出最多65536字节、30秒，批次最多600秒/8MiB，串行执行，远端进程内存上限512MiB。",
        "- 未执行COUNT、MIN、MAX或无界全表聚合；无法证明有界索引路径的对象保持无法判定，空样本不解释为未成熟。",
        "- 数据库与日志只输出指纹、计数、状态、资源和错误类别；发生权限不足、超时、未来时间、输入漂移、输出不完整或敏感信息泄漏时失败关闭。",
        "- 这批次不计算胜率、收益、方向、仓位、订单或交易许可；不关闭ZS-DATA-GAP-003/005，不放行阶段2。", "",
        "## 逐对象脱敏证据", "", "逐对象结果保存在同批次`对象结果.json`；仅包含资产编号、对象指纹、状态、计数、资源与错误类别。", "",
        "| 资产编号 | 状态 | 记录数 | 已观察记录数 | 错误类别 |", "| --- | --- | ---: | ---: | --- |",
    ]
    for result in results:
        lines.append(f"| {result.get('资产编号', '')} | {result.get('状态', '失败')} | {result.get('记录数') if result.get('记录数') is not None else '—'} | {result.get('已观察记录数') if result.get('已观察记录数') is not None else '—'} | {result.get('错误类别') or '—'} |")
    lines += [
        "", "## 结论与限制", "", "- 本批次只证明白名单对象在当前截止事实下可执行的结构性质量观察；描述性状态不能推导因果、预测优势、胜率、收益或交易许可。",
        "- 三个输入身份漂移文件不在本批次授权范围，继续沿用任务-000063的拒绝事实；BTC/ETH不跨标的补偿，SOL不进入前向范围。",
        "- 数据库有界样本不能替代全量正文质量证明；无法判定、失败和未成熟状态均保留，不缩小分母。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--log-target", required=True)
    parser.add_argument("--log-key", required=True)
    parser.add_argument("--body-key", default=DEFAULT_BODY_KEY_PATH, help="专用正文复采密钥的受限本地路径")
    args = parser.parse_args()
    if not re.fullmatch(r"批次-\d{8}T\d{6}Z-v\d+", args.batch_id):
        raise RuntimeError("批次标识格式错误")
    if args.cutoff != FROZEN_DATA_CUTOFF:
        raise RuntimeError("数据截止不是已批准冻结时点")
    cutoff = dt.datetime.fromisoformat(args.cutoff)
    if cutoff.tzinfo is None or cutoff > dt.datetime.now(cutoff.tzinfo):
        raise RuntimeError("数据截止不能晚于当前时间")
    if sha256_bytes(CONTRACT.read_bytes()) != EXPECTED_CONTRACT_FP:
        raise RuntimeError("授权合同指纹漂移，安全停止")
    database, logs = load_targets()
    batch_root = ROOT / "artifacts/审计/Ubuntu未完整扫描对象正文质量复验" / args.batch_id
    if batch_root.exists() or any(part in {".", ".."} for part in Path(args.batch_id).parts):
        raise RuntimeError("批次路径已存在或非法")
    report_path = ROOT / "docs/审计/Ubuntu未完整扫描对象正文质量复验报告.md"
    previous_report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    started = stable_now()
    script_fp = sha256_text(Path(__file__).read_text(encoding="utf-8"))
    matrix_fp = sha256_bytes(MATRIX.read_bytes())
    contract_fp = sha256_bytes(CONTRACT.read_bytes())
    logs_document, logs_raw = run_remote_logs(args.log_target, Path(args.log_key))
    body_key = Path(args.body_key).expanduser()
    database_document, database_raw = run_remote_database(database, args.cutoff, script_fp, body_key)
    results = list(database_document["对象结果"])
    for index, item in enumerate(logs_document["对象结果"]):
        result = dict(item)
        result["资产编号"] = logs[index]["资产编号"]
        result["对象指纹"] = EXPECTED_LOG_ORDER[index]
        results.append(result)
    if len(results) != 94:
        raise RuntimeError("合并后的对象结果不是94")
    statuses = {status: 0 for status in ALLOWED_STATUSES}
    for result in results:
        if result.get("状态") not in statuses:
            raise RuntimeError("出现未注册状态")
        statuses[result["状态"]] += 1
    ended = stable_now()
    metadata = {
        "批次": args.batch_id, "开始时间": started.isoformat(), "结束时间": ended.isoformat(),
        "合同授权截止": AUTHORIZATION_DEADLINE, "数据截止": args.cutoff, "合同版本指纹": contract_fp,
        "覆盖矩阵指纹": matrix_fp, "规则脚本指纹": script_fp,
        "数据库远端输出指纹": sha256_text(database_raw), "日志远端输出指纹": sha256_text(logs_raw),
        "日志固定入口指纹": EXPECTED_LOG_WRAPPER_FP,
        "授权输入指纹": {
            "数据库会话": EXPECTED_DB_SESSION_FP,
            "数据库权限快照": EXPECTED_DB_GRANTS_FP,
            "正文固定入口": EXPECTED_BODY_WRAPPER_FP,
            "正文对象清单": EXPECTED_BODY_TARGETS_FP,
            "正文专用密钥": EXPECTED_BODY_KEY_FP,
            "日志目标": EXPECTED_LOG_TARGET_FP,
            "日志密钥": EXPECTED_LOG_KEY_FP,
            "日志强制入口": EXPECTED_LOG_WRAPPER_FP,
        },
        "资源合同": RESOURCE_CONTRACT,
        "对象总数": len(results), "状态计数": statuses,
        "安全声明": {"原始数据修改": False, "远端临时写入": False, "日志正文输出": False, "业务字段输出": False, "未来数据使用": False, "交易结论": False},
    }
    batch_root.mkdir(parents=True)
    write_json(batch_root / "批次元数据.json", metadata)
    write_json(batch_root / "对象结果.json", results)
    write_json(batch_root / "状态摘要.json", statuses)
    current_report = build_report(args.batch_id, metadata, statuses, results)
    if previous_report:
        current_report = previous_report.rstrip() + "\n\n---\n\n" + current_report
    report_path.write_text(current_report, encoding="utf-8")
    print(json.dumps({"批次": args.batch_id, "报告": str(report_path.relative_to(ROOT)), "对象总数": len(results), "状态计数": statuses, "批次指纹": sha256_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True))}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"安全停止：{error}", file=sys.stderr)
        raise SystemExit(2)
