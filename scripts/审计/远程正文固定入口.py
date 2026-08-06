#!/usr/bin/env python3
"""任务-000070专用正文固定入口。

该文件部署为远端root-owned强制命令；只接受版本化的正文复采请求。
对象白名单、数据库配置路径、资源上限和审计语义均固定在入口中，
不接受任意脚本、任意SQL、交互终端或未登记对象。输出只包含脱敏状态、
计数、指纹和资源事实，不输出业务字段值或错误正文。
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
from typing import Any


PROTOCOL = "zhishi-ro/2"
WRAPPER_VERSION = "zhishi-ro-body-audit-1.0"
CONTRACT_VERSION = "task-000070"
MATRIX_FINGERPRINT = "6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79"
TARGETS_PATH = Path("/usr/local/libexec/zhishi_ro_body_targets.json")
TARGETS_FINGERPRINT = "1c8adccb082d30ff37ff456b139c5560a716f55e208450e8945ddfabce11e187"
DB_CONFIG_PATH = "/home/zhishi_ro/.zhishi_audit_ro.cnf"
EXPECTED_SESSION_FINGERPRINT = "2e642610c2d0f286f489b5226081f23077a8674bffb0e255c8cea98825601943"
EXPECTED_GRANTS_FINGERPRINT = "ad26cec63d094b7a68f4229ca4668a36eaa9aee7343970d8dfc6e8f9c6631a2e"
RESOURCE_CONTRACT = {
    "数据库单对象最大读取字节": 65536,
    "数据库单对象最大耗时秒": 30,
    "数据库批次最大耗时秒": 600,
    "数据库批次最大输出字节": 8388608,
    "数据库最大并发": 1,
    "数据库样本最大行数": 64,
    "最大内存字节": 536870912,
    "远端临时写入": False,
}
RESOURCE_CONTRACT_FINGERPRINT = "d28c31bbc213b0aaa5586f7cb40ba67bac7039065d8fac60bc99620352e93edc"
FROZEN_DATA_CUTOFF = "2026-08-06T12:00:00+08:00"
ALLOWED_STATUSES = {"通过", "拒绝", "无法判定", "失败", "未成熟", "失效", "未执行"}


class ProtocolError(ValueError):
    pass


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate-key")
        result[key] = value
    return result


def _reject(reason: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "wrapper_version": WRAPPER_VERSION,
        "wrapper_sha256": _wrapper_sha256(),
        "operation": "",
        "status": "拒绝",
        "reason_code": reason,
        "远端临时写入": False,
    }


def _wrapper_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return ""


def _parse_request(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > 4096:
        raise ProtocolError("request-too-large")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ProtocolError) as error:
        raise ProtocolError("invalid-json") from error
    if not isinstance(value, dict) or set(value) != {"protocol", "operation", "payload"}:
        raise ProtocolError("request-fields")
    if value.get("protocol") != PROTOCOL or value.get("operation") != "body-audit":
        raise ProtocolError("request-operation")
    payload = value.get("payload")
    if not isinstance(payload, dict) or set(payload) != {
        "合同版本", "覆盖矩阵指纹", "对象清单指纹", "资源合同指纹", "数据截止", "规则脚本指纹"
    }:
        raise ProtocolError("request-payload")
    if payload["合同版本"] != CONTRACT_VERSION:
        raise ProtocolError("contract-mismatch")
    if payload["覆盖矩阵指纹"] != MATRIX_FINGERPRINT:
        raise ProtocolError("matrix-mismatch")
    if payload["对象清单指纹"] != TARGETS_FINGERPRINT:
        raise ProtocolError("targets-mismatch")
    if payload["资源合同指纹"] != RESOURCE_CONTRACT_FINGERPRINT:
        raise ProtocolError("resource-contract-mismatch")
    if not isinstance(payload["数据截止"], str) or not isinstance(payload["规则脚本指纹"], str):
        raise ProtocolError("payload-type")
    if len(payload["规则脚本指纹"]) != 64 or any(c not in "0123456789abcdef" for c in payload["规则脚本指纹"]):
        raise ProtocolError("script-fingerprint")
    try:
        cutoff = dt.datetime.fromisoformat(payload["数据截止"])
    except ValueError as error:
        raise ProtocolError("cutoff-format") from error
    if payload["数据截止"] != FROZEN_DATA_CUTOFF or cutoff.tzinfo is None or cutoff > dt.datetime.now(cutoff.tzinfo):
        raise ProtocolError("cutoff-invalid")
    return value


def _load_targets() -> list[dict[str, str]]:
    raw = TARGETS_PATH.read_bytes()
    if _fp(raw.decode("utf-8")) != TARGETS_FINGERPRINT:
        raise RuntimeError("targets-fingerprint")
    value = json.loads(raw.decode("utf-8"))
    if set(value) != {"覆盖矩阵指纹", "对象"} or value["覆盖矩阵指纹"] != MATRIX_FINGERPRINT:
        raise RuntimeError("targets-contract")
    objects = value["对象"]
    if not isinstance(objects, list) or len(objects) != 92:
        raise RuntimeError("targets-count")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"资产编号", "数据库", "表"}:
            raise RuntimeError("target-fields")
        db, table, asset = item["数据库"], item["表"], item["资产编号"]
        if not all(isinstance(v, str) and v and v.replace("_", "").isalnum() for v in (db, table)):
            raise RuntimeError("target-identifier")
        if (db, table) in seen:
            raise RuntimeError("target-duplicate")
        seen.add((db, table))
        result.append({"资产编号": asset, "数据库": db, "表": table})
    return result


def _ident(value: str) -> str:
    if not value or not value.replace("_", "").isalnum():
        raise ValueError("identifier-rejected")
    return "`" + value.replace("`", "``") + "`"


def _lit(value: str) -> str:
    if "'" in value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("literal-rejected")
    return "'" + value + "'"


def _mysql(sql: str, deadline: float) -> dict[str, Any]:
    timeout = min(25.0, deadline - time.monotonic())
    if timeout <= 0:
        return {"ok": False, "error": "object-timeout", "bytes": 0}
    command = [
        "mysql", f"--defaults-extra-file={DB_CONFIG_PATH}", "--batch", "--raw",
        "--skip-column-names", "--quick", "--connect-timeout=5",
        "--init-command=SET SESSION max_execution_time=25000", "-e", sql,
    ]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "query-timeout", "bytes": 0}
    stdout = completed.stdout.encode("utf-8", errors="replace")
    if len(stdout) > RESOURCE_CONTRACT["数据库单对象最大读取字节"]:
        return {"ok": False, "error": "query-output-over-limit", "bytes": len(stdout)}
    if completed.returncode != 0:
        return {"ok": False, "error": "query-failed", "bytes": len(stdout)}
    return {"ok": True, "stdout": completed.stdout, "bytes": len(stdout)}


def _parse_time(value: str | None) -> dt.datetime | None:
    if not value or value == "NULL":
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _one(item: dict[str, str], cutoff: dt.datetime) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + RESOURCE_CONTRACT["数据库单对象最大耗时秒"]
    result: dict[str, Any] = {
        "资产编号": item["资产编号"],
        "对象指纹": _fp("MySQL/" + item["数据库"] + "/" + item["表"]),
        "状态": "失败", "记录数": None, "已观察记录数": None,
        "时间字段指纹": None, "时间可解析记录数": None, "时间空值记录数": None,
        "未来记录": None, "Schema指纹": None, "读取字节数": 0,
        "耗时毫秒": 0, "错误类别": None,
    }
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
        columns: list[tuple[str, str]] = []
        for line in metadata["stdout"].splitlines():
            fields = line.split("\t")
            if len(fields) == 2:
                columns.append((fields[0], fields[1].lower()))
        result["Schema指纹"] = _fp("|".join(name + ":" + kind for name, kind in columns))
        candidates = [
            (name, kind) for name, kind in columns
            if kind in {"date", "datetime", "timestamp", "bigint", "int", "integer", "decimal"}
            and any(token in name.lower() for token in (
                "time", "date", "timestamp", "created", "updated", "event", "occurred",
                "received", "arrived", "start", "end",
            ))
        ]
        if not candidates:
            result["状态"], result["错误类别"] = "无法判定", "no-freezable-time-field"
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
        indexed = {line.split("\t", 1)[0] for line in stats["stdout"].splitlines() if "\t" in line}
        chosen = next((value for value in candidates if value[0] in indexed), None)
        if chosen is None:
            result["状态"], result["错误类别"] = "无法判定", "time-field-not-indexed"
            return result
        field = chosen[0]
        result["时间字段指纹"] = _fp(field)
        explain = _mysql(
            "EXPLAIN SELECT " + _ident(field) + " FROM " + _ident(db) + "." + _ident(table) +
            " ORDER BY " + _ident(field) + " DESC LIMIT 64;", deadline
        )
        result["读取字节数"] += explain.get("bytes", 0)
        if not explain["ok"]:
            result["错误类别"] = explain["error"]
            return result
        plan = explain["stdout"].strip().split("\t")
        if len(plan) < 7 or plan[4].upper() == "ALL" or plan[6] in {"", "NULL"}:
            result["状态"], result["错误类别"] = "无法判定", "bounded-index-not-proven"
            return result
        sample = _mysql(
            "SELECT " + _ident(field) + " FROM " + _ident(db) + "." + _ident(table) +
            " ORDER BY " + _ident(field) + " DESC LIMIT 64;", deadline
        )
        result["读取字节数"] += sample.get("bytes", 0)
        if not sample["ok"]:
            result["错误类别"] = sample["error"]
            return result
        if result["读取字节数"] > RESOURCE_CONTRACT["数据库单对象最大读取字节"]:
            result["错误类别"] = "object-output-over-limit"
            return result
        values = [line.strip() for line in sample["stdout"].splitlines() if line.strip()]
        result["已观察记录数"] = len(values)
        if not values:
            result["状态"], result["错误类别"] = "无法判定", "empty-sample-not-maturity"
            return result
        parsed = [_parse_time(value) for value in values]
        result["时间可解析记录数"] = sum(value is not None for value in parsed)
        result["时间空值记录数"] = len(values) - result["时间可解析记录数"]
        maximum = next((value for value in parsed if value is not None), None)
        result["未来记录"] = bool(maximum is not None and maximum > cutoff)
        result["状态"] = "失败" if result["未来记录"] else "无法判定"
        result["错误类别"] = "future-timestamp-detected" if result["未来记录"] else "bounded-sample-only"
    except (OSError, TypeError, ValueError, TimeoutError):
        result["错误类别"] = "safe-parser-failure"
    finally:
        result["耗时毫秒"] = int((time.monotonic() - started) * 1000)
        if result["耗时毫秒"] > RESOURCE_CONTRACT["数据库单对象最大耗时秒"] * 1000:
            result["状态"], result["错误类别"] = "失败", "object-timeout"
    return result


def _set_limits() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (RESOURCE_CONTRACT["最大内存字节"], RESOURCE_CONTRACT["最大内存字节"]))
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.alarm(RESOURCE_CONTRACT["数据库批次最大耗时秒"])
    except (OSError, ValueError) as error:
        raise RuntimeError("resource-limit-failed") from error


def body_audit(request: dict[str, Any]) -> dict[str, Any]:
    payload = request["payload"]
    cutoff = dt.datetime.fromisoformat(payload["数据截止"])
    targets = _load_targets()
    session = _mysql("SELECT CURRENT_USER();", time.monotonic() + 20)
    grants = _mysql("SHOW GRANTS;", time.monotonic() + 20)
    if not session["ok"] or not grants["ok"]:
        raise RuntimeError("readonly-authorization-failed")
    if _fp(session["stdout"]) != EXPECTED_SESSION_FINGERPRINT:
        raise RuntimeError("session-fingerprint")
    if _fp(grants["stdout"]) != EXPECTED_GRANTS_FINGERPRINT:
        raise RuntimeError("grants-fingerprint")
    started = time.monotonic()
    results: list[dict[str, Any]] = []
    for item in targets:
        if time.monotonic() - started > RESOURCE_CONTRACT["数据库批次最大耗时秒"] - 10:
            results.append({"资产编号": item["资产编号"], "对象指纹": _fp("MySQL/" + item["数据库"] + "/" + item["表"]), "状态": "失败", "记录数": None, "已观察记录数": None, "时间字段指纹": None, "时间可解析记录数": None, "时间空值记录数": None, "未来记录": None, "Schema指纹": None, "读取字节数": 0, "耗时毫秒": 0, "错误类别": "batch-timeout"})
        else:
            results.append(_one(item, cutoff))
    document = {
        "protocol": PROTOCOL,
        "wrapper_version": WRAPPER_VERSION,
        "wrapper_sha256": _wrapper_sha256(),
        "operation": "body-audit",
        "合同版本": CONTRACT_VERSION,
        "覆盖矩阵指纹": MATRIX_FINGERPRINT,
        "规则脚本指纹": payload["规则脚本指纹"],
        "授权会话指纹": _fp(session["stdout"]),
        "授权权限快照指纹": _fp(grants["stdout"]),
        "对象结果": results,
        "资源上限": RESOURCE_CONTRACT,
        "远端临时写入": False,
    }
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(raw.encode("utf-8")) > RESOURCE_CONTRACT["数据库批次最大输出字节"]:
        raise RuntimeError("batch-output-over-limit")
    return document


def main() -> int:
    try:
        _set_limits()
        if os.environ.get("SSH_ORIGINAL_COMMAND"):
            response = _reject("original-command")
        else:
            raw = sys.stdin.read(4097)
            response = body_audit(_parse_request(raw))
    except (OSError, ProtocolError, RuntimeError, ValueError, TypeError) as error:
        response = _reject(str(error)[:64] or "safe-failure")
    sys.stdout.write(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if response.get("status", "通过") == "通过" else 1


if __name__ == "__main__":
    raise SystemExit(main())
