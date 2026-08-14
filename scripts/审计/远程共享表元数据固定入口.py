#!/usr/bin/env python3
"""任务-000071专用、元数据只读的远端强制入口。

入口只接受固定协议和固定16个对象，查询 information_schema.COLUMNS/STATISTICS，
并只返回列/索引计数与指纹。它不接受任意SQL、远程命令、业务字段或交互终端。
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


PROTOCOL = "zhishi-ro/schema-audit/1"
WRAPPER_VERSION = "zhishi-ro-schema-audit-1.1"
CONTRACT_VERSION = "task-000071"
MATRIX_FINGERPRINT = "6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79"
TARGETS_PATH = Path("/usr/local/libexec/zhishi_ro_schema_targets.json")
TARGETS_FINGERPRINT = "8ba1b762c7739efd45a53b48f861d848cba21c2dea3f584093a28c071e4cc7e9"
DB_CONFIG_PATH = "/home/zhishi_ro/.zhishi_audit_ro.cnf"
EXPECTED_SESSION_FINGERPRINT = "2e642610c2d0f286f489b5226081f23077a8674bffb0e255c8cea98825601943"
EXPECTED_GRANTS_FINGERPRINT = "ad26cec63d094b7a68f4229ca4668a36eaa9aee7343970d8dfc6e8f9c6631a2e"
RESOURCE_CONTRACT = {
    "单对象字节": 65536,
    "单对象秒": 30,
    "批次秒": 300,
    "批次输出字节": 4194304,
    "最大并发": 1,
    "最大内存字节": 268435456,
    "远端临时写入": False,
}
RESOURCE_CONTRACT_FINGERPRINT = "e1848916ced2bc3343ca0bda53e985add32070630c3ece8af317ac62e631e8b4"
FROZEN_DATA_CUTOFF = "2026-08-06T12:00:00+08:00"


class ProtocolError(ValueError):
    pass


def _fp(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("duplicate-key")
        value[key] = item
    return value


def _wrapper_sha256() -> str:
    try:
        return _fp(Path(__file__).read_bytes())
    except OSError:
        return ""


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


def _parse_request(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > 4096:
        raise ProtocolError("request-too-large")
    try:
        request = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ProtocolError) as error:
        raise ProtocolError("invalid-json") from error
    if not isinstance(request, dict) or set(request) != {"protocol", "operation", "payload"}:
        raise ProtocolError("request-fields")
    if request["protocol"] != PROTOCOL or request["operation"] != "schema-audit":
        raise ProtocolError("request-operation")
    payload = request["payload"]
    required = {"合同版本", "覆盖矩阵指纹", "对象清单指纹", "资源合同指纹", "数据截止", "规则脚本指纹"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ProtocolError("request-payload")
    if payload["合同版本"] != CONTRACT_VERSION:
        raise ProtocolError("contract-mismatch")
    if payload["覆盖矩阵指纹"] != MATRIX_FINGERPRINT:
        raise ProtocolError("matrix-mismatch")
    if payload["对象清单指纹"] != TARGETS_FINGERPRINT:
        raise ProtocolError("targets-mismatch")
    if payload["资源合同指纹"] != RESOURCE_CONTRACT_FINGERPRINT:
        raise ProtocolError("resource-contract-mismatch")
    script_fp = payload["规则脚本指纹"]
    if not isinstance(script_fp, str) or len(script_fp) != 64 or any(char not in "0123456789abcdef" for char in script_fp):
        raise ProtocolError("script-fingerprint")
    try:
        cutoff = dt.datetime.fromisoformat(payload["数据截止"])
    except (TypeError, ValueError) as error:
        raise ProtocolError("cutoff-format") from error
    if payload["数据截止"] != FROZEN_DATA_CUTOFF or cutoff.tzinfo is None or cutoff > dt.datetime.now(cutoff.tzinfo):
        raise ProtocolError("cutoff-invalid")
    return request


def _load_targets() -> list[dict[str, str]]:
    raw = TARGETS_PATH.read_bytes()
    if _fp(raw) != TARGETS_FINGERPRINT:
        raise RuntimeError("targets-fingerprint")
    value = json.loads(raw.decode("utf-8"))
    if set(value) != {"对象", "覆盖矩阵指纹"} or value["覆盖矩阵指纹"] != MATRIX_FINGERPRINT:
        raise RuntimeError("targets-contract")
    objects = value["对象"]
    if not isinstance(objects, list) or len(objects) != 16:
        raise RuntimeError("targets-count")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"资产编号", "数据库", "表"}:
            raise RuntimeError("target-fields")
        asset, database, table = item["资产编号"], item["数据库"], item["表"]
        if not all(isinstance(value, str) and value for value in (asset, database, table)):
            raise RuntimeError("target-types")
        if not database.replace("_", "").isalnum() or not table.replace("_", "").isalnum():
            raise RuntimeError("target-identifier")
        identity = (database, table)
        if identity in seen:
            raise RuntimeError("target-duplicate")
        seen.add(identity)
        result.append({"资产编号": asset, "数据库": database, "表": table})
    return result


def _lit(value: str) -> str:
    if "'" in value or "\\" in value or any(ord(char) < 32 for char in value):
        raise ValueError("literal-rejected")
    return "'" + value + "'"


def _mysql(sql: str, deadline: float) -> dict[str, Any]:
    if "information_schema" not in sql and "CURRENT_USER" not in sql and "SHOW GRANTS" not in sql:
        raise RuntimeError("non-metadata-query")
    timeout = min(25.0, deadline - time.monotonic())
    if timeout <= 0:
        return {"ok": False, "error": "object-timeout", "bytes": 0, "stdout": ""}
    command = [
        "mysql", f"--defaults-extra-file={DB_CONFIG_PATH}", "--batch", "--raw", "--skip-column-names", "--quick",
        "--connect-timeout=5", "--init-command=SET SESSION max_execution_time=25000", "-e", sql,
    ]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "query-timeout", "bytes": 0, "stdout": ""}
    stdout = completed.stdout.encode("utf-8", errors="replace")
    if len(stdout) > RESOURCE_CONTRACT["单对象字节"]:
        return {"ok": False, "error": "query-output-over-limit", "bytes": len(stdout), "stdout": ""}
    if completed.returncode != 0:
        return {"ok": False, "error": "query-failed", "bytes": len(stdout), "stdout": ""}
    return {"ok": True, "error": None, "bytes": len(stdout), "stdout": completed.stdout}


def _one(item: dict[str, str], deadline: float) -> dict[str, Any]:
    started = time.monotonic()
    object_deadline = min(deadline, started + RESOURCE_CONTRACT["单对象秒"])
    result: dict[str, Any] = {
        "资产编号": item["资产编号"],
        "表身份指纹": _fp("MySQL/" + item["数据库"] + "/" + item["表"]),
        "表": item["表"],
        "采集状态": "失败",
        "列数": None,
        "列指纹": None,
        "索引数": None,
        "索引指纹": None,
        "读取字节数": 0,
        "耗时毫秒": 0,
        "原因码": None,
    }
    try:
        columns = _mysql(
            "SELECT COLUMN_NAME, COLUMN_TYPE, ORDINAL_POSITION, IS_NULLABLE, COLUMN_KEY FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=" + _lit(item["数据库"]) + " AND TABLE_NAME=" + _lit(item["表"]) +
            " ORDER BY ORDINAL_POSITION;", object_deadline
        )
        result["读取字节数"] += columns["bytes"]
        if not columns["ok"]:
            result["原因码"] = columns["error"]
            return result
        column_rows: list[str] = []
        for line in columns["stdout"].splitlines():
            fields = line.split("\t")
            if not line or len(fields) != 5 or not fields[2].isdigit() or not fields[0] or not fields[1] or fields[3].casefold() not in {"yes", "no"} or fields[4].casefold() not in {"", "pri", "uni", "mul"}:
                result["原因码"] = "malformed-column-row"
                return result
            column_rows.append(f"{fields[0].casefold()}:{fields[1].casefold()}:{fields[2]}:{fields[3].casefold()}:{fields[4].casefold()}")
        if not column_rows:
            result["采集状态"], result["原因码"] = "未发现", "table-not-found"
            return result
        if time.monotonic() >= object_deadline:
            result["原因码"] = "object-timeout"
            return result
        result["列数"] = len(column_rows)
        result["列指纹"] = _fp("|".join(column_rows))
        indexes = _mysql(
            "SELECT INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE, INDEX_TYPE FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA=" + _lit(item["数据库"]) + " AND TABLE_NAME=" + _lit(item["表"]) +
            " ORDER BY LOWER(INDEX_NAME), SEQ_IN_INDEX, LOWER(COLUMN_NAME);", object_deadline
        )
        result["读取字节数"] += indexes["bytes"]
        if not indexes["ok"]:
            result["原因码"] = indexes["error"]
            return result
        index_rows: list[str] = []
        for line in indexes["stdout"].splitlines():
            fields = line.split("\t")
            if not line or len(fields) != 5 or not fields[1].isdigit() or not fields[0] or not fields[2] or fields[3] not in {"0", "1"} or not fields[4]:
                result["原因码"] = "malformed-index-row"
                return result
            index_rows.append(f"{fields[0].casefold()}:{fields[1]}:{fields[2].casefold()}:{fields[3]}:{fields[4].casefold()}")
        result["索引数"] = len(index_rows)
        result["索引指纹"] = _fp("|".join(index_rows))
        result["采集状态"], result["原因码"] = "已采集", "metadata-only"
    except (OSError, TypeError, ValueError, RuntimeError):
        result["原因码"] = "safe-parser-failure"
    finally:
        result["耗时毫秒"] = int((time.monotonic() - started) * 1000)
        if result["耗时毫秒"] > RESOURCE_CONTRACT["单对象秒"] * 1000:
            result["采集状态"], result["原因码"] = "失败", "object-timeout"
    return result


def _set_limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (RESOURCE_CONTRACT["最大内存字节"], RESOURCE_CONTRACT["最大内存字节"]))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(RESOURCE_CONTRACT["批次秒"])


def schema_audit(request: dict[str, Any]) -> dict[str, Any]:
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
        if time.monotonic() - started > RESOURCE_CONTRACT["批次秒"] - 10:
            results.append({"资产编号": item["资产编号"], "表身份指纹": _fp("MySQL/" + item["数据库"] + "/" + item["表"]), "表": item["表"], "采集状态": "失败", "列数": None, "列指纹": None, "索引数": None, "索引指纹": None, "读取字节数": 0, "耗时毫秒": 0, "原因码": "batch-timeout"})
        else:
            results.append(_one(item, started + RESOURCE_CONTRACT["批次秒"]))
    document = {
        "protocol": PROTOCOL,
        "wrapper_version": WRAPPER_VERSION,
        "wrapper_sha256": _wrapper_sha256(),
        "operation": "schema-audit",
        "合同版本": CONTRACT_VERSION,
        "覆盖矩阵指纹": MATRIX_FINGERPRINT,
        "对象清单指纹": TARGETS_FINGERPRINT,
        "规则脚本指纹": request["payload"]["规则脚本指纹"],
        "授权会话指纹": _fp(session["stdout"]),
        "授权权限快照指纹": _fp(grants["stdout"]),
        "对象结果": results,
        "资源合同": RESOURCE_CONTRACT,
        "远端临时写入": False,
    }
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(raw.encode("utf-8")) > RESOURCE_CONTRACT["批次输出字节"]:
        raise RuntimeError("batch-output-over-limit")
    return document


def main() -> int:
    try:
        _set_limits()
        if os.environ.get("SSH_ORIGINAL_COMMAND"):
            response = _reject("original-command")
        else:
            response = schema_audit(_parse_request(sys.stdin.read(4097)))
            response["status"] = "通过"
    except (OSError, ProtocolError, RuntimeError, ValueError, TypeError) as error:
        response = _reject(str(error)[:64] or "safe-failure")
    sys.stdout.write(json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if response.get("status") == "通过" else 1


if __name__ == "__main__":
    raise SystemExit(main())
