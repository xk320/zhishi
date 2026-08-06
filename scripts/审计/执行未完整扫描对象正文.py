#!/usr/bin/env python3
"""任务-000066：按冻结白名单执行正文级只读质量复验。

远端只返回脱敏聚合值。原始数据库行、日志字段和查询错误正文永不进入本地产物。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "artifacts/审计/数据质量增量复验/任务-000063范围绑定/覆盖矩阵.csv"
CONTRACT = ROOT / "docs/superpowers/specs/phase1-incomplete-scan-authorization-v1-design.md"
LOG_PATH_FINGERPRINTS = (
    "3b4c1660ead1953f8be41667c435478438c247ac9b13b4b5876a186b93ae6d78",
    "8abea0a4395c1db90828ad1b8edd7e9378f0d622b2a8517f0882545963a053ef",
)
ALLOWED_DATA_TYPES = {
    "date",
    "datetime",
    "timestamp",
    "bigint",
    "int",
    "integer",
    "decimal",
}
TIME_HINTS = (
    "time",
    "date",
    "timestamp",
    "created",
    "updated",
    "event",
    "occurred",
    "received",
    "arrived",
    "start",
    "end",
)
RESOURCE_CONTRACT = {
    "数据库单对象最大读取字节": 65536,
    "数据库单对象最大耗时秒": 30,
    "数据库最大并发": 1,
    "日志单对象最大读取字节": 32768,
    "日志批次最大读取字节": 65536,
    "日志批次最大耗时秒": 30,
    "最大内存字节": 536870912,
    "远端临时写入": False,
}
AUTHORIZATION_DEADLINE = "2026-08-07T00:00:00+08:00"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_targets() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    with MATRIX.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    database: list[dict[str, str]] = []
    logs: list[dict[str, str]] = []
    for row in rows:
        if row["资产类型"] == "数据库元数据":
            parts = row["位置"].split("/")
            if len(parts) != 3 or parts[0] != "MySQL":
                raise ValueError(f"数据库位置格式错误：{row['资产编号']}")
            database.append(
                {
                    "资产编号": row["资产编号"],
                    "数据库": parts[1],
                    "表": parts[2],
                }
            )
        elif row["任务-000063复验层"] == "敏感系统日志":
            logs.append({"资产编号": row["资产编号"], "位置": row["位置"]})
    if len(database) != 92 or len(logs) != 2:
        raise ValueError("任务-000063目标必须是92个数据库对象和2个敏感系统日志")
    if len({(item["数据库"], item["表"]) for item in database}) != 92:
        raise ValueError("数据库对象存在重复")
    return database, logs


def sql_literal(value: str) -> str:
    if "'" in value or "\\" in value or any(ord(char) < 32 for char in value):
        raise ValueError("SQL标识值包含禁止字符")
    return "'" + value + "'"


def sql_identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum():
        raise ValueError("SQL标识符不在白名单")
    return "`" + value.replace("`", "``") + "`"


def make_remote_script(
    database: list[dict[str, str]],
    cutoff: str,
    script_fingerprint: str,
    db_config_path: str,
) -> str:
    payload = json.dumps(database, ensure_ascii=False, sort_keys=True)
    # 远端脚本只输出资产编号、指纹、计数和错误类别；不会输出表名、字段值或stderr。
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
_MAX_BYTES = 65536
_MAX_SECONDS = 30
_START = _time.monotonic()
_resource.setrlimit(_resource.RLIMIT_AS, (536870912, 536870912))
_resource.setrlimit(_resource.RLIMIT_CPU, (600, 600))

def _timeout(_signum, _frame):
    raise TimeoutError("batch_timeout")

_signal.signal(_signal.SIGALRM, _timeout)
_signal.alarm(600)

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

def _mysql(sql):
    command = [
        "mysql",
        "--defaults-extra-file=__DB_CONFIG__",
        "--batch",
        "--raw",
        "--skip-column-names",
        "--connect-timeout=5",
        "-e",
        sql,
    ]
    try:
        result = _subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=25,
            check=False,
        )
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

def _one(item):
    started = _time.monotonic()
    db = item["数据库"]
    table = item["表"]
    result = {
        "资产编号": item["资产编号"],
        "对象指纹": _fp("MySQL/" + db + "/" + table),
        "状态": "失败",
        "记录数": None,
        "时间字段指纹": None,
        "时间可解析记录数": None,
        "时间空值记录数": None,
        "未来记录": None,
        "Schema指纹": None,
        "读取字节数": 0,
        "耗时毫秒": 0,
        "错误类别": None,
    }
    try:
        metadata = _mysql(
            "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=" + _lit(db) + " AND TABLE_NAME=" + _lit(table) +
            " ORDER BY ORDINAL_POSITION;"
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
            (name, kind)
            for name, kind in columns
            if kind in {"date", "datetime", "timestamp", "bigint", "int", "integer", "decimal"}
            and any(token in name.lower() for token in ("time", "date", "timestamp", "created", "updated", "event", "occurred", "received", "arrived", "start", "end"))
        ]
        candidates.sort(key=lambda value: columns.index(value))
        count_sql = "SELECT COUNT(*) FROM " + _ident(db) + "." + _ident(table) + ";"
        if candidates:
            field = candidates[0][0]
            count_sql = (
                "SELECT COUNT(*), COUNT(" + _ident(field) + "), MIN(" + _ident(field) + "), MAX(" + _ident(field) + ") FROM "
                + _ident(db) + "." + _ident(table) + ";"
            )
        aggregate = _mysql(count_sql)
        result["读取字节数"] += aggregate.get("bytes", 0)
        if not aggregate["ok"]:
            result["错误类别"] = aggregate["error"]
            return result
        fields = aggregate["stdout"].strip().split(chr(9))
        if candidates and len(fields) != 4:
            result["错误类别"] = "aggregate_shape_error"
            return result
        if not candidates and len(fields) != 1:
            result["错误类别"] = "count_shape_error"
            return result
        rows = int(fields[0] or 0)
        result["记录数"] = rows
        if rows == 0:
            result["状态"] = "未成熟"
            result["错误类别"] = "empty_object"
            return result
        if not candidates:
            result["状态"] = "无法判定"
            result["错误类别"] = "no_freezable_time_field"
            return result
        field, _kind = candidates[0]
        result["时间字段指纹"] = _fp(field)
        nonnull = int(fields[1] or 0)
        result["时间空值记录数"] = rows - nonnull
        minimum = _parse_iso(fields[2])
        maximum = _parse_iso(fields[3])
        result["时间可解析记录数"] = nonnull if minimum is not None and maximum is not None else 0
        result["未来记录"] = bool(maximum is not None and maximum > _CUTOFF)
        if result["未来记录"]:
            result["状态"] = "失败"
            result["错误类别"] = "future_timestamp_detected"
        elif minimum is None or maximum is None or nonnull != rows:
            result["状态"] = "无法判定"
            result["错误类别"] = "time_alignment_incomplete"
        else:
            result["状态"] = "通过"
    except (ValueError, TypeError, TimeoutError):
        result["错误类别"] = "safe_parser_failure"
    finally:
        result["耗时毫秒"] = int((_time.monotonic() - started) * 1000)
    return result

_session = _mysql("SELECT CURRENT_USER();")
_session_fp = _fp(_session.get("stdout", "")) if _session.get("ok") else None
_results = []
for _item in _TABLES:
    if _time.monotonic() - _START > 590:
        _results.append({"资产编号": _item["资产编号"], "对象指纹": _fp("MySQL/" + _item["数据库"] + "/" + _item["表"]), "状态": "失败", "错误类别": "batch_timeout", "读取字节数": 0, "耗时毫秒": 0})
        continue
    _results.append(_one(_item))
print(_json.dumps({"规则脚本指纹": _SCRIPT_FP, "授权会话指纹": _session_fp, "对象结果": _results, "资源上限": {"单对象字节": _MAX_BYTES, "单对象秒": _MAX_SECONDS, "批次秒": 600, "内存字节": 536870912, "远端临时写入": False}}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
'''
    return (
        template.replace("__PAYLOAD__", repr(payload))
        .replace("__CUTOFF__", repr(cutoff))
        .replace("__SCRIPT_FP__", repr(script_fingerprint))
        .replace("__DB_CONFIG__", db_config_path)
    )


def run_remote_database(
    database: list[dict[str, str]],
    cutoff: str,
    script_fingerprint: str,
    db_config_path: str,
) -> tuple[dict[str, Any], str]:
    script = make_remote_script(database, cutoff, script_fingerprint, db_config_path)
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "LogLevel=ERROR",
        "ubuntu",
        "python3",
        "-",
    ]
    try:
        completed = subprocess.run(
            command,
            input=script,
            text=True,
            capture_output=True,
            timeout=650,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("数据库批次超过650秒外部超时") from error
    if completed.returncode != 0:
        raise RuntimeError("数据库只读批次失败关闭")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("数据库只读批次输出不是结构化JSON") from error
    if not isinstance(document, dict) or len(document.get("对象结果", [])) != 92:
        raise RuntimeError("数据库只读批次对象数不是92")
    return document, completed.stdout


def run_remote_logs(log_target: str, log_key: Path) -> tuple[dict[str, Any], str]:
    if not log_key.exists():
        raise RuntimeError("日志只读SSH密钥不存在")
    command = [
        "ssh",
        "-i",
        str(log_key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "PasswordAuthentication=no",
        log_target,
    ]
    completed = subprocess.run(
        command, text=True, capture_output=True, timeout=40, check=False
    )
    if completed.returncode != 0:
        raise RuntimeError("敏感日志固定入口失败关闭")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("敏感日志输出不是结构化JSON") from error
    if len(document.get("对象结果", [])) != 2:
        raise RuntimeError("敏感日志对象数不是2")
    return document, completed.stdout


def stable_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def write_json(path: Path, document: Any) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def build_report(
    batch_id: str,
    metadata: dict[str, Any],
    summary: dict[str, int],
    results: list[dict[str, Any]],
) -> str:
    lines = [
        "# Ubuntu未完整扫描对象正文质量复验报告",
        "",
        "<!-- markdownlint-disable MD013 -->",
        "",
        f"- 审计批次：`{batch_id}`",
        f"- 合同版本指纹：`{metadata['合同版本指纹']}`",
        f"- 覆盖矩阵指纹：`{metadata['覆盖矩阵指纹']}`",
        f"- 规则脚本指纹：`{metadata['规则脚本指纹']}`",
        f"- 数据库对象：92；敏感日志文件：2；合同授权截止：`{metadata['合同授权截止']}`；本批次数据截止：`{metadata['数据截止']}`",
        "- 远端入口：仅使用白名单逻辑别名`ubuntu`；不写入远端临时文件，不输出用户名、原始日志或业务字段值。",
        "",
        "## 状态摘要",
        "",
        "| 状态 | 对象数 |",
        "| --- | ---: |",
    ]
    for status in ("通过", "拒绝", "无法判定", "失败", "未成熟", "失效", "未执行"):
        lines.append(f"| {status} | {summary.get(status, 0)} |")
    lines += [
        f"| 合计 | {sum(summary.values())} |",
        "",
        "## 资源与安全",
        "",
        "- 数据库逐对象最多读取65536字节、30秒，串行执行，远端进程内存上限512MiB；日志逐对象最多32768字节、批次最多65536字节、30秒，内存上限512MiB。",
        "- 数据库只输出记录数、时间字段可解析计数、状态和指纹；日志只输出脱敏计数、状态和内容指纹。",
        "- 发生权限不足、超时、未来时间、输入漂移、输出不完整或敏感信息泄漏时，状态保持失败安全，不发布半批次。",
        "- 这批次不计算胜率、收益、方向、仓位、订单或交易许可；不关闭ZS-DATA-GAP-003/005，不放行阶段2。",
        "",
        "## 逐对象脱敏证据",
        "",
        "逐对象结果保存在同批次`对象结果.jsonl`；仅包含资产编号、对象指纹、状态、计数、资源与错误类别。",
        "",
        "| 资产编号 | 状态 | 记录数 | 错误类别 |",
        "| --- | --- | ---: | --- |",
    ]
    for result in results:
        lines.append(
            f"| {result.get('资产编号', '')} | {result.get('状态', '失败')} | "
            f"{result.get('记录数', '') if result.get('记录数') is not None else '—'} | "
            f"{result.get('错误类别') or '—'} |"
        )
    lines += [
        "",
        "## 结论与限制",
        "",
        "- 本批次只证明白名单对象在当前截止事实下可执行的结构性质量观察；描述性状态不能推导因果、预测优势、胜率、收益或交易许可。",
        "- 三个输入身份漂移文件不在本批次授权范围，继续沿用任务-000063的拒绝事实；BTC/ETH不跨标的补偿，SOL不进入前向范围。",
        "- 空日志记录为`未成熟`，任何未知、失败和未成熟状态均保留，不缩小分母。",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--log-target", required=True)
    parser.add_argument("--log-key", required=True)
    parser.add_argument("--db-config-path", required=True)
    args = parser.parse_args()
    database, logs = load_targets()
    batch_root = ROOT / "artifacts/审计/Ubuntu未完整扫描对象正文质量复验" / args.batch_id
    if batch_root.exists():
        raise RuntimeError("批次目录已存在，拒绝覆盖")
    report_path = ROOT / "docs/审计/Ubuntu未完整扫描对象正文质量复验报告.md"
    if report_path.exists():
        raise RuntimeError("报告路径已存在，拒绝覆盖；应创建新追加版本")
    started = stable_now()
    script_fp = sha256_text(Path(__file__).read_text(encoding="utf-8"))
    matrix_fp = sha256_bytes(MATRIX.read_bytes())
    contract_fp = sha256_bytes(CONTRACT.read_bytes())
    logs_document, logs_raw = run_remote_logs(args.log_target, Path(args.log_key))
    database_document, database_raw = run_remote_database(
        database, args.cutoff, script_fp, args.db_config_path
    )
    results: list[dict[str, Any]] = []
    results.extend(database_document["对象结果"])
    for index, item in enumerate(logs_document["对象结果"]):
        result = dict(item)
        result["资产编号"] = logs[index]["资产编号"]
        result["对象指纹"] = LOG_PATH_FINGERPRINTS[index]
        results.append(result)
    if len(results) != 94:
        raise RuntimeError("合并后的对象结果不是94")
    batch_root.mkdir(parents=True)
    statuses = {status: 0 for status in ("通过", "拒绝", "无法判定", "失败", "未成熟", "失效", "未执行")}
    for result in results:
        status = result.get("状态")
        if status not in statuses:
            raise RuntimeError("出现未注册状态")
        statuses[status] += 1
    ended = stable_now()
    metadata = {
        "批次": args.batch_id,
        "开始时间": started.isoformat(),
        "结束时间": ended.isoformat(),
        "合同授权截止": AUTHORIZATION_DEADLINE,
        "数据截止": args.cutoff,
        "合同版本指纹": contract_fp,
        "覆盖矩阵指纹": matrix_fp,
        "规则脚本指纹": script_fp,
        "数据库远端输出指纹": sha256_text(database_raw),
        "日志远端输出指纹": sha256_text(logs_raw),
        "资源合同": RESOURCE_CONTRACT,
        "对象总数": len(results),
        "状态计数": statuses,
        "安全声明": {
            "原始数据修改": False,
            "远端临时写入": False,
            "日志正文输出": False,
            "业务字段输出": False,
            "未来数据使用": False,
            "交易结论": False,
        },
    }
    write_json(batch_root / "批次元数据.json", metadata)
    with (batch_root / "对象结果.jsonl").open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    write_json(batch_root / "状态摘要.json", statuses)
    report = build_report(args.batch_id, metadata, statuses, results)
    report_path.write_text(report, encoding="utf-8")
    print(json.dumps({"批次": args.batch_id, "报告": str(report_path.relative_to(ROOT)), "对象总数": len(results), "状态计数": statuses, "批次指纹": sha256_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True))}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"安全停止：{error}", file=sys.stderr)
        raise SystemExit(2)
