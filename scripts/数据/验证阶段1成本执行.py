#!/usr/bin/env python3
"""任务-000100：阶段1成本与执行证据的低负载、追加式验证器。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import resource
import subprocess
import sys
import time
import urllib.parse
from itertools import product
from pathlib import Path
from typing import Any, Iterable, Mapping


SCRIPT_VERSION = "stage1-cost-execution-evidence-1.0"
CONFIG_RELATIVE_PATH = Path("config/数据/任务-000100阶段1成本执行.json")
TASK_RELATIVE_PATH = Path("docs/研发中心/任务/任务-000100.md")
BATCH_PATTERN = re.compile(r"^stage1-cost-execution-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|token\s*=|authorization:|api[_-]?key|"
    r"-----BEGIN|\b\d{1,3}(?:\.\d{1,3}){3}\b)"
)
FORBIDDEN_SQL = re.compile(
    r"(?is)(?:\b(?:insert|update|delete|replace|alter|drop|create|truncate|"
    r"grant|revoke|lock|unlock|call|load|outfile|dumpfile|procedure)\b|"
    r"/\*|--|#|;|\*)"
)
ALLOWED_ACCESS_TYPES = frozenset({"system", "const", "ref", "range"})
SYMBOL_COLUMNS = ("symbol", "contract_symbol", "instrument")
TIME_COLUMNS = (
    "event_time",
    "event_ts",
    "exchange_timestamp",
    "capture_ts_ms",
    "bucket_ts_sec",
    "as_of_ms",
    "metadata_updated_at_ms",
    "bucket_start",
    "snapshot_time",
    "timestamp",
    "ts",
    "created_at",
)
ARRIVAL_COLUMNS = ("arrival_time", "received_at", "receive_time", "ingested_at")
CAPTURE_COLUMNS = ("collected_at", "capture_time", "captured_at", "created_at")


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"INPUT_NOT_REGULAR_FILE:{path}")
    return sha256_bytes(path.read_bytes())


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def assert_safe_text(text: str) -> None:
    if SENSITIVE.search(text):
        raise ValueError("SENSITIVE_TEXT_REJECTED")


def write_bytes_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o644)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def write_json_exclusive(path: Path, value: Any) -> None:
    payload = canonical_bytes(value)
    assert_safe_text(payload.decode("utf-8"))
    write_bytes_exclusive(path, payload)


def write_text_exclusive(path: Path, text: str) -> None:
    assert_safe_text(text)
    write_bytes_exclusive(path, text.encode("utf-8"))


def read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"INPUT_NOT_REGULAR_FILE:{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_relative_regular(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("INPUT_PATH_OUTSIDE_REPOSITORY")
    current = root.resolve()
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("INPUT_PATH_SYMLINK_REJECTED")
    if not current.is_file():
        raise ValueError("INPUT_FILE_MISSING")
    return current


def validate_config(config: Mapping[str, Any]) -> None:
    required = {
        "合同版本",
        "任务编号",
        "SSH逻辑别名",
        "数据库",
        "标的",
        "交易场所",
        "市场",
        "方向",
        "阶段",
        "主研究尺度",
        "事后观察窗口",
        "固定候选表",
        "Binance公开端点",
        "上游输入",
        "资源上限",
    }
    if set(config) != required:
        raise ValueError("CONFIG_FIELDS_MISMATCH")
    if config["合同版本"] != SCRIPT_VERSION or config["任务编号"] != "任务-000100":
        raise ValueError("CONFIG_IDENTITY_MISMATCH")
    if config["SSH逻辑别名"] != "ubuntu" or config["数据库"] != "orderbook":
        raise ValueError("CONFIG_REMOTE_SCOPE_MISMATCH")
    if config["标的"] != ["BTCUSDT", "ETHUSDT"]:
        raise ValueError("CONFIG_SYMBOL_SCOPE_MISMATCH")
    if config["方向"] != ["做多", "做空"] or config["阶段"] != ["入场", "退出"]:
        raise ValueError("CONFIG_GROUP_SCOPE_MISMATCH")
    if config["主研究尺度"] != [
        "主研究尺度：4小时",
        "主研究尺度：8小时",
        "主研究尺度：24小时",
        "主研究尺度：48小时",
    ] or config["事后观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("CONFIG_HORIZON_SCOPE_MISMATCH")
    tables = config["固定候选表"]
    if len(tables) != 5 or len(set(tables)) != 5 or not all(IDENTIFIER.fullmatch(x) for x in tables):
        raise ValueError("CONFIG_TABLE_SCOPE_MISMATCH")
    limits = config["资源上限"]
    expected_limits = {
        "单SQL秒": 30,
        "SQL总数": 24,
        "单SQL估算扫描行": 250000,
        "批次估算扫描行": 1000000,
        "返回聚合行": 10000,
        "业务读取字节": 268435456,
        "远端日志字节": 65536,
        "本地输出字节": 33554432,
        "RSS字节": 536870912,
        "总时限秒": 900,
    }
    if limits != expected_limits:
        raise ValueError("CONFIG_RESOURCE_LIMIT_MISMATCH")
    upstream = config["上游输入"]
    if upstream.get("规范结果SHA-256") != "d363c17bad6bbaa3a07ff0076b85c37e73ec41a3fb2d15929473c0e43c7a6e0b":
        raise ValueError("UPSTREAM_RESULT_IDENTITY_MISMATCH")
    if upstream.get("正式输入") != 5180 or upstream.get("叶子") != 8:
        raise ValueError("UPSTREAM_DENOMINATOR_MISMATCH")


def validate_business_sql(sql: str, config: Mapping[str, Any]) -> str:
    compact = " ".join(sql.strip().split())
    lowered = compact.lower()
    if not lowered.startswith("select ") or FORBIDDEN_SQL.search(compact):
        raise ValueError("SQL_NOT_READ_ONLY")
    if re.search(r"(?is)select\s+(?:distinct\s+)?\*", compact):
        raise ValueError("SQL_WILDCARD_REJECTED")
    match = re.search(r"(?i)\bfrom\s+`?([A-Za-z_][A-Za-z0-9_]*)`?", compact)
    if match is None:
        raise ValueError("SQL_TABLE_MISSING")
    table = match.group(1)
    if table not in config["固定候选表"]:
        raise ValueError("SQL_TABLE_NOT_ALLOWED")
    if " limit " not in f" {lowered} ":
        raise ValueError("SQL_LIMIT_REQUIRED")
    return table


def _walk_plan(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if "access_type" in value:
            yield value
        for child in value.values():
            yield from _walk_plan(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_plan(child)


def validate_explain(
    plan: Mapping[str, Any], *, allowed_indexes: set[str], max_rows: int
) -> int:
    tables = list(_walk_plan(plan))
    if not tables:
        if "Select tables optimized away" in json.dumps(plan, ensure_ascii=False):
            return 0
        raise ValueError("EXPLAIN_TABLE_MISSING")
    total = 0
    for table in tables:
        access = str(table.get("access_type", "")).lower()
        if access not in ALLOWED_ACCESS_TYPES:
            raise ValueError("EXPLAIN_ACCESS_TYPE_REJECTED")
        key = table.get("key")
        if access not in {"system", "const"} and key not in allowed_indexes:
            raise ValueError("EXPLAIN_INDEX_NOT_ALLOWED")
        rows = table.get("rows_examined_per_scan", table.get("rows"))
        if not isinstance(rows, (int, float)) or rows < 0:
            raise ValueError("EXPLAIN_ROWS_MISSING")
        total += int(rows)
    if total > max_rows:
        raise ValueError("EXPLAIN_ESTIMATED_ROWS_EXCEEDED")
    return total


def validate_query_manifest(queries: list[Mapping[str, Any]], *, max_queries: int) -> None:
    if len(queries) > max_queries:
        raise ValueError("QUERY_COUNT_EXCEEDED")
    ids = [q.get("查询编号") for q in queries]
    sqls = [q.get("SQL") for q in queries]
    if len(ids) != len(set(ids)) or len(sqls) != len(set(sqls)):
        raise ValueError("QUERY_DUPLICATE_REJECTED")
    if not all(isinstance(x, str) and x for x in ids + sqls):
        raise ValueError("QUERY_IDENTITY_INVALID")


def validate_public_url(url: str, config: Mapping[str, Any]) -> bool:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "fapi.binance.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path not in config["Binance公开端点"]
    ):
        raise ValueError("BINANCE_URL_NOT_ALLOWED")
    return True


def assert_historical_compatibility(*, source_kind: str, requested_at: str) -> None:
    if source_kind in {"current_depth", "current_premium", "current_exchange_info"}:
        raise ValueError(f"CURRENT_SNAPSHOT_CANNOT_BACKFILL:{requested_at}")


def build_gate_decision(observable: Mapping[str, str]) -> dict[str, str]:
    result = dict(observable)
    result["执行延迟"] = "无法判定"
    result["成本与执行总门"] = "无法判定"
    return result


def build_group_rows(*, batch: str, evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    statuses = {
        "手续费": "无法判定",
        "价差": "无法判定",
        "深度": "无法判定",
        "冲击": "无法判定",
        "资金费率": "无法判定",
        "行情可见性延迟": "无法判定",
        "可成交量": "无法判定",
    }
    if evidence.get("资金费率历史窗口已观察") is True:
        statuses["资金费率"] = "已观察（覆盖不足）"
    gate = build_gate_decision(statuses)
    rows = []
    for symbol, direction, phase, horizon in product(
        ("BTCUSDT", "ETHUSDT"),
        ("做多", "做空"),
        ("入场", "退出"),
        (4, 8, 24, 48),
    ):
        rows.append(
            {
                "批次": batch,
                "标的": symbol,
                "交易场所": "Binance",
                "市场": "USDⓈ-M永续合约",
                "精确合约": symbol,
                "方向": direction,
                "阶段": phase,
                "主研究尺度小时": horizon,
                "结果观察窗口分钟": "15,60",
                "手续费状态": gate["手续费"],
                "价差状态": gate["价差"],
                "深度状态": gate["深度"],
                "冲击状态": gate["冲击"],
                "资金费率状态": gate["资金费率"],
                "行情可见性延迟状态": gate["行情可见性延迟"],
                "可成交量状态": gate["可成交量"],
                "执行延迟状态": gate["执行延迟"],
                "成本与执行总门": gate["成本与执行总门"],
                "原因代码": "EXECUTION_LIFECYCLE_EVIDENCE_MISSING",
                "解除条件": "同一历史现场的版本化模拟委托发送、确认/成交、排队和撤单时间证据",
            }
        )
    return rows


def _normalized_task_fingerprint(path: Path) -> str:
    volatile = (
        "- 状态：",
        "- 执行分支：",
        "- 开始时间：",
        "- 提交SHA：",
        "- Pull Request：",
        "- 交付物：",
        "- 验证结果：",
    )
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith(volatile)]
    return sha256_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _load_config(repo_root: Path) -> tuple[dict[str, Any], Path]:
    path = repo_root / CONFIG_RELATIVE_PATH
    config = read_json(path)
    if not isinstance(config, dict):
        raise ValueError("CONFIG_OBJECT_REQUIRED")
    validate_config(config)
    return config, path


def _batch_directory(repo_root: Path, batch: str) -> Path:
    if BATCH_PATTERN.fullmatch(batch) is None:
        raise ValueError("BATCH_ID_INVALID")
    return repo_root / "artifacts" / "数据" / "阶段1成本执行" / batch


def _assert_upstream(repo_root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    upstream = config["上游输入"]
    published = _assert_relative_regular(repo_root, upstream["决策路径"])
    if sha256_path(published) != upstream["决策SHA-256"]:
        raise ValueError("UPSTREAM_PUBLICATION_DRIFT")
    decision = published.parent / "decision" / "decision.json"
    value = read_json(decision)
    if value.get("result_sha256") != upstream["规范结果SHA-256"]:
        raise ValueError("UPSTREAM_NORMATIVE_RESULT_DRIFT")
    return {"公布文件SHA-256": sha256_path(published), "决策文件SHA-256": sha256_path(decision)}


def prepare(repo_root: Path, batch: str) -> dict[str, Any]:
    started = time.monotonic()
    config, config_path = _load_config(repo_root)
    upstream = _assert_upstream(repo_root, config)
    batch_dir = _batch_directory(repo_root, batch)
    batch_dir.mkdir(parents=True, exist_ok=False)
    intent = {
        "schema_version": "zhishi-stage1-cost-execution-intent/v1",
        "task_id": "000100",
        "batch_id": batch,
        "created_at": utc_now(),
        "data_cutoff_at": utc_now(),
        "config_sha256": sha256_path(config_path),
        "script_sha256": sha256_path(Path(__file__).resolve()),
        "task_contract_normalized_sha256": _normalized_task_fingerprint(repo_root / TASK_RELATIVE_PATH),
        "upstream": upstream,
        "source_scope": {
            "ssh_alias": "ubuntu",
            "database": "orderbook",
            "tables": config["固定候选表"],
            "binance_endpoints": config["Binance公开端点"],
        },
        "resource_limits": config["资源上限"],
        "process": {"pid": os.getpid(), "elapsed_seconds": round(time.monotonic() - started, 6), "rss_bytes": _rss_bytes()},
    }
    write_json_exclusive(batch_dir / "intent.json", intent)
    return intent


def _assert_intent(repo_root: Path, batch: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    config, config_path = _load_config(repo_root)
    batch_dir = _batch_directory(repo_root, batch)
    intent = read_json(batch_dir / "intent.json")
    expected = {
        "config_sha256": sha256_path(config_path),
        "script_sha256": sha256_path(Path(__file__).resolve()),
        "task_contract_normalized_sha256": _normalized_task_fingerprint(repo_root / TASK_RELATIVE_PATH),
    }
    for key, value in expected.items():
        if intent.get(key) != value:
            raise ValueError(f"INTENT_{key.upper()}_DRIFT")
    _assert_upstream(repo_root, config)
    return intent, config, batch_dir


REMOTE_METADATA_PROGRAM = r'''
import hashlib,json,os,shutil,subprocess,sys
tables=("order_book_raw_snapshots","order_book_feature_buckets","order_book_market_structure_snapshots","order_book_public_context_snapshots","symbol_metadata")
client=shutil.which("mysql") or shutil.which("mariadb")
if not client: raise SystemExit("MYSQL_CLIENT_MISSING")
def run(sql):
 p=subprocess.run([client,"--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",sql],capture_output=True,text=True,timeout=30,check=False)
 if p.returncode: raise SystemExit("MYSQL_READ_FAILED")
 return p.stdout
quoted=",".join("'%s'"%x for x in tables)
identity=run("SELECT CURRENT_USER(),USER(),VERSION()")
grants=run("SHOW GRANTS FOR CURRENT_USER()")
table_rows=run("SELECT TABLE_NAME,ENGINE,COALESCE(TABLE_ROWS,0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME"%quoted)
columns=run("SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,DATA_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME,ORDINAL_POSITION"%quoted)
indexes=run("SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX"%quoted)
def lines(text): return [x.split("\t") for x in text.splitlines() if x]
out={"protocol":"zhishi-stage1-cost-metadata/1","uid":os.getuid(),"identity_sha256":hashlib.sha256(identity.encode()).hexdigest(),"grant_sha256":hashlib.sha256(grants.encode()).hexdigest(),"select_capability":bool(grants.strip()),"tables":lines(table_rows),"columns":lines(columns),"indexes":lines(indexes)}
print(json.dumps(out,sort_keys=True,separators=(",",":")))
'''


def _run_ssh_python(program: str, *, timeout: int, max_log: int) -> dict[str, Any]:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "ubuntu",
        "python3",
        "-",
    ]
    try:
        result = subprocess.run(command, input=program, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("REMOTE_PROBE_TIMEOUT") from exc
    stderr_bytes = result.stderr.encode("utf-8", errors="replace")
    stdout_bytes = result.stdout.encode("utf-8", errors="replace")
    if len(stderr_bytes) > max_log or len(stdout_bytes) > max_log or result.returncode != 0:
        raise RuntimeError(f"REMOTE_PROBE_FAILED:{result.returncode}:{sha256_bytes(stderr_bytes)}")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("REMOTE_PROBE_OBJECT_REQUIRED")
    return value


def probe_metadata(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    value = _run_ssh_python(
        REMOTE_METADATA_PROGRAM,
        timeout=config["资源上限"]["单SQL秒"] * 5,
        max_log=config["资源上限"]["远端日志字节"],
    )
    if value.get("protocol") != "zhishi-stage1-cost-metadata/1" or value.get("uid") != 0:
        raise ValueError("REMOTE_IDENTITY_MISMATCH")
    if not value.get("select_capability"):
        raise ValueError("REMOTE_SELECT_CAPABILITY_MISSING")
    evidence = {
        "schema_version": "zhishi-stage1-cost-metadata-evidence/v1",
        "batch_id": batch,
        "intent_sha256": sha256_path(batch_dir / "intent.json"),
        "observed_at": utc_now(),
        "root_compatible_read_only": True,
        "remote_write_performed": False,
        "metadata": value,
        "metadata_sha256": sha256_bytes(canonical_bytes(value)),
    }
    write_json_exclusive(batch_dir / "metadata.json", evidence)
    return evidence


def _metadata_maps(metadata: Mapping[str, Any]) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, list[str]]]]:
    columns: dict[str, dict[str, str]] = {}
    for row in metadata.get("columns", []):
        if len(row) == 5:
            columns.setdefault(row[0], {})[row[1]] = row[3].lower()
    indexes: dict[str, dict[str, list[tuple[int, str]]]] = {}
    for row in metadata.get("indexes", []):
        if len(row) == 5:
            indexes.setdefault(row[0], {}).setdefault(row[1], []).append((int(row[3]), row[4]))
    normalized = {
        table: {name: [col for _, col in sorted(parts)] for name, parts in names.items()}
        for table, names in indexes.items()
    }
    return columns, normalized


def _time_literal(column_name: str, data_type: str, cutoff: str) -> tuple[str, str]:
    parsed = dt.datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    if data_type in {"tinyint", "smallint", "mediumint", "int", "bigint", "decimal", "double", "float"}:
        if column_name.endswith("_ms"):
            upper = int(parsed.timestamp() * 1000)
        elif column_name.endswith("_sec"):
            upper = int(parsed.timestamp())
        else:
            raise ValueError("NUMERIC_TIME_UNIT_NOT_EXPLICIT")
        return "0", str(upper)
    if data_type in {"date", "datetime", "timestamp"}:
        return "'2017-01-01 00:00:00'", f"'{parsed.strftime('%Y-%m-%d %H:%M:%S')}'"
    raise ValueError("TIME_COLUMN_TYPE_NOT_SUPPORTED")


def build_query_plan(metadata_evidence: Mapping[str, Any], intent: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    metadata = metadata_evidence["metadata"]
    columns, indexes = _metadata_maps(metadata)
    queries: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for table in config["固定候选表"]:
        table_columns = columns.get(table, {})
        symbol = next((name for name in SYMBOL_COLUMNS if name in table_columns), None)
        event_time = next((name for name in TIME_COLUMNS if name in table_columns), None)
        index = next(
            (
                name
                for name, parts in indexes.get(table, {}).items()
                if symbol is not None and event_time is not None and parts[:2] == [symbol, event_time]
            ),
            None,
        )
        if symbol is None or event_time is None or index is None:
            skipped.append({"表": table, "原因": "SYMBOL_TIME_COMPOSITE_INDEX_MISSING"})
            continue
        if not all(IDENTIFIER.fullmatch(x) for x in (table, symbol, event_time, index)):
            raise ValueError("METADATA_IDENTIFIER_INVALID")
        try:
            lower, upper = _time_literal(event_time, table_columns[event_time], intent["data_cutoff_at"])
        except ValueError:
            skipped.append({"表": table, "原因": "TIME_COLUMN_TYPE_NOT_SUPPORTED"})
            continue
        for target, order in product(config["标的"], ("ASC", "DESC")):
            query_id = f"{table}:{target}:{order.lower()}"
            sql = (
                f"SELECT `{symbol}` AS symbol,`{event_time}` AS event_time FROM `{table}` "
                f"FORCE INDEX (`{index}`) WHERE `{symbol}`='{target}' "
                f"AND `{event_time}`>={lower} AND `{event_time}`<{upper} "
                f"ORDER BY `{event_time}` {order} LIMIT 1"
            )
            validate_business_sql(sql, config)
            queries.append(
                {
                    "查询编号": query_id,
                    "表": table,
                    "标的": target,
                    "边界": "最早" if order == "ASC" else "最晚",
                    "索引": index,
                    "SQL": sql,
                    "SQL_SHA-256": sha256_bytes(sql.encode("utf-8")),
                }
            )
    validate_query_manifest(queries, max_queries=config["资源上限"]["SQL总数"])
    return {
        "schema_version": "zhishi-stage1-cost-query-plan/v1",
        "batch_id": intent["batch_id"],
        "intent_sha256": sha256_bytes(canonical_bytes(intent)),
        "metadata_sha256": sha256_bytes(canonical_bytes(metadata_evidence)),
        "planned_at": utc_now(),
        "queries": queries,
        "skipped_tables": skipped,
        "query_count": len(queries),
        "business_query_retry_count": 0,
    }


def plan_queries(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    metadata = read_json(batch_dir / "metadata.json")
    plan = build_query_plan(metadata, intent, config)
    write_json_exclusive(batch_dir / "query-plan.json", plan)
    return plan


def _remote_query_program(queries: list[Mapping[str, Any]], *, explain_only: bool) -> str:
    payload = json.dumps(queries, ensure_ascii=False, separators=(",", ":"))
    mode = "explain" if explain_only else "execute"
    return f'''
import hashlib,json,shutil,subprocess
queries=json.loads({payload!r})
client=shutil.which("mysql") or shutil.which("mariadb")
if not client: raise SystemExit("MYSQL_CLIENT_MISSING")
out=[]
for query in queries:
 sql=query["SQL"]
 statement=("EXPLAIN FORMAT=JSON "+sql) if {mode!r}=="explain" else sql
 p=subprocess.run([client,"--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",statement],capture_output=True,text=True,timeout=30,check=False)
 if p.returncode: raise SystemExit("MYSQL_QUERY_FAILED")
 raw=p.stdout.encode()
 if {mode!r}=="explain":
  value=json.loads(p.stdout)
  out.append({{"query_id":query["查询编号"],"plan":value,"response_sha256":hashlib.sha256(raw).hexdigest()}})
 else:
  lines=[line.split("\\t") for line in p.stdout.splitlines() if line]
  out.append({{"query_id":query["查询编号"],"row_count":len(lines),"rows":lines,"response_sha256":hashlib.sha256(raw).hexdigest(),"response_bytes":len(raw)}})
print(json.dumps({{"protocol":"zhishi-stage1-cost-query/1","mode":{mode!r},"results":out}},sort_keys=True,separators=(",",":")))
'''


def explain_queries(repo_root: Path, batch: str) -> dict[str, Any]:
    _intent, config, batch_dir = _assert_intent(repo_root, batch)
    plan = read_json(batch_dir / "query-plan.json")
    queries = plan["queries"]
    validate_query_manifest(queries, max_queries=config["资源上限"]["SQL总数"])
    result = _run_ssh_python(
        _remote_query_program(queries, explain_only=True),
        timeout=max(30, len(queries) * config["资源上限"]["单SQL秒"]),
        max_log=config["资源上限"]["远端日志字节"],
    )
    if result.get("mode") != "explain" or len(result.get("results", [])) != len(queries):
        raise ValueError("EXPLAIN_RESULT_MISMATCH")
    evidence = {
        "schema_version": "zhishi-stage1-cost-query-explain/v1",
        "batch_id": batch,
        "query_plan_sha256": sha256_path(batch_dir / "query-plan.json"),
        "explained_at": utc_now(),
        "results": result["results"],
    }
    write_json_exclusive(batch_dir / "query-explain.json", evidence)
    return evidence


def _approved_queries(config: Mapping[str, Any], plan: Mapping[str, Any], explain: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]], int]:
    by_id = {item["query_id"]: item for item in explain["results"]}
    approved = []
    decisions = []
    total_rows = 0
    for query in plan["queries"]:
        item = by_id.get(query["查询编号"])
        if item is None:
            raise ValueError("EXPLAIN_QUERY_ID_MISSING")
        try:
            rows = validate_explain(
                item["plan"],
                allowed_indexes={query["索引"]},
                max_rows=config["资源上限"]["单SQL估算扫描行"],
            )
        except ValueError as exc:
            decisions.append({"查询编号": query["查询编号"], "状态": "拒绝", "原因": str(exc)})
            continue
        if total_rows + rows > config["资源上限"]["批次估算扫描行"]:
            decisions.append({"查询编号": query["查询编号"], "状态": "拒绝", "原因": "BATCH_ESTIMATED_ROWS_EXCEEDED"})
            continue
        total_rows += rows
        approved.append(query)
        decisions.append({"查询编号": query["查询编号"], "状态": "通过", "估算扫描行": rows})
    return approved, decisions, total_rows


def _public_requests(config: Mapping[str, Any]) -> list[dict[str, str]]:
    base = "https://fapi.binance.com"
    requests = [{"id": "exchange-info", "url": base + "/fapi/v1/exchangeInfo", "kind": "current_exchange_info"}]
    for symbol in config["标的"]:
        encoded = urllib.parse.urlencode({"symbol": symbol, "limit": 5})
        requests.append({"id": f"depth-{symbol}", "url": base + "/fapi/v1/depth?" + encoded, "kind": "current_depth"})
        requests.append({"id": f"premium-{symbol}", "url": base + "/fapi/v1/premiumIndex?" + urllib.parse.urlencode({"symbol": symbol}), "kind": "current_premium"})
        requests.append({"id": f"funding-{symbol}", "url": base + "/fapi/v1/fundingRate?" + urllib.parse.urlencode({"symbol": symbol, "limit": 1000}), "kind": "historical_funding"})
    return requests


def build_binance_remote_program(config: Mapping[str, Any], request_item: Mapping[str, str] | None = None) -> str:
    requests = [dict(request_item)] if request_item is not None else _public_requests(config)
    for item in requests:
        validate_public_url(item["url"], config)
    payload = json.dumps(requests, ensure_ascii=False, separators=(",", ":"))
    return f'''
import datetime as dt,hashlib,json,shutil,subprocess
requests=json.loads({payload!r})
def now(): return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z")
def canonical(value): return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\\n").encode()
def shape(value):
 if isinstance(value,dict): return {{key:shape(value[key]) for key in sorted(value)}}
 if isinstance(value,list): return [] if not value else [shape(value[0])]
 return type(value).__name__
results=[]
for item in requests:
 collected=now()
 try:
  curl=shutil.which("curl")
  if not curl: raise RuntimeError("CURL_MISSING")
  response=subprocess.run([curl,"--ipv4","--silent","--show-error","--fail","--connect-timeout","5","--max-time","10","--max-filesize","2000000","--user-agent","zhishi-cost-evidence/1.0",item["url"]],capture_output=True,timeout=15,check=False)
  if response.returncode: raise RuntimeError("HTTPS_REQUEST_FAILED_"+str(response.returncode))
  raw=response.stdout
  if len(raw)>2000000: raise ValueError("BINANCE_RESPONSE_LIMIT_EXCEEDED")
  value=json.loads(raw)
  facts={{"request_id":item["id"],"kind":item["kind"],"status":"observed","collected_at":collected,"url_sha256":hashlib.sha256(item["url"].encode()).hexdigest(),"response_sha256":hashlib.sha256(raw).hexdigest(),"response_bytes":len(raw),"schema_sha256":hashlib.sha256(canonical(shape(value))).hexdigest()}}
  if isinstance(value,list):
   facts["item_count"]=len(value)
   times=[x.get("fundingTime") for x in value if isinstance(x,dict) and isinstance(x.get("fundingTime"),int)]
   if times: facts.update({{"earliest_event_time_ms":min(times),"latest_event_time_ms":max(times)}})
  elif isinstance(value,dict) and isinstance(value.get("serverTime"),int): facts["server_time_ms"]=value["serverTime"]
  results.append(facts)
 except Exception as exc:
  reason=str(exc) if str(exc).startswith(("HTTPS_REQUEST_FAILED_","BINANCE_RESPONSE_LIMIT_EXCEEDED","CURL_MISSING")) else type(exc).__name__
  results.append({{"request_id":item["id"],"kind":item["kind"],"status":"failed","collected_at":collected,"url_sha256":hashlib.sha256(item["url"].encode()).hexdigest(),"reason":reason}})
print(json.dumps({{"protocol":"zhishi-binance-public-evidence/1","requests":results}},sort_keys=True,separators=(",",":")))
'''


def fetch_binance_public(config: Mapping[str, Any]) -> dict[str, Any]:
    evidence = []
    for item in _public_requests(config):
        try:
            result = _run_ssh_python(
                build_binance_remote_program(config, item),
                timeout=20,
                max_log=config["资源上限"]["远端日志字节"],
            )
            if result.get("protocol") != "zhishi-binance-public-evidence/1" or len(result.get("requests", [])) != 1:
                raise ValueError("BINANCE_REMOTE_EVIDENCE_MISMATCH")
            evidence.extend(result["requests"])
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            evidence.append(
                {
                    "request_id": item["id"],
                    "kind": item["kind"],
                    "status": "failed",
                    "collected_at": utc_now(),
                    "url_sha256": sha256_bytes(item["url"].encode("utf-8")),
                    "reason": str(exc),
                }
            )
    return {"schema_version": "zhishi-binance-public-evidence/v1", "transport": "ubuntu-curl-ipv4-verified-https", "requests": evidence}


def _schema_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _schema_shape(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [] if not value else [_schema_shape(value[0])]
    return type(value).__name__


def _csv_payload(rows: list[Mapping[str, Any]]) -> str:
    if not rows:
        raise ValueError("CSV_ROWS_REQUIRED")
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def collect(repo_root: Path, batch: str) -> dict[str, Any]:
    started = time.monotonic()
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    plan = read_json(batch_dir / "query-plan.json")
    explain = read_json(batch_dir / "query-explain.json")
    approved, decisions, estimated_rows = _approved_queries(config, plan, explain)
    database_result = _run_ssh_python(
        _remote_query_program(approved, explain_only=False),
        timeout=max(30, len(approved) * config["资源上限"]["单SQL秒"]),
        max_log=config["资源上限"]["远端日志字节"],
    )
    if database_result.get("mode") != "execute" or len(database_result.get("results", [])) != len(approved):
        raise ValueError("DATABASE_RESULT_MISMATCH")
    response_bytes = sum(int(item["response_bytes"]) for item in database_result["results"])
    if response_bytes > config["资源上限"]["业务读取字节"]:
        raise ValueError("DATABASE_RESPONSE_BYTES_EXCEEDED")
    database_evidence = {
        "schema_version": "zhishi-stage1-cost-database-evidence/v1",
        "batch_id": batch,
        "collected_at": utc_now(),
        "query_decisions": decisions,
        "estimated_rows": estimated_rows,
        "executed_query_count": len(approved),
        "query_retry_count": 0,
        "response_bytes": response_bytes,
        "results": database_result["results"],
        "remote_write_performed": False,
    }
    binance = fetch_binance_public(config)
    funding_ok = all(
        any(
            item["request_id"] == f"funding-{symbol}"
            and item["status"] == "observed"
            and item.get("item_count", 0) > 0
            for item in binance["requests"]
        )
        for symbol in config["标的"]
    )
    rows = build_group_rows(batch=batch, evidence={"资金费率历史窗口已观察": funding_ok})
    summary = {
        "schema_version": "zhishi-stage1-cost-execution-summary/v1",
        "task_id": "000100",
        "batch_id": batch,
        "intent_sha256": sha256_path(batch_dir / "intent.json"),
        "metadata_sha256": sha256_path(batch_dir / "metadata.json"),
        "query_plan_sha256": sha256_path(batch_dir / "query-plan.json"),
        "query_explain_sha256": sha256_path(batch_dir / "query-explain.json"),
        "candidate_group_count": 32,
        "observed_group_count": 32,
        "status_counts": {"拒绝": 0, "无法判定": 32, "失败": 0, "未成熟": 0, "失效": 0, "通过": 0},
        "funding_window_observed_for_both_symbols": funding_ok,
        "execution_latency_status": "无法判定",
        "cost_execution_gate": "无法判定",
        "stage1_complete": False,
        "stage2_released": False,
        "remaining_condition": "同一历史现场的版本化模拟委托生命周期证据",
        "resource_facts": {
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "rss_bytes": _rss_bytes(),
            "estimated_database_rows": estimated_rows,
            "database_response_bytes": response_bytes,
            "output_limit_bytes": config["资源上限"]["本地输出字节"],
        },
        "safety": {
            "remote_write": False,
            "database_write": False,
            "account_endpoint": False,
            "credential_read": False,
            "raw_price_or_quantity_persisted": False,
            "model_or_backtest": False,
            "trade_decision": False,
        },
    }
    write_json_exclusive(batch_dir / "database-evidence.json", database_evidence)
    write_json_exclusive(batch_dir / "binance-evidence.json", binance)
    write_text_exclusive(batch_dir / "group-results.csv", _csv_payload(rows))
    write_json_exclusive(batch_dir / "summary.json", summary)
    manifest_files = {}
    for path in sorted(batch_dir.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "manifest.json":
            manifest_files[path.name] = {"sha256": sha256_path(path), "bytes": path.stat().st_size}
    total_output = sum(item["bytes"] for item in manifest_files.values())
    if total_output > config["资源上限"]["本地输出字节"]:
        raise ValueError("LOCAL_OUTPUT_BYTES_EXCEEDED")
    manifest = {
        "schema_version": "zhishi-stage1-cost-execution-manifest/v1",
        "batch_id": batch,
        "published_at": utc_now(),
        "files": manifest_files,
        "file_count": len(manifest_files),
        "total_bytes": total_output,
        "manifest_payload_sha256": sha256_bytes(canonical_bytes(manifest_files)),
    }
    write_json_exclusive(batch_dir / "manifest.json", manifest)
    return summary


def validate_batch(repo_root: Path, batch: str) -> dict[str, Any]:
    _intent, config, batch_dir = _assert_intent(repo_root, batch)
    manifest = read_json(batch_dir / "manifest.json")
    for name, expected in manifest["files"].items():
        path = batch_dir / name
        if sha256_path(path) != expected["sha256"] or path.stat().st_size != expected["bytes"]:
            raise ValueError("BATCH_FILE_DRIFT")
        assert_safe_text(path.read_text(encoding="utf-8"))
    if manifest["total_bytes"] > config["资源上限"]["本地输出字节"]:
        raise ValueError("BATCH_OUTPUT_LIMIT_EXCEEDED")
    summary = read_json(batch_dir / "summary.json")
    counts = summary["status_counts"]
    if sum(counts.values()) != summary["candidate_group_count"] or summary["cost_execution_gate"] != "无法判定":
        raise ValueError("BATCH_DENOMINATOR_OR_GATE_INVALID")
    return {
        "status": "ok",
        "batch": batch,
        "manifest_sha256": sha256_path(batch_dir / "manifest.json"),
        "summary_sha256": sha256_path(batch_dir / "summary.json"),
        "candidate_group_count": summary["candidate_group_count"],
        "cost_execution_gate": summary["cost_execution_gate"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "probe", "plan", "explain", "collect", "validate"))
    parser.add_argument("--batch", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    actions = {
        "prepare": prepare,
        "probe": probe_metadata,
        "plan": plan_queries,
        "explain": explain_queries,
        "collect": collect,
        "validate": validate_batch,
    }
    result = actions[args.command](repo_root, args.batch)
    print(canonical_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"阶段1成本执行验证失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
