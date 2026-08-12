#!/usr/bin/env python3
"""任务-000100：阶段1成本与执行证据的低负载、追加式验证器。"""

from __future__ import annotations

import argparse
import csv
import ctypes
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
REQUIRED_BATCH_FILES = frozenset(
    {
        "intent.json",
        "metadata.json",
        "metadata-post.json",
        "query-plan.json",
        "query-explain.json",
        "database-evidence.json",
        "binance-evidence.json",
        "group-results.csv",
        "summary.json",
    }
)


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


def publish_directory_no_replace(source: Path, target: Path) -> None:
    """以操作系统原生no-replace语义原子发布同文件系统目录。"""
    if source.parent.stat().st_dev != target.parent.stat().st_dev:
        raise ValueError("PUBLISH_FILESYSTEM_MISMATCH")
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        result = libc.renamex_np(source_bytes, target_bytes, 0x00000004)
    elif hasattr(libc, "renameat2"):
        result = libc.renameat2(-100, source_bytes, -100, target_bytes, 1)
    else:
        raise RuntimeError("ATOMIC_NOREPLACE_UNAVAILABLE")
    if result != 0:
        error = ctypes.get_errno()
        if error in (17, 39):
            raise FileExistsError(target)
        raise OSError(error, os.strerror(error), target)


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
    if not lowered.startswith(("select ", "(select ")) or FORBIDDEN_SQL.search(compact):
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


def validate_resource_facts(facts: Mapping[str, Any], limits: Mapping[str, int]) -> None:
    elapsed = facts.get("elapsed_seconds")
    rss = facts.get("rss_bytes")
    if not isinstance(elapsed, (int, float)) or elapsed < 0 or elapsed > limits["总时限秒"]:
        raise ValueError("BATCH_ELAPSED_LIMIT_EXCEEDED")
    if not isinstance(rss, int) or isinstance(rss, bool) or rss < 0 or rss > limits["RSS字节"]:
        raise ValueError("BATCH_RSS_LIMIT_EXCEEDED")
    sql_count = facts.get("non_explain_sql_count")
    if sql_count is not None and (
        not isinstance(sql_count, int)
        or isinstance(sql_count, bool)
        or sql_count < 0
        or sql_count > limits["SQL总数"]
    ):
        raise ValueError("BATCH_SQL_COUNT_EXCEEDED")


def _metadata_invariant(value: Mapping[str, Any]) -> dict[str, Any]:
    tables = [[row[0], row[1]] for row in value.get("tables", []) if len(row) >= 2]
    return {
        "protocol": value.get("protocol"),
        "uid": value.get("uid"),
        "client_sha256": value.get("client_sha256"),
        "client_version_sha256": value.get("client_version_sha256"),
        "select_capability": value.get("select_capability"),
        "option_files_disabled": value.get("option_files_disabled"),
        "login_path_redirected": value.get("login_path_redirected"),
        "credential_environment_cleared": value.get("credential_environment_cleared"),
        "metadata_query_count": value.get("metadata_query_count"),
        "tables": tables,
        "columns": value.get("columns"),
        "table_privileges": value.get("table_privileges"),
        "indexes": value.get("indexes"),
    }


def validate_metadata_snapshot(value: Mapping[str, Any]) -> None:
    if (
        value.get("protocol") != "zhishi-stage1-cost-metadata/1"
        or value.get("uid") != 0
        or value.get("select_capability") is not True
        or value.get("option_files_disabled") is not True
        or value.get("login_path_redirected") is not True
        or value.get("credential_environment_cleared") is not True
        or value.get("metadata_query_count") != 4
    ):
        raise ValueError("REMOTE_METADATA_IDENTITY_INVALID")
    for key in ("client_sha256", "client_version_sha256"):
        if not isinstance(value.get(key), str) or SHA_PATTERN.fullmatch(value[key]) is None:
            raise ValueError("REMOTE_METADATA_FINGERPRINT_INVALID")
    table_names = {row[0] for row in value.get("tables", []) if isinstance(row, list) and len(row) >= 1}
    select_tables = {
        row[0]
        for row in value.get("table_privileges", [])
        if isinstance(row, list) and len(row) == 3 and row[1] == "SELECT"
    }
    if len(table_names) != 5 or select_tables != table_names:
        raise ValueError("REMOTE_TABLE_SELECT_PRIVILEGE_INVALID")
    load1 = value.get("load1")
    cpu_count = value.get("cpu_count")
    if (
        not isinstance(load1, (int, float))
        or load1 < 0
        or not isinstance(cpu_count, int)
        or isinstance(cpu_count, bool)
        or cpu_count < 1
        or load1 > max(4.0, float(cpu_count) * 2.0)
    ):
        raise ValueError("REMOTE_LOAD_ALARM")


def assert_metadata_invariants_equal(pre: Mapping[str, Any], post: Mapping[str, Any]) -> None:
    validate_metadata_snapshot(pre)
    validate_metadata_snapshot(post)
    if _metadata_invariant(pre) != _metadata_invariant(post):
        raise ValueError("REMOTE_METADATA_DRIFT")


def validate_public_url(request_uri: str, config: Mapping[str, Any]) -> bool:
    parsed = urllib.parse.urlsplit(request_uri)
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
    funding_by_symbol = evidence.get("资金费率历史窗口已观察", {})
    if not isinstance(funding_by_symbol, Mapping):
        raise ValueError("FUNDING_STATUS_BY_SYMBOL_REQUIRED")
    reasons = {
        "手续费": ("PUBLIC_FEE_VERSION_UNPROVEN", "提供同版本、非账户专属的公开手续费身份"),
        "价差": ("HISTORICAL_ORDERBOOK_COVERAGE_INSUFFICIENT", "提供覆盖正式输入历史现场的买卖盘证据"),
        "深度": ("HISTORICAL_ORDERBOOK_COVERAGE_INSUFFICIENT", "提供覆盖正式输入历史现场的深度证据"),
        "冲击": ("HISTORICAL_ORDERBOOK_COVERAGE_INSUFFICIENT", "提供同历史现场、固定名义规模的冲击证据"),
        "行情可见性延迟": ("THREE_TIME_EXECUTION_MAPPING_MISSING", "绑定同历史现场的事件、到达与采集时间"),
        "可成交量": ("HISTORICAL_ORDERBOOK_COVERAGE_INSUFFICIENT", "提供同历史现场的可成交量证据"),
        "执行延迟": ("EXECUTION_LIFECYCLE_EVIDENCE_MISSING", "提供版本化模拟委托发送、确认/成交、排队和撤单时间"),
    }
    rows = []
    for symbol, direction, phase, horizon in product(
        ("BTCUSDT", "ETHUSDT"),
        ("做多", "做空"),
        ("入场", "退出"),
        (4, 8, 24, 48),
    ):
        statuses = {name: "无法判定" for name in ("手续费", "价差", "深度", "冲击", "资金费率", "行情可见性延迟", "可成交量")}
        funding_observed = funding_by_symbol.get(symbol) is True
        if funding_observed:
            statuses["资金费率"] = "已观察（覆盖不足）"
        funding_reason = (
            ("FUNDING_HISTORY_COVERAGE_INSUFFICIENT", "扩展同版本资金费率至正式输入历史窗口")
            if funding_observed
            else ("BINANCE_FUNDING_EVIDENCE_UNAVAILABLE", "取得该标的截止冻结时点的官方历史资金费率证据")
        )
        gate = build_gate_decision(statuses)
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
                "手续费原因代码": reasons["手续费"][0],
                "手续费解除条件": reasons["手续费"][1],
                "价差原因代码": reasons["价差"][0],
                "价差解除条件": reasons["价差"][1],
                "深度原因代码": reasons["深度"][0],
                "深度解除条件": reasons["深度"][1],
                "冲击原因代码": reasons["冲击"][0],
                "冲击解除条件": reasons["冲击"][1],
                "资金费率原因代码": funding_reason[0],
                "资金费率解除条件": funding_reason[1],
                "行情可见性延迟原因代码": reasons["行情可见性延迟"][0],
                "行情可见性延迟解除条件": reasons["行情可见性延迟"][1],
                "可成交量原因代码": reasons["可成交量"][0],
                "可成交量解除条件": reasons["可成交量"][1],
                "执行延迟原因代码": reasons["执行延迟"][0],
                "执行延迟解除条件": reasons["执行延迟"][1],
                "总门原因代码": "EXECUTION_LIFECYCLE_EVIDENCE_MISSING",
                "总门解除条件": "同一历史现场的版本化模拟委托生命周期证据",
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


def _working_directory(repo_root: Path, batch: str) -> Path:
    if BATCH_PATTERN.fullmatch(batch) is None:
        raise ValueError("BATCH_ID_INVALID")
    return repo_root / "artifacts" / "数据" / "阶段1成本执行" / ".pending" / batch


def _active_batch_directory(repo_root: Path, batch: str) -> Path:
    pending = _working_directory(repo_root, batch)
    return pending if pending.is_dir() else _batch_directory(repo_root, batch)


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
    final_dir = _batch_directory(repo_root, batch)
    if final_dir.exists():
        raise FileExistsError(final_dir)
    batch_dir = _working_directory(repo_root, batch)
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
    batch_dir = _active_batch_directory(repo_root, batch)
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
clean_env={"PATH":"/usr/bin:/bin","LC_ALL":"C","MYSQL_TEST_LOGIN_FILE":"/dev/null"}
def file_sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as stream:
  for chunk in iter(lambda:stream.read(1048576),b""): h.update(chunk)
 return h.hexdigest()
def run(sql):
 p=subprocess.run([client,"--no-defaults","--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",sql],capture_output=True,text=True,timeout=30,check=False,env=clean_env)
 if p.returncode: raise SystemExit("MYSQL_READ_FAILED")
 return p.stdout
quoted=",".join("'%s'"%x for x in tables)
table_rows=run("SELECT TABLE_NAME,ENGINE,COALESCE(TABLE_ROWS,0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME"%quoted)
columns=run("SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,DATA_TYPE,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME,ORDINAL_POSITION"%quoted)
privileges=run("SELECT TABLE_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME,PRIVILEGE_TYPE"%quoted)
indexes=run("SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME IN (%s) ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX"%quoted)
def lines(text): return [x.split("\t") for x in text.splitlines() if x]
version=subprocess.run([client,"--no-defaults","--version"],capture_output=True,text=True,timeout=5,check=True,env=clean_env).stdout
out={"protocol":"zhishi-stage1-cost-metadata/1","uid":os.getuid(),"client_sha256":file_sha(client),"client_version_sha256":hashlib.sha256(version.encode()).hexdigest(),"select_capability":True,"option_files_disabled":True,"login_path_redirected":True,"credential_environment_cleared":True,"metadata_query_count":4,"tables":lines(table_rows),"columns":lines(columns),"table_privileges":lines(privileges),"indexes":lines(indexes),"load1":os.getloadavg()[0],"cpu_count":os.cpu_count() or 1}
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
    validate_metadata_snapshot(value)
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


def _read_remote_metadata(config: Mapping[str, Any]) -> dict[str, Any]:
    value = _run_ssh_python(
        REMOTE_METADATA_PROGRAM,
        timeout=config["资源上限"]["单SQL秒"] * 5,
        max_log=config["资源上限"]["远端日志字节"],
    )
    validate_metadata_snapshot(value)
    return value


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
        targets = ",".join(f"'{target}'" for target in config["标的"])
        sql = (
            f"SELECT `{symbol}` AS symbol,MIN(`{event_time}`) AS earliest,MAX(`{event_time}`) AS latest "
            f"FROM `{table}` FORCE INDEX (`{index}`) WHERE `{symbol}` IN ({targets}) "
            f"AND `{event_time}`>={lower} AND `{event_time}`<{upper} "
            f"GROUP BY `{symbol}` ORDER BY `{symbol}` LIMIT 2"
        )
        validate_business_sql(sql, config)
        queries.append(
            {
                "查询编号": f"{table}:coverage-boundaries",
                "表": table,
                "标的": list(config["标的"]),
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


def validate_query_plan(
    plan: Mapping[str, Any],
    intent: Mapping[str, Any],
    metadata_evidence: Mapping[str, Any],
    config: Mapping[str, Any],
) -> None:
    if (
        plan.get("schema_version") != "zhishi-stage1-cost-query-plan/v1"
        or plan.get("batch_id") != intent.get("batch_id")
        or plan.get("intent_sha256") != sha256_bytes(canonical_bytes(intent))
        or plan.get("metadata_sha256") != sha256_bytes(canonical_bytes(metadata_evidence))
        or plan.get("business_query_retry_count") != 0
    ):
        raise ValueError("QUERY_PLAN_IDENTITY_DRIFT")
    queries = plan.get("queries")
    if not isinstance(queries, list):
        raise ValueError("QUERY_PLAN_LIST_REQUIRED")
    validate_query_manifest(queries, max_queries=config["资源上限"]["SQL总数"])
    if plan.get("query_count") != len(queries):
        raise ValueError("QUERY_PLAN_COUNT_DRIFT")
    expected = build_query_plan(metadata_evidence, intent, config)
    if queries != expected["queries"] or plan.get("skipped_tables") != expected["skipped_tables"]:
        raise ValueError("QUERY_PLAN_CONTENT_DRIFT")
    for query in queries:
        sql = query.get("SQL")
        if (
            not isinstance(sql, str)
            or query.get("SQL_SHA-256") != sha256_bytes(sql.encode("utf-8"))
            or validate_business_sql(sql, config) != query.get("表")
        ):
            raise ValueError("QUERY_SQL_IDENTITY_DRIFT")


def plan_queries(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    metadata = read_json(batch_dir / "metadata.json")
    plan = build_query_plan(metadata, intent, config)
    validate_query_plan(plan, intent, metadata, config)
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
clean_env={{"PATH":"/usr/bin:/bin","LC_ALL":"C","MYSQL_TEST_LOGIN_FILE":"/dev/null"}}
out=[]
for query in queries:
 sql=query["SQL"]
 compact=" ".join(sql.strip().split())
 lowered=compact.lower()
 forbidden=(not lowered.startswith(("select ","(select ")) or any(x in lowered for x in (" insert "," update "," delete "," replace "," alter "," drop "," create "," truncate "," grant "," revoke "," outfile "," dumpfile ",";","--","/*")) or " limit " not in " "+lowered+" ")
 if forbidden: raise SystemExit("REMOTE_SQL_NOT_READ_ONLY")
 statement=("EXPLAIN FORMAT=JSON "+sql) if {mode!r}=="explain" else sql
 p=subprocess.run([client,"--no-defaults","--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",statement],capture_output=True,text=True,timeout=30,check=False,env=clean_env)
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
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    metadata = read_json(batch_dir / "metadata.json")
    plan = read_json(batch_dir / "query-plan.json")
    validate_query_plan(plan, intent, metadata, config)
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


def validate_explain_evidence(
    explain: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    plan_sha256: str,
    config: Mapping[str, Any],
) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]], int]:
    if (
        explain.get("schema_version") != "zhishi-stage1-cost-query-explain/v1"
        or explain.get("batch_id") != plan.get("batch_id")
        or explain.get("query_plan_sha256") != plan_sha256
    ):
        raise ValueError("EXPLAIN_PLAN_IDENTITY_DRIFT")
    results = explain.get("results")
    if not isinstance(results, list) or len(results) != len(plan.get("queries", [])):
        raise ValueError("EXPLAIN_RESULT_MISMATCH")
    return _approved_queries(config, plan, explain)


def _approved_queries(config: Mapping[str, Any], plan: Mapping[str, Any], explain: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]], int]:
    by_id = {item["query_id"]: item for item in explain["results"]}
    if len(by_id) != len(explain["results"]):
        raise ValueError("EXPLAIN_QUERY_ID_DUPLICATE")
    approved = []
    decisions = []
    total_rows = 0
    for query in plan["queries"]:
        sql = query.get("SQL")
        if (
            not isinstance(sql, str)
            or query.get("SQL_SHA-256") != sha256_bytes(sql.encode("utf-8"))
            or validate_business_sql(sql, config) != query.get("表")
        ):
            raise ValueError("QUERY_SQL_IDENTITY_DRIFT")
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


def _public_requests(config: Mapping[str, Any], *, data_cutoff_at: str) -> list[dict[str, str]]:
    base = "https://fapi.binance.com"
    cutoff_ms = int(dt.datetime.fromisoformat(data_cutoff_at.replace("Z", "+00:00")).timestamp() * 1000)
    requests = [{"id": "exchange-info", "request_uri": base + "/fapi/v1/exchangeInfo", "kind": "current_exchange_info"}]
    for symbol in config["标的"]:
        encoded = urllib.parse.urlencode({"symbol": symbol, "limit": 5})
        requests.append({"id": f"depth-{symbol}", "request_uri": base + "/fapi/v1/depth?" + encoded, "kind": "current_depth"})
        requests.append({"id": f"premium-{symbol}", "request_uri": base + "/fapi/v1/premiumIndex?" + urllib.parse.urlencode({"symbol": symbol}), "kind": "current_premium"})
        requests.append({"id": f"funding-{symbol}", "request_uri": base + "/fapi/v1/fundingRate?" + urllib.parse.urlencode({"symbol": symbol, "endTime": cutoff_ms, "limit": 1000}), "kind": "historical_funding"})
    return requests


def build_binance_remote_program(config: Mapping[str, Any], request_item: Mapping[str, str] | None = None, *, data_cutoff_at: str = "2026-08-12T00:00:00Z") -> str:
    requests = [dict(request_item)] if request_item is not None else _public_requests(config, data_cutoff_at=data_cutoff_at)
    for item in requests:
        validate_public_url(item["request_uri"], config)
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
  response=subprocess.run([curl,"-q","--ipv4","--silent","--show-error","--fail","--connect-timeout","5","--max-time","10","--max-filesize","2000000","--user-agent","zhishi-cost-evidence/1.0",item["request_uri"]],capture_output=True,timeout=15,check=False,env={{"PATH":"/usr/bin:/bin","LC_ALL":"C"}})
  if response.returncode: raise RuntimeError("HTTPS_REQUEST_FAILED_"+str(response.returncode))
  raw=response.stdout
  if len(raw)>2000000: raise ValueError("BINANCE_RESPONSE_LIMIT_EXCEEDED")
  value=json.loads(raw)
  facts={{"request_id":item["id"],"kind":item["kind"],"status":"observed","collected_at":collected,"url_sha256":hashlib.sha256(item["request_uri"].encode()).hexdigest(),"response_sha256":hashlib.sha256(raw).hexdigest(),"response_bytes":len(raw),"schema_sha256":hashlib.sha256(canonical(shape(value))).hexdigest()}}
  if isinstance(value,list):
   facts["item_count"]=len(value)
   times=[x.get("fundingTime") for x in value if isinstance(x,dict) and isinstance(x.get("fundingTime"),int)]
   if times: facts.update({{"earliest_event_time_ms":min(times),"latest_event_time_ms":max(times)}})
  elif isinstance(value,dict) and isinstance(value.get("serverTime"),int): facts["server_time_ms"]=value["serverTime"]
  results.append(facts)
 except Exception as exc:
  reason=str(exc) if str(exc).startswith(("HTTPS_REQUEST_FAILED_","BINANCE_RESPONSE_LIMIT_EXCEEDED","CURL_MISSING")) else type(exc).__name__
  results.append({{"request_id":item["id"],"kind":item["kind"],"status":"failed","collected_at":collected,"url_sha256":hashlib.sha256(item["request_uri"].encode()).hexdigest(),"reason":reason}})
print(json.dumps({{"protocol":"zhishi-binance-public-evidence/1","requests":results}},sort_keys=True,separators=(",",":")))
'''


def fetch_binance_public(config: Mapping[str, Any], *, data_cutoff_at: str) -> dict[str, Any]:
    evidence = []
    cutoff_ms = int(dt.datetime.fromisoformat(data_cutoff_at.replace("Z", "+00:00")).timestamp() * 1000)
    for item in _public_requests(config, data_cutoff_at=data_cutoff_at):
        try:
            result = _run_ssh_python(
                build_binance_remote_program(config, item, data_cutoff_at=data_cutoff_at),
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
                    "url_sha256": sha256_bytes(item["request_uri"].encode("utf-8")),
                    "reason": str(exc),
                }
            )
    for item in evidence:
        if item.get("kind") == "historical_funding" and item.get("status") == "observed":
            if item.get("latest_event_time_ms", cutoff_ms + 1) > cutoff_ms:
                raise ValueError("BINANCE_EVENT_AFTER_CUTOFF")
    return {"schema_version": "zhishi-binance-public-evidence/v1", "transport": "ubuntu-curl-ipv4-verified-https", "data_cutoff_at": data_cutoff_at, "requests": evidence}


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
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    metadata = read_json(batch_dir / "metadata.json")
    plan = read_json(batch_dir / "query-plan.json")
    explain = read_json(batch_dir / "query-explain.json")
    validate_query_plan(plan, intent, metadata, config)
    approved, decisions, estimated_rows = validate_explain_evidence(
        explain,
        plan=plan,
        plan_sha256=sha256_path(batch_dir / "query-plan.json"),
        config=config,
    )
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
    if any(
        item.get("row_count", 0) > config["资源上限"]["返回聚合行"]
        for item in database_result["results"]
    ):
        raise ValueError("DATABASE_RESULT_ROWS_EXCEEDED")
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
    post_metadata_value = _read_remote_metadata(config)
    assert_metadata_invariants_equal(metadata["metadata"], post_metadata_value)
    post_metadata = {
        "schema_version": "zhishi-stage1-cost-metadata-post-evidence/v1",
        "batch_id": batch,
        "observed_at": utc_now(),
        "root_compatible_read_only": True,
        "remote_write_performed": False,
        "metadata": post_metadata_value,
        "metadata_sha256": sha256_bytes(canonical_bytes(post_metadata_value)),
    }
    write_json_exclusive(batch_dir / "metadata-post.json", post_metadata)
    binance = fetch_binance_public(config, data_cutoff_at=intent["data_cutoff_at"])
    funding_by_symbol = {
        symbol: any(
            item["request_id"] == f"funding-{symbol}"
            and item["status"] == "observed"
            and item.get("item_count", 0) > 0
            for item in binance["requests"]
        )
        for symbol in config["标的"]
    }
    funding_ok = all(funding_by_symbol.values())
    rows = build_group_rows(batch=batch, evidence={"资金费率历史窗口已观察": funding_by_symbol})
    elapsed_seconds = (
        dt.datetime.now(dt.timezone.utc)
        - dt.datetime.fromisoformat(intent["created_at"].replace("Z", "+00:00"))
    ).total_seconds()
    resource_facts = {
        "elapsed_seconds": round(elapsed_seconds, 6),
        "rss_bytes": _rss_bytes(),
        "estimated_database_rows": estimated_rows,
        "database_response_bytes": response_bytes,
        "metadata_query_count": 8,
        "business_query_count": len(approved),
        "non_explain_sql_count": 8 + len(approved),
        "output_limit_bytes": config["资源上限"]["本地输出字节"],
    }
    validate_resource_facts(resource_facts, config["资源上限"])
    summary = {
        "schema_version": "zhishi-stage1-cost-execution-summary/v1",
        "task_id": "000100",
        "batch_id": batch,
        "intent_sha256": sha256_path(batch_dir / "intent.json"),
        "metadata_sha256": sha256_path(batch_dir / "metadata.json"),
        "metadata_post_sha256": sha256_path(batch_dir / "metadata-post.json"),
        "query_plan_sha256": sha256_path(batch_dir / "query-plan.json"),
        "query_explain_sha256": sha256_path(batch_dir / "query-explain.json"),
        "candidate_group_count": 32,
        "observed_group_count": 32,
        "status_counts": {"拒绝": 0, "无法判定": 32, "失败": 0, "未成熟": 0, "失效": 0, "通过": 0},
        "funding_window_observed_for_both_symbols": funding_ok,
        "funding_window_observed_by_symbol": funding_by_symbol,
        "execution_latency_status": "无法判定",
        "cost_execution_gate": "无法判定",
        "stage1_complete": False,
        "stage2_released": False,
        "remaining_condition": "同一历史现场的版本化模拟委托生命周期证据",
        "resource_facts": resource_facts,
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
    validate_batch(repo_root, batch)
    final_dir = _batch_directory(repo_root, batch)
    publish_directory_no_replace(batch_dir, final_dir)
    pending_parent = batch_dir.parent
    try:
        pending_parent.rmdir()
    except OSError:
        pass
    return summary


def validate_batch(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, batch_dir = _assert_intent(repo_root, batch)
    manifest = read_json(batch_dir / "manifest.json")
    if (
        manifest.get("schema_version") != "zhishi-stage1-cost-execution-manifest/v1"
        or manifest.get("batch_id") != batch
        or set(manifest.get("files", {})) != REQUIRED_BATCH_FILES
        or manifest.get("file_count") != len(REQUIRED_BATCH_FILES)
    ):
        raise ValueError("BATCH_FILE_SET_INVALID")
    actual_files = {
        path.name for path in batch_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    if actual_files != REQUIRED_BATCH_FILES:
        raise ValueError("BATCH_ACTUAL_FILE_SET_INVALID")
    for name, expected in manifest["files"].items():
        path = batch_dir / name
        if sha256_path(path) != expected["sha256"] or path.stat().st_size != expected["bytes"]:
            raise ValueError("BATCH_FILE_DRIFT")
        assert_safe_text(path.read_text(encoding="utf-8"))
    total_bytes = sum(item["bytes"] for item in manifest["files"].values())
    if (
        manifest.get("total_bytes") != total_bytes
        or manifest.get("manifest_payload_sha256") != sha256_bytes(canonical_bytes(manifest["files"]))
        or total_bytes > config["资源上限"]["本地输出字节"]
    ):
        raise ValueError("BATCH_OUTPUT_LIMIT_EXCEEDED")

    metadata = read_json(batch_dir / "metadata.json")
    metadata_post = read_json(batch_dir / "metadata-post.json")
    for value, schema in (
        (metadata, "zhishi-stage1-cost-metadata-evidence/v1"),
        (metadata_post, "zhishi-stage1-cost-metadata-post-evidence/v1"),
    ):
        if (
            value.get("schema_version") != schema
            or value.get("batch_id") != batch
            or value.get("remote_write_performed") is not False
            or value.get("metadata_sha256") != sha256_bytes(canonical_bytes(value.get("metadata")))
        ):
            raise ValueError("BATCH_METADATA_EVIDENCE_INVALID")
    assert_metadata_invariants_equal(metadata["metadata"], metadata_post["metadata"])

    plan = read_json(batch_dir / "query-plan.json")
    validate_query_plan(plan, intent, metadata, config)
    explain = read_json(batch_dir / "query-explain.json")
    approved, decisions, estimated_rows = validate_explain_evidence(
        explain, plan=plan,
        plan_sha256=sha256_path(batch_dir / "query-plan.json"),
        config=config,
    )
    database = read_json(batch_dir / "database-evidence.json")
    results = database.get("results")
    if (
        database.get("schema_version") != "zhishi-stage1-cost-database-evidence/v1"
        or database.get("batch_id") != batch
        or database.get("query_decisions") != decisions
        or database.get("estimated_rows") != estimated_rows
        or database.get("executed_query_count") != len(approved)
        or database.get("query_retry_count") != 0
        or database.get("remote_write_performed") is not False
        or not isinstance(results, list)
        or [item.get("query_id") for item in results]
        != [item["查询编号"] for item in approved]
    ):
        raise ValueError("BATCH_DATABASE_EVIDENCE_INVALID")
    response_bytes = 0
    cutoff = dt.datetime.fromisoformat(intent["data_cutoff_at"].replace("Z", "+00:00"))
    for query, result in zip(approved, results, strict=True):
        rows = result.get("rows")
        if (
            not isinstance(rows, list)
            or result.get("row_count") != len(rows)
            or len(rows) > config["资源上限"]["返回聚合行"]
            or not isinstance(result.get("response_bytes"), int)
        ):
            raise ValueError("BATCH_DATABASE_RESULT_INVALID")
        response_bytes += result["response_bytes"]
        observed_symbols: set[str] = set()
        for row in rows:
            if (
                not isinstance(row, list)
                or len(row) != 3
                or row[0] not in query["标的"]
                or row[0] in observed_symbols
            ):
                raise ValueError("BATCH_DATABASE_ROW_INVALID")
            observed_symbols.add(row[0])
            for raw_value in row[1:]:
                raw_time = int(raw_value)
                event = dt.datetime.fromtimestamp(
                    raw_time / (1000 if "_ms" in query["SQL"] else 1),
                    tz=dt.timezone.utc,
                )
                if event >= cutoff:
                    raise ValueError("BATCH_DATABASE_EVENT_AFTER_CUTOFF")
    if database.get("response_bytes") != response_bytes:
        raise ValueError("BATCH_DATABASE_BYTES_INVALID")

    binance = read_json(batch_dir / "binance-evidence.json")
    expected_request_ids = {
        item["id"] for item in _public_requests(
            config, data_cutoff_at=intent["data_cutoff_at"]
        )
    }
    requests = binance.get("requests")
    if (
        binance.get("schema_version") != "zhishi-binance-public-evidence/v1"
        or binance.get("data_cutoff_at") != intent["data_cutoff_at"]
        or not isinstance(requests, list)
        or {item.get("request_id") for item in requests} != expected_request_ids
        or len(requests) != len(expected_request_ids)
    ):
        raise ValueError("BATCH_BINANCE_EVIDENCE_INVALID")
    cutoff_ms = int(cutoff.timestamp() * 1000)
    for item in requests:
        if (
            item.get("kind") == "historical_funding"
            and item.get("status") == "observed"
            and item.get("latest_event_time_ms", cutoff_ms + 1) > cutoff_ms
        ):
            raise ValueError("BATCH_BINANCE_EVENT_AFTER_CUTOFF")
    funding_by_symbol = {
        symbol: any(
            item.get("request_id") == f"funding-{symbol}"
            and item.get("status") == "observed"
            and item.get("item_count", 0) > 0
            for item in requests
        )
        for symbol in config["标的"]
    }
    funding_ok = all(funding_by_symbol.values())
    expected_csv = _csv_payload(
        build_group_rows(batch=batch, evidence={"资金费率历史窗口已观察": funding_by_symbol})
    )
    if (batch_dir / "group-results.csv").read_text(encoding="utf-8") != expected_csv:
        raise ValueError("BATCH_GROUP_RESULTS_INVALID")

    summary = read_json(batch_dir / "summary.json")
    counts = summary["status_counts"]
    expected_hashes = {
        "intent_sha256": sha256_path(batch_dir / "intent.json"),
        "metadata_sha256": sha256_path(batch_dir / "metadata.json"),
        "metadata_post_sha256": sha256_path(batch_dir / "metadata-post.json"),
        "query_plan_sha256": sha256_path(batch_dir / "query-plan.json"),
        "query_explain_sha256": sha256_path(batch_dir / "query-explain.json"),
    }
    if (
        any(summary.get(key) != value for key, value in expected_hashes.items())
        or sum(counts.values()) != summary["candidate_group_count"]
        or summary.get("candidate_group_count") != 32
        or summary.get("observed_group_count") != 32
        or counts != {"拒绝": 0, "无法判定": 32, "失败": 0, "未成熟": 0, "失效": 0, "通过": 0}
        or summary.get("funding_window_observed_for_both_symbols") != funding_ok
        or summary.get("funding_window_observed_by_symbol") != funding_by_symbol
        or summary.get("execution_latency_status") != "无法判定"
        or summary.get("cost_execution_gate") != "无法判定"
        or summary.get("stage1_complete") is not False
        or summary.get("stage2_released") is not False
        or summary.get("safety") != {
            "remote_write": False,
            "database_write": False,
            "account_endpoint": False,
            "credential_read": False,
            "raw_price_or_quantity_persisted": False,
            "model_or_backtest": False,
            "trade_decision": False,
        }
        or summary.get("resource_facts", {}).get("estimated_database_rows") != estimated_rows
        or summary.get("resource_facts", {}).get("database_response_bytes") != response_bytes
        or summary.get("resource_facts", {}).get("metadata_query_count") != 8
        or summary.get("resource_facts", {}).get("business_query_count") != len(approved)
        or summary.get("resource_facts", {}).get("non_explain_sql_count") != 8 + len(approved)
    ):
        raise ValueError("BATCH_DENOMINATOR_OR_GATE_INVALID")
    validate_resource_facts(summary["resource_facts"], config["资源上限"])
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
