#!/usr/bin/env python3
"""任务-000103：用有界只读订单簿输入验证模拟委托生命周期。"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from collections import Counter
from decimal import Decimal, InvalidOperation
from itertools import product
from pathlib import Path
from typing import Any, Iterable, Mapping


SCRIPT_VERSION = "stage1-simulated-order-lifecycle-1.0"
CONFIG_RELATIVE_PATH = Path("config/模拟交易/任务-000103阶段1委托生命周期.json")
TASK_RELATIVE_PATH = Path("docs/研发中心/任务/任务-000103.md")
BATCH_PATTERN = re.compile(r"^stage1-simulated-lifecycle-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_SQL = re.compile(
    r"(?is)(?:\b(?:insert|update|delete|replace|alter|drop|create|truncate|grant|"
    r"revoke|lock|unlock|call|load|outfile|dumpfile|procedure)\b|/\*|--|#|;)"
)
ALLOWED_STATES = {
    "created": {"sent"},
    "sent": {"acknowledged"},
    "acknowledged": {"evaluated"},
    "evaluated": {"filled", "canceled", "unknown"},
}
REQUIRED_SCHEMA = (
    "snapshot_id",
    "exchange",
    "symbol",
    "capture_ts_ms",
    "capture_reason",
    "trigger_signal_id",
    "trigger_event_id",
    "bucket_ts_sec",
    "payload_json",
    "payload_msgpack",
    "payload_size_bytes",
    "payload_json_full",
    "created_at",
)
PENDING_FILES_BEFORE_VALIDATE = frozenset(
    {
        "intent.json",
        "metadata.json",
        "query-plan.json",
        "query-explain.json",
        "frozen-input.json",
        "lifecycle.json",
        "replay-1.json",
        "replay-2.json",
    }
)
PUBLISHED_FILES = PENDING_FILES_BEFORE_VALIDATE | frozenset({"summary.json"})


def _load_base_module() -> Any:
    path = Path(__file__).resolve().parents[1] / "数据" / "验证阶段1成本执行.py"
    spec = importlib.util.spec_from_file_location("zhishi_stage1_cost_base", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BASE_MODULE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = _load_base_module()
canonical_bytes = BASE.canonical_bytes
sha256_bytes = BASE.sha256_bytes
sha256_path = BASE.sha256_path
utc_now = BASE.utc_now
write_json_exclusive = BASE.write_json_exclusive
publish_directory_no_replace = BASE.publish_directory_no_replace
read_json = BASE.read_json
validate_explain = BASE.validate_explain
_rss_bytes = BASE._rss_bytes


def _normalized_task_fingerprint(path: Path) -> str:
    volatile = (
        "- 状态：",
        "- 执行分支：",
        "- 开始时间：",
        "- 提交SHA：",
        "- Pull Request：",
        "- 交付物：",
        "- 验证结果：",
        "- 合并时间：",
        "- 合并提交SHA：",
    )
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.startswith(volatile)
    ]
    return sha256_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def validate_config(config: Mapping[str, Any]) -> None:
    expected_fields = {
        "合同版本",
        "任务编号",
        "SSH逻辑别名",
        "数据库",
        "数据表",
        "复合索引",
        "标的",
        "交易场所",
        "市场",
        "方向",
        "委托场景",
        "时钟场景",
        "主研究尺度",
        "上游输入",
        "资源上限",
    }
    if set(config) != expected_fields:
        raise ValueError("CONFIG_FIELDS_MISMATCH")
    if config["合同版本"] != SCRIPT_VERSION or config["任务编号"] != "任务-000103":
        raise ValueError("CONFIG_IDENTITY_MISMATCH")
    if (
        config["SSH逻辑别名"] != "ubuntu"
        or config["数据库"] != "orderbook"
        or config["数据表"] != "order_book_raw_snapshots"
        or config["复合索引"] != "idx_raw_snapshot_symbol_capture"
    ):
        raise ValueError("CONFIG_REMOTE_SCOPE_MISMATCH")
    if config["标的"] != ["BTCUSDT", "ETHUSDT"]:
        raise ValueError("CONFIG_SYMBOL_SCOPE_MISMATCH")
    if config["方向"] != ["做多", "做空"]:
        raise ValueError("CONFIG_DIRECTION_SCOPE_MISMATCH")
    if config["委托场景"] != ["进取型市价", "进取型限价", "被动限价撤销"]:
        raise ValueError("CONFIG_SCENARIO_SCOPE_MISMATCH")
    if config["时钟场景"] != ["基准", "压力"]:
        raise ValueError("CONFIG_CLOCK_SCOPE_MISMATCH")
    if config["主研究尺度"] != [
        "主研究尺度：4小时",
        "主研究尺度：8小时",
        "主研究尺度：24小时",
        "主研究尺度：48小时",
    ]:
        raise ValueError("CONFIG_HORIZON_SCOPE_MISMATCH")
    limits = config["资源上限"]
    if limits != {
        "单SQL秒": 30,
        "每标的快照": 256,
        "总快照": 512,
        "估算扫描行": 10000,
        "业务响应字节": 67108864,
        "远端日志字节": 65536,
        "本地输出字节": 16777216,
        "RSS字节": 268435456,
        "总时限秒": 600,
    }:
        raise ValueError("CONFIG_RESOURCE_LIMIT_MISMATCH")
    upstream = config["上游输入"]
    if (
        upstream.get("批次") != "stage1-cost-execution-20260812T171000Z-81f61b9fae06"
        or upstream.get("清单SHA-256")
        != "4ba3842c1f52255a9cc7dee0c2872917962b15bf9957bf9b016f61c1f6f28b47"
        or upstream.get("摘要SHA-256")
        != "f8743203c7499398087919735df27b060a919785d5627d6e9f5e4714b02bfdfb"
    ):
        raise ValueError("CONFIG_UPSTREAM_IDENTITY_MISMATCH")


def validate_business_sql(sql: str, config: Mapping[str, Any]) -> None:
    compact = " ".join(sql.strip().split())
    lowered = compact.lower()
    if not lowered.startswith("select ") or FORBIDDEN_SQL.search(compact):
        raise ValueError("SQL_NOT_READ_ONLY")
    if re.search(r"(?is)select\s+(?:distinct\s+)?\*", compact):
        raise ValueError("SQL_WILDCARD_REJECTED")
    if f"from `{config['数据表']}`" not in lowered:
        raise ValueError("SQL_TABLE_NOT_ALLOWED")
    if f"force index (`{config['复合索引']}`)" not in lowered:
        raise ValueError("SQL_INDEX_REQUIRED")
    if " limit 256" not in lowered:
        raise ValueError("SQL_LIMIT_REQUIRED")
    if "order by `capture_ts_ms` desc,`snapshot_id` desc" not in lowered:
        raise ValueError("SQL_TOTAL_ORDER_REQUIRED")


def _load_config(repo_root: Path) -> tuple[dict[str, Any], Path]:
    path = repo_root / CONFIG_RELATIVE_PATH
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError("CONFIG_OBJECT_REQUIRED")
    validate_config(value)
    return value, path


def _batch_directory(repo_root: Path, batch: str) -> Path:
    if BATCH_PATTERN.fullmatch(batch) is None:
        raise ValueError("BATCH_ID_INVALID")
    return repo_root / "artifacts" / "模拟交易" / "阶段1委托生命周期" / batch


def _working_directory(repo_root: Path, batch: str) -> Path:
    if BATCH_PATTERN.fullmatch(batch) is None:
        raise ValueError("BATCH_ID_INVALID")
    return repo_root / "artifacts" / "模拟交易" / "阶段1委托生命周期" / ".pending" / batch


def _active_directory(repo_root: Path, batch: str) -> Path:
    pending = _working_directory(repo_root, batch)
    return pending if pending.is_dir() else _batch_directory(repo_root, batch)


def _assert_upstream(repo_root: Path, config: Mapping[str, Any]) -> dict[str, str]:
    upstream = config["上游输入"]
    root = repo_root / str(upstream["目录"])
    manifest = root / "manifest.json"
    summary = root / "summary.json"
    if sha256_path(manifest) != upstream["清单SHA-256"]:
        raise ValueError("UPSTREAM_MANIFEST_DRIFT")
    if sha256_path(summary) != upstream["摘要SHA-256"]:
        raise ValueError("UPSTREAM_SUMMARY_DRIFT")
    return {"manifest_sha256": sha256_path(manifest), "summary_sha256": sha256_path(summary)}


def prepare(repo_root: Path, batch: str) -> dict[str, Any]:
    started = time.monotonic()
    config, config_path = _load_config(repo_root)
    if _batch_directory(repo_root, batch).exists():
        raise FileExistsError(_batch_directory(repo_root, batch))
    batch_dir = _working_directory(repo_root, batch)
    batch_dir.mkdir(parents=True, exist_ok=False)
    now = dt.datetime.now(dt.timezone.utc)
    intent = {
        "schema_version": "zhishi-simulated-order-lifecycle-intent/v1",
        "task_id": "000103",
        "batch_id": batch,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "data_cutoff_ms": int(now.timestamp() * 1000),
        "config_sha256": sha256_path(config_path),
        "script_sha256": sha256_path(Path(__file__).resolve()),
        "base_script_sha256": sha256_path(Path(BASE.__file__).resolve()),
        "task_contract_normalized_sha256": _normalized_task_fingerprint(
            repo_root / TASK_RELATIVE_PATH
        ),
        "upstream": _assert_upstream(repo_root, config),
        "source_scope": {
            "ssh_alias": "ubuntu",
            "database": "orderbook",
            "table": "order_book_raw_snapshots",
            "symbols": config["标的"],
        },
        "scenario_scope": {
            "directions": config["方向"],
            "order_scenarios": config["委托场景"],
            "clock_scenarios": config["时钟场景"],
            "horizons": config["主研究尺度"],
        },
        "resource_limits": config["资源上限"],
        "process": {
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "rss_bytes": _rss_bytes(),
        },
    }
    write_json_exclusive(batch_dir / "intent.json", intent)
    return intent


def _assert_intent(repo_root: Path, batch: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    config, config_path = _load_config(repo_root)
    directory = _active_directory(repo_root, batch)
    intent = read_json(directory / "intent.json")
    expected = {
        "config_sha256": sha256_path(config_path),
        "script_sha256": sha256_path(Path(__file__).resolve()),
        "base_script_sha256": sha256_path(Path(BASE.__file__).resolve()),
        "task_contract_normalized_sha256": _normalized_task_fingerprint(
            repo_root / TASK_RELATIVE_PATH
        ),
    }
    for key, value in expected.items():
        if intent.get(key) != value:
            raise ValueError(f"INTENT_{key.upper()}_DRIFT")
    _assert_upstream(repo_root, config)
    return intent, config, directory


REMOTE_METADATA_PROGRAM = r'''
import hashlib,json,os,shutil,subprocess
table="order_book_raw_snapshots"
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
def lines(text): return [x.split("\t") for x in text.splitlines() if x]
tables=run("SELECT TABLE_NAME,ENGINE,COALESCE(TABLE_ROWS,0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME='order_book_raw_snapshots' ORDER BY TABLE_NAME")
columns=run("SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,DATA_TYPE,IS_NULLABLE,COLUMN_COMMENT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME='order_book_raw_snapshots' ORDER BY ORDINAL_POSITION")
privileges=run("SELECT TABLE_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME='order_book_raw_snapshots' ORDER BY PRIVILEGE_TYPE")
indexes=run("SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='orderbook' AND TABLE_NAME='order_book_raw_snapshots' ORDER BY INDEX_NAME,SEQ_IN_INDEX")
version=subprocess.run([client,"--no-defaults","--version"],capture_output=True,text=True,timeout=5,check=True,env=clean_env).stdout
out={"protocol":"zhishi-stage1-simulated-lifecycle-metadata/1","uid":os.getuid(),"client_sha256":file_sha(client),"client_version_sha256":hashlib.sha256(version.encode()).hexdigest(),"select_capability":True,"option_files_disabled":True,"login_path_redirected":True,"credential_environment_cleared":True,"metadata_query_count":4,"tables":lines(tables),"columns":lines(columns),"table_privileges":lines(privileges),"indexes":lines(indexes),"load1":os.getloadavg()[0],"cpu_count":os.cpu_count() or 1}
print(json.dumps(out,sort_keys=True,separators=(",",":")))
'''


def _run_ssh_python(
    program: str, *, timeout: int, max_stderr: int, max_stdout: int
) -> dict[str, Any]:
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
        result = subprocess.run(
            command,
            input=program,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("REMOTE_READ_TIMEOUT") from exc
    stderr = result.stderr.encode("utf-8", errors="replace")
    stdout = result.stdout.encode("utf-8", errors="replace")
    if len(stderr) > max_stderr:
        raise RuntimeError("REMOTE_LOG_LIMIT_EXCEEDED")
    if len(stdout) > max_stdout:
        raise RuntimeError("REMOTE_RESPONSE_LIMIT_EXCEEDED")
    if result.returncode != 0:
        raise RuntimeError(
            f"REMOTE_READ_FAILED:{result.returncode}:{sha256_bytes(stderr)}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("REMOTE_RESPONSE_OBJECT_REQUIRED")
    return value


def validate_metadata_snapshot(value: Mapping[str, Any]) -> None:
    if (
        value.get("protocol") != "zhishi-stage1-simulated-lifecycle-metadata/1"
        or value.get("uid") != 0
        or value.get("select_capability") is not True
        or value.get("option_files_disabled") is not True
        or value.get("login_path_redirected") is not True
        or value.get("credential_environment_cleared") is not True
        or value.get("metadata_query_count") != 4
    ):
        raise ValueError("REMOTE_METADATA_IDENTITY_INVALID")
    for name in ("client_sha256", "client_version_sha256"):
        if not isinstance(value.get(name), str) or SHA_PATTERN.fullmatch(value[name]) is None:
            raise ValueError("REMOTE_METADATA_FINGERPRINT_INVALID")
    tables = value.get("tables", [])
    if len(tables) != 1 or tables[0][0] != "order_book_raw_snapshots":
        raise ValueError("REMOTE_TABLE_IDENTITY_INVALID")
    columns = value.get("columns", [])
    if tuple(row[1] for row in columns) != REQUIRED_SCHEMA:
        raise ValueError("REMOTE_SCHEMA_DRIFT")
    privileges = value.get("table_privileges", [])
    if [row[:2] for row in privileges] != [["order_book_raw_snapshots", "SELECT"]]:
        raise ValueError("REMOTE_SELECT_PRIVILEGE_INVALID")
    index_parts: dict[str, list[tuple[int, str]]] = {}
    for row in value.get("indexes", []):
        index_parts.setdefault(row[1], []).append((int(row[3]), row[4]))
    indexes = {
        name: [column for _, column in sorted(parts)]
        for name, parts in index_parts.items()
    }
    if indexes.get("idx_raw_snapshot_symbol_capture") != ["symbol", "capture_ts_ms"]:
        raise ValueError("REMOTE_COMPOSITE_INDEX_DRIFT")
    if indexes.get("PRIMARY") != ["snapshot_id"]:
        raise ValueError("REMOTE_PRIMARY_KEY_DRIFT")
    load1 = value.get("load1")
    cpu = value.get("cpu_count")
    if not isinstance(load1, (int, float)) or not isinstance(cpu, int) or load1 > max(4, cpu * 2):
        raise ValueError("REMOTE_LOAD_ALARM")


def probe_metadata(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, directory = _assert_intent(repo_root, batch)
    value = _run_ssh_python(
        REMOTE_METADATA_PROGRAM,
        timeout=config["资源上限"]["单SQL秒"] * 5,
        max_stderr=config["资源上限"]["远端日志字节"],
        max_stdout=config["资源上限"]["远端日志字节"],
    )
    validate_metadata_snapshot(value)
    evidence = {
        "schema_version": "zhishi-simulated-order-metadata-evidence/v1",
        "batch_id": batch,
        "intent_sha256": sha256_path(directory / "intent.json"),
        "observed_at": utc_now(),
        "root_compatible_read_only": True,
        "remote_write_performed": False,
        "metadata": value,
        "metadata_sha256": sha256_bytes(canonical_bytes(value)),
    }
    write_json_exclusive(directory / "metadata.json", evidence)
    return evidence


def build_query_plan(
    metadata_evidence: Mapping[str, Any], intent: Mapping[str, Any], config: Mapping[str, Any]
) -> dict[str, Any]:
    validate_metadata_snapshot(metadata_evidence["metadata"])
    upper = int(intent["data_cutoff_ms"])
    lower = max(0, upper - 7 * 24 * 60 * 60 * 1000)
    queries = []
    for symbol in config["标的"]:
        sql = (
            "SELECT `snapshot_id`,`symbol`,`capture_ts_ms`,`created_at`,`payload_json_full` "
            "FROM `order_book_raw_snapshots` FORCE INDEX (`idx_raw_snapshot_symbol_capture`) "
            f"WHERE `symbol`='{symbol}' AND `capture_ts_ms`>={lower} "
            f"AND `capture_ts_ms`<{upper} AND `payload_size_bytes`<=65536 "
            "ORDER BY `capture_ts_ms` DESC,`snapshot_id` DESC LIMIT 256"
        )
        validate_business_sql(sql, config)
        queries.append(
            {
                "query_id": f"bounded-snapshot:{symbol}",
                "symbol": symbol,
                "index": config["复合索引"],
                "SQL": sql,
                "SQL_SHA-256": sha256_bytes(sql.encode("utf-8")),
            }
        )
    return {
        "schema_version": "zhishi-simulated-order-query-plan/v1",
        "batch_id": intent["batch_id"],
        "intent_sha256": sha256_bytes(canonical_bytes(intent)),
        "metadata_sha256": sha256_bytes(canonical_bytes(metadata_evidence)),
        "time_lower_ms": lower,
        "time_upper_ms": upper,
        "queries": queries,
        "query_count": len(queries),
        "retry_count": 0,
    }


def _remote_query_program(queries: list[Mapping[str, Any]], *, explain_only: bool) -> str:
    encoded = json.dumps(queries, ensure_ascii=False, separators=(",", ":"))
    mode = "explain" if explain_only else "execute"
    return f'''
import base64,hashlib,json,shutil,subprocess
queries=json.loads({encoded!r})
client=shutil.which("mysql") or shutil.which("mariadb")
if not client: raise SystemExit("MYSQL_CLIENT_MISSING")
clean_env={{"PATH":"/usr/bin:/bin","LC_ALL":"C","MYSQL_TEST_LOGIN_FILE":"/dev/null"}}
out=[]
for query in queries:
 sql=query["SQL"]
 lowered=" ".join(sql.strip().split()).lower()
 if not lowered.startswith("select ") or any(x in lowered for x in (" insert "," update "," delete "," replace "," alter "," drop "," create "," truncate "," grant "," revoke "," outfile "," dumpfile ",";","--","/*")) or " limit 256" not in lowered:
  raise SystemExit("REMOTE_SQL_NOT_READ_ONLY")
 statement=("EXPLAIN FORMAT=JSON "+sql) if {mode!r}=="explain" else sql
 p=subprocess.run([client,"--no-defaults","--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",statement],capture_output=True,timeout=30,check=False,env=clean_env)
 if p.returncode: raise SystemExit("MYSQL_QUERY_FAILED")
 if {mode!r}=="explain":
  out.append({{"query_id":query["query_id"],"plan":json.loads(p.stdout.decode()),"response_sha256":hashlib.sha256(p.stdout).hexdigest(),"response_bytes":len(p.stdout)}})
 else:
  lines=[line for line in p.stdout.splitlines() if line]
  out.append({{"query_id":query["query_id"],"row_count":len(lines),"rows_base64":[base64.b64encode(line).decode() for line in lines],"response_sha256":hashlib.sha256(p.stdout).hexdigest(),"response_bytes":len(p.stdout)}})
print(json.dumps({{"protocol":"zhishi-stage1-simulated-lifecycle-query/1","mode":{mode!r},"results":out}},sort_keys=True,separators=(",",":")))
'''


def plan_queries(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, directory = _assert_intent(repo_root, batch)
    metadata = read_json(directory / "metadata.json")
    plan = build_query_plan(metadata, intent, config)
    explain_result = _run_ssh_python(
        _remote_query_program(plan["queries"], explain_only=True),
        timeout=90,
        max_stderr=config["资源上限"]["远端日志字节"],
        max_stdout=config["资源上限"]["远端日志字节"],
    )
    if explain_result.get("mode") != "explain":
        raise ValueError("EXPLAIN_MODE_INVALID")
    total_rows = 0
    for query, result in zip(plan["queries"], explain_result.get("results", []), strict=True):
        if result.get("query_id") != query["query_id"]:
            raise ValueError("EXPLAIN_QUERY_ID_DRIFT")
        total_rows += validate_explain(
            result["plan"],
            allowed_indexes={config["复合索引"]},
            max_rows=config["资源上限"]["估算扫描行"],
        )
    if total_rows > config["资源上限"]["估算扫描行"]:
        raise ValueError("EXPLAIN_TOTAL_ROWS_EXCEEDED")
    explain = {
        "schema_version": "zhishi-simulated-order-query-explain/v1",
        "batch_id": batch,
        "query_plan_sha256": sha256_bytes(canonical_bytes(plan)),
        "estimated_rows": total_rows,
        "results": explain_result["results"],
    }
    write_json_exclusive(directory / "query-plan.json", plan)
    write_json_exclusive(directory / "query-explain.json", explain)
    return {"plan": plan, "explain": explain}


def _decimal_pair(value: Any) -> tuple[Decimal, Decimal]:
    if isinstance(value, Mapping) and set(value) >= {"price", "quantity"}:
        raw_price, raw_quantity = value["price"], value["quantity"]
    elif isinstance(value, list) and len(value) >= 2:
        raw_price, raw_quantity = value[0], value[1]
    else:
        raise ValueError("BOOK_LEVEL_SHAPE_INVALID")
    try:
        price = Decimal(str(raw_price))
        quantity = Decimal(str(raw_quantity))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("BOOK_LEVEL_NUMBER_INVALID") from exc
    if not price.is_finite() or not quantity.is_finite() or price <= 0 or quantity < 0:
        raise ValueError("BOOK_LEVEL_RANGE_INVALID")
    return price, quantity


def _payload_body(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    candidates = []
    if any(key in payload for key in ("bids", "asks", "b", "a")):
        candidates.append(payload)
    nested = payload.get("payload")
    if isinstance(nested, Mapping):
        candidates.append(nested)
    data = payload.get("data")
    if isinstance(data, Mapping):
        candidates.append(data)
    if len(candidates) != 1:
        raise ValueError("PAYLOAD_BODY_MAPPING_NOT_UNIQUE")
    return candidates[0]


def _book_arrays(payload: Mapping[str, Any]) -> tuple[list[Any], list[Any]]:
    candidates = []
    if isinstance(payload.get("bids"), list) and isinstance(payload.get("asks"), list):
        candidates.append((payload["bids"], payload["asks"]))
    if isinstance(payload.get("b"), list) and isinstance(payload.get("a"), list):
        candidates.append((payload["b"], payload["a"]))
    data = payload.get("data")
    if isinstance(data, Mapping) and isinstance(data.get("bids"), list) and isinstance(data.get("asks"), list):
        candidates.append((data["bids"], data["asks"]))
    if isinstance(data, Mapping) and isinstance(data.get("b"), list) and isinstance(data.get("a"), list):
        candidates.append((data["b"], data["a"]))
    if len(candidates) != 1:
        raise ValueError("PAYLOAD_BOOK_MAPPING_NOT_UNIQUE")
    return candidates[0]


def _market_event_time(payload: Mapping[str, Any]) -> tuple[int | None, str | None]:
    values = []
    if "E" in payload:
        values.append((payload["E"], "payload.E"))
    if "last_event_time_ms" in payload:
        values.append((payload["last_event_time_ms"], "payload.last_event_time_ms"))
    if not values:
        return None, None
    normalized: list[tuple[int, str]] = []
    for value, source in values:
        if isinstance(value, bool):
            raise ValueError("MARKET_EVENT_TIME_INVALID")
        try:
            item = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("MARKET_EVENT_TIME_INVALID") from exc
        if item < 0:
            raise ValueError("MARKET_EVENT_TIME_INVALID")
        normalized.append((item, source))
    if len({item for item, _ in normalized}) != 1:
        raise ValueError("MARKET_EVENT_TIME_AMBIGUOUS")
    return normalized[0]


def _source_arrival_time(payload: Mapping[str, Any]) -> tuple[int | None, str | None]:
    if "last_local_recv_ts_ms" not in payload:
        return None, None
    value = payload["last_local_recv_ts_ms"]
    if isinstance(value, bool):
        raise ValueError("SOURCE_ARRIVAL_TIME_INVALID")
    try:
        item = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("SOURCE_ARRIVAL_TIME_INVALID") from exc
    if item < 0:
        raise ValueError("SOURCE_ARRIVAL_TIME_INVALID")
    return item, "payload.last_local_recv_ts_ms"


def normalize_snapshot(row: list[str], *, collected_at_ms: int) -> dict[str, Any]:
    if len(row) != 5:
        raise ValueError("SNAPSHOT_ROW_SHAPE_INVALID")
    snapshot_id, symbol, capture_raw, created_raw, payload_raw = row
    if symbol not in {"BTCUSDT", "ETHUSDT"} or not snapshot_id:
        raise ValueError("SNAPSHOT_IDENTITY_INVALID")
    capture_ts_ms = int(capture_raw)
    created_at = int(created_raw)
    payload = json.loads(payload_raw)
    if not isinstance(payload, Mapping):
        raise ValueError("PAYLOAD_OBJECT_REQUIRED")
    body = _payload_body(payload)
    bids, asks = _book_arrays(body)
    if not bids or not asks:
        raise ValueError("BOOK_SIDE_EMPTY")
    best_bid, bid_qty = _decimal_pair(bids[0])
    best_ask, ask_qty = _decimal_pair(asks[0])
    if best_bid >= best_ask:
        raise ValueError("BOOK_CROSSED_OR_LOCKED")
    event_time, event_source = _market_event_time(body)
    arrival_time, arrival_source = _source_arrival_time(body)
    if event_time is not None and event_time > collected_at_ms:
        raise ValueError("FUTURE_EVENT_TIME")
    if arrival_time is not None and arrival_time > collected_at_ms:
        raise ValueError("FUTURE_ARRIVAL_TIME")
    if event_time is not None and arrival_time is not None and event_time > arrival_time:
        raise ValueError("EVENT_AFTER_ARRIVAL_TIME")
    raw_hash = sha256_bytes(payload_raw.encode("utf-8"))
    identity = sha256_bytes(
        canonical_bytes([symbol, capture_ts_ms, snapshot_id, raw_hash])
    )
    return {
        "snapshot_identity_sha256": identity,
        "snapshot_id_sha256": sha256_bytes(snapshot_id.encode("utf-8")),
        "payload_sha256": raw_hash,
        "symbol": symbol,
        "capture_ts_ms": capture_ts_ms,
        "created_at_raw": created_at,
        "market_event_time_ms": event_time,
        "market_event_time_source": event_source,
        "source_arrival_time_ms": arrival_time,
        "source_arrival_time_source": arrival_source,
        "confirmed_visible_time_ms": arrival_time if arrival_time is not None else collected_at_ms,
        "confirmed_visible_time_source": arrival_source or "local_post_receive_clock",
        "time_semantics_status": "pass" if event_time is not None and arrival_time is not None else "unknown",
        "time_semantics_reason": None if event_time is not None and arrival_time is not None else "SOURCE_TIME_SEMANTICS_INCOMPLETE",
        "book_valid": True,
        "aggressive_buy_fillable": ask_qty > 0,
        "aggressive_sell_fillable": bid_qty > 0,
    }


def validate_member_order(rows: Iterable[Mapping[str, Any]]) -> None:
    seen: set[tuple[int, str]] = set()
    by_symbol: dict[str, list[tuple[int, str]]] = {}
    for row in rows:
        identity = (int(row["capture_ts_ms"]), str(row.get("snapshot_id_sha256", row.get("snapshot_id", ""))))
        if identity in seen:
            raise ValueError("MEMBER_IDENTITY_DUPLICATE")
        seen.add(identity)
        by_symbol.setdefault(str(row.get("symbol", "")), []).append(identity)
    for identities in by_symbol.values():
        if identities != sorted(identities, reverse=True):
            raise ValueError("MEMBER_ORDER_INVALID")


def collect(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, directory = _assert_intent(repo_root, batch)
    metadata = read_json(directory / "metadata.json")
    validate_metadata_snapshot(metadata["metadata"])
    plan = read_json(directory / "query-plan.json")
    explain = read_json(directory / "query-explain.json")
    if explain.get("query_plan_sha256") != sha256_path(directory / "query-plan.json"):
        raise ValueError("QUERY_PLAN_FINGERPRINT_DRIFT")
    result = _run_ssh_python(
        _remote_query_program(plan["queries"], explain_only=False),
        timeout=90,
        max_stderr=config["资源上限"]["远端日志字节"],
        max_stdout=config["资源上限"]["业务响应字节"],
    )
    if result.get("mode") != "execute" or len(result.get("results", [])) != 2:
        raise ValueError("DATABASE_RESULT_MISMATCH")
    response_bytes = sum(int(item["response_bytes"]) for item in result["results"])
    if response_bytes > config["资源上限"]["业务响应字节"]:
        raise ValueError("DATABASE_RESPONSE_LIMIT_EXCEEDED")
    collected_at_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    members = []
    denominators = {}
    for query, item in zip(plan["queries"], result["results"], strict=True):
        if item.get("query_id") != query["query_id"]:
            raise ValueError("DATABASE_QUERY_ID_DRIFT")
        encoded_rows = item.get("rows_base64")
        if not isinstance(encoded_rows, list) or len(encoded_rows) > 256:
            raise ValueError("DATABASE_ROW_LIMIT_EXCEEDED")
        symbol_members = []
        for encoded in encoded_rows:
            raw_line = base64.b64decode(encoded, validate=True).decode("utf-8")
            normalized = normalize_snapshot(raw_line.split("\t", 4), collected_at_ms=collected_at_ms)
            if normalized["symbol"] != query["symbol"]:
                raise ValueError("DATABASE_SYMBOL_DRIFT")
            symbol_members.append(normalized)
        validate_member_order(symbol_members)
        members.extend(symbol_members)
        denominators[query["symbol"]] = len(symbol_members)
    if len(members) > config["资源上限"]["总快照"]:
        raise ValueError("TOTAL_SNAPSHOT_LIMIT_EXCEEDED")
    frozen = {
        "schema_version": "zhishi-simulated-order-frozen-input/v1",
        "batch_id": batch,
        "intent_sha256": sha256_path(directory / "intent.json"),
        "metadata_sha256": sha256_path(directory / "metadata.json"),
        "query_plan_sha256": sha256_path(directory / "query-plan.json"),
        "query_explain_sha256": sha256_path(directory / "query-explain.json"),
        "collected_at_ms": collected_at_ms,
        "denominators": denominators,
        "member_count": len(members),
        "database_response_bytes": response_bytes,
        "members": members,
        "safety": {
            "remote_write": False,
            "database_write": False,
            "raw_price_or_quantity_persisted": False,
            "network_order": False,
        },
    }
    write_json_exclusive(directory / "frozen-input.json", frozen)
    return {
        "batch_id": batch,
        "member_count": len(members),
        "denominators": denominators,
        "database_response_bytes": response_bytes,
    }


def transition(current: str, target: str) -> str:
    if target not in ALLOWED_STATES.get(current, set()):
        raise ValueError("STATE_TRANSITION_INVALID")
    return target


def simulate_member(
    member: Mapping[str, Any], scenario: str, direction: str, clock: str
) -> dict[str, Any]:
    if scenario not in {"进取型市价", "进取型限价", "被动限价撤销"}:
        raise ValueError("SCENARIO_INVALID")
    if direction not in {"做多", "做空"} or clock not in {"基准", "压力"}:
        raise ValueError("SIMULATION_SCOPE_INVALID")
    offsets = [0, 1, 2, 3, 4] if clock == "基准" else [0, 10, 30, 80, 120]
    start = max(
        int(member["confirmed_visible_time_ms"]),
        int(member.get("market_event_time_ms") or 0),
    ) + 1
    states = ["created", "sent", "acknowledged", "evaluated"]
    if scenario == "被动限价撤销":
        terminal, reason = "canceled", "QUEUE_IDENTITY_UNAVAILABLE"
    elif member.get("time_semantics_status") != "pass":
        terminal, reason = "unknown", "SOURCE_TIME_SEMANTICS_INCOMPLETE"
    else:
        fillable = member[
            "aggressive_buy_fillable" if direction == "做多" else "aggressive_sell_fillable"
        ]
        terminal, reason = ("filled", "TOP_BOOK_CAPACITY_PRESENT") if fillable else ("unknown", "TOP_BOOK_CAPACITY_ABSENT")
    states.append(terminal)
    for current, target in zip(states, states[1:]):
        transition(current, target)
    events = [
        {"state": state, "simulated_time_ms": start + offset}
        for state, offset in zip(states, offsets, strict=True)
    ]
    return {
        "snapshot_identity_sha256": member["snapshot_identity_sha256"],
        "symbol": member["symbol"],
        "scenario": scenario,
        "direction": direction,
        "clock": clock,
        "events": events,
        "terminal_state": terminal,
        "reason_code": reason,
        "real_exchange_latency_claimed": False,
    }


def simulate(frozen: Mapping[str, Any]) -> dict[str, Any]:
    members = frozen.get("members")
    if not isinstance(members, list):
        raise ValueError("FROZEN_MEMBERS_REQUIRED")
    validate_member_order(members)
    results = [
        simulate_member(member, scenario, direction, clock)
        for member in members
        for direction, scenario, clock in product(
            ("做多", "做空"),
            ("进取型市价", "进取型限价", "被动限价撤销"),
            ("基准", "压力"),
        )
    ]
    groups = []
    for symbol, direction, scenario, clock, horizon in product(
        ("BTCUSDT", "ETHUSDT"),
        ("做多", "做空"),
        ("进取型市价", "进取型限价", "被动限价撤销"),
        ("基准", "压力"),
        ("主研究尺度：4小时", "主研究尺度：8小时", "主研究尺度：24小时", "主研究尺度：48小时"),
    ):
        subset = [
            row
            for row in results
            if row["symbol"] == symbol
            and row["direction"] == direction
            and row["scenario"] == scenario
            and row["clock"] == clock
        ]
        counts = Counter(row["terminal_state"] for row in subset)
        groups.append(
            {
                "symbol": symbol,
                "venue": "Binance",
                "market": "USDⓈ-M永续合约",
                "direction": direction,
                "scenario": scenario,
                "clock": clock,
                "horizon": horizon,
                "candidate": len(subset),
                "observed": len(subset),
                "filled": counts["filled"],
                "canceled": counts["canceled"],
                "unknown": counts["unknown"],
                "failed": 0,
                "immature": 0,
                "invalid": 0,
            }
        )
    terminal_counts = Counter(row["terminal_state"] for row in results)
    return {
        "schema_version": "zhishi-simulated-order-lifecycle-result/v1",
        "frozen_input_sha256": sha256_bytes(canonical_bytes(frozen)),
        "member_count": len(members),
        "scenario_count": len(results),
        "results": results,
        "groups": groups,
        "terminal_counts": dict(sorted(terminal_counts.items())),
    }


def simulate_batch(repo_root: Path, batch: str) -> dict[str, Any]:
    _, _, directory = _assert_intent(repo_root, batch)
    frozen = read_json(directory / "frozen-input.json")
    result = simulate(frozen)
    write_json_exclusive(directory / "lifecycle.json", result)
    return {
        "batch_id": batch,
        "result_sha256": sha256_bytes(canonical_bytes(result)),
        "member_count": result["member_count"],
        "scenario_count": result["scenario_count"],
    }


def replay(repo_root: Path, batch: str, number: int) -> dict[str, Any]:
    if number not in {1, 2}:
        raise ValueError("REPLAY_NUMBER_INVALID")
    _, _, directory = _assert_intent(repo_root, batch)
    frozen = read_json(directory / "frozen-input.json")
    initial = read_json(directory / "lifecycle.json")
    replayed = simulate(frozen)
    result_sha = sha256_bytes(canonical_bytes(replayed))
    initial_sha = sha256_bytes(canonical_bytes(initial))
    if result_sha != initial_sha:
        raise ValueError("REPLAY_RESULT_DRIFT")
    proof = {
        "schema_version": "zhishi-simulated-order-replay-proof/v1",
        "batch_id": batch,
        "replay_number": number,
        "frozen_input_sha256": sha256_path(directory / "frozen-input.json"),
        "result_sha256": result_sha,
        "matches_initial": True,
        "independent_process": True,
    }
    write_json_exclusive(directory / f"replay-{number}.json", proof)
    return proof


def _resource_facts(intent: Mapping[str, Any], frozen: Mapping[str, Any]) -> dict[str, Any]:
    created = dt.datetime.fromisoformat(str(intent["created_at"]).replace("Z", "+00:00"))
    return {
        "elapsed_seconds": round((dt.datetime.now(dt.timezone.utc) - created).total_seconds(), 6),
        "rss_bytes": _rss_bytes(),
        "estimated_database_rows": None,
        "business_query_count": 2,
        "query_retry_count": 0,
        "database_response_bytes": frozen["database_response_bytes"],
        "snapshot_count": frozen["member_count"],
    }


def _validate_resource_facts(facts: Mapping[str, Any], limits: Mapping[str, Any]) -> None:
    if facts["elapsed_seconds"] > limits["总时限秒"]:
        raise ValueError("BATCH_ELAPSED_LIMIT_EXCEEDED")
    if facts["rss_bytes"] > limits["RSS字节"]:
        raise ValueError("BATCH_RSS_LIMIT_EXCEEDED")
    if facts["database_response_bytes"] > limits["业务响应字节"]:
        raise ValueError("BATCH_RESPONSE_LIMIT_EXCEEDED")
    if facts["snapshot_count"] > limits["总快照"]:
        raise ValueError("BATCH_SNAPSHOT_LIMIT_EXCEEDED")


def _validate_evidence(directory: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    present = {path.name for path in directory.iterdir() if path.is_file()}
    if not PENDING_FILES_BEFORE_VALIDATE.issubset(present):
        raise ValueError("BATCH_REQUIRED_FILES_MISSING")
    frozen = read_json(directory / "frozen-input.json")
    lifecycle = read_json(directory / "lifecycle.json")
    expected = simulate(frozen)
    expected_sha = sha256_bytes(canonical_bytes(expected))
    if lifecycle != expected:
        raise ValueError("LIFECYCLE_RESULT_DRIFT")
    for number in (1, 2):
        proof = read_json(directory / f"replay-{number}.json")
        if (
            proof.get("replay_number") != number
            or proof.get("result_sha256") != expected_sha
            or proof.get("matches_initial") is not True
            or proof.get("independent_process") is not True
        ):
            raise ValueError("REPLAY_PROOF_INVALID")
    if frozen.get("safety") != {
        "remote_write": False,
        "database_write": False,
        "raw_price_or_quantity_persisted": False,
        "network_order": False,
    }:
        raise ValueError("BATCH_SAFETY_FACT_INVALID")
    if set(frozen.get("denominators", {})) != set(config["标的"]):
        raise ValueError("BATCH_SYMBOL_DENOMINATOR_INVALID")
    return {"frozen": frozen, "lifecycle": lifecycle, "result_sha256": expected_sha}


def validate_batch(repo_root: Path, batch: str) -> dict[str, Any]:
    intent, config, directory = _assert_intent(repo_root, batch)
    if directory == _batch_directory(repo_root, batch):
        manifest = read_json(directory / "manifest.json")
        for name, facts in manifest["files"].items():
            path = directory / name
            if sha256_path(path) != facts["sha256"] or path.stat().st_size != facts["bytes"]:
                raise ValueError("BATCH_FILE_DRIFT")
        return {
            "status": "ok",
            "batch_id": batch,
            "manifest_sha256": sha256_path(directory / "manifest.json"),
            "summary_sha256": sha256_path(directory / "summary.json"),
        }
    evidence = _validate_evidence(directory, config)
    explain = read_json(directory / "query-explain.json")
    resource_facts = _resource_facts(intent, evidence["frozen"])
    resource_facts["estimated_database_rows"] = explain["estimated_rows"]
    _validate_resource_facts(resource_facts, config["资源上限"])
    members = evidence["frozen"]["members"]
    time_counts = Counter(row["time_semantics_status"] for row in members)
    summary = {
        "schema_version": "zhishi-simulated-order-lifecycle-summary/v1",
        "task_id": "000103",
        "batch_id": batch,
        "member_count": len(members),
        "denominators": evidence["frozen"]["denominators"],
        "time_semantics_counts": dict(sorted(time_counts.items())),
        "lifecycle_result_sha256": evidence["result_sha256"],
        "terminal_counts": evidence["lifecycle"]["terminal_counts"],
        "replay_1_sha256": read_json(directory / "replay-1.json")["result_sha256"],
        "replay_2_sha256": read_json(directory / "replay-2.json")["result_sha256"],
        "simulation_lifecycle_runnable": len(members) > 0,
        "future_data_gate": "unknown" if time_counts.get("unknown", 0) else "pass",
        "real_exchange_latency_status": "unknown",
        "multi_year_cost_status": "unknown",
        "stage1_complete": False,
        "stage2_released": False,
        "resource_facts": resource_facts,
        "safety": {
            "remote_write": False,
            "database_write": False,
            "account_endpoint": False,
            "credential_read": False,
            "raw_price_or_quantity_persisted": False,
            "network_order": False,
            "real_order": False,
            "model_or_backtest": False,
            "trade_decision": False,
        },
        "remaining_condition": "版本化容量压力与隔离恢复证据；多年历史成本覆盖仍保持未知",
    }
    write_json_exclusive(directory / "summary.json", summary)
    files = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "manifest.json":
            files[path.name] = {"sha256": sha256_path(path), "bytes": path.stat().st_size}
    if set(files) != PUBLISHED_FILES:
        raise ValueError("BATCH_FILE_SET_INVALID")
    total_bytes = sum(item["bytes"] for item in files.values())
    if total_bytes > config["资源上限"]["本地输出字节"]:
        raise ValueError("LOCAL_OUTPUT_LIMIT_EXCEEDED")
    manifest = {
        "schema_version": "zhishi-simulated-order-lifecycle-manifest/v1",
        "batch_id": batch,
        "published_at": utc_now(),
        "files": files,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "manifest_payload_sha256": sha256_bytes(canonical_bytes(files)),
    }
    write_json_exclusive(directory / "manifest.json", manifest)
    final = _batch_directory(repo_root, batch)
    publish_directory_no_replace(directory, final)
    try:
        directory.parent.rmdir()
    except OSError:
        pass
    return {
        "status": "ok",
        "batch_id": batch,
        "manifest_sha256": sha256_path(final / "manifest.json"),
        "summary_sha256": sha256_path(final / "summary.json"),
        "member_count": summary["member_count"],
        "future_data_gate": summary["future_data_gate"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "probe", "plan", "collect", "simulate", "replay-1", "replay-2", "validate"),
    )
    parser.add_argument("--batch", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    actions = {
        "prepare": prepare,
        "probe": probe_metadata,
        "plan": plan_queries,
        "collect": collect,
        "simulate": simulate_batch,
        "replay-1": lambda repo, batch: replay(repo, batch, 1),
        "replay-2": lambda repo, batch: replay(repo, batch, 2),
        "validate": validate_batch,
    }
    result = actions[args.command](root, args.batch)
    print(canonical_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"阶段1模拟委托生命周期验证失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
