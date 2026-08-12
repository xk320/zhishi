#!/usr/bin/env python3
"""任务-000103：用有界只读订单簿输入验证模拟委托生命周期。"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import resource
import selectors
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
        "simulate-process.json",
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


def _process_facts(started: float) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "peak_rss_bytes": _rss_bytes(),
    }


def _assert_rss(limit: int) -> None:
    if _rss_bytes() > limit:
        raise RuntimeError("PROCESS_RSS_LIMIT_EXCEEDED")


def _normalized_task_fingerprint(path: Path) -> str:
    volatile = (
        "- 状态：",
        "- 执行分支：",
        "- 开始时间：",
        "- 提交SHA：",
        "- 实现提交SHA：",
        "- Pull Request：",
        "- 交付物：",
        "- 验证结果：",
        "- 合并时间：",
        "- 合并提交SHA：",
    )
    source_lines = path.read_text(encoding="utf-8").splitlines()
    record_start = next(
        (
            index
            for index, line in enumerate(source_lines)
            if line.strip() == "## 执行记录"
        ),
        len(source_lines),
    )
    contract_lines = source_lines[:record_start]
    while contract_lines and not contract_lines[-1].strip():
        contract_lines.pop()
    lines = [
        line
        for line in contract_lines
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
        "生产者来源合同",
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
    if config["生产者来源合同"] != {
        "仓库快照": "orderbook-intelligence-service-release-20260731",
        "提交": "030499faca3d6955d75c75cbc59656a4981f6c05",
        "real_orderbook.py SHA-256": "fdb17777bd325aa52b55a5b03af5187ebc5804ded8ab3cde81237561be17639e",
        "storage.py SHA-256": "d4fed7bf0fc89666a9836a17f144ef41d2a6d13d829124437032c9787bf9b05d",
        "快照Schema版本": 1,
        "来源": "canonical_book",
        "市场事件字段": "payload.last_event_time_ms",
        "系统到达字段": "payload.last_local_recv_ts_ms",
        "市场事件语义": "Binance USDⓈ-M深度增量事件E字段，UTC毫秒",
        "系统到达语义": "订单簿apply_diff处理增量事件时调用now_ms取得的本地墙钟，UTC毫秒",
    }:
        raise ValueError("CONFIG_PRODUCER_CONTRACT_MISMATCH")
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
        "producer_contract": config["生产者来源合同"],
        "producer_contract_sha256": sha256_bytes(
            canonical_bytes(config["生产者来源合同"])
        ),
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
        returncode, stdout, stderr = _run_bounded_process(
            command,
            input_bytes=program.encode("utf-8"),
            timeout=timeout,
            max_stdout=max_stdout,
            max_stderr=max_stderr,
        )
    except RuntimeError as exc:
        reason = str(exc)
        if reason == "PROCESS_TIMEOUT":
            raise RuntimeError("REMOTE_READ_TIMEOUT") from exc
        if reason == "PROCESS_STDOUT_LIMIT_EXCEEDED":
            raise RuntimeError("REMOTE_RESPONSE_LIMIT_EXCEEDED") from exc
        if reason == "PROCESS_STDERR_LIMIT_EXCEEDED":
            raise RuntimeError("REMOTE_LOG_LIMIT_EXCEEDED") from exc
        raise
    if returncode != 0:
        raise RuntimeError(
            f"REMOTE_READ_FAILED:{returncode}:{sha256_bytes(stderr)}"
        )
    value = json.loads(stdout.decode("utf-8"))
    _assert_rss(268435456)
    if not isinstance(value, dict):
        raise RuntimeError("REMOTE_RESPONSE_OBJECT_REQUIRED")
    return value


def _run_bounded_process(
    command: list[str],
    *,
    input_bytes: bytes,
    timeout: int,
    max_stdout: int,
    max_stderr: int,
) -> tuple[int, bytes, bytes]:
    """并发增量读取子进程输出，并在越界发生时立即终止。"""

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        process.stdin.write(input_bytes)
        process.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", max_stdout))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", max_stderr))
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("PROCESS_TIMEOUT")
            for key, _ in selector.select(min(0.1, remaining)):
                stream_name, limit = key.data
                chunk = os.read(key.fileobj.fileno(), min(65536, limit + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[stream_name].extend(chunk)
                if len(buffers[stream_name]) > limit:
                    raise RuntimeError(f"PROCESS_{stream_name.upper()}_LIMIT_EXCEEDED")
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except (BrokenPipeError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("PROCESS_TIMEOUT") from exc
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


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
    started = time.monotonic()
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
        "process": _process_facts(started),
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
    response_limit = 65536 if explain_only else 67108864
    return f'''
import base64,hashlib,json,os,resource,selectors,shutil,subprocess,time
queries=json.loads({encoded!r})
client=shutil.which("mysql") or shutil.which("mariadb")
if not client: raise SystemExit("MYSQL_CLIENT_MISSING")
clean_env={{"PATH":"/usr/bin:/bin","LC_ALL":"C","MYSQL_TEST_LOGIN_FILE":"/dev/null"}}
rss_limit=268435456
response_limit={response_limit}
stderr_limit=65536
resource.setrlimit(resource.RLIMIT_AS,(rss_limit,rss_limit))
def run(statement,remaining):
 p=subprocess.Popen([client,"--no-defaults","--batch","--raw","--skip-column-names","--connect-timeout=5","--database=orderbook","--execute",statement],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=clean_env)
 selector=selectors.DefaultSelector(); buffers={{"stdout":bytearray(),"stderr":bytearray()}}
 selector.register(p.stdout,selectors.EVENT_READ,("stdout",remaining)); selector.register(p.stderr,selectors.EVENT_READ,("stderr",stderr_limit))
 deadline=time.monotonic()+30
 try:
  while selector.get_map():
   left=deadline-time.monotonic()
   if left<=0: raise SystemExit("MYSQL_QUERY_TIMEOUT")
   for key,_ in selector.select(min(0.1,left)):
    name,limit=key.data; chunk=os.read(key.fileobj.fileno(),min(65536,limit+1))
    if not chunk: selector.unregister(key.fileobj); continue
    buffers[name].extend(chunk)
    if len(buffers[name])>limit: raise SystemExit("MYSQL_RESPONSE_LIMIT_EXCEEDED" if name=="stdout" else "MYSQL_LOG_LIMIT_EXCEEDED")
  code=p.wait(timeout=max(0.1,deadline-time.monotonic()))
  if code: raise SystemExit("MYSQL_QUERY_FAILED")
  return bytes(buffers["stdout"])
 finally:
  if p.poll() is None: p.kill(); p.wait()
out=[]
raw_total=0
for query in queries:
 sql=query["SQL"]
 lowered=" ".join(sql.strip().split()).lower()
 if not lowered.startswith("select ") or any(x in lowered for x in (" insert "," update "," delete "," replace "," alter "," drop "," create "," truncate "," grant "," revoke "," outfile "," dumpfile ",";","--","/*")) or " limit 256" not in lowered:
  raise SystemExit("REMOTE_SQL_NOT_READ_ONLY")
 statement=("EXPLAIN FORMAT=JSON "+sql) if {mode!r}=="explain" else sql
 payload=run(statement,response_limit-raw_total)
 raw_total+=len(payload)
 if {mode!r}=="explain":
  out.append({{"query_id":query["query_id"],"plan":json.loads(payload.decode()),"response_sha256":hashlib.sha256(payload).hexdigest(),"response_bytes":len(payload)}})
 else:
  lines=[line for line in payload.splitlines() if line]
  out.append({{"query_id":query["query_id"],"row_count":len(lines),"rows_base64":[base64.b64encode(line).decode() for line in lines],"response_sha256":hashlib.sha256(payload).hexdigest(),"response_bytes":len(payload)}})
self_rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
child_rss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss*1024
peak=max(self_rss,child_rss)
if peak>rss_limit: raise SystemExit("REMOTE_RSS_LIMIT_EXCEEDED")
print(json.dumps({{"protocol":"zhishi-stage1-simulated-lifecycle-query/1","mode":{mode!r},"results":out,"remote_peak_rss_bytes":peak,"remote_rss_limit_enforced":True,"stdout_incrementally_bounded":True}},sort_keys=True,separators=(",",":")))
'''


def plan_queries(repo_root: Path, batch: str) -> dict[str, Any]:
    started = time.monotonic()
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
        "remote_peak_rss_bytes": explain_result["remote_peak_rss_bytes"],
        "remote_rss_limit_enforced": explain_result["remote_rss_limit_enforced"],
        "stdout_incrementally_bounded": explain_result["stdout_incrementally_bounded"],
        "process": _process_facts(started),
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
    producer_identity_proved = (
        payload.get("snapshot_schema_version") == 1
        and payload.get("source") == "canonical_book"
    )
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
        "producer_identity_proved": producer_identity_proved,
        "time_semantics_status": (
            "pass"
            if producer_identity_proved
            and event_time is not None
            and arrival_time is not None
            else "unknown"
        ),
        "time_semantics_reason": (
            None
            if producer_identity_proved
            and event_time is not None
            and arrival_time is not None
            else "SOURCE_TIME_SEMANTICS_INCOMPLETE"
        ),
        "book_valid": True,
        "aggressive_buy_fillable": ask_qty > 0,
        "aggressive_sell_fillable": bid_qty > 0,
    }


def validate_raw_member_order(rows: Iterable[list[str]]) -> None:
    """在脱敏前按数据库声明的原始复合键验证唯一全序。"""

    seen: set[tuple[str, int, str]] = set()
    by_symbol: dict[str, list[tuple[int, str]]] = {}
    for row in rows:
        if len(row) != 5:
            raise ValueError("SNAPSHOT_ROW_SHAPE_INVALID")
        snapshot_id, symbol, capture_raw = row[:3]
        identity = (symbol, int(capture_raw), snapshot_id)
        if identity in seen:
            raise ValueError("MEMBER_IDENTITY_DUPLICATE")
        seen.add(identity)
        by_symbol.setdefault(symbol, []).append((int(capture_raw), snapshot_id))
    for identities in by_symbol.values():
        if identities != sorted(identities, reverse=True):
            raise ValueError("MEMBER_ORDER_INVALID")


def validate_member_order(rows: Iterable[Mapping[str, Any]]) -> None:
    """用脱敏身份与原始顺序承诺验证发布后的成员顺序。"""

    seen: set[tuple[str, str]] = set()
    by_symbol: dict[str, list[tuple[int, int | None]]] = {}
    for row in rows:
        symbol = str(row.get("symbol", ""))
        identity_sha = str(row.get("snapshot_identity_sha256", ""))
        identity = (symbol, identity_sha)
        if not symbol or SHA_PATTERN.fullmatch(identity_sha) is None:
            raise ValueError("MEMBER_IDENTITY_INVALID")
        if identity in seen:
            raise ValueError("MEMBER_IDENTITY_DUPLICATE")
        seen.add(identity)
        sequence = row.get("member_sequence")
        if sequence is not None and (isinstance(sequence, bool) or not isinstance(sequence, int)):
            raise ValueError("MEMBER_SEQUENCE_INVALID")
        by_symbol.setdefault(symbol, []).append((int(row["capture_ts_ms"]), sequence))
    for values in by_symbol.values():
        timestamps = [capture for capture, _ in values]
        if timestamps != sorted(timestamps, reverse=True):
            raise ValueError("MEMBER_ORDER_INVALID")
        sequences = [sequence for _, sequence in values]
        if len(sequences) > 1 and sequences != list(range(len(sequences))):
            raise ValueError("MEMBER_SEQUENCE_INVALID")


def collect(repo_root: Path, batch: str) -> dict[str, Any]:
    started = time.monotonic()
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
        _assert_rss(config["资源上限"]["RSS字节"])
        if item.get("query_id") != query["query_id"]:
            raise ValueError("DATABASE_QUERY_ID_DRIFT")
        encoded_rows = item.get("rows_base64")
        if not isinstance(encoded_rows, list) or len(encoded_rows) > 256:
            raise ValueError("DATABASE_ROW_LIMIT_EXCEEDED")
        raw_rows = []
        for encoded in encoded_rows:
            _assert_rss(config["资源上限"]["RSS字节"])
            raw_line = base64.b64decode(encoded, validate=True).decode("utf-8")
            raw_rows.append(raw_line.split("\t", 4))
        validate_raw_member_order(raw_rows)
        symbol_members = []
        for member_sequence, raw_row in enumerate(raw_rows):
            normalized = normalize_snapshot(raw_row, collected_at_ms=collected_at_ms)
            if normalized["symbol"] != query["symbol"]:
                raise ValueError("DATABASE_SYMBOL_DRIFT")
            normalized["member_sequence"] = member_sequence
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
        "remote_peak_rss_bytes": result["remote_peak_rss_bytes"],
        "remote_rss_limit_enforced": result["remote_rss_limit_enforced"],
        "stdout_incrementally_bounded": result["stdout_incrementally_bounded"],
        "process": _process_facts(started),
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
    if member.get("time_semantics_status") != "pass":
        terminal, reason = "unknown", "SOURCE_TIME_SEMANTICS_INCOMPLETE"
        states = []
        offsets = []
    elif scenario == "被动限价撤销":
        terminal, reason = "canceled", "QUEUE_IDENTITY_UNAVAILABLE"
    else:
        fillable = member[
            "aggressive_buy_fillable" if direction == "做多" else "aggressive_sell_fillable"
        ]
        terminal, reason = ("filled", "TOP_BOOK_CAPACITY_PRESENT") if fillable else ("unknown", "TOP_BOOK_CAPACITY_ABSENT")
    if states:
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
    results = []
    for member in members:
        _assert_rss(268435456)
        results.extend(
            simulate_member(member, scenario, direction, clock)
            for direction, scenario, clock in product(
                ("做多", "做空"),
                ("进取型市价", "进取型限价", "被动限价撤销"),
                ("基准", "压力"),
            )
        )
    groups = []
    stage_statuses = (
        ("created", ("created",)),
        ("sent", ("sent",)),
        ("acknowledged", ("acknowledged",)),
        ("evaluated", ("evaluated",)),
        ("terminal", ("filled", "canceled", "unknown")),
    )
    all_statuses = (
        "created",
        "sent",
        "acknowledged",
        "evaluated",
        "filled",
        "canceled",
        "unknown",
    )
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
        for stage, statuses in stage_statuses:
            observed_states = [
                row["terminal_state"]
                if stage == "terminal"
                else next(
                    (event["state"]
                    for event in row["events"]
                    if event["state"] == stage),
                    None,
                )
                for row in subset
            ]
            counts = Counter(state for state in observed_states if state is not None)
            for result_status in statuses:
                state_counts = {
                    status: counts[status] if status == result_status else 0
                    for status in all_statuses
                }
                groups.append(
                    {
                        "symbol": symbol,
                        "venue": "Binance",
                        "market": "USDⓈ-M永续合约",
                        "contract": f"{symbol}永续合约",
                        "direction": direction,
                        "stage": stage,
                        "scenario": scenario,
                        "clock": clock,
                        "horizon": horizon,
                        "result_status": result_status,
                        "candidate": len(subset),
                        "observed": counts[result_status],
                        "state_counts": state_counts,
                        "filled": state_counts["filled"],
                        "canceled": state_counts["canceled"],
                        "unknown": state_counts["unknown"],
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
    started = time.monotonic()
    _, _, directory = _assert_intent(repo_root, batch)
    frozen = read_json(directory / "frozen-input.json")
    result = simulate(frozen)
    write_json_exclusive(directory / "lifecycle.json", result)
    write_json_exclusive(
        directory / "simulate-process.json",
        {
            "schema_version": "zhishi-simulated-order-stage-process/v1",
            "batch_id": batch,
            "stage": "simulate",
            "process": _process_facts(started),
        },
    )
    return {
        "batch_id": batch,
        "result_sha256": sha256_bytes(canonical_bytes(result)),
        "member_count": result["member_count"],
        "scenario_count": result["scenario_count"],
    }


def replay(repo_root: Path, batch: str, number: int) -> dict[str, Any]:
    started = time.monotonic()
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
        "process": _process_facts(started),
    }
    write_json_exclusive(directory / f"replay-{number}.json", proof)
    return proof


def _resource_facts(intent: Mapping[str, Any], frozen: Mapping[str, Any]) -> dict[str, Any]:
    created = dt.datetime.fromisoformat(str(intent["created_at"]).replace("Z", "+00:00"))
    return {
        "elapsed_seconds": round((dt.datetime.now(dt.timezone.utc) - created).total_seconds(), 6),
        "estimated_database_rows": None,
        "business_query_count": 2,
        "query_retry_count": 0,
        "database_response_bytes": frozen["database_response_bytes"],
        "snapshot_count": frozen["member_count"],
    }


def _stage_resource_facts(
    directory: Path, *, validate_rss_bytes: int | None = None
) -> dict[str, Any]:
    intent = read_json(directory / "intent.json")
    metadata = read_json(directory / "metadata.json")
    explain = read_json(directory / "query-explain.json")
    frozen = read_json(directory / "frozen-input.json")
    simulate_process = read_json(directory / "simulate-process.json")
    replay_1 = read_json(directory / "replay-1.json")
    replay_2 = read_json(directory / "replay-2.json")
    stages = {
        "prepare": int(intent["process"]["rss_bytes"]),
        "probe": int(metadata["process"]["peak_rss_bytes"]),
        "plan": int(explain["process"]["peak_rss_bytes"]),
        "collect": int(frozen["process"]["peak_rss_bytes"]),
        "simulate": int(simulate_process["process"]["peak_rss_bytes"]),
        "replay-1": int(replay_1["process"]["peak_rss_bytes"]),
        "replay-2": int(replay_2["process"]["peak_rss_bytes"]),
        "validate": _rss_bytes() if validate_rss_bytes is None else validate_rss_bytes,
    }
    remote = {
        "plan": int(explain["remote_peak_rss_bytes"]),
        "collect": int(frozen["remote_peak_rss_bytes"]),
    }
    if not all(
        value.get("remote_rss_limit_enforced") is True
        and value.get("stdout_incrementally_bounded") is True
        for value in (explain, frozen)
    ):
        raise ValueError("REMOTE_RESOURCE_ENFORCEMENT_MISSING")
    return {
        "stage_peak_rss_bytes": stages,
        "remote_peak_rss_bytes": remote,
        "local_peak_rss_bytes": max(stages.values()),
        "combined_process_peak_rss_bytes": max((*stages.values(), *remote.values())),
    }


def _validate_resource_facts(facts: Mapping[str, Any], limits: Mapping[str, Any]) -> None:
    if facts["elapsed_seconds"] > limits["总时限秒"]:
        raise ValueError("BATCH_ELAPSED_LIMIT_EXCEEDED")
    if facts["combined_process_peak_rss_bytes"] > limits["RSS字节"]:
        raise ValueError("BATCH_RSS_LIMIT_EXCEEDED")
    if any(
        value > limits["RSS字节"]
        for values in (
            facts["stage_peak_rss_bytes"],
            facts["remote_peak_rss_bytes"],
        )
        for value in values.values()
    ):
        raise ValueError("STAGE_RSS_LIMIT_EXCEEDED")
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
        if set(manifest.get("files", {})) != PUBLISHED_FILES:
            raise ValueError("BATCH_FILE_SET_INVALID")
        expected_total = sum(
            int(facts["bytes"]) for facts in manifest["files"].values()
        )
        if (
            manifest.get("file_count") != len(PUBLISHED_FILES)
            or manifest.get("total_bytes") != expected_total
            or manifest.get("manifest_payload_sha256")
            != sha256_bytes(canonical_bytes(manifest["files"]))
        ):
            raise ValueError("BATCH_MANIFEST_INCONSISTENT")
        for name, facts in manifest["files"].items():
            path = directory / name
            if sha256_path(path) != facts["sha256"] or path.stat().st_size != facts["bytes"]:
                raise ValueError("BATCH_FILE_DRIFT")
        evidence = _validate_evidence(directory, config)
        summary = read_json(directory / "summary.json")
        time_counts = Counter(
            row["time_semantics_status"] for row in evidence["frozen"]["members"]
        )
        declared_resources = summary.get("resource_facts", {})
        declared_validate_rss = declared_resources.get(
            "stage_peak_rss_bytes", {}
        ).get("validate")
        if not isinstance(declared_validate_rss, int):
            raise ValueError("BATCH_STAGE_RESOURCE_DRIFT")
        stage_resources = _stage_resource_facts(
            directory, validate_rss_bytes=declared_validate_rss
        )
        for key, value in stage_resources.items():
            if declared_resources.get(key) != value:
                raise ValueError("BATCH_STAGE_RESOURCE_DRIFT")
        if (
            summary.get("member_count") != len(evidence["frozen"]["members"])
            or summary.get("denominators") != evidence["frozen"]["denominators"]
            or summary.get("time_semantics_counts") != dict(sorted(time_counts.items()))
            or summary.get("lifecycle_result_sha256") != evidence["result_sha256"]
            or summary.get("terminal_counts") != evidence["lifecycle"]["terminal_counts"]
            or summary.get("replay_1_sha256")
            != read_json(directory / "replay-1.json")["result_sha256"]
            or summary.get("replay_2_sha256")
            != read_json(directory / "replay-2.json")["result_sha256"]
        ):
            raise ValueError("BATCH_SUMMARY_SEMANTIC_DRIFT")
        _validate_resource_facts(declared_resources, config["资源上限"])
        return {
            "status": "ok",
            "batch_id": batch,
            "manifest_sha256": sha256_path(directory / "manifest.json"),
            "summary_sha256": sha256_path(directory / "summary.json"),
        }
    evidence = _validate_evidence(directory, config)
    explain = read_json(directory / "query-explain.json")
    resource_facts = _resource_facts(intent, evidence["frozen"])
    resource_facts.update(_stage_resource_facts(directory))
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
