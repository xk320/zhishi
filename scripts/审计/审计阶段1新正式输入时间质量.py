#!/usr/bin/env python3
"""任务-000094：逐行审计阶段1新正式输入的时间与质量。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence


EXPECTED_CONFIG_SHA256 = "6968246516ef65704dbccfc348e4e20835783446e0f9366d7e7d35a2000a99ae"
DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})\.zip$")
DECIMAL_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STATUSES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
EXPECTED_CONFIG_RELATIVE_PATH = Path("config/审计/任务-000094逐行时间质量审计.json")
EXPECTED_OUTPUT_RELATIVE_PATH = Path("artifacts/审计/阶段1逐行时间质量")
TASK_CONTRACT_HEADER_PREFIXES = (
    "# 任务-000094：", "- 类型：", "- 阶段：", "- 优先级：", "- 执行方案：",
    "- 方案状态：", "- 执行授权：", "- 并行规则：",
)


AWK_SCANNER = r'''
BEGIN {
  FS=",";
  row_count=0; byte_count=0; first_key=""; last_key="";
  first_time=""; last_time=""; reason_count=0;
}
function reason(code) {
  if (!(code in reasons)) { reasons[code]=1; reason_order[++reason_count]=code; }
}
function uint(s) { return s ~ /^[0-9]+$/; }
function normint(s, t) {
  t=s; sub(/^0+/, "", t); return t == "" ? "0" : t;
}
function cmpint(a,b, na,nb) {
  na=normint(a); nb=normint(b);
  if (length(na) != length(nb)) return length(na) < length(nb) ? -1 : 1;
  return na == nb ? 0 : (na < nb ? -1 : 1);
}
function epochms(s) {
  if (!uint(s)) return "";
  if (length(s) == 13) return s;
  if (length(s) == 16) return substr(s,1,13);
  return "";
}
function decimal(s) { return s ~ /^[0-9]+([.][0-9]+)?$/; }
function positive(s, t) {
  if (!decimal(s)) return 0;
  t=s; gsub(/[0.]/, "", t); return t != "";
}
function nonnegative(s) { return decimal(s); }
{
  sub(/\r$/, "", $0);
  byte_count += length($0) + 1;
  if (index($0, "\"") > 0) reason("QUOTED_FIELD_REJECTED");
  if (header_expected == 1 && NR == 1) {
    if ($0 != header_line) reason("HEADER_INVALID");
    next;
  }
  if ($0 == "") { reason("EMPTY_LINE"); next; }
  row_count++;
  if (NF != column_count) { reason("COLUMN_COUNT_INVALID"); next; }
  key=$1;
  time_raw=$(event_time_index);
  time_ms=epochms(time_raw);
  if (!uint(key)) reason("BUSINESS_KEY_INVALID");
  if (time_ms == "") reason("EVENT_TIME_INVALID");
  if (!positive($2) || !positive($3)) reason("DECIMAL_INVALID");
  if (dataset == "trades") {
    if (!nonnegative($4)) reason("DECIMAL_INVALID");
    if ($6 != "true" && $6 != "false") reason("BOOLEAN_INVALID");
  } else if (dataset == "aggTrades") {
    if (!uint($4) || !uint($5) || cmpint($4,$5) > 0) reason("AGG_TRADE_RANGE_INVALID");
    if ($7 != "true" && $7 != "false") reason("BOOLEAN_INVALID");
  } else reason("DATASET_INVALID");
  if (uint(key) && last_key != "" && cmpint(key,last_key) <= 0) reason("DUPLICATE_OR_REVERSED_KEY");
  if (time_ms != "" && last_time != "" && cmpint(time_ms,last_time) < 0) reason("EVENT_TIME_REVERSED");
  if (time_ms != "" && (cmpint(time_ms,date_start_ms) < 0 || cmpint(time_ms,date_end_ms) >= 0)) reason("EVENT_DATE_MISMATCH");
  if (first_key == "" && uint(key)) first_key=key;
  if (first_time == "" && time_ms != "") first_time=time_ms;
  if (uint(key)) last_key=key;
  if (time_ms != "") last_time=time_ms;
}
END {
  if (row_count == 0) reason("EMPTY_MEMBER");
  status = reason_count == 0 ? "已证明" : "拒绝";
  printf "%s\t%.0f\t%.0f\t%s\t%s\t%s\t%s\t", status, row_count, byte_count, first_key, last_key, first_time, last_time;
  for (i=1; i<=reason_count; i++) printf "%s%s", (i==1 ? "" : ","), reason_order[i];
  printf "\n";
}
'''


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_bytes):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def task_contract_sha256(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        body_start = lines.index("## 依赖与阻塞条件")
    except ValueError as error:
        raise ValueError("TASK_CONTRACT_BOUNDARY_INVALID") from error
    try:
        body_end = lines.index("## 执行记录", body_start + 1)
    except ValueError:
        body_end = len(lines)
    header = [
        line for line in lines[:body_start]
        if any(line.startswith(prefix) for prefix in TASK_CONTRACT_HEADER_PREFIXES)
    ]
    if len(header) != len(TASK_CONTRACT_HEADER_PREFIXES):
        raise ValueError("TASK_CONTRACT_HEADER_INVALID")
    canonical = "\n".join(header + [""] + lines[body_start:body_end]).rstrip() + "\n"
    return sha256_bytes(canonical.encode("utf-8"))


def decode_record_table(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    if payload.get("schema_version") != "zhishi-record-table/v1":
        raise ValueError("RECORD_TABLE_VERSION_INVALID")
    columns = payload.get("columns")
    dictionaries = payload.get("dictionaries")
    rows = payload.get("rows")
    if not isinstance(columns, list) or len(columns) != len(set(columns)) or not all(isinstance(item, str) for item in columns):
        raise ValueError("RECORD_TABLE_COLUMNS_INVALID")
    if not isinstance(dictionaries, Mapping) or not isinstance(rows, list):
        raise ValueError("RECORD_TABLE_INVALID")
    for column, values in dictionaries.items():
        if column not in columns or not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("RECORD_TABLE_DICTIONARY_INVALID")
    decoded: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(columns):
            raise ValueError("RECORD_TABLE_ROW_INVALID")
        record: dict[str, Any] = {}
        for column, value in zip(columns, row):
            if column in dictionaries:
                if not isinstance(value, int) or value < 0 or value >= len(dictionaries[column]):
                    raise ValueError("RECORD_TABLE_INDEX_INVALID")
                value = dictionaries[column][value]
            record[column] = value
        decoded.append(record)
    return decoded


def load_record_table_shards(batch_dir: Path, prefix: str, limit: int) -> list[dict[str, Any]]:
    paths = sorted(batch_dir.glob(f"{prefix}-*.json"), key=lambda item: item.name.encode("utf-8"))
    if not paths:
        raise ValueError("RECORD_TABLE_SHARDS_MISSING")
    records: list[dict[str, Any]] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("RECORD_TABLE_SHARD_INVALID")
        records.extend(decode_record_table(load_json(path)))
        if len(records) > limit:
            raise ValueError("MEMBER_COUNT_LIMIT_EXCEEDED")
    return records


def verify_json_batch_files(
    batch_dir: Path, *, expected_fingerprint: str, max_files: int, max_file_bytes: int
) -> dict[str, str]:
    if batch_dir.is_symlink() or not batch_dir.is_dir():
        raise ValueError("BATCH_DIR_INVALID")
    root = batch_dir.resolve(strict=True)
    paths: list[Path] = []
    for path in batch_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("BATCH_FILE_INVALID")
        if path.is_dir():
            continue
        if len(paths) >= max_files or not path.is_file() or path.suffix != ".json":
            raise ValueError("BATCH_FILE_INVALID")
        if path.stat().st_size > max_file_bytes:
            raise ValueError("BATCH_FILE_SIZE_LIMIT_EXCEEDED")
        try:
            path.resolve(strict=True).relative_to(root)
        except ValueError as error:
            raise ValueError("BATCH_PATH_REJECTED") from error
        paths.append(path)
    if not paths:
        raise ValueError("BATCH_EMPTY")
    files = {
        str(path.relative_to(batch_dir)): sha256_file(path)
        for path in sorted(paths, key=lambda item: str(item.relative_to(batch_dir)).encode("utf-8"))
    }
    if sha256_bytes(canonical_json(files).encode("utf-8")) != expected_fingerprint:
        raise ValueError("BATCH_FILES_FINGERPRINT_DRIFT")
    return files


def load_source_records(batch_dir: Path, limit: int) -> list[dict[str, Any]]:
    member_dir = batch_dir / "members"
    if member_dir.is_symlink() or not member_dir.is_dir():
        raise ValueError("SOURCE_MEMBER_DIR_INVALID")
    records: list[dict[str, Any]] = []
    for path in sorted(member_dir.glob("*.json"), key=lambda item: item.name.encode("utf-8")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("SOURCE_MEMBER_SHARD_INVALID")
        payload = load_json(path)
        if not isinstance(payload, list):
            raise ValueError("SOURCE_MEMBER_SHARD_INVALID")
        records.extend(payload)
        if len(records) > limit:
            raise ValueError("MEMBER_COUNT_LIMIT_EXCEEDED")
    return records


def reconcile_formal_members(
    formal: Sequence[Mapping[str, Any]], source: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source_by_id: dict[str, Mapping[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for item in source:
        member_id = str(item.get("member_id") or "")
        if not member_id or member_id in source_by_id:
            raise ValueError("SOURCE_MEMBER_ID_INVALID")
        source_by_id[member_id] = item
        if item.get("status") != "已证明":
            rejected.append({
                "member_id": member_id,
                "group": item.get("group"),
                "relative_name": item.get("relative_name"),
                "status": item.get("status"),
                "reason_codes": item.get("reason_codes", []),
            })
    joined: list[dict[str, Any]] = []
    seen: set[str] = set()
    identity_fields = ("group", "contract", "dataset", "relative_name", "content_sha256", "size_bytes")
    for compact in formal:
        member_id = str(compact.get("member_id") or "")
        if not member_id or member_id in seen:
            raise ValueError("FORMAL_MEMBER_ID_INVALID")
        seen.add(member_id)
        source_item = source_by_id.get(member_id)
        if source_item is None or source_item.get("status") != "已证明":
            raise ValueError("FORMAL_SOURCE_MEMBER_MISSING")
        if any(compact.get(field) != source_item.get(field) for field in identity_fields):
            raise ValueError("FORMAL_SOURCE_IDENTITY_DRIFT")
        schema = source_item.get("schema")
        if not isinstance(schema, Mapping) or compact.get("schema_version") != schema.get("schema_version"):
            raise ValueError("FORMAL_SOURCE_IDENTITY_DRIFT")
        joined.append(dict(source_item, underlying=compact.get("underlying")))
    if len(joined) != sum(item.get("status") == "已证明" for item in source):
        raise ValueError("FORMAL_SOURCE_DENOMINATOR_DRIFT")
    joined.sort(key=lambda item: (str(item.get("underlying")), str(item["group"]), _event_date(str(item["relative_name"]))))
    return joined, rejected


def assert_no_symlink_components(path: Path, *, stop: Path | None = None) -> None:
    current = path.absolute()
    boundary = stop.absolute() if stop is not None else current
    while True:
        if current.is_symlink():
            raise ValueError("SOURCE_PATH_SYMLINK_REJECTED")
        if current == boundary:
            return
        parent = current.parent
        if parent == current or boundary not in (current, *current.parents):
            raise ValueError("SOURCE_PATH_BOUNDARY_INVALID")
        current = parent


def resolve_member_path(root: Path, group: Mapping[str, Any], member: Mapping[str, Any]) -> Path:
    relative_name = str(member.get("relative_name") or "")
    if Path(relative_name).name != relative_name or not relative_name.endswith(".zip"):
        raise ValueError("PATH_REJECTED")
    if not relative_name.startswith(f"{group['contract']}-{group['dataset']}-"):
        raise ValueError("PATH_REJECTED")
    assert_no_symlink_components(root)
    root_resolved = root.resolve(strict=True)
    group_root = root / str(group["relative_dir"])
    assert_no_symlink_components(group_root, stop=root)
    path = group_root / relative_name
    if path.is_symlink() or not path.is_file():
        raise ValueError("SOURCE_FILE_INVALID")
    try:
        path.resolve(strict=True).relative_to(root_resolved)
    except ValueError as error:
        raise ValueError("PATH_REJECTED") from error
    return path


def verify_member_file(
    root: Path, group: Mapping[str, Any], member: Mapping[str, Any], max_bytes: int
) -> Path:
    path = resolve_member_path(root, group, member)
    info = path.stat()
    if info.st_size > max_bytes:
        raise ValueError("SOURCE_FILE_SIZE_LIMIT_EXCEEDED")
    if info.st_size != member.get("size_bytes"):
        raise ValueError("FILE_SIZE_DRIFT")
    if sha256_file(path) != member.get("content_sha256"):
        raise ValueError("CONTENT_SHA_DRIFT")
    return path


def inventory_fingerprint(paths: Sequence[Path], root: Path, limit: int) -> tuple[str, int]:
    rows: list[dict[str, Any]] = []

    def append(path: Path, kind: str, size: int = 0, mtime_ns: int = 0) -> None:
        if len(rows) >= limit:
            raise ValueError("INVENTORY_ENTRY_LIMIT_EXCEEDED")
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            relative = str(path)
        row: dict[str, Any] = {"path": relative, "kind": kind}
        if kind != "missing":
            row.update(size=size, mtime_ns=mtime_ns)
        rows.append(row)

    for parent in paths:
        assert_no_symlink_components(parent, stop=root)
        if not parent.exists() and not parent.is_symlink():
            append(parent, "missing")
            continue
        candidates = [parent]
        if parent.is_dir() and not parent.is_symlink():
            with os.scandir(parent) as entries:
                candidates.extend(sorted((Path(item.path) for item in entries), key=lambda item: item.name.encode("utf-8")))
        for path in candidates:
            info = path.lstat()
            kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
            append(path, kind, info.st_size, info.st_mtime_ns)
    return sha256_bytes(canonical_json(rows).encode("utf-8")), len(rows)


def _memory_available_percent() -> float:
    try:
        output = subprocess.run(["/usr/bin/memory_pressure", "-Q"], check=True, capture_output=True, text=True, timeout=10).stdout
        match = re.search(r"free percentage:\s*(\d+)%", output)
        if match:
            return float(match.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, separator, raw = line.partition(":")
            if separator and raw.strip().endswith("kB"):
                values[key] = int(raw.strip().split()[0])
        if values.get("MemTotal", 0) > 0:
            return values.get("MemAvailable", 0) * 100.0 / values["MemTotal"]
    except (OSError, UnicodeError, ValueError):
        pass
    return 0.0


def _process_max_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _child_max_rss_bytes(usage: resource.struct_rusage) -> int:
    value = int(usage.ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _wait4_process(process: subprocess.Popen[bytes], timeout: float) -> int:
    """等待唯一子进程并返回该进程自身的峰值RSS，不使用聚合子进程值。"""

    if not hasattr(os, "wait4"):
        raise OSError("PROCESS_RUSAGE_UNAVAILABLE")
    deadline = time.monotonic() + timeout
    while True:
        waited_pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if waited_pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return _child_max_rss_bytes(usage)
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(0.01)


def _kill_and_reap(process: subprocess.Popen[bytes] | None) -> int:
    if process is None or process.returncode is not None:
        return 0
    try:
        process.kill()
    except ProcessLookupError:
        pass
    try:
        return _wait4_process(process, 10)
    except (ChildProcessError, OSError, subprocess.TimeoutExpired):
        return 0


def resource_snapshot(output_root: Path, source_root: Path) -> dict[str, Any]:
    output_probe = output_root if output_root.exists() else output_root.parent
    return {
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "memory_available_percent": _memory_available_percent(),
        "output_disk_free_bytes": shutil.disk_usage(output_probe).free,
        "source_disk_free_bytes": shutil.disk_usage(source_root).free,
        "process_max_rss_bytes": _process_max_rss_bytes(),
    }


def assert_resource_limits(snapshot: Mapping[str, Any], limits: Mapping[str, Any]) -> None:
    if float(snapshot["memory_available_percent"]) < float(limits["min_available_memory_percent"]):
        raise ValueError("MEMORY_HEADROOM_INSUFFICIENT")
    if int(snapshot["output_disk_free_bytes"]) < int(limits["min_output_disk_bytes"]):
        raise ValueError("OUTPUT_DISK_HEADROOM_INSUFFICIENT")
    if int(snapshot["source_disk_free_bytes"]) < int(limits["min_source_disk_bytes"]):
        raise ValueError("SOURCE_DISK_HEADROOM_INSUFFICIENT")
    if int(snapshot["process_max_rss_bytes"]) > int(limits["memory_bytes"]):
        raise ValueError("PROCESS_MEMORY_LIMIT_EXCEEDED")


def assert_time_limit(started: float, limits: Mapping[str, Any]) -> None:
    if time.monotonic() - started > float(limits["total_seconds"]):
        raise TimeoutError("TOTAL_TIME_LIMIT_EXCEEDED")


def load_config(path: Path) -> dict[str, Any]:
    config = load_json(path)
    fingerprint = sha256_bytes(canonical_json(config).encode("utf-8"))
    if fingerprint != EXPECTED_CONFIG_SHA256:
        raise ValueError("CONFIG_FINGERPRINT_INVALID")
    if config.get("schema_version") != "zhishi-stage1-time-quality-audit/v1":
        raise ValueError("CONFIG_VERSION_INVALID")
    if config.get("task_id") != "000094":
        raise ValueError("CONFIG_TASK_INVALID")
    if [item.get("id") for item in config.get("groups", [])] != [
        "BTCUSDT-trades",
        "ETHUSDT-trades",
        "BTCUSDT-aggTrades",
    ]:
        raise ValueError("CONFIG_GROUPS_INVALID")
    if config.get("main_horizons_hours") != [4, 8, 24, 48]:
        raise ValueError("CONFIG_HORIZONS_INVALID")
    return config


def normalize_epoch_ms(value: str) -> int:
    if not isinstance(value, str) or not value.isdigit() or len(value) not in {13, 16}:
        raise ValueError("EVENT_TIME_INVALID")
    return int(value if len(value) == 13 else value[:13])


def normalize_decimal(value: str, positive: bool) -> bool:
    if not isinstance(value, str) or DECIMAL_PATTERN.fullmatch(value) is None:
        return False
    if not positive:
        return True
    return any(char not in {"0", "."} for char in value)


def _parse_rfc3339(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("SOURCE_VISIBILITY_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("SOURCE_VISIBILITY_INVALID") from error
    if parsed.tzinfo is None:
        raise ValueError("SOURCE_VISIBILITY_INVALID")
    return parsed.astimezone(timezone.utc)


def source_visible_at(member: Mapping[str, Any]) -> str:
    remote = member.get("remote_evidence")
    if not isinstance(remote, Mapping):
        raise ValueError("SOURCE_VISIBILITY_INVALID")
    visible = max(
        _parse_rfc3339(remote.get("zip_last_modified")),
        _parse_rfc3339(remote.get("checksum_last_modified")),
    )
    return visible.isoformat(timespec="seconds").replace("+00:00", "Z")


def _event_date(name: str) -> str:
    match = DATE_PATTERN.search(name)
    if match is None:
        raise ValueError("MEMBER_NAME_INVALID")
    datetime.strptime(match.group(1), "%Y-%m-%d")
    return match.group(1)


def _check_tool(path_value: Any) -> str:
    if not isinstance(path_value, str) or not path_value.startswith("/usr/bin/"):
        raise ValueError("SCANNER_TOOL_INVALID")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
        raise ValueError("SCANNER_TOOL_INVALID")
    return path_value


def compile_scanner(
    source: Path,
    directory: Path,
    compiler: str,
    expected_source_sha256: str | None = None,
    process_resources: dict[str, int] | None = None,
) -> Path:
    compiler_path = _check_tool(compiler)
    if source.is_symlink() or not source.is_file():
        raise ValueError("SCANNER_SOURCE_INVALID")
    if expected_source_sha256 is not None and sha256_file(source) != expected_source_sha256:
        raise ValueError("SCANNER_SOURCE_FINGERPRINT_DRIFT")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "stage1-time-quality-scanner"
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            [compiler_path, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(target)],
            stdout=stdout_file,
            stderr=stderr_file,
        )
        try:
            compiler_rss = _wait4_process(process, 120)
        except (OSError, subprocess.TimeoutExpired):
            _kill_and_reap(process)
            raise ValueError("SCANNER_COMPILE_FAILED") from None
        stderr_file.seek(0)
        stderr = stderr_file.read(65537)
    if process_resources is not None:
        process_resources["compiler_max_rss_bytes"] = max(
            process_resources.get("compiler_max_rss_bytes", 0), compiler_rss
        )
    if process.returncode != 0 or len(stderr) > 65536 or not target.is_file() or target.is_symlink() or not os.access(target, os.X_OK):
        raise ValueError("SCANNER_COMPILE_FAILED")
    return target


def _scanner_failure(member: Mapping[str, Any], group: Mapping[str, Any], code: str) -> dict[str, Any]:
    return {
        "member_id": str(member.get("member_id") or ""),
        "group": str(group.get("id") or ""),
        "underlying": str(group.get("underlying") or ""),
        "contract": str(group.get("contract") or ""),
        "dataset": str(group.get("dataset") or ""),
        "event_date": _event_date(str(member.get("relative_name") or "")),
        "status": "失败",
        "reason_codes": [code],
        "row_count": 0,
        "uncompressed_bytes": 0,
    }


def scan_member(
    path: Path,
    member: Mapping[str, Any],
    group: Mapping[str, Any],
    tools: Mapping[str, Any],
    limits: Mapping[str, Any],
    process_resources: dict[str, int] | None = None,
) -> dict[str, Any]:
    relative_name = str(member.get("relative_name") or "")
    event_date = _event_date(relative_name)
    expected_csv = Path(relative_name).stem + ".csv"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > int(limits["single_source_file_bytes"]):
        return _scanner_failure(member, group, "SOURCE_FILE_INVALID")
    try:
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            if len(items) != 1:
                return _scanner_failure(member, group, "ZIP_MEMBER_INVALID")
            item = items[0]
            pure = PurePosixPath(item.filename)
            if item.is_dir() or item.filename != expected_csv or pure.is_absolute() or ".." in pure.parts or len(pure.parts) != 1:
                return _scanner_failure(member, group, "ZIP_MEMBER_INVALID")
    except (OSError, zipfile.BadZipFile):
        return _scanner_failure(member, group, "ZIP_INVALID")

    visible_at = source_visible_at(member)
    day_start = datetime.strptime(event_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)
    if _parse_rfc3339(visible_at) < day_end:
        return _scanner_failure(member, group, "SOURCE_VISIBILITY_BEFORE_EVENT_DAY_END")
    header_present = bool((member.get("schema") or {}).get("header_present"))
    header = ",".join(str(value) for value in group["header"])
    unzip = _check_tool(tools.get("unzip"))
    scanner_value = tools.get("scanner")
    if scanner_value is not None:
        scanner = Path(str(scanner_value))
        if scanner.is_symlink() or not scanner.is_file() or not os.access(scanner, os.X_OK):
            raise ValueError("SCANNER_TOOL_INVALID")
        command = [
            str(scanner), str(group["dataset"]), str(int(group["column_count"])),
            str(int(group["event_time_index"])), "1" if header_present else "0", header,
            str(int(day_start.timestamp() * 1000)), str(int(day_end.timestamp() * 1000)),
        ]
    else:
        awk = _check_tool(tools.get("awk"))
        command = [
            awk,
            "-v", f"dataset={group['dataset']}",
            "-v", f"column_count={int(group['column_count'])}",
            "-v", f"event_time_index={int(group['event_time_index'])}",
            "-v", f"header_expected={1 if header_present else 0}",
            "-v", f"header_line={header}",
            "-v", f"date_start_ms={int(day_start.timestamp() * 1000)}",
            "-v", f"date_end_ms={int(day_end.timestamp() * 1000)}",
            AWK_SCANNER,
        ]
    unzip_process: subprocess.Popen[bytes] | None = None
    scanner_process: subprocess.Popen[bytes] | None = None
    unzip_rss = 0
    scanner_rss = 0
    try:
        with (
            tempfile.TemporaryFile() as scanner_stdout,
            tempfile.TemporaryFile() as scanner_stderr,
            tempfile.TemporaryFile() as unzip_stderr_file,
        ):
            unzip_process = subprocess.Popen(
                [unzip, "-p", str(path), expected_csv],
                stdout=subprocess.PIPE,
                stderr=unzip_stderr_file,
            )
            if unzip_process.stdout is None:
                raise OSError("unzip stdout unavailable")
            scanner_process = subprocess.Popen(
                command,
                stdin=unzip_process.stdout,
                stdout=scanner_stdout,
                stderr=scanner_stderr,
            )
            unzip_process.stdout.close()
            member_timeout = int(limits["member_seconds"])
            scanner_rss = _wait4_process(scanner_process, member_timeout)
            unzip_rss = _wait4_process(unzip_process, 10)
            scanner_stdout.seek(0)
            stdout = scanner_stdout.read(int(limits["scanner_stdout_bytes"]) + 1)
            scanner_stderr.seek(0)
            awk_stderr = scanner_stderr.read(int(limits["scanner_stderr_bytes"]) + 1)
            unzip_stderr_file.seek(0)
            unzip_stderr = unzip_stderr_file.read(int(limits["scanner_stderr_bytes"]) + 1)
    except (ChildProcessError, OSError, subprocess.TimeoutExpired):
        scanner_rss = max(scanner_rss, _kill_and_reap(scanner_process))
        unzip_rss = max(unzip_rss, _kill_and_reap(unzip_process))
        if process_resources is not None:
            process_resources["unzip_max_rss_bytes"] = max(process_resources.get("unzip_max_rss_bytes", 0), unzip_rss)
            process_resources["scanner_max_rss_bytes"] = max(process_resources.get("scanner_max_rss_bytes", 0), scanner_rss)
        return _scanner_failure(member, group, "SCANNER_EXECUTION_FAILED")
    if process_resources is not None:
        process_resources["unzip_max_rss_bytes"] = max(process_resources.get("unzip_max_rss_bytes", 0), unzip_rss)
        process_resources["scanner_max_rss_bytes"] = max(process_resources.get("scanner_max_rss_bytes", 0), scanner_rss)
    if (
        len(stdout) > int(limits["scanner_stdout_bytes"])
        or len(awk_stderr) > int(limits["scanner_stderr_bytes"])
        or len(unzip_stderr) > int(limits["scanner_stderr_bytes"])
        or scanner_process is None
        or scanner_process.returncode != 0
        or unzip_process is None
        or unzip_process.returncode != 0
    ):
        return _scanner_failure(member, group, "SCANNER_EXECUTION_FAILED")
    try:
        fields = stdout.decode("utf-8").rstrip("\n").split("\t")
        if len(fields) != 8:
            raise ValueError
        status, row_count, byte_count, first_key, last_key, first_time, last_time, reasons = fields
        if status not in {"已证明", "拒绝"}:
            raise ValueError
        reason_codes = [] if reasons == "" else reasons.split(",")
        result = {
            "member_id": str(member["member_id"]),
            "member_identity_sha256": sha256_bytes(str(member["member_id"]).encode("utf-8")),
            "group": str(group["id"]),
            "underlying": str(group["underlying"]),
            "contract": str(group["contract"]),
            "dataset": str(group["dataset"]),
            "event_date": event_date,
            "source_visible_at": visible_at,
            "status": status,
            "reason_codes": reason_codes,
            "row_count": int(row_count),
            "uncompressed_bytes": int(byte_count),
            "first_event_time_ms": int(first_time) if first_time else None,
            "last_event_time_ms": int(last_time) if last_time else None,
            "_first_key": first_key,
            "_last_key": last_key,
        }
    except (UnicodeError, ValueError, KeyError):
        return _scanner_failure(member, group, "SCANNER_OUTPUT_INVALID")
    return result


def compact_member_result(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if not key.startswith("_")}


def validate_cross_member_boundaries(member_results: Sequence[dict[str, Any]]) -> None:
    previous: dict[str, dict[str, Any]] = {}
    for row in sorted(member_results, key=lambda item: (str(item["group"]), str(item["event_date"]))):
        if row.get("status") != "已证明":
            previous.pop(str(row["group"]), None)
            continue
        group = str(row["group"])
        prior = previous.get(group)
        if prior is not None:
            prior_date = datetime.strptime(str(prior["event_date"]), "%Y-%m-%d").date()
            date_value = datetime.strptime(str(row["event_date"]), "%Y-%m-%d").date()
            if date_value == prior_date + timedelta(days=1):
                reasons: list[str] = []
                if int(str(row.get("_first_key") or "0")) <= int(str(prior.get("_last_key") or "0")):
                    reasons.append("CROSS_MEMBER_KEY_NOT_INCREASING")
                first_time = row.get("first_event_time_ms")
                last_time = prior.get("last_event_time_ms")
                if first_time is None or last_time is None or int(first_time) < int(last_time):
                    reasons.append("CROSS_MEMBER_EVENT_TIME_REVERSED")
                if reasons:
                    row["status"] = "拒绝"
                    existing = list(row.get("reason_codes") or [])
                    row["reason_codes"] = list(dict.fromkeys(existing + reasons))
                    previous.pop(group, None)
                    continue
        previous[group] = row


def build_segments(member_results: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    accepted = sorted(
        (row for row in member_results if row.get("status") == "已证明"),
        key=lambda row: (
            str(row["underlying"]),
            str(row["contract"]),
            str(row["dataset"]),
            str(row["event_date"]),
        ),
    )
    segments: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for row in accepted:
        group = f"{row['contract']}-{row['dataset']}"
        date_value = datetime.strptime(str(row["event_date"]), "%Y-%m-%d").date()
        if (
            current is None
            or current["group"] != group
            or date_value != datetime.strptime(current["end_date"], "%Y-%m-%d").date() + timedelta(days=1)
        ):
            current = {
                "underlying": row["underlying"],
                "contract": row["contract"],
                "dataset": row["dataset"],
                "group": group,
                "start_date": str(row["event_date"]),
                "end_date": str(row["event_date"]),
                "day_count": 1,
            }
            segments.append(current)
        else:
            current["end_date"] = str(row["event_date"])
            current["day_count"] += 1
    return segments


def update_gate_leaves(
    old_leaves: Sequence[Mapping[str, Any]],
    expected_counts: Mapping[str, int],
    audited_counts: Mapping[str, int],
    max_segment_days: Mapping[str, int],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    updated: list[dict[str, Any]] = []
    for old in old_leaves:
        leaf = copy.deepcopy(dict(old))
        underlying = str(leaf.get("underlying") or "")
        horizon = int(leaf.get("horizon_hours") or 0)
        expected = int(expected_counts.get(underlying, 0))
        audited = int(audited_counts.get(underlying, 0))
        segment_days = int(max_segment_days.get(underlying, 0))
        complete = expected > 0 and audited == expected
        coverage = segment_days * 24 >= horizon
        leaf["gates"]["三类时间"] = {
            "status": "通过" if complete and coverage else "无法判定",
            "reason_code": "ARCHIVE_VISIBILITY_AND_CAPTURE_BOUND" if complete and coverage else "TIME_AUDIT_INCOMPLETE",
            "evidence_refs": ["members-*.json#/", "segments.json#/"],
            "release_conditions": ["同一正式输入逐成员三类时间、官方归档可见边界和连续段持续全等"],
        }
        leaf["gates"]["质量"] = {
            "status": "通过" if complete and coverage else "无法判定",
            "reason_code": "FULL_ROW_QUALITY_AUDITED" if complete and coverage else "FULL_ROW_QUALITY_INCOMPLETE",
            "evidence_refs": ["members-*.json#/", "segments.json#/", "summary.json#/status_counts"],
            "release_conditions": ["同一正式输入完整逐行扫描、状态守恒且研究窗口不跨缺口"],
        }
        leaf["decision"] = "通过" if all(gate.get("status") == "通过" for gate in leaf["gates"].values()) else "阻塞"
        updated.append(leaf)
    return updated


def json_table_shards(
    records: Sequence[Mapping[str, Any]], prefix: str, max_bytes: int
) -> Iterator[tuple[str, str]]:
    if not records:
        return
    columns = sorted(records[0])
    expected = set(columns)
    candidates: dict[str, set[str]] = {column: set() for column in columns}
    for record in records:
        if set(record) != expected:
            raise ValueError("OUTPUT_TABLE_SCHEMA_DRIFT")
        for column in list(candidates):
            value = record[column]
            if not isinstance(value, str):
                candidates.pop(column, None)
            else:
                candidates[column].add(value)
                if len(candidates[column]) > 32:
                    candidates.pop(column, None)
    dictionaries = {
        column: sorted(values, key=lambda value: value.encode("utf-8"))
        for column, values in sorted(candidates.items()) if values
    }
    indexes = {column: {value: index for index, value in enumerate(values)} for column, values in dictionaries.items()}
    header = (
        '{"schema_version":"zhishi-record-table/v1","columns":'
        + canonical_json(columns) + ',"dictionaries":' + canonical_json(dictionaries) + ',"rows":['
    )
    suffix = "]}\n"
    base_bytes = len(header.encode("utf-8")) + len(suffix.encode("utf-8"))
    current: list[str] = []
    current_bytes = base_bytes
    index = 1
    for record in records:
        encoded = canonical_json([indexes[column][record[column]] if column in indexes else record[column] for column in columns])
        encoded_bytes = len(encoded.encode("utf-8"))
        separator = 1 if current else 0
        if current and current_bytes + separator + encoded_bytes > max_bytes:
            yield f"{prefix}-{index:03d}.json", header + ",".join(current) + suffix
            index += 1
            current = []
            current_bytes = base_bytes
            separator = 0
        if current_bytes + separator + encoded_bytes > max_bytes:
            raise ValueError("OUTPUT_RECORD_LIMIT_EXCEEDED")
        current.append(encoded)
        current_bytes += separator + encoded_bytes
    if current:
        yield f"{prefix}-{index:03d}.json", header + ",".join(current) + suffix


def atomic_publish(output_root: Path, batch_id: str, files: Mapping[str, str], max_total_bytes: int) -> Path:
    if not batch_id or Path(batch_id).name != batch_id:
        raise ValueError("BATCH_ID_INVALID")
    output_root.mkdir(parents=True, exist_ok=True)
    target = output_root / batch_id
    if target.exists():
        raise FileExistsError("BATCH_ALREADY_EXISTS")
    total = sum(len(content.encode("utf-8")) for content in files.values())
    if total > max_total_bytes:
        raise ValueError("OUTPUT_TOTAL_LIMIT_EXCEEDED")
    temporary = Path(tempfile.mkdtemp(prefix=f".{batch_id}.", dir=output_root))
    try:
        for relative_name, content in files.items():
            relative = Path(relative_name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("OUTPUT_PATH_INVALID")
            if len(content.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("OUTPUT_FILE_LIMIT_EXCEEDED")
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        temporary.rename(target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target


def _normalized_output_record(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "member_id": str(result.get("member_id") or ""),
        "member_identity_sha256": str(result.get("member_identity_sha256") or sha256_bytes(str(result.get("member_id") or "").encode("utf-8"))),
        "group": str(result.get("group") or ""),
        "underlying": str(result.get("underlying") or ""),
        "contract": str(result.get("contract") or ""),
        "dataset": str(result.get("dataset") or ""),
        "event_date": str(result.get("event_date") or ""),
        "source_visible_at": result.get("source_visible_at"),
        "collected_at": result.get("collected_at"),
        "status": str(result.get("status") or "失败"),
        "reason_codes": ",".join(str(value) for value in result.get("reason_codes", [])),
        "row_count": int(result.get("row_count") or 0),
        "uncompressed_bytes": int(result.get("uncompressed_bytes") or 0),
        "first_event_time_ms": result.get("first_event_time_ms"),
        "last_event_time_ms": result.get("last_event_time_ms"),
    }


def scan_all_members(
    members: Sequence[Mapping[str, Any]],
    group_map: Mapping[str, Mapping[str, Any]],
    config: Mapping[str, Any],
    repo_root: Path,
    output_root: Path,
    source_root: Path,
    started: float,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, int]]:
    limits = config["limits"]
    tools = dict(config["tools"])
    scanner_source = repo_root / str(tools["scanner_source"])
    process_resources = {
        "compiler_max_rss_bytes": 0,
        "unzip_max_rss_bytes": 0,
        "scanner_max_rss_bytes": 0,
    }
    with tempfile.TemporaryDirectory(prefix="zhishi-task094-scanner-") as directory:
        scanner = compile_scanner(
            scanner_source,
            Path(directory),
            str(tools["compiler"]),
            str(tools["scanner_source_sha256"]),
            process_resources,
        )
        scanner_facts = {
            "source_sha256": sha256_file(scanner_source),
            "binary_sha256": sha256_file(scanner),
            "compiler": str(tools["compiler"]),
        }
        tools["scanner"] = str(scanner)
        results: list[dict[str, Any]] = []
        for index, member in enumerate(members, start=1):
            group = group_map.get(str(member.get("group") or ""))
            if group is None:
                raise ValueError("UNKNOWN_GROUP")
            try:
                path = verify_member_file(source_root, group, member, int(limits["single_source_file_bytes"]))
                result = scan_member(path, member, group, tools, limits, process_resources)
            except (OSError, ValueError) as error:
                result = _scanner_failure(member, group, str(error))
            result["collected_at"] = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            try:
                result.setdefault("source_visible_at", source_visible_at(member))
            except ValueError:
                result.setdefault("source_visible_at", None)
            results.append(result)
            if index % 25 == 0 or index == len(members):
                statuses = Counter(str(item["status"]) for item in results)
                print(f"逐行时间质量审计: {index}/{len(members)}，拒绝={statuses['拒绝']}，失败={statuses['失败']}", file=sys.stderr, flush=True)
                assert_resource_limits(resource_snapshot(output_root, source_root), limits)
                assert_time_limit(started, limits)
        return results, scanner_facts, process_resources


def run(config_path: Path, repo_root: Path, output_root: Path, batch_id: str) -> Path:
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if config_path.resolve() != (repo_root / EXPECTED_CONFIG_RELATIVE_PATH).resolve():
        raise ValueError("CONFIG_PATH_INVALID")
    if output_root.resolve() != (repo_root / EXPECTED_OUTPUT_RELATIVE_PATH).resolve():
        raise ValueError("OUTPUT_PATH_INVALID")
    config = load_config(config_path)
    limits = config["limits"]
    task_path = repo_root / "docs/研发中心/任务/任务-000094.md"
    contract_sha = task_contract_sha256(task_path)
    if contract_sha != config.get("task_contract_sha256"):
        raise ValueError("TASK_CONTRACT_FINGERPRINT_DRIFT")

    source_batch = repo_root / str(config["source_batch_dir"])
    formal_batch = repo_root / str(config["formal_batch_dir"])
    source_files = verify_json_batch_files(
        source_batch,
        expected_fingerprint=str(config["source_batch_files_fingerprint"]),
        max_files=int(limits["batch_file_count"]),
        max_file_bytes=int(limits["batch_file_bytes"]),
    )
    formal_files = verify_json_batch_files(
        formal_batch,
        expected_fingerprint=str(config["formal_batch_files_fingerprint"]),
        max_files=int(limits["batch_file_count"]),
        max_file_bytes=int(limits["batch_file_bytes"]),
    )
    if sha256_file(formal_batch / "summary.json") != config["formal_summary_sha256"]:
        raise ValueError("FORMAL_SUMMARY_SHA_DRIFT")
    formal_summary = load_json(formal_batch / "summary.json")
    if formal_summary.get("batch_id") != config["formal_batch_id"]:
        raise ValueError("FORMAL_BATCH_IDENTITY_INVALID")
    formal = load_record_table_shards(formal_batch, "formal-input", int(limits["member_count"]) + 1)
    if sha256_bytes(canonical_json(formal).encode("utf-8")) != config["formal_input_fingerprint"]:
        raise ValueError("FORMAL_INPUT_FINGERPRINT_DRIFT")
    source = load_source_records(source_batch, int(limits["source_member_count"]))
    members, source_rejected = reconcile_formal_members(formal, source)
    expected = config["expected_counts"]
    if len(source) != int(expected["candidate_total"]) or len(members) != int(expected["formal_members"]) or len(source_rejected) != int(expected["source_rejected"]):
        raise ValueError("DENOMINATOR_DRIFT")

    group_map = {str(group["id"]): group for group in config["groups"]}
    source_root = Path(str(config["local_root"]))
    assert_no_symlink_components(source_root)
    inventory_paths = [source_root / str(relative) for relative in config["inventory_relative_paths"]]
    before_inventory, before_count = inventory_fingerprint(inventory_paths, source_root, int(limits["inventory_entry_count"]))
    if before_inventory != config["source_inventory_fingerprint"]:
        raise ValueError("SOURCE_INVENTORY_BASELINE_DRIFT")
    start_snapshot = resource_snapshot(output_root, source_root)
    assert_resource_limits(start_snapshot, limits)

    results, scanner_facts, child_resources = scan_all_members(
        members, group_map, config, repo_root, output_root, source_root, started
    )

    validate_cross_member_boundaries(results)
    after_inventory, after_count = inventory_fingerprint(inventory_paths, source_root, int(limits["inventory_entry_count"]))
    if before_inventory != after_inventory or before_count != after_count:
        raise ValueError("SOURCE_INVENTORY_DRIFT")
    status_counts = Counter(str(item["status"]) for item in results)
    if len(results) != sum(status_counts[status] for status in STATUSES):
        raise ValueError("STATUS_CONSERVATION_FAILED")
    segments = build_segments(results)
    expected_underlying = Counter(str(item["underlying"]) for item in formal)
    audited_underlying = Counter(str(item["underlying"]) for item in results if item.get("status") not in {"失败", "无法判定", "未成熟", "失效"})
    max_segment_days: dict[str, int] = {}
    for segment in segments:
        underlying = str(segment["underlying"])
        max_segment_days[underlying] = max(max_segment_days.get(underlying, 0), int(segment["day_count"]))
    old_leaves = load_json(formal_batch / "leaves.json")
    leaves = update_gate_leaves(old_leaves, expected_underlying, audited_underlying, max_segment_days)
    completed_snapshot = resource_snapshot(output_root, source_root)
    assert_resource_limits(completed_snapshot, limits)
    controller_rss = _process_max_rss_bytes()
    compiler_rss = int(child_resources["compiler_max_rss_bytes"])
    unzip_rss = int(child_resources["unzip_max_rss_bytes"])
    scanner_rss = int(child_resources["scanner_max_rss_bytes"])
    children_rss = compiler_rss + unzip_rss + scanner_rss
    process_group_rss = controller_rss + children_rss
    process_group_resource_facts = {
        "measurement_protocol": "zhishi-process-group-rusage/v1",
        "measurement_platform": "darwin-rusage-maxrss-by-process/v1",
        "rss_unit": "bytes",
        "process_topology": [
            "python_controller",
            "fixed_clang_compile",
            "fixed_unzip",
            "fixed_scanner",
        ],
        "members_parallelism": 1,
        "controller_max_rss_bytes": controller_rss,
        "compiler_max_rss_bytes": compiler_rss,
        "unzip_max_rss_bytes": unzip_rss,
        "scanner_max_rss_bytes": scanner_rss,
        "children_conservative_sum_max_rss_bytes": children_rss,
        "conservative_process_group_max_rss_bytes": process_group_rss,
    }
    if sys.platform != "darwin" or process_group_rss > int(limits["memory_bytes"]):
        raise ValueError("PROCESS_GROUP_MEMORY_LIMIT_EXCEEDED")
    compact_results = [_normalized_output_record(item) for item in results]
    total_rows = sum(int(item["row_count"]) for item in compact_results)
    total_uncompressed = sum(int(item["uncompressed_bytes"]) for item in compact_results)
    summary = {
        "schema_version": "zhishi-stage1-time-quality-audit-batch/v1",
        "task_id": "000094",
        "batch_id": batch_id,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "route_decision": "任务-000092/000093新候选集替代任务-000084旧路线",
        "legacy_task_000084_current_gate": False,
        "source_batch_id": config["source_batch_id"],
        "formal_batch_id": config["formal_batch_id"],
        "formal_input_fingerprint": config["formal_input_fingerprint"],
        "source_batch_files_fingerprint": sha256_bytes(canonical_json(source_files).encode("utf-8")),
        "formal_batch_files_fingerprint": sha256_bytes(canonical_json(formal_files).encode("utf-8")),
        "config_sha256": sha256_file(config_path),
        "executor_sha256": sha256_file(Path(__file__).resolve()),
        "scanner_source_sha256": scanner_facts["source_sha256"],
        "scanner": scanner_facts,
        "task_contract_sha256": contract_sha,
        "task_file_sha256_at_run": sha256_file(task_path),
        "candidate_total": len(source),
        "formal_member_count": len(formal),
        "source_rejected_count": len(source_rejected),
        "observation_item_count": int(expected["observation_items"]),
        "audited_member_count": len(results),
        "status_counts": {status: status_counts[status] for status in STATUSES},
        "scanned_row_count": total_rows,
        "uncompressed_bytes": total_uncompressed,
        "segment_count": len(segments),
        "leaf_count": len(leaves),
        "allowed_research_leaf_count": sum(item["decision"] == "通过" for item in leaves),
        "stage1_complete": all(item["decision"] == "通过" for item in leaves),
        "stage2_released": False,
        "source_inventory_before_sha256": before_inventory,
        "source_inventory_after_sha256": after_inventory,
        "source_inventory_entry_count": before_count,
        "source_data_modified": False,
        "scan_scope": "5180个正式成员逐文件SHA复验并逐行验证全部CSV业务行；未抽样、未外推、未落盘解压",
        "remaining_blockers": ["同版本历史重放证据缺失", "成本与执行证据缺失", "研究流水线容量证据缺失", "隔离恢复证据缺失"],
        "process_group_resource_facts": process_group_resource_facts,
        "resource_facts": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "processes": 3,
            "start": start_snapshot,
            "completed": completed_snapshot,
        },
    }
    files: dict[str, str] = {
        "segments.json": json.dumps(segments, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "leaves.json": json.dumps(leaves, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "source-rejected.json": canonical_json(source_rejected) + "\n",
        "source-batch-files.json": canonical_json(source_files) + "\n",
        "formal-batch-files.json": canonical_json(formal_files) + "\n",
    }
    for name, content in json_table_shards(compact_results, "members", int(limits["output_file_bytes"]) - 1024):
        files[name] = content
    output_payload_files = {
        name: sha256_bytes(content.encode("utf-8")) for name, content in sorted(files.items())
    }
    summary["output_payload_files"] = output_payload_files
    summary["output_payload_fingerprint"] = sha256_bytes(canonical_json(output_payload_files).encode("utf-8"))
    prepublish_snapshot = resource_snapshot(output_root, source_root)
    assert_resource_limits(prepublish_snapshot, limits)
    assert_time_limit(started, limits)
    summary["resource_facts"]["prepublish"] = prepublish_snapshot
    files["summary.json"] = json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    target = atomic_publish(output_root, batch_id, files, int(limits["output_total_bytes"]))
    print(json.dumps({"batch_id": batch_id, "output": str(target), "summary": summary}, ensure_ascii=False), flush=True)
    return target


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--batch-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    output_root = args.output_root if args.output_root.is_absolute() else repo_root / args.output_root
    if re.fullmatch(r"stage1-time-quality-[0-9TZ-]+-[0-9a-f]{12}", args.batch_id) is None:
        raise SystemExit("BATCH_ID_INVALID")
    run(config_path, repo_root, output_root, args.batch_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
