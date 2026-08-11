#!/usr/bin/env python3
"""任务-000093：基于已证明Binance归档重算阶段1门禁。"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
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
from typing import Any, Callable, Mapping, Sequence


STATUSES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
GATES = ("来源身份", "三类时间", "质量", "历史重放", "成本与执行", "血缘", "容量", "恢复")
DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})\.zip$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_CONFIG_CANONICAL_SHA256 = "c88fa0502d54139b1245bb561f3e6850bd2f76067004fecda48a1da2b64c906e"
EXPECTED_CONFIG_RELATIVE_PATH = Path("config/审计/任务-000093阶段1新候选集重算.json")
EXPECTED_OUTPUT_RELATIVE_PATH = Path("artifacts/审计/阶段1新候选集重算")


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


def load_config(path: Path) -> dict[str, Any]:
    config = load_json(path)
    if sha256_bytes(canonical_json(config).encode("utf-8")) != EXPECTED_CONFIG_CANONICAL_SHA256:
        raise ValueError("CONFIG_FINGERPRINT_INVALID")
    if config.get("schema_version") != "zhishi-stage1-candidate-recompute/v1":
        raise ValueError("CONFIG_VERSION_INVALID")
    groups = config.get("groups")
    if not isinstance(groups, list) or len(groups) != 3:
        raise ValueError("CONFIG_GROUPS_INVALID")
    if [item.get("id") for item in groups] != ["BTCUSDT-trades", "ETHUSDT-trades", "BTCUSDT-aggTrades"]:
        raise ValueError("CONFIG_GROUPS_INVALID")
    if config.get("main_horizons_hours") != [4, 8, 24, 48]:
        raise ValueError("CONFIG_HORIZONS_INVALID")
    if tuple(config.get("gates") or ()) != GATES:
        raise ValueError("CONFIG_GATES_INVALID")
    return config


def verify_source_batch_files(
    batch_dir: Path,
    *,
    expected_fingerprint: str,
    max_files: int,
    max_file_bytes: int,
) -> dict[str, str]:
    """在读取来源摘要或成员前冻结完整普通JSON文件集合。"""

    if batch_dir.is_symlink() or not batch_dir.is_dir():
        raise ValueError("SOURCE_BATCH_DIR_INVALID")
    root = batch_dir.resolve(strict=True)
    paths: list[Path] = []
    for path in batch_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("SOURCE_BATCH_FILE_INVALID")
        if path.is_dir():
            continue
        if len(paths) >= max_files:
            raise ValueError("SOURCE_BATCH_FILE_COUNT_LIMIT_EXCEEDED")
        if not path.is_file() or path.suffix != ".json":
            raise ValueError("SOURCE_BATCH_FILE_INVALID")
        try:
            path.resolve(strict=True).relative_to(root)
        except ValueError as error:
            raise ValueError("SOURCE_BATCH_PATH_REJECTED") from error
        if path.stat().st_size > max_file_bytes:
            raise ValueError("SOURCE_BATCH_FILE_SIZE_LIMIT_EXCEEDED")
        paths.append(path)
    if not paths:
        raise ValueError("SOURCE_BATCH_EMPTY")
    files = {
        str(path.relative_to(batch_dir)): sha256_file(path)
        for path in sorted(paths, key=lambda item: str(item.relative_to(batch_dir)).encode("utf-8"))
    }
    fingerprint = sha256_bytes(canonical_json(files).encode("utf-8"))
    if fingerprint != expected_fingerprint:
        raise ValueError("SOURCE_BATCH_FILES_FINGERPRINT_DRIFT")
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


def _group_map(groups: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    if isinstance(groups, Mapping):
        return dict(groups)
    return {str(item["id"]): item for item in groups}


def select_formal_members(
    records: Sequence[Mapping[str, Any]],
    groups: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    group_by_id = _group_map(groups)
    seen: set[str] = set()
    accepted: list[dict[str, Any]] = []
    totals = Counter({status: 0 for status in STATUSES})
    by_group: dict[str, Counter[str]] = {group_id: Counter({status: 0 for status in STATUSES}) for group_id in group_by_id}
    for raw in records:
        record = dict(raw)
        group_id = str(record.get("group") or "")
        if group_id not in group_by_id:
            raise ValueError("UNKNOWN_GROUP")
        member_id = str(record.get("member_id") or "")
        if not member_id or member_id in seen:
            raise ValueError("DUPLICATE_MEMBER")
        seen.add(member_id)
        status_value = str(record.get("status") or "")
        if status_value not in STATUSES:
            raise ValueError("MEMBER_STATUS_INVALID")
        totals[status_value] += 1
        by_group[group_id][status_value] += 1
        if status_value != "已证明":
            continue
        expected = group_by_id[group_id]
        if record.get("contract") != expected.get("contract") or record.get("dataset") != expected.get("dataset"):
            raise ValueError("MEMBER_IDENTITY_DRIFT")
        content_sha = record.get("content_sha256")
        if not isinstance(content_sha, str) or SHA_PATTERN.fullmatch(content_sha) is None:
            raise ValueError("MEMBER_SHA_INVALID")
        record["underlying"] = expected["underlying"]
        accepted.append(record)
    accepted.sort(
        key=lambda item: (
            str(item["underlying"]),
            str(item["contract"]),
            str(item["dataset"]),
            _member_date(str(item["relative_name"])),
            str(item["relative_name"]).encode("utf-8"),
            str(item["content_sha256"]),
        )
    )
    summary = {
        "totals": {"candidate_total": len(records), **{status: totals[status] for status in STATUSES}},
        "groups": {
            group_id: {"candidate_total": sum(counts.values()), **{status: counts[status] for status in STATUSES}}
            for group_id, counts in sorted(by_group.items())
        },
    }
    if len(records) != sum(summary["totals"][status] for status in STATUSES):
        raise ValueError("COUNTER_CONSERVATION_FAILED")
    return accepted, summary


def _member_date(name: str) -> str:
    match = DATE_PATTERN.search(name)
    if match is None:
        raise ValueError("MEMBER_NAME_INVALID")
    datetime.strptime(match.group(1), "%Y-%m-%d")
    return match.group(1)


def assert_no_symlink_components(path: Path, *, stop: Path | None = None) -> None:
    """拒绝目标自身及从固定根到目标之间的任一级符号链接。"""

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
    expected_prefix = f"{group['contract']}-{group['dataset']}-"
    if not relative_name.startswith(expected_prefix):
        raise ValueError("PATH_REJECTED")
    assert_no_symlink_components(root)
    root_resolved = root.resolve(strict=True)
    group_root = root / str(group["relative_dir"])
    assert_no_symlink_components(group_root, stop=root)
    if group_root.is_symlink() or not group_root.is_dir():
        raise ValueError("GROUP_ROOT_INVALID")
    path = group_root / relative_name
    if path.is_symlink() or not path.is_file():
        raise ValueError("SOURCE_FILE_INVALID")
    try:
        path.resolve(strict=True).relative_to(root_resolved)
    except ValueError as error:
        raise ValueError("PATH_REJECTED") from error
    return path


def verify_file_identity(
    root: Path,
    group: Mapping[str, Any],
    member: Mapping[str, Any],
    *,
    max_file_bytes: int | None = None,
) -> Path:
    path = resolve_member_path(root, group, member)
    info = path.stat()
    if max_file_bytes is not None and info.st_size > max_file_bytes:
        raise ValueError("SOURCE_FILE_SIZE_LIMIT_EXCEEDED")
    if info.st_size != member.get("size_bytes"):
        raise ValueError("FILE_SIZE_DRIFT")
    if sha256_file(path) != member.get("content_sha256"):
        raise ValueError("CONTENT_SHA_DRIFT")
    return path


def normalize_event_time_ms(value: str) -> int:
    if not value.isdigit():
        raise ValueError("EVENT_TIME_INVALID")
    number = int(value)
    if len(value) == 16:
        number //= 1000
    elif len(value) != 13:
        raise ValueError("EVENT_TIME_PRECISION_INVALID")
    return number


def _parse_boundary_line(line: bytes, dataset: str) -> tuple[int, int]:
    try:
        row = next(csv.reader(io.StringIO(line.decode("utf-8"))))
    except (UnicodeError, csv.Error, StopIteration) as error:
        raise ValueError("CSV_BOUNDARY_INVALID") from error
    expected_columns, time_index = (6, 4) if dataset == "trades" else (7, 5) if dataset == "aggTrades" else (0, -1)
    if len(row) != expected_columns:
        raise ValueError("CSV_SCHEMA_INVALID")
    return normalize_event_time_ms(row[time_index].strip()), len(row)


def _stream_boundaries(
    stream: Any, chunk_bytes: int, *, skip_header: bool = False
) -> tuple[bytes, bytes, int, int]:
    if chunk_bytes < 64 or chunk_bytes > 1024 * 1024:
        raise ValueError("STREAM_CHUNK_INVALID")
    pending = b""
    first: bytes | None = None
    last: bytes | None = None
    rows = 0
    total_bytes = 0
    header_pending = skip_header
    while chunk := stream.read(chunk_bytes):
        total_bytes += len(chunk)
        parts = (pending + chunk).split(b"\n")
        pending = parts.pop()
        if len(pending) > 1024 * 1024:
            raise ValueError("CSV_LINE_LIMIT_EXCEEDED")
        for line in parts:
            normalized = line.rstrip(b"\r")
            if not normalized:
                continue
            if header_pending:
                header_pending = False
                continue
            if first is None:
                first = normalized
            last = normalized
            rows += 1
    normalized = pending.rstrip(b"\r")
    if normalized:
        if header_pending:
            normalized = b""
            header_pending = False
    if normalized:
        if first is None:
            first = normalized
        last = normalized
        rows += 1
    if first is None or last is None or rows == 0:
        raise ValueError("CSV_EMPTY")
    return first, last, rows, total_bytes


def inspect_formal_member(
    root: Path,
    group: Mapping[str, Any],
    member: Mapping[str, Any],
    chunk_bytes: int,
    max_file_bytes: int | None = None,
) -> dict[str, Any]:
    path = verify_file_identity(
        root,
        group,
        member,
        max_file_bytes=max_file_bytes,
    )
    expected_csv = Path(str(member["relative_name"])).stem + ".csv"
    try:
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            if len(items) != 1:
                raise ValueError("ZIP_MEMBER_INVALID")
            item = items[0]
            pure = PurePosixPath(item.filename)
            if item.is_dir() or item.filename != expected_csv or pure.is_absolute() or ".." in pure.parts or len(pure.parts) != 1:
                raise ValueError("ZIP_MEMBER_INVALID")
            with archive.open(item, "r") as stream:
                first, last, rows, uncompressed_bytes = _stream_boundaries(
                    stream,
                    chunk_bytes,
                    skip_header=bool(member.get("schema", {}).get("header_present")),
                )
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ValueError("ZIP_READ_FAILED") from error
    first_ms, first_columns = _parse_boundary_line(first, str(group["dataset"]))
    last_ms, last_columns = _parse_boundary_line(last, str(group["dataset"]))
    date_value = datetime.strptime(_member_date(str(member["relative_name"])), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    start_ms = int(date_value.timestamp() * 1000)
    end_ms = int((date_value + timedelta(days=1)).timestamp() * 1000)
    if not (start_ms <= first_ms < end_ms and start_ms <= last_ms < end_ms and first_ms <= last_ms):
        raise ValueError("EVENT_TIME_DATE_BOUNDARY_INVALID")
    return {
        "member_id": member["member_id"],
        "group": member["group"],
        "underlying": group["underlying"],
        "contract": group["contract"],
        "dataset": group["dataset"],
        "relative_name": member["relative_name"],
        "content_sha256": member["content_sha256"],
        "schema_version": member["schema"]["schema_version"],
        "event_date": _member_date(str(member["relative_name"])),
        "status": "已观察",
        "first_event_time_ms": first_ms,
        "last_event_time_ms": last_ms,
        "column_count": first_columns,
        "last_column_count": last_columns,
        "row_count": rows,
        "uncompressed_bytes": uncompressed_bytes,
        "inspection_scope": "全量解压流读取；仅解析首末有效记录，未执行逐行业务质量验证",
    }


def build_gate_leaves(
    *, accepted_counts: Mapping[str, int], observations: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    for underlying in ("BTC", "ETH"):
        source_count = int(accepted_counts.get(underlying, 0))
        observed = int((observations.get(underlying) or {}).get("observed", 0))
        group_refs = (
            ["coverage.json#/BTCUSDT-trades", "coverage.json#/BTCUSDT-aggTrades"]
            if underlying == "BTC"
            else ["coverage.json#/ETHUSDT-trades"]
        )
        formal_ref = f"formal-input-*.json#/underlying={underlying}"
        observation_ref = f"member-observations-*.json#/underlying={underlying}"
        for horizon in (4, 8, 24, 48):
            gates = {
                "来源身份": {
                    "status": "通过" if source_count > 0 else "无法判定",
                    "reason_code": "FORMAL_SOURCE_IDENTITY_BOUND" if source_count > 0 else "FORMAL_SOURCE_EMPTY",
                    "evidence_refs": ["source-batch-files.json#/", formal_ref],
                    "release_conditions": ["来源批次文件集合、正式输入成员SHA与固定指纹持续全等"],
                },
                "三类时间": {
                    "status": "无法判定",
                    "reason_code": "ARRIVAL_AND_CAPTURE_TIME_MISSING",
                    "evidence_refs": [observation_ref],
                    "release_conditions": ["同一正式输入版本逐成员补齐事件时间、到达时间和采集时间并验证可见性"],
                },
                "质量": {
                    "status": "无法判定",
                    "reason_code": "FULL_ROW_QUALITY_NOT_AUDITED",
                    "evidence_refs": [observation_ref, *group_refs],
                    "release_conditions": ["同一正式输入版本完成逐行断档、重复、乱序、Schema和异常值质量审计"],
                },
                "历史重放": {
                    "status": "无法判定",
                    "reason_code": "REPLAY_EVIDENCE_NOT_COMPATIBLE",
                    "evidence_refs": ["summary.json#/remaining_blockers/2"],
                    "release_conditions": ["以同一正式输入和三类时间规则完成无时间穿越的历史现场重放"],
                },
                "成本与执行": {
                    "status": "无法判定",
                    "reason_code": "COST_EXECUTION_DATA_MISSING",
                    "evidence_refs": ["summary.json#/remaining_blockers/3"],
                    "release_conditions": ["同版本补齐手续费、价差、深度、冲击、资金费率和执行延迟证据"],
                },
                "血缘": {
                    "status": "通过" if source_count > 0 and observed == source_count else "无法判定",
                    "reason_code": "CONTENT_ADDRESSED_LINEAGE" if source_count > 0 and observed == source_count else "LINEAGE_INCOMPLETE",
                    "evidence_refs": ["source-batch-files.json#/", formal_ref, observation_ref],
                    "release_conditions": ["来源批次、正式输入、观察成员和内容SHA的一对一血缘持续闭合"],
                },
                "容量": {
                    "status": "无法判定",
                    "reason_code": "RESEARCH_PIPELINE_CAPACITY_NOT_PROVEN",
                    "evidence_refs": ["summary.json#/resource_facts"],
                    "release_conditions": ["在隔离研究流水线上完成同版本容量试采并满足资源预算"],
                },
                "恢复": {
                    "status": "无法判定",
                    "reason_code": "ISOLATED_RECOVERY_NOT_PROVEN",
                    "evidence_refs": ["summary.json#/remaining_blockers/4"],
                    "release_conditions": ["完成隔离故障注入、幂等重启和不可变输出恢复验证"],
                },
            }
            decision = "通过" if all(item["status"] == "通过" for item in gates.values()) else "阻塞"
            leaves.append(
                {
                    "underlying": underlying,
                    "venue": "Binance",
                    "market_type": "USDⓈ-M合约",
                    "horizon_hours": horizon,
                    "post_event_observation_minutes": [15, 60],
                    "formal_member_count": source_count,
                    "observed_member_count": observed,
                    "gates": gates,
                    "decision": decision,
                }
            )
    return leaves


def atomic_publish(
    root: Path,
    batch_id: str,
    files: Mapping[str, str],
    *,
    max_file_bytes: int,
    max_total_bytes: int,
    before_rename: Callable[[], None] | None = None,
) -> Path:
    encoded = {name: content.encode("utf-8") for name, content in files.items()}
    if any(len(content) > max_file_bytes for content in encoded.values()):
        raise ValueError("OUTPUT_FILE_LIMIT_EXCEEDED")
    if sum(map(len, encoded.values())) > max_total_bytes:
        raise ValueError("OUTPUT_TOTAL_LIMIT_EXCEEDED")
    root.mkdir(parents=True, exist_ok=True)
    target = root / batch_id
    if target.exists():
        raise FileExistsError(batch_id)
    temporary = Path(tempfile.mkdtemp(prefix=f".{batch_id}.", dir=root))
    try:
        for relative, content in sorted(encoded.items()):
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        if before_rename is not None:
            before_rename()
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target


def inventory_fingerprint(paths: Sequence[Path], root: Path, limit: int) -> tuple[str, int]:
    rows: list[dict[str, Any]] = []

    def append(path: Path, kind: str, size: int = 0, mtime_ns: int = 0) -> None:
        if len(rows) >= limit:
            raise ValueError("INVENTORY_ENTRY_LIMIT_EXCEEDED")
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            relative = str(path)
        rows.append({"path": relative, "kind": kind, **({"size": size, "mtime_ns": mtime_ns} if kind != "missing" else {})})

    for parent in paths:
        assert_no_symlink_components(parent, stop=root)
        if not parent.exists() and not parent.is_symlink():
            append(parent, "missing")
            continue
        append_parent = True
        candidates: list[Path] = []
        if parent.is_dir() and not parent.is_symlink():
            with os.scandir(parent) as entries:
                for item in entries:
                    if len(rows) + 1 + len(candidates) >= limit:
                        raise ValueError("INVENTORY_ENTRY_LIMIT_EXCEEDED")
                    candidates.append(Path(item.path))
            candidates.sort(key=lambda item: item.name.encode("utf-8"))
        if append_parent:
            candidates.insert(0, parent)
        for path in candidates:
            info = path.lstat()
            kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
            append(path, kind, info.st_size, info.st_mtime_ns)
    return sha256_bytes(canonical_json(rows).encode("utf-8")), len(rows)


def _memory_available_percent() -> float:
    try:
        output = subprocess.run(
            ["/usr/bin/memory_pressure", "-Q"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
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
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        if total > 0 and 0 <= available <= total:
            return available * 100.0 / total
    except (OSError, UnicodeError, ValueError):
        pass
    return 0.0


def _process_max_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _resource_snapshot(output_root: Path, source_root: Path) -> dict[str, Any]:
    return {
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "memory_available_percent": _memory_available_percent(),
        "output_disk_free_bytes": shutil.disk_usage(output_root.parent if not output_root.exists() else output_root).free,
        "source_disk_free_bytes": shutil.disk_usage(source_root).free,
        "process_max_rss_bytes": _process_max_rss_bytes(),
    }


def assert_resource_limits(snapshot: Mapping[str, Any], limits: Mapping[str, Any]) -> None:
    if float(snapshot["memory_available_percent"]) < float(limits["min_available_memory_percent"]):
        raise ValueError("MEMORY_HEADROOM_INSUFFICIENT")
    if int(snapshot["output_disk_free_bytes"]) < int(limits["min_free_disk_bytes"]):
        raise ValueError("DISK_HEADROOM_INSUFFICIENT")
    if int(snapshot["process_max_rss_bytes"]) > int(limits["memory_bytes"]):
        raise ValueError("PROCESS_MEMORY_LIMIT_EXCEEDED")


def assert_time_limit(started: float, limits: Mapping[str, Any]) -> None:
    if time.monotonic() - started > float(limits["total_seconds"]):
        raise TimeoutError("TOTAL_TIME_LIMIT_EXCEEDED")


def _compact_member(member: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "member_id": member["member_id"],
        "group": member["group"],
        "underlying": member["underlying"],
        "contract": member["contract"],
        "dataset": member["dataset"],
        "relative_name": member["relative_name"],
        "content_sha256": member["content_sha256"],
        "size_bytes": member["size_bytes"],
        "schema_version": member["schema"]["schema_version"],
    }


def _json_shards(records: Sequence[Mapping[str, Any]], prefix: str, max_bytes: int) -> dict[str, str]:
    files: dict[str, str] = {}
    current: list[str] = []
    current_bytes = 2
    index = 1
    for record in records:
        encoded = canonical_json(record)
        encoded_bytes = len(encoded.encode("utf-8"))
        separator_bytes = 1 if current else 0
        if current and current_bytes + separator_bytes + encoded_bytes + 1 > max_bytes:
            files[f"{prefix}-{index:03d}.json"] = "[" + ",".join(current) + "]\n"
            index += 1
            current = []
            current_bytes = 2
            separator_bytes = 0
        if current_bytes + separator_bytes + encoded_bytes + 1 > max_bytes:
            raise ValueError("OUTPUT_RECORD_LIMIT_EXCEEDED")
        current.append(encoded)
        current_bytes += separator_bytes + encoded_bytes
    if current:
        files[f"{prefix}-{index:03d}.json"] = "[" + ",".join(current) + "]\n"
    return files


def _coverage(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for item in observations:
        grouped.setdefault(str(item["group"]), []).append(item)
    result: dict[str, Any] = {}
    for group_id, rows in sorted(grouped.items()):
        dates = sorted({str(item["event_date"]) for item in rows})
        start = datetime.strptime(dates[0], "%Y-%m-%d").date()
        end = datetime.strptime(dates[-1], "%Y-%m-%d").date()
        expected = {(start + timedelta(days=index)).isoformat() for index in range((end - start).days + 1)}
        result[group_id] = {
            "observed": len(rows),
            "date_start": dates[0],
            "date_end": dates[-1],
            "unique_dates": len(dates),
            "missing_date_count": len(expected - set(dates)),
            "missing_dates": sorted(expected - set(dates)),
            "rows": sum(int(item["row_count"]) for item in rows),
            "uncompressed_bytes": sum(int(item["uncompressed_bytes"]) for item in rows),
        }
    return result


def run(config_path: Path, repo_root: Path, output_root: Path, batch_id: str) -> Path:
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expected_config_path = (repo_root / EXPECTED_CONFIG_RELATIVE_PATH).resolve()
    expected_output_root = (repo_root / EXPECTED_OUTPUT_RELATIVE_PATH).resolve()
    if config_path.resolve() != expected_config_path:
        raise ValueError("CONFIG_PATH_INVALID")
    if output_root.resolve() != expected_output_root:
        raise ValueError("OUTPUT_PATH_INVALID")
    config = load_config(config_path)
    limits = config["limits"]
    batch_dir = repo_root / config["source_batch_dir"]
    source_batch_files = verify_source_batch_files(
        batch_dir,
        expected_fingerprint=config["source_batch_files_fingerprint"],
        max_files=limits["source_member_count"],
        max_file_bytes=limits["single_source_file_bytes"],
    )
    summary_path = batch_dir / "summary.json"
    if sha256_file(summary_path) != config["source_summary_sha256"]:
        raise ValueError("SOURCE_SUMMARY_SHA_DRIFT")
    source_summary = load_json(summary_path)
    if source_summary.get("batch_id") != config["source_batch_id"] or source_summary.get("totals", {}).get("已证明") != 5180:
        raise ValueError("SOURCE_BATCH_IDENTITY_INVALID")
    records = load_source_records(batch_dir, limits["source_member_count"])
    groups = _group_map(config["groups"])
    accepted, denominator = select_formal_members(records, groups)
    if len(accepted) != 5180 or denominator["totals"].get("拒绝") != 207:
        raise ValueError("SOURCE_DENOMINATOR_DRIFT")

    source_root = Path(config["local_root"])
    assert_no_symlink_components(source_root)
    inventory_paths = [source_root / item["relative_dir"] for item in config["groups"]]
    inventory_paths.extend(source_root / value for value in config["observations"])
    inventory_paths.extend(source_root / value for value in config["manifests"])
    before_fingerprint, inventory_count = inventory_fingerprint(inventory_paths, source_root, limits["inventory_entry_count"])
    if before_fingerprint != source_summary["source_inventory_before_sha256"]:
        raise ValueError("SOURCE_INVENTORY_BASELINE_DRIFT")
    start_snapshot = _resource_snapshot(output_root, source_root)
    assert_resource_limits(start_snapshot, limits)

    observations: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, member in enumerate(accepted, start=1):
        try:
            observations.append(
                inspect_formal_member(
                    source_root,
                    groups[str(member["group"])],
                    member,
                    limits["stream_chunk_bytes"],
                    limits["single_source_file_bytes"],
                )
            )
        except (OSError, ValueError) as error:
            failures.append({
                "member_id": member["member_id"],
                "group": member["group"],
                "underlying": member["underlying"],
                "relative_name": member["relative_name"],
                "status": "失败",
                "reason_code": str(error),
            })
        if index % 50 == 0 or index == len(accepted):
            print(f"正式输入观察: {index}/{len(accepted)}，失败={len(failures)}", file=sys.stderr, flush=True)
            snapshot = _resource_snapshot(output_root, source_root)
            assert_resource_limits(snapshot, limits)
            assert_time_limit(started, limits)

    after_fingerprint, after_count = inventory_fingerprint(inventory_paths, source_root, limits["inventory_entry_count"])
    if before_fingerprint != after_fingerprint or inventory_count != after_count:
        raise ValueError("SOURCE_INVENTORY_DRIFT")
    formal = [_compact_member(item) for item in accepted]
    coverage = _coverage(observations) if observations else {}
    accepted_counts = Counter(item["underlying"] for item in formal)
    observed_counts = Counter(item["underlying"] for item in observations)
    leaves = build_gate_leaves(
        accepted_counts=accepted_counts,
        observations={key: {"observed": value} for key, value in observed_counts.items()},
    )
    completed_snapshot = _resource_snapshot(output_root, source_root)
    assert_resource_limits(completed_snapshot, limits)
    compact_rejected = [
        {
            "member_id": item["member_id"],
            "group": item["group"],
            "relative_name": item["relative_name"],
            "status": item["status"],
            "reason_codes": item.get("reason_codes", []),
        }
        for item in records
        if item["status"] != "已证明"
    ]
    del accepted
    del records
    summary = {
        "schema_version": "zhishi-stage1-candidate-recompute-batch/v1",
        "task_id": "000093",
        "batch_id": batch_id,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_batch_id": source_summary["batch_id"],
        "source_summary_sha256": sha256_file(summary_path),
        "source_batch_files_fingerprint": sha256_bytes(canonical_json(source_batch_files).encode("utf-8")),
        "formal_input_fingerprint": sha256_bytes(canonical_json(formal).encode("utf-8")),
        "config_sha256": sha256_file(config_path),
        "executor_sha256": sha256_file(Path(__file__).resolve()),
        "task_contract_sha256": sha256_file(repo_root / "docs/研发中心/任务/任务-000093.md"),
        "source_inventory_before_sha256": before_fingerprint,
        "source_inventory_after_sha256": after_fingerprint,
        "source_inventory_entry_count": inventory_count,
        "denominator": denominator,
        "formal_member_count": len(formal),
        "observed_member_count": len(observations),
        "inspection_failure_count": len(failures),
        "observation_item_count": len(source_summary.get("observation_items", [])),
        "leaf_count": len(leaves),
        "allowed_research_leaf_count": sum(item["decision"] == "通过" for item in leaves),
        "stage1_complete": all(item["decision"] == "通过" for item in leaves),
        "stage2_released": False,
        "legacy_task_000084_current_gate": False,
        "legacy_task_000084_modified": False,
        "source_data_modified": False,
        "source_root_symlink": source_root.is_symlink(),
        "source_path_symlink_policy": "固定根自身及根内相对路径每级均拒绝符号链接",
        "total_time_limit_checked_before_publish": True,
        "inspection_scope": "5180个正式输入逐文件内容SHA复验并全量解压流读取；仅解析首末有效记录，未执行逐行业务质量验证",
        "remaining_blockers": [
            "到达时间与采集时间缺失",
            "逐行断档、重复、乱序与异常质量未证明",
            "同版本历史重放证据缺失",
            "手续费、价差、深度、冲击、资金费率与延迟证据缺失",
            "研究流水线容量与隔离恢复未证明",
        ],
        "resource_facts": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "processes": 1,
            "start": start_snapshot,
            "completed": completed_snapshot,
        },
    }
    files: dict[str, str] = {
        "summary.json": json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "coverage.json": json.dumps(coverage, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "leaves.json": json.dumps(leaves, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "rejected-source-members.json": canonical_json(compact_rejected) + "\n",
        "inspection-failures.json": canonical_json(failures) + "\n",
        "source-batch-files.json": canonical_json(source_batch_files) + "\n",
    }
    files.update(_json_shards(formal, "formal-input", limits["output_file_bytes"] - 1024))
    files.update(_json_shards(observations, "member-observations", limits["output_file_bytes"] - 1024))
    prepublish_snapshot = _resource_snapshot(output_root, source_root)
    assert_resource_limits(prepublish_snapshot, limits)
    assert_time_limit(started, limits)
    summary["resource_facts"]["prepublish"] = prepublish_snapshot
    files["summary.json"] = json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n"

    def assert_publish_safe() -> None:
        assert_time_limit(started, limits)
        assert_resource_limits(_resource_snapshot(output_root, source_root), limits)

    target = atomic_publish(
        output_root,
        batch_id,
        files,
        max_file_bytes=limits["output_file_bytes"],
        max_total_bytes=limits["output_total_bytes"],
        before_rename=assert_publish_safe,
    )
    print(json.dumps({"batch_id": batch_id, "output": str(target), "summary": summary}, ensure_ascii=False), flush=True)
    return target


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config/审计/任务-000093阶段1新候选集重算.json"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/审计/阶段1新候选集重算"))
    parser.add_argument("--batch-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    config_path = args.config if args.config.is_absolute() else repo_root / args.config
    output_root = args.output_root if args.output_root.is_absolute() else repo_root / args.output_root
    if not re.fullmatch(r"stage1-candidate-recompute-[0-9TZ-]+-[0-9a-f]{12}", args.batch_id):
        raise SystemExit("BATCH_ID_INVALID")
    run(config_path, repo_root, output_root, args.batch_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
