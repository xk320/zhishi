#!/usr/bin/env python3
"""任务-000098：重放阶段1同版本数据资格决策。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import resource
import stat
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


EXPECTED_CONFIG_CANONICAL_SHA256 = "ef65e3cfc47d3a2f3befb6187736942b6475c93a284370054083c69bff250d34"
EXPECTED_CONFIG_RELATIVE_PATH = Path("config/审计/任务-000098阶段1同版本历史重放.json")
EXPECTED_OUTPUT_RELATIVE_PATH = Path("artifacts/审计/阶段1同版本历史重放")
SOURCE_SCHEMA = "zhishi-stage1-time-quality-audit-batch/v1"
REPLAY_SCHEMA = "zhishi-stage1-versioned-replay/v1"
SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TASK_CONTRACT_HEADER_PREFIXES = (
    "# 任务-000098：",
    "- 类型：",
    "- 阶段：",
    "- 优先级：",
    "- 执行方案：",
    "- 方案状态：",
    "- 执行授权：",
    "- 并行规则：",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_bytes):
                digest.update(chunk)
    except OSError as error:
        raise ValueError("SOURCE_FILE_READ_FAILED") from error
    return digest.hexdigest()


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def load_json_strict(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except ValueError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("JSON_INPUT_INVALID") from error


def parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("UTC_TIME_INVALID") from error
    if parsed.tzinfo != timezone.utc:
        raise ValueError("UTC_TIME_INVALID")
    return parsed


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
    body = "\n".join(header + [""] + lines[body_start:body_end]).rstrip() + "\n"
    return sha256_bytes(body.encode("utf-8"))


def load_config(path: Path) -> dict[str, Any]:
    config = load_json_strict(path)
    if not isinstance(config, dict):
        raise ValueError("CONFIG_INVALID")
    digest = sha256_bytes(canonical_json(config).encode("utf-8"))
    if digest != EXPECTED_CONFIG_CANONICAL_SHA256:
        raise ValueError("CONFIG_FINGERPRINT_INVALID")
    if config.get("schema_version") != "zhishi-stage1-versioned-replay-config/v1":
        raise ValueError("CONFIG_VERSION_INVALID")
    if config.get("task_id") != "000098":
        raise ValueError("CONFIG_TASK_INVALID")
    if config.get("main_horizons_hours") != [4, 8, 24, 48]:
        raise ValueError("CONFIG_HORIZONS_INVALID")
    if config.get("observation_windows_minutes") != [15, 60]:
        raise ValueError("CONFIG_OBSERVATION_WINDOWS_INVALID")
    if sorted(config.get("allowed_underlyings") or []) != ["BTC", "ETH"]:
        raise ValueError("CONFIG_UNDERLYINGS_INVALID")
    if sorted(config.get("allowed_datasets") or []) != ["aggTrades", "trades"]:
        raise ValueError("CONFIG_DATASETS_INVALID")
    expected_files = config.get("expected_source_files")
    if not isinstance(expected_files, dict) or len(expected_files) != 7:
        raise ValueError("CONFIG_SOURCE_FILES_INVALID")
    if not all(isinstance(key, str) and isinstance(value, str) and SHA_PATTERN.fullmatch(value) for key, value in expected_files.items()):
        raise ValueError("CONFIG_SOURCE_FILES_INVALID")
    decision_at = parse_utc(config.get("decision_at"))
    completed_at = parse_utc(config.get("source_completed_at"))
    if decision_at.replace(microsecond=0) != completed_at or decision_at.microsecond != 999999:
        raise ValueError("CONFIG_DECISION_BOUNDARY_INVALID")
    return config


def _ordinary_json_files(batch_dir: Path, max_files: int, max_file_bytes: int) -> dict[str, Path]:
    if batch_dir.is_symlink() or not batch_dir.is_dir():
        raise ValueError("SOURCE_BATCH_DIR_INVALID")
    resolved = batch_dir.resolve(strict=True)
    files: dict[str, Path] = {}
    for path in batch_dir.iterdir():
        if len(files) >= max_files:
            raise ValueError("SOURCE_FILE_COUNT_LIMIT_EXCEEDED")
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError("SOURCE_FILE_IDENTITY_FAILED") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or path.suffix != ".json":
            raise ValueError("SOURCE_FILE_INVALID")
        if metadata.st_size > max_file_bytes:
            raise ValueError("SOURCE_FILE_SIZE_LIMIT_EXCEEDED")
        try:
            path.resolve(strict=True).relative_to(resolved)
        except ValueError as error:
            raise ValueError("SOURCE_PATH_REJECTED") from error
        files[path.name] = path
    return files


def verify_source_files(batch_dir: Path, config: Mapping[str, Any]) -> dict[str, str]:
    limits = config["limits"]
    paths = _ordinary_json_files(
        batch_dir,
        int(limits["max_source_file_count"]),
        int(limits["max_source_file_bytes"]),
    )
    expected = dict(config["expected_source_files"])
    if set(paths) != set(expected):
        raise ValueError("SOURCE_FILE_SET_DRIFT")
    actual = {name: sha256_file(paths[name]) for name in sorted(paths, key=lambda value: value.encode("utf-8"))}
    if actual != expected:
        raise ValueError("SOURCE_FILE_SHA_DRIFT")
    fingerprint = sha256_bytes(canonical_json(actual).encode("utf-8"))
    if fingerprint != config["source_batch_files_fingerprint"]:
        raise ValueError("SOURCE_BATCH_FINGERPRINT_DRIFT")
    return actual


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


def validate_members(
    members: Sequence[Mapping[str, Any]], config: Mapping[str, Any], decision_at: datetime
) -> dict[str, Any]:
    limits = config["limits"]
    if len(members) > int(limits["max_member_count"]):
        raise ValueError("MEMBER_COUNT_LIMIT_EXCEEDED")
    groups = config["allowed_groups"]
    seen: set[str] = set()
    status_counts: Counter[str] = Counter()
    group_counts: dict[str, Counter[str]] = {group: Counter() for group in groups}
    row_count = 0
    byte_count = 0
    order: list[str] = []
    for raw in members:
        member = dict(raw)
        member_id = member.get("member_id")
        if not isinstance(member_id, str) or not member_id or member_id in seen:
            raise ValueError("DUPLICATE_MEMBER")
        seen.add(member_id)
        group_id = member.get("group")
        if group_id not in groups:
            raise ValueError("UNKNOWN_GROUP")
        expected = groups[group_id]
        for field in ("underlying", "contract", "dataset"):
            if member.get(field) != expected[field]:
                raise ValueError("MEMBER_GROUP_IDENTITY_DRIFT")
        if not isinstance(member.get("event_date"), str) or not DATE_PATTERN.fullmatch(member["event_date"]):
            raise ValueError("MEMBER_EVENT_DATE_INVALID")
        if not isinstance(member.get("member_identity_sha256"), str) or not SHA_PATTERN.fullmatch(member["member_identity_sha256"]):
            raise ValueError("MEMBER_IDENTITY_SHA_INVALID")
        for field in ("source_visible_at", "collected_at"):
            if parse_utc(member.get(field)) > decision_at:
                raise ValueError("FUTURE_VISIBLE_MEMBER")
        status_value = member.get("status")
        if status_value not in ("已证明", "拒绝"):
            raise ValueError("MEMBER_STATUS_INVALID")
        if not isinstance(member.get("row_count"), int) or member["row_count"] < 0:
            raise ValueError("MEMBER_ROW_COUNT_INVALID")
        if not isinstance(member.get("uncompressed_bytes"), int) or member["uncompressed_bytes"] < 0:
            raise ValueError("MEMBER_BYTE_COUNT_INVALID")
        status_counts[str(status_value)] += 1
        group_counts[str(group_id)][str(status_value)] += 1
        row_count += member["row_count"]
        byte_count += member["uncompressed_bytes"]
        order.append(member_id)
    expected_counts = config["expected_counts"]
    if len(members) != int(expected_counts["audited_member_count"]):
        raise ValueError("FORMAL_MEMBER_COUNT_DRIFT")
    if status_counts != Counter({
        "已证明": int(expected_counts["quality_proved_count"]),
        "拒绝": int(expected_counts["quality_rejected_count"]),
    }):
        raise ValueError("QUALITY_STATUS_COUNT_DRIFT")
    if row_count != int(expected_counts["scanned_row_count"]) or byte_count != int(expected_counts["uncompressed_bytes"]):
        raise ValueError("MEMBER_TOTALS_DRIFT")
    group_summary: dict[str, Any] = {}
    for group_id, expected in groups.items():
        counts = group_counts[group_id]
        if sum(counts.values()) != expected["formal_member_count"]:
            raise ValueError("GROUP_FORMAL_COUNT_DRIFT")
        if counts["已证明"] != expected["quality_proved_count"] or counts["拒绝"] != expected["quality_rejected_count"]:
            raise ValueError("GROUP_STATUS_COUNT_DRIFT")
        group_summary[group_id] = {
            "formal_member_count": sum(counts.values()),
            "quality_proved_count": counts["已证明"],
            "quality_rejected_count": counts["拒绝"],
        }
    stable_order = sorted(order, key=lambda value: value.encode("utf-8"))
    return {
        "formal_member_count": len(members),
        "member_order_sha256": sha256_bytes(canonical_json(stable_order).encode("utf-8")),
        "quality_proved_count": status_counts["已证明"],
        "quality_rejected_count": status_counts["拒绝"],
        "scanned_row_count": row_count,
        "uncompressed_bytes": byte_count,
        "groups": group_summary,
    }


def update_replay_gate(leaves: Any, config: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(leaves, list) or len(leaves) != int(config["expected_counts"]["leaf_count"]):
        raise ValueError("LEAF_COUNT_DRIFT")
    expected_keys = {
        (underlying, horizon)
        for underlying in config["allowed_underlyings"]
        for horizon in config["main_horizons_hours"]
    }
    actual_keys: set[tuple[Any, Any]] = set()
    updated: list[dict[str, Any]] = []
    for raw in leaves:
        if not isinstance(raw, dict) or not isinstance(raw.get("gates"), dict):
            raise ValueError("LEAF_INVALID")
        leaf = copy.deepcopy(raw)
        key = (leaf.get("underlying"), leaf.get("horizon_hours"))
        if key in actual_keys or key not in expected_keys:
            raise ValueError("LEAF_IDENTITY_DRIFT")
        actual_keys.add(key)
        for passed_gate in ("来源身份", "三类时间", "质量", "血缘"):
            if leaf["gates"].get(passed_gate, {}).get("status") != "通过":
                raise ValueError("UPSTREAM_GATE_DRIFT")
        for blocked_gate in ("成本与执行", "容量", "恢复"):
            if leaf["gates"].get(blocked_gate, {}).get("status") != "无法判定":
                raise ValueError("BLOCKED_GATE_DRIFT")
        if leaf["gates"].get("历史重放", {}).get("status") != "无法判定":
            raise ValueError("REPLAY_GATE_BASELINE_DRIFT")
        leaf["gates"]["历史重放"] = {
            "evidence_refs": ["replay-first.json#/", "replay-second.json#/"],
            "reason_code": "SAME_VERSION_DATA_ELIGIBILITY_DECISION_REPLAYED",
            "release_conditions": ["同一任务-000094版本、历史可见集和规范输出持续逐字节全等"],
            "status": "通过",
        }
        leaf["decision"] = "阻塞"
        updated.append(leaf)
    if actual_keys != expected_keys:
        raise ValueError("LEAF_IDENTITY_DRIFT")
    return sorted(updated, key=lambda leaf: (leaf["underlying"], leaf["horizon_hours"]))


def _validate_summary(summary: Any, config: Mapping[str, Any]) -> None:
    if not isinstance(summary, dict) or summary.get("schema_version") != SOURCE_SCHEMA:
        raise ValueError("SOURCE_SUMMARY_VERSION_DRIFT")
    exact = {
        "batch_id": config["source_batch_id"],
        "completed_at": config["source_completed_at"],
        "formal_member_count": config["expected_counts"]["audited_member_count"],
        "source_rejected_count": config["expected_counts"]["source_rejected_count"],
        "segment_count": config["expected_counts"]["segment_count"],
        "leaf_count": config["expected_counts"]["leaf_count"],
        "observation_item_count": config["expected_counts"]["observation_item_count"],
        "scanned_row_count": config["expected_counts"]["scanned_row_count"],
        "uncompressed_bytes": config["expected_counts"]["uncompressed_bytes"],
        "output_payload_fingerprint": "c9cef13395b3f777854d29736e8f9755af6dcaf40ec640a197bc77afdd79a98c",
        "formal_input_fingerprint": "a1c69d6e2446c364578edb08e6b6fa30912f2e5577d7e51377ef8ab4c648952d",
    }
    for key, expected in exact.items():
        if summary.get(key) != expected:
            raise ValueError("SOURCE_SUMMARY_FACT_DRIFT")
    if summary.get("status_counts") != {"失效": 0, "失败": 0, "已证明": 4789, "拒绝": 391, "无法判定": 0, "未成熟": 0}:
        raise ValueError("SOURCE_SUMMARY_STATUS_DRIFT")
    if summary.get("stage1_complete") is not False or summary.get("stage2_released") is not False:
        raise ValueError("SOURCE_RELEASE_STATE_DRIFT")


def replay_once(repo_root: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    source_dir = repo_root / str(config["source_batch_relative_path"])
    source_files = verify_source_files(source_dir, config)
    summary = load_json_strict(source_dir / "summary.json")
    _validate_summary(summary, config)
    members = decode_record_table(load_json_strict(source_dir / "members-001.json"))
    member_facts = validate_members(members, config, parse_utc(config["decision_at"]))

    source_rejected = load_json_strict(source_dir / "source-rejected.json")
    if not isinstance(source_rejected, list) or len(source_rejected) != config["expected_counts"]["source_rejected_count"]:
        raise ValueError("SOURCE_REJECTED_COUNT_DRIFT")
    rejected_ids = [item.get("member_id") for item in source_rejected if isinstance(item, dict)]
    if len(rejected_ids) != len(source_rejected) or any(not isinstance(value, str) or not value for value in rejected_ids):
        raise ValueError("SOURCE_REJECTED_ID_INVALID")
    if len(set(rejected_ids)) != len(rejected_ids):
        raise ValueError("SOURCE_REJECTED_DUPLICATE")
    if set(rejected_ids) & {item["member_id"] for item in members}:
        raise ValueError("SOURCE_REJECTED_FORMAL_OVERLAP")

    segments = load_json_strict(source_dir / "segments.json")
    if not isinstance(segments, list) or len(segments) != config["expected_counts"]["segment_count"]:
        raise ValueError("SEGMENT_COUNT_DRIFT")
    for segment in segments:
        if not isinstance(segment, dict) or segment.get("group") not in config["allowed_groups"]:
            raise ValueError("SEGMENT_IDENTITY_DRIFT")
        group = config["allowed_groups"][segment["group"]]
        if any(segment.get(field) != group[field] for field in ("underlying", "contract", "dataset")):
            raise ValueError("SEGMENT_IDENTITY_DRIFT")
        if not isinstance(segment.get("day_count"), int) or segment["day_count"] <= 0:
            raise ValueError("SEGMENT_DAY_COUNT_INVALID")

    leaves = update_replay_gate(load_json_strict(source_dir / "leaves.json"), config)
    candidate_total = len(members) + len(source_rejected)
    if candidate_total != config["expected_counts"]["candidate_total"]:
        raise ValueError("CANDIDATE_TOTAL_DRIFT")
    repo_script = repo_root / "scripts/审计/重放阶段1同版本数据资格决策.py"
    contract_path = repo_root / "docs/数据/阶段1同版本历史重放合同.md"
    task_path = repo_root / "docs/研发中心/任务/任务-000098.md"
    config_path = repo_root / EXPECTED_CONFIG_RELATIVE_PATH
    decision_identity = {
        "config_sha256": sha256_file(config_path),
        "decision_at": config["decision_at"],
        "executor_sha256": sha256_file(repo_script),
        "formal_input_fingerprint": summary["formal_input_fingerprint"],
        "replay_contract_sha256": sha256_file(contract_path),
        "source_batch_files_fingerprint": config["source_batch_files_fingerprint"],
        "source_batch_id": config["source_batch_id"],
        "source_completed_at": config["source_completed_at"],
        "source_config_sha256": summary["config_sha256"],
        "source_executor_sha256": summary["executor_sha256"],
        "source_output_payload_fingerprint": summary["output_payload_fingerprint"],
        "source_scanner_sha256": summary["scanner_source_sha256"],
        "source_task_contract_sha256": summary["task_contract_sha256"],
        "task_000094_merge_commit": config["task_000094_merge_commit"],
        "task_contract_sha256": task_contract_sha256(task_path),
        "task_id": config["task_id"],
    }
    return {
        "counts": {
            "candidate_total": candidate_total,
            **{key: member_facts[key] for key in (
                "formal_member_count", "quality_proved_count", "quality_rejected_count",
                "scanned_row_count", "uncompressed_bytes",
            )},
            "observation_item_count": config["expected_counts"]["observation_item_count"],
            "segment_count": len(segments),
            "source_rejected_count": len(source_rejected),
        },
        "decision_identity": decision_identity,
        "groups": member_facts["groups"],
        "leaves": leaves,
        "main_horizons_hours": list(config["main_horizons_hours"]),
        "member_order_sha256": member_facts["member_order_sha256"],
        "observation_windows_minutes": list(config["observation_windows_minutes"]),
        "remaining_blockers": ["成本与执行证据缺失", "研究流水线容量证据缺失", "隔离恢复证据缺失"],
        "schema_version": REPLAY_SCHEMA,
        "segment_order_sha256": sha256_bytes(canonical_json(segments).encode("utf-8")),
        "source_files": source_files,
        "source_rejected_order_sha256": sha256_bytes(canonical_json(sorted(rejected_ids, key=lambda value: value.encode("utf-8"))).encode("utf-8")),
        "stage1_complete": False,
        "stage2_released": False,
    }


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _write_json(path: Path, value: Any) -> str:
    payload = canonical_json(value).encode("utf-8") + b"\n"
    path.write_bytes(payload)
    if path.read_bytes() != payload:
        raise ValueError("OUTPUT_READBACK_DRIFT")
    return sha256_bytes(payload)


def execute(repo_root: Path, output_root: Path, batch_id: str, config: Mapping[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    if not batch_id.startswith("stage1-versioned-replay-") or "/" in batch_id or ".." in batch_id:
        raise ValueError("BATCH_ID_INVALID")
    output_root.mkdir(parents=True, exist_ok=True)
    if output_root.is_symlink() or not output_root.is_dir():
        raise ValueError("OUTPUT_ROOT_INVALID")
    target = output_root / batch_id
    if target.exists() or target.is_symlink():
        raise ValueError("OUTPUT_BATCH_EXISTS")

    first = replay_once(repo_root, config)
    second = replay_once(repo_root, config)
    first_bytes = canonical_json(first).encode("utf-8") + b"\n"
    second_bytes = canonical_json(second).encode("utf-8") + b"\n"
    if first_bytes != second_bytes:
        raise ValueError("REPLAY_OUTPUT_DRIFT")
    first_sha = sha256_bytes(first_bytes)

    with tempfile.TemporaryDirectory(prefix=f".{batch_id}-", dir=output_root) as directory:
        temporary = Path(directory)
        output_files = {
            "decision.json": _write_json(temporary / "decision.json", first["decision_identity"]),
            "leaves.json": _write_json(temporary / "leaves.json", first["leaves"]),
            "replay-first.json": _write_json(temporary / "replay-first.json", first),
            "replay-second.json": _write_json(temporary / "replay-second.json", second),
        }
        elapsed = round(time.monotonic() - started, 6)
        output_bytes_without_summary = sum(path.stat().st_size for path in temporary.iterdir())
        summary = {
            "batch_id": batch_id,
            "counts": first["counts"],
            "first_replay_sha256": first_sha,
            "output_payload_files": output_files,
            "output_payload_fingerprint": sha256_bytes(canonical_json(output_files).encode("utf-8")),
            "remaining_blockers": first["remaining_blockers"],
            "replays_byte_identical": True,
            "resource_facts": {
                "elapsed_seconds": elapsed,
                "output_bytes": output_bytes_without_summary,
                "process_max_rss_bytes": _rss_bytes(),
                "processes": 1,
            },
            "schema_version": "zhishi-stage1-versioned-replay-batch/v1",
            "second_replay_sha256": first_sha,
            "source_data_modified": False,
            "source_files_before": first["source_files"],
            "stage1_complete": False,
            "stage2_released": False,
            "status": "已证明",
            "task_id": "000098",
        }
        for _ in range(4):
            estimated_summary_bytes = len(canonical_json(summary).encode("utf-8")) + 1
            total_output_bytes = output_bytes_without_summary + estimated_summary_bytes
            if summary["resource_facts"]["output_bytes"] == total_output_bytes:
                break
            summary["resource_facts"]["output_bytes"] = total_output_bytes
        summary_sha = _write_json(temporary / "summary.json", summary)
        output_bytes = sum(path.stat().st_size for path in temporary.iterdir())
        limits = config["limits"]
        if elapsed > float(limits["max_elapsed_seconds"]):
            raise TimeoutError("TOTAL_TIME_LIMIT_EXCEEDED")
        if _rss_bytes() > int(limits["max_rss_bytes"]):
            raise ValueError("PROCESS_MEMORY_LIMIT_EXCEEDED")
        if output_bytes > int(limits["max_output_bytes"]):
            raise ValueError("OUTPUT_SIZE_LIMIT_EXCEEDED")
        source_dir = repo_root / str(config["source_batch_relative_path"])
        third = verify_source_files(source_dir, config)
        if third != first["source_files"]:
            raise ValueError("SOURCE_PREPUBLISH_DRIFT")
        for path in temporary.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError("OUTPUT_FILE_INVALID")
            sha256_file(path)
        os.rename(temporary, target)
        summary["summary_sha256"] = summary_sha
        return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--batch-id", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve(strict=True)
    expected_config = repo_root / EXPECTED_CONFIG_RELATIVE_PATH
    if args.config.resolve(strict=True) != expected_config:
        raise ValueError("CONFIG_PATH_INVALID")
    expected_output = repo_root / EXPECTED_OUTPUT_RELATIVE_PATH
    if args.output_root.resolve(strict=False) != expected_output.resolve(strict=False):
        raise ValueError("OUTPUT_ROOT_PATH_INVALID")
    summary = execute(repo_root, args.output_root, args.batch_id, load_config(args.config))
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
