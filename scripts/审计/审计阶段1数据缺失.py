#!/usr/bin/env python3
"""只读、确定性地复算阶段1脱敏批次的数据缺失情况。

本入口不访问网络、服务器、数据库或原始业务数据；它只读取配置中冻结的
仓库文件，并把结果写入新的追加式批次目录。来源事实只作为已有批次的
输入元数据复用，不在此处重新证明来源身份。
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import pathlib
import resource
import subprocess
import sys
import time
from typing import Any, Iterable


STATUS_ORDER = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
GROUP_FIELDS = ("underlying", "group", "contract", "dataset")
REQUIRED_MEMBER_COLUMNS = (
    "event_date",
    "group",
    "member_id",
    "reason_codes",
    "status",
    "underlying",
)


class AuditError(RuntimeError):
    """任何输入漂移或计数不守恒都进入失败安全。"""


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"JSON_DUPLICATE_KEY:{key}")
        result[key] = value
    return result


def read_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"JSON_READ_FAILED:{path}:{exc}") from exc


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"INPUT_READ_FAILED:{path}:{exc}") from exc
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def date_range(start: str, end: str) -> list[str]:
    try:
        first = dt.date.fromisoformat(start)
        last = dt.date.fromisoformat(end)
    except ValueError as exc:
        raise AuditError(f"DATE_INVALID:{start}:{end}") from exc
    if last < first:
        raise AuditError(f"DATE_RANGE_REVERSED:{start}:{end}")
    return [(first + dt.timedelta(days=i)).isoformat() for i in range((last - first).days + 1)]


def compress_dates(dates: Iterable[str]) -> list[dict[str, Any]]:
    ordered = sorted(set(dates))
    if not ordered:
        return []
    result: list[dict[str, Any]] = []
    start = previous = dt.date.fromisoformat(ordered[0])
    for text in ordered[1:]:
        current = dt.date.fromisoformat(text)
        if current != previous + dt.timedelta(days=1):
            result.append({"start_date": start.isoformat(), "end_date": previous.isoformat(), "day_count": (previous - start).days + 1})
            start = current
        previous = current
    result.append({"start_date": start.isoformat(), "end_date": previous.isoformat(), "day_count": (previous - start).days + 1})
    return result


def git_head(cwd: pathlib.Path) -> str | None:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cwd, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def load_inputs(repo_root: pathlib.Path, config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, pathlib.Path]]:
    input_root = repo_root / config["input_root"]
    if not input_root.is_dir():
        raise AuditError(f"INPUT_ROOT_MISSING:{input_root}")
    paths: dict[str, pathlib.Path] = {}
    total_bytes = 0
    for name, expected in config["inputs"].items():
        path = input_root / name
        if not path.is_file():
            raise AuditError(f"INPUT_FILE_MISSING:{name}")
        total_bytes += path.stat().st_size
        actual = sha256_file(path)
        if actual != expected:
            raise AuditError(f"INPUT_FINGERPRINT_DRIFT:{name}:{actual}")
        paths[name] = path
    if total_bytes > int(config["resource_limits"]["max_input_bytes"]):
        raise AuditError(f"INPUT_BYTES_EXCEEDED:{total_bytes}")
    loaded = {name: read_json(path) for name, path in paths.items()}
    return loaded, paths


def decode_members(raw: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    if raw.get("schema_version") != "zhishi-record-table/v1":
        raise AuditError("MEMBER_SCHEMA_UNSUPPORTED")
    columns = raw.get("columns")
    dictionaries = raw.get("dictionaries")
    rows = raw.get("rows")
    if not isinstance(columns, list) or not isinstance(dictionaries, dict) or not isinstance(rows, list):
        raise AuditError("MEMBER_TABLE_SHAPE_INVALID")
    missing = set(REQUIRED_MEMBER_COLUMNS) - set(columns)
    if missing:
        raise AuditError(f"MEMBER_COLUMNS_MISSING:{','.join(sorted(missing))}")
    if len(rows) > int(config["resource_limits"]["max_rows"]):
        raise AuditError("MEMBER_ROWS_EXCEEDED")
    reverse: dict[str, dict[int, Any]] = {}
    for key, values in dictionaries.items():
        if not isinstance(values, list):
            raise AuditError(f"DICTIONARY_INVALID:{key}")
        reverse[key] = {index: value for index, value in enumerate(values)}
    column_index = {name: index for index, name in enumerate(columns)}
    allowed = set(config["allowed_statuses"])
    seen: set[str] = set()
    decoded: list[dict[str, Any]] = []
    for row_number, row in enumerate(rows, 1):
        if not isinstance(row, list) or len(row) != len(columns):
            raise AuditError(f"MEMBER_ROW_SHAPE_INVALID:{row_number}")
        item: dict[str, Any] = {}
        for index, name in enumerate(columns):
            value = row[index]
            if name in reverse:
                if not isinstance(value, int) or value not in reverse[name]:
                    raise AuditError(f"DICTIONARY_INDEX_INVALID:{name}:{row_number}")
                value = reverse[name][value]
            item[name] = value
        member_id = item["member_id"]
        if not isinstance(member_id, str) or not member_id or member_id in seen:
            raise AuditError(f"MEMBER_ID_NOT_UNIQUE:{row_number}")
        seen.add(member_id)
        if item["underlying"] not in config["underlyings"] or item["status"] not in allowed:
            raise AuditError(f"MEMBER_ENUM_INVALID:{row_number}")
        try:
            dt.date.fromisoformat(item["event_date"])
        except (TypeError, ValueError) as exc:
            raise AuditError(f"EVENT_DATE_INVALID:{row_number}") from exc
        decoded.append(item)
    return decoded


def validate_segments(raw: Any, covered: dict[str, set[str]]) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise AuditError("SEGMENTS_NOT_LIST")
    seen_by_group: dict[str, set[str]] = collections.defaultdict(set)
    normalized: list[dict[str, Any]] = []
    for index, segment in enumerate(raw, 1):
        if not isinstance(segment, dict):
            raise AuditError(f"SEGMENT_INVALID:{index}")
        required = {"contract", "dataset", "day_count", "end_date", "group", "start_date", "underlying"}
        if set(segment) != required:
            raise AuditError(f"SEGMENT_FIELDS_INVALID:{index}")
        dates = date_range(segment["start_date"], segment["end_date"])
        if int(segment["day_count"]) != len(dates):
            raise AuditError(f"SEGMENT_DAY_COUNT_INVALID:{index}")
        key = segment["group"]
        if seen_by_group[key].intersection(dates):
            raise AuditError(f"SEGMENT_OVERLAP:{key}")
        seen_by_group[key].update(dates)
        normalized.append(segment)
    for group, dates in covered.items():
        if seen_by_group[group] != dates:
            raise AuditError(f"SEGMENT_COVERAGE_MISMATCH:{group}")
    return normalized


def build_groups(members: list[dict[str, Any]], segments: list[dict[str, Any]], config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_group: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for item in members:
        by_group[item["group"]].append(item)
    covered: dict[str, set[str]] = {}
    groups: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    for group_key in sorted(by_group):
        rows = by_group[group_key]
        statuses = collections.Counter(item["status"] for item in rows)
        all_dates = {item["event_date"] for item in rows}
        good_dates = {item["event_date"] for item in rows if item["status"] in config["covered_statuses"]}
        covered[group_key] = good_dates
        if not all_dates:
            raise AuditError(f"GROUP_WITHOUT_DATES:{group_key}")
        start_date, end_date = min(all_dates), max(all_dates)
        expected_dates = set(date_range(start_date, end_date))
        missing_dates = sorted(expected_dates - good_dates)
        segment_rows = [item for item in segments if item["group"] == group_key]
        group_fields = {field: rows[0].get(field) for field in GROUP_FIELDS}
        if any(any(item.get(field) != group_fields[field] for field in GROUP_FIELDS) for item in rows):
            raise AuditError(f"GROUP_FIELDS_DRIFT:{group_key}")
        status_counts = {status: int(statuses.get(status, 0)) for status in STATUS_ORDER}
        if sum(status_counts.values()) != len(rows):
            raise AuditError(f"STATUS_COUNT_NOT_CONSERVE:{group_key}")
        segment_day_count = sum(int(item["day_count"]) for item in segment_rows)
        if segment_day_count != len(good_dates):
            raise AuditError(f"SEGMENT_DAY_COUNT_NOT_CONSERVE:{group_key}")
        group_result = {
            **group_fields,
            "candidate_total": len(rows),
            "observed": len(rows),
            "status_counts": status_counts,
            "missing_member_count": 0,
            "missing_date_count": len(missing_dates),
            "date_span": {"start_date": start_date, "end_date": end_date, "day_count": len(expected_dates)},
            "covered_date_count": len(good_dates),
            "continuous_segment_count": len(segment_rows),
            "continuous_segment_day_count": segment_day_count,
            "coverage_continuous": not missing_dates,
        }
        groups.append(group_result)
        for missing_date in missing_dates:
            missing_rows.append({
                **group_fields,
                "date": missing_date,
                "reason": "状态不是已证明或成员日期在正式范围内缺失",
            })
    validate_segments(segments, covered)
    return groups, missing_rows


def build_leaves(raw: Any, groups: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) != int(config["expected"]["leaf_count"]):
        raise AuditError("LEAF_COUNT_INVALID")
    group_by_underlying: dict[str, dict[str, Any]] = {}
    for group in groups:
        group_by_underlying.setdefault(group["underlying"], {"candidate_total": 0, "observed": 0, "status_counts": {status: 0 for status in STATUS_ORDER}})
        aggregate = group_by_underlying[group["underlying"]]
        aggregate["candidate_total"] += group["candidate_total"]
        aggregate["observed"] += group["observed"]
        for status in STATUS_ORDER:
            aggregate["status_counts"][status] += group["status_counts"][status]
    leaves: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for leaf in raw:
        if not isinstance(leaf, dict):
            raise AuditError("LEAF_INVALID")
        key = (leaf.get("underlying"), int(leaf.get("horizon_hours", -1)))
        if key in seen or key[0] not in config["underlyings"] or key[1] not in config["horizons_hours"]:
            raise AuditError(f"LEAF_KEY_INVALID:{key}")
        seen.add(key)
        aggregate = group_by_underlying[key[0]]
        if leaf.get("formal_member_count") != aggregate["candidate_total"] or leaf.get("observed_member_count") != aggregate["observed"]:
            raise AuditError(f"LEAF_MEMBER_COUNT_DRIFT:{key}")
        leaves.append({
            "underlying": key[0],
            "horizon_hours": key[1],
            "market_type": leaf.get("market_type"),
            "venue": leaf.get("venue"),
            "candidate_total": aggregate["candidate_total"],
            "observed": aggregate["observed"],
            "status_counts": aggregate["status_counts"],
            "missing_member_count": 0,
            "missing_date_count": sum(group["missing_date_count"] for group in groups if group["underlying"] == key[0]),
            "continuous_coverage": all(group["coverage_continuous"] for group in groups if group["underlying"] == key[0]),
            "post_event_observation_minutes": list(config["post_event_observation_minutes"]),
            "decision": "数据缺失审计，不构成研究准入或交易许可",
        })
    if len(seen) != len(config["underlyings"]) * len(config["horizons_hours"]):
        raise AuditError("LEAF_CARTESIAN_PRODUCT_INCOMPLETE")
    return sorted(leaves, key=lambda item: (config["underlyings"].index(item["underlying"]), item["horizon_hours"]))


def ensure_expected(summary: dict[str, Any], source_rejected: list[Any], config: dict[str, Any]) -> None:
    expected = config["expected"]
    if summary.get("candidate_total") != expected["candidate_total"] or summary.get("formal_member_count") != expected["formal_member_count"]:
        raise AuditError("SUMMARY_CANDIDATE_COUNT_DRIFT")
    if len(source_rejected) != expected["source_rejected_count"] or any(item.get("status") != "拒绝" for item in source_rejected):
        raise AuditError("SOURCE_REJECTED_COUNT_DRIFT")
    actual = {status: int(summary.get("status_counts", {}).get(status, 0)) for status in STATUS_ORDER}
    if actual != expected["status_counts"]:
        raise AuditError("SUMMARY_STATUS_COUNT_DRIFT")


def write_exclusive(path: pathlib.Path, payload: Any, max_output: int) -> str:
    data = json_bytes(payload)
    if len(data) > max_output:
        raise AuditError(f"OUTPUT_BYTES_EXCEEDED:{path.name}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(data).hexdigest()


def run(repo_root: pathlib.Path, config_path: pathlib.Path, output_root: pathlib.Path, batch_id: str | None = None) -> pathlib.Path:
    started = time.monotonic()
    config = read_json(config_path)
    if config.get("schema_version") != "zhishi-stage1-missing-data-audit-config/v1":
        raise AuditError("CONFIG_SCHEMA_UNSUPPORTED")
    loaded, paths = load_inputs(repo_root, config)
    summary = loaded["summary.json"]
    source_rejected = loaded["source-rejected.json"]
    ensure_expected(summary, source_rejected, config)
    members = decode_members(loaded["members-001.json"], config)
    if len(members) != int(summary["formal_member_count"]):
        raise AuditError("MEMBER_COUNT_NOT_CONSERVE")
    segments = validate_segments(loaded["segments.json"], {}) if not loaded["segments.json"] else loaded["segments.json"]
    groups, missing_rows = build_groups(members, segments, config)
    leaves = build_leaves(loaded["leaves.json"], groups, config)
    computed_status = {status: sum(group["status_counts"][status] for group in groups) for status in STATUS_ORDER}
    if computed_status != {status: int(summary["status_counts"].get(status, 0)) for status in STATUS_ORDER}:
        raise AuditError("COMPUTED_STATUS_NOT_CONSERVE")
    formal_count = sum(group["candidate_total"] for group in groups)
    if formal_count != int(summary["formal_member_count"]):
        raise AuditError("GROUP_MEMBER_COUNT_NOT_CONSERVE")
    if formal_count + len(source_rejected) != int(summary["candidate_total"]):
        raise AuditError("CANDIDATE_TOTAL_NOT_CONSERVE")
    missing_members = [
        {"member_id": item["member_id"], "underlying": item["underlying"], "group": item["group"], "status": item["status"], "reason_codes": item["reason_codes"]}
        for item in members
        if item["status"] in {"无法判定", "失败", "未成熟", "失效"}
    ]
    rules = {
        "schema_version": "zhishi-stage1-missing-data-audit-rules/v1",
        "source_identity_audit_performed": False,
        "source_identity_fact_reused": True,
        "covered_statuses": list(config["covered_statuses"]),
        "status_order": list(STATUS_ORDER),
        "group_dimensions": ["标的", "数据对象", "合约"],
        "horizons_hours": list(config["horizons_hours"]),
        "post_event_observation_minutes": list(config["post_event_observation_minutes"]),
        "missing_date_rule": "正式成员日期范围内不在已证明集合的日期；拒绝日期也属于缺失覆盖",
        "missing_member_rule": "正式成员记录缺失或处于无法判定/失败/未成熟/失效状态",
        "cross_underlying_compensation": False,
        "result_visible_reclassification": False,
        "trading_or_research_conclusion": False,
    }
    rules_sha = canonical_sha256(rules)
    input_fingerprint = canonical_sha256({name: config["inputs"][name] for name in sorted(config["inputs"])})
    executor = {
        "schema_version": "zhishi-stage1-missing-data-audit-executor/v1",
        "script": "scripts/审计/审计阶段1数据缺失.py",
        "python": sys.version.split()[0],
        "git_head": git_head(repo_root),
    }
    executor_sha = canonical_sha256(executor)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if batch_id is None:
        batch_id = f"stage1-missing-data-audit-{now.strftime('%Y%m%dT%H%M%SZ')}-{input_fingerprint[:12]}"
    batch_dir = output_root / batch_id
    try:
        batch_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise AuditError(f"BATCH_ALREADY_EXISTS:{batch_id}") from exc
    output: dict[str, Any] = {
        "summary.json": {
            "schema_version": "zhishi-stage1-missing-data-audit-batch/v1",
            "batch_id": batch_id,
            "task_id": "000109",
            "replaces_task_id": "000084",
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "input_root": config["input_root"],
            "input_fingerprint": input_fingerprint,
            "rules_sha256": rules_sha,
            "executor_sha256": executor_sha,
            "source_identity_audit_performed": False,
            "source_identity_fact_reused": True,
            "candidate_total": int(summary["candidate_total"]),
            "formal_member_count": formal_count,
            "source_rejected_count": len(source_rejected),
            "observed": formal_count,
            "missing_member_count": len(missing_members),
            "status_counts": computed_status,
            "missing_date_count": len(missing_rows),
            "group_count": len(groups),
            "leaf_count": len(leaves),
            "research_horizons_hours": list(config["horizons_hours"]),
            "post_event_observation_minutes": list(config["post_event_observation_minutes"]),
            "decision": "只报告数据缺失；不产生来源身份、研究准入或交易许可结论",
        },
        "groups.json": groups,
        "leaves.json": leaves,
        "missing-dates.json": missing_rows,
        "missing-members.json": missing_members,
        "rules.json": rules,
        "executor.json": executor,
    }
    file_hashes: dict[str, str] = {}
    try:
        for name, payload in output.items():
            file_hashes[name] = write_exclusive(batch_dir / name, payload, int(config["resource_limits"]["max_output_bytes"]))
        elapsed = time.monotonic() - started
        usage = resource.getrusage(resource.RUSAGE_SELF)
        manifest = {
            "schema_version": "zhishi-stage1-missing-data-audit-manifest/v1",
            "batch_id": batch_id,
            "task_id": "000109",
            "input_files": {name: {"path": str(paths[name].relative_to(repo_root)), "sha256": config["inputs"][name], "bytes": paths[name].stat().st_size} for name in sorted(paths)},
            "output_files": file_hashes,
            "rules_sha256": rules_sha,
            "executor_sha256": executor_sha,
            "resource_facts": {
                "elapsed_seconds": round(elapsed, 6),
                "max_rss_bytes": int(usage.ru_maxrss) if sys.platform == "darwin" else int(usage.ru_maxrss) * 1024,
                "processes": 1,
                "network_access": False,
                "remote_access": False,
                "database_access": False,
                "raw_data_access": False,
            },
        }
        file_hashes["manifest.json"] = write_exclusive(batch_dir / "manifest.json", manifest, int(config["resource_limits"]["max_output_bytes"]))
        total_output_bytes = sum((batch_dir / name).stat().st_size for name in file_hashes)
        if total_output_bytes > int(config["resource_limits"]["max_output_bytes"]):
            raise AuditError("OUTPUT_TOTAL_BYTES_EXCEEDED")
        return batch_dir
    except Exception:
        # 保留已创建的目录和文件作为失败安全证据，不覆盖、不删除历史批次。
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--config", type=pathlib.Path, default=pathlib.Path("config/审计/任务-000084数据缺失审计.json"))
    parser.add_argument("--output-root", type=pathlib.Path, default=pathlib.Path("artifacts/审计/阶段1数据缺失"))
    parser.add_argument("--batch-id")
    args = parser.parse_args(argv)
    try:
        batch = run(args.repo_root.resolve(), (args.repo_root / args.config).resolve() if not args.config.is_absolute() else args.config, (args.repo_root / args.output_root).resolve() if not args.output_root.is_absolute() else args.output_root, args.batch_id)
    except AuditError as exc:
        print(f"FAIL_SAFE:{exc}", file=sys.stderr)
        return 2
    print(batch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
