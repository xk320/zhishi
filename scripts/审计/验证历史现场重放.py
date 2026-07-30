#!/usr/bin/env python3
"""以只读、失败安全方式验证《知势》历史决策现场可重放性。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence, TextIO


REPLAY_VERSION = "historical-replay-1.0"
REPLAY_SNAPSHOT_CONTRACT_VERSION = "replay-snapshot-contract-1.0"
UNREPLAYABLE_REMEDIATIONS = {
    "input_identity_drift": "修复建议：创建新审计批次并重新冻结输入身份。",
    "input_scan_incomplete": "修复建议：在不修改原始数据的前提下完成全量只读扫描。",
    "decision_record_missing": "修复建议：提供带来源证据、唯一编号和时区的历史决策记录。",
    "snapshot_contract_incomplete": "修复建议：补全快照逻辑身份、历史时间、决策时间及不可变引用。",
    "data_version_missing": "修复建议：冻结确切输入数据版本，禁止latest、current或空值。",
    "data_hash_missing": "修复建议：提供按业务键稳定排序的完整输入规范JSON SHA-256。",
    "data_hash_mismatch": "修复建议：停止重放，核对全部快照身份、输入版本与完整内容后创建新快照。",
    "input_asset_set_missing": "修复建议：显式冻结非空、去重的输入资产集合。",
    "available_fields_unproven": "修复建议：分别证明并冻结事件、到达和采集时间字段语义。",
    "output_hash_mismatch": "修复建议：拒绝当前结果，排查非确定输入、排序或重放逻辑后生成新版本。",
}
ALLOWED_SSH_TARGETS = {"ubuntu"}
SSH_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]+"
)
TOKEN_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", re.IGNORECASE
)

INVENTORY_COLUMNS = (
    "发现批次", "资产编号", "资产类型", "逻辑主机", "服务或项目", "资源名称", "位置", "格式",
    "标的范围", "时间范围", "字节数", "最后修改时间", "访问状态", "发现证据", "限制", "后续任务",
)
QUALITY_COLUMNS = (
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "资产类型", "服务或项目", "位置",
    "格式", "候选标的范围", "扫描状态", "扫描完整性", "记录数", "字段数", "结构缺失数", "结构缺失率",
    "重复状态", "精确重复数", "事件时间状态", "事件时间候选字段", "到达时间状态", "到达时间候选字段",
    "采集时间状态", "采集时间候选字段", "延迟状态", "乱序状态", "实际覆盖范围", "可用性结论", "依据", "限制",
    "解除条件", "证据指纹",
)
GAP_COLUMNS = (
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "候选标的范围", "断档状态",
    "预期频率", "事件时间字段", "断档数", "断档范围", "原因", "解除条件",
)
ANOMALY_COLUMNS = (
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "候选标的范围", "规则编号",
    "异常类型", "异常数量", "异常比例", "严重度", "规则状态", "证据", "处置",
)
LEGACY_RESULT_COLUMNS = (
    "验证批次", "清单指纹", "质量审计批次", "资产编号", "候选标的范围", "决策记录编号",
    "决策时间", "事件时间字段", "到达时间字段", "采集时间字段", "可见性合同状态", "输入身份状态",
    "第一门状态", "可见记录数", "首次快照指纹", "再次快照指纹", "确定性状态", "未来数据拒绝状态",
    "重放结论", "依据", "限制", "解除条件",
)
RESULT_COLUMNS = LEGACY_RESULT_COLUMNS + (
    "快照记录编号", "快照合同版本", "快照逻辑标识", "快照版本标识", "输入数据版本",
    "输入数据哈希", "输入资产集合指纹", "重放结果哈希", "不可重放原因代码", "修复建议",
)

REMOTE_PREFLIGHT_PROGRAM = textwrap.dedent(
    """
    import json
    import platform
    print(json.dumps({
        "status": "ok",
        "python": platform.python_version(),
        "runtime": "python3-stdin-read-only-preflight"
    }, sort_keys=True))
    """
).lstrip()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _canonical_records(
    records: Iterable[Mapping[str, object]],
    business_key_fields: Sequence[str],
) -> list[dict[str, object]]:
    """深拷贝并按业务键稳定排序完整记录。"""

    if not business_key_fields or any(not isinstance(field, str) or not field for field in business_key_fields):
        raise ValueError("business_key_required")
    if len(set(business_key_fields)) != len(business_key_fields):
        raise ValueError("business_key_duplicate_field")
    normalized: list[dict[str, object]] = []
    seen_keys: set[tuple[str, ...]] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("records_required")
        if any(field not in record or record[field] in (None, "") for field in business_key_fields):
            raise ValueError("business_key_missing")
        try:
            copied = json.loads(_canonical_json(dict(record)))
        except (TypeError, ValueError) as error:
            raise ValueError("record_not_canonical_json") from error
        if not isinstance(copied, dict):
            raise ValueError("records_required")
        business_key = tuple(_canonical_json(copied[field]) for field in business_key_fields)
        if business_key in seen_keys:
            raise ValueError("business_key_duplicate")
        seen_keys.add(business_key)
        normalized.append(copied)
    normalized.sort(
        key=lambda record: (
            tuple(_canonical_json(record[field]) for field in business_key_fields),
            _canonical_json(record),
        )
    )
    return normalized


def calculate_data_sha256(
    records: Iterable[Mapping[str, object]],
    business_key_fields: Sequence[str],
) -> str:
    """对按业务键稳定排序的完整输入记录计算SHA-256。"""

    normalized = _canonical_records(records, business_key_fields)
    return _sha256_bytes(_canonical_json(normalized).encode("utf-8"))


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list) or isinstance(value, tuple):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return value


STABLE_IDENTIFIER_PATTERN = re.compile(
    r"(?=.{1,128}\Z)[A-Za-z0-9\u4e00-\u9fff][A-Za-z0-9\u4e00-\u9fff._:/-]*"
)
GENERATED_SNAPSHOT_FIELDS = {
    "快照记录编号", "快照版本标识", "输入资产集合指纹", "输入记录",
}


def _validate_stable_identifier(value: object, failure_code: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(failure_code)
    if value.lower() in {"latest", "current"}:
        raise ValueError(failure_code)
    if re.fullmatch(r"\d{10}|\d{13}", value):
        raise ValueError(failure_code)
    if re.match(r"^\d{4}-\d{2}-\d{2}(?:T.*)?$", value):
        raise ValueError(failure_code)
    if not STABLE_IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(failure_code)
    return value


def _build_snapshot_identity(
    source: Mapping[str, object],
    *,
    records_field: str,
) -> dict[str, object]:
    """规范化全部快照身份并生成唯一内容寻址版本。"""

    contract_version = source.get("快照合同版本", REPLAY_SNAPSHOT_CONTRACT_VERSION)
    if contract_version != REPLAY_SNAPSHOT_CONTRACT_VERSION:
        raise ValueError("snapshot_contract_incomplete")
    data_version = _validate_stable_identifier(
        source.get("输入数据版本"), "data_version_missing"
    )
    supplied_hash = source.get("输入数据哈希")
    if not isinstance(supplied_hash, str) or not supplied_hash:
        raise ValueError("data_hash_missing")
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_hash):
        raise ValueError("data_hash_missing")
    assets = source.get("输入资产集合")
    if (
        not isinstance(assets, (list, tuple))
        or not assets
        or not all(isinstance(asset, str) and asset.strip() for asset in assets)
    ):
        raise ValueError("input_asset_set_missing")
    if any(asset != asset.strip() for asset in assets):
        raise ValueError("input_asset_set_missing")
    normalized_assets = sorted({_validate_stable_identifier(asset, "input_asset_set_missing") for asset in assets})
    if len(normalized_assets) != len(assets):
        raise ValueError("input_asset_set_missing")

    keys = source.get("业务键")
    if not isinstance(keys, (list, tuple)):
        raise ValueError("business_key_required")
    key_fields = tuple(keys)
    records = source.get(records_field)
    if not isinstance(records, list):
        raise ValueError("records_required")
    normalized_records = _canonical_records(records, key_fields)
    actual_hash = _sha256_bytes(_canonical_json(normalized_records).encode("utf-8"))
    if actual_hash != supplied_hash:
        raise ValueError("data_hash_mismatch")

    historical_time = source.get("历史时间")
    decision_time = source.get("决策时间")
    if not isinstance(historical_time, str) or not isinstance(decision_time, str):
        raise ValueError("snapshot_contract_incomplete")
    _aware_datetime(historical_time)
    _aware_datetime(decision_time)

    logical_id = _validate_stable_identifier(
        source.get("快照逻辑标识"), "snapshot_contract_incomplete"
    )
    event_field = source.get("事件时间字段")
    arrival_field = source.get("到达时间字段")
    collection_field = source.get("采集时间字段")
    if (
        not all(isinstance(field, str) and field for field in (event_field, arrival_field, collection_field))
        or len({event_field, arrival_field, collection_field}) != 3
    ):
        raise ValueError("available_fields_unproven")
    field_status = source.get("字段冻结状态")
    required_fields = (event_field, arrival_field, collection_field)
    if (
        not isinstance(field_status, Mapping)
        or any(field_status.get(field) != "已冻结" for field in required_fields)
    ):
        raise ValueError("available_fields_unproven")
    for record in normalized_records:
        for field in required_fields:
            if field not in record or record[field] in (None, ""):
                raise ValueError("available_fields_unproven")
            _aware_datetime(str(record[field]))

    asset_fingerprint = _sha256_bytes(_canonical_json({
        "输入资产集合": normalized_assets,
        "输入数据版本": data_version,
        "输入数据哈希": actual_hash,
    }).encode("utf-8"))
    version_content = {
        "快照合同版本": REPLAY_SNAPSHOT_CONTRACT_VERSION,
        "快照逻辑标识": logical_id,
        "历史时间": historical_time,
        "决策时间": decision_time,
        "输入数据版本": data_version,
        "输入数据哈希": actual_hash,
        "输入资产集合": normalized_assets,
        "输入资产集合指纹": asset_fingerprint,
        "业务键": list(key_fields),
        "事件时间字段": event_field,
        "到达时间字段": arrival_field,
        "采集时间字段": collection_field,
        "字段冻结状态": {field: "已冻结" for field in required_fields},
        "输入记录": normalized_records,
    }
    content_fingerprint = _sha256_bytes(_canonical_json(version_content).encode("utf-8"))
    version_content["快照版本标识"] = f"sha256:{content_fingerprint}"
    version_content["快照记录编号"] = f"ZS-历史重放-{content_fingerprint}"
    return version_content


def freeze_replay_snapshot(evidence: Mapping[str, object]) -> Mapping[str, object]:
    """创建内容寻址、深度不可变的历史重放输入快照。"""

    if GENERATED_SNAPSHOT_FIELDS & set(evidence):
        raise ValueError("snapshot_contract_incomplete")
    version_content = _build_snapshot_identity(evidence, records_field="记录")
    return _deep_freeze(version_content)  # type: ignore[return-value]


def _redact(value: object) -> str:
    text = str(value)
    text = PRIVATE_KEY_PATTERN.sub("[已脱敏私钥]", text)
    text = TOKEN_PATTERN.sub("[已脱敏令牌]", text)
    text = CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}=[已脱敏]", text)
    return IPV4_PATTERN.sub("[已脱敏地址]", text)


def _safe_csv_cell(value: object) -> str:
    text = _redact(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def _assert_no_sensitive_content(text: str) -> None:
    if (
        PRIVATE_KEY_PATTERN.search(text)
        or TOKEN_PATTERN.search(text)
        or CREDENTIAL_PATTERN.search(text)
        or IPV4_PATTERN.search(text)
    ):
        raise ValueError("sensitive_content_detected")


def validate_ssh_target(target: str) -> str:
    if not target or not SSH_TARGET_PATTERN.fullmatch(target):
        raise ValueError("SSH目标别名不安全")
    if target not in ALLOWED_SSH_TARGETS:
        raise ValueError("SSH目标不在任务固定白名单")
    return target


def run_remote_preflight(target: str, timeout: int = 30) -> dict[str, str]:
    """只确认固定逻辑主机的Python运行入口，不读取数据正文。"""

    validate_ssh_target(target)
    if timeout < 5 or timeout > 300:
        raise ValueError("SSH预检超时必须在5至300秒之间")
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(30, timeout)}",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
        target, "python3", "-",
    ]
    try:
        completed = subprocess.run(
            command,
            input=REMOTE_PREFLIGHT_PROGRAM,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("remote_preflight_failed") from error
    if completed.returncode != 0:
        raise RuntimeError("remote_preflight_failed")
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("remote_preflight_invalid_response") from error
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise RuntimeError("remote_preflight_invalid_response")
    allowed = {"status", "python", "runtime"}
    if set(payload) != allowed or payload.get("runtime") != "python3-stdin-read-only-preflight":
        raise RuntimeError("remote_preflight_invalid_response")
    return {key: _redact(payload[key]) for key in sorted(allowed)}


def _read_csv(path: Path, columns: Sequence[str], label: str) -> list[dict[str, str]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label}必须是普通文件")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != tuple(columns):
            raise ValueError(f"{label}列与输入合同不一致")
        rows = [{key: value or "" for key, value in row.items()} for row in reader]
    if not rows:
        raise ValueError(f"{label}为空")
    return rows


def _single_value(rows: Sequence[Mapping[str, str]], field: str, label: str) -> str:
    values = {row.get(field, "") for row in rows}
    if "" in values or len(values) != 1:
        raise ValueError(f"{label}{field}批次或指纹不一致")
    return next(iter(values))


def _index_unique(rows: Sequence[dict[str, str]], label: str) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows:
        asset_id = row.get("资产编号", "")
        if not re.fullmatch(r"DS-\d{6}", asset_id) or asset_id in index:
            raise ValueError(f"{label}资产编号覆盖不唯一")
        index[asset_id] = row
    return index


def _validate_quality_report(
    report_path: Path,
    audit_batch: str,
    inventory_fingerprint: str,
    rule_version: str,
    rule_fingerprint: str,
) -> None:
    if not report_path.is_file() or report_path.is_symlink():
        raise ValueError("数据质量审计报告必须是普通文件")
    report = report_path.read_text(encoding="utf-8")
    required = (
        f"- 审计批次：`{audit_batch}`",
        f"- 资产清单SHA-256：`{inventory_fingerprint}`",
        f"- 规则版本：`{rule_version}`",
        f"- 规则SHA-256：`{rule_fingerprint}`",
    )
    if any(item not in report for item in required):
        raise ValueError("数据质量审计报告与CSV批次或指纹不一致")


def load_and_freeze_inputs(
    inventory_path: Path,
    quality_path: Path,
    audit_report_path: Path | None = None,
) -> dict[str, object]:
    """校验任务-000003/000004四份CSV的身份和覆盖合同。"""

    inventory_path = Path(inventory_path)
    quality_path = Path(quality_path)
    gap_path = quality_path.with_name("数据断档结果.csv")
    anomaly_path = quality_path.with_name("数据异常结果.csv")
    inventory_rows = _read_csv(inventory_path, INVENTORY_COLUMNS, "数据源清单")
    quality_rows = _read_csv(quality_path, QUALITY_COLUMNS, "数据质量结果")
    gap_rows = _read_csv(gap_path, GAP_COLUMNS, "数据断档结果")
    anomaly_rows = _read_csv(anomaly_path, ANOMALY_COLUMNS, "数据异常结果")

    inventory_index = _index_unique(inventory_rows, "数据源清单")
    quality_index = _index_unique(quality_rows, "数据质量结果")
    gap_index = _index_unique(gap_rows, "数据断档结果")
    anomaly_index = _index_unique(anomaly_rows, "数据异常结果")
    coverage = set(quality_index)
    if set(gap_index) != coverage or set(anomaly_index) != coverage:
        raise ValueError("任务-000004三份结果资产覆盖不一致")
    if not coverage.issubset(inventory_index):
        raise ValueError("质量验证单元超出冻结清单覆盖")

    actual_inventory_fingerprint = _sha256_bytes(inventory_path.read_bytes())
    audit_batch = _single_value(quality_rows, "审计批次", "质量结果")
    rule_version = _single_value(quality_rows, "规则版本", "质量结果")
    rule_fingerprint = _single_value(quality_rows, "规则指纹", "质量结果")
    inventory_fingerprint = _single_value(quality_rows, "清单指纹", "质量结果")
    if inventory_fingerprint != actual_inventory_fingerprint:
        raise ValueError("清单指纹与当前输入不一致")

    for label, rows in (("断档结果", gap_rows), ("异常结果", anomaly_rows)):
        expected = {
            "审计批次": audit_batch,
            "规则版本": rule_version,
            "规则指纹": rule_fingerprint,
            "清单指纹": inventory_fingerprint,
        }
        for field, value in expected.items():
            if _single_value(rows, field, label) != value:
                raise ValueError(f"{label}{field}批次或指纹不一致")

    if audit_report_path is not None:
        _validate_quality_report(
            Path(audit_report_path), audit_batch, inventory_fingerprint,
            rule_version, rule_fingerprint,
        )

    for asset_id, quality in quality_index.items():
        inventory = inventory_index[asset_id]
        comparisons = (
            ("资产类型", "资产类型"), ("服务或项目", "服务或项目"),
            ("位置", "位置"), ("格式", "格式"), ("标的范围", "候选标的范围"),
        )
        if any(inventory[left] != quality[right] for left, right in comparisons):
            raise ValueError(f"{asset_id}清单与质量证据身份漂移")

    return {
        "清单指纹": inventory_fingerprint,
        "质量审计批次": audit_batch,
        "规则版本": rule_version,
        "规则指纹": rule_fingerprint,
        "清单记录": inventory_index,
        "质量记录": quality_index,
        "断档记录": gap_index,
        "异常记录": anomaly_index,
    }


def _aware_datetime(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError("invalid_time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone_required")
    return parsed


def replay_visible_records(
    records: Iterable[Mapping[str, object]],
    decision_time: str,
    arrival_field: str,
    business_key_fields: Sequence[str],
) -> dict[str, object]:
    """按已证明的到达时间闭区间重放，并显式拒绝未来到达记录。"""

    cutoff = _aware_datetime(decision_time)
    if not arrival_field:
        raise ValueError("arrival_field_required")
    if not business_key_fields:
        raise ValueError("business_key_required")
    visible: list[Mapping[str, object]] = []
    rejected = 0
    seen_keys: set[tuple[str, ...]] = set()
    for record in records:
        if any(field not in record or record[field] in (None, "") for field in business_key_fields):
            raise ValueError("business_key_missing")
        if arrival_field not in record or record[arrival_field] in (None, ""):
            raise ValueError("arrival_time_missing")
        business_key = tuple(_canonical_json(record[field]) for field in business_key_fields)
        if business_key in seen_keys:
            raise ValueError("business_key_duplicate")
        seen_keys.add(business_key)
        arrival = _aware_datetime(str(record[arrival_field]))
        if arrival <= cutoff:
            visible.append(dict(record))
        else:
            rejected += 1
    visible.sort(
        key=lambda record: (
            tuple(_canonical_json(record[field]) for field in business_key_fields),
            _canonical_json(record),
        )
    )
    snapshot_json = _canonical_json(visible)
    snapshot_fingerprint = _sha256_bytes(snapshot_json.encode("utf-8"))
    output_payload = {
        "visible_count": len(visible),
        "rejected_count": rejected,
        "future_rejection_code": "future_arrival_rejected" if rejected else "no_future_arrival",
        "snapshot_fingerprint": snapshot_fingerprint,
    }
    return {
        "visible_count": len(visible),
        "rejected_count": rejected,
        "future_rejection_code": "future_arrival_rejected" if rejected else "no_future_arrival",
        "snapshot_json": snapshot_json,
        "snapshot_fingerprint": snapshot_fingerprint,
        "output_fingerprint": _sha256_bytes(_canonical_json(output_payload).encode("utf-8")),
    }


def execute_second_gate(
    records: Iterable[Mapping[str, object]],
    decision_time: str,
    arrival_field: str,
    business_key_fields: Sequence[str],
) -> dict[str, object]:
    frozen_records = [dict(record) for record in records]
    first = replay_visible_records(
        frozen_records, decision_time, arrival_field, business_key_fields
    )
    second = replay_visible_records(
        frozen_records, decision_time, arrival_field, business_key_fields
    )
    deterministic = (
        first["visible_count"] == second["visible_count"]
        and first.get("output_fingerprint", first["snapshot_fingerprint"])
        == second.get("output_fingerprint", second["snapshot_fingerprint"])
    )
    future_rejected = (
        first["future_rejection_code"] == "future_arrival_rejected"
        and second["future_rejection_code"] == "future_arrival_rejected"
    )
    result_hash = _sha256_bytes(_canonical_json({
        "visible_count": first["visible_count"],
        "rejected_count": first["rejected_count"],
        "future_rejection_code": first["future_rejection_code"],
        "output_fingerprint": first.get("output_fingerprint", first["snapshot_fingerprint"]),
    }).encode("utf-8"))
    return {
        "可见记录数": first["visible_count"],
        "首次快照指纹": first["snapshot_fingerprint"],
        "再次快照指纹": second["snapshot_fingerprint"],
        "确定性状态": "通过" if deterministic else "拒绝（连续重放快照不一致）",
        "未来数据拒绝状态": (
            "通过（future_arrival_rejected）" if future_rejected
            else "未触发（无未来到达记录）"
        ),
        "重放结论": "通过" if deterministic else "拒绝",
        "重放结果哈希": result_hash if deterministic else "无法判定（output_hash_mismatch）",
        "不可重放原因代码": "无" if deterministic else "output_hash_mismatch",
        "修复建议": "无需修复" if deterministic else UNREPLAYABLE_REMEDIATIONS["output_hash_mismatch"],
    }


def execute_snapshot_replay(snapshot: Mapping[str, object]) -> dict[str, object]:
    """仅从已冻结快照连续执行两次重放。"""

    thawed = _deep_thaw(snapshot)
    if not isinstance(thawed, dict):
        raise ValueError("snapshot_contract_incomplete")
    expected = _build_snapshot_identity(thawed, records_field="输入记录")
    if set(thawed) != set(expected):
        raise ValueError("snapshot_contract_incomplete")
    if _canonical_json(thawed) != _canonical_json(expected):
        raise ValueError("data_hash_mismatch")
    records = expected["输入记录"]
    keys = expected["业务键"]
    if not isinstance(records, list) or not isinstance(keys, list):
        raise ValueError("snapshot_contract_incomplete")
    result = execute_second_gate(
        records,
        str(expected["决策时间"]),
        str(expected["到达时间字段"]),
        keys,
    )
    result["快照版本标识"] = expected["快照版本标识"]
    return result


def _evaluate_qualified_evidence(
    quality: Mapping[str, str],
    evidence: Mapping[str, object],
    asset_id: str,
) -> dict[str, object]:
    if quality["扫描完整性"] != "完整":
        raise ValueError("input_scan_incomplete")
    required_text = ("证据类型", "合同版本", "来源证据", "决策记录编号")
    if any(not isinstance(evidence.get(field), str) or not evidence[field] for field in required_text):
        raise ValueError("decision_record_missing")
    if "三类时间合同状态" not in evidence:
        raise ValueError("snapshot_contract_incomplete")
    if evidence.get("三类时间合同状态") != "已证明":
        raise ValueError("available_fields_unproven")
    snapshot = freeze_replay_snapshot(evidence)
    if asset_id not in snapshot["输入资产集合"]:
        raise ValueError("input_asset_set_missing")
    second_gate = execute_snapshot_replay(snapshot)
    evidence_fingerprint = _sha256_bytes(_canonical_json(evidence).encode("utf-8"))
    result: dict[str, object] = {
        "决策记录编号": evidence["决策记录编号"],
        "决策时间": snapshot["决策时间"],
        "事件时间字段": snapshot["事件时间字段"],
        "到达时间字段": snapshot["到达时间字段"],
        "采集时间字段": snapshot["采集时间字段"],
        "可见性合同状态": f"通过（{evidence['合同版本']}）",
        "输入身份状态": "一致（冻结清单、质量证据与重放证据）",
        "第一门状态": "通过",
        "依据": f"来源与时间合同证据指纹{evidence_fingerprint}；连续执行两次第二门",
        "限制": (
            "smoke-only合成证据，禁止发布为正式产物"
            if evidence["证据类型"] == "smoke-only"
            else "仅对冻结决策时点、证据版本和资产身份有效"
        ),
        "解除条件": "无需（本验证单元已执行双门重放）",
        "快照记录编号": snapshot["快照记录编号"],
        "快照合同版本": snapshot["快照合同版本"],
        "快照逻辑标识": snapshot["快照逻辑标识"],
        "快照版本标识": snapshot["快照版本标识"],
        "输入数据版本": snapshot["输入数据版本"],
        "输入数据哈希": snapshot["输入数据哈希"],
        "输入资产集合指纹": snapshot["输入资产集合指纹"],
    }
    result.update(second_gate)
    return result


def _unavailable_snapshot_fields(reason_code: str) -> dict[str, str]:
    if reason_code not in UNREPLAYABLE_REMEDIATIONS:
        reason_code = "snapshot_contract_incomplete"
    unavailable = f"无法判定（{reason_code}）"
    return {
        "快照记录编号": unavailable,
        "快照合同版本": REPLAY_SNAPSHOT_CONTRACT_VERSION,
        "快照逻辑标识": unavailable,
        "快照版本标识": unavailable,
        "输入数据版本": unavailable,
        "输入数据哈希": unavailable,
        "输入资产集合指纹": unavailable,
        "重放结果哈希": unavailable,
        "不可重放原因代码": reason_code,
        "修复建议": UNREPLAYABLE_REMEDIATIONS[reason_code],
    }


def build_formal_coverage(
    frozen: Mapping[str, object],
    batch: str,
    replay_evidence: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict[str, str]]:
    quality_index = frozen["质量记录"]
    if not isinstance(quality_index, dict):
        raise ValueError("冻结质量记录结构非法")
    rows: list[dict[str, str]] = []
    for asset_id in sorted(quality_index):
        quality = quality_index[asset_id]
        completeness = quality["扫描完整性"]
        identity_drift = quality["扫描状态"] == "输入漂移"
        reason_code = (
            "input_identity_drift" if identity_drift
            else "input_scan_incomplete" if completeness != "完整"
            else "decision_record_missing"
        )
        if identity_drift:
            scan_basis = "任务-000004已确认结构阶段与质量阶段之间输入漂移，禁止进入重放"
        elif completeness == "完整":
            scan_basis = "完整扫描不等于可见性合同，且冻结输入合同未提供带来源证据的真实决策记录"
        else:
            scan_basis = f"扫描完整性为{completeness}，仅保留覆盖记录，禁止读取正文"
        basis = (
            f"{scan_basis}；事件、到达、采集时间状态均未形成可验证语义合同；"
            "字段名候选证据未被提升为时间语义"
        )
        row: dict[str, object] = {
            "验证批次": batch,
            "清单指纹": str(frozen["清单指纹"]),
            "质量审计批次": str(frozen["质量审计批次"]),
            "资产编号": asset_id,
            "候选标的范围": quality["候选标的范围"],
            "决策记录编号": "无法判定",
            "决策时间": "无法判定",
            "事件时间字段": "无法判定",
            "到达时间字段": "无法判定",
            "采集时间字段": "无法判定",
            "可见性合同状态": "无法判定（缺少已证明的到达时间合同）",
            "输入身份状态": (
                "拒绝（任务-000004已确认输入漂移）"
                if identity_drift else "一致（冻结清单与质量证据）"
            ),
            "第一门状态": (
                "拒绝（输入身份漂移）" if identity_drift
                else "无法判定（缺少真实决策记录与已证明到达时间合同）"
            ),
            "可见记录数": "无法判定",
            "首次快照指纹": "无法判定",
            "再次快照指纹": "无法判定",
            "确定性状态": "未执行（第一门未通过）",
            "未来数据拒绝状态": "未执行（第一门未通过）",
            "重放结论": "拒绝" if identity_drift else "无法判定",
            "依据": basis,
            "限制": "本结果不得用于预测研究、胜率或收益声称、交易许可或真实下单",
            "解除条件": (
                "在新审计批次重新冻结输入，证明结构、质量与重放阶段身份一致；"
                "再提供带来源证据和明确时区的历史决策记录，冻结三类时间语义、"
                "稳定业务键与到达可见性合同"
                if identity_drift else
                "提供带来源证据和明确时区的历史决策记录，冻结三类时间语义、稳定业务键与到达可见性合同"
            ),
        }
        row.update(_unavailable_snapshot_fields(reason_code))
        if not identity_drift and replay_evidence and asset_id in replay_evidence:
            try:
                row.update(_evaluate_qualified_evidence(
                    quality, replay_evidence[asset_id], asset_id
                ))
            except ValueError as error:
                failure_code = str(error)
                if failure_code not in UNREPLAYABLE_REMEDIATIONS:
                    failure_code = "snapshot_contract_incomplete"
                rejected = failure_code in {"data_hash_mismatch", "output_hash_mismatch"}
                row["第一门状态"] = (
                    "拒绝（重放证据未通过合同校验）" if rejected
                    else "无法判定（重放证据未通过合同校验）"
                )
                row["重放结论"] = "拒绝" if rejected else "无法判定"
                row["依据"] = f"重放证据合同校验失败：{failure_code}"
                row["解除条件"] = "修复重放证据合同并创建新验证批次"
                row.update(_unavailable_snapshot_fields(failure_code))
        rows.append({key: str(value) for key, value in row.items()})
    return rows


def _scope_contains(scope: str, symbol: str) -> bool:
    tokens = {token for token in re.split(r"[^A-Za-z0-9]+", scope.upper()) if token}
    return symbol in tokens


def summarize_formal_conclusion(rows: Sequence[Mapping[str, str]]) -> str:
    conclusions = {row.get("重放结论", "") for row in rows}
    allowed_order = ("拒绝", "无法判定", "通过")
    if not conclusions or not conclusions.issubset(set(allowed_order)):
        raise ValueError("正式重放结论集合非法")
    return "与".join(value for value in allowed_order if value in conclusions)


def render_report(rows: Sequence[Mapping[str, str]], metadata: Mapping[str, str]) -> str:
    symbol_counts = {
        symbol: sum(_scope_contains(row.get("候选标的范围", ""), symbol) for row in rows)
        for symbol in ("BTC", "ETH", "SOL")
    }
    conclusions = {}
    for symbol in ("BTC", "ETH", "SOL"):
        symbol_rows = [
            row for row in rows
            if _scope_contains(row.get("候选标的范围", ""), symbol)
        ]
        symbol_statuses = {row.get("重放结论") for row in symbol_rows}
        if "拒绝" in symbol_statuses:
            conclusions[symbol] = "拒绝（候选验证单元存在输入或重放拒绝）"
        elif symbol_rows and symbol_statuses == {"通过"}:
            conclusions[symbol] = "通过（全部候选验证单元通过双门重放）"
        elif "通过" in symbol_statuses:
            conclusions[symbol] = "无法判定（仅部分候选验证单元通过，其余证据不足）"
        else:
            conclusions[symbol] = "无法判定（缺少已证明的历史决策时点与到达可见性合同）"
    rejected_count = sum(row.get("重放结论") == "拒绝" for row in rows)
    unavailable_count = sum(row.get("重放结论") == "无法判定" for row in rows)
    passed_count = sum(row.get("重放结论") == "通过" for row in rows)
    reason_counts: dict[str, int] = {}
    for row in rows:
        reason = row.get("不可重放原因代码", "")
        if reason and reason != "无":
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    evidence_statement = (
        "通过单元仅处理已冻结的重放证据，正式产物不保存原始业务记录。"
        if passed_count else
        "没有读取无资格业务正文，也没有生成虚假决策时点或快照。"
    )
    first_limitation = (
        "1. 通过仅对对应决策时点、合同版本和冻结身份有效，不得外推。"
        if passed_count else
        "1. 当前只能证明验证器能失败安全地阻断无证据输入，不能证明任一历史交易决策可重放。"
    )
    lines = [
        "# 历史现场重放验证",
        "",
        "<!-- markdownlint-disable MD013 -->",
        "",
        "> 宁可停止或无法判定，也不得让未来数据进入历史决策现场。",
        "",
        "## 验证身份",
        "",
        f"- 验证器版本：`{REPLAY_VERSION}`",
        f"- 快照合同版本：`{REPLAY_SNAPSHOT_CONTRACT_VERSION}`",
        f"- 验证批次：`{_redact(metadata['验证批次'])}`",
        f"- 质量审计批次：`{_redact(metadata['质量审计批次'])}`",
        f"- 清单指纹：`{_redact(metadata['清单指纹'])}`",
        f"- 远端只读预检：{_redact(metadata['远端预检'])}（仅验证固定 Python 入口，未读取数据正文）",
        f"- 正式覆盖：{len(rows)} 个任务-000004验证单元",
        "",
        "## 总体结论",
        "",
        "冻结输入的资产编号、审计批次、规则指纹与清单指纹一致。"
        f"统一双门评估结果：第二门通过：{passed_count} 个；输入或重放拒绝：{rejected_count} 个；"
        f"证据不足无法判定：{unavailable_count} 个。{evidence_statement}",
        "",
        "## 标的独立结论",
        "",
        "| 标的 | 候选覆盖单元 | 结论 |",
        "| --- | ---: | --- |",
    ]
    for symbol in ("BTC", "ETH", "SOL"):
        lines.append(f"| {symbol} | {symbol_counts[symbol]} | {conclusions[symbol]} |")
    lines.extend([
        "",
        "“未限定”或其他标的的证据不得外推给 BTC、ETH 或 SOL；BTC 和 ETH 的结果也不得外推给 SOL。",
        "",
        "## 快照与版本合同",
        "",
        f"- 合同版本：`{REPLAY_SNAPSHOT_CONTRACT_VERSION}`。",
        "- 数据哈希：将完整输入记录按已冻结业务键稳定排序，序列化为 UTF-8 规范JSON，计算 SHA-256。",
        "- 资产集合指纹：对排序、去重后的资产身份、输入数据版本与数据哈希规范JSON计算 SHA-256。",
        "- 重放前重新规范化全部快照身份，逐项核对资产指纹、内容指纹、版本标识与记录编号。",
        "- 重放结果哈希：对可见数量、未来拒绝状态和输出指纹计算独立 SHA-256。",
        "- 与知识版本合同一致：逻辑标识稳定，内容变化生成内容寻址的不可变版本标识，下游不得仅引用“最新版本”。",
        "",
        "## 不可重放原因分布",
        "",
        (
            "、".join(f"`{code}`：{reason_counts[code]}" for code in sorted(reason_counts))
            if reason_counts else "未提供原因分类记录。"
        ),
        "",
        "## 验证器机制证据",
        "",
        "- 带时区的决策时间和到达时间才能进入比较。",
        "- 到达时间等于决策时间的记录在闭区间内；晚于决策时间的记录返回 `future_arrival_rejected`。",
        "- 快照使用冻结业务键稳定排序和 SHA-256 指纹；业务键缺失或重复时失败终止。",
        "- 上述未来数据拒绝仅由 `smoke-only` 合成夹具验证生产函数路径；合成记录未进入本报告或正式 CSV。",
        "",
        "## 限制与解除条件",
        "",
        first_limitation,
        "2. 输入漂移单元必须在新审计批次重新冻结，证明结构、质量与重放阶段身份一致。",
        "3. 需要提供带来源证据、唯一记录编号和明确时区的历史决策时点。",
        "4. 需要版本化冻结事件、到达和采集时间语义，以及业务键、排序和去重合同。",
        "5. 本结果不得提升研究准入、模型状态或交易许可，不涉及真实资金。",
        "",
    ])
    return "\n".join(lines)


def write_csv_stream(handle: TextIO, rows: Sequence[Mapping[str, str]]) -> None:
    writer = csv.DictWriter(
        handle, fieldnames=RESULT_COLUMNS, extrasaction="raise", lineterminator="\n"
    )
    writer.writeheader()
    for row in sorted(rows, key=lambda item: (item["资产编号"], item["决策记录编号"])):
        if set(row) != set(RESULT_COLUMNS):
            raise ValueError("历史重放结果列不完整")
        writer.writerow({column: _safe_csv_cell(row[column]) for column in RESULT_COLUMNS})


def _validate_output_path(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("输出路径必须是普通文件")
    if path.parent.is_symlink():
        raise ValueError("输出目录不得为符号链接")


def validate_output_separation(
    output_path: Path,
    report_path: Path,
    protected_inputs: Sequence[Path],
) -> None:
    outputs = {Path(output_path).resolve(), Path(report_path).resolve()}
    if len(outputs) != 2:
        raise ValueError("output_paths_overlap")
    protected = {Path(path).resolve() for path in protected_inputs}
    if outputs & protected:
        raise ValueError("protected_input_path_overlap")


def publish_outputs(
    output_path: Path,
    report_path: Path,
    rows: Sequence[Mapping[str, str]],
    report: str,
) -> None:
    """在内容和路径全部通过后原子发布，失败不覆盖旧产物。"""

    output_path = Path(output_path)
    report_path = Path(report_path)
    _validate_output_path(output_path)
    _validate_output_path(report_path)
    if output_path.suffix.lower() != ".csv" or report_path.suffix.lower() != ".md":
        raise ValueError("历史重放产物扩展名与合同不一致")
    if output_path.resolve() == report_path.resolve():
        raise ValueError("CSV与Markdown输出路径不得相同")
    serialized_rows = _canonical_json(list(rows))
    if "smoke-only" in serialized_rows:
        raise ValueError("smoke_only_formal_output_rejected")
    _assert_no_sensitive_content(serialized_rows)
    csv_buffer = io.StringIO(newline="")
    write_csv_stream(csv_buffer, rows)
    csv_text = csv_buffer.getvalue()
    _assert_no_sensitive_content(csv_text)
    _assert_no_sensitive_content(report)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_paths: list[Path | None] = []
    backups: list[Path | None] = [None, None]
    published = [False, False]
    preserve_backups = False

    def move_to_backup(target: Path) -> Path | None:
        if not target.exists() and not target.is_symlink():
            return None
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".bak", dir=target.parent
        )
        os.close(descriptor)
        backup = Path(raw_path)
        backup.unlink()
        os.replace(target, backup)
        return backup

    def restore(backup: Path | None, target: Path, was_published: bool) -> None:
        if was_published and (target.exists() or target.is_symlink()):
            target.unlink()
        if backup is not None:
            os.replace(backup, target)

    targets = (output_path, report_path)
    contents = (csv_text, report)
    try:
        for target, content in zip(targets, contents):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
            )
            temporary = Path(temporary_name)
            temporary_paths.append(temporary)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        backups[0] = move_to_backup(output_path)
        backups[1] = move_to_backup(report_path)
        for index, target in enumerate(targets):
            temporary = temporary_paths[index]
            if temporary is None:
                raise OSError("临时产物丢失")
            os.replace(temporary, target)
            temporary_paths[index] = None
            published[index] = True
    except BaseException as publish_error:
        rollback_errors: list[BaseException] = []
        for index, target in enumerate(targets):
            try:
                restore(backups[index], target, published[index])
                backups[index] = None
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        if rollback_errors:
            preserve_backups = True
            raise OSError("产物发布失败且回滚未完整；可恢复备份已保留") from publish_error
        raise
    finally:
        for temporary in temporary_paths:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if not preserve_backups:
            for backup in backups:
                if backup is not None:
                    backup.unlink(missing_ok=True)


def _default_batch() -> str:
    now = dt.datetime.now(dt.timezone.utc).astimezone()
    return now.strftime("replay-%Y%m%dT%H%M%S%z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="只读验证《知势》历史决策现场重放")
    parser.add_argument("--inventory", required=True, type=Path, help="任务-000003数据源清单")
    parser.add_argument("--quality", required=True, type=Path, help="任务-000004数据质量结果")
    parser.add_argument("--audit-report", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--ssh-target", required=True, help="固定SSH逻辑别名")
    parser.add_argument("--output", required=True, type=Path, help="历史重放结果CSV")
    parser.add_argument("--report", required=True, type=Path, help="历史现场重放验证报告")
    parser.add_argument("--timeout", type=int, default=30, help="SSH只读预检超时秒数")
    parser.add_argument("--batch", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    validate_ssh_target(arguments.ssh_target)
    audit_report = arguments.audit_report
    if audit_report is None:
        quality_path = arguments.quality.resolve()
        if quality_path.parent.name != "审计" or quality_path.parent.parent.name != "artifacts":
            raise ValueError("非标准仓库路径必须显式提供数据质量审计报告")
        audit_report = quality_path.parents[2] / "docs" / "审计" / "数据质量审计报告.md"
    validate_output_separation(
        arguments.output,
        arguments.report,
        (
            arguments.inventory,
            arguments.quality,
            arguments.quality.with_name("数据断档结果.csv"),
            arguments.quality.with_name("数据异常结果.csv"),
            audit_report,
        ),
    )
    frozen = load_and_freeze_inputs(arguments.inventory, arguments.quality, audit_report)
    remote = run_remote_preflight(arguments.ssh_target, arguments.timeout)
    batch = arguments.batch or _default_batch()
    if not re.fullmatch(r"[A-Za-z0-9+_.:-]+", batch):
        raise ValueError("验证批次格式不安全")
    rows = build_formal_coverage(frozen, batch)
    metadata = {
        "验证批次": batch,
        "清单指纹": str(frozen["清单指纹"]),
        "质量审计批次": str(frozen["质量审计批次"]),
        "远端预检": f"通过（Python {remote['python']}）",
    }
    report = render_report(rows, metadata)
    publish_outputs(arguments.output, arguments.report, rows, report)
    print(
        _canonical_json({
            "status": "ok", "batch": batch, "covered_units": len(rows),
            "formal_conclusion": summarize_formal_conclusion(rows),
            "remote_preflight": "passed",
        })
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"历史现场重放验证失败：{_redact(error)}", file=sys.stderr)
        raise SystemExit(1)
