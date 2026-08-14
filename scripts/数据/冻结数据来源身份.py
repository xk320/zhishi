#!/usr/bin/env python3
"""冻结《知势》数据来源与资产身份登记批次。"""

from __future__ import annotations

import argparse
import ctypes
import csv
import datetime as dt
import errno
import hashlib
import io
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence


CONTRACT_VERSION = "source-identity-1.0"
PROBE_VERSION = "source-identity-probe-1.0"
EVIDENCE_VERSION = "source-identity-evidence-1.0"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = REPO_ROOT / "config" / "数据" / "数据来源与资产身份.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts" / "数据" / "来源身份"
MAIN_BASELINE = "c7763a411ba6c239ddecb923bf04ebbbec5eebf3"
TASK_28_MERGE = "e138bd589a5bde38c81f48d38b7c449f6f13df37"
TASK_38_MERGE = "b49cf2fabfbbb2968dc18efba80121de0d7601e8"
TASK_29_BASELINE_PATH = "docs/研发中心/任务/任务-000029.md"
TASK_29_BASELINE_SHA256 = "025f6498fa29edc5fc6c1cdb8214a1215b3e0fe7869bdb543a9ceb440e56d560"

CONTRACT_KEYS = {
    "合同版本",
    "任务编号",
    "治理基线",
    "输入文件",
    "候选资产类型",
    "标的",
    "身份字段",
    "允许状态",
    "允许SSH目标",
    "允许文件根目录",
    "数据库元数据范围",
    "资源上限",
    "安全边界",
    "身份声明",
}
BASELINE_KEYS = {
    "main基线提交",
    "任务-000028合并提交",
    "任务-000038合并提交",
    "任务-000029基线路径",
    "任务-000029基线SHA-256",
}
INPUT_KEYS = {"用途", "路径", "SHA-256"}
RESOURCE_KEYS = {
    "批次总超时秒",
    "逐成员超时秒",
    "最大成员数",
    "最大输出字节数",
    "最大日志字节数",
}
SAFETY_KEYS = {
    "远端写入",
    "远端临时文件",
    "数据库业务记录读取",
    "读取环境变量或凭据",
    "原始业务记录落盘",
    "修改原始数据",
}
IDENTITY_FIELDS = [
    "来源提供者",
    "交易场所",
    "市场类型",
    "标的身份",
    "精确合约",
    "数据对象",
    "Schema确切版本",
    "授权边界",
    "字段中文映射",
]
CLAIM_KEYS = {
    "资产编号",
    "标的",
    "状态",
    "输入成员SHA-256",
    "远端元数据SHA-256",
    *IDENTITY_FIELDS,
    "证据",
    "限制",
    "解除条件",
}
EVIDENCE_KEYS = {"证据用途", "证据定位", "SHA-256", "证明字段"}
EVIDENCE_DOCUMENT_KEYS = {"证据版本", "记录"}
EVIDENCE_RECORD_KEYS = {
    "证据记录编号",
    "资产编号",
    "标的",
    "输入成员SHA-256",
    "证明字段",
    "声明值",
}
FIELD_MAP_KEYS = {"原始字段", "中文名称", "类型", "单位", "精度", "空值语义"}
ALLOWED_ASSET_TYPES = ["候选数据文件", "数据库元数据"]
TARGETS = ["BTC", "ETH"]
STATES = ["已证明", "拒绝", "无法判定"]
ALLOWED_FILE_ROOTS = [
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
    "/var/lib/mysql",
]
APPROVED_DATABASE_METADATA = [
    "information_schema.TABLES",
    "information_schema.COLUMNS",
]
INVENTORY_COLUMNS = (
    "发现批次",
    "资产编号",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
)
OUTPUT_COLUMNS = (
    "来源身份批次",
    "成员编号",
    "资产编号",
    "资产类型",
    "标的",
    "来源提供者",
    "交易场所",
    "市场类型",
    "标的身份",
    "精确合约",
    "数据对象",
    "Schema确切版本",
    "授权边界",
    "字段中文映射",
    "状态",
    "证据",
    "限制",
    "解除条件",
    "输入成员SHA-256",
    "远端元数据SHA-256",
    "身份记录SHA-256",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ASSET_ID_PATTERN = re.compile(r"^DS-[0-9]{6}$")
MYSQL_LOCATION_PATTERN = re.compile(
    r"^MySQL/(?P<schema>[A-Za-z0-9_]+)/(?P<table>[A-Za-z0-9_]+)$"
)
SSH_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----", re.IGNORECASE
)
TOKEN_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b")
CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]+"
)
USER_AT_HOST_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9_.-]+\b")
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
PUBLIC_RUNTIME_ERRORS = {
    "只读元数据复核失败：批次超时，未发布批次": (
        "ZI-SI-2001",
        "只读元数据复核超时",
    ),
    "只读元数据复核失败：响应超过冻结上限，未发布批次": (
        "ZI-SI-2002",
        "只读元数据复核超过资源上限",
    ),
    "只读元数据复核失败：输出超过冻结上限，未发布批次": (
        "ZI-SI-2002",
        "只读元数据复核超过资源上限",
    ),
    "只读元数据复核失败：日志超过冻结上限，未发布批次": (
        "ZI-SI-2002",
        "只读元数据复核超过资源上限",
    ),
}


class PublicArgumentError(Exception):
    """不携带原始argv、参数名或解析器正文的固定参数错误。"""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise PublicArgumentError()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def object_fingerprint(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bytes_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_exact_keys(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    actual = set(value)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unknown:
        raise ValueError(f"{label}包含未知字段：{'、'.join(unknown)}")
    if missing:
        raise ValueError(f"{label}缺少字段：{'、'.join(missing)}")


def _require_exact_string_list(value: object, expected: list[str], label: str) -> None:
    if value != expected:
        raise ValueError(f"{label}必须严格为{'、'.join(expected)}")


def _resolve_repository_file(repo_root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label}路径必须是非空字符串")
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"{label}路径必须位于仓库内")
    root = repo_root.resolve()
    candidate = root / relative_path
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label}必须是仓库内普通文件")
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"{label}路径越界")
    return resolved


def _read_regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label}必须是普通文件")
    return path.read_bytes()


def capture_execution_snapshot(
    contract_path: Path,
    repo_root: Path,
) -> dict[str, object]:
    """在合同加载前冻结配置、执行器、任务与全部输入的字节和指纹。"""

    contract_bytes = _read_regular_bytes(contract_path, "来源身份合同")
    try:
        raw_contract = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("来源身份合同不是合法JSON") from error
    if not isinstance(raw_contract, dict) or not isinstance(raw_contract.get("输入文件"), list):
        raise ValueError("来源身份合同结构非法")

    input_paths: dict[str, Path] = {}
    input_bytes: dict[str, bytes] = {}
    input_hashes: dict[str, str] = {}
    purpose_bytes: dict[str, bytes] = {}
    for item in raw_contract["输入文件"]:
        if not isinstance(item, dict):
            raise ValueError("来源身份合同输入结构非法")
        purpose = item.get("用途")
        relative = item.get("路径")
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("来源身份合同输入用途非法")
        path = _resolve_repository_file(repo_root, relative, "执行快照输入")
        data = _read_regular_bytes(path, "执行快照输入")
        relative_text = str(relative)
        input_paths[relative_text] = path
        input_bytes[relative_text] = data
        input_hashes[relative_text] = bytes_fingerprint(data)
        purpose_bytes[purpose] = data

    executor_path = Path(__file__).resolve()
    task_path = _resolve_repository_file(repo_root, TASK_29_BASELINE_PATH, "当前执行任务文件")
    executor_bytes = _read_regular_bytes(executor_path, "执行器")
    task_bytes = _read_regular_bytes(task_path, "当前执行任务文件")
    return {
        "配置路径": contract_path,
        "配置字节": contract_bytes,
        "规则SHA-256": bytes_fingerprint(contract_bytes),
        "执行器路径": executor_path,
        "执行器SHA-256": bytes_fingerprint(executor_bytes),
        "当前任务路径": task_path,
        "当前执行任务文件SHA-256": bytes_fingerprint(task_bytes),
        "输入路径": input_paths,
        "输入字节": input_bytes,
        "用途输入字节": purpose_bytes,
        "输入SHA-256": input_hashes,
    }


def assert_execution_snapshot(snapshot: Mapping[str, object]) -> None:
    """复算冻结执行快照；任一字节变化均失败安全。"""

    try:
        if bytes_fingerprint(_read_regular_bytes(Path(snapshot["配置路径"]), "来源身份合同")) != snapshot["规则SHA-256"]:
            raise ValueError("执行快照指纹漂移")
        if bytes_fingerprint(_read_regular_bytes(Path(snapshot["执行器路径"]), "执行器")) != snapshot["执行器SHA-256"]:
            raise ValueError("执行快照指纹漂移")
        if bytes_fingerprint(_read_regular_bytes(Path(snapshot["当前任务路径"]), "当前执行任务文件")) != snapshot["当前执行任务文件SHA-256"]:
            raise ValueError("执行快照指纹漂移")
        input_paths = snapshot["输入路径"]
        input_hashes = snapshot["输入SHA-256"]
        if not isinstance(input_paths, dict) or not isinstance(input_hashes, dict):
            raise ValueError("执行快照指纹漂移")
        for relative, path in input_paths.items():
            if bytes_fingerprint(_read_regular_bytes(Path(path), "执行快照输入")) != input_hashes.get(relative):
                raise ValueError("执行快照指纹漂移")
    except OSError as error:
        raise ValueError("执行快照指纹漂移") from error


def _contains_sensitive(text: str) -> bool:
    return any(
        pattern.search(text)
        for pattern in (
            IPV4_PATTERN,
            PRIVATE_KEY_PATTERN,
            TOKEN_PATTERN,
            CREDENTIAL_PATTERN,
            USER_AT_HOST_PATTERN,
        )
    )


def _contains_smoke_marker(value: object) -> bool:
    if isinstance(value, str):
        normalized = value.lower().replace("_", "-")
        return "smoke-only" in normalized
    if isinstance(value, list):
        return any(_contains_smoke_marker(item) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_smoke_marker(key) or _contains_smoke_marker(item)
            for key, item in value.items()
        )
    return False


def _load_identity_evidence(path: Path) -> dict[str, dict[str, object]]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ValueError("专用证据必须是结构化身份合同证据JSON") from error
    return _load_identity_evidence_bytes(data)


def _load_identity_evidence_bytes(data: bytes) -> dict[str, dict[str, object]]:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("专用证据必须是结构化身份合同证据JSON") from error
    if not isinstance(document, dict):
        raise ValueError("结构化身份合同证据必须是对象")
    _require_exact_keys(document, EVIDENCE_DOCUMENT_KEYS, "结构化身份合同证据")
    if document["证据版本"] != EVIDENCE_VERSION:
        raise ValueError("结构化身份合同证据版本不受支持")
    if _contains_smoke_marker(document):
        raise ValueError("结构化身份合同证据不得是smoke自述")
    records = document["记录"]
    if not isinstance(records, list) or not records:
        raise ValueError("结构化身份合同证据记录必须是非空列表")
    by_id: dict[str, dict[str, object]] = {}
    bindings: set[tuple[str, str, str, str]] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("结构化身份合同证据记录必须是对象")
        _require_exact_keys(record, EVIDENCE_RECORD_KEYS, "结构化身份合同证据记录")
        record_id = record["证据记录编号"]
        if (
            not isinstance(record_id, str)
            or not re.fullmatch(r"EVI-[A-Z0-9-]{3,64}", record_id)
            or record_id in by_id
        ):
            raise ValueError("结构化身份合同证据记录编号非法或重复")
        asset_id = record["资产编号"]
        target = record["标的"]
        member_hash = record["输入成员SHA-256"]
        proof_field = record["证明字段"]
        if not isinstance(asset_id, str) or not ASSET_ID_PATTERN.fullmatch(asset_id):
            raise ValueError("结构化身份合同证据资产编号非法")
        if target not in TARGETS:
            raise ValueError("结构化身份合同证据标的非法")
        if not isinstance(member_hash, str) or not SHA256_PATTERN.fullmatch(member_hash):
            raise ValueError("结构化身份合同证据输入成员指纹非法")
        if proof_field not in {*IDENTITY_FIELDS, "拒绝结论"}:
            raise ValueError("结构化身份合同证据证明字段非法")
        binding = (asset_id, str(target), member_hash, str(proof_field))
        if binding in bindings:
            raise ValueError("结构化身份合同证据证明字段绑定重复")
        bindings.add(binding)
        by_id[record_id] = record
    return by_id


def _validate_claims(
    claims: object,
    input_fingerprints: Mapping[str, str],
    member_fingerprints: Mapping[str, str],
    identity_evidence: Mapping[str, Mapping[str, object]],
) -> None:
    if not isinstance(claims, list):
        raise ValueError("身份声明必须是列表")
    seen: set[tuple[str, str]] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError("身份声明成员必须是对象")
        _require_exact_keys(claim, CLAIM_KEYS, "身份声明")
        asset_id = claim["资产编号"]
        target = claim["标的"]
        if not isinstance(asset_id, str) or not ASSET_ID_PATTERN.fullmatch(asset_id):
            raise ValueError("身份声明资产编号格式非法")
        if target not in TARGETS:
            raise ValueError("身份声明标的不在BTC、ETH范围")
        key = (asset_id, str(target))
        if key in seen:
            raise ValueError("同一资产与标的只能有一条身份声明")
        seen.add(key)
        if claim["状态"] not in {"已证明", "拒绝"}:
            raise ValueError("冻结身份声明状态只允许已证明或拒绝")
        input_member_hash = claim["输入成员SHA-256"]
        if (
            not isinstance(input_member_hash, str)
            or not SHA256_PATTERN.fullmatch(input_member_hash)
            or member_fingerprints.get(asset_id) != input_member_hash
        ):
            raise ValueError("身份声明输入成员指纹与当前冻结资产不一致")
        metadata_hash = claim["远端元数据SHA-256"]
        if not isinstance(metadata_hash, str) or not SHA256_PATTERN.fullmatch(metadata_hash):
            raise ValueError("身份声明远端元数据指纹格式非法")
        if not isinstance(claim["限制"], str) or not claim["限制"]:
            raise ValueError("身份声明必须记录限制")
        if not isinstance(claim["解除条件"], str) or not claim["解除条件"]:
            raise ValueError("身份声明必须记录解除条件")

        evidence = claim["证据"]
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("身份声明必须包含可复核证据")
        proved_fields: list[str] = []
        for item in evidence:
            if not isinstance(item, dict):
                raise ValueError("身份声明证据必须是对象")
            _require_exact_keys(item, EVIDENCE_KEYS, "身份声明证据")
            purpose = item["证据用途"]
            location = item["证据定位"]
            fingerprint = item["SHA-256"]
            proof_fields = item["证明字段"]
            if (
                not isinstance(purpose, str)
                or not purpose.startswith("身份合同证据:")
                or input_fingerprints.get(purpose) != fingerprint
            ):
                raise ValueError("身份声明证据必须绑定专用身份合同证据用途")
            if not isinstance(location, str) or not location.strip():
                raise ValueError("身份声明证据定位必须非空")
            if _contains_sensitive(location):
                raise ValueError("身份声明证据定位包含敏感信息")
            if (
                not isinstance(proof_fields, list)
                or len(proof_fields) != 1
                or not isinstance(proof_fields[0], str)
                or proof_fields[0] not in {*IDENTITY_FIELDS, "拒绝结论"}
            ):
                raise ValueError("身份声明证据必须逐字段声明唯一证明字段")
            proof_field = proof_fields[0]
            record = identity_evidence.get(purpose, {}).get(location)
            if not isinstance(record, dict):
                raise ValueError("身份声明证据定位不存在")
            if (
                record["资产编号"] != asset_id
                or record["标的"] != target
                or record["输入成员SHA-256"] != input_member_hash
                or record["证明字段"] != proof_field
            ):
                raise ValueError("身份声明与结构化证据记录绑定不一致")
            expected_value = "拒绝" if proof_field == "拒绝结论" else claim[proof_field]
            if canonical_json(record["声明值"]) != canonical_json(expected_value):
                raise ValueError("身份声明值与结构化证据记录声明值不一致")
            proved_fields.append(proof_field)

        field_mapping = claim["字段中文映射"]
        if claim["状态"] == "已证明":
            for field in IDENTITY_FIELDS[:-1]:
                value = claim[field]
                if not isinstance(value, str) or not value or value == "未知":
                    raise ValueError(f"已证明身份缺少{field}")
            if claim["标的身份"] != target:
                raise ValueError("已证明身份的标的身份必须与独立判定标的一致")
            schema = claim["Schema确切版本"]
            if not isinstance(schema, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", schema):
                raise ValueError("已证明身份必须绑定Schema确切版本指纹")
            if not isinstance(field_mapping, list) or not field_mapping:
                raise ValueError("已证明身份必须包含字段中文映射")
            for field_item in field_mapping:
                if not isinstance(field_item, dict):
                    raise ValueError("字段中文映射成员必须是对象")
                _require_exact_keys(field_item, FIELD_MAP_KEYS, "字段中文映射")
                if any(
                    not isinstance(field_item[key_name], str)
                    or not field_item[key_name]
                    for key_name in FIELD_MAP_KEYS
                ):
                    raise ValueError("字段中文映射不得包含空值")
            if Counter(proved_fields) != Counter({field: 1 for field in IDENTITY_FIELDS}):
                raise ValueError("已证明身份的专用证据必须覆盖全部身份字段")
        elif field_mapping != []:
            raise ValueError("拒绝声明不得附带未证明的字段中文映射")
        elif Counter(proved_fields) != Counter({"拒绝结论": 1}):
            raise ValueError("拒绝声明必须由专用证据证明拒绝结论")


def _validate_governance_baseline(
    baseline: object,
    repo_root: Path,
) -> dict[str, str]:
    if not isinstance(baseline, dict):
        raise ValueError("治理基线必须是对象")
    _require_exact_keys(baseline, BASELINE_KEYS, "治理基线")
    expected = {
        "main基线提交": MAIN_BASELINE,
        "任务-000028合并提交": TASK_28_MERGE,
        "任务-000038合并提交": TASK_38_MERGE,
        "任务-000029基线路径": TASK_29_BASELINE_PATH,
    }
    for field, value in expected.items():
        if baseline[field] != value:
            raise ValueError(f"治理基线{field}漂移")
    baseline_hash = baseline["任务-000029基线SHA-256"]
    if not isinstance(baseline_hash, str) or not SHA256_PATTERN.fullmatch(baseline_hash):
        raise ValueError("治理基线任务内容指纹格式非法")
    git_marker = repo_root / ".git"
    if git_marker.exists():
        completed = run_bounded_process(
            [
                "git",
                "-C",
                str(repo_root.resolve()),
                "show",
                f"{MAIN_BASELINE}:{TASK_29_BASELINE_PATH}",
            ],
            input_text="",
            timeout=10,
            maximum_stdout=1024 * 1024,
            maximum_stderr=4096,
        )
        if completed.returncode != 0:
            raise ValueError("无法复核治理基线任务内容")
        actual_hash = hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
        if actual_hash != baseline_hash or actual_hash != TASK_29_BASELINE_SHA256:
            raise ValueError("治理基线任务内容指纹不一致")
    elif baseline_hash != TASK_29_BASELINE_SHA256:
        raise ValueError("治理基线任务内容指纹不一致")
    return {key: str(baseline[key]) for key in BASELINE_KEYS}


def _parse_contract_bytes(data: bytes) -> dict[str, object]:
    try:
        contract = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("来源身份合同不是合法JSON") from error
    if not isinstance(contract, dict):
        raise ValueError("来源身份合同必须是对象")
    return contract


def load_contract(contract_path: Path, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    """从当前业务路径加载合同，供批次外独立验证使用。"""

    contract_bytes = _read_regular_bytes(contract_path, "来源身份合同")
    raw_contract = _parse_contract_bytes(contract_bytes)
    input_bytes: dict[str, bytes] = {}
    inputs = raw_contract.get("输入文件")
    if isinstance(inputs, list):
        for item in inputs:
            if not isinstance(item, dict) or not isinstance(item.get("路径"), str):
                continue
            relative = str(item["路径"])
            path = _resolve_repository_file(repo_root, relative, "输入文件")
            input_bytes[relative] = _read_regular_bytes(path, "输入文件")
    return _load_contract_from_bytes(contract_bytes, input_bytes, repo_root)


def load_contract_from_snapshot(
    snapshot: Mapping[str, object],
    repo_root: Path,
) -> dict[str, object]:
    """只消费执行快照保存的合同和输入字节，不回读业务路径。"""

    contract_bytes = snapshot.get("配置字节")
    input_bytes = snapshot.get("输入字节")
    if not isinstance(contract_bytes, bytes) or not isinstance(input_bytes, dict):
        raise ValueError("执行快照合同字节无效")
    if not all(isinstance(key, str) and isinstance(value, bytes) for key, value in input_bytes.items()):
        raise ValueError("执行快照输入字节无效")
    return _load_contract_from_bytes(contract_bytes, input_bytes, repo_root)


def _load_contract_from_bytes(
    contract_bytes: bytes,
    input_bytes: Mapping[str, bytes],
    repo_root: Path,
) -> dict[str, object]:
    contract = _parse_contract_bytes(contract_bytes)
    _require_exact_keys(contract, CONTRACT_KEYS, "来源身份合同")
    if contract["合同版本"] != CONTRACT_VERSION:
        raise ValueError("来源身份合同版本不受支持")
    if contract["任务编号"] != "任务-000029":
        raise ValueError("来源身份合同任务编号漂移")
    _validate_governance_baseline(contract["治理基线"], repo_root)
    _require_exact_string_list(contract["候选资产类型"], ALLOWED_ASSET_TYPES, "候选资产类型")
    _require_exact_string_list(contract["标的"], TARGETS, "标的")
    _require_exact_string_list(contract["身份字段"], IDENTITY_FIELDS, "身份字段")
    _require_exact_string_list(contract["允许状态"], STATES, "允许状态")
    _require_exact_string_list(contract["允许SSH目标"], ["ubuntu"], "允许SSH目标")
    _require_exact_string_list(contract["允许文件根目录"], ALLOWED_FILE_ROOTS, "允许文件根目录")
    _require_exact_string_list(
        contract["数据库元数据范围"],
        APPROVED_DATABASE_METADATA,
        "数据库元数据范围",
    )

    inputs = contract["输入文件"]
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("输入文件必须是非空列表")
    input_fingerprints: dict[str, str] = {}
    identity_evidence: dict[str, dict[str, dict[str, object]]] = {}
    purposes: set[str] = set()
    paths: set[str] = set()
    inventory_bytes: bytes | None = None
    for item in inputs:
        if not isinstance(item, dict):
            raise ValueError("输入文件成员必须是对象")
        _require_exact_keys(item, INPUT_KEYS, "输入文件成员")
        purpose = item["用途"]
        relative = item["路径"]
        expected = item["SHA-256"]
        if not isinstance(purpose, str) or not purpose or purpose in purposes:
            raise ValueError("输入文件用途必须非空且唯一")
        purposes.add(purpose)
        if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
            raise ValueError("输入文件指纹格式非法")
        if not isinstance(relative, str) or not relative or relative in paths:
            raise ValueError("输入文件路径必须非空且唯一")
        paths.add(relative)
        frozen_bytes = input_bytes.get(relative)
        if not isinstance(frozen_bytes, bytes):
            raise ValueError("执行快照缺少冻结输入字节")
        if bytes_fingerprint(frozen_bytes) != expected:
            raise ValueError(f"输入文件指纹漂移：{purpose}")
        if purpose in input_fingerprints:
            raise ValueError("输入文件用途不得重复")
        input_fingerprints[purpose] = expected
        if purpose.startswith("身份合同证据:"):
            identity_evidence[purpose] = _load_identity_evidence_bytes(frozen_bytes)
        if purpose == "资产清单":
            inventory_bytes = frozen_bytes
    if "资产清单" not in purposes:
        raise ValueError("输入文件缺少资产清单")

    resources = contract["资源上限"]
    if not isinstance(resources, dict):
        raise ValueError("资源上限必须是对象")
    _require_exact_keys(resources, RESOURCE_KEYS, "资源上限")
    bounds = {
        "批次总超时秒": (10, 3600),
        "逐成员超时秒": (1, 30),
        "最大成员数": (2, 10_000),
        "最大输出字节数": (1024, 64 * 1024 * 1024),
        "最大日志字节数": (256, 1024 * 1024),
    }
    for name, (minimum, maximum) in bounds.items():
        value = resources[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name}必须是整数")
        if value < minimum or value > maximum:
            raise ValueError(f"{name}超出安全范围")
    if resources["逐成员超时秒"] >= resources["批次总超时秒"]:
        raise ValueError("逐成员超时必须小于批次总超时")

    safety = contract["安全边界"]
    if not isinstance(safety, dict):
        raise ValueError("安全边界必须是对象")
    _require_exact_keys(safety, SAFETY_KEYS, "安全边界")
    if any(safety[name] is not False for name in SAFETY_KEYS):
        raise ValueError("安全边界不得授权写入、正文读取或原始数据修改")
    if inventory_bytes is None:
        raise ValueError("执行快照缺少冻结资产清单")
    member_fingerprints = {
        str(member["资产编号"]): str(member["输入成员SHA-256"])
        for member in build_members_from_inventory_bytes(inventory_bytes, contract)
    }
    _validate_claims(
        contract["身份声明"],
        input_fingerprints,
        member_fingerprints,
        identity_evidence,
    )
    if _contains_sensitive(canonical_json(contract)):
        raise ValueError("来源身份合同包含地址、用户名或敏感信息")
    return contract


def _load_inventory_bytes(data: bytes) -> list[dict[str, str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("资产清单编码非法") from error
    with io.StringIO(text, newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INVENTORY_COLUMNS:
            raise ValueError("资产清单列与冻结合同不一致")
        rows = [{key: value or "" for key, value in row.items()} for row in reader]
    asset_ids = [row["资产编号"] for row in rows]
    if len(asset_ids) != len(set(asset_ids)):
        raise ValueError("资产清单资产编号重复")
    return rows


def _load_inventory(path: Path) -> list[dict[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("资产清单必须是普通文件")
    return _load_inventory_bytes(path.read_bytes())


def _candidate_rows_from_rows(
    inventory_rows: Sequence[Mapping[str, str]],
    contract: Mapping[str, object],
) -> list[dict[str, str]]:
    allowed_types = set(contract["候选资产类型"])
    rows = [dict(row) for row in inventory_rows if row["资产类型"] in allowed_types]
    if not rows:
        raise ValueError("资产清单没有候选数据对象")
    maximum = int(contract["资源上限"]["最大成员数"])
    if len(rows) * len(TARGETS) > maximum:
        raise ValueError("来源身份成员数超过冻结资源上限")
    for row in rows:
        if not ASSET_ID_PATTERN.fullmatch(row["资产编号"]):
            raise ValueError("候选资产编号格式非法")
        if row["逻辑主机"] != "ubuntu":
            raise ValueError("候选资产包含未授权逻辑主机")
    return sorted(rows, key=lambda row: row["资产编号"])


def _candidate_rows(
    inventory_path: Path,
    contract: Mapping[str, object],
) -> list[dict[str, str]]:
    return _candidate_rows_from_rows(_load_inventory(inventory_path), contract)


def build_members(
    inventory_path: Path,
    contract: Mapping[str, object],
) -> list[dict[str, object]]:
    """按资产与BTC、ETH笛卡尔积形成不猜测身份的冻结成员。"""

    return _build_members_from_rows(_candidate_rows(inventory_path, contract))


def _build_members_from_rows(
    rows: Sequence[Mapping[str, str]],
) -> list[dict[str, object]]:
    members: list[dict[str, object]] = []
    for row in rows:
        frozen_input = {
            "资产编号": row["资产编号"],
            "资产类型": row["资产类型"],
            "逻辑主机": row["逻辑主机"],
            "服务或项目": row["服务或项目"],
            "资源名称": row["资源名称"],
            "位置": row["位置"],
            "格式": row["格式"],
            "字节数": row["字节数"],
            "最后修改时间": row["最后修改时间"],
        }
        input_hash = object_fingerprint(frozen_input)
        for target in TARGETS:
            identity = {
                "资产编号": row["资产编号"],
                "标的": target,
                "输入成员SHA-256": input_hash,
            }
            members.append(
                {
                    "成员编号": "ZI-" + object_fingerprint(identity)[:24],
                    "资产编号": row["资产编号"],
                    "资产类型": row["资产类型"],
                    "标的": target,
                    "来源提供者": "未知",
                    "交易场所": "未知",
                    "市场类型": "未知",
                    "标的身份": "未知",
                    "精确合约": "未知",
                    "数据对象": "未知",
                    "Schema确切版本": "未知",
                    "授权边界": "未知",
                    "字段中文映射": "未知",
                    "输入成员SHA-256": input_hash,
                }
            )
    return members


def build_members_from_inventory_bytes(
    inventory_bytes: bytes,
    contract: Mapping[str, object],
) -> list[dict[str, object]]:
    rows = _candidate_rows_from_rows(_load_inventory_bytes(inventory_bytes), contract)
    return _build_members_from_rows(rows)


def _is_allowed_file_path(path: str, roots: Sequence[str]) -> bool:
    candidate = PurePosixPath(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return False
    return any(candidate == PurePosixPath(root) or PurePosixPath(root) in candidate.parents for root in roots)


def build_probe_assets(
    inventory_path: Path,
    contract: Mapping[str, object],
) -> list[dict[str, str]]:
    """从冻结清单生成最小只读元数据复核请求。"""

    return _build_probe_assets_from_rows(_candidate_rows(inventory_path, contract), contract)


def build_probe_assets_from_inventory_bytes(
    inventory_bytes: bytes,
    contract: Mapping[str, object],
) -> list[dict[str, str]]:
    rows = _candidate_rows_from_rows(_load_inventory_bytes(inventory_bytes), contract)
    return _build_probe_assets_from_rows(rows, contract)


def _build_probe_assets_from_rows(
    rows: Sequence[Mapping[str, str]],
    contract: Mapping[str, object],
) -> list[dict[str, str]]:

    assets: list[dict[str, str]] = []
    roots = list(contract["允许文件根目录"])
    for row in rows:
        item = {
            "资产编号": row["资产编号"],
            "资产类型": row["资产类型"],
            "位置": row["位置"],
            "格式": row["格式"],
            "字节数": row["字节数"],
            "最后修改时间": row["最后修改时间"],
            "数据库Schema": "",
            "数据库表": "",
        }
        if row["资产类型"] == "候选数据文件":
            if not _is_allowed_file_path(row["位置"], roots):
                raise ValueError("候选文件位置超出冻结白名单")
        else:
            match = MYSQL_LOCATION_PATTERN.fullmatch(row["位置"])
            if match is None:
                raise ValueError("数据库元数据位置格式非法")
            item["数据库Schema"] = match.group("schema")
            item["数据库表"] = match.group("table")
        assets.append(item)
    return sorted(assets, key=lambda item: item["资产编号"])


def build_probe_script(
    assets: Sequence[Mapping[str, str]],
    contract: Mapping[str, object],
) -> str:
    """构造不落远端文件、只读取stat和获批information_schema的探针。"""

    request_json = canonical_json(list(assets))
    roots_json = canonical_json(list(contract["允许文件根目录"]))
    member_timeout = int(contract["资源上限"]["逐成员超时秒"])
    maximum_remote_stdout = int(contract["资源上限"]["最大输出字节数"])
    maximum_remote_stderr = int(contract["资源上限"]["最大日志字节数"])
    database_pairs = sorted(
        {
            (asset["数据库Schema"], asset["数据库表"])
            for asset in assets
            if asset["资产类型"] == "数据库元数据"
        }
    )
    metadata_filter = " OR ".join(
        f"(t.TABLE_SCHEMA='{schema}' AND t.TABLE_NAME='{table}')"
        for schema, table in database_pairs
    ) or "1=0"
    return textwrap.dedent(
        f'''\
        import datetime as dt
        import hashlib
        import json
        import os
        import selectors
        import signal
        import stat
        import subprocess
        import time

        PROBE_VERSION = {PROBE_VERSION!r}
        ASSETS = json.loads({request_json!r})
        ALLOWED_ROOTS = json.loads({roots_json!r})
        MEMBER_TIMEOUT = {member_timeout}
        MAXIMUM_STDOUT = {maximum_remote_stdout}
        MAXIMUM_STDERR = {maximum_remote_stderr}
        DB_ROW_LIMIT = 200000
        METADATA_FILTER = {metadata_filter!r}
        SAFE_ENV = {{
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent",
            "MYSQL_TEST_LOGIN_FILE": "/nonexistent/.mylogin.cnf",
            "PYTHONDONTWRITEBYTECODE": "1",
        }}

        def fingerprint(value):
            encoded = json.dumps(
                value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()

        def alarm_handler(_signum, _frame):
            raise TimeoutError("member timeout")

        signal.signal(signal.SIGALRM, alarm_handler)

        schema_sql = (
            "SELECT CONCAT('H',HEX(t.TABLE_SCHEMA)),CONCAT('H',HEX(t.TABLE_NAME)),"
            "CONCAT('H',HEX(COALESCE(t.ENGINE,''))),"
            "IF(t.TABLE_COLLATION IS NULL,'N',CONCAT('H',HEX(t.TABLE_COLLATION))),"
            "CONCAT('H',HEX(COALESCE(t.ROW_FORMAT,''))),"
            "CONCAT('H',HEX(COALESCE(t.CREATE_OPTIONS,''))),"
            "CONCAT('V',c.ORDINAL_POSITION),CONCAT('H',HEX(c.COLUMN_NAME)),"
            "CONCAT('H',HEX(c.COLUMN_TYPE)),CONCAT('H',HEX(c.IS_NULLABLE)),"
            "IF(c.COLUMN_DEFAULT IS NULL,'N',CONCAT('H',HEX(c.COLUMN_DEFAULT))),"
            "IF(c.CHARACTER_SET_NAME IS NULL,'N',CONCAT('H',HEX(c.CHARACTER_SET_NAME))),"
            "IF(c.COLLATION_NAME IS NULL,'N',CONCAT('H',HEX(c.COLLATION_NAME))),"
            "CONCAT('H',HEX(COALESCE(c.COLUMN_KEY,''))),"
            "IF(c.NUMERIC_PRECISION IS NULL,'N',CONCAT('V',c.NUMERIC_PRECISION)),"
            "IF(c.NUMERIC_SCALE IS NULL,'N',CONCAT('V',c.NUMERIC_SCALE)),"
            "IF(c.DATETIME_PRECISION IS NULL,'N',CONCAT('V',c.DATETIME_PRECISION)),"
            "CONCAT('H',HEX(COALESCE(c.EXTRA,''))),"
            "CONCAT('H',HEX(COALESCE(c.GENERATION_EXPRESSION,''))),"
            "CONCAT('H',HEX(COALESCE(c.COLUMN_COMMENT,''))) "
            "FROM information_schema.TABLES t JOIN information_schema.COLUMNS c "
            "ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME "
            "WHERE " + METADATA_FILTER + " "
            "ORDER BY t.TABLE_SCHEMA,t.TABLE_NAME,c.ORDINAL_POSITION LIMIT "
            + str(DB_ROW_LIMIT + 1)
        )

        def bounded_process(arguments, timeout, maximum_stdout, maximum_stderr):
            selector = None
            try:
                process = subprocess.Popen(
                    arguments,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=SAFE_ENV,
                )
            except OSError:
                return None
            try:
                selector = selectors.DefaultSelector()
                stdout = bytearray()
                stderr = bytearray()
                deadline = time.monotonic() + timeout
                selector.register(process.stdout, selectors.EVENT_READ, (stdout, maximum_stdout))
                selector.register(process.stderr, selectors.EVENT_READ, (stderr, maximum_stderr))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        process.kill()
                        process.wait()
                        return None
                    events = selector.select(min(remaining, 0.1))
                    for key, _mask in events:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target, maximum = key.data
                        target.extend(chunk)
                        if len(target) > maximum:
                            process.kill()
                            process.wait()
                            return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    return None
                returncode = process.wait(timeout=remaining)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait()
                return None
            finally:
                try:
                    if process.poll() is None:
                        process.kill()
                finally:
                    try:
                        process.wait()
                    finally:
                        try:
                            if selector is not None:
                                selector.close()
                        finally:
                            try:
                                if process.stdout is not None:
                                    process.stdout.close()
                            finally:
                                if process.stderr is not None:
                                    process.stderr.close()
            if returncode != 0:
                return None
            try:
                return bytes(stdout).decode("utf-8", errors="strict").splitlines()
            except UnicodeDecodeError:
                return None

        def mysql_lines(sql):
            return bounded_process(
                [
                    "mysql", "--no-defaults", "--batch", "--raw",
                    "--skip-column-names", "--protocol=SOCKET",
                    "--connect-timeout=3", "-e", sql,
                ],
                MEMBER_TIMEOUT,
                MAXIMUM_STDOUT,
                MAXIMUM_STDERR,
            )

        def decode_text(encoded, nullable=False):
            if encoded == "N":
                if nullable:
                    return None
                raise ValueError("unexpected null")
            if not encoded.startswith("H") or len(encoded[1:]) % 2:
                raise ValueError("invalid hex")
            return bytes.fromhex(encoded[1:]).decode("utf-8", errors="strict")

        def decode_number(encoded):
            if encoded == "N":
                return None
            if not encoded.startswith("V") or not encoded[1:].isdigit():
                raise ValueError("invalid number")
            return int(encoded[1:])

        tables = {{}}
        schema_valid = True
        schema_lines = [] if METADATA_FILTER == "1=0" else mysql_lines(schema_sql)
        if schema_lines is None or len(schema_lines) >= DB_ROW_LIMIT + 1:
            schema_valid = False
        if schema_valid:
            try:
                for line in schema_lines:
                    fields = line.split("\\t")
                    if len(fields) != 20:
                        raise ValueError("invalid field count")
                    key = (decode_text(fields[0]), decode_text(fields[1]))
                    if key not in {database_pairs!r}:
                        raise ValueError("unexpected table")
                    table_metadata = [
                        decode_text(fields[2]), decode_text(fields[3], True),
                        decode_text(fields[4]), decode_text(fields[5]),
                    ]
                    column = [
                        decode_number(fields[6]), decode_text(fields[7]),
                        decode_text(fields[8]), decode_text(fields[9]),
                        decode_text(fields[10], True), decode_text(fields[11], True),
                        decode_text(fields[12], True), decode_text(fields[13]),
                        decode_number(fields[14]), decode_number(fields[15]),
                        decode_number(fields[16]), decode_text(fields[17]),
                        decode_text(fields[18]), decode_text(fields[19]),
                    ]
                    entry = tables.setdefault(key, {{"table": table_metadata, "columns": []}})
                    if entry["table"] != table_metadata:
                        raise ValueError("table metadata drift")
                    if column[0] != len(entry["columns"]) + 1:
                        raise ValueError("invalid ordinal")
                    if any(existing[1] == column[1] for existing in entry["columns"]):
                        raise ValueError("duplicate column")
                    entry["columns"].append(column)
                if any(key not in tables or not tables[key]["columns"] for key in {database_pairs!r}):
                    raise ValueError("missing table columns")
            except (UnicodeDecodeError, ValueError):
                schema_valid = False
                tables = {{}}

        results = []
        for asset in ASSETS:
            asset_id = asset["资产编号"]
            try:
                signal.setitimer(signal.ITIMER_REAL, MEMBER_TIMEOUT)
                if asset["资产类型"] == "候选数据文件":
                    path = asset["位置"]
                    real_path = os.path.realpath(path)
                    allowed = any(
                        os.path.commonpath((root, real_path)) == root
                        for root in ALLOWED_ROOTS
                    )
                    if not allowed or os.path.islink(path):
                        result = {{
                            "资产编号": asset_id,
                            "复核状态": "拒绝",
                            "元数据SHA-256": "",
                            "SchemaSHA-256": "",
                            "证据": "资源越界或为符号链接",
                            "限制": "未读取文件正文",
                        }}
                    else:
                        stat_result = os.lstat(path)
                        is_regular = stat.S_ISREG(stat_result.st_mode)
                        modified_at = dt.datetime.fromtimestamp(
                            stat_result.st_mtime
                        ).astimezone().isoformat()
                        metadata = {{
                            "资产编号": asset_id,
                            "资产类型": asset["资产类型"],
                            "字节数": str(stat_result.st_size),
                            "最后修改时间": modified_at,
                            "文件类型": "普通文件" if is_regular else "非普通文件",
                            "模式": format(stat.S_IMODE(stat_result.st_mode), "04o"),
                        }}
                        matches = (
                            is_regular
                            and str(stat_result.st_size) == asset["字节数"]
                            and modified_at == asset["最后修改时间"]
                        )
                        result = {{
                            "资产编号": asset_id,
                            "复核状态": "已观察" if matches else "拒绝",
                            "元数据SHA-256": fingerprint(metadata),
                            "SchemaSHA-256": "",
                            "证据": (
                                "白名单普通文件stat元数据与冻结输入一致"
                                if matches
                                else (
                                    "资源不是普通文件"
                                    if not is_regular else "冻结文件元数据漂移"
                                )
                            ),
                            "限制": "未读取文件正文",
                        }}
                else:
                    key = (asset["数据库Schema"], asset["数据库表"])
                    if not schema_valid or key not in tables:
                        result = {{
                            "资产编号": asset_id,
                            "复核状态": "无法判定",
                            "元数据SHA-256": "",
                            "SchemaSHA-256": "",
                            "证据": "获批数据库元数据查询不可用或超时",
                            "限制": "未读取数据库业务记录",
                        }}
                    else:
                        metadata = {{
                            "资产编号": asset_id,
                            "Schema": key[0],
                            "表": key[1],
                            "表元数据": tables[key]["table"],
                        }}
                        matches = tables[key]["table"][0] == asset["格式"]
                        result = {{
                            "资产编号": asset_id,
                            "复核状态": "已观察" if matches else "拒绝",
                            "元数据SHA-256": fingerprint(metadata),
                            "SchemaSHA-256": fingerprint(tables[key]),
                            "证据": (
                                "获批information_schema元数据与冻结输入一致"
                                if matches else "冻结数据库元数据漂移"
                            ),
                            "限制": "未读取数据库业务记录",
                        }}
            except FileNotFoundError:
                result = {{
                    "资产编号": asset_id,
                    "复核状态": "拒绝",
                    "元数据SHA-256": "",
                    "SchemaSHA-256": "",
                    "证据": "冻结资源不存在",
                    "限制": "未读取业务正文",
                }}
            except (OSError, TimeoutError):
                result = {{
                    "资产编号": asset_id,
                    "复核状态": "无法判定",
                    "元数据SHA-256": "",
                    "SchemaSHA-256": "",
                    "证据": "逐成员元数据复核失败或超时",
                    "限制": "未扩大读取范围",
                }}
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
            results.append(result)

        print(json.dumps({{
            "探针版本": PROBE_VERSION,
            "远端写入": False,
            "数据库业务记录读取": False,
            "结果": results,
        }}, ensure_ascii=False, sort_keys=True))
        '''
    )


def validate_probe_result(
    payload: object,
    assets: Sequence[Mapping[str, str]],
) -> dict[str, object]:
    """拒绝不完整、越权或状态不受支持的远端探针结果。"""

    if not isinstance(payload, dict):
        raise ValueError("远端探针结果必须是对象")
    if set(payload) != {"探针版本", "远端写入", "数据库业务记录读取", "结果"}:
        raise ValueError("远端探针结果结构不符合固定合同")
    if payload["探针版本"] != PROBE_VERSION:
        raise ValueError("远端探针版本漂移")
    if payload["远端写入"] is not False or payload["数据库业务记录读取"] is not False:
        raise ValueError("远端探针越过只读元数据边界")
    results = payload["结果"]
    if not isinstance(results, list):
        raise ValueError("远端探针结果集合必须是列表")
    expected_ids = sorted(asset["资产编号"] for asset in assets)
    asset_types = {
        str(asset["资产编号"]): str(asset.get("资产类型", ""))
        for asset in assets
    }
    observed_ids: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("远端探针结果成员必须是对象")
        if set(result) != {
            "资产编号",
            "复核状态",
            "元数据SHA-256",
            "SchemaSHA-256",
            "证据",
            "限制",
        }:
            raise ValueError("远端探针结果结构不符合固定合同")
        observed_ids.append(str(result["资产编号"]))
        if result["复核状态"] not in {"已观察", "拒绝", "无法判定"}:
            raise ValueError("远端探针复核状态非法")
        for field in ("元数据SHA-256", "SchemaSHA-256"):
            value = result[field]
            if not isinstance(value, str) or (value and not SHA256_PATTERN.fullmatch(value)):
                raise ValueError("远端探针指纹格式非法")
        if result["复核状态"] == "已观察" and not result["元数据SHA-256"]:
            raise ValueError("已观察结果缺少元数据指纹")
        asset_type = asset_types.get(str(result["资产编号"]), "")
        if result["复核状态"] == "已观察" and asset_type == "数据库元数据":
            if not result["SchemaSHA-256"]:
                raise ValueError("数据库已观察结果必须包含Schema指纹")
        if result["复核状态"] == "已观察" and asset_type == "候选数据文件":
            if result["SchemaSHA-256"]:
                raise ValueError("文件已观察结果不得包含伪造Schema指纹")
        if not isinstance(result["证据"], str) or not result["证据"]:
            raise ValueError("远端探针结果缺少证据")
        if not isinstance(result["限制"], str) or not result["限制"]:
            raise ValueError("远端探针结果缺少限制")
        if _contains_sensitive(str(result["证据"]) + "\n" + str(result["限制"])):
            raise ValueError("远端探针结果包含地址、用户名或敏感信息")
    if sorted(observed_ids) != expected_ids or len(observed_ids) != len(set(observed_ids)):
        raise ValueError("远端探针结果未完整覆盖冻结资产")
    return payload


def _identity_sort_key(row: Mapping[str, object]) -> tuple[str, ...]:
    return (
        str(row["来源提供者"]),
        str(row["交易场所"]),
        str(row["市场类型"]),
        str(row["标的"]),
        str(row["精确合约"]),
        str(row["数据对象"]),
        str(row["Schema确切版本"]),
        str(row["资产编号"]),
        str(row["成员编号"]),
    )


def evaluate_identities(
    members: Sequence[Mapping[str, object]],
    probe_payload: object,
    contract: Mapping[str, object],
) -> tuple[list[dict[str, str]], dict[str, object]]:
    """将只读元数据复核与冻结证据声明合并为保守三态结果。"""

    asset_ids = sorted({str(member["资产编号"]) for member in members})
    type_by_asset = {
        str(member["资产编号"]): str(member["资产类型"])
        for member in members
    }
    assets = [
        {"资产编号": asset_id, "资产类型": type_by_asset[asset_id]}
        for asset_id in asset_ids
    ]
    payload = validate_probe_result(probe_payload, assets)
    probe_by_id = {str(item["资产编号"]): item for item in payload["结果"]}
    claims = {
        (str(claim["资产编号"]), str(claim["标的"])): claim
        for claim in contract["身份声明"]
    }
    member_keys = {(str(member["资产编号"]), str(member["标的"])) for member in members}
    unknown_claims = sorted(set(claims) - member_keys)
    if unknown_claims:
        raise ValueError("身份声明引用了冻结成员之外的资产")

    rows: list[dict[str, str]] = []
    for member in members:
        asset_id = str(member["资产编号"])
        target = str(member["标的"])
        probe = probe_by_id[asset_id]
        claim = claims.get((asset_id, target))
        row = {key: str(value) for key, value in member.items()}
        row.update(
            {
                "状态": "无法判定",
                "证据": str(probe["证据"]),
                "限制": str(probe["限制"]),
                "解除条件": "提供并冻结来源、场所、市场、标的、合约、数据对象、Schema、授权和字段映射证据",
                "远端元数据SHA-256": str(probe["元数据SHA-256"]) or "未知",
            }
        )
        if claim is not None and claim["状态"] == "拒绝":
            row["状态"] = "拒绝"
            row["证据"] = canonical_json(claim["证据"])
            row["限制"] = str(claim["限制"])
            row["解除条件"] = str(claim["解除条件"])
        elif probe["复核状态"] == "拒绝":
            row["状态"] = "拒绝"
            row["解除条件"] = "重新发现并冻结与只读元数据一致的候选资产版本"
        elif probe["复核状态"] == "已观察" and claim is not None:
            if claim["远端元数据SHA-256"] != probe["元数据SHA-256"]:
                row["状态"] = "拒绝"
                row["证据"] = "冻结身份声明与本批次元数据指纹不一致"
                row["限制"] = "身份声明已失效，不选择任一冲突值"
                row["解除条件"] = "复核来源证据并创建新的不可变身份声明版本"
            elif probe["SchemaSHA-256"] and claim["Schema确切版本"] != (
                "sha256:" + str(probe["SchemaSHA-256"])
            ):
                row["状态"] = "拒绝"
                row["证据"] = "冻结身份声明与本批次Schema指纹不一致"
                row["限制"] = "Schema声明已失效，不选择任一冲突值"
                row["解除条件"] = "复核Schema证据并创建新的不可变身份声明版本"
            else:
                row["状态"] = "已证明"
                for field in IDENTITY_FIELDS[:-1]:
                    row[field] = str(claim[field])
                row["字段中文映射"] = canonical_json(claim["字段中文映射"])
                row["证据"] = canonical_json(claim["证据"])
                row["限制"] = str(claim["限制"])
                row["解除条件"] = str(claim["解除条件"])
        record_without_hash = dict(row)
        row["身份记录SHA-256"] = object_fingerprint(record_without_hash)
        rows.append(row)
    rows.sort(key=_identity_sort_key)

    state_counts = Counter(row["状态"] for row in rows)
    if set(state_counts) - set(STATES):
        raise ValueError("身份结果出现合同外状态")
    normalized_counts = {state: state_counts.get(state, 0) for state in STATES}
    if sum(normalized_counts.values()) != len(rows):
        raise ValueError("来源身份三态计数不守恒")
    per_target: dict[str, dict[str, int]] = {}
    for target in TARGETS:
        target_counts = Counter(row["状态"] for row in rows if row["标的"] == target)
        per_target[target] = {state: target_counts.get(state, 0) for state in STATES}
        if sum(per_target[target].values()) != len(asset_ids):
            raise ValueError(f"{target}身份三态计数不守恒")
    summary: dict[str, object] = {
        "候选资产总体": len(asset_ids),
        "身份成员总体": len(rows),
        "三态计数": normalized_counts,
        "分标的三态计数": per_target,
        "结论边界": "来源身份结果不构成质量通过、研究准入、收益结论或交易许可",
    }
    return rows, summary


def build_ssh_command(ssh_bin: str, target: str, timeout: int) -> list[str]:
    if not SSH_TARGET_PATTERN.fullmatch(target) or target != "ubuntu":
        raise ValueError("SSH目标只允许逻辑别名ubuntu")
    if timeout < 10 or timeout > 3600:
        raise ValueError("SSH批次超时超出安全范围")
    connect_timeout = min(30, max(1, timeout // 4))
    return [
        ssh_bin,
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        target,
        "env",
        "-i",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/nonexistent",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONDONTWRITEBYTECODE=1",
        "python3",
        "-I",
        "-B",
        "-",
    ]


def run_bounded_process(
    command: Sequence[str],
    *,
    input_text: str,
    timeout: float,
    maximum_stdout: int,
    maximum_stderr: int,
    popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> subprocess.CompletedProcess:
    """流式读取子进程输出，超时或超限时立即终止且不回显正文。"""

    if timeout <= 0 or maximum_stdout < 1 or maximum_stderr < 1:
        raise ValueError("有界子进程资源上限非法")
    encoded_input = input_text.encode("utf-8")
    with tempfile.TemporaryFile(mode="w+b") as input_handle:
        input_handle.write(encoded_input)
        input_handle.seek(0)
        selector = None
        try:
            process = popen_factory(
                list(command),
                stdin=input_handle,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise RuntimeError("只读元数据复核失败：命令不可用，未发布批次") from error
        try:
            selector = selectors.DefaultSelector()
            stdout = bytearray()
            stderr = bytearray()
            deadline = time.monotonic() + timeout
            if process.stdout is None or process.stderr is None:
                process.kill()
                process.wait()
                raise RuntimeError("只读元数据复核失败：输出管道不可用，未发布批次")
            selector.register(process.stdout, selectors.EVENT_READ, (stdout, maximum_stdout, "输出"))
            selector.register(process.stderr, selectors.EVENT_READ, (stderr, maximum_stderr, "日志"))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    process.wait()
                    raise RuntimeError("只读元数据复核失败：批次超时，未发布批次")
                events = selector.select(min(remaining, 0.1))
                for key, _mask in events:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target, maximum, label = key.data
                    target.extend(chunk)
                    if len(target) > maximum:
                        process.kill()
                        process.wait()
                        raise RuntimeError(
                            f"只读元数据复核失败：{label}超过冻结上限，未发布批次"
                        )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise RuntimeError("只读元数据复核失败：批次超时，未发布批次")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait()
                raise RuntimeError("只读元数据复核失败：批次超时，未发布批次") from error
        except OSError as error:
            process.kill()
            process.wait()
            raise RuntimeError("只读元数据复核失败：流式读取失败，未发布批次") from error
        finally:
            try:
                if process.poll() is None:
                    process.kill()
            finally:
                try:
                    process.wait()
                finally:
                    try:
                        if selector is not None:
                            selector.close()
                    finally:
                        try:
                            if process.stdout is not None:
                                process.stdout.close()
                        finally:
                            if process.stderr is not None:
                                process.stderr.close()
    return subprocess.CompletedProcess(
        list(command),
        returncode,
        stdout=bytes(stdout).decode("utf-8", errors="replace"),
        stderr=bytes(stderr).decode("utf-8", errors="replace"),
    )


def safe_csv_cell(value: object) -> str:
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def _render_csv(rows: Sequence[Mapping[str, str]], batch_id: str) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        output_row = {"来源身份批次": batch_id, **row}
        writer.writerow({column: safe_csv_cell(output_row[column]) for column in OUTPUT_COLUMNS})
    return output.getvalue()


def _input_fingerprints(contract: Mapping[str, object]) -> dict[str, str]:
    return {
        str(item["路径"]): str(item["SHA-256"])
        for item in contract["输入文件"]
    }


def _asset_inventory_path(
    contract: Mapping[str, object], repo_root: Path
) -> Path:
    item = next(item for item in contract["输入文件"] if item["用途"] == "资产清单")
    return _resolve_repository_file(repo_root, item["路径"], "资产清单")


def _scan_outputs(paths: Sequence[Path]) -> None:
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if _contains_sensitive(text):
            raise ValueError("来源身份输出包含地址、用户名或敏感信息")


def atomic_publish_directory_no_replace(source: Path, target: Path) -> None:
    """以操作系统原子no-clobber重命名发布目录；不支持时失败关闭。"""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    result: int
    if sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        if rename is None:
            raise OSError(errno.ENOTSUP, "原子no-clobber发布不可用")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-2, source_bytes, -2, target_bytes, 0x00000004)
    elif sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise OSError(errno.ENOTSUP, "原子no-clobber发布不可用")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, target_bytes, 0x00000001)
    else:
        raise OSError(errno.ENOTSUP, "原子no-clobber发布不支持当前平台")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, "不可变来源身份批次已存在")
    raise OSError(error_number, "原子no-clobber发布失败")


def execute_batch(
    contract_path: Path,
    ssh_target: str,
    batch_root: Path,
    timeout: int,
    *,
    repo_root: Path = REPO_ROOT,
    ssh_bin: str = "ssh",
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
    now: dt.datetime | None = None,
) -> Path:
    """执行一次有界只读复核并原子发布不可覆盖的本地身份批次。"""

    snapshot = capture_execution_snapshot(contract_path, repo_root)
    contract = load_contract_from_snapshot(snapshot, repo_root)
    assert_execution_snapshot(snapshot)
    if ssh_target not in contract["允许SSH目标"]:
        raise ValueError("SSH目标不在冻结合同白名单")
    maximum_timeout = int(contract["资源上限"]["批次总超时秒"])
    if timeout < 10 or timeout > maximum_timeout:
        raise ValueError("批次超时超出冻结资源上限")
    purpose_bytes = snapshot["用途输入字节"]
    if not isinstance(purpose_bytes, dict) or not isinstance(
        purpose_bytes.get("资产清单"), bytes
    ):
        raise ValueError("执行快照缺少冻结资产清单")
    inventory_bytes = purpose_bytes["资产清单"]
    assets = build_probe_assets_from_inventory_bytes(inventory_bytes, contract)
    members = build_members_from_inventory_bytes(inventory_bytes, contract)
    probe_script = build_probe_script(assets, contract)
    command = build_ssh_command(ssh_bin, ssh_target, timeout)
    assert_execution_snapshot(snapshot)
    if runner is None:
        completed = run_bounded_process(
            command,
            input_text=probe_script,
            timeout=timeout,
            maximum_stdout=int(contract["资源上限"]["最大输出字节数"]),
            maximum_stderr=int(contract["资源上限"]["最大日志字节数"]),
        )
    else:
        try:
            completed = runner(
                command,
                input=probe_script,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("只读元数据复核失败：批次超时，未发布批次") from error
        except OSError as error:
            raise RuntimeError("只读元数据复核失败：SSH客户端不可用，未发布批次") from error
    assert_execution_snapshot(snapshot)
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    maximum_output = int(contract["资源上限"]["最大输出字节数"])
    maximum_log = int(contract["资源上限"]["最大日志字节数"])
    if len(stderr.encode("utf-8")) > maximum_log:
        raise RuntimeError("只读元数据复核失败：日志超过冻结上限，未发布批次")
    if len(stdout.encode("utf-8")) > maximum_output:
        raise RuntimeError("只读元数据复核失败：响应超过冻结上限，未发布批次")
    if completed.returncode != 0:
        raise RuntimeError("只读元数据复核失败：远端返回非零状态，未发布批次")
    try:
        raw_probe = json.loads(stdout)
    except ValueError as error:
        raise RuntimeError("只读元数据复核失败：远端响应不是合法JSON，未发布批次") from error
    probe = validate_probe_result(raw_probe, assets)
    rows, summary = evaluate_identities(members, probe, contract)

    frozen_time = now or dt.datetime.now().astimezone()
    if frozen_time.tzinfo is None or frozen_time.utcoffset() is None:
        raise ValueError("冻结时间必须包含时区")
    content_hash = object_fingerprint(rows)
    input_hashes = dict(snapshot["输入SHA-256"])
    rule_hash = str(snapshot["规则SHA-256"])
    executor_hash = str(snapshot["执行器SHA-256"])
    member_hash = object_fingerprint(members)
    current_task_hash = str(snapshot["当前执行任务文件SHA-256"])
    batch_payload: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": contract["任务编号"],
        "治理基线": contract["治理基线"],
        "输入SHA-256": input_hashes,
        "规则SHA-256": rule_hash,
        "执行器SHA-256": executor_hash,
        "当前执行任务文件SHA-256": current_task_hash,
        "成员SHA-256": member_hash,
        "清单内容SHA-256": content_hash,
        "结果摘要": summary,
    }
    batch_payload_hash = object_fingerprint(batch_payload)
    batch_id = (
        "source-identity-"
        + frozen_time.strftime("%Y%m%dT%H%M%S%z")
        + "-"
        + batch_payload_hash[:12]
    )
    csv_text = _render_csv(rows, batch_id)
    csv_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()
    manifest: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": contract["任务编号"],
        "来源身份批次": batch_id,
        "冻结时间": frozen_time.isoformat(timespec="microseconds"),
        "SSH逻辑目标": "ubuntu",
        "远端写入": False,
        "数据库业务记录读取": False,
        "治理基线": contract["治理基线"],
        "输入SHA-256": input_hashes,
        "规则SHA-256": rule_hash,
        "执行器SHA-256": executor_hash,
        "当前执行任务文件SHA-256": current_task_hash,
        "成员SHA-256": member_hash,
        "清单内容SHA-256": content_hash,
        "批次载荷": batch_payload,
        "批次载荷SHA-256": batch_payload_hash,
        "批次载荷定义": "非递归规范JSON哈希；不包含冻结时间、批次编号、输出SHA-256或批次载荷SHA-256自身",
        "输出SHA-256": {
            "来源身份清单.csv": csv_hash,
            "身份清单.json载荷": batch_payload_hash,
        },
        "结果摘要": summary,
        "成员顺序": rows,
        "安全声明": {
            "远端不落盘": True,
            "仅复核白名单文件stat和获批information_schema元数据": True,
            "未记录主机地址用户名凭据或原始业务记录": True,
        },
        "结论边界": "本批次不完成质量、重放、成本、模型、回测、收益或交易许可",
    }
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode("utf-8")) + len(json_text.encode("utf-8")) > maximum_output:
        raise ValueError("来源身份批次输出超过冻结大小上限")

    assert_execution_snapshot(snapshot)
    if batch_root.is_symlink():
        raise ValueError("批次根目录不能是符号链接")
    batch_root.mkdir(parents=True, exist_ok=True)
    if not batch_root.is_dir():
        raise ValueError("批次根目录必须是普通目录")
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"历史来源身份批次已存在：{batch_id}")
    with tempfile.TemporaryDirectory(prefix=".source-identity-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        csv_path = staging / "来源身份清单.csv"
        json_path = staging / "身份清单.json"
        csv_path.write_text(csv_text, encoding="utf-8", newline="")
        json_path.write_text(json_text, encoding="utf-8")
        _scan_outputs([csv_path, json_path])
        assert_execution_snapshot(snapshot)
        atomic_publish_directory_no_replace(staging, target)

    print(
        json.dumps(
            {
                "状态": "成功",
                "来源身份批次": batch_id,
                "候选资产总体": summary["候选资产总体"],
                "身份成员总体": summary["身份成员总体"],
                "三态计数": summary["三态计数"],
                "分标的三态计数": summary["分标的三态计数"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description="冻结《知势》数据来源与资产身份登记批次")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT, help="冻结合同JSON")
    parser.add_argument("--ssh-target", required=True, help="固定SSH逻辑别名ubuntu")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT, help="不可变批次根目录")
    parser.add_argument("--timeout", required=True, type=int, help="批次总超时秒数")
    parser.add_argument("--ssh-bin", default="ssh", help="SSH客户端路径")
    return parser


def public_error(error: BaseException) -> tuple[str, str]:
    """将内部异常映射为不含正文、路径或cause的固定公开类别。"""

    if isinstance(error, PublicArgumentError):
        return "ZI-SI-1000", "命令行参数无效"
    if isinstance(error, FileExistsError):
        return "ZI-SI-1003", "不可变来源身份批次已存在"
    if isinstance(error, RuntimeError):
        return PUBLIC_RUNTIME_ERRORS.get(
            str(error),
            ("ZI-SI-2999", "只读元数据复核失败"),
        )
    if isinstance(error, OSError):
        return "ZI-SI-1002", "本地文件系统操作失败"
    return "ZI-SI-1001", "输入或冻结合同无效"


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = build_parser().parse_args(argv)
        execute_batch(
            arguments.contract,
            arguments.ssh_target,
            arguments.batch_root,
            arguments.timeout,
            ssh_bin=arguments.ssh_bin,
        )
        return 0
    except (
        FileExistsError,
        OSError,
        PublicArgumentError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        code, category = public_error(error)
        print(f"冻结来源身份失败：[{code}] {category}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
