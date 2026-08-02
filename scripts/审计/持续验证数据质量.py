#!/usr/bin/env python3
"""复用现有只读审计器，生成不可覆盖的数据质量验证批次。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Callable, Mapping, Sequence


SCRIPT_VERSION = "dq-continuous-1.0"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDITOR = REPO_ROOT / "scripts" / "审计" / "审计数据质量.py"
PLAN_KEYS = {
    "方案版本",
    "底层审计规则版本",
    "资产清单指纹",
    "允许SSH目标",
    "检查项",
    "状态映射",
    "作用域",
    "资源上限",
    "安全边界",
}
RESOURCE_KEYS = {"批次总超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}
SCOPE_KEYS = {"标的", "主研究尺度", "结果观察窗口", "分组维度"}
SAFETY_KEYS = {
    "远端写入",
    "远端临时文件",
    "数据库业务正文",
    "自动数据修复",
    "自动研究或交易放行",
}
EXPECTED_STATE_MAP = {
    "可用": "通过",
    "有限可用": "拒绝",
    "不可用": "拒绝",
    "无法判定": "无法判定",
}
MAIN_SCALES = ["4小时", "8小时", "24小时", "48小时"]
RESULT_WINDOWS = ["15分钟", "1小时"]
TARGETS = ["BTC", "ETH", "SOL"]
GROUP_DIMENSIONS = [
    "标的",
    "交易场所",
    "市场类型",
    "精确合约",
    "数据资产",
    "Schema确切版本",
]
MAIN_STATES = ("通过", "拒绝", "无法判定", "失败", "未成熟", "失效")
OUTPUT_NAMES = (
    "数据质量结果.csv",
    "数据断档结果.csv",
    "数据异常结果.csv",
    "验证报告.md",
)
INDEX_COLUMNS = (
    "验证批次",
    "冻结时间",
    "底层审计批次",
    "方案指纹",
    "规则指纹",
    "资产清单指纹",
    "Schema指纹",
    "作用域指纹",
    "候选总体",
    "通过",
    "拒绝",
    "无法判定",
    "失败",
    "未成熟",
    "失效",
    "前序批次",
    "比较状态",
    "清单文件指纹",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
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
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


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


def safe_csv_cell(value: object) -> str:
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def load_auditor_module(path: Path) -> ModuleType:
    if path.is_symlink():
        raise ValueError("底层审计器必须是普通文件")
    resolved = path.resolve()
    if not resolved.is_file():
        raise ValueError("底层审计器必须是普通文件")
    spec = importlib.util.spec_from_file_location("zhishi_data_quality_auditor", resolved)
    if spec is None or spec.loader is None:
        raise ValueError("底层审计器无法加载")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for attribute in (
        "RULE_VERSION",
        "QUALITY_COLUMNS",
        "GAP_COLUMNS",
        "ANOMALY_COLUMNS",
        "load_inventory",
        "build_validation_units",
        "validate_ssh_target",
    ):
        if not hasattr(module, attribute):
            raise ValueError("底层审计器合同不完整")
    return module


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unknown:
        raise ValueError(f"{label}包含未知字段：{'、'.join(unknown)}")
    if missing:
        raise ValueError(f"{label}缺少字段：{'、'.join(missing)}")


def _require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"{label}必须是非空字符串列表")
    if len(value) != len(set(value)):
        raise ValueError(f"{label}不得重复")
    return list(value)


def load_plan(plan_path: Path, inventory_path: Path, auditor_path: Path) -> dict[str, object]:
    if not plan_path.is_file() or plan_path.is_symlink():
        raise ValueError("持续验证方案必须是普通文件")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("持续验证方案不是合法JSON") from error
    if not isinstance(plan, dict):
        raise ValueError("持续验证方案必须是对象")
    _require_exact_keys(plan, PLAN_KEYS, "持续验证方案")

    if plan["方案版本"] != "dq-continuous-plan-1.0":
        raise ValueError("持续验证方案版本不受支持")
    auditor = load_auditor_module(auditor_path)
    if plan["底层审计规则版本"] != auditor.RULE_VERSION:
        raise ValueError("底层审计规则版本漂移")
    expected_inventory = str(plan["资产清单指纹"])
    if not SHA256_PATTERN.fullmatch(expected_inventory):
        raise ValueError("资产清单指纹格式非法")
    if not inventory_path.is_file() or inventory_path.is_symlink():
        raise ValueError("资产清单必须是普通文件")
    if file_fingerprint(inventory_path) != expected_inventory:
        raise ValueError("资产清单指纹与冻结方案不一致")

    targets = _require_string_list(plan["允许SSH目标"], "允许SSH目标")
    if targets != ["ubuntu"]:
        raise ValueError("SSH目标只允许逻辑别名ubuntu")
    _require_string_list(plan["检查项"], "检查项")
    if plan["状态映射"] != EXPECTED_STATE_MAP:
        raise ValueError("状态映射与冻结合同不一致")

    scope = plan["作用域"]
    if not isinstance(scope, dict):
        raise ValueError("作用域必须是对象")
    _require_exact_keys(scope, SCOPE_KEYS, "作用域")
    if scope["标的"] != TARGETS:
        raise ValueError("标的作用域必须严格为BTC、ETH、SOL")
    if scope["主研究尺度"] != MAIN_SCALES:
        raise ValueError("主研究尺度漂移")
    if scope["结果观察窗口"] != RESULT_WINDOWS:
        raise ValueError("结果观察窗口漂移")
    if scope["分组维度"] != GROUP_DIMENSIONS:
        raise ValueError("分组维度漂移")

    resources = plan["资源上限"]
    if not isinstance(resources, dict):
        raise ValueError("资源上限必须是对象")
    _require_exact_keys(resources, RESOURCE_KEYS, "资源上限")
    limits = {
        "批次总超时秒": (10, 7200),
        "最大成员数": (1, 10_000),
        "最大输出字节数": (1024, 100 * 1024 * 1024),
        "最大日志字节数": (256, 64 * 1024),
    }
    for name, (minimum, maximum) in limits.items():
        value = resources[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name}必须是整数")
        if value < minimum or value > maximum:
            raise ValueError(f"{name}超出安全范围")

    safety = plan["安全边界"]
    if not isinstance(safety, dict):
        raise ValueError("安全边界必须是对象")
    _require_exact_keys(safety, SAFETY_KEYS, "安全边界")
    if any(safety[key] is not False for key in SAFETY_KEYS):
        raise ValueError("安全边界不得授权写入、修复或自动放行")

    serialized = canonical_json(plan)
    if any(pattern.search(serialized) for pattern in (
        IPV4_PATTERN,
        PRIVATE_KEY_PATTERN,
        TOKEN_PATTERN,
        CREDENTIAL_PATTERN,
    )):
        raise ValueError("持续验证方案包含地址或敏感信息")
    return plan


def build_member_manifest(
    inventory_path: Path,
    plan: Mapping[str, object],
    auditor: ModuleType,
) -> list[dict[str, str]]:
    rows = auditor.load_inventory(inventory_path)
    units = auditor.build_validation_units(rows)
    maximum = int(plan["资源上限"]["最大成员数"])
    if len(units) > maximum:
        raise ValueError("验证成员数超过冻结资源上限")
    members = []
    for unit in units:
        if unit["逻辑主机"] != "ubuntu":
            raise ValueError("资产清单包含未授权逻辑主机")
        members.append({
            "资产编号": unit["资产编号"],
            "资产类型": unit["资产类型"],
            "逻辑主机": "ubuntu",
            "服务或项目": unit["服务或项目"],
            "位置": unit["位置"],
            "格式": unit["格式"],
            "候选标的范围": unit["标的范围"],
            "精确作用域状态": "无法判定",
            "作用域限制": "交易场所、市场类型、精确合约和研究尺度尚无正式身份合同",
        })
    return sorted(
        members,
        key=lambda row: (
            row["资产编号"],
            row["逻辑主机"],
            row["服务或项目"],
            row["位置"],
            row["格式"],
        ),
    )


def build_auditor_command(
    auditor_path: Path,
    inventory_path: Path,
    ssh_target: str,
    output_dir: Path,
    report_path: Path,
    timeout: int,
    auditor: ModuleType,
) -> list[str]:
    auditor.validate_ssh_target(ssh_target)
    return [
        sys.executable,
        str(auditor_path.resolve()),
        "--inventory",
        str(inventory_path.resolve()),
        "--ssh-target",
        ssh_target,
        "--timeout",
        str(timeout),
        "--output-dir",
        str(output_dir),
        "--report",
        str(report_path),
    ]


def _nonnegative_integer(value: object) -> int | None:
    text = str(value)
    if not re.fullmatch(r"0|[1-9]\d*", text):
        return None
    return int(text)


def _aggregate(rows: list[dict[str, str]], field: str) -> dict[str, int]:
    total = 0
    unknown = 0
    for row in rows:
        value = _nonnegative_integer(row.get(field, ""))
        if value is None:
            unknown += 1
        else:
            total += value
    return {"已知合计": total, "无法判定成员数": unknown}


def _member_state(row: Mapping[str, str], state_map: Mapping[str, str]) -> str:
    scan_status = row.get("扫描状态", "")
    completeness = row.get("扫描完整性", "")
    if scan_status in {"失败", "超时"} or completeness in {"失败", "超时"}:
        return "失败"
    if scan_status == "输入漂移":
        return "拒绝"
    conclusion = row.get("可用性结论", "无法判定")
    if conclusion in {"未成熟", "失效"}:
        return conclusion
    return state_map.get(conclusion, "无法判定")


def build_summary(
    quality_rows: list[dict[str, str]],
    gap_rows: list[dict[str, str]],
    anomaly_rows: list[dict[str, str]],
    plan: Mapping[str, object],
) -> dict[str, object]:
    state_map = plan["状态映射"]
    states = {state: 0 for state in MAIN_STATES}
    observed = 0
    target_candidates = {target: 0 for target in TARGETS}
    for row in quality_rows:
        states[_member_state(row, state_map)] += 1
        if row.get("扫描完整性") in {"完整", "元数据范围"}:
            observed += 1
        candidates = set(filter(None, row.get("候选标的范围", "").split("、")))
        for target in TARGETS:
            if target in candidates:
                target_candidates[target] += 1
    if sum(states.values()) != len(quality_rows):
        raise ValueError("验证成员主状态不守恒")

    metrics = {
        "记录数": _aggregate(quality_rows, "记录数"),
        "结构缺失数": _aggregate(quality_rows, "结构缺失数"),
        "精确重复数": _aggregate(quality_rows, "精确重复数"),
        "断档数": _aggregate(gap_rows, "断档数"),
        "异常数量": _aggregate(anomaly_rows, "异常数量"),
    }
    comparison_metrics = {
        "记录数已知合计": metrics["记录数"]["已知合计"],
        "结构缺失数已知合计": metrics["结构缺失数"]["已知合计"],
        "精确重复数已知合计": metrics["精确重复数"]["已知合计"],
        "断档数已知合计": metrics["断档数"]["已知合计"],
        "异常数量已知合计": metrics["异常数量"]["已知合计"],
        "通过数": states["通过"],
        "拒绝数": states["拒绝"],
        "无法判定数": states["无法判定"],
        "失败数": states["失败"],
        "未成熟数": states["未成熟"],
        "失效数": states["失效"],
    }
    return {
        "候选总体": len(quality_rows),
        "已观察": observed,
        "主状态计数": states,
        "质量指标": metrics,
        "候选标的覆盖计数": target_candidates,
        "精确作用域已证明成员数": 0,
        "对比指标": comparison_metrics,
        "结论边界": "质量结果不构成研究准入、预测优势或交易许可",
    }


def _read_csv(path: Path, columns: Sequence[str], maximum_size: int) -> list[dict[str, str]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("底层审计输出缺失或不是普通文件")
    if path.stat().st_size > maximum_size:
        raise ValueError("底层审计输出超过冻结大小上限")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != tuple(columns):
            raise ValueError("底层审计输出列漂移")
        return [{key: value or "" for key, value in row.items()} for row in reader]


def _single_value(rows: list[dict[str, str]], field: str) -> str:
    values = {row[field] for row in rows}
    if len(values) != 1 or "" in values:
        raise ValueError(f"底层审计输出{field}不唯一")
    return next(iter(values))


def _report_metadata(report_path: Path, maximum_size: int) -> dict[str, str]:
    if not report_path.is_file() or report_path.is_symlink():
        raise ValueError("底层审计报告缺失或不是普通文件")
    if report_path.stat().st_size > maximum_size:
        raise ValueError("底层审计报告超过冻结大小上限")
    text = report_path.read_text(encoding="utf-8")
    fields = {
        "底层审计批次": "审计批次",
        "数据截止时间": "数据截止时间",
        "资产清单指纹": "资产清单SHA-256",
        "规则版本": "规则版本",
        "规则指纹": "规则SHA-256",
        "Schema指纹": "结构SHA-256",
        "规则冻结时间": "规则冻结时间",
    }
    result = {}
    for output_name, report_name in fields.items():
        match = re.search(rf"^- {re.escape(report_name)}：`([^`]+)`$", text, re.MULTILINE)
        if match is None:
            raise ValueError("底层审计报告元数据合同不完整")
        result[output_name] = match.group(1)
    for field in ("资产清单指纹", "规则指纹", "Schema指纹"):
        if not SHA256_PATTERN.fullmatch(result[field]):
            raise ValueError("底层审计报告指纹格式非法")
    return result


def validate_outputs(
    output_dir: Path,
    report_path: Path,
    plan: Mapping[str, object],
    auditor: ModuleType,
    members: list[dict[str, str]],
) -> dict[str, object]:
    maximum_size = int(plan["资源上限"]["最大输出字节数"])
    quality = _read_csv(output_dir / "数据质量结果.csv", auditor.QUALITY_COLUMNS, maximum_size)
    gaps = _read_csv(output_dir / "数据断档结果.csv", auditor.GAP_COLUMNS, maximum_size)
    anomalies = _read_csv(
        output_dir / "数据异常结果.csv", auditor.ANOMALY_COLUMNS, maximum_size
    )
    if not quality:
        raise ValueError("底层审计结果为空")
    expected_ids = [member["资产编号"] for member in members]
    for rows in (quality, gaps, anomalies):
        ids = [row["资产编号"] for row in rows]
        if sorted(ids) != expected_ids or len(ids) != len(set(ids)):
            raise ValueError("底层审计结果未完整覆盖冻结成员")

    report = _report_metadata(report_path, maximum_size)
    combined = quality + gaps + anomalies
    checks = {
        "底层审计批次": _single_value(combined, "审计批次"),
        "规则版本": _single_value(combined, "规则版本"),
        "规则指纹": _single_value(combined, "规则指纹"),
        "资产清单指纹": _single_value(combined, "清单指纹"),
    }
    for key, value in checks.items():
        if report[key] != value:
            raise ValueError("底层审计CSV与报告元数据不一致")
    if checks["规则版本"] != plan["底层审计规则版本"]:
        raise ValueError("底层审计规则版本与冻结方案不一致")
    if checks["资产清单指纹"] != plan["资产清单指纹"]:
        raise ValueError("底层审计清单指纹与冻结方案不一致")
    if sum(path.stat().st_size for path in (
        output_dir / "数据质量结果.csv",
        output_dir / "数据断档结果.csv",
        output_dir / "数据异常结果.csv",
        report_path,
    )) > maximum_size:
        raise ValueError("批次输出总大小超过冻结上限")
    return {
        **report,
        "质量结果": quality,
        "断档结果": gaps,
        "异常结果": anomalies,
        "结果摘要": build_summary(quality, gaps, anomalies, plan),
    }


def compare_with_previous(
    previous: Mapping[str, object],
    current: Mapping[str, object],
) -> dict[str, object]:
    identity_fields = (
        "方案指纹",
        "规则指纹",
        "资产清单指纹",
        "Schema指纹",
        "作用域指纹",
    )
    mismatches = [field for field in identity_fields if previous.get(field) != current.get(field)]
    previous_id = str(previous.get("验证批次", "无法判定"))
    if mismatches:
        return {
            "前序批次": previous_id,
            "比较状态": "不可比较",
            "原因": "身份不一致：" + "、".join(mismatches),
            "指标变化": {},
        }
    previous_metrics = previous.get("结果摘要", {}).get("对比指标", {})
    current_metrics = current.get("结果摘要", {}).get("对比指标", {})
    if set(previous_metrics) != set(current_metrics) or any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in list(previous_metrics.values()) + list(current_metrics.values())
    ):
        return {
            "前序批次": previous_id,
            "比较状态": "不可比较",
            "原因": "对比指标合同不一致",
            "指标变化": {},
        }
    return {
        "前序批次": previous_id,
        "比较状态": "可比较",
        "原因": "方案、规则、Schema、清单和作用域身份一致",
        "指标变化": {
            key: int(current_metrics[key]) - int(previous_metrics[key])
            for key in sorted(current_metrics)
        },
    }


def _load_previous_manifest(batch_root: Path) -> dict[str, object] | None:
    index_path = batch_root / "批次索引.csv"
    if not index_path.exists():
        return None
    if not index_path.is_file() or index_path.is_symlink():
        raise ValueError("批次索引必须是普通文件")
    with index_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INDEX_COLUMNS:
            raise ValueError("批次索引列漂移")
        rows = list(reader)
    if not rows:
        return None
    batch_id = rows[-1]["验证批次"]
    if not re.fullmatch(r"dqv-[0-9]{8}T[0-9]{6}[+-][0-9]{4}-[0-9a-f]{12}", batch_id):
        raise ValueError("前序批次标识非法")
    manifest_path = batch_root / batch_id / "验证清单.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("前序批次清单缺失")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("前序批次清单非法") from error
    if not isinstance(manifest, dict) or manifest.get("验证批次") != batch_id:
        raise ValueError("前序批次清单身份不一致")
    return manifest


def _render_index(rows: list[dict[str, str]]) -> str:
    from io import StringIO

    buffer = StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=INDEX_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: safe_csv_cell(row[column]) for column in INDEX_COLUMNS})
    return buffer.getvalue()


def _existing_index_rows(batch_root: Path) -> list[dict[str, str]]:
    index_path = batch_root / "批次索引.csv"
    if not index_path.exists():
        return []
    with index_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != INDEX_COLUMNS:
            raise ValueError("批次索引列漂移")
        return [{key: value or "" for key, value in row.items()} for row in reader]


def _scan_sensitive(paths: Sequence[Path]) -> None:
    patterns = (IPV4_PATTERN, PRIVATE_KEY_PATTERN, TOKEN_PATTERN, CREDENTIAL_PATTERN)
    for path in paths:
        text = path.read_text(encoding="utf-8-sig")
        if any(pattern.search(text) for pattern in patterns):
            raise ValueError("批次产物包含地址或敏感信息")


def _publish_batch(staging: Path, batch_root: Path, manifest: Mapping[str, object]) -> Path:
    batch_id = str(manifest["验证批次"])
    target = batch_root / batch_id
    if target.exists():
        raise FileExistsError("验证批次已存在，禁止覆盖")
    rows = _existing_index_rows(batch_root)
    if any(row["验证批次"] == batch_id for row in rows):
        raise FileExistsError("验证批次索引已存在，禁止覆盖")
    states = manifest["结果摘要"]["主状态计数"]
    comparison = manifest["前序比较"]
    rows.append({
        "验证批次": batch_id,
        "冻结时间": str(manifest["冻结时间"]),
        "底层审计批次": str(manifest["底层审计批次"]),
        "方案指纹": str(manifest["方案指纹"]),
        "规则指纹": str(manifest["规则指纹"]),
        "资产清单指纹": str(manifest["资产清单指纹"]),
        "Schema指纹": str(manifest["Schema指纹"]),
        "作用域指纹": str(manifest["作用域指纹"]),
        "候选总体": str(manifest["结果摘要"]["候选总体"]),
        "通过": str(states["通过"]),
        "拒绝": str(states["拒绝"]),
        "无法判定": str(states["无法判定"]),
        "失败": str(states["失败"]),
        "未成熟": str(states["未成熟"]),
        "失效": str(states["失效"]),
        "前序批次": str(comparison["前序批次"]),
        "比较状态": str(comparison["比较状态"]),
        "清单文件指纹": file_fingerprint(staging / "验证清单.json"),
    })
    index_content = _render_index(rows)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=".批次索引.", suffix=".tmp", dir=batch_root
    )
    temp_index = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(index_content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, target)
        try:
            os.replace(temp_index, batch_root / "批次索引.csv")
        except Exception:
            shutil.rmtree(target)
            raise
    finally:
        if temp_index.exists():
            temp_index.unlink()
    return target


def execute_batch(
    inventory_path: Path,
    plan_path: Path,
    ssh_target: str,
    batch_root: Path,
    timeout: int,
    *,
    auditor_path: Path = DEFAULT_AUDITOR,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    now: dt.datetime | None = None,
) -> Path:
    plan = load_plan(plan_path, inventory_path, auditor_path)
    auditor = load_auditor_module(auditor_path)
    auditor_path = auditor_path.resolve()
    if ssh_target not in plan["允许SSH目标"]:
        raise ValueError("SSH目标不在冻结方案白名单")
    if timeout < 10 or timeout > int(plan["资源上限"]["批次总超时秒"]):
        raise ValueError("批次超时超出冻结资源上限")
    members = build_member_manifest(inventory_path, plan, auditor)

    frozen_time = now or dt.datetime.now().astimezone()
    if frozen_time.tzinfo is None or frozen_time.utcoffset() is None:
        raise ValueError("冻结时间必须包含时区")
    batch_root = batch_root.resolve()
    if batch_root.exists() and (not batch_root.is_dir() or batch_root.is_symlink()):
        raise ValueError("批次根目录必须是普通目录")
    batch_root.mkdir(parents=True, exist_ok=True)
    previous = _load_previous_manifest(batch_root)

    with tempfile.TemporaryDirectory(prefix=".dqv-", dir=batch_root.parent) as directory:
        temporary = Path(directory)
        audit_output = temporary / "audit-output"
        staging = temporary / "batch"
        audit_output.mkdir()
        staging.mkdir()
        report_path = temporary / "audit-report.md"
        stdout_path = temporary / "auditor.stdout"
        stderr_path = temporary / "auditor.stderr"
        command = build_auditor_command(
            auditor_path,
            inventory_path,
            ssh_target,
            audit_output,
            report_path,
            timeout,
            auditor,
        )
        try:
            with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
                "w", encoding="utf-8"
            ) as stderr_handle:
                completed = runner(
                    command,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("底层只读审计失败：命令不可用或批次超时") from error
        maximum_log = int(plan["资源上限"]["最大日志字节数"])
        if stdout_path.stat().st_size > maximum_log or stderr_path.stat().st_size > maximum_log:
            raise RuntimeError("底层只读审计失败：日志超过冻结资源上限")
        if completed.returncode != 0:
            raise RuntimeError("底层只读审计失败：返回非零状态，未发布批次")

        validated = validate_outputs(audit_output, report_path, plan, auditor, members)
        for name in OUTPUT_NAMES[:3]:
            shutil.copy2(audit_output / name, staging / name)
        shutil.copy2(report_path, staging / "验证报告.md")
        output_fingerprints = {
            name: file_fingerprint(staging / name) for name in OUTPUT_NAMES
        }
        completed_time = now or dt.datetime.now().astimezone()
        manifest: dict[str, object] = {
            "合同版本": SCRIPT_VERSION,
            "冻结时间": frozen_time.isoformat(timespec="microseconds"),
            "执行开始时间": frozen_time.isoformat(timespec="microseconds"),
            "执行结束时间": completed_time.isoformat(timespec="microseconds"),
            "数据截止时间": validated["数据截止时间"],
            "规则冻结时间": validated["规则冻结时间"],
            "底层审计批次": validated["底层审计批次"],
            "方案版本": plan["方案版本"],
            "方案指纹": object_fingerprint(plan),
            "底层审计器指纹": file_fingerprint(auditor_path),
            "规则版本": validated["规则版本"],
            "规则指纹": validated["规则指纹"],
            "资产清单指纹": validated["资产清单指纹"],
            "Schema指纹": validated["Schema指纹"],
            "作用域指纹": object_fingerprint(plan["作用域"]),
            "SSH逻辑目标": "ubuntu",
            "远端写入": False,
            "成员顺序": members,
            "结果摘要": validated["结果摘要"],
            "输出文件指纹": output_fingerprints,
            "失效记录": [],
        }
        identity = {
            "冻结时间": manifest["冻结时间"],
            "底层审计批次": manifest["底层审计批次"],
            "方案指纹": manifest["方案指纹"],
            "规则指纹": manifest["规则指纹"],
            "资产清单指纹": manifest["资产清单指纹"],
            "Schema指纹": manifest["Schema指纹"],
            "作用域指纹": manifest["作用域指纹"],
            "输出文件指纹": output_fingerprints,
        }
        batch_id = (
            "dqv-"
            + frozen_time.strftime("%Y%m%dT%H%M%S%z")
            + "-"
            + object_fingerprint(identity)[:12]
        )
        manifest["验证批次"] = batch_id
        if previous is None:
            manifest["前序比较"] = {
                "前序批次": "无",
                "比较状态": "无前序批次",
                "原因": "这是当前索引中的首个不可变批次",
                "指标变化": {},
            }
        else:
            manifest["前序比较"] = compare_with_previous(previous, manifest)
        (staging / "验证清单.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _scan_sensitive([path for path in staging.iterdir() if path.is_file()])
        published = _publish_batch(staging, batch_root, manifest)

    print(json.dumps({
        "状态": "成功",
        "验证批次": published.name,
        "候选总体": manifest["结果摘要"]["候选总体"],
        "主状态计数": manifest["结果摘要"]["主状态计数"],
        "比较状态": manifest["前序比较"]["比较状态"],
    }, ensure_ascii=False, sort_keys=True))
    return published


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="生成《知势》数据质量持续验证批次")
    parser.add_argument("--inventory", required=True, type=Path, help="冻结资产清单")
    parser.add_argument("--plan", required=True, type=Path, help="持续验证方案")
    parser.add_argument("--ssh-target", required=True, help="固定SSH逻辑别名")
    parser.add_argument("--batch-root", required=True, type=Path, help="不可变批次根目录")
    parser.add_argument("--timeout", required=True, type=int, help="批次总超时秒数")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        execute_batch(
            arguments.inventory,
            arguments.plan,
            arguments.ssh_target,
            arguments.batch_root,
            arguments.timeout,
        )
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"数据质量持续验证失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
