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
from typing import Iterable, Mapping, Sequence, TextIO


REPLAY_VERSION = "historical-replay-1.0"
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
RESULT_COLUMNS = (
    "验证批次", "清单指纹", "质量审计批次", "资产编号", "候选标的范围", "决策记录编号",
    "决策时间", "事件时间字段", "到达时间字段", "采集时间字段", "可见性合同状态", "输入身份状态",
    "第一门状态", "可见记录数", "首次快照指纹", "再次快照指纹", "确定性状态", "未来数据拒绝状态",
    "重放结论", "依据", "限制", "解除条件",
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
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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
    return {
        "visible_count": len(visible),
        "rejected_count": rejected,
        "future_rejection_code": "future_arrival_rejected" if rejected else "no_future_arrival",
        "snapshot_json": snapshot_json,
        "snapshot_fingerprint": _sha256_bytes(snapshot_json.encode("utf-8")),
    }


def build_formal_coverage(frozen: Mapping[str, object], batch: str) -> list[dict[str, str]]:
    quality_index = frozen["质量记录"]
    if not isinstance(quality_index, dict):
        raise ValueError("冻结质量记录结构非法")
    rows: list[dict[str, str]] = []
    for asset_id in sorted(quality_index):
        quality = quality_index[asset_id]
        completeness = quality["扫描完整性"]
        if completeness == "完整":
            scan_basis = "完整扫描不等于可见性合同，且未发现带来源证据的真实决策记录"
        else:
            scan_basis = f"扫描完整性为{completeness}，仅保留覆盖记录，禁止读取正文"
        basis = (
            f"{scan_basis}；事件、到达、采集时间状态均未形成可验证语义合同；"
            "字段名候选证据未被提升为时间语义"
        )
        rows.append({
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
            "输入身份状态": "一致（冻结清单与质量证据）",
            "第一门状态": "无法判定（缺少真实决策记录与已证明到达时间合同）",
            "可见记录数": "无法判定",
            "首次快照指纹": "无法判定",
            "再次快照指纹": "无法判定",
            "确定性状态": "未执行（第一门未通过）",
            "未来数据拒绝状态": "未执行（第一门未通过）",
            "重放结论": "无法判定",
            "依据": basis,
            "限制": "本结果不得用于预测研究、胜率或收益声称、交易许可或真实下单",
            "解除条件": "提供带来源证据和明确时区的历史决策记录，冻结三类时间语义、稳定业务键与到达可见性合同",
        })
    return rows


def _scope_contains(scope: str, symbol: str) -> bool:
    tokens = {token for token in re.split(r"[^A-Za-z0-9]+", scope.upper()) if token}
    return symbol in tokens


def render_report(rows: Sequence[Mapping[str, str]], metadata: Mapping[str, str]) -> str:
    symbol_counts = {
        symbol: sum(_scope_contains(row.get("候选标的范围", ""), symbol) for row in rows)
        for symbol in ("BTC", "ETH", "SOL")
    }
    conclusions = {
        symbol: "无法判定（缺少已证明的历史决策时点与到达可见性合同）"
        for symbol in ("BTC", "ETH", "SOL")
    }
    lines = [
        "# 历史现场重放验证",
        "",
        "> 宁可停止或无法判定，也不得让未来数据进入历史决策现场。",
        "",
        "## 验证身份",
        "",
        f"- 验证器版本：`{REPLAY_VERSION}`",
        f"- 验证批次：`{_redact(metadata['验证批次'])}`",
        f"- 质量审计批次：`{_redact(metadata['质量审计批次'])}`",
        f"- 清单指纹：`{_redact(metadata['清单指纹'])}`",
        f"- 远端只读预检：{_redact(metadata['远端预检'])}（仅验证固定 Python 入口，未读取数据正文）",
        f"- 正式覆盖：{len(rows)} 个任务-000004验证单元",
        "",
        "## 总体结论",
        "",
        "冻结输入的资产编号、审计批次、规则指纹与清单指纹一致。"
        "但全部验证单元都缺少带来源证据的真实决策记录，且任务-000004未证明"
        "到达时间语义。因此第一门全部保守终止，正式结论均为“无法判定”，"
        "没有读取业务正文，也没有生成虚假决策时点或快照。",
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
        "## 验证器机制证据",
        "",
        "- 带时区的决策时间和到达时间才能进入比较。",
        "- 到达时间等于决策时间的记录在闭区间内；晚于决策时间的记录返回 `future_arrival_rejected`。",
        "- 快照使用冻结业务键稳定排序和 SHA-256 指纹；业务键缺失或重复时失败终止。",
        "- 上述未来数据拒绝仅由 `smoke-only` 合成夹具验证生产函数路径；合成记录未进入本报告或正式 CSV。",
        "",
        "## 限制与解除条件",
        "",
        "1. 当前只能证明验证器能失败安全地阻断无证据输入，不能证明任一历史交易决策可重放。",
        "2. 需要提供带来源证据、唯一记录编号和明确时区的历史决策时点。",
        "3. 需要版本化冻结事件、到达和采集时间语义，以及业务键、排序和去重合同。",
        "4. 本结果不得提升研究准入、模型状态或交易许可，不涉及真实资金。",
        "",
    ])
    return "\n".join(lines)


def write_csv_stream(handle: TextIO, rows: Sequence[Mapping[str, str]]) -> None:
    writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS, extrasaction="raise")
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
    _assert_no_sensitive_content(_canonical_json(list(rows)))
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
            "formal_conclusion": "无法判定", "remote_preflight": "passed",
        })
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"历史现场重放验证失败：{_redact(error)}", file=sys.stderr)
        raise SystemExit(1)
