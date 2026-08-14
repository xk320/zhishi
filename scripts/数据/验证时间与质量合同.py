#!/usr/bin/env python3
"""验证并冻结任务-000030的三类时间与对象级质量合同。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "数据" / "时间与质量规则.json"
DEFAULT_TASK = REPO_ROOT / "docs" / "研发中心" / "任务" / "任务-000030.md"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts" / "数据" / "时间质量合同"
CONTRACT_VERSION = "time-quality-1.0"
SOURCE_CONTRACT_VERSION = "source-identity-1.0"
TASK_ID = "任务-000030"
TARGETS = ("BTC", "ETH")
SCALES = ("4小时", "8小时", "24小时", "48小时")
OBSERVATION_WINDOWS = ("15分钟", "1小时")
TIME_FIELDS = ("事件时间", "到达时间", "采集时间")
QUALITY_FIELDS = (
    "频率",
    "业务键",
    "排序",
    "迟到",
    "补录",
    "撤销",
    "修订",
    "重复",
    "断档",
    "异常",
    "时钟漂移",
    "数据截止",
)
QUALITY_STATES = ("已证明", "失败", "无法判定")
MEMBER_REQUIRED = {
    "成员编号",
    "资产编号",
    "资产类型",
    "标的",
    "状态",
    "输入成员SHA-256",
}
CONFIG_KEYS = {
    "合同版本",
    "任务编号",
    "来源身份输入",
    "标的",
    "主研究尺度",
    "事后结果观察窗口",
    "三类时间规则",
    "数据质量规则",
    "状态",
    "未知处理",
    "安全边界",
}
SOURCE_INPUT_KEYS = {"合同版本", "清单路径", "清单SHA-256", "成员SHA-256"}
SAFETY_KEYS = {
    "访问模式",
    "允许远端目标",
    "允许远端写入",
    "允许修改原始数据",
    "允许生产写入",
    "允许真实交易",
    "允许模型或回测",
    "允许凭据",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """输入合同或不可变清单不满足严格结构。"""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except (OSError, UnicodeError) as exc:
        raise ContractError("输入文件不可读取") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("JSON存在重复字段")
        result[key] = value
    return result


def load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except ContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("JSON合同不可读取或格式无效") from exc


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ContractError(f"{label}字段集合不一致")


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label}必须是非空字符串")
    return value


def _string_list(value: object, expected: Sequence[str], label: str) -> None:
    if value != list(expected):
        raise ContractError(f"{label}顺序或内容不符合冻结合同")


def validate_rules(config: object) -> dict[str, object]:
    if not isinstance(config, Mapping):
        raise ContractError("规则合同根对象无效")
    _exact_keys(config, CONFIG_KEYS, "规则合同")
    if config["合同版本"] != CONTRACT_VERSION or config["任务编号"] != TASK_ID:
        raise ContractError("规则合同版本或任务编号不一致")
    _string_list(config["标的"], TARGETS, "标的")
    _string_list(config["主研究尺度"], SCALES, "主研究尺度")
    _string_list(config["事后结果观察窗口"], OBSERVATION_WINDOWS, "事后结果观察窗口")

    source = config["来源身份输入"]
    if not isinstance(source, Mapping):
        raise ContractError("来源身份输入无效")
    _exact_keys(source, SOURCE_INPUT_KEYS, "来源身份输入")
    if source["合同版本"] != SOURCE_CONTRACT_VERSION:
        raise ContractError("来源身份合同版本不一致")
    for key in ("清单SHA-256", "成员SHA-256"):
        if not isinstance(source[key], str) or not SHA256_RE.fullmatch(source[key]):
            raise ContractError("来源身份输入指纹无效")
    _nonempty_string(source["清单路径"], "来源身份清单路径")

    times = config["三类时间规则"]
    if not isinstance(times, Mapping) or set(times) != set(TIME_FIELDS):
        raise ContractError("三类时间规则字段集合不一致")
    for field in TIME_FIELDS:
        item = times[field]
        if not isinstance(item, Mapping) or set(item) != {
            "必须证明",
            "时区要求",
            "精度要求",
            "允许范围",
        }:
            raise ContractError("三类时间规则结构无效")
        if item["必须证明"] is not True:
            raise ContractError("三类时间必须显式证明")
        for key in ("时区要求", "精度要求", "允许范围"):
            _nonempty_string(item[key], f"三类时间规则-{field}-{key}")

    quality = config["数据质量规则"]
    if not isinstance(quality, Mapping) or set(quality) != set(QUALITY_FIELDS):
        raise ContractError("数据质量规则字段集合不一致")
    for key in QUALITY_FIELDS:
        _nonempty_string(quality[key], f"数据质量规则-{key}")
    _string_list(config["状态"], QUALITY_STATES, "状态")
    if config["未知处理"] != "无法判定":
        raise ContractError("未知处理必须为无法判定")

    safety = config["安全边界"]
    if not isinstance(safety, Mapping):
        raise ContractError("安全边界无效")
    _exact_keys(safety, SAFETY_KEYS, "安全边界")
    if safety["允许远端目标"] != ["ubuntu"]:
        raise ContractError("远端目标不符合白名单")
    for key in (
        "允许远端写入",
        "允许修改原始数据",
        "允许生产写入",
        "允许真实交易",
        "允许模型或回测",
        "允许凭据",
    ):
        if safety[key] is not False:
            raise ContractError(f"安全边界-{key}必须为false")
    return dict(config)


def load_identity_batch(path: Path, expected_sha: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    if sha256_path(path) != expected_sha:
        raise ContractError("来源身份清单指纹漂移")
    value = load_json(path)
    if not isinstance(value, Mapping):
        raise ContractError("来源身份清单根对象无效")
    for key in ("任务编号", "合同版本", "来源身份批次", "成员顺序", "成员SHA-256"):
        if key not in value:
            raise ContractError("来源身份清单缺少必要字段")
    if value["任务编号"] != "任务-000029" or value["合同版本"] != SOURCE_CONTRACT_VERSION:
        raise ContractError("来源身份清单合同不匹配")
    if not isinstance(value["成员SHA-256"], str) or not SHA256_RE.fullmatch(value["成员SHA-256"]):
        raise ContractError("来源身份成员指纹无效")
    members = value["成员顺序"]
    if not isinstance(members, list) or not members:
        raise ContractError("来源身份成员为空")
    if len(members) > 1000:
        raise ContractError("来源身份成员超过上限")
    identifiers: set[str] = set()
    normalized: list[dict[str, object]] = []
    for member in members:
        if not isinstance(member, Mapping) or not MEMBER_REQUIRED.issubset(member):
            raise ContractError("来源身份成员字段不完整")
        item = dict(member)
        member_id = _nonempty_string(item["成员编号"], "成员编号")
        asset_id = _nonempty_string(item["资产编号"], "资产编号")
        if member_id in identifiers:
            raise ContractError("来源身份成员重复")
        identifiers.add(member_id)
        if item["标的"] not in TARGETS:
            raise ContractError("来源身份出现非BTC/ETH标的")
        if item["状态"] not in {"已证明", "拒绝", "无法判定"}:
            raise ContractError("来源身份状态无效")
        if not isinstance(item["输入成员SHA-256"], str) or not SHA256_RE.fullmatch(item["输入成员SHA-256"]):
            raise ContractError("来源身份输入成员指纹无效")
        normalized.append(item)
    normalized.sort(key=lambda item: (str(item["标的"]), str(item["资产编号"]), str(item["成员编号"])))
    return dict(value), normalized


def _unknown_time_contract() -> dict[str, object]:
    return {
        "状态": "无法判定",
        "字段": "未知",
        "时区": "未知",
        "精度": "未知",
        "证据": "任务-000029来源身份清单未提供可证明的时间语义",
    }


def _unknown_quality_contract() -> dict[str, object]:
    return {
        "状态": "无法判定",
        "规则": "未知；不得统计、修复、去重或推断",
        "证据": "尚未取得该对象的质量规则证据",
    }


def build_member_contract(member: Mapping[str, object]) -> dict[str, object]:
    identity_state = member["状态"]
    quality_state = "失败" if identity_state == "拒绝" else "无法判定"
    reason = (
        "来源身份已拒绝，不能形成时间与质量输入"
        if identity_state == "拒绝"
        else "缺少事件、到达、采集时间及对象级质量证据"
    )
    record: dict[str, object] = {
        "成员编号": member["成员编号"],
        "资产编号": member["资产编号"],
        "资产类型": member["资产类型"],
        "标的": member["标的"],
        "输入成员SHA-256": member["输入成员SHA-256"],
        "来源身份状态": identity_state,
        "合同版本": CONTRACT_VERSION,
        "主研究尺度": list(SCALES),
        "事后结果观察窗口": list(OBSERVATION_WINDOWS),
        "三类时间": {field: _unknown_time_contract() for field in TIME_FIELDS},
        "质量规则": {field: _unknown_quality_contract() for field in QUALITY_FIELDS},
        "质量状态": quality_state,
        "原因": reason,
        "解除条件": "按对象和确切版本提供三类时间、时区、频率、业务键、修订、重复、断档和异常证据",
    }
    record["内容指纹"] = sha256_bytes(canonical_json(record).encode("utf-8"))
    return record


def _counts(records: Sequence[Mapping[str, object]], target: str) -> dict[str, int]:
    counts = Counter(
        str(record["质量状态"]) for record in records if record["标的"] == target
    )
    return {state: counts.get(state, 0) for state in QUALITY_STATES}


def build_manifest(
    config: Mapping[str, object],
    identity: Mapping[str, object],
    members: Sequence[Mapping[str, object]],
    *,
    config_sha: str,
    identity_sha: str,
    task_sha: str,
    batch_name: str,
) -> dict[str, object]:
    records = [build_member_contract(member) for member in members]
    member_sha = sha256_bytes(canonical_json(records).encode("utf-8"))
    payload: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份批次": identity["来源身份批次"],
        "来源身份清单SHA-256": identity_sha,
        "来源身份成员SHA-256": config["来源身份输入"]["成员SHA-256"],
        "规则SHA-256": config_sha,
        "任务文件SHA-256": task_sha,
        "成员合同SHA-256": member_sha,
        "成员总数": len(records),
        "BTC状态计数": _counts(records, "BTC"),
        "ETH状态计数": _counts(records, "ETH"),
    }
    return {
        "批次": batch_name,
        "生成时间": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份批次": identity["来源身份批次"],
        "来源身份清单SHA-256": identity_sha,
        "来源身份成员SHA-256": config["来源身份输入"]["成员SHA-256"],
        "规则SHA-256": config_sha,
        "任务文件SHA-256": task_sha,
        "主研究尺度": list(SCALES),
        "事后结果观察窗口": list(OBSERVATION_WINDOWS),
        "成员总数": len(records),
        "成员合同SHA-256": member_sha,
        "BTC状态计数": _counts(records, "BTC"),
        "ETH状态计数": _counts(records, "ETH"),
        "安全声明": {
            "仅读取来源身份清单和规则文件": True,
            "未读取原始业务记录": True,
            "未修改原始数据": True,
            "未使用未来数据": True,
            "未生成研究或交易结论": True,
        },
        "批次载荷": payload,
        "批次载荷SHA-256": sha256_bytes(canonical_json(payload).encode("utf-8")),
        "成员顺序": records,
    }


def validate_manifest(manifest: Mapping[str, object]) -> None:
    required = {
        "批次",
        "生成时间",
        "合同版本",
        "任务编号",
        "来源身份批次",
        "来源身份清单SHA-256",
        "来源身份成员SHA-256",
        "规则SHA-256",
        "任务文件SHA-256",
        "主研究尺度",
        "事后结果观察窗口",
        "成员总数",
        "成员合同SHA-256",
        "BTC状态计数",
        "ETH状态计数",
        "安全声明",
        "批次载荷",
        "批次载荷SHA-256",
        "成员顺序",
    }
    if set(manifest) != required:
        raise ContractError("合同清单字段集合不一致")
    if manifest["合同版本"] != CONTRACT_VERSION or manifest["任务编号"] != TASK_ID:
        raise ContractError("合同清单版本或任务编号不一致")
    _string_list(manifest["主研究尺度"], SCALES, "合同清单主研究尺度")
    _string_list(manifest["事后结果观察窗口"], OBSERVATION_WINDOWS, "合同清单观察窗口")
    records = manifest["成员顺序"]
    if not isinstance(records, list) or manifest["成员总数"] != len(records):
        raise ContractError("合同清单成员计数不一致")
    if list(records) != sorted(
        records,
        key=lambda item: (str(item["标的"]), str(item["资产编号"]), str(item["成员编号"])),
    ):
        raise ContractError("合同清单成员顺序不确定")
    if any(record.get("主研究尺度") != list(SCALES) for record in records):
        raise ContractError("成员主研究尺度不一致")
    if any(record.get("事后结果观察窗口") != list(OBSERVATION_WINDOWS) for record in records):
        raise ContractError("成员观察窗口不一致")
    expected_member_sha = sha256_bytes(canonical_json(records).encode("utf-8"))
    if manifest["成员合同SHA-256"] != expected_member_sha:
        raise ContractError("成员合同指纹不一致")
    for record in records:
        if record.get("质量状态") not in QUALITY_STATES:
            raise ContractError("成员质量状态无效")
        content = dict(record)
        fingerprint = content.pop("内容指纹", None)
        if not isinstance(fingerprint, str) or fingerprint != sha256_bytes(canonical_json(content).encode("utf-8")):
            raise ContractError("成员内容指纹不一致")
        if record.get("标的") not in TARGETS:
            raise ContractError("成员出现非BTC/ETH标的")
    for target in TARGETS:
        expected = _counts(records, target)
        if manifest[f"{target}状态计数"] != expected or sum(expected.values()) != sum(
            1 for record in records if record["标的"] == target
        ):
            raise ContractError("BTC/ETH状态计数不守恒")
    payload = manifest["批次载荷"]
    if not isinstance(payload, Mapping) or manifest["批次载荷SHA-256"] != sha256_bytes(
        canonical_json(payload).encode("utf-8")
    ):
        raise ContractError("批次载荷指纹不一致")


def _csv_value(value: object) -> str:
    if isinstance(value, (dict, list)):
        return canonical_json(value)
    return str(value)


def write_batch(manifest: Mapping[str, object], batch_root: Path) -> Path:
    validate_manifest(manifest)
    batch_root.mkdir(parents=True, exist_ok=True)
    batch_name = str(manifest["批次"])
    destination = batch_root / batch_name
    if destination.exists():
        raise ContractError("历史批次已存在，拒绝覆盖")
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=batch_root))
    try:
        (staging / "合同清单.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        columns = [
            "批次",
            "成员编号",
            "资产编号",
            "标的",
            "资产类型",
            "质量状态",
            "来源身份状态",
            "主研究尺度",
            "事后结果观察窗口",
            "三类时间",
            "质量规则",
            "输入成员SHA-256",
            "内容指纹",
            "原因",
            "解除条件",
        ]
        with (staging / "合同清单.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for record in manifest["成员顺序"]:
                writer.writerow(
                    {
                        "批次": batch_name,
                        "成员编号": record["成员编号"],
                        "资产编号": record["资产编号"],
                        "标的": record["标的"],
                        "资产类型": record["资产类型"],
                        "质量状态": record["质量状态"],
                        "来源身份状态": record["来源身份状态"],
                        "主研究尺度": _csv_value(record["主研究尺度"]),
                        "事后结果观察窗口": _csv_value(record["事后结果观察窗口"]),
                        "三类时间": _csv_value(record["三类时间"]),
                        "质量规则": _csv_value(record["质量规则"]),
                        "输入成员SHA-256": record["输入成员SHA-256"],
                        "内容指纹": record["内容指纹"],
                        "原因": record["原因"],
                        "解除条件": record["解除条件"],
                    }
                )
        os.rename(staging, destination)
        return destination
    except Exception:
        for child in staging.iterdir():
            child.unlink()
        staging.rmdir()
        raise


def create_batch(
    *,
    config_path: Path = DEFAULT_CONFIG,
    identity_path: Path | None = None,
    task_path: Path = DEFAULT_TASK,
    batch_root: Path = DEFAULT_BATCH_ROOT,
    freeze_time: dt.datetime | None = None,
) -> Path:
    config_path = config_path.resolve()
    task_path = task_path.resolve()
    batch_root = batch_root.resolve()
    config = validate_rules(load_json(config_path))
    config_sha = sha256_path(config_path)
    source_input = config["来源身份输入"]
    assert isinstance(source_input, Mapping)
    identity_path = identity_path or (REPO_ROOT / str(source_input["清单路径"]))
    identity_path = identity_path.resolve()
    identity_sha = sha256_path(identity_path)
    if identity_sha != source_input["清单SHA-256"]:
        raise ContractError("来源身份清单不匹配规则合同")
    identity, members = load_identity_batch(identity_path, identity_sha)
    task_sha = sha256_path(task_path)
    moment = freeze_time or dt.datetime.now(dt.timezone.utc).astimezone()
    stamp = moment.strftime("%Y%m%dT%H%M%S%z")
    provisional = build_manifest(
        config,
        identity,
        members,
        config_sha=config_sha,
        identity_sha=identity_sha,
        task_sha=task_sha,
        batch_name="pending",
    )
    payload_hash = provisional["批次载荷SHA-256"]
    batch_name = f"time-quality-{stamp}-{str(payload_hash)[:12]}"
    manifest = build_manifest(
        config,
        identity,
        members,
        config_sha=config_sha,
        identity_sha=identity_sha,
        task_sha=task_sha,
        batch_name=batch_name,
    )
    return write_batch(manifest, batch_root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="冻结三类时间与数据对象质量合同")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--identity-batch", type=Path)
    parser.add_argument("--task", type=Path, default=DEFAULT_TASK)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        path = create_batch(
            config_path=arguments.contract,
            identity_path=arguments.identity_batch,
            task_path=arguments.task,
            batch_root=arguments.batch_root,
        )
        manifest = load_json(path / "合同清单.json")
        assert isinstance(manifest, Mapping)
        print(
            json.dumps(
                {
                    "状态": "成功",
                    "批次": str(path.relative_to(REPO_ROOT)),
                    "成员总数": manifest["成员总数"],
                    "BTC状态计数": manifest["BTC状态计数"],
                    "ETH状态计数": manifest["ETH状态计数"],
                    "结论": "仅冻结合同；未知时间与质量语义保持无法判定，不产生研究或交易许可",
                },
                ensure_ascii=False,
            )
        )
        return 0
    except (ContractError, OSError, ValueError):
        print(json.dumps({"状态": "失败", "错误": "合同验证失败，未发布批次"}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
