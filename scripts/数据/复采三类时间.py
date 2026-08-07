#!/usr/bin/env python3
"""执行任务-000073的三类时间与可见性只读复采。

该入口只冻结任务-000072来源身份成员和时间语义证据，不读取业务正文，不修改远端、数据库、
原始数据或生产服务。远端探针只返回固定版本的可达性元数据；无法证明的字段保持无法判定。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000073"
CONTRACT_VERSION = "time-visibility-recapture-1.0"
SOURCE_CONTRACT_VERSION = "source-identity-recapture-1.0"
PROBE_VERSION = "time-visibility-recapture-probe-1.0"
TASK_PATH = "docs/研发中心/任务/任务-000073.md"
DEFAULT_CONTRACT = REPO_ROOT / "config" / "数据" / "三类时间与可见性复采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts" / "数据" / "三类时间与可见性"
SCALES = ("4小时", "8小时", "24小时", "48小时")
OBSERVATION_WINDOWS = ("15分钟", "1小时")
TARGETS = ("BTC", "ETH")
TIME_FIELDS = ("事件时间", "到达时间", "采集时间")
RULE_FIELDS = ("频率", "业务键", "排序", "迟到", "补录", "撤销", "修订", "重复", "断档", "异常", "时钟漂移", "数据截止")
STATUSES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
SHA_FIELDS = ("清单SHA-256", "成员SHA-256")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _object_sha(value: object) -> str:
    return _sha(_canonical(value).encode("utf-8"))


def _read(path: Path, label: str) -> bytes:
    return engine._read_regular_bytes(path, label)


def _resolve(relative: str, repo_root: Path = REPO_ROOT) -> Path:
    return engine._resolve_repository_file(repo_root, relative, "任务-000073输入")


def _validate_hex(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"{name}不是SHA-256")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(_read(path, label).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}不是合法JSON") from error
    if not isinstance(raw, dict):
        raise ValueError(f"{label}必须是对象")
    return raw


def load_contract(path: Path = DEFAULT_CONTRACT, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    raw = _load_json(path, "三类时间与可见性复采合同")
    required = {
        "合同版本", "任务编号", "来源身份输入", "输入文件", "标的", "主研究尺度",
        "事后结果观察窗口", "三类时间字段", "可见性规则", "状态", "未知处理",
        "安全边界", "远端探针", "资源上限",
    }
    if set(raw) != required or raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("三类时间与可见性合同字段、版本或任务编号漂移")
    if raw["标的"] != list(TARGETS) or raw["主研究尺度"] != list(SCALES) or raw["事后结果观察窗口"] != list(OBSERVATION_WINDOWS):
        raise ValueError("标的或尺度边界漂移")
    if raw["三类时间字段"] != list(TIME_FIELDS) or raw["状态"] != list(STATUSES) or raw["未知处理"] != "无法判定":
        raise ValueError("时间字段或状态规则漂移")
    safety = raw["安全边界"]
    if not isinstance(safety, dict) or set(safety) != {
        "读取原始业务记录", "读取数据库业务记录", "读取环境变量或凭据", "远端写入",
        "修改原始数据", "修改生产系统", "模型或回测", "真实交易",
    } or any(value is not False for value in safety.values()):
        raise ValueError("安全边界不得授权写入或业务正文读取")
    probe = raw["远端探针"]
    if not isinstance(probe, dict) or probe.get("允许SSH目标") != ["ubuntu"] or probe.get("探针版本") != PROBE_VERSION:
        raise ValueError("远端探针白名单或版本漂移")
    resources = raw["资源上限"]
    if not isinstance(resources, dict) or set(resources) != {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}:
        raise ValueError("资源上限字段漂移")
    if not 10 <= resources["批次总超时秒"] <= 3600 or not 1 <= resources["逐成员超时秒"] <= 30 or not 2 <= resources["最大成员数"] <= 10000:
        raise ValueError("资源上限越界")
    source_input = raw["来源身份输入"]
    if not isinstance(source_input, dict) or source_input.get("合同版本") != SOURCE_CONTRACT_VERSION:
        raise ValueError("来源身份输入合同版本漂移")
    for field in SHA_FIELDS:
        _validate_hex(source_input.get(field), f"来源身份输入{field}")
    if not isinstance(source_input.get("来源身份批次"), str) or not source_input["来源身份批次"].startswith("source-identity-recapture-"):
        raise ValueError("来源身份批次标识非法")
    input_items = raw["输入文件"]
    if not isinstance(input_items, list) or len(input_items) != 5:
        raise ValueError("输入文件必须为五项且完整")
    seen: set[str] = set()
    for item in input_items:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"}:
            raise ValueError("输入文件成员字段非法")
        purpose, relative = item["用途"], item["路径"]
        if not isinstance(purpose, str) or not purpose or purpose in seen or not isinstance(relative, str) or not relative:
            raise ValueError("输入文件用途或路径重复")
        seen.add(purpose)
        expected = _validate_hex(item["SHA-256"], f"输入文件{purpose}")
        if _sha(_read(_resolve(relative, repo_root), purpose)) != expected:
            raise ValueError(f"输入文件指纹漂移：{purpose}")
    if seen != {"来源身份清单", "来源身份合同证据", "阶段1最终审计报告", "ZS-DATA-GAP-002台账基线", "任务-000072"}:
        raise ValueError("输入文件用途不完整")
    if _sha(_read(_resolve(source_input["清单路径"], repo_root), "来源身份清单")) != source_input["清单SHA-256"]:
        raise ValueError("来源身份清单SHA-256漂移")
    return raw


def _load_identity(contract: Mapping[str, Any], repo_root: Path) -> dict[str, Any]:
    source = contract["来源身份输入"]
    manifest = _load_json(_resolve(source["清单路径"], repo_root), "来源身份清单")
    if manifest.get("合同版本") != SOURCE_CONTRACT_VERSION or manifest.get("任务编号") != "任务-000072" or manifest.get("来源身份批次") != source["来源身份批次"]:
        raise ValueError("来源身份清单版本或批次漂移")
    members = manifest.get("成员顺序")
    if not isinstance(members, list) or not members or len(members) > 3000:
        raise ValueError("来源身份成员为空或超出资源上限")
    if manifest.get("成员SHA-256") != source["成员SHA-256"]:
        raise ValueError("来源身份成员SHA-256漂移")
    if members != sorted(members, key=lambda row: (str(row.get("标的")), str(row.get("资产编号")), str(row.get("成员编号")))):
        raise ValueError("来源身份成员顺序不确定")
    if {row.get("标的") for row in members} != set(TARGETS):
        raise ValueError("来源身份成员必须同时覆盖BTC和ETH")
    for row in members:
        if not isinstance(row, dict) or row.get("标的") not in TARGETS or row.get("状态") not in {"拒绝", "无法判定", "已证明"}:
            raise ValueError("来源身份成员状态非法")
        if not isinstance(row.get("输入成员SHA-256"), str) or len(row["输入成员SHA-256"]) != 64:
            raise ValueError("来源身份成员指纹缺失")
    return manifest


def _status_reason(identity_status: str) -> tuple[str, str, str]:
    if identity_status == "拒绝":
        return "失败", "来源身份已拒绝，三类时间与可见性无法建立", "重新冻结与只读元数据一致的来源身份版本"
    return "无法判定", "未读取业务正文，缺少三类时间、时区、精度、截止点和规则证据", "提供当前版本字段级时间与可见性证据后新建批次"


def _build_row(member: Mapping[str, Any], batch_id: str, source_batch: str) -> dict[str, Any]:
    visibility, reason, release = _status_reason(str(member["状态"]))
    time_records = {
        field: {
            "状态": visibility,
            "值": None,
            "时区": "未知",
            "精度": "未知",
            "数据截止": "未知",
            "证据": reason,
        }
        for field in TIME_FIELDS
    }
    rule_records = {field: {"状态": visibility, "证据": reason} for field in RULE_FIELDS}
    row: dict[str, Any] = {
        "批次": batch_id,
        "标的": member["标的"],
        "资产编号": member["资产编号"],
        "成员编号": member["成员编号"],
        "资产类型": member.get("资产类型", "未知"),
        "交易场所": member.get("交易场所", "未知"),
        "精确合约": member.get("精确合约", "未知"),
        "数据对象": member.get("数据对象", "未知"),
        "事件类型": "未知（未读取业务记录）",
        "主研究尺度": list(SCALES),
        "结果观察窗口": list(OBSERVATION_WINDOWS),
        "来源身份批次": source_batch,
        "来源身份合同版本": SOURCE_CONTRACT_VERSION,
        "来源身份状态": member["状态"],
        "输入成员SHA-256": member["输入成员SHA-256"],
        "状态版本": f"{SOURCE_CONTRACT_VERSION}:{member['输入成员SHA-256']}",
        "三类时间": time_records,
        "数据质量规则": rule_records,
        "可见性状态": visibility,
        "候选状态": "已观察",
        "结果可见后冻结": {
            "更换状态分类": False,
            "筛选事件": False,
            "修改分组": False,
            "缩小分母": False,
            "寻找最佳状态事件窗口": False,
        },
        "原因": reason,
        "解除条件": release,
        "限制": "未读取业务正文；本行不构成质量通过、可重放、研究准入或交易许可",
    }
    row["内容指纹"] = _object_sha(row)
    return row


def _counts(rows: Sequence[Mapping[str, Any]], target: str | None = None, scale: str | None = None) -> dict[str, int]:
    selected = [row for row in rows if (target is None or row["标的"] == target) and (scale is None or scale in row["主研究尺度"])]
    source_rejected = sum(1 for row in selected if row["来源身份状态"] == "拒绝")
    return {
        "候选总体": len(selected),
        "分母": len(selected),
        "已观察": sum(1 for row in selected if row["候选状态"] == "已观察"),
        "拒绝": source_rejected,
        "无法判定": sum(1 for row in selected if row["可见性状态"] == "无法判定"),
        "失败": sum(1 for row in selected if row["可见性状态"] == "失败"),
        "未成熟": sum(1 for row in selected if row["可见性状态"] == "未成熟"),
        "失效": sum(1 for row in selected if row["可见性状态"] == "失效"),
    }


def _probe(ssh_target: str, timeout: int, *, ssh_bin: str = "ssh", runner: Any | None = None) -> dict[str, Any]:
    probe_code = "import json; print(json.dumps({'探针版本':'time-visibility-recapture-probe-1.0','状态':'可执行','读取业务正文':False,'读取数据库业务记录':False,'远端写入':False},ensure_ascii=False))"
    remote_command = "python3 -c " + shlex.quote(probe_code)
    command = [ssh_bin, "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=5", ssh_target, remote_command]
    completed = runner(command) if runner is not None else engine.run_bounded_process(
        command,
        input_text="",
        timeout=timeout,
        maximum_stdout=4096,
        maximum_stderr=4096,
    )
    if completed.returncode != 0 or len(completed.stdout.encode()) > 4096 or len(completed.stderr.encode()) > 4096:
        raise RuntimeError("白名单只读元数据探针失败，未发布批次")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("白名单只读元数据探针返回非法结果") from error
    if result != {"探针版本": PROBE_VERSION, "状态": "可执行", "读取业务正文": False, "读取数据库业务记录": False, "远端写入": False}:
        raise RuntimeError("白名单只读元数据探针结果越权或漂移")
    return result


def _csv_value(value: object) -> str:
    return _canonical(value) if isinstance(value, (dict, list)) else str(value)


def validate_manifest(path: Path) -> dict[str, Any]:
    """复核已发布批次的顺序、成员指纹、统计守恒和载荷指纹。"""

    manifest = _load_json(path, "三类时间与可见性批次")
    if manifest.get("合同版本") != CONTRACT_VERSION or manifest.get("任务编号") != TASK_ID:
        raise ValueError("批次版本或任务编号漂移")
    rows = manifest.get("成员顺序")
    if not isinstance(rows, list) or manifest.get("分组成员数") != len(rows):
        raise ValueError("批次成员清单计数不一致")
    if rows != sorted(rows, key=lambda row: (str(row["标的"]), str(row["资产编号"]), str(row["成员编号"]))):
        raise ValueError("批次成员顺序不确定")
    for row in rows:
        if row.get("标的") not in TARGETS or row.get("主研究尺度") != list(SCALES) or row.get("结果观察窗口") != list(OBSERVATION_WINDOWS):
            raise ValueError("批次出现越权标的或尺度")
        content = dict(row)
        fingerprint = content.pop("内容指纹", None)
        if not isinstance(fingerprint, str) or fingerprint != _object_sha(content):
            raise ValueError("批次成员内容指纹不一致")
    if manifest.get("清单内容SHA-256") != _object_sha(rows):
        raise ValueError("批次清单指纹不一致")
    if manifest.get("结果摘要") != _counts(rows):
        raise ValueError("批次主统计不守恒")
    payload = manifest.get("批次载荷")
    if not isinstance(payload, dict) or manifest.get("批次载荷SHA-256") != _object_sha(payload):
        raise ValueError("批次载荷指纹不一致")
    return manifest


def execute_batch(
    contract_path: Path = DEFAULT_CONTRACT,
    *,
    ssh_target: str = "ubuntu",
    batch_root: Path = DEFAULT_BATCH_ROOT,
    ssh_bin: str = "ssh",
    timeout: int | None = None,
    repo_root: Path = REPO_ROOT,
    now: dt.datetime | None = None,
    probe_runner: Any | None = None,
) -> Path:
    contract_path = contract_path.resolve()
    contract = load_contract(contract_path, repo_root)
    if ssh_target not in contract["远端探针"]["允许SSH目标"]:
        raise ValueError("SSH目标不在冻结合同白名单")
    resources = contract["资源上限"]
    total_timeout = timeout or int(resources["批次总超时秒"])
    if total_timeout < 10 or total_timeout > int(resources["批次总超时秒"]):
        raise ValueError("批次超时超出合同资源上限")
    identity = _load_identity(contract, repo_root)
    probe_result = probe_runner(ssh_target, total_timeout, ssh_bin) if probe_runner is not None else _probe(ssh_target, total_timeout, ssh_bin=ssh_bin)
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    task_path = _resolve(TASK_PATH, repo_root)
    contract_bytes = _read(contract_path, "三类时间与可见性复采合同")
    executor_path = Path(__file__).resolve()
    rows_seed = [_build_row(member, "pending", identity["来源身份批次"]) for member in identity["成员顺序"]]
    rows_seed = sorted(rows_seed, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    # 批次身份只依赖冻结输入和规则，不依赖生成时间；pending行中的批次字段在载荷前统一替换。
    payload_seed = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份批次": identity["来源身份批次"],
        "来源身份清单SHA-256": contract["来源身份输入"]["清单SHA-256"],
        "来源身份成员SHA-256": contract["来源身份输入"]["成员SHA-256"],
        "规则SHA-256": _sha(contract_bytes),
        "任务文件SHA-256": _sha(_read(task_path, "任务-000073")),
        "执行器SHA-256": _sha(_read(executor_path, "执行器")),
        "输入SHA-256": {item["用途"]: item["SHA-256"] for item in contract["输入文件"]},
        "远端探针摘要": probe_result,
        "成员顺序": rows_seed,
    }
    batch_hash = _object_sha(payload_seed)
    batch_id = "time-visibility-recapture-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + batch_hash[:12]
    rows = []
    for row in rows_seed:
        copied = dict(row)
        copied["批次"] = batch_id
        copied.pop("内容指纹", None)
        copied["内容指纹"] = _object_sha(copied)
        rows.append(copied)
    rows_sha = _object_sha(rows)
    by_target = {target: _counts(rows, target=target) for target in TARGETS}
    by_scale = {scale: _counts(rows, scale=scale) for scale in SCALES}
    payload_core = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份批次": identity["来源身份批次"],
        "输入SHA-256": payload_seed["输入SHA-256"],
        "规则SHA-256": payload_seed["规则SHA-256"],
        "任务文件SHA-256": payload_seed["任务文件SHA-256"],
        "执行器SHA-256": payload_seed["执行器SHA-256"],
        "远端探针摘要": probe_result,
        "成员SHA-256": contract["来源身份输入"]["成员SHA-256"],
        "清单内容SHA-256": rows_sha,
    }
    manifest: dict[str, Any] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "批次": batch_id,
        "冻结时间": frozen.isoformat(timespec="microseconds"),
        "来源身份批次": identity["来源身份批次"],
        "来源身份清单SHA-256": contract["来源身份输入"]["清单SHA-256"],
        "来源身份成员SHA-256": contract["来源身份输入"]["成员SHA-256"],
        "输入SHA-256": payload_seed["输入SHA-256"],
        "规则SHA-256": payload_seed["规则SHA-256"],
        "任务文件SHA-256": payload_seed["任务文件SHA-256"],
        "执行器SHA-256": payload_seed["执行器SHA-256"],
        "远端探针摘要": probe_result,
        "主研究尺度": list(SCALES),
        "事后结果观察窗口": list(OBSERVATION_WINDOWS),
        "成员总数": len(identity["成员顺序"]),
        "分组成员数": len(rows),
        "成员顺序": rows,
        "清单内容SHA-256": rows_sha,
        "按标的状态计数": by_target,
        "按主研究尺度状态计数": by_scale,
        "结果摘要": _counts(rows),
        "批次载荷": payload_core,
        "批次载荷SHA-256": _object_sha(payload_core),
        "安全声明": {
            "远端逻辑目标": "ubuntu",
            "远端只读元数据": True,
            "未读取业务正文": True,
            "未读取数据库业务记录": True,
            "未读取凭据或环境变量": True,
            "未修改远端、数据库、生产服务或原始数据": True,
            "未使用未来数据": True,
            "未生成模型、回测或交易结论": True,
        },
        "结论边界": "三类时间与可见性证据不足时保持无法判定；本批次不关闭阶段1门禁",
    }
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    csv_columns = ["批次", "标的", "资产编号", "成员编号", "资产类型", "交易场所", "精确合约", "数据对象", "事件类型", "主研究尺度", "结果观察窗口", "来源身份状态", "状态版本", "三类时间", "数据质量规则", "可见性状态", "候选状态", "输入成员SHA-256", "内容指纹", "原因", "解除条件"]
    csv_path_text = []
    import io
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=csv_columns)
    writer.writeheader()
    for row in rows:
        writer.writerow({column: _csv_value(row[column]) for column in csv_columns})
    csv_text = buffer.getvalue()
    if len(json_text.encode()) + len(csv_text.encode()) > int(resources["最大输出字节数"]):
        raise ValueError("批次输出超过合同上限")
    batch_root = batch_root.resolve()
    batch_root.mkdir(parents=True, exist_ok=True)
    if batch_root.is_symlink() or not batch_root.is_dir():
        raise ValueError("批次根目录必须为普通目录")
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在，拒绝覆盖")
    with tempfile.TemporaryDirectory(prefix=".time-visibility-recapture-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "三类时间与可见性清单.json").write_text(json_text, encoding="utf-8")
        (staging / "三类时间与可见性清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        engine._scan_outputs([staging / "三类时间与可见性清单.json", staging / "三类时间与可见性清单.csv"])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "批次": batch_id, "成员总数": len(identity["成员顺序"]), "分组成员数": len(rows), "结果摘要": manifest["结果摘要"]}, ensure_ascii=False, sort_keys=True))
    return target


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="执行任务-000073三类时间与可见性只读复采")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--ssh-target", default="ubuntu")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--ssh-bin", default="ssh")
    parser.add_argument("--timeout", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        execute_batch(args.contract, ssh_target=args.ssh_target, batch_root=args.batch_root, ssh_bin=args.ssh_bin, timeout=args.timeout)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"三类时间与可见性复采失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
