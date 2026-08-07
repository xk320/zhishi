#!/usr/bin/env python3
"""执行任务-000077的数据库元数据只读身份证据复采。

只消费任务-000076的不可变成员清单和当前资产清单，复用冻结来源身份引擎的固定
information_schema.TABLES/COLUMNS探针。结构观察不会被提升为完整来源身份已证明。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000077"
CONTRACT_VERSION = "database-metadata-identity-evidence-recapture-1.0"
PROBE_VERSION = engine.PROBE_VERSION
CONFIG_PATH = REPO_ROOT / "config/数据/数据库元数据身份证据复采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts/数据/数据库元数据身份证据复采"
TASK_CONTRACT_SNAPSHOT_PATH = REPO_ROOT / "docs/研发中心/任务/任务-000077.md"
CONTRACT_DOC_PATH = REPO_ROOT / "docs/研究/数据库元数据身份与Schema证据合同.md"
TARGETS = ("BTC", "ETH")
MEMBER_COLUMNS = (
    "来源身份批次", "成员编号", "资产编号", "资产类型", "标的", "输入成员SHA-256",
)
OUTPUT_COLUMNS = MEMBER_COLUMNS + (
    "数据库Schema", "数据库表", "状态", "元数据状态", "原因代码", "证据定位",
    "结构证据", "限制", "解除条件", "元数据SHA-256", "SchemaSHA-256",
    "授权边界快照SHA-256", "探针SHA-256", "规则SHA-256", "执行器SHA-256", "成员记录SHA-256",
)
CONFIG_KEYS = {
    "合同版本", "任务编号", "输入文件", "任务-000076来源身份批次", "标的",
    "主研究尺度", "事后结果观察窗口", "允许SSH目标", "数据库元数据范围",
    "安全边界", "资源上限",
}
INPUT_KEYS = {"用途", "路径", "SHA-256"}
SAFETY_KEYS = {
    "远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据",
    "原始业务记录落盘", "读取价格成交订单簿", "修改原始数据", "修改生产系统",
}
RESOURCE_KEYS = {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}
DB_ASSET_TYPE = "数据库元数据"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fingerprint(value: object) -> str:
    return _sha(_canonical(value))


def rules_fingerprint(config: Mapping[str, object]) -> str:
    """返回不依赖运行时结果的规则指纹。"""
    return _fingerprint({
        "合同版本": CONTRACT_VERSION,
        "探针版本": PROBE_VERSION,
        "数据库元数据范围": config["数据库元数据范围"],
        "状态范围": ["已观察", "拒绝", "无法判定", "失败", "未成熟", "失效"],
        "主研究尺度": config["主研究尺度"],
        "事后结果观察窗口": config["事后结果观察窗口"],
    })


def executor_fingerprint() -> str:
    return engine.file_fingerprint(Path(__file__))


def _read(path: Path, label: str) -> bytes:
    return engine._read_regular_bytes(path, label)


def load_config(path: Path = CONFIG_PATH, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    raw = json.loads(_read(path, "数据库元数据身份证据配置").decode("utf-8"))
    if not isinstance(raw, dict) or set(raw) != CONFIG_KEYS:
        raise ValueError("数据库元数据身份证据配置字段漂移")
    if raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("数据库元数据身份证据配置版本或任务编号漂移")
    if raw["任务-000076来源身份批次"] != "source-identity-field-evidence-20260808T020108+0800-7634991794d9":
        raise ValueError("任务-000076来源身份批次漂移")
    if raw["标的"] != list(TARGETS) or raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("标的或研究尺度漂移")
    if raw["允许SSH目标"] != ["ubuntu"] or raw["数据库元数据范围"] != ["information_schema.TABLES", "information_schema.COLUMNS"]:
        raise ValueError("SSH或数据库元数据范围漂移")
    safety = raw["安全边界"]
    if not isinstance(safety, dict) or set(safety) != SAFETY_KEYS or any(value is not False for value in safety.values()):
        raise ValueError("安全边界必须全部为false")
    inputs = raw["输入文件"]
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("输入文件不能为空")
    seen: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != INPUT_KEYS:
            raise ValueError("输入文件字段漂移")
        relative = str(item["路径"])
        if relative in seen:
            raise ValueError("输入文件重复")
        seen.add(relative)
        if _sha(_read(repo_root / relative, "数据库元数据身份证据输入")) != item["SHA-256"]:
            raise ValueError(f"输入文件指纹漂移：{relative}")
    resources = raw["资源上限"]
    if not isinstance(resources, dict) or set(resources) != RESOURCE_KEYS:
        raise ValueError("资源上限字段漂移")
    if not 10 <= int(resources["批次总超时秒"]) <= 3600 or not 1 <= int(resources["逐成员超时秒"]) <= 30:
        raise ValueError("资源上限非法")
    if int(resources["最大成员数"]) < 184:
        raise ValueError("成员资源上限不足")
    return raw


def _input_path(config: Mapping[str, object], purpose: str, repo_root: Path) -> Path:
    for item in config["输入文件"]:
        if item["用途"] == purpose:
            return repo_root / str(item["路径"])
    raise ValueError(f"缺少输入：{purpose}")


def load_members(config: Mapping[str, object], repo_root: Path = REPO_ROOT) -> list[dict[str, str]]:
    path = _input_path(config, "任务-000076成员清单", repo_root)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    source_batch = str(config["任务-000076来源身份批次"])
    selected = [row for row in rows if row.get("来源身份批次") == source_batch and row.get("资产类型") == DB_ASSET_TYPE]
    if len(selected) != 184 or len({row.get("资产编号") for row in selected}) != 92:
        raise ValueError("任务-000076数据库成员覆盖不是92个资产/184个成员")
    if any(row.get("标的") not in TARGETS for row in selected):
        raise ValueError("数据库成员标的不在BTC/ETH")
    expected = sorted(selected, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if selected != expected:
        raise ValueError("数据库成员顺序不确定")
    required = {"来源身份批次", "成员编号", "资产编号", "资产类型", "标的", "输入成员SHA-256"}
    if any(set(row) < required for row in selected):
        raise ValueError("数据库成员字段不完整")
    return [{key: str(row[key]) for key in required} | {"来源身份批次": str(row["来源身份批次"])} for row in selected]


def load_database_assets(config: Mapping[str, object], repo_root: Path = REPO_ROOT) -> list[dict[str, str]]:
    inventory_bytes = _read(_input_path(config, "资产清单", repo_root), "资产清单")
    contract = engine.load_contract(engine.DEFAULT_CONTRACT, repo_root=repo_root)
    all_assets = engine.build_probe_assets_from_inventory_bytes(inventory_bytes, contract)
    member_ids = {row["资产编号"] for row in load_members(config, repo_root)}
    assets = [asset for asset in all_assets if asset["资产类型"] == DB_ASSET_TYPE and asset["资产编号"] in member_ids]
    if len(assets) != 92 or len({asset["资产编号"] for asset in assets}) != 92:
        raise ValueError("资产清单数据库对象覆盖不是92个")
    return assets


def build_probe_script(assets: Sequence[Mapping[str, str]], config: Mapping[str, object]) -> str:
    if not assets or any(asset.get("资产类型") != DB_ASSET_TYPE for asset in assets):
        raise ValueError("探针只接受数据库元数据资产")
    contract = engine.load_contract(engine.DEFAULT_CONTRACT, repo_root=REPO_ROOT)
    script = engine.build_probe_script(list(assets), contract)
    if "information_schema.TABLES" not in script or "information_schema.COLUMNS" not in script:
        raise ValueError("探针缺少固定information_schema范围")
    if "SELECT * FROM" in script or "SELECT *" in script:
        raise ValueError("探针出现业务正文查询")
    return script


def run_probe(
    command: Sequence[str], script: str, resources: Mapping[str, object],
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict[str, object]:
    timeout = int(resources["批次总超时秒"])
    stdout_limit = int(resources["最大输出字节数"])
    stderr_limit = int(resources["最大日志字节数"])
    if runner is None:
        completed = engine.run_bounded_process(command, input_text=script, timeout=timeout, maximum_stdout=stdout_limit, maximum_stderr=stderr_limit)
    else:
        completed = runner(command, input=script, capture_output=True, text=True, timeout=timeout, check=False)
        stderr = completed.stderr if isinstance(completed.stderr, str) else ""
        if len(stderr.encode("utf-8")) > stderr_limit:
            raise RuntimeError("数据库元数据探针日志超限，未发布批次")
    if completed.returncode != 0:
        raise RuntimeError("数据库元数据只读探针失败，未发布批次")
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if len(stdout.encode("utf-8")) > stdout_limit:
        raise RuntimeError("数据库元数据探针输出超限，未发布批次")
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("数据库元数据探针响应非法，未发布批次") from error
    return payload


def _authorization_fingerprint(asset_id: str, config: Mapping[str, object]) -> str:
    return _fingerprint({
        "资产编号": asset_id,
        "SSH逻辑目标": "ubuntu",
        "数据库元数据范围": config["数据库元数据范围"],
        "远端写入": False,
        "数据库业务记录读取": False,
        "凭据读取": False,
    })


def build_rows(
    members: Sequence[Mapping[str, str]], assets: Sequence[Mapping[str, str]],
    payload: Mapping[str, object], batch_id: str, config: Mapping[str, object],
    *, probe_hash: str | None = None, rules_hash: str | None = None,
    executor_hash: str | None = None,
) -> tuple[list[dict[str, str]], dict[str, object]]:
    engine.validate_probe_result(payload, assets)
    by_asset = {str(item["资产编号"]): item for item in payload["结果"]}
    asset_by_id = {str(asset["资产编号"]): asset for asset in assets}
    rows: list[dict[str, str]] = []
    probe_hash = probe_hash or _fingerprint(payload)
    rules_hash = rules_hash or rules_fingerprint(config)
    executor_hash = executor_hash or executor_fingerprint()
    for member in members:
        asset_id = member["资产编号"]
        probe = by_asset[asset_id]
        asset = asset_by_id[asset_id]
        metadata_state = str(probe["复核状态"])
        prior_state = "拒绝" if str(member.get("状态", "")) == "拒绝" else "无法判定"
        final_state = "拒绝" if prior_state == "拒绝" or metadata_state == "拒绝" else "无法判定"
        if prior_state == "拒绝":
            reason_code = "INPUT_MEMBER_REJECTED"
        elif metadata_state == "拒绝":
            reason_code = "METADATA_REJECTED"
        elif metadata_state == "失败":
            reason_code = "METADATA_PROBE_FAILED"
        elif metadata_state == "未成熟":
            reason_code = "METADATA_NOT_MATURE"
        elif metadata_state == "失效":
            reason_code = "METADATA_INVALIDATED"
        elif metadata_state == "已观察":
            reason_code = "METADATA_OBSERVED_IDENTITY_UNPROVEN"
        else:
            reason_code = "METADATA_UNDETERMINED"
        metadata_hash = str(probe["元数据SHA-256"] or "未知")
        schema_hash = str(probe["SchemaSHA-256"] or "未知")
        row = {
            "来源身份批次": str(member["来源身份批次"]),
            "成员编号": str(member["成员编号"]),
            "资产编号": asset_id,
            "资产类型": DB_ASSET_TYPE,
            "标的": str(member["标的"]),
            "输入成员SHA-256": str(member["输入成员SHA-256"]),
            "数据库Schema": "sha256:" + _fingerprint({"数据库Schema": str(asset["数据库Schema"])}),
            "数据库表": "sha256:" + _fingerprint({"数据库表": str(asset["数据库表"])}),
            "状态": final_state,
            "元数据状态": metadata_state,
            "原因代码": reason_code,
            "证据定位": (
                "固定探针:information_schema.TABLES;information_schema.COLUMNS;"
                f"资产编号={asset_id};成员编号={member['成员编号']};"
                f"元数据SHA-256={metadata_hash};SchemaSHA-256={schema_hash}"
            ),
            "结构证据": str(probe["证据"]),
            "限制": "只读取information_schema元数据；结构观察不证明来源、市场、合约或时间",
            "解除条件": "补齐当前版本来源提供者、交易场所、市场类型、精确合约、数据对象、Schema和授权证据后重新发布不可变批次",
            "元数据SHA-256": metadata_hash,
            "SchemaSHA-256": schema_hash,
            "授权边界快照SHA-256": _authorization_fingerprint(asset_id, config),
            "探针SHA-256": probe_hash,
            "规则SHA-256": rules_hash,
            "执行器SHA-256": executor_hash,
        }
        row["成员记录SHA-256"] = _fingerprint(row)
        rows.append(row)
    expected = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != expected:
        raise ValueError("输出成员顺序不确定")
    states = ("已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")
    summary = {
        "候选总体": len(asset_by_id),
        "身份成员总体": len(rows),
        "已观察": sum(row["元数据状态"] == "已观察" for row in rows),
        "拒绝": sum(row["状态"] == "拒绝" for row in rows),
        "无法判定": sum(row["状态"] == "无法判定" for row in rows),
        "失败": sum(row["元数据状态"] == "失败" for row in rows),
        "未成熟": sum(row["状态"] == "未成熟" for row in rows),
        "失效": sum(row["状态"] == "失效" for row in rows),
        "状态计数范围": states,
        "分标的": {
            target: {
                "候选总体": len({row["资产编号"] for row in rows if row["标的"] == target}),
                "已观察": sum(row["元数据状态"] == "已观察" for row in rows if row["标的"] == target),
                "拒绝": sum(row["状态"] == "拒绝" for row in rows if row["标的"] == target),
                "无法判定": sum(row["状态"] == "无法判定" for row in rows if row["标的"] == target),
            } for target in TARGETS
        },
        "结论边界": "数据库结构证据不构成完整来源身份、时间质量、研究准入或交易许可",
    }
    if summary["身份成员总体"] != summary["候选总体"] * 2:
        raise ValueError("成员状态计数不守恒")
    return rows, summary


def _render_csv(rows: Sequence[Mapping[str, str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: engine.safe_csv_cell(row[key]) for key in OUTPUT_COLUMNS})
    return output.getvalue()


def execute_batch(
    config_path: Path = CONFIG_PATH, ssh_target: str = "ubuntu",
    batch_root: Path = DEFAULT_BATCH_ROOT, timeout: int = 600, *,
    repo_root: Path = REPO_ROOT, runner: Callable[..., subprocess.CompletedProcess] | None = None,
    now: dt.datetime | None = None,
) -> Path:
    config = load_config(config_path, repo_root)
    if ssh_target not in config["允许SSH目标"]:
        raise ValueError("SSH目标不在白名单")
    resources = config["资源上限"]
    if timeout < 10 or timeout > int(resources["批次总超时秒"]):
        raise ValueError("批次超时超出资源上限")
    members = load_members(config, repo_root)
    assets = load_database_assets(config, repo_root)
    assets_by_id = {asset["资产编号"]: asset for asset in assets}
    if {member["资产编号"] for member in members} != set(assets_by_id):
        raise ValueError("成员与数据库资产集合不一致")
    script = build_probe_script(assets, config)
    command = engine.build_ssh_command("ssh", ssh_target, timeout)
    payload = run_probe(command, script, resources, runner)
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    config_hash = engine.file_fingerprint(config_path)
    task_hash = engine.file_fingerprint(repo_root / "docs/研发中心/任务/任务-000077.md")
    snapshot_hash = engine.file_fingerprint(TASK_CONTRACT_SNAPSHOT_PATH)
    rules_hash = rules_fingerprint(config)
    executor_hash = executor_fingerprint()
    members_hash = _fingerprint(members)
    assets_hash = _fingerprint(assets)
    probe_hash = _fingerprint(payload)
    batch_payload = {
        "合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "配置SHA-256": config_hash,
        "成员SHA-256": members_hash, "资产清单指纹": assets_hash, "探针SHA-256": probe_hash,
        "任务文件SHA-256": task_hash,
    }
    batch_id = "database-metadata-identity-evidence-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + _fingerprint(batch_payload)[:12]
    rows, summary = build_rows(
        members, assets, payload, batch_id, config,
        probe_hash=probe_hash, rules_hash=rules_hash, executor_hash=executor_hash,
    )
    csv_text = _render_csv(rows)
    manifest = {
        "合同版本": CONTRACT_VERSION, "任务编号": TASK_ID,
        "任务-000077数据库元数据身份证据批次": batch_id,
        "来源身份批次": config["任务-000076来源身份批次"],
        "冻结时间": frozen.isoformat(timespec="microseconds"), "SSH逻辑目标": "ubuntu",
        "探针版本": PROBE_VERSION, "探针SHA-256": probe_hash, "配置SHA-256": config_hash,
        "成员SHA-256": members_hash, "资产清单SHA-256": assets_hash, "任务文件SHA-256": task_hash,
        "执行器SHA-256": executor_hash, "规则SHA-256": rules_hash,
        "任务合同快照路径": "任务-000077执行合同快照.md", "任务合同快照SHA-256": snapshot_hash,
        "结果摘要": summary,
        "数据库元数据范围": config["数据库元数据范围"],
        "授权边界": {"SSH逻辑目标": "ubuntu", "只读": True, "范围": config["数据库元数据范围"]},
        "安全声明": {"远端写入": False, "数据库业务记录读取": False, "读取凭据": False, "原始业务记录落盘": False},
        "撤销事实": "本批次无远端临时文件；只读探针结束后不保留远端状态；结果由输入、规则和探针指纹复算",
        "输出SHA-256": {"数据库元数据身份证据清单.csv": _sha(csv_text.encode("utf-8"))},
        "结论边界": "结构证据不关闭ZS-DATA-GAP-001，不解除阶段1或阶段2",
    }
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode()) + len(json_text.encode()) > int(resources["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=".database-metadata-identity-evidence-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "数据库元数据身份证据清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        (staging / "批次清单.json").write_text(json_text, encoding="utf-8")
        (staging / "任务-000077执行合同快照.md").write_bytes(_read(TASK_CONTRACT_SNAPSHOT_PATH, "任务合同快照"))
        engine._scan_outputs([
            staging / "数据库元数据身份证据清单.csv", staging / "批次清单.json",
            staging / "任务-000077执行合同快照.md",
        ])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "任务-000077数据库元数据身份证据批次": batch_id, "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(description="执行任务-000077数据库元数据身份证据复采")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--ssh-target", default="ubuntu")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--timeout", type=int, default=600)
    try:
        args = parser.parse_args(argv)
        execute_batch(args.config, args.ssh_target, args.batch_root, args.timeout)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError):
        print("数据库元数据身份证据复采失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
