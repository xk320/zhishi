#!/usr/bin/env python3
"""执行任务-000072的来源身份与标的范围只读复采。

本入口复用任务-000029已经验证过的探针、成员排序和保守判定逻辑，
但使用独立的任务合同、执行器指纹和不可变批次命名。远端只接收固定
的标准输入探针，不写入文件、数据库或服务，也不读取业务记录。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence

# 允许按任务合同中的直接命令从仓库根目录外启动。
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000072"
CONTRACT_VERSION = "source-identity-recapture-1.0"
PROBE_VERSION = "source-identity-recapture-probe-1.0"
TASK_PATH = "docs/研发中心/任务/任务-000072.md"
DEFAULT_CONTRACT = REPO_ROOT / "config" / "数据" / "来源身份复采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts" / "数据" / "来源身份复采"
BASELINE_KEYS = {
    "main基线提交",
    "任务-000071合并提交",
    "任务-000072基线路径",
    "任务-000072基线SHA-256",
}

# 使复用的探针构造器与本任务的确切版本一致；不改写任务-000029的历史脚本。
engine.PROBE_VERSION = PROBE_VERSION


def _snapshot(contract_path: Path, repo_root: Path) -> dict[str, object]:
    """冻结合同、输入、任务和本执行器的字节，避免执行中漂移。"""

    contract_bytes = engine._read_regular_bytes(contract_path, "来源身份复采合同")
    try:
        raw = json.loads(contract_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("来源身份复采合同不是合法JSON") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("输入文件"), list):
        raise ValueError("来源身份复采合同结构非法")
    input_paths: dict[str, Path] = {}
    input_bytes: dict[str, bytes] = {}
    input_hashes: dict[str, str] = {}
    purpose_bytes: dict[str, bytes] = {}
    for item in raw["输入文件"]:
        if not isinstance(item, dict):
            raise ValueError("来源身份复采合同输入结构非法")
        purpose = item.get("用途")
        relative = item.get("路径")
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("来源身份复采合同输入用途非法")
        path = engine._resolve_repository_file(repo_root, relative, "执行快照输入")
        data = engine._read_regular_bytes(path, "执行快照输入")
        relative_text = str(relative)
        if relative_text in input_paths or purpose in purpose_bytes:
            raise ValueError("来源身份复采合同输入不得重复")
        input_paths[relative_text] = path
        input_bytes[relative_text] = data
        input_hashes[relative_text] = engine.bytes_fingerprint(data)
        purpose_bytes[purpose] = data
    task_path = engine._resolve_repository_file(repo_root, TASK_PATH, "当前执行任务文件")
    executor_path = Path(__file__).resolve()
    return {
        "配置路径": contract_path,
        "配置字节": contract_bytes,
        "规则SHA-256": engine.bytes_fingerprint(contract_bytes),
        "执行器路径": executor_path,
        "执行器SHA-256": engine.file_fingerprint(executor_path),
        "当前任务路径": task_path,
        "当前执行任务文件SHA-256": engine.file_fingerprint(task_path),
        "输入路径": input_paths,
        "输入字节": input_bytes,
        "用途输入字节": purpose_bytes,
        "输入SHA-256": input_hashes,
    }


def _validate_baseline(value: object, repo_root: Path) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("治理基线必须是对象")
    engine._require_exact_keys(value, BASELINE_KEYS, "治理基线")
    for name in ("main基线提交", "任务-000071合并提交"):
        item = value[name]
        if not isinstance(item, str) or len(item) != 40 or any(c not in "0123456789abcdef" for c in item):
            raise ValueError(f"治理基线{name}格式非法")
    if value["任务-000072基线路径"] != TASK_PATH:
        raise ValueError("治理基线任务路径漂移")
    baseline_hash = value["任务-000072基线SHA-256"]
    if not isinstance(baseline_hash, str) or not engine.SHA256_PATTERN.fullmatch(baseline_hash):
        raise ValueError("治理基线任务内容指纹格式非法")
    completed = engine.run_bounded_process(
        ["git", "-C", str(repo_root.resolve()), "show", f"{value['main基线提交']}:{TASK_PATH}"],
        input_text="",
        timeout=10,
        maximum_stdout=1024 * 1024,
        maximum_stderr=4096,
    )
    baseline_bytes = completed.stdout.encode("utf-8") if isinstance(completed.stdout, str) else completed.stdout
    if completed.returncode != 0 or hashlib.sha256(baseline_bytes).hexdigest() != baseline_hash:
        raise ValueError("治理基线任务内容指纹不一致")
    return {key: str(value[key]) for key in BASELINE_KEYS}


def _load_contract_from_bytes(
    contract_bytes: bytes,
    input_bytes: Mapping[str, bytes],
    repo_root: Path,
) -> dict[str, object]:
    contract = engine._parse_contract_bytes(contract_bytes)
    engine._require_exact_keys(contract, engine.CONTRACT_KEYS, "来源身份复采合同")
    if contract["合同版本"] != CONTRACT_VERSION or contract["任务编号"] != TASK_ID:
        raise ValueError("来源身份复采合同版本或任务编号漂移")
    _validate_baseline(contract["治理基线"], repo_root)
    for field, expected in (
        ("候选资产类型", engine.ALLOWED_ASSET_TYPES),
        ("标的", engine.TARGETS),
        ("身份字段", engine.IDENTITY_FIELDS),
        ("允许状态", engine.STATES),
        ("允许SSH目标", ["ubuntu"]),
        ("允许文件根目录", engine.ALLOWED_FILE_ROOTS),
        ("数据库元数据范围", engine.APPROVED_DATABASE_METADATA),
    ):
        engine._require_exact_string_list(contract[field], expected, field)
    inputs = contract["输入文件"]
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("输入文件必须是非空列表")
    purposes: set[str] = set()
    paths: set[str] = set()
    input_fingerprints: dict[str, str] = {}
    identity_evidence: dict[str, dict[str, dict[str, object]]] = {}
    inventory_bytes: bytes | None = None
    for item in inputs:
        if not isinstance(item, dict):
            raise ValueError("输入文件成员必须是对象")
        engine._require_exact_keys(item, engine.INPUT_KEYS, "输入文件成员")
        purpose, relative, expected = item["用途"], item["路径"], item["SHA-256"]
        if not isinstance(purpose, str) or not purpose or purpose in purposes:
            raise ValueError("输入文件用途必须非空且唯一")
        if not isinstance(relative, str) or not relative or relative in paths:
            raise ValueError("输入文件路径必须非空且唯一")
        if not isinstance(expected, str) or not engine.SHA256_PATTERN.fullmatch(expected):
            raise ValueError("输入文件指纹格式非法")
        frozen = input_bytes.get(relative)
        if not isinstance(frozen, bytes) or engine.bytes_fingerprint(frozen) != expected:
            raise ValueError(f"输入文件指纹漂移：{purpose}")
        purposes.add(purpose)
        paths.add(relative)
        input_fingerprints[purpose] = expected
        if purpose.startswith("身份合同证据:"):
            identity_evidence[purpose] = engine._load_identity_evidence_bytes(frozen)
        if purpose == "资产清单":
            inventory_bytes = frozen
    if inventory_bytes is None:
        raise ValueError("输入文件缺少资产清单")
    resources = contract["资源上限"]
    if not isinstance(resources, dict):
        raise ValueError("资源上限必须是对象")
    engine._require_exact_keys(resources, engine.RESOURCE_KEYS, "资源上限")
    bounds = {
        "批次总超时秒": (10, 3600),
        "逐成员超时秒": (1, 30),
        "最大成员数": (2, 10_000),
        "最大输出字节数": (1024, 64 * 1024 * 1024),
        "最大日志字节数": (256, 1024 * 1024),
    }
    for name, (minimum, maximum) in bounds.items():
        value = resources[name]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"{name}超出安全范围")
    if resources["逐成员超时秒"] >= resources["批次总超时秒"]:
        raise ValueError("逐成员超时必须小于批次总超时")
    safety = contract["安全边界"]
    if not isinstance(safety, dict):
        raise ValueError("安全边界必须是对象")
    engine._require_exact_keys(safety, engine.SAFETY_KEYS, "安全边界")
    if any(safety[name] is not False for name in engine.SAFETY_KEYS):
        raise ValueError("安全边界不得授权写入、正文读取或原始数据修改")
    member_fingerprints = {
        str(member["资产编号"]): str(member["输入成员SHA-256"])
        for member in engine.build_members_from_inventory_bytes(inventory_bytes, contract)
    }
    engine._validate_claims(contract["身份声明"], input_fingerprints, member_fingerprints, identity_evidence)
    if engine._contains_sensitive(engine.canonical_json(contract)):
        raise ValueError("来源身份复采合同包含地址、用户名或敏感信息")
    return contract


def load_contract(path: Path = DEFAULT_CONTRACT, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    contract_bytes = engine._read_regular_bytes(path, "来源身份复采合同")
    raw = engine._parse_contract_bytes(contract_bytes)
    input_bytes: dict[str, bytes] = {}
    for item in raw.get("输入文件", []):
        if isinstance(item, dict) and isinstance(item.get("路径"), str):
            relative = str(item["路径"])
            input_bytes[relative] = engine._read_regular_bytes(
                engine._resolve_repository_file(repo_root, relative, "输入文件"), "输入文件"
            )
    return _load_contract_from_bytes(contract_bytes, input_bytes, repo_root)


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
    snapshot = _snapshot(contract_path, repo_root)
    contract = _load_contract_from_bytes(snapshot["配置字节"], snapshot["输入字节"], repo_root)
    engine.assert_execution_snapshot(snapshot)
    if ssh_target not in contract["允许SSH目标"]:
        raise ValueError("SSH目标不在冻结合同白名单")
    if timeout < 10 or timeout > int(contract["资源上限"]["批次总超时秒"]):
        raise ValueError("批次超时超出冻结资源上限")
    inventory_bytes = snapshot["用途输入字节"].get("资产清单")
    if not isinstance(inventory_bytes, bytes):
        raise ValueError("执行快照缺少冻结资产清单")
    assets = engine.build_probe_assets_from_inventory_bytes(inventory_bytes, contract)
    members = engine.build_members_from_inventory_bytes(inventory_bytes, contract)
    probe_script = engine.build_probe_script(assets, contract).replace(
        "PROBE_VERSION = 'source-identity-probe-1.0'",
        f"PROBE_VERSION = {PROBE_VERSION!r}",
    )
    command = engine.build_ssh_command(ssh_bin, ssh_target, timeout)
    if runner is None:
        completed = engine.run_bounded_process(
            command,
            input_text=probe_script,
            timeout=timeout,
            maximum_stdout=int(contract["资源上限"]["最大输出字节数"]),
            maximum_stderr=int(contract["资源上限"]["最大日志字节数"]),
        )
    else:
        completed = runner(command, input=probe_script, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode != 0:
        raise RuntimeError("只读来源身份复采失败：远端返回非零状态，未发布批次")
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    if len(stdout.encode()) > int(contract["资源上限"]["最大输出字节数"]) or len(stderr.encode()) > int(contract["资源上限"]["最大日志字节数"]):
        raise RuntimeError("只读来源身份复采失败：响应超过冻结资源上限，未发布批次")
    try:
        raw_probe = json.loads(stdout)
    except ValueError as error:
        raise RuntimeError("只读来源身份复采失败：远端响应不是合法JSON，未发布批次") from error
    assets_for_validation = [{"资产编号": a["资产编号"], "资产类型": a["资产类型"]} for a in assets]
    probe = engine.validate_probe_result(raw_probe, assets_for_validation)
    rows, summary = engine.evaluate_identities(members, probe, contract)
    frozen_time = now or dt.datetime.now().astimezone()
    if frozen_time.tzinfo is None or frozen_time.utcoffset() is None:
        raise ValueError("冻结时间必须包含时区")
    input_hashes = dict(snapshot["输入SHA-256"])
    rows_hash = engine.object_fingerprint(rows)
    payload: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "治理基线": contract["治理基线"],
        "输入SHA-256": input_hashes,
        "规则SHA-256": snapshot["规则SHA-256"],
        "执行器SHA-256": snapshot["执行器SHA-256"],
        "当前执行任务文件SHA-256": snapshot["当前执行任务文件SHA-256"],
        "成员SHA-256": engine.object_fingerprint(members),
        "清单内容SHA-256": rows_hash,
        "结果摘要": summary,
    }
    payload_hash = engine.object_fingerprint(payload)
    batch_id = "source-identity-recapture-" + frozen_time.strftime("%Y%m%dT%H%M%S%z") + "-" + payload_hash[:12]
    csv_text = engine._render_csv(rows, batch_id)
    csv_hash = hashlib.sha256(csv_text.encode("utf-8")).hexdigest()
    manifest: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份批次": batch_id,
        "冻结时间": frozen_time.isoformat(timespec="microseconds"),
        "SSH逻辑目标": "ubuntu",
        "远端写入": False,
        "数据库业务记录读取": False,
        "治理基线": contract["治理基线"],
        "输入SHA-256": input_hashes,
        "规则SHA-256": snapshot["规则SHA-256"],
        "执行器SHA-256": snapshot["执行器SHA-256"],
        "当前执行任务文件SHA-256": snapshot["当前执行任务文件SHA-256"],
        "成员SHA-256": engine.object_fingerprint(members),
        "清单内容SHA-256": rows_hash,
        "批次载荷": payload,
        "批次载荷SHA-256": payload_hash,
        "输出SHA-256": {"来源身份清单.csv": csv_hash, "身份清单.json载荷": payload_hash},
        "结果摘要": summary,
        "成员顺序": rows,
        "安全声明": {
            "远端不落盘": True,
            "仅复核白名单文件stat和获批information_schema元数据": True,
            "未记录主机地址用户名凭据或原始业务记录": True,
        },
        "结论边界": "本批次只复核来源身份，不完成时间、质量、重放、成本、模型、回测、收益或交易许可",
    }
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode()) + len(json_text.encode()) > int(contract["资源上限"]["最大输出字节数"]):
        raise ValueError("来源身份复采批次输出超过冻结大小上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    if batch_root.is_symlink() or not batch_root.is_dir():
        raise ValueError("批次根目录必须是普通目录")
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变来源身份复采批次已存在")
    with tempfile.TemporaryDirectory(prefix=".source-identity-recapture-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        csv_path = staging / "来源身份清单.csv"
        json_path = staging / "身份清单.json"
        csv_path.write_text(csv_text, encoding="utf-8", newline="")
        json_path.write_text(json_text, encoding="utf-8")
        engine._scan_outputs([csv_path, json_path])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "来源身份批次": batch_id, "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(description="执行任务-000072来源身份只读复采")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--ssh-bin", default="ssh")
    try:
        args = parser.parse_args(argv)
        execute_batch(args.contract, args.ssh_target, args.batch_root, args.timeout, ssh_bin=args.ssh_bin)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError):
        print("来源身份复采失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
