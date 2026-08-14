#!/usr/bin/env python3
"""执行任务-000075的来源身份输入指纹漂移复采。

本入口只比较仓库内当前main与任务-000072执行前基线的输入字节，并复用
已有固定来源身份只读探针。历史批次、原始文件和远端业务记录均保持只读。
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

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine
from scripts.数据 import 复采来源身份 as source_recapture


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000075"
CONTRACT_VERSION = "source-identity-input-drift-recapture-1.0"
PROBE_VERSION = "source-identity-input-drift-probe-1.0"
CONFIG_PATH = REPO_ROOT / "config" / "数据" / "来源身份输入指纹复采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts" / "数据" / "来源身份输入指纹复采"
TASK_PATH = "docs/研发中心/任务/任务-000075.md"
CONFIG_KEYS = {
    "合同版本", "任务编号", "治理基线", "历史批次", "当前输入文件", "标的",
    "主研究尺度", "事后结果观察窗口", "允许SSH目标", "数据库元数据范围",
    "安全边界", "资源上限",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bytes(path: Path, label: str) -> bytes:
    return engine._read_regular_bytes(path, label)


def _load_config(path: Path = CONFIG_PATH, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    raw_bytes = _read_bytes(path, "来源身份输入指纹复采配置")
    raw = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(raw, dict) or set(raw) != CONFIG_KEYS:
        raise ValueError("来源身份输入指纹复采配置字段漂移")
    if raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("来源身份输入指纹复采配置版本或任务编号漂移")
    if raw["标的"] != ["BTC", "ETH"]:
        raise ValueError("标的范围漂移")
    if raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"]:
        raise ValueError("主研究尺度漂移")
    if raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("结果观察窗口漂移")
    if raw["允许SSH目标"] != ["ubuntu"]:
        raise ValueError("SSH白名单漂移")
    if raw["数据库元数据范围"] != ["information_schema.TABLES", "information_schema.COLUMNS"]:
        raise ValueError("数据库元数据范围漂移")
    safety = raw["安全边界"]
    if not isinstance(safety, dict) or set(safety) != {
        "远端写入", "数据库业务记录读取", "读取环境变量或凭据",
        "原始业务记录落盘", "修改原始数据", "修改生产系统",
    } or any(value is not False for value in safety.values()):
        raise ValueError("安全边界必须全部为false")
    governance = raw["治理基线"]
    if not isinstance(governance, dict) or governance.get("main基线提交") != "42d6715a82549f5858a369f357a6e3ce849ae87b":
        raise ValueError("治理基线漂移")
    history = raw["历史批次"]
    if not isinstance(history, dict):
        raise ValueError("历史批次配置非法")
    history_path = repo_root / str(history.get("路径"))
    history_bytes = _read_bytes(history_path, "历史来源身份批次")
    if _sha(history_bytes) != history.get("文件SHA-256"):
        raise ValueError("历史来源身份批次指纹漂移")
    history_manifest = json.loads(history_bytes.decode("utf-8"))
    historical_inputs = history_manifest.get("输入SHA-256")
    expected_historical = history.get("输入SHA-256")
    if not isinstance(historical_inputs, dict) or historical_inputs != expected_historical:
        raise ValueError("历史来源身份输入指纹与批次不一致")
    if not isinstance(history.get("历史Git基线提交"), str) or len(history["历史Git基线提交"]) != 40:
        raise ValueError("历史Git基线提交非法")
    current = raw["当前输入文件"]
    if not isinstance(current, list) or not current:
        raise ValueError("当前输入文件不能为空")
    seen: set[str] = set()
    for item in current:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"}:
            raise ValueError("当前输入文件成员字段漂移")
        path_text = item["路径"]
        if not isinstance(path_text, str) or path_text in seen:
            raise ValueError("当前输入文件路径重复")
        seen.add(path_text)
        data = _read_bytes(repo_root / path_text, "当前输入文件")
        if _sha(data) != item["SHA-256"]:
            raise ValueError(f"当前输入文件指纹漂移：{path_text}")
    resources = raw["资源上限"]
    if not isinstance(resources, dict) or set(resources) != {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}:
        raise ValueError("资源上限字段漂移")
    if not 10 <= resources["批次总超时秒"] <= 3600 or not 1 <= resources["逐成员超时秒"] <= 30:
        raise ValueError("资源上限超出安全范围")
    return raw


def _git_bytes(repo_root: Path, commit: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(repo_root.resolve()), "show", f"{commit}:{path}"],
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def classify_drift(current: bytes | None, historical: bytes | None) -> str:
    """对两个确定性字节版本作保守漂移分类。"""

    if current is None or historical is None:
        return "输入缺失"
    if current == historical:
        return "未漂移"
    if current.replace(b"\r\n", b"\n") == historical.replace(b"\r\n", b"\n"):
        return "仅换行规范化差异"
    return "内容变化"


def _drift_snapshot(config: Mapping[str, object], repo_root: Path) -> list[dict[str, object]]:
    history = config["历史批次"]
    assert isinstance(history, dict)
    commit = str(history["历史Git基线提交"])
    historical_hashes = history["输入SHA-256"]
    assert isinstance(historical_hashes, dict)
    rows: list[dict[str, object]] = []
    current_files = config["当前输入文件"]
    assert isinstance(current_files, list)
    for item in current_files:
        assert isinstance(item, dict)
        path = str(item["路径"])
        current = _read_bytes(repo_root / path, "当前输入文件")
        historical = _git_bytes(repo_root, commit, path)
        historical_hash = historical_hashes.get(path)
        if historical is None or (historical_hash is not None and _sha(historical) != historical_hash):
            raise ValueError(f"历史输入无法由基线复算：{path}")
        rows.append({
            "用途": item["用途"],
            "路径": path,
            "历史SHA-256": _sha(historical),
            "当前SHA-256": _sha(current),
            "漂移分类": classify_drift(current, historical),
        })
    return rows


def execute_batch(
    config_path: Path = CONFIG_PATH,
    ssh_target: str = "ubuntu",
    batch_root: Path = DEFAULT_BATCH_ROOT,
    timeout: int = 600,
    *,
    repo_root: Path = REPO_ROOT,
    ssh_bin: str = "ssh",
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
    now: dt.datetime | None = None,
) -> Path:
    config = _load_config(config_path, repo_root)
    if ssh_target not in config["允许SSH目标"]:
        raise ValueError("SSH目标不在白名单")
    resources = config["资源上限"]
    assert isinstance(resources, dict)
    if timeout < 10 or timeout > int(resources["批次总超时秒"]):
        raise ValueError("批次超时超出资源上限")
    drift_rows = _drift_snapshot(config, repo_root)
    current_files = config["当前输入文件"]
    assert isinstance(current_files, list)
    inventory_path = next(item["路径"] for item in current_files if item["用途"] == "资产清单")
    inventory_bytes = _read_bytes(repo_root / str(inventory_path), "资产清单")
    source_contract = source_recapture.load_contract(repo_root=repo_root)
    members = engine.build_members_from_inventory_bytes(inventory_bytes, source_contract)
    if len(members) > int(resources["最大成员数"]):
        raise ValueError("候选成员超过资源上限")
    assets = engine.build_probe_assets_from_inventory_bytes(inventory_bytes, source_contract)
    probe_script = engine.build_probe_script(assets, source_contract).replace(
        f"PROBE_VERSION = {source_recapture.PROBE_VERSION!r}",
        f"PROBE_VERSION = {PROBE_VERSION!r}",
    )
    command = engine.build_ssh_command(ssh_bin, ssh_target, timeout)
    if runner is None:
        completed = engine.run_bounded_process(
            command, input_text=probe_script, timeout=timeout,
            maximum_stdout=int(resources["最大输出字节数"]), maximum_stderr=int(resources["最大日志字节数"]),
        )
    else:
        completed = runner(command, input=probe_script, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode != 0:
        raise RuntimeError("只读来源身份复采失败：远端非零状态，未发布批次")
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    stderr = completed.stderr if isinstance(completed.stderr, str) else ""
    if len(stdout.encode()) > int(resources["最大输出字节数"]) or len(stderr.encode()) > int(resources["最大日志字节数"]):
        raise RuntimeError("只读来源身份复采失败：响应超过资源上限，未发布批次")
    try:
        raw_probe = json.loads(stdout)
    except ValueError as error:
        raise RuntimeError("只读来源身份复采失败：响应不是合法JSON，未发布批次") from error
    previous_probe_version = engine.PROBE_VERSION
    engine.PROBE_VERSION = PROBE_VERSION
    try:
        probe = engine.validate_probe_result(raw_probe, [{"资产编号": a["资产编号"], "资产类型": a["资产类型"]} for a in assets])
        rows, summary = engine.evaluate_identities(members, probe, source_contract)
    finally:
        engine.PROBE_VERSION = previous_probe_version
    frozen_time = now or dt.datetime.now().astimezone()
    if frozen_time.tzinfo is None or frozen_time.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    drift_payload = {
        "当前输入": drift_rows,
        "漂移计数": {name: sum(1 for row in drift_rows if row["漂移分类"] == name) for name in ("未漂移", "仅换行规范化差异", "内容变化", "输入缺失", "路径越界", "无法判定")},
    }
    executor_hash = engine.file_fingerprint(Path(__file__))
    task_hash = engine.file_fingerprint(repo_root / TASK_PATH)
    payload: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "配置SHA-256": engine.file_fingerprint(config_path),
        "历史批次文件SHA-256": str(config["历史批次"]["文件SHA-256"]),
        "历史Git基线提交": config["历史批次"]["历史Git基线提交"],
        "漂移快照": drift_payload,
        "规则SHA-256": engine.file_fingerprint(repo_root / "config/数据/来源身份复采.json"),
        "执行器SHA-256": executor_hash,
        "任务文件SHA-256": task_hash,
        "成员SHA-256": engine.object_fingerprint(members),
        "结果摘要": summary,
    }
    payload_hash = engine.object_fingerprint(payload)
    batch_id = "source-identity-input-drift-" + frozen_time.strftime("%Y%m%dT%H%M%S%z") + "-" + payload_hash[:12]
    csv_text = engine._render_csv(rows, batch_id)
    csv_hash = _sha(csv_text.encode("utf-8"))
    manifest: dict[str, object] = {
        "合同版本": CONTRACT_VERSION,
        "任务编号": TASK_ID,
        "来源身份输入指纹批次": batch_id,
        "冻结时间": frozen_time.isoformat(timespec="microseconds"),
        "SSH逻辑目标": "ubuntu",
        "远端写入": False,
        "数据库业务记录读取": False,
        "读取环境变量或凭据": False,
        "历史批次": config["历史批次"],
        "漂移快照": drift_payload,
        "执行器SHA-256": executor_hash,
        "任务文件SHA-256": task_hash,
        "成员SHA-256": engine.object_fingerprint(members),
        "结果摘要": summary,
        "批次载荷": payload,
        "批次载荷SHA-256": payload_hash,
        "输出SHA-256": {"来源身份清单.csv": csv_hash, "批次清单.json载荷": payload_hash},
        "成员顺序": rows,
        "安全声明": {"远端不落盘": True, "仅固定information_schema元数据": True, "未记录地址用户名凭据原始业务记录": True},
        "结论边界": "本批次只复核输入漂移与来源身份，不完成时间、质量、重放、成本、模型、回测、收益或交易许可",
    }
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode()) + len(json_text.encode()) > int(resources["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    if batch_root.is_symlink() or not batch_root.is_dir():
        raise ValueError("批次根目录必须是普通目录")
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=".source-identity-input-drift-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "来源身份清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        (staging / "批次清单.json").write_text(json_text, encoding="utf-8")
        engine._scan_outputs([staging / "来源身份清单.csv", staging / "批次清单.json"])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "来源身份输入指纹批次": batch_id, "结果摘要": summary, "漂移计数": drift_payload["漂移计数"]}, ensure_ascii=False, sort_keys=True))
    return target


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(description="执行任务-000075来源身份输入指纹漂移复采")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--ssh-target", default="ubuntu")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--ssh-bin", default="ssh")
    try:
        args = parser.parse_args(argv)
        execute_batch(args.config, args.ssh_target, args.batch_root, args.timeout, ssh_bin=args.ssh_bin)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError):
        print("来源身份输入指纹复采失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
