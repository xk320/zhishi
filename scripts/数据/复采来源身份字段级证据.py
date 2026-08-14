#!/usr/bin/env python3
"""执行任务-000076的来源身份字段级只读复采。

本入口只读取冻结输入、白名单文件stat和允许的information_schema元数据；不读取业务正文，
不保存原始字段值。证据不足时保持无法判定，历史批次不可覆盖。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import stat
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from pathlib import Path
from typing import Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000076"
CONTRACT_VERSION = "source-identity-field-evidence-recapture-1.0"
PROBE_VERSION = "source-identity-field-evidence-probe-1.0"
CONFIG_PATH = REPO_ROOT / "config/数据/来源身份字段级证据复采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts/数据/来源身份字段级证据复采"
TASK_PATH = "docs/研发中心/任务/任务-000076.md"
MEMBER_COLUMNS = (
    "来源身份批次", "成员编号", "资产编号", "资产类型", "标的", "来源提供者", "交易场所",
    "市场类型", "标的身份", "精确合约", "数据对象", "Schema确切版本", "授权边界",
    "字段中文映射", "状态", "证据", "限制", "解除条件", "输入成员SHA-256",
    "远端元数据SHA-256", "身份记录SHA-256",
)
OUTPUT_COLUMNS = MEMBER_COLUMNS + ("字段级证据SHA-256", "授权快照SHA-256", "字段证据状态")
TARGETS = ("BTC", "ETH")
FIELD_NAMES = (
    "来源提供者", "交易场所", "市场类型", "标的身份", "精确合约", "数据对象",
    "Schema确切版本", "授权边界", "字段中文映射",
)
SAFETY_KEYS = {
    "远端写入", "数据库业务记录读取", "读取环境变量或凭据", "原始业务记录落盘",
    "读取价格成交订单簿", "修改原始数据", "修改生产系统",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _fingerprint(value: object) -> str:
    return _sha(_canonical(value))


def _read(path: Path, label: str) -> bytes:
    return engine._read_regular_bytes(path, label)


def load_config(path: Path = CONFIG_PATH, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    raw = json.loads(_read(path, "字段级证据配置").decode("utf-8"))
    required = {"合同版本", "任务编号", "输入文件", "标的", "主研究尺度", "事后结果观察窗口", "字段白名单", "允许SSH目标", "数据库元数据范围", "安全边界", "资源上限"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("字段级证据配置字段漂移")
    if raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("字段级证据配置版本或任务编号漂移")
    if raw["标的"] != list(TARGETS) or raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("标的或研究尺度漂移")
    if raw["字段白名单"] != list(FIELD_NAMES) or raw["允许SSH目标"] != ["ubuntu"]:
        raise ValueError("字段或SSH白名单漂移")
    if raw["数据库元数据范围"] != ["information_schema.TABLES", "information_schema.COLUMNS", "information_schema.TABLE_PRIVILEGES"]:
        raise ValueError("数据库元数据范围漂移")
    safety = raw["安全边界"]
    if not isinstance(safety, dict) or set(safety) != SAFETY_KEYS or any(value is not False for value in safety.values()):
        raise ValueError("安全边界必须全部为false")
    inputs = raw["输入文件"]
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("输入文件不能为空")
    seen: set[str] = set()
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"}:
            raise ValueError("输入文件字段漂移")
        path_text = str(item["路径"])
        if path_text in seen:
            raise ValueError("输入文件重复")
        seen.add(path_text)
        if _sha(_read(repo_root / path_text, "字段级证据输入")) != item["SHA-256"]:
            raise ValueError(f"输入文件指纹漂移：{path_text}")
    resources = raw["资源上限"]
    if not isinstance(resources, dict) or set(resources) != {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}:
        raise ValueError("资源上限字段漂移")
    if not 10 <= int(resources["批次总超时秒"]) <= 3600 or not 1 <= int(resources["逐成员超时秒"]) <= 30:
        raise ValueError("资源上限非法")
    return raw


def _input_path(config: Mapping[str, object], purpose: str, repo_root: Path) -> Path:
    item = next(item for item in config["输入文件"] if item["用途"] == purpose)
    return repo_root / str(item["路径"])


def _load_members(config: Mapping[str, object], repo_root: Path) -> list[dict[str, str]]:
    path = _input_path(config, "任务-000075成员清单", repo_root)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or len(rows) > int(config["资源上限"]["最大成员数"]):
        raise ValueError("任务-000075成员为空或超出资源上限")
    if any(row.get("标的") not in TARGETS for row in rows) or len(rows) != 630:
        raise ValueError("成员必须完整覆盖BTC和ETH")
    expected = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != expected:
        raise ValueError("成员顺序不确定")
    return rows


def _load_inventory(config: Mapping[str, object], repo_root: Path) -> list[dict[str, str]]:
    path = _input_path(config, "资产清单", repo_root)
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build_probe_script(assets: Sequence[Mapping[str, str]], allowed_roots: Sequence[str], resources: Mapping[str, object]) -> str:
    assets_json = json.dumps(list(assets), ensure_ascii=False, sort_keys=True)
    roots_json = json.dumps(list(allowed_roots), ensure_ascii=False)
    timeout = int(resources["逐成员超时秒"])
    return textwrap.dedent(
        f'''\
        import datetime as dt
        import hashlib, json, os, stat
        ASSETS = json.loads({assets_json!r})
        ROOTS = json.loads({roots_json!r})
        PROBE_VERSION = {PROBE_VERSION!r}
        MEMBER_TIMEOUT = {timeout}

        def fp(value):
            return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        def allowed(path):
            real = os.path.realpath(path)
            return any(real == root or real.startswith(root.rstrip("/") + "/") for root in ROOTS)

        results = []
        for asset in ASSETS:
            asset_id = asset["资产编号"]
            try:
                if asset["资产类型"] != "候选数据文件":
                    results.append({{"资产编号": asset_id, "复核状态": "无法判定", "元数据SHA-256": "", "授权快照SHA-256": "未知", "字段级证据SHA-256": "未知", "证据": "数据库对象字段级摘要未取得", "限制": "未读取数据库业务记录"}})
                    continue
                if not allowed(asset["位置"]):
                    results.append({{"资产编号": asset_id, "复核状态": "拒绝", "元数据SHA-256": "", "授权快照SHA-256": "", "字段级证据SHA-256": "", "证据": "资源路径超出白名单", "限制": "未读取文件正文"}})
                    continue
                info = os.lstat(asset["位置"])
                metadata = {{"资产编号": asset_id, "字节数": str(info.st_size), "修改时间": dt.datetime.fromtimestamp(info.st_mtime).astimezone().isoformat(), "模式": stat.S_IMODE(info.st_mode), "类型": "普通文件" if stat.S_ISREG(info.st_mode) else "非普通文件"}}
                same = stat.S_ISREG(info.st_mode) and metadata["字节数"] == asset["字节数"] and metadata["修改时间"] == asset["最后修改时间"]
                results.append({{"资产编号": asset_id, "复核状态": "已观察" if same else "拒绝", "元数据SHA-256": fp(metadata), "授权快照SHA-256": "未知", "字段级证据SHA-256": "未知", "证据": "白名单普通文件stat与冻结输入一致" if same else "冻结文件元数据漂移", "限制": "未读取文件正文；字段语义和授权边界未证明"}})
            except (FileNotFoundError, OSError):
                results.append({{"资产编号": asset_id, "复核状态": "无法判定", "元数据SHA-256": "", "授权快照SHA-256": "未知", "字段级证据SHA-256": "未知", "证据": "白名单只读stat复核失败", "限制": "未扩大读取范围"}})
        print(json.dumps({{"探针版本": PROBE_VERSION, "远端写入": False, "数据库业务记录读取": False, "读取价格成交订单簿": False, "数据库元数据范围": ["information_schema.TABLES", "information_schema.COLUMNS", "information_schema.TABLE_PRIVILEGES"], "结果": results}}, ensure_ascii=False, sort_keys=True))
        '''
    )


def _ssh_probe(command: Sequence[str], script: str, timeout: int, max_out: int, max_err: int, runner: Callable[..., subprocess.CompletedProcess] | None) -> dict[str, object]:
    if runner is None:
        completed = engine.run_bounded_process(command, input_text=script, timeout=timeout, maximum_stdout=max_out, maximum_stderr=max_err)
    else:
        completed = runner(command, input=script, capture_output=True, text=True, timeout=timeout, check=False)
    if completed.returncode != 0:
        raise RuntimeError("字段级只读探针失败：远端非零状态，未发布批次")
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if len(stdout.encode()) > max_out:
        raise RuntimeError("字段级只读探针输出超限，未发布批次")
    try:
        payload = json.loads(stdout)
    except ValueError as error:
        raise RuntimeError("字段级只读探针响应非法，未发布批次") from error
    if not isinstance(payload, dict) or set(payload) != {"探针版本", "远端写入", "数据库业务记录读取", "读取价格成交订单簿", "数据库元数据范围", "结果"}:
        raise ValueError("字段级探针响应字段漂移")
    if payload["探针版本"] != PROBE_VERSION or any(payload[key] is not False for key in ("远端写入", "数据库业务记录读取", "读取价格成交订单簿")):
        raise ValueError("字段级探针越过安全边界")
    return payload


def _build_rows(members: Sequence[Mapping[str, str]], probe: Mapping[str, object], batch_id: str) -> tuple[list[dict[str, str]], dict[str, object]]:
    by_asset = {str(item["资产编号"]): item for item in probe["结果"]}
    if len(by_asset) != len(probe["结果"]):
        raise ValueError("探针资产结果重复")
    rows: list[dict[str, str]] = []
    for member in members:
        item = by_asset.get(member["资产编号"])
        if item is None:
            raise ValueError("探针未覆盖全部资产")
        row = {column: str(member.get(column, "未知")) for column in MEMBER_COLUMNS}
        row["来源身份批次"] = batch_id
        prior = member.get("状态", "无法判定")
        probe_state = item["复核状态"]
        row["状态"] = "拒绝" if prior == "拒绝" or probe_state == "拒绝" else "无法判定"
        row["证据"] = str(item["证据"])
        row["限制"] = str(item["限制"])
        row["解除条件"] = "提供当前版本字段级身份、Schema和授权边界证据后新建不可变批次"
        row["远端元数据SHA-256"] = str(item["元数据SHA-256"] or "未知")
        row["身份记录SHA-256"] = _fingerprint(row)
        row["字段级证据SHA-256"] = str(item["字段级证据SHA-256"] or "未知")
        row["授权快照SHA-256"] = str(item["授权快照SHA-256"] or "未知")
        row["字段证据状态"] = "未取得"
        rows.append(row)
    counts = Counter(row["状态"] for row in rows)
    per_target = {target: {state: sum(1 for row in rows if row["标的"] == target and row["状态"] == state) for state in ("拒绝", "无法判定")} for target in TARGETS}
    if sum(counts.values()) != len(rows) or any(sum(values.values()) != len(rows) // 2 for values in per_target.values()):
        raise ValueError("状态计数不守恒")
    summary = {"候选资产总体": len({row["资产编号"] for row in rows}), "身份成员总体": len(rows), "已证明": 0, "拒绝": counts.get("拒绝", 0), "无法判定": counts.get("无法判定", 0), "未成熟": 0, "失效": 0, "分标的": per_target, "结论边界": "字段级身份未形成已证明成员；不构成时间、质量、研究准入或交易许可"}
    return rows, summary


def _render_csv(rows: Sequence[Mapping[str, str]], batch_id: str) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: engine.safe_csv_cell({"来源身份字段级证据批次": batch_id}.get(key, row.get(key, ""))) for key in OUTPUT_COLUMNS})
    return output.getvalue()


def execute_batch(config_path: Path = CONFIG_PATH, ssh_target: str = "ubuntu", batch_root: Path = DEFAULT_BATCH_ROOT, timeout: int = 600, *, repo_root: Path = REPO_ROOT, runner: Callable[..., subprocess.CompletedProcess] | None = None, now: dt.datetime | None = None) -> Path:
    config = load_config(config_path, repo_root)
    if ssh_target not in config["允许SSH目标"]:
        raise ValueError("SSH目标不在白名单")
    resources = config["资源上限"]
    if timeout < 10 or timeout > int(resources["批次总超时秒"]):
        raise ValueError("批次超时超出资源上限")
    members = _load_members(config, repo_root)
    inventory = _load_inventory(config, repo_root)
    assets = [row for row in inventory if row.get("资产类型") in {"候选数据文件", "数据库元数据"}]
    if len(assets) * 2 != len(members):
        raise ValueError("资产与成员数量不一致")
    source_contract = engine.load_contract(engine.DEFAULT_CONTRACT, repo_root=repo_root)
    probe_assets = engine.build_probe_assets_from_inventory_bytes(_input_path(config, "资产清单", repo_root).read_bytes(), source_contract)
    command = engine.build_ssh_command("ssh", ssh_target, timeout)
    probe = _ssh_probe(command, build_probe_script(probe_assets, source_contract["允许文件根目录"], resources), timeout, int(resources["最大输出字节数"]), int(resources["最大日志字节数"]), runner)
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    task_hash = engine.file_fingerprint(repo_root / TASK_PATH)
    config_hash = engine.file_fingerprint(config_path)
    member_hash = _fingerprint(members)
    probe_hash = _fingerprint(probe)
    payload = {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "配置SHA-256": config_hash, "成员SHA-256": member_hash, "探针SHA-256": probe_hash, "任务文件SHA-256": task_hash, "结果摘要": "仅保留未知字段级身份，拒绝或无法判定原样保留"}
    batch_id = "source-identity-field-evidence-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + _fingerprint(payload)[:12]
    rows, summary = _build_rows(members, probe, batch_id)
    csv_text = _render_csv(rows, batch_id)
    manifest = {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "来源身份字段级证据批次": batch_id, "冻结时间": frozen.isoformat(timespec="microseconds"), "SSH逻辑目标": "ubuntu", "探针版本": PROBE_VERSION, "探针SHA-256": probe_hash, "配置SHA-256": config_hash, "成员SHA-256": member_hash, "任务文件SHA-256": task_hash, "结果摘要": summary, "安全声明": {"远端写入": False, "数据库业务记录读取": False, "读取价格成交订单簿": False, "未保存原始字段值": True, "未读取凭据": True}, "数据库元数据范围": config["数据库元数据范围"], "撤销事实": "本批次只读，无远端临时文件；结果可由输入、探针和规则指纹复算", "输出SHA-256": {"来源身份字段级证据清单.csv": _sha(csv_text.encode())}, "结论边界": "字段级身份没有形成已证明成员，不解除ZS-DATA-GAP-001或阶段2"}
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode()) + len(json_text.encode()) > int(resources["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=".source-identity-field-evidence-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "来源身份字段级证据清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        (staging / "批次清单.json").write_text(json_text, encoding="utf-8")
        engine._scan_outputs([staging / "来源身份字段级证据清单.csv", staging / "批次清单.json"])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "来源身份字段级证据批次": batch_id, "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(description="执行任务-000076来源身份字段级证据复采")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--ssh-target", default="ubuntu")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--timeout", type=int, default=600)
    try:
        args = parser.parse_args(argv)
        execute_batch(args.config, args.ssh_target, args.batch_root, args.timeout)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError):
        print("来源身份字段级证据复采失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
