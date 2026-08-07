#!/usr/bin/env python3
"""任务-000079：来源身份声明与当前证据失败安全复采。

只读取冻结成员和资产元数据，并通过 ``ubuntu`` 白名单执行无交互 stat 探针。
本批次不读取业务正文；未配置逐字段声明时，所有成员保持未知或历史拒绝。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import stat
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
TASK_ID = "任务-000079"
CONTRACT_VERSION = "source-identity-declaration-recapture-1.0"
PROBE_VERSION = "source-identity-declaration-probe-1.0"
CONFIG_PATH = REPO_ROOT / "config/数据/来源身份声明补采.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts/数据/来源身份声明复采"
TARGETS = ("BTC", "ETH")
FIELDS = (
    "来源提供者", "交易场所", "市场类型", "标的身份", "精确合约",
    "数据对象", "Schema确切版本", "授权边界", "字段中文映射",
)
SAFETY_KEYS = (
    "远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据",
    "原始业务记录落盘", "读取价格成交订单簿", "修改原始数据", "修改生产系统",
)
OUTPUT_COLUMNS = (
    "来源身份声明批次", "成员编号", "资产编号", "资产类型", "标的", "主研究尺度", "结果观察窗口",
    *FIELDS, "声明来源", "声明版本", "证据定位", "证据文件SHA-256", "输入成员SHA-256",
    "远端元数据SHA-256", "Schema指纹", "授权快照SHA-256", "状态", "原因代码", "撤销事实",
    "限制", "解除条件", "规则SHA-256", "执行器SHA-256", "成员记录SHA-256",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fp(value: object) -> str:
    return _sha(_canonical(value))


def _read(path: Path, label: str) -> bytes:
    return engine._read_regular_bytes(path, label)


def _input_path(config: Mapping[str, object], purpose: str, repo_root: Path) -> Path:
    for item in config["输入文件"]:
        if item["用途"] == purpose:
            return repo_root / str(item["路径"])
    raise ValueError(f"缺少输入：{purpose}")


def load_config(path: Path = CONFIG_PATH, repo_root: Path = REPO_ROOT) -> dict[str, object]:
    raw = json.loads(_read(path, "来源身份声明补采配置").decode("utf-8"))
    required = {"合同版本", "任务编号", "允许SSH目标", "标的", "主研究尺度", "事后结果观察窗口", "身份字段", "身份声明", "输入文件", "安全边界", "资源上限"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("来源身份声明配置字段漂移")
    if raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("合同版本或任务编号漂移")
    if raw["允许SSH目标"] != ["ubuntu"] or raw["标的"] != list(TARGETS):
        raise ValueError("SSH白名单或标的漂移")
    if raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度边界漂移")
    if raw["身份字段"] != list(FIELDS) or not isinstance(raw["身份声明"], list):
        raise ValueError("身份字段或声明结构漂移")
    for declaration in raw["身份声明"]:
        if not isinstance(declaration, dict) or set(declaration) != {"资产编号", "标的", "字段值", "证据来源", "证据文件SHA-256", "Schema指纹", "授权快照SHA-256", "声明版本"}:
            raise ValueError("声明字段不完整")
        if declaration["标的"] not in TARGETS or declaration["资产编号"] == "":
            raise ValueError("声明标的或资产编号非法")
        if set(declaration["字段值"]) != set(FIELDS):
            raise ValueError("声明字段集合不完整")
    safety = raw["安全边界"]
    if not isinstance(safety, dict) or tuple(safety) != SAFETY_KEYS or any(value is not False for value in safety.values()):
        raise ValueError("安全边界必须固定为false")
    resources = raw["资源上限"]
    if not isinstance(resources, dict) or set(resources) != {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数"}:
        raise ValueError("资源上限字段漂移")
    if not 10 <= int(resources["批次总超时秒"]) <= 3600 or not 1 <= int(resources["逐成员超时秒"]) <= 30:
        raise ValueError("资源上限非法")
    seen: set[str] = set()
    for item in raw["输入文件"]:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"} or item["路径"] in seen:
            raise ValueError("输入合同字段或路径重复")
        seen.add(item["路径"])
        if _sha(_read(repo_root / item["路径"], "来源身份声明输入")) != item["SHA-256"]:
            raise ValueError(f"输入指纹漂移：{item['路径']}")
    return raw


def load_members(config: Mapping[str, object], repo_root: Path = REPO_ROOT) -> list[dict[str, str]]:
    path = _input_path(config, "任务-000076来源身份成员", repo_root)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 630 or any(row.get("标的") not in TARGETS for row in rows):
        raise ValueError("当前成员必须完整覆盖BTC和ETH")
    expected = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != expected or len({row["成员编号"] for row in rows}) != len(rows):
        raise ValueError("成员顺序或唯一性不确定")
    return rows


def load_inventory(config: Mapping[str, object], repo_root: Path = REPO_ROOT) -> list[dict[str, str]]:
    path = _input_path(config, "资产清单", repo_root)
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    selected = [row for row in rows if row.get("资产类型") in {"候选数据文件", "数据库元数据"}]
    if len(selected) != 315 or len({row["资产编号"] for row in selected}) != 315:
        raise ValueError("资产清单覆盖或唯一性不满足")
    return selected


def build_probe_script(assets: Sequence[Mapping[str, str]], roots: Sequence[str], timeout: int = 5) -> str:
    assets_json = json.dumps(list(assets), ensure_ascii=False, sort_keys=True)
    roots_json = json.dumps(list(roots), ensure_ascii=False)
    return textwrap.dedent(f"""\
        import datetime as dt, hashlib, json, os, stat
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
            item = {{"资产编号": asset["资产编号"], "元数据SHA-256": "未知", "状态": "无法判定", "原因代码": "IDENTITY_DECLARATION_MISSING", "证据": "未登记逐字段来源身份声明；未读取业务正文"}}
            try:
                if asset["资产类型"] == "数据库元数据":
                    item["原因代码"] = "DATABASE_METADATA_IDENTITY_UNPROVEN"
                    item["证据"] = "仅登记数据库元数据对象；未读取业务记录"
                elif not allowed(asset["位置"]):
                    item["状态"] = "拒绝"
                    item["原因代码"] = "PATH_OUTSIDE_WHITELIST"
                    item["证据"] = "资产位置不在白名单；未读取文件正文"
                else:
                    info = os.lstat(asset["位置"])
                    metadata = {{"字节数": str(info.st_size), "修改时间": dt.datetime.fromtimestamp(info.st_mtime).astimezone().isoformat(), "模式": stat.S_IMODE(info.st_mode), "类型": "普通文件" if stat.S_ISREG(info.st_mode) else "非普通文件"}}
                    item["元数据SHA-256"] = fp(metadata)
                    if stat.S_ISREG(info.st_mode) and metadata["字节数"] == asset["字节数"] and metadata["修改时间"] == asset["最后修改时间"]:
                        item["原因代码"] = "FILE_STAT_OBSERVED_IDENTITY_UNPROVEN"
                        item["证据"] = "白名单文件stat与冻结输入一致；字段语义和授权仍未证明"
                    else:
                        item["状态"] = "拒绝"
                        item["原因代码"] = "FILE_STAT_DRIFT"
                        item["证据"] = "白名单文件stat与冻结输入不一致；未读取文件正文"
            except (FileNotFoundError, OSError):
                item["原因代码"] = "READONLY_METADATA_UNAVAILABLE"
                item["证据"] = "白名单只读元数据不可用；未扩大读取范围"
            results.append(item)
        print(json.dumps({{"探针版本": PROBE_VERSION, "远端写入": False, "远端临时文件": False, "数据库业务记录读取": False, "读取环境变量或凭据": False, "读取价格成交订单簿": False, "结果": results}}, ensure_ascii=False, sort_keys=True))
    """)


def run_probe(script: str, config: Mapping[str, object], runner: Callable[..., object] | None = None) -> dict[str, object]:
    resources = config["资源上限"]
    command = engine.build_ssh_command("ssh", "ubuntu", int(resources["批次总超时秒"]))
    if runner is None:
        completed = engine.run_bounded_process(command, input_text=script, timeout=int(resources["批次总超时秒"]), maximum_stdout=int(resources["最大输出字节数"]), maximum_stderr=int(resources["最大日志字节数"]))
    else:
        completed = runner(command, input=script, capture_output=True, text=True, timeout=int(resources["批次总超时秒"]), check=False)
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if completed.returncode != 0 or len(stdout.encode()) > int(resources["最大输出字节数"]):
        raise RuntimeError("来源身份只读探针失败或输出超限：未发布批次")
    payload = json.loads(stdout)
    required = {"探针版本", "远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据", "读取价格成交订单簿", "结果"}
    if not isinstance(payload, dict) or set(payload) != required or payload["探针版本"] != PROBE_VERSION or any(payload[key] is not False for key in required - {"探针版本", "结果"}):
        raise ValueError("探针响应越过安全边界")
    if len(payload["结果"]) != 315 or len({item["资产编号"] for item in payload["结果"]}) != 315:
        raise ValueError("探针未确定性覆盖全部资产")
    return payload


def rules_fingerprint(config: Mapping[str, object]) -> str:
    return _fp({"合同版本": CONTRACT_VERSION, "探针版本": PROBE_VERSION, "身份字段": config["身份字段"], "主研究尺度": config["主研究尺度"], "事后结果观察窗口": config["事后结果观察窗口"], "状态": ["已证明", "拒绝", "无法判定", "失败", "未成熟", "失效"]})


def build_rows(members: Sequence[Mapping[str, str]], inventory: Sequence[Mapping[str, str]], probe: Mapping[str, object], config: Mapping[str, object], batch_id: str, *, config_hash: str, rules_hash: str, executor_hash: str) -> tuple[list[dict[str, str]], dict[str, object]]:
    by_asset = {str(item["资产编号"]): item for item in probe["结果"]}
    assets = {str(item["资产编号"]): item for item in inventory}
    declarations = {str(item["资产编号"]): item for item in config["身份声明"]}
    rows: list[dict[str, str]] = []
    for member in members:
        asset_id = member["资产编号"]
        item = by_asset[asset_id]
        declaration = declarations.get(asset_id)
        if declaration is not None:
            # 当前仓库没有声明；保留此分支只用于未来逐字段证据合同的显式扩展，绝不从名称推断。
            field_values = {field: str(declaration["字段值"][field]) for field in FIELDS}
            declaration_source = str(declaration["证据来源"])
            declaration_hash = str(declaration["证据文件SHA-256"])
            declaration_version = str(declaration["声明版本"])
            evidence_location = "声明记录"
        else:
            field_values = {field: "未知" for field in FIELDS}
            declaration_source = "未登记"
            declaration_hash = config_hash
            declaration_version = "无"
            evidence_location = "config/数据/来源身份声明补采.json#身份声明[]"
        prior = str(member.get("状态", "无法判定"))
        state = "拒绝" if prior == "拒绝" or item["状态"] == "拒绝" else "无法判定"
        reason = "INPUT_MEMBER_REJECTED" if prior == "拒绝" else str(item["原因代码"])
        row: dict[str, str] = {
            "来源身份声明批次": batch_id, "成员编号": str(member["成员编号"]), "资产编号": asset_id,
            "资产类型": str(assets[asset_id]["资产类型"]), "标的": str(member["标的"]),
            "主研究尺度": ";".join(config["主研究尺度"]), "结果观察窗口": ";".join(config["事后结果观察窗口"]),
            **field_values, "声明来源": declaration_source, "声明版本": declaration_version,
            "证据定位": evidence_location, "证据文件SHA-256": declaration_hash,
            "输入成员SHA-256": str(member["输入成员SHA-256"]), "远端元数据SHA-256": str(item["元数据SHA-256"]),
            "Schema指纹": str(declaration["Schema指纹"] if declaration else "未知"),
            "授权快照SHA-256": str(declaration["授权快照SHA-256"] if declaration else _fp({"SSH逻辑目标": "ubuntu", "远端写入": False, "数据库业务记录读取": False, "凭据读取": False})),
            "状态": state, "原因代码": reason,
            "撤销事实": "本批次只读；若声明、输入、Schema或授权漂移，既有结论自动失效并须追加新批次",
            "限制": "未读取业务正文、价格、成交、订单簿、账户或凭据；身份字段不完整",
            "解除条件": "为该成员提供当前版本九字段声明及逐字段Schema、授权和唯一证据定位后追加不可变批次",
            "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash, "成员记录SHA-256": "",
        }
        row["成员记录SHA-256"] = _fp(row)
        rows.append(row)
    counts = Counter(row["状态"] for row in rows)
    by_target = {target: {state: sum(1 for row in rows if row["标的"] == target and row["状态"] == state) for state in ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")} for target in TARGETS}
    if sum(counts.values()) != len(rows) or any(sum(value.values()) != len(rows) // 2 for value in by_target.values()):
        raise ValueError("状态计数不守恒")
    summary = {"候选成员总体": len(rows), "已证明": counts.get("已证明", 0), "拒绝": counts.get("拒绝", 0), "无法判定": counts.get("无法判定", 0), "失败": counts.get("失败", 0), "未成熟": counts.get("未成熟", 0), "失效": counts.get("失效", 0), "分标的": by_target, "ZS-DATA-GAP-001": "继续阻塞；没有完整九字段声明形成已证明成员"}
    return rows, summary


def _render(rows: Sequence[Mapping[str, str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: engine.safe_csv_cell(row.get(key, "")) for key in OUTPUT_COLUMNS})
    return output.getvalue()


def execute_batch(config_path: Path = CONFIG_PATH, batch_root: Path = DEFAULT_BATCH_ROOT, *, repo_root: Path = REPO_ROOT, runner: Callable[..., object] | None = None, now: dt.datetime | None = None) -> Path:
    config = load_config(config_path, repo_root)
    members = load_members(config, repo_root)
    inventory = load_inventory(config, repo_root)
    source_contract = engine.load_contract(engine.DEFAULT_CONTRACT, repo_root=repo_root)
    assets = engine.build_probe_assets_from_inventory_bytes(_input_path(config, "资产清单", repo_root).read_bytes(), source_contract)
    assets = [asset for asset in assets if asset["资产编号"] in {row["资产编号"] for row in inventory}]
    if len(assets) != len(inventory):
        raise ValueError("探针资产与清单不一致")
    probe = run_probe(build_probe_script(assets, source_contract["允许文件根目录"], int(config["资源上限"]["逐成员超时秒"])), config, runner)
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    config_hash = engine.file_fingerprint(config_path)
    rules_hash = rules_fingerprint(config)
    executor_hash = engine.file_fingerprint(Path(__file__))
    member_hash = _fp(members)
    probe_hash = _fp(probe)
    payload = {"合同版本": CONTRACT_VERSION, "配置SHA-256": config_hash, "成员SHA-256": member_hash, "探针SHA-256": probe_hash, "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash}
    batch_id = "source-identity-declaration-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + _fp(payload)[:12]
    rows, summary = build_rows(members, inventory, probe, config, batch_id, config_hash=config_hash, rules_hash=rules_hash, executor_hash=executor_hash)
    csv_text = _render(rows)
    manifest = {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "批次": batch_id, "冻结时间": frozen.isoformat(timespec="microseconds"), "SSH逻辑目标": "ubuntu", "成员SHA-256": member_hash, "配置SHA-256": config_hash, "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash, "探针SHA-256": probe_hash, "结果摘要": summary, "安全声明": {key: False for key in SAFETY_KEYS}, "撤销事实": "批次只读、追加式、历史目录不可覆盖；未证明身份不解除缺口或阶段门", "输出SHA-256": {"来源身份声明证据清单.csv": _sha(csv_text.encode("utf-8"))}, "结论边界": "描述性身份差异不推导因果、预测优势、胜率、收益、研究准入或交易许可"}
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(csv_text.encode()) + len(json_text.encode()) > int(config["资源上限"]["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=".source-identity-declaration-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "来源身份声明证据清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        (staging / "批次清单.json").write_text(json_text, encoding="utf-8")
        engine._scan_outputs([staging / "来源身份声明证据清单.csv", staging / "批次清单.json"])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "批次": batch_id, "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


class SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeParser(description="任务-000079来源身份声明失败安全复采")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    try:
        args = parser.parse_args(argv)
        execute_batch(args.config, args.batch_root)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        print("来源身份声明复采失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
