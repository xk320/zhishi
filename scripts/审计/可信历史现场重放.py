#!/usr/bin/env python3
"""从已批准来源登记加载历史重放成员；缺证据时失败安全。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Mapping, Sequence


SCRIPT_VERSION = "trusted-replay-source-1.0"
CONTRACT_VERSION = "trusted-replay-source-1.0"
TARGETS = ("BTC", "ETH")
SCALES = ("4小时", "8小时", "24小时", "48小时")
QUALITY_COLUMNS = (
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "资产类型", "服务或项目", "位置",
    "格式", "候选标的范围", "扫描状态", "扫描完整性", "记录数", "字段数", "结构缺失数", "结构缺失率",
    "重复状态", "精确重复数", "事件时间状态", "事件时间候选字段", "到达时间状态", "到达时间候选字段",
    "采集时间状态", "采集时间候选字段", "延迟状态", "乱序状态", "实际覆盖范围", "可用性结论", "依据", "限制",
    "解除条件", "证据指纹",
)
RESULT_COLUMNS = (
    "验证批次", "资产编号", "标的", "来源成员编号", "来源身份状态", "来源身份版本", "来源成员指纹",
    "质量审计批次", "质量扫描状态", "质量扫描完整性", "质量证据指纹", "来源提供者", "交易场所", "市场类型",
    "精确合约", "数据对象", "Schema确切版本", "主研究尺度", "决策记录编号", "决策时间", "数据截止时间",
    "事件时间字段", "到达时间字段", "采集时间字段", "可见性合同状态", "输入数据版本", "输入数据哈希", "输入资产集合指纹",
    "规则版本", "代码版本", "输入清单指纹", "输出指纹", "第一门状态", "确定性状态", "未来数据拒绝状态",
    "重放结论", "不可重放原因代码", "依据", "解除条件",
)
SENSITIVE = re.compile(r"(?i)(?:password|passwd|secret|token|authorization|private key|-----BEGIN|\b\d{1,3}(?:\.\d{1,3}){3}\b)")
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def safe_text(value: object) -> str:
    text = str(value)
    if SENSITIVE.search(text):
        raise ValueError("sensitive_content_detected")
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def read_json(path: Path, expected_sha: str | None = None) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("input_must_be_regular_file")
    if expected_sha and sha256_path(path) != expected_sha:
        raise ValueError("input_fingerprint_mismatch")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input_json_object_required")
    return value


def read_quality(path: Path, expected_sha: str) -> dict[str, dict[str, str]]:
    if path.is_symlink() or not path.is_file() or sha256_path(path) != expected_sha:
        raise ValueError("quality_input_fingerprint_mismatch")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != QUALITY_COLUMNS:
            raise ValueError("quality_columns_mismatch")
        rows = [{key: value or "" for key, value in row.items()} for row in reader]
    index: dict[str, dict[str, str]] = {}
    for row in rows:
        asset_id = row["资产编号"]
        if not re.fullmatch(r"DS-\d{6}", asset_id) or asset_id in index:
            raise ValueError("quality_asset_identity_invalid")
        index[asset_id] = row
    if len(index) != 315:
        raise ValueError("quality_candidate_total_mismatch")
    return index


def validate_config(config: Mapping[str, object]) -> None:
    required = {"合同版本", "任务编号", "允许SSH目标", "允许标的", "主研究尺度", "输入", "资源上限", "安全边界"}
    if set(config) != required or config["合同版本"] != CONTRACT_VERSION or config["任务编号"] != "任务-000032":
        raise ValueError("config_contract_mismatch")
    if tuple(config["允许SSH目标"]) != ("ubuntu",) or tuple(config["允许标的"]) != TARGETS:
        raise ValueError("config_scope_mismatch")
    if tuple(config["主研究尺度"]) != SCALES:
        raise ValueError("config_scale_mismatch")
    resources = config["资源上限"]
    if not isinstance(resources, dict) or resources != {
        "远端预检超时秒": 30, "批次总超时秒": 300, "最大成员数": 1000,
        "最大输出字节数": 16777216, "最大日志字节数": 4096,
    }:
        raise ValueError("config_resource_mismatch")
    security = config["安全边界"]
    if not isinstance(security, dict) or security != {
        "远端只读": True, "远端读取业务正文": False, "远端落盘": False,
        "修改原始数据": False, "生成样例决策": False, "生成交易结论": False,
    }:
        raise ValueError("config_security_mismatch")


def load_inputs(repo_root: Path, config: Mapping[str, object]) -> tuple[dict[str, object], dict[str, dict[str, str]], list[dict[str, object]]]:
    validate_config(config)
    inputs = config["输入"]
    if not isinstance(inputs, dict):
        raise ValueError("config_inputs_invalid")
    source_spec = inputs["来源身份清单"]
    quality_spec = inputs["质量验证清单"]
    if not isinstance(source_spec, dict) or not isinstance(quality_spec, dict):
        raise ValueError("config_input_spec_invalid")
    source_path = repo_root / str(source_spec["路径"])
    quality_manifest_path = repo_root / str(quality_spec["路径"])
    quality_path = repo_root / str(quality_spec["质量结果"])
    source = read_json(source_path, str(source_spec["SHA-256"]))
    quality_manifest = read_json(quality_manifest_path, str(quality_spec["SHA-256"]))
    quality = read_quality(quality_path, str(quality_spec["质量结果SHA-256"]))
    if source.get("合同版本") != "source-identity-1.0" or source.get("任务编号") != "任务-000029":
        raise ValueError("source_manifest_contract_mismatch")
    if quality_manifest.get("合同版本") != "dq-continuous-1.1" or quality_manifest.get("底层审计批次") != "audit-20260805T005824+0800":
        raise ValueError("quality_manifest_contract_mismatch")
    members = source.get("成员顺序")
    if not isinstance(members, list) or len(members) != 630:
        raise ValueError("source_member_total_mismatch")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("source_member_invalid")
        member_id = str(member.get("成员编号", ""))
        asset_id = str(member.get("资产编号", ""))
        target = str(member.get("标的", ""))
        if member_id in seen or not re.fullmatch(r"ZI-[0-9a-f]{24}", member_id) or target not in TARGETS or asset_id not in quality:
            raise ValueError("source_member_identity_invalid")
        seen.add(member_id)
        normalized.append(member)
    normalized.sort(key=lambda item: (str(item["资产编号"]), str(item["标的"]), str(item["成员编号"])))
    return source, quality, normalized


REMOTE_PREFLIGHT = (
    "import json, platform; print(json.dumps({'status':'ok','python':platform.python_version(),"
    "'runtime':'trusted-replay-read-only-preflight'}, sort_keys=True))"
)


def run_remote_preflight(target: str, timeout: int = 30) -> dict[str, str]:
    if target != "ubuntu":
        raise ValueError("ssh_target_not_allowlisted")
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", target, "python3", "-I", "-B", "-",
    ]
    try:
        result = subprocess.run(command, input=REMOTE_PREFLIGHT, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("remote_preflight_failed") from error
    if result.returncode != 0:
        raise RuntimeError("remote_preflight_failed")
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise RuntimeError("remote_preflight_invalid_response") from error
    if not isinstance(value, dict) or set(value) != {"status", "python", "runtime"} or value.get("status") != "ok" or value.get("runtime") != "trusted-replay-read-only-preflight":
        raise RuntimeError("remote_preflight_invalid_response")
    return {"status": "ok", "python": str(value["python"]), "runtime": str(value["runtime"])}


def visible_records(records: Iterable[Mapping[str, object]], decision_time: dt.datetime) -> list[Mapping[str, object]]:
    """第二门的到达时间闭区间；该函数只供受控测试使用。"""
    visible: list[Mapping[str, object]] = []
    for record in records:
        arrival = record.get("到达时间")
        if not isinstance(arrival, str):
            raise ValueError("arrival_time_missing")
        parsed = dt.datetime.fromisoformat(arrival.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed > decision_time:
            continue
        visible.append(record)
    return visible


def build_rows(batch: str, source: Mapping[str, object], quality: Mapping[str, Mapping[str, str]], members: Sequence[Mapping[str, object]], code_sha: str) -> list[dict[str, str]]:
    source_sha = str(source.get("成员SHA-256", ""))
    source_version = str(source.get("合同版本", ""))
    rows: list[dict[str, str]] = []
    for member in members:
        asset_id = str(member["资产编号"])
        target = str(member["标的"])
        quality_row = quality[asset_id]
        source_status = str(member.get("状态", ""))
        drift = source_status == "拒绝" or quality_row["扫描状态"] == "输入漂移"
        conclusion = "拒绝" if drift else "无法判定"
        reason = "input_identity_drift" if drift else "decision_record_missing"
        basis = (
            "来源身份成员或质量批次显示输入身份漂移，禁止载入历史现场"
            if drift else
            "来源身份已登记但没有获批历史决策记录登记；不读取候选正文，不构造样例记录"
        )
        row: dict[str, str] = {column: "无法判定" for column in RESULT_COLUMNS}
        row.update({
            "验证批次": batch, "资产编号": asset_id, "标的": target,
            "来源成员编号": str(member["成员编号"]), "来源身份状态": source_status,
            "来源身份版本": source_version, "来源成员指纹": str(member.get("身份记录SHA-256", "")),
            "质量审计批次": quality_row["审计批次"], "质量扫描状态": quality_row["扫描状态"],
            "质量扫描完整性": quality_row["扫描完整性"], "质量证据指纹": quality_row["证据指纹"],
            "来源提供者": str(member.get("来源提供者", "未知")), "交易场所": str(member.get("交易场所", "未知")),
            "市场类型": str(member.get("市场类型", "未知")), "精确合约": str(member.get("精确合约", "未知")),
            "数据对象": str(member.get("数据对象", "未知")), "Schema确切版本": str(member.get("Schema确切版本", "未知")),
            "主研究尺度": "未判定（缺少确切研究尺度合同）", "决策记录编号": "未登记",
            "可见性合同状态": "未判定（未登记到达时间合同）", "输入资产集合指纹": source_sha,
            "规则版本": quality_row["规则版本"], "代码版本": code_sha,
            "输入清单指纹": quality_row["清单指纹"], "第一门状态": conclusion,
            "确定性状态": "未执行（第一门未通过）", "未来数据拒绝状态": "未执行（无决策记录）",
            "重放结论": conclusion, "不可重放原因代码": reason, "依据": basis,
            "解除条件": "登记带来源证据的决策编号、决策时点、数据截止时间及三类时间合同；重新生成不可变批次",
        })
        row["输出指纹"] = sha256_bytes(canonical({k: row[k] for k in RESULT_COLUMNS if k != "输出指纹"}).encode())
        if len(canonical(row).encode()) > 16384:
            raise ValueError("member_output_too_large")
        rows.append(row)
    return rows


def write_csv(path: Path, rows: Sequence[Mapping[str, str]]) -> str:
    temp = path.with_name(f".{path.name}.tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_text(row[key]) for key in RESULT_COLUMNS})
    data = temp.read_bytes()
    os.replace(temp, path)
    return sha256_bytes(data)


def render_report(batch: str, rows: Sequence[Mapping[str, str]], remote: Mapping[str, str], input_fingerprints: Mapping[str, str]) -> str:
    lines = [
        "# 可信来源与历史决策现场重放验证",
        "",
        "<!-- markdownlint-disable MD013 -->",
        "",
        "> 宁可无法判定，也不把未证明的历史输入当作可重放现场。",
        "",
        "## 验证身份",
        "",
        f"- 验证器版本：`{SCRIPT_VERSION}`",
        f"- 合同版本：`{CONTRACT_VERSION}`",
        f"- 验证批次：`{batch}`",
        f"- 远端只读预检：通过（Python {remote['python']}，未读取业务正文）",
        f"- 来源身份清单指纹：`{input_fingerprints['source']}`",
        f"- 质量验证清单指纹：`{input_fingerprints['quality_manifest']}`",
        f"- 任务-000031合并提交：`bf8a00f95cdf5be9d56b963e6fa8f29807dbb918`",
        "",
        "## 总体结论",
        "",
        f"- 候选成员：{len(rows)}；BTC：{sum(row['标的'] == 'BTC' for row in rows)}；ETH：{sum(row['标的'] == 'ETH' for row in rows)}。",
        f"- 拒绝：{sum(row['重放结论'] == '拒绝' for row in rows)}；无法判定：{sum(row['重放结论'] == '无法判定' for row in rows)}；通过：0。",
        "- 没有历史决策登记文件；没有读取远端或候选资产正文，没有生成样例决策、方向、仓位、订单、胜率或收益。",
        "",
        "## 标的独立结论",
        "",
        "| 标的 | 候选成员 | 拒绝 | 无法判定 | 通过 | 结论 |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for target in TARGETS:
        target_rows = [row for row in rows if row["标的"] == target]
        lines.append(
            f"| {target} | {len(target_rows)} | {sum(row['重放结论'] == '拒绝' for row in target_rows)} | "
            f"{sum(row['重放结论'] == '无法判定' for row in target_rows)} | 0 | 无法判定（缺少历史决策记录与到达时间合同） |"
        )
    lines.extend([
        "",
        "## 版本链与硬门",
        "",
        "- 来源链：任务-000029 `source-identity-1.0` → 来源身份清单确切 SHA-256 → 来源成员身份指纹。",
        "- 质量链：任务-000031合并提交 → `dq-continuous-1.1` → 质量清单与逐成员质量证据指纹。",
        "- 决策链：历史决策登记未存在，因此决策编号、决策时间、数据截止时间、事件/到达/采集时间、输入版本哈希和输出版本均不生成。",
        "- 研究尺度：主尺度只允许4小时、8小时、24小时、48小时；因缺少确切尺度合同，本批次不把任何成员提升为主尺度证据。",
        "- 到达时间过滤函数仅在受控测试中验证`到达时间 <= 决策时间`闭区间；没有真实记录进入第二门。",
        "",
        "## 限制与解除条件",
        "",
        "1. 当前只能证明可信来源边界和缺证据时的失败安全，不能证明历史决策可重放。",
        "2. 必须登记带来源证据的决策编号、决策时点、数据截止时间和三类时间语义，并绑定确切输入版本。",
        "3. 任何后续记录、修订或晚到数据必须创建新版本；不得改写本批次。",
        "4. 本结果不提升研究准入、模型状态或交易许可，不涉及真实资金。",
        "",
    ])
    return "\n".join(lines)


def publish_batch(root: Path, batch: str, rows: Sequence[Mapping[str, str]], report: str, checklist: Mapping[str, object], index_row: Mapping[str, str]) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    destination = root / batch
    if destination.exists() or destination.is_symlink():
        raise ValueError("batch_exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{batch}.", dir=root))
    try:
        csv_path = temporary / "逐成员结果.csv"
        csv_sha = write_csv(csv_path, rows)
        report_path = temporary / "验证报告.md"
        report_path.write_text(report, encoding="utf-8")
        checklist_value = dict(checklist)
        checklist_value["逐成员结果SHA-256"] = csv_sha
        checklist_value["验证报告SHA-256"] = sha256_path(report_path)
        (temporary / "验证清单.json").write_text(canonical(checklist_value) + "\n", encoding="utf-8")
        os.mkdir(destination)
        for child in temporary.iterdir():
            os.replace(child, destination / child.name)
        shutil.rmtree(temporary)
        index = root / "批次索引.csv"
        new_file = not index.exists()
        with index.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=tuple(index_row), lineterminator="\n")
            if new_file:
                writer.writeheader()
            writer.writerow({key: safe_text(value) for key, value in index_row.items()})
        return {"csv_sha": csv_sha, "report_sha": sha256_path(destination / "验证报告.md"), "checklist_sha": sha256_path(destination / "验证清单.json")}
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        if destination.exists() and not any(destination.iterdir()):
            destination.rmdir()
        raise


def execute(repo_root: Path, config_path: Path, batch_root: Path, batch: str, target: str) -> dict[str, object]:
    config = read_json(config_path)
    source, quality, members = load_inputs(repo_root, config)
    if len(members) > 1000:
        raise ValueError("member_limit_exceeded")
    remote = run_remote_preflight(target, 30)
    code_sha = sha256_path(Path(__file__).resolve())
    rows = build_rows(batch, source, quality, members, code_sha)
    fingerprints = {
        "source": sha256_path(repo_root / str(config["输入"]["来源身份清单"]["路径"])),
        "quality_manifest": sha256_path(repo_root / str(config["输入"]["质量验证清单"]["路径"])),
    }
    report = render_report(batch, rows, remote, fingerprints)
    checklist = {
        "合同版本": CONTRACT_VERSION, "验证器版本": SCRIPT_VERSION, "验证批次": batch,
        "冻结时间": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds"),
        "成员顺序": "按资产编号、标的、来源成员编号升序", "候选成员总数": len(rows),
        "标的计数": {target_name: sum(row["标的"] == target_name for row in rows) for target_name in TARGETS},
        "状态计数": {status: sum(row["重放结论"] == status for row in rows) for status in ("拒绝", "无法判定", "通过")},
        "来源身份清单SHA-256": fingerprints["source"], "质量验证清单SHA-256": fingerprints["quality_manifest"],
        "代码SHA-256": code_sha, "远端预检": remote, "历史决策登记": "未登记；未创建样例文件",
        "安全声明": {"远端读取业务正文": False, "远端落盘": False, "原始数据修改": False, "交易结论": False},
    }
    index_row = {
        "验证批次": batch, "合同版本": CONTRACT_VERSION, "来源身份清单SHA-256": fingerprints["source"],
        "质量验证清单SHA-256": fingerprints["quality_manifest"], "代码SHA-256": code_sha,
        "候选成员总数": str(len(rows)), "拒绝数": str(sum(row["重放结论"] == "拒绝" for row in rows)),
        "无法判定数": str(sum(row["重放结论"] == "无法判定" for row in rows)), "通过数": "0",
        "远端预检": "通过", "状态": "已发布",
    }
    artifacts = publish_batch(batch_root, batch, rows, report, checklist, index_row)
    return {"status": "ok", "batch": batch, "members": len(rows), "remote": remote, "artifacts": artifacts, "counts": checklist["状态计数"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="可信来源登记边界内的只读历史现场验证")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--batch-root", type=Path, required=True)
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--batch", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not re.fullmatch(r"replay-[0-9]{8}T[0-9]{6}[+-][0-9]{4}-[0-9a-f]{12}", args.batch):
        raise ValueError("batch_id_invalid")
    result = execute(Path.cwd(), args.config.resolve(), args.batch_root.resolve(), args.batch, args.ssh_target)
    print(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"可信历史现场重放失败：{error}")
        raise SystemExit(1)
