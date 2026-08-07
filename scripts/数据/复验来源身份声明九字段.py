#!/usr/bin/env python3
"""任务-000081：只读复验来源身份声明九字段与证据绑定。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine
from scripts.数据 import 复核来源身份声明入口 as entry_engine


ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000081"
FINAL_BATCH = (
    ROOT
    / "artifacts/数据/来源身份声明证据入口复核"
    / "source-identity-entry-review-20260808T055600+0800-v9"
)
SOURCE_BATCH = entry_engine.FINAL_BATCH
IDENTITY_FIELDS = entry_engine.IDENTITY_FIELDS
EVIDENCE_FIELDS = (
    "证据定位",
    "证据文件SHA-256",
    "输入成员SHA-256",
    "Schema指纹",
    "授权快照SHA-256",
    "撤销事实",
)
ENTRY_STATES = {"未登记", "入口不完整", "已登记"}
FINAL_STATES = {"已证明", "拒绝", "无法判定", "失败", "未成熟", "失效"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_entry_key(entry: dict[str, Any]) -> str:
    return json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _matching_entries(entries: list[dict[str, Any]], row: dict[str, str]) -> list[dict[str, Any]]:
    matches = [
        entry
        for entry in entries
        if entry.get("资产编号") in {row.get("资产编号"), "*"}
        and entry.get("标的") in {row.get("标的"), "*"}
    ]
    return sorted(matches, key=lambda item: (str(item.get("配置", "")), _canonical_entry_key(item)))


def _evaluate_member(row: dict[str, str], entries: list[dict[str, Any]]) -> dict[str, str]:
    matches = _matching_entries(entries, row)
    if not matches:
        return {
            "入口状态": "未登记",
            "九字段状态": "无法判定",
            "缺失字段": ";".join((*IDENTITY_FIELDS, *EVIDENCE_FIELDS)),
            "声明来源": "未登记",
            "证据定位": "config/数据/来源身份声明补采.json#身份声明[]",
            "声明内容SHA-256": "未知",
            "原因代码": "IDENTITY_DECLARATION_MISSING",
            "解除条件": "提供当前版本九字段声明、唯一证据定位、成员、Schema、授权和撤销指纹后追加批次",
        }

    complete = []
    for entry in matches:
        missing = [
            field
            for field in (*IDENTITY_FIELDS, *EVIDENCE_FIELDS)
            if not str(entry.get(field, "")).strip() or str(entry.get(field)).strip() == "未知"
        ]
        if not missing:
            complete.append(entry)
    if not complete:
        missing = [
            field
            for field in (*IDENTITY_FIELDS, *EVIDENCE_FIELDS)
            if not any(str(item.get(field, "")).strip() for item in matches)
        ]
        entry = matches[0]
        return {
            "入口状态": "入口不完整",
            "九字段状态": "无法判定",
            "缺失字段": ";".join(missing),
            "声明来源": str(entry.get("配置", "未知")),
            "证据定位": str(entry.get("证据定位", "未知")),
            "声明内容SHA-256": str(entry.get("声明内容SHA-256", "未知")),
            "原因代码": "IDENTITY_DECLARATION_INCOMPLETE",
            "解除条件": "补齐九字段及全部证据指纹、授权和撤销事实后重新复验",
        }

    entry = complete[0]
    mismatches = [
        field
        for field in IDENTITY_FIELDS
        if str(row.get(field, "")).strip() in {"", "未知"}
        or str(entry.get(field, "")).strip() != str(row.get(field, "")).strip()
    ]
    if str(entry.get("输入成员SHA-256", "")).strip() != str(row.get("输入成员SHA-256", "")).strip():
        mismatches.append("输入成员SHA-256")
    if str(entry.get("撤销事实", "")).strip() not in {"有效", "未撤销"}:
        mismatches.append("撤销事实")
    if mismatches:
        return {
            "入口状态": "已登记",
            "九字段状态": "无法判定",
            "缺失字段": ";".join(sorted(set(mismatches))),
            "声明来源": str(entry.get("配置", "未知")),
            "证据定位": str(entry.get("证据定位", "未知")),
            "声明内容SHA-256": str(entry.get("声明内容SHA-256", "未知")),
            "原因代码": "IDENTITY_DECLARATION_MISMATCH",
            "解除条件": "修复当前成员、声明、Schema、授权或撤销指纹漂移后追加批次",
        }
    return {
        "入口状态": "已登记",
        "九字段状态": "已证明",
        "缺失字段": "",
        "声明来源": str(entry.get("配置", "未知")),
        "证据定位": str(entry.get("证据定位", "未知")),
        "声明内容SHA-256": str(entry.get("声明内容SHA-256", "未知")),
        "原因代码": "IDENTITY_DECLARATION_MATCHED",
        "解除条件": "成员在当前版本证据和撤销状态保持有效",
    }


def load_frozen_members() -> tuple[dict[str, Any], list[dict[str, str]]]:
    """读取任务-000080入口批次，并绑定任务-000079成员字段。"""

    manifest_path = FINAL_BATCH / "批次清单.json"
    csv_path = FINAL_BATCH / "来源身份声明入口复核清单.csv"
    manifest = entry_engine.read_json(manifest_path)
    if manifest.get("任务编号") != "任务-000080":
        raise ValueError("任务-000080最终入口批次任务编号漂移")
    expected_output = manifest.get("输出SHA-256", {}).get(csv_path.name)
    if expected_output != sha256(csv_path):
        raise ValueError("任务-000080最终入口清单指纹漂移")
    with csv_path.open(encoding="utf-8-sig", newline="") as stream:
        entry_rows = list(csv.DictReader(stream))
    required = {"成员编号", "资产编号", "标的", "入口状态", "最终状态", "输入成员SHA-256"}
    if len(entry_rows) != 630 or not required.issubset(entry_rows[0]):
        raise ValueError("任务-000080最终入口批次字段或分母漂移")
    _source_manifest, source_rows = entry_engine.load_final_members()
    source_by_member = {row["成员编号"]: row for row in source_rows}
    if set(source_by_member) != {row["成员编号"] for row in entry_rows}:
        raise ValueError("任务-000080入口批次成员集合漂移")
    merged: list[dict[str, str]] = []
    for entry_row in entry_rows:
        source_row = source_by_member[entry_row["成员编号"]]
        if entry_row["输入成员SHA-256"] != source_row.get("输入成员SHA-256", ""):
            raise ValueError("任务-000080入口批次成员指纹漂移")
        merged.append({**source_row, "入口状态": entry_row["入口状态"], "最终状态": entry_row["最终状态"]})
    return manifest, merged


def execute(batch: str, output_root: Path = ROOT / "artifacts/数据/来源身份声明九字段复验") -> Path:
    target = output_root / batch
    if target.exists() or target.is_symlink():
        raise ValueError("历史批次目录已存在，不覆盖")
    entries, config_fingerprints = entry_engine.load_declaration_entries()
    _source_manifest, rows = load_frozen_members()
    source_csv = FINAL_BATCH / "来源身份声明入口复核清单.csv"
    output_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{batch}-", dir=output_root))
    try:
        result_rows: list[dict[str, str]] = []
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        for row in rows:
            result = _evaluate_member(row, entries)
            counts[row["标的"]][result["九字段状态"]] += 1
            result_rows.append(
                {
                    "批次": batch,
                    "成员编号": row["成员编号"],
                    "资产编号": row["资产编号"],
                    "标的": row["标的"],
                    **result,
                    "最终身份状态": row.get("最终状态", row["状态"]),
                    "输入成员SHA-256": row.get("输入成员SHA-256", ""),
                    "Schema指纹": row.get("Schema指纹", ""),
                    "授权快照SHA-256": row.get("授权快照SHA-256", ""),
                    "撤销事实": row.get("撤销事实", ""),
                }
            )
        output_csv = staging / "来源身份声明九字段复验清单.csv"
        fieldnames = list(result_rows[0])
        with output_csv.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(result_rows)
        summary = {symbol: dict(sorted(value.items())) for symbol, value in sorted(counts.items())}
        manifest = {
            "任务编号": TASK_ID,
            "批次": batch,
            "冻结时间": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
            "输入": {
                "任务-000080最终批次": str(FINAL_BATCH.relative_to(ROOT)),
                "任务-000080最终批次清单SHA-256": sha256(FINAL_BATCH / "批次清单.json"),
                "任务-000080成员清单SHA-256": sha256(source_csv),
                "任务-000079来源成员清单SHA-256": sha256(SOURCE_BATCH / "来源身份声明证据清单.csv"),
                "声明配置": config_fingerprints,
                "声明入口条数": len(entries),
            },
            "结果摘要": {
                "候选成员总体": len(result_rows),
                "分标的九字段状态": summary,
                "已证明": sum(1 for row in result_rows if row["九字段状态"] == "已证明"),
                "ZS-DATA-GAP-001": "继续阻塞；没有完整当前九字段声明入口" if not entries else "按成员精确裁决",
            },
            "安全边界": {
                "服务器访问": False,
                "数据库业务记录读取": False,
                "真实市场数据读取": False,
                "远端写入": False,
                "原始数据修改": False,
                "生产系统修改": False,
                "凭据读取": False,
            },
            "资源上限": {"批次总超时秒": 600, "逐成员超时秒": 5, "最大成员数": 1000, "最大输出字节数": 8388608, "最大日志字节数": 32768},
            "规则SHA-256": sha256(Path(__file__).resolve()),
            "执行器SHA-256": sha256(Path(__file__).resolve()),
            "输出SHA-256": {output_csv.name: sha256(output_csv)},
            "结论边界": "描述性身份差异不推导因果、预测优势、胜率、收益、研究准入或交易许可",
        }
        (staging / "批次清单.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if target.exists() or target.is_symlink():
            raise ValueError("历史批次目录在发布前已存在")
        engine.atomic_publish_directory_no_replace(staging, target)
        return target
    except Exception:
        for path in staging.glob("*"):
            path.unlink(missing_ok=True)
        staging.rmdir()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="复验来源身份声明九字段")
    parser.add_argument("--batch", required=True)
    parser.add_argument("--output-root", type=Path, default=ROOT / "artifacts/数据/来源身份声明九字段复验")
    args = parser.parse_args()
    target = execute(args.batch, args.output_root)
    print(json.dumps({"批次": target.name, "路径": str(target.relative_to(ROOT)), "状态": "成功"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
