#!/usr/bin/env python3
"""复核已登记的来源身份声明入口，不从缺失事实推断身份。

本入口只读取仓库中的任务-000079最终批次、来源身份合同和结构化声明配置。
入口为空、字段缺失或证据指纹不完整时，输出失败安全的“未登记/无法判定”，
不访问服务器、数据库业务记录或真实市场数据，也不覆盖历史批次。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FINAL_BATCH = (
    ROOT
    / "artifacts/数据/来源身份声明复采"
    / "source-identity-declaration-20260808T051806+0800-dd1e3d74dca4"
)
DECLARATION_CONFIGS = (
    ROOT / "config/数据/数据来源与资产身份.json",
    ROOT / "config/数据/来源身份声明补采.json",
)
IDENTITY_FIELDS = (
    "来源提供者",
    "交易场所",
    "市场类型",
    "标的身份",
    "精确合约",
    "数据对象",
    "Schema确切版本",
    "授权边界",
    "字段中文映射",
)
STATUS_VALUES = {"已证明", "拒绝", "无法判定", "失败", "未成熟", "失效"}
BATCH_PATTERN = re.compile(
    r"^source-identity-entry-review-[0-9]{8}T[0-9]{6}[+-][0-9]{4}-[A-Za-z0-9]+$"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"输入不是普通文件：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_declaration_entries() -> tuple[list[dict[str, Any]], dict[str, str]]:
    entries: list[dict[str, Any]] = []
    fingerprints: dict[str, str] = {}
    for path in DECLARATION_CONFIGS:
        document = read_json(path)
        declarations = document.get("身份声明")
        if not isinstance(declarations, list):
            raise ValueError(f"身份声明不是数组：{path}")
        fingerprints[str(path.relative_to(ROOT))] = sha256(path)
        for item in declarations:
            if not isinstance(item, dict):
                raise ValueError(f"身份声明成员不是对象：{path}")
            entries.append({"配置": str(path.relative_to(ROOT)), **item})
    return entries, fingerprints


def load_final_members() -> tuple[dict[str, Any], list[dict[str, str]]]:
    manifest_path = FINAL_BATCH / "批次清单.json"
    csv_path = FINAL_BATCH / "来源身份声明证据清单.csv"
    manifest = read_json(manifest_path)
    if manifest.get("任务编号") != "任务-000079":
        raise ValueError("最终来源身份批次任务编号漂移")
    expected_output = manifest.get("输出SHA-256", {}).get(csv_path.name)
    if expected_output != sha256(csv_path):
        raise ValueError("任务-000079最终成员清单指纹漂移")
    with csv_path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    required = {"成员编号", "资产编号", "标的", "状态", *IDENTITY_FIELDS}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("任务-000079最终成员清单字段不足")
    if len(rows) != 630 or {row["标的"] for row in rows} != {"BTC", "ETH"}:
        raise ValueError("任务-000079最终成员分母漂移")
    if any(row["状态"] not in STATUS_VALUES for row in rows):
        raise ValueError("任务-000079最终成员状态未登记")
    return manifest, rows


def _entry_state(entries: list[dict[str, Any]], row: dict[str, str]) -> tuple[str, list[str]]:
    """只有完整声明入口才能进入已登记；空入口明确返回未登记。"""

    candidates = [
        entry
        for entry in entries
        if entry.get("资产编号") in {row.get("资产编号"), "*"}
        and entry.get("标的") in {row.get("标的"), "*"}
    ]
    if not candidates:
        return "未登记", list(IDENTITY_FIELDS)
    missing = [
        field
        for field in IDENTITY_FIELDS
        if not any(str(candidate.get(field, "")).strip() for candidate in candidates)
    ]
    return ("已登记" if not missing else "入口不完整"), missing


def execute(batch: str, output_root: Path = ROOT / "artifacts/数据/来源身份声明证据入口复核") -> Path:
    if BATCH_PATTERN.fullmatch(batch) is None:
        raise ValueError("批次必须为source-identity-entry-review-YYYYMMDDTHHMMSS±HHMM-标识")
    target = output_root / batch
    if target.exists():
        raise ValueError("历史批次目录已存在，不覆盖")
    entries, config_fingerprints = load_declaration_entries()
    source_manifest, rows = load_final_members()
    source_csv = FINAL_BATCH / "来源身份声明证据清单.csv"
    temp_dir = Path(tempfile.mkdtemp(prefix=f".{batch}-", dir=output_root))
    try:
        output_csv = temp_dir / "来源身份声明入口复核清单.csv"
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        output_rows: list[dict[str, str]] = []
        for row in rows:
            entry_state, missing = _entry_state(entries, row)
            counts[row["标的"]][entry_state] += 1
            output_rows.append(
                {
                    "批次": batch,
                    "成员编号": row["成员编号"],
                    "资产编号": row["资产编号"],
                    "标的": row["标的"],
                    "入口状态": entry_state,
                    "最终状态": row["状态"],
                    "缺失字段": ";".join(missing),
                    "声明来源": row.get("声明来源", ""),
                    "证据定位": row.get("证据定位", ""),
                    "输入成员SHA-256": row.get("输入成员SHA-256", ""),
                    "Schema指纹": row.get("Schema指纹", ""),
                    "授权快照SHA-256": row.get("授权快照SHA-256", ""),
                    "原因代码": row.get("原因代码", ""),
                    "解除条件": row.get("解除条件", ""),
                }
            )
        fieldnames = list(output_rows[0])
        with output_csv.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)
        summary = {
            symbol: dict(sorted(values.items())) for symbol, values in sorted(counts.items())
        }
        manifest = {
            "任务编号": "任务-000080",
            "批次": batch,
            "冻结时间": dt.datetime.now(dt.timezone.utc).astimezone().isoformat(),
            "输入": {
                "任务-000079批次": str(FINAL_BATCH.relative_to(ROOT)),
                "任务-000079批次SHA-256": sha256(FINAL_BATCH / "批次清单.json"),
                "任务-000079成员清单SHA-256": sha256(source_csv),
                "声明配置": config_fingerprints,
                "声明入口条数": len(entries),
            },
            "结果摘要": {
                "候选成员总体": len(output_rows),
                "分标的入口状态": summary,
                "已证明": 0,
                "ZS-DATA-GAP-001": "继续阻塞；当前没有完整九字段声明入口",
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
            "规则SHA-256": sha256(Path(__file__).resolve()),
            "输出SHA-256": {output_csv.name: sha256(output_csv)},
            "结论边界": "入口状态差异不推导来源身份、因果、预测优势、胜率、收益、研究准入或交易许可",
        }
        (temp_dir / "批次清单.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if target.exists():
            raise ValueError("历史批次目录在发布前已存在")
        os.replace(temp_dir, target)
        return target
    except Exception:
        for path in temp_dir.glob("*"):
            path.unlink(missing_ok=True)
        temp_dir.rmdir()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="复核来源身份声明证据入口")
    parser.add_argument("--batch", required=True)
    parser.add_argument("--output-root", type=Path, default=ROOT / "artifacts/数据/来源身份声明证据入口复核")
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    target = execute(args.batch, args.output_root)
    print(json.dumps({"批次": target.name, "路径": str(target.relative_to(ROOT)), "状态": "成功"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
