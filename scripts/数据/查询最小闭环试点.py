#!/usr/bin/env python3
"""只读查询最小闭环试点批次，不跨越已冻结维度边界。"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


主研究尺度 = {"4小时", "8小时", "24小时", "48小时"}
允许窗口 = '["15分钟","1小时"]'


def 查询(批次目录: Path, *, 标的: str | None = None, 主尺度: str | None = None) -> dict[str, object]:
    清单路径 = 批次目录 / "清单.json"
    报告路径 = 批次目录 / "验证报告.json"
    成员路径 = 批次目录 / "成员.csv"
    if not all(路径.is_file() and not 路径.is_symlink() for 路径 in (清单路径, 报告路径, 成员路径)):
        raise ValueError("批次产物不完整")
    报告 = json.loads(报告路径.read_text(encoding="utf-8"))
    if 主尺度 is not None and 主尺度 not in 主研究尺度:
        raise ValueError("主研究尺度超出合同")
    if 标的 is not None and 标的 not in {"BTC", "ETH"}:
        raise ValueError("标的超出合同")
    with 成员路径.open(encoding="utf-8-sig", newline="") as 文件:
        行 = list(csv.DictReader(文件))
    结果 = [
        记录
        for 记录 in 行
        if (标的 is None or 记录.get("标的") == 标的)
        and (主尺度 is None or 记录.get("主研究尺度") == 主尺度)
        and 记录.get("事后结果观察窗口") == 允许窗口
    ]
    return {
        "状态": "空集" if not 结果 else "只读结果",
        "批次": 报告.get("批次", ""),
        "原因": 报告.get("原因", "") if not 结果 else "",
        "成员数": len(结果),
        "成员": 结果,
    }


def main() -> int:
    解析器 = argparse.ArgumentParser(description="只读查询最小闭环试点")
    解析器.add_argument("--batch-dir", type=Path, required=True)
    解析器.add_argument("--target")
    解析器.add_argument("--scale")
    参数 = 解析器.parse_args()
    try:
        print(json.dumps(查询(参数.batch_dir.resolve(), 标的=参数.target, 主尺度=参数.scale), ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as 异常:
        print(f"只读查询失败：{异常}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
