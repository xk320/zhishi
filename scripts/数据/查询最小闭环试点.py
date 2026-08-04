#!/usr/bin/env python3
"""只读查询最小闭环试点批次，不跨越已冻结维度边界。"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


主研究尺度 = {"4小时", "8小时", "24小时", "48小时"}
允许窗口 = '["15分钟","1小时"]'
成员列 = (
    "标的", "资产编号", "交易场所", "市场类型", "精确合约", "数据对象",
    "主研究尺度", "事后结果观察窗口", "时间范围", "来源成员编号",
    "成员指纹", "来源批次", "来源行号",
)


def 文件指纹(路径: Path) -> str:
    if not 路径.is_file() or 路径.is_symlink():
        raise ValueError("批次文件不可用")
    摘要 = hashlib.sha256()
    with 路径.open("rb") as 文件:
        while 数据 := 文件.read(1024 * 1024):
            摘要.update(数据)
    return 摘要.hexdigest()


def 校验批次文件(批次目录: Path, 清单: dict[str, object]) -> None:
    对应 = {
        "报告SHA256": "验证报告.json",
        "成员SHA256": "成员.csv",
        "评估SHA256": "候选评估.csv",
        "血缘SHA256": "血缘.csv",
    }
    for 指纹键, 文件名 in 对应.items():
        期望 = 清单.get(指纹键)
        if not isinstance(期望, str) or 文件指纹(批次目录 / 文件名) != 期望:
            raise ValueError(f"批次文件指纹不一致：{文件名}")


def 校验成员(成员路径: Path, 报告: dict[str, object]) -> list[dict[str, str]]:
    with 成员路径.open(encoding="utf-8-sig", newline="") as 文件:
        读取器 = csv.DictReader(文件)
        if tuple(读取器.fieldnames or ()) != 成员列:
            raise ValueError("成员清单列漂移")
        行 = list(读取器)
    来源批次 = 报告.get("来源批次")
    for 记录 in 行:
        if 记录.get("标的") not in {"BTC", "ETH"}:
            raise ValueError("成员标的越界")
        if 记录.get("主研究尺度") not in 主研究尺度:
            raise ValueError("成员主研究尺度越界")
        if 记录.get("事后结果观察窗口") != 允许窗口:
            raise ValueError("成员观察窗口越界")
        if 记录.get("来源批次") != 来源批次:
            raise ValueError("成员来源批次漂移")
        for 字段 in ("交易场所", "市场类型", "精确合约", "数据对象", "时间范围"):
            if not 记录.get(字段) or 记录[字段] == "未知":
                raise ValueError(f"成员维度缺失：{字段}")
    return 行


def 查询(
    批次目录: Path,
    *,
    标的: str | None = None,
    主尺度: str | None = None,
    交易场所: str | None = None,
    市场类型: str | None = None,
    精确合约: str | None = None,
    时间范围: str | None = None,
) -> dict[str, object]:
    清单路径 = 批次目录 / "清单.json"
    报告路径 = 批次目录 / "验证报告.json"
    成员路径 = 批次目录 / "成员.csv"
    if not all(路径.is_file() and not 路径.is_symlink() for 路径 in (清单路径, 报告路径, 成员路径)):
        raise ValueError("批次产物不完整")
    清单 = json.loads(清单路径.read_text(encoding="utf-8"))
    报告 = json.loads(报告路径.read_text(encoding="utf-8"))
    if 报告.get("批次") != 批次目录.name:
        raise ValueError("批次身份漂移")
    校验批次文件(批次目录, 清单)
    if 主尺度 is not None and 主尺度 not in 主研究尺度:
        raise ValueError("主研究尺度超出合同")
    if 标的 is not None and 标的 not in {"BTC", "ETH"}:
        raise ValueError("标的超出合同")
    行 = 校验成员(成员路径, 报告)
    结果 = [
        记录
        for 记录 in 行
        if (标的 is None or 记录.get("标的") == 标的)
        and (主尺度 is None or 记录.get("主研究尺度") == 主尺度)
        and (交易场所 is None or 记录.get("交易场所") == 交易场所)
        and (市场类型 is None or 记录.get("市场类型") == 市场类型)
        and (精确合约 is None or 记录.get("精确合约") == 精确合约)
        and (时间范围 is None or 记录.get("时间范围") == 时间范围)
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
    解析器.add_argument("--venue")
    解析器.add_argument("--market")
    解析器.add_argument("--contract")
    解析器.add_argument("--time-range")
    参数 = 解析器.parse_args()
    try:
        print(json.dumps(查询(参数.batch_dir.resolve(), 标的=参数.target, 主尺度=参数.scale, 交易场所=参数.venue, 市场类型=参数.market, 精确合约=参数.contract, 时间范围=参数.time_range), ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as 异常:
        print(f"只读查询失败：{异常}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
