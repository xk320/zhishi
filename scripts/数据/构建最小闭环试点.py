#!/usr/bin/env python3
"""从双标闭环证据构建隔离的最小闭环试点或真实零成员拒绝批次。

本脚本只读取仓库内已冻结的聚合证据，不读取服务器、数据库或市场正文。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Iterable


主研究尺度 = ("4小时", "8小时", "24小时", "48小时")
结果观察窗口 = ("15分钟", "1小时")
标的顺序 = {"BTC": 0, "ETH": 1}
允许状态 = frozenset({"可用", "有限可用"})
必需列 = frozenset(
    {
        "批次",
        "资产编号",
        "标的",
        "交易场所",
        "市场类型",
        "精确合约",
        "数据对象",
        "主研究尺度",
        "尺度证据状态",
        "事后结果观察窗口",
        "时间范围",
        "来源成员编号",
        "最终状态",
        "门1来源身份",
        "门2时间与质量合同",
        "门3质量审计",
        "门4历史重放",
        "门5成本与执行",
        "门6血缘",
        "成员指纹",
    }
)
维度列 = (
    "标的",
    "资产编号",
    "交易场所",
    "市场类型",
    "精确合约",
    "数据对象",
    "主研究尺度",
    "事后结果观察窗口",
    "时间范围",
)
成员列 = (
    *维度列,
    "来源成员编号",
    "成员指纹",
    "来源批次",
    "来源行号",
)
评估列 = (
    *维度列,
    "最终状态",
    "尺度证据状态",
    "门1来源身份",
    "门2时间与质量合同",
    "门3质量审计",
    "门4历史重放",
    "门5成本与执行",
    "门6血缘",
    "是否合格",
    "拒绝原因",
    "成员指纹",
)
规则版本 = "minimum-pilot-selection/v1"


class 合同错误(ValueError):
    """输入、规则或输出不满足任务合同。"""


def 文件指纹(路径: Path) -> str:
    if not 路径.is_file() or 路径.is_symlink():
        raise 合同错误(f"输入不是普通文件：{路径}")
    摘要 = hashlib.sha256()
    try:
        with 路径.open("rb") as 文件:
            while 数据 := 文件.read(1024 * 1024):
                摘要.update(数据)
    except OSError as 异常:
        raise 合同错误(f"输入读取失败：{路径}") from 异常
    return 摘要.hexdigest()


def 稳定JSON(值: Any) -> str:
    return json.dumps(值, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def 规则指纹() -> str:
    规则 = {
        "版本": 规则版本,
        "标的顺序": list(标的顺序),
        "主研究尺度": list(主研究尺度),
        "结果观察窗口": list(结果观察窗口),
        "允许状态": sorted(允许状态),
        "必须通过门": [f"门{i}" for i in range(1, 7)],
        "未知值": "拒绝",
        "选择": "按确定性排序后取首个合格叶子；无合格叶子形成拒绝批次",
    }
    return hashlib.sha256(稳定JSON(规则).encode("utf-8")).hexdigest()


def 读取配置(路径: Path) -> dict[str, Any]:
    if not 路径.is_file() or 路径.is_symlink():
        raise 合同错误(f"配置不可用：{路径}")
    try:
        配置 = json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as 异常:
        raise 合同错误("配置读取失败") from 异常
    必需 = {
        "配置版本",
        "来源批次",
        "来源成员路径",
        "来源成员SHA256",
        "最大成员数",
        "最大评估行数",
        "最大输出字节数",
        "限制",
    }
    if set(配置) != 必需:
        raise 合同错误("配置字段漂移")
    if not isinstance(配置["来源批次"], str) or not 配置["来源批次"]:
        raise 合同错误("来源批次无效")
    for 字段 in ("最大成员数", "最大评估行数", "最大输出字节数"):
        if type(配置[字段]) is not int or 配置[字段] <= 0:
            raise 合同错误(f"{字段}必须为正整数")
    return 配置


def 读取成员(路径: Path, 来源批次: str, 最大评估行数: int) -> list[dict[str, str]]:
    if 文件指纹(路径) == "":  # pragma: no cover - 防止静态分析误判未使用
        raise 合同错误("来源指纹为空")
    try:
        with 路径.open(encoding="utf-8-sig", newline="") as 文件:
            读取器 = csv.DictReader(文件)
            表头 = frozenset(读取器.fieldnames or ())
            if not 必需列.issubset(表头):
                raise 合同错误("来源成员列不足")
            行: list[dict[str, str]] = []
            for 行号, 记录 in enumerate(读取器, start=2):
                if 行号 > 最大评估行数 + 1:
                    raise 合同错误("来源评估行数超过硬上限")
                if 记录.get("批次") != 来源批次:
                    raise 合同错误("来源批次混杂")
                行.append({列: 记录.get(列, "") for 列 in 表头})
    except (OSError, UnicodeError, csv.Error) as 异常:
        if isinstance(异常, 合同错误):
            raise
        raise 合同错误("来源成员读取失败") from 异常
    if not 行:
        raise 合同错误("来源成员为空")
    return 行


def 观察窗口(值: str) -> tuple[str, ...]:
    try:
        解析 = json.loads(值)
    except json.JSONDecodeError as 异常:
        raise 合同错误("结果观察窗口不是JSON数组") from 异常
    if tuple(解析) != 结果观察窗口:
        raise 合同错误("结果观察窗口必须固定为15分钟、1小时")
    return tuple(解析)


def 拒绝原因(记录: dict[str, str]) -> list[str]:
    原因: list[str] = []
    if 记录.get("标的") not in 标的顺序:
        原因.append("标的不在BTC/ETH范围")
    if 记录.get("主研究尺度") not in 主研究尺度:
        原因.append("主研究尺度不在4小时/8小时/24小时/48小时")
    try:
        观察窗口(记录.get("事后结果观察窗口", ""))
    except 合同错误:
        原因.append("事后结果观察窗口不符合合同")
    for 字段 in ("交易场所", "市场类型", "精确合约", "数据对象", "时间范围"):
        if not 记录.get(字段) or 记录[字段] == "未知":
            原因.append(f"{字段}未知")
    if 记录.get("尺度证据状态") != "通过":
        原因.append("尺度证据未通过")
    if 记录.get("最终状态") not in 允许状态:
        原因.append(f"最终状态={记录.get('最终状态', '')}不允许")
    for 门 in ("门1来源身份", "门2时间与质量合同", "门3质量审计", "门4历史重放", "门5成本与执行", "门6血缘"):
        if 记录.get(门) != "通过":
            原因.append(f"{门}={记录.get(门, '')}")
    return 原因


def 评估(行: Iterable[dict[str, str]], 来源批次: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    评估结果: list[dict[str, str]] = []
    合格: list[dict[str, str]] = []
    for 记录 in 行:
        原因 = 拒绝原因(记录)
        结果 = {列: 记录.get(列, "") for 列 in 评估列 if 列 not in {"是否合格", "拒绝原因"}}
        结果["是否合格"] = "是" if not 原因 else "否"
        结果["拒绝原因"] = "；".join(原因)
        评估结果.append(结果)
        if not 原因:
            合格.append(记录)
    合格.sort(key=lambda 记录: (
        标的顺序[记录["标的"]],
        记录["资产编号"],
        主研究尺度.index(记录["主研究尺度"]),
        记录["交易场所"],
        记录["市场类型"],
        记录["精确合约"],
        记录["数据对象"],
        记录["时间范围"],
        记录["成员指纹"],
    ))
    return 评估结果, 合格


def 原子写入CSV(路径: Path, 列: tuple[str, ...], 行: Iterable[dict[str, str]]) -> None:
    临时: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=路径.parent,
            prefix=f".{路径.name}.", suffix=".tmp", delete=False
        ) as 文件:
            临时 = Path(文件.name)
            写入器 = csv.DictWriter(文件, fieldnames=列, lineterminator="\n")
            写入器.writeheader()
            写入器.writerows(行)
            文件.flush()
            os.fsync(文件.fileno())
        os.replace(临时, 路径)
    except (OSError, csv.Error) as 异常:
        if 临时 is not None:
            临时.unlink(missing_ok=True)
        raise 合同错误(f"输出发布失败：{路径}") from 异常


def 原子写入文本(路径: Path, 内容: str) -> None:
    临时: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=路径.parent,
            prefix=f".{路径.name}.", suffix=".tmp", delete=False
        ) as 文件:
            临时 = Path(文件.name)
            文件.write(内容)
            文件.flush()
            os.fsync(文件.fileno())
        os.replace(临时, 路径)
    except OSError as 异常:
        if 临时 is not None:
            临时.unlink(missing_ok=True)
        raise 合同错误(f"输出发布失败：{路径}") from 异常


def 构建批次(配置路径: Path, 批次根: Path, 批次号: str) -> dict[str, Any]:
    配置 = 读取配置(配置路径)
    来源路径 = (配置路径.parent.parent.parent / 配置["来源成员路径"]).resolve()
    来源摘要 = 文件指纹(来源路径)
    if 来源摘要 != 配置["来源成员SHA256"]:
        raise 合同错误("来源成员指纹漂移")
    行 = 读取成员(来源路径, 配置["来源批次"], 配置["最大评估行数"])
    评估结果, 合格 = 评估(行, 配置["来源批次"])
    if len(评估结果) > 配置["最大评估行数"]:
        raise 合同错误("评估结果超过硬上限")
    if len(合格) > 配置["最大成员数"]:
        合格 = 合格[: 配置["最大成员数"]]
    目标 = (批次根 / 批次号).resolve()
    if 目标.exists():
        raise 合同错误("批次已存在，拒绝覆盖")
    目标.mkdir(parents=True)
    try:
        评估路径 = 目标 / "候选评估.csv"
        成员路径 = 目标 / "成员.csv"
        血缘路径 = 目标 / "血缘.csv"
        报告路径 = 目标 / "验证报告.json"
        原子写入CSV(评估路径, 评估列, 评估结果)
        成员行 = [
            {
                "标的": 记录["标的"], "资产编号": 记录["资产编号"],
                "交易场所": 记录["交易场所"], "市场类型": 记录["市场类型"],
                "精确合约": 记录["精确合约"], "数据对象": 记录["数据对象"],
                "主研究尺度": 记录["主研究尺度"],
                "事后结果观察窗口": 记录["事后结果观察窗口"],
                "时间范围": 记录["时间范围"],
                "来源成员编号": 记录.get("来源成员编号", ""),
                "成员指纹": 记录.get("成员指纹", ""),
                "来源批次": 配置["来源批次"],
                "来源行号": str(行.index(记录) + 2),
            }
            for 记录 in 合格
        ]
        原子写入CSV(成员路径, 成员列, 成员行)
        原子写入CSV(
            血缘路径,
            ("对象类型", "对象路径", "来源批次", "来源SHA256", "规则版本", "规则指纹"),
            [{
                "对象类型": "输入成员证据",
                "对象路径": 配置["来源成员路径"],
                "来源批次": 配置["来源批次"],
                "来源SHA256": 来源摘要,
                "规则版本": 规则版本,
                "规则指纹": 规则指纹(),
            }],
        )
        统计 = {
            "候选行数": len(评估结果),
            "合格成员数": len(合格),
            "拒绝行数": len(评估结果) - len(合格),
            "按标的候选": {标的: sum(记录["标的"] == 标的 for 记录 in 行) for 标的 in 标的顺序},
            "按标的合格": {标的: sum(记录["标的"] == 标的 for 记录 in 合格) for 标的 in 标的顺序},
        }
        报告 = {
            "批次": 批次号,
            "状态": "零成员拒绝" if not 合格 else "单成员试点",
            "原因": "没有满足全部闭环门、精确维度和尺度边界的叶子；零成员不是成功闭环。" if not 合格 else "按事前规则选择首个合格叶子。",
            "来源批次": 配置["来源批次"],
            "来源成员SHA256": 来源摘要,
            "规则版本": 规则版本,
            "规则指纹": 规则指纹(),
            "主研究尺度": list(主研究尺度),
            "事后结果观察窗口": list(结果观察窗口),
            "统计": 统计,
            "禁止事项": ["不使用样例替代", "不跨BTC/ETH补偿", "不生成交易许可、方向、仓位或订单"],
            "解除条件": "重新生成通过六道门且维度、时间和成本证据完整的不可变闭环批次；再按同一规则重跑。",
            "输入与输出文件": {},
        }
        for 路径 in (评估路径, 成员路径, 血缘路径):
            报告["输入与输出文件"][路径.name] = 文件指纹(路径)
        原子写入文本(报告路径, 稳定JSON(报告) + "\n")
        清单 = {
            "批次": 批次号,
            "报告SHA256": 文件指纹(报告路径),
            "成员SHA256": 文件指纹(成员路径),
            "评估SHA256": 文件指纹(评估路径),
            "血缘SHA256": 文件指纹(血缘路径),
        }
        原子写入文本(目标 / "清单.json", 稳定JSON(清单) + "\n")
        总大小 = sum(路径.stat().st_size for 路径 in 目标.iterdir() if 路径.is_file())
        if 总大小 > 配置["最大输出字节数"]:
            raise 合同错误("输出超过字节上限")
        return 报告
    except Exception:
        # 失败批次不得留下可被误认的完整发布目录；目标此前已确认不存在。
        if 目标.exists():
            shutil.rmtree(目标)
        raise


def 构建参数() -> argparse.ArgumentParser:
    解析器 = argparse.ArgumentParser(description="构建最小数据闭环试点或零成员拒绝批次")
    解析器.add_argument("--config", type=Path, required=True)
    解析器.add_argument("--batch-root", type=Path, required=True)
    解析器.add_argument("--batch-id", required=True)
    return 解析器


def main(参数列表: list[str] | None = None) -> int:
    参数 = 构建参数().parse_args(参数列表)
    try:
        报告 = 构建批次(参数.config.resolve(), 参数.batch_root.resolve(), 参数.batch_id)
        print(稳定JSON(报告))
        return 0
    except 合同错误 as 异常:
        print(f"最小闭环试点失败：{异常}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
