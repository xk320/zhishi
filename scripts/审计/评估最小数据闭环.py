#!/usr/bin/env python3
"""基于冻结审计证据生成最小数据闭环容量规划，不读取市场数据正文。"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


一天秒数 = 86_400
输出列 = [
    "配置版本",
    "估算类型",
    "期限月数",
    "期限天数",
    "数据族",
    "标的数",
    "每标的数据流数",
    "采样间隔秒数",
    "单记录预算字节数",
    "基础字节数",
    "质量血缘字节数",
    "副本后字节数",
    "安全余量后字节数",
    "限制",
]


class 合同错误(ValueError):
    """输入、配置或输出不满足冻结合同时抛出。"""


def 向上整除(分子: int, 分母: int) -> int:
    if 分母 <= 0:
        raise 合同错误("分母必须为正整数")
    return (分子 + 分母 - 1) // 分母


def 要求精确键(值: Any, 预期: set[str], 名称: str) -> dict[str, Any]:
    if type(值) is not dict:
        raise 合同错误(f"{名称}必须为JSON对象")
    实际 = set(值)
    if 实际 != 预期:
        缺少 = sorted(预期 - 实际)
        多余 = sorted(实际 - 预期)
        raise 合同错误(f"{名称}字段漂移：缺少={缺少}，多余={多余}")
    return 值


def 要求正整数(值: Any, 名称: str) -> int:
    if type(值) is not int or 值 <= 0:
        raise 合同错误(f"{名称}必须为正整数")
    return 值


def 要求安全字符串(值: Any, 名称: str) -> str:
    if type(值) is not str or not 值 or 值 != 值.strip():
        raise 合同错误(f"{名称}必须为无首尾空白的非空字符串")
    if 值[0] in "=+-@":
        raise 合同错误(f"{名称}包含表格公式前缀")
    if any(ord(字符) < 32 for 字符 in 值):
        raise 合同错误(f"{名称}包含控制字符")
    return 值


def 加载配置(路径: Path) -> dict[str, Any]:
    if not 路径.is_file() or 路径.is_symlink():
        raise 合同错误(f"配置文件不可用：{路径}")
    try:
        配置 = json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as 异常:
        raise 合同错误(f"配置文件读取失败：{异常}") from 异常

    要求精确键(
        配置,
        {
            "配置版本",
            "估算类型",
            "证据合同",
            "标的",
            "期限",
            "数据族",
            "质量血缘倍率",
            "副本数",
            "安全余量倍率",
            "限制",
        },
        "配置",
    )
    for 字段 in ("配置版本", "估算类型", "限制"):
        要求安全字符串(配置[字段], 字段)

    证据 = 要求精确键(
        配置["证据合同"],
        {
            "发现批次",
            "质量审计批次",
            "重放批次",
            "清单指纹",
            "快照合同版本",
            "验证单元数",
            "质量无法判定数",
            "重放拒绝数",
            "重放无法判定数",
            "输入文件指纹",
            "输入列指纹",
        },
        "证据合同",
    )
    for 字段 in ("发现批次", "质量审计批次", "重放批次", "清单指纹", "快照合同版本"):
        要求安全字符串(证据[字段], f"证据合同.{字段}")
    for 字段 in ("验证单元数", "质量无法判定数", "重放拒绝数", "重放无法判定数"):
        if type(证据[字段]) is not int or 证据[字段] < 0:
            raise 合同错误(f"证据合同.{字段}必须为非负整数")
    要求精确键(
        证据["输入文件指纹"],
        {"资产清单", "质量结果", "断档结果", "异常结果", "重放结果"},
        "输入文件指纹",
    )
    要求精确键(
        证据["输入列指纹"],
        {"资产清单", "质量结果", "断档结果", "异常结果", "重放结果"},
        "输入列指纹",
    )

    if type(配置["标的"]) is not list or not 配置["标的"]:
        raise 合同错误("标的必须为非空数组")
    for 标的 in 配置["标的"]:
        要求安全字符串(标的, "标的")
    if len(set(配置["标的"])) != len(配置["标的"]):
        raise 合同错误("标的不得重复")

    if type(配置["期限"]) is not list or not 配置["期限"]:
        raise 合同错误("期限必须为非空数组")
    期限月数: set[int] = set()
    for 期限 in 配置["期限"]:
        要求精确键(期限, {"月数", "天数"}, "期限项")
        月数 = 要求正整数(期限["月数"], "期限月数")
        要求正整数(期限["天数"], "期限天数")
        if 月数 in 期限月数:
            raise 合同错误("期限月数不得重复")
        期限月数.add(月数)

    if type(配置["数据族"]) is not list or not 配置["数据族"]:
        raise 合同错误("数据族必须为非空数组")
    数据族名称: set[str] = set()
    for 数据族 in 配置["数据族"]:
        要求精确键(
            数据族,
            {"名称", "每标的数据流数", "采样间隔秒数", "单记录预算字节数"},
            "数据族项",
        )
        名称 = 要求安全字符串(数据族["名称"], "数据族名称")
        if 名称 == "总计":
            raise 合同错误("数据族名称无效")
        if 名称 in 数据族名称:
            raise 合同错误("数据族名称不得重复")
        数据族名称.add(名称)
        for 字段 in ("每标的数据流数", "采样间隔秒数", "单记录预算字节数"):
            要求正整数(数据族[字段], f"{名称}.{字段}")

    for 字段 in ("质量血缘倍率", "安全余量倍率"):
        比率 = 要求精确键(配置[字段], {"分子", "分母"}, 字段)
        分子 = 要求正整数(比率["分子"], f"{字段}.分子")
        分母 = 要求正整数(比率["分母"], f"{字段}.分母")
        if 分子 < 分母:
            raise 合同错误(f"{字段}不得小于1")
    要求正整数(配置["副本数"], "副本数")
    return 配置


def 文件指纹(路径: Path) -> str:
    摘要 = hashlib.sha256()
    try:
        with 路径.open("rb") as 文件:
            while 数据 := 文件.read(1024 * 1024):
                摘要.update(数据)
    except OSError as 异常:
        raise 合同错误(f"文件指纹计算失败：{异常}") from 异常
    return 摘要.hexdigest()


def 读取证据(
    路径: Path,
    预期文件指纹: str,
    列指纹: str,
    名称: str,
) -> tuple[list[str], list[dict[str, str]]]:
    if not 路径.is_file() or 路径.is_symlink():
        raise 合同错误(f"{名称}不可用：{路径}")
    if 文件指纹(路径) != 预期文件指纹:
        raise 合同错误(f"{名称}文件指纹不一致")
    try:
        with 路径.open(encoding="utf-8-sig", newline="") as 文件:
            读取器 = csv.DictReader(文件)
            if 读取器.fieldnames is None:
                raise 合同错误(f"{名称}缺少表头")
            表头 = list(读取器.fieldnames)
            实际指纹 = hashlib.sha256("\x1f".join(表头).encode("utf-8")).hexdigest()
            if 实际指纹 != 列指纹:
                raise 合同错误(f"{名称}列指纹不一致")
            行 = list(读取器)
    except (OSError, UnicodeError, csv.Error) as 异常:
        raise 合同错误(f"{名称}读取失败：{异常}") from 异常
    if not 行:
        raise 合同错误(f"{名称}没有数据行")
    return 表头, 行


def 唯一值(行: list[dict[str, str]], 字段: str, 名称: str) -> str:
    值 = {记录.get(字段, "") for 记录 in 行}
    if len(值) != 1 or "" in 值:
        raise 合同错误(f"{名称}.{字段}不是唯一非空值")
    return next(iter(值))


def 资产编号集合(行: list[dict[str, str]], 名称: str) -> set[str]:
    编号 = [记录.get("资产编号", "") for 记录 in 行]
    if any(not 值 for 值 in 编号) or len(set(编号)) != len(编号):
        raise 合同错误(f"{名称}资产编号缺失或重复")
    return set(编号)


def 校验证据(参数: argparse.Namespace, 配置: dict[str, Any]) -> dict[str, int]:
    合同 = 配置["证据合同"]
    文件指纹合同 = 合同["输入文件指纹"]
    列指纹 = 合同["输入列指纹"]
    _, 清单 = 读取证据(
        参数.inventory,
        文件指纹合同["资产清单"],
        列指纹["资产清单"],
        "资产清单",
    )
    _, 质量 = 读取证据(
        参数.quality,
        文件指纹合同["质量结果"],
        列指纹["质量结果"],
        "质量结果",
    )
    _, 断档 = 读取证据(
        参数.gaps,
        文件指纹合同["断档结果"],
        列指纹["断档结果"],
        "断档结果",
    )
    _, 异常 = 读取证据(
        参数.anomalies,
        文件指纹合同["异常结果"],
        列指纹["异常结果"],
        "异常结果",
    )
    _, 重放 = 读取证据(
        参数.replay,
        文件指纹合同["重放结果"],
        列指纹["重放结果"],
        "重放结果",
    )

    if 唯一值(清单, "发现批次", "资产清单") != 合同["发现批次"]:
        raise 合同错误("资产清单发现批次不一致")
    清单编号 = 资产编号集合(清单, "资产清单")
    结果集合: list[tuple[str, list[dict[str, str]]]] = [
        ("质量结果", 质量),
        ("断档结果", 断档),
        ("异常结果", 异常),
        ("重放结果", 重放),
    ]
    固定编号: set[str] | None = None
    for 名称, 行 in 结果集合:
        if len(行) != 合同["验证单元数"]:
            raise 合同错误(f"{名称}验证单元数不一致")
        编号 = 资产编号集合(行, 名称)
        if not 编号.issubset(清单编号):
            raise 合同错误(f"{名称}包含清单外资产")
        if 固定编号 is None:
            固定编号 = 编号
        elif 编号 != 固定编号:
            raise 合同错误(f"{名称}资产覆盖与其他结果不一致")

    for 名称, 行 in (("质量结果", 质量), ("断档结果", 断档), ("异常结果", 异常)):
        if 唯一值(行, "审计批次", 名称) != 合同["质量审计批次"]:
            raise 合同错误(f"{名称}审计批次不一致")
        if 唯一值(行, "清单指纹", 名称) != 合同["清单指纹"]:
            raise 合同错误(f"{名称}清单指纹不一致")
    if 唯一值(重放, "验证批次", "重放结果") != 合同["重放批次"]:
        raise 合同错误("重放批次不一致")
    if 唯一值(重放, "清单指纹", "重放结果") != 合同["清单指纹"]:
        raise 合同错误("重放清单指纹不一致")
    if 唯一值(重放, "快照合同版本", "重放结果") != 合同["快照合同版本"]:
        raise 合同错误("快照合同版本不一致")

    质量无法判定数 = sum(记录["可用性结论"] == "无法判定" for 记录 in 质量)
    if 质量无法判定数 != 合同["质量无法判定数"]:
        raise 合同错误("质量结论分布与冻结合同不一致")
    if any(记录["可用性结论"] != "无法判定" for 记录 in 质量):
        raise 合同错误("质量结果出现未获合同允许的结论")
    拒绝数 = sum(记录["重放结论"] == "拒绝" for 记录 in 重放)
    无法判定数 = sum(记录["重放结论"] == "无法判定" for 记录 in 重放)
    if 拒绝数 != 合同["重放拒绝数"] or 无法判定数 != 合同["重放无法判定数"]:
        raise 合同错误("重放结论分布与冻结合同不一致")
    if any(记录["重放结论"] not in {"拒绝", "无法判定"} for 记录 in 重放):
        raise 合同错误("重放结果出现未获合同允许的结论")
    return {
        "资产清单记录数": len(清单),
        "验证单元数": len(质量),
        "质量无法判定数": 质量无法判定数,
        "重放拒绝数": 拒绝数,
        "重放无法判定数": 无法判定数,
    }


def 生成容量行(配置: dict[str, Any]) -> list[dict[str, str]]:
    标的数 = len(配置["标的"])
    质量分子 = 配置["质量血缘倍率"]["分子"]
    质量分母 = 配置["质量血缘倍率"]["分母"]
    余量分子 = 配置["安全余量倍率"]["分子"]
    余量分母 = 配置["安全余量倍率"]["分母"]
    副本数 = 配置["副本数"]
    结果: list[dict[str, str]] = []
    for 期限 in sorted(配置["期限"], key=lambda 项: 项["月数"]):
        明细: list[dict[str, str]] = []
        for 数据族 in 配置["数据族"]:
            每日记录 = 向上整除(一天秒数, 数据族["采样间隔秒数"])
            基础 = (
                期限["天数"]
                * 标的数
                * 数据族["每标的数据流数"]
                * 每日记录
                * 数据族["单记录预算字节数"]
            )
            质量血缘 = 向上整除(基础 * (质量分子 - 质量分母), 质量分母)
            副本后 = (基础 + 质量血缘) * 副本数
            安全余量后 = 向上整除(副本后 * 余量分子, 余量分母)
            明细.append(
                {
                    "配置版本": 配置["配置版本"],
                    "估算类型": 配置["估算类型"],
                    "期限月数": str(期限["月数"]),
                    "期限天数": str(期限["天数"]),
                    "数据族": 数据族["名称"],
                    "标的数": str(标的数),
                    "每标的数据流数": str(数据族["每标的数据流数"]),
                    "采样间隔秒数": str(数据族["采样间隔秒数"]),
                    "单记录预算字节数": str(数据族["单记录预算字节数"]),
                    "基础字节数": str(基础),
                    "质量血缘字节数": str(质量血缘),
                    "副本后字节数": str(副本后),
                    "安全余量后字节数": str(安全余量后),
                    "限制": 配置["限制"],
                }
            )
        结果.extend(明细)
        结果.append(
            {
                "配置版本": 配置["配置版本"],
                "估算类型": 配置["估算类型"],
                "期限月数": str(期限["月数"]),
                "期限天数": str(期限["天数"]),
                "数据族": "总计",
                "标的数": str(标的数),
                "每标的数据流数": "不适用",
                "采样间隔秒数": "不适用",
                "单记录预算字节数": "不适用",
                "基础字节数": str(sum(int(行["基础字节数"]) for 行 in 明细)),
                "质量血缘字节数": str(sum(int(行["质量血缘字节数"]) for 行 in 明细)),
                "副本后字节数": str(sum(int(行["副本后字节数"]) for 行 in 明细)),
                "安全余量后字节数": str(sum(int(行["安全余量后字节数"]) for 行 in 明细)),
                "限制": 配置["限制"],
            }
        )
    return 结果


def 原子写入(路径: Path, 行: list[dict[str, str]]) -> None:
    if 路径.exists() and (not 路径.is_file() or 路径.is_symlink()):
        raise 合同错误(f"输出路径不是普通文件：{路径}")
    路径.parent.mkdir(parents=True, exist_ok=True)
    临时路径: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=路径.parent,
            prefix=f".{路径.name}.",
            suffix=".tmp",
            delete=False,
        ) as 文件:
            临时路径 = Path(文件.name)
            写入器 = csv.DictWriter(文件, fieldnames=输出列, lineterminator="\n")
            写入器.writeheader()
            写入器.writerows(行)
            文件.flush()
            os.fsync(文件.fileno())
        os.replace(临时路径, 路径)
    except (OSError, csv.Error) as 异常:
        if 临时路径 is not None:
            try:
                临时路径.unlink(missing_ok=True)
            except OSError:
                pass
        raise 合同错误(f"容量结果发布失败：{异常}") from 异常


def 构建参数() -> argparse.ArgumentParser:
    解析器 = argparse.ArgumentParser(description="评估最小数据闭环与容量规划")
    解析器.add_argument("--inventory", type=Path, required=True)
    解析器.add_argument("--quality", type=Path, required=True)
    解析器.add_argument("--gaps", type=Path, required=True)
    解析器.add_argument("--anomalies", type=Path, required=True)
    解析器.add_argument("--replay", type=Path, required=True)
    解析器.add_argument("--config", type=Path, required=True)
    解析器.add_argument("--capacity-output", type=Path, required=True)
    return 解析器


def 主函数(参数列表: list[str] | None = None) -> int:
    参数 = 构建参数().parse_args(参数列表)
    try:
        输入路径 = {
            参数.inventory.resolve(),
            参数.quality.resolve(),
            参数.gaps.resolve(),
            参数.anomalies.resolve(),
            参数.replay.resolve(),
            参数.config.resolve(),
        }
        if 参数.capacity_output.resolve() in 输入路径:
            raise 合同错误("输出路径不得覆盖任何输入")
        配置 = 加载配置(参数.config)
        摘要 = 校验证据(参数, 配置)
        原子写入(参数.capacity_output, 生成容量行(配置))
        摘要.update(
            {
                "配置版本": 配置["配置版本"],
                "估算类型": 配置["估算类型"],
                "基准模型阶段": "禁止",
                "原因": "资产、三类时间、质量、重放与最小闭环关键证据未全部通过",
            }
        )
        print(json.dumps(摘要, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except 合同错误 as 异常:
        print(f"最小数据闭环评估失败：{异常}", file=sys.stderr)
        return 2
    except Exception as 异常:  # pragma: no cover - 最后一道失败安全边界
        print(f"最小数据闭环评估异常：{type(异常).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(主函数())
