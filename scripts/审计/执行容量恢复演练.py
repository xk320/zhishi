#!/usr/bin/env python3
"""对最小闭环零成员试点执行有界的本地容量测量和隔离恢复演练。"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import resource
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


批次目录名 = "pilot-20260805T045300+0800-zero-v2"
必需文件 = ("候选评估.csv", "成员.csv", "血缘.csv", "清单.json", "验证报告.json")
容量列 = [
    "标的", "期限月数", "期限天数", "数据族", "估算类型", "基础字节数",
    "质量血缘字节数", "副本后字节数", "安全余量后字节数", "状态", "公式版本",
]


class 合同错误(ValueError):
    """输入或资源边界违反合同。"""


def sha256(路径: Path) -> str:
    摘要 = hashlib.sha256()
    with 路径.open("rb") as 文件:
        while 块 := 文件.read(1024 * 1024):
            摘要.update(块)
    return 摘要.hexdigest()


def json指纹(值: Any) -> str:
    return hashlib.sha256(json.dumps(值, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def 读取json(路径: Path) -> dict[str, Any]:
    if not 路径.is_file() or 路径.is_symlink():
        raise 合同错误(f"JSON不可用：{路径}")
    try:
        值 = json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as 异常:
        raise 合同错误(f"JSON读取失败：{路径}：{异常}") from 异常
    if not isinstance(值, dict):
        raise 合同错误(f"JSON必须为对象：{路径}")
    return 值


def 文件清单(目录: Path) -> list[dict[str, Any]]:
    结果 = []
    for 名称 in 必需文件:
        路径 = 目录 / 名称
        if not 路径.is_file() or 路径.is_symlink():
            raise 合同错误(f"试点文件缺失或为符号链接：{路径}")
        结果.append({"文件": 名称, "字节数": 路径.stat().st_size, "SHA256": sha256(路径)})
    return 结果


def 校验试点(目录: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    清单 = 读取json(目录 / "清单.json")
    报告 = 读取json(目录 / "验证报告.json")
    if 清单.get("批次") != 批次目录名 or 报告.get("批次") != 批次目录名:
        raise 合同错误("试点批次身份不匹配")
    if 报告.get("状态") != "零成员拒绝" or 报告.get("统计", {}).get("合格成员数") != 0:
        raise 合同错误("本演练只接受任务035零成员试点")
    实际 = 文件清单(目录)
    # 任务035清单记录了三个CSV及报告，逐一核对可验证的指纹。
    对照 = {
        "成员.csv": 清单.get("成员SHA256"),
        "候选评估.csv": 清单.get("评估SHA256"),
        "血缘.csv": 清单.get("血缘SHA256"),
        "验证报告.json": 清单.get("报告SHA256"),
    }
    for 项 in 实际:
        预期 = 对照.get(项["文件"])
        if 预期 and 预期 != 项["SHA256"]:
            raise 合同错误(f"试点文件指纹不一致：{项['文件']}")
    return {"清单": 清单, "报告": 报告}, 实际


def 检查资源(目录: Path, 最小可用字节数: int, 截止时间: float | None = None) -> dict[str, Any]:
    可用 = shutil.disk_usage(目录).free
    if 可用 < 最小可用字节数:
        raise 合同错误(f"可用磁盘低于安全余量：{可用} < {最小可用字节数}")
    if 截止时间 is not None and time.monotonic() > 截止时间:
        raise 合同错误("演练超过时间上限")
    使用量 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS单位为字节，Linux单位为KiB；结果只用于本次环境指纹，不用于容量承诺。
    峰值内存字节 = 使用量 if os.uname().sysname == "Darwin" else 使用量 * 1024
    return {"可用磁盘字节数": 可用, "进程峰值内存字节数": 峰值内存字节}


def 复制并恢复(来源: Path, 临时根: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    备份 = 临时根 / "备份"
    恢复 = 临时根 / "恢复"
    备份.mkdir()
    恢复.mkdir()
    结果 = []
    for 名称 in 必需文件:
        原文件 = 来源 / 名称
        备份文件 = 备份 / 名称
        恢复文件 = 恢复 / 名称
        shutil.copyfile(原文件, 备份文件)
        shutil.copyfile(备份文件, 恢复文件)
        原SHA = sha256(原文件)
        备份SHA = sha256(备份文件)
        恢复SHA = sha256(恢复文件)
        结果.append({
            "文件": 名称, "源SHA256": 原SHA, "备份SHA256": 备份SHA,
            "恢复SHA256": 恢复SHA, "字节数": 原文件.stat().st_size,
            "匹配": 原SHA == 备份SHA == 恢复SHA, "状态": "通过" if 原SHA == 备份SHA == 恢复SHA else "失败",
        })
    return 结果, {"备份字节数": sum(项["字节数"] for 项 in 结果), "恢复字节数": sum(项["字节数"] for 项 in 结果)}


def 计算容量(配置: dict[str, Any]) -> list[dict[str, Any]]:
    行 = []
    质量 = 配置["质量血缘倍率"]
    安全 = 配置["安全余量倍率"]
    for 标的 in 配置["标的"]:
        for 期限 in 配置["期限"]:
            for 数据族 in 配置["数据族"]:
                基础 = 期限["天数"] * 86400 // 数据族["采样间隔秒数"] * 数据族["每标的数据流数"] * 数据族["单记录预算字节数"]
                血缘 = (基础 * 质量["分子"] + 质量["分母"] - 1) // 质量["分母"]
                副本 = 血缘 * 配置["副本数"]
                安全后 = (副本 * 安全["分子"] + 安全["分母"] - 1) // 安全["分母"]
                行.append({
                    "标的": 标的, "期限月数": 期限["月数"], "期限天数": 期限["天数"],
                    "数据族": 数据族["名称"], "估算类型": 配置["估算类型"],
                    "基础字节数": 基础, "质量血缘字节数": 血缘, "副本后字节数": 副本,
                    "安全余量后字节数": 安全后, "状态": "规划假设，零成员无法用试点校准",
                    "公式版本": 配置["配置版本"],
                })
    return 行


def 写JSON(路径: Path, 值: Any) -> None:
    路径.write_text(json.dumps(值, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def 执行(试点: Path, 配置路径: Path, 输出根: Path, 最小可用字节数: int = 10 * 1024 * 1024, 总时长秒数: int = 30) -> Path:
    输出根.mkdir(parents=True, exist_ok=True)
    配置 = 读取json(配置路径)
    if 配置.get("标的") != ["BTC", "ETH"] or [项.get("月数") for 项 in 配置.get("期限", [])] != [3, 6, 12]:
        raise 合同错误("配置必须固定为BTC/ETH及3、6、12个月")
    if 试点.name != 批次目录名:
        raise 合同错误("试点目录名称不是冻结批次")
    开始 = time.monotonic()
    资源前 = 检查资源(输出根, 最小可用字节数, 开始 + 总时长秒数)
    _, 输入文件 = 校验试点(试点)
    临时父 = Path(tempfile.mkdtemp(prefix="zhishi-capacity-"))
    try:
        恢复结果, 副本统计 = 复制并恢复(试点, 临时父)
        资源后 = 检查资源(输出根, 最小可用字节数, 开始 + 总时长秒数)
        名称 = "capacity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        目标 = 输出根 / 名称
        目标.mkdir()
        原始字节数 = sum(项["字节数"] for 项 in 输入文件)
        with gzip.open(临时父 / "压缩.gz", "wb", compresslevel=6) as 压缩:
            for 项 in 输入文件:
                压缩.write((试点 / 项["文件"]).read_bytes())
        压缩字节数 = (临时父 / "压缩.gz").stat().st_size
        成员行数 = 0
        with (试点 / "成员.csv").open(encoding="utf-8-sig", newline="") as 文件:
            成员行数 = max(sum(1 for _ in csv.reader(文件)) - 1, 0)
        测量 = {
            "状态": "零成员容量无法判定",
            "试点批次": 批次目录名,
            "成员记录数": 成员行数,
            "试点元数据原始字节数": 原始字节数,
            "试点元数据压缩字节数": 压缩字节数,
            "压缩方法": "gzip-6，仅对试点元数据，不代表市场原始数据压缩率",
            "索引开销": {"状态": "无法判定", "原因": "零成员且试点未生成索引"},
            "质量血缘开销字节数": next(项["字节数"] for 项 in 输入文件 if 项["文件"] == "血缘.csv"),
            "日志开销": {"状态": "无法判定", "原因": "本地演练未写入生产日志"},
            "进程峰值内存字节数": max(资源前["进程峰值内存字节数"], 资源后["进程峰值内存字节数"]),
            "隔离副本字节数": 副本统计["备份字节数"] + 副本统计["恢复字节数"],
            "服务器与生产数据": "未访问、未修改",
            "测量边界": "仅测量任务035零成员试点元数据；市场记录增长、索引和生产副本均不能由此推断",
        }
        写JSON(目标 / "测量.json", 测量)
        with (目标 / "容量区间.csv").open("w", encoding="utf-8", newline="") as 文件:
            写入 = csv.DictWriter(文件, fieldnames=容量列)
            写入.writeheader()
            写入.writerows(计算容量(配置))
        with (目标 / "恢复清单.csv").open("w", encoding="utf-8", newline="") as 文件:
            列 = ["文件", "源SHA256", "备份SHA256", "恢复SHA256", "字节数", "匹配", "状态"]
            写入 = csv.DictWriter(文件, fieldnames=列)
            写入.writeheader()
            写入.writerows(恢复结果)
        恢复通过 = bool(恢复结果) and all(项["匹配"] for 项 in 恢复结果)
        写JSON(目标 / "验证报告.json", {
            "状态": "零成员容量无法判定",
            "隔离元数据恢复": "通过" if 恢复通过 else "失败",
            "市场记录恢复": "无法判定（零成员）",
            "恢复记录数": len(恢复结果),
            "恢复指纹全部匹配": 恢复通过,
            "失败处理": "任一指纹不匹配均不得标记为通过",
            "清理": "仅清理本次mktemp目录",
        })
        输出文件 = sorted(目标.iterdir())
        写JSON(目标 / "清单.json", {
            "批次": 名称,
            "输入试点批次": 批次目录名,
            "输入清单指纹": json指纹(输入文件),
            "配置SHA256": sha256(配置路径),
            "脚本SHA256": sha256(Path(__file__)),
            "环境指纹": json指纹({"python": os.sys.version, "平台": os.uname().sysname}),
            "输出文件": {项.name: sha256(项) for 项 in 输出文件 if 项.name != "清单.json"},
            "成员顺序": "成员.csv文件顺序；本批次为空",
            "完成时间": datetime.now(timezone.utc).isoformat(),
        })
        return 目标
    finally:
        shutil.rmtree(临时父, ignore_errors=False)


def main() -> int:
    解析器 = argparse.ArgumentParser(description=__doc__)
    根 = Path(__file__).resolve().parents[2]
    解析器.add_argument("--试点", type=Path, default=根 / "artifacts/数据/最小闭环试点" / 批次目录名)
    解析器.add_argument("--配置", type=Path, default=根 / "config/审计/双标的容量恢复.json")
    解析器.add_argument("--输出根", type=Path, default=根 / "artifacts/审计/容量恢复")
    解析器.add_argument("--最小可用字节数", type=int, default=10 * 1024 * 1024)
    参数 = 解析器.parse_args()
    try:
        输出 = 执行(参数.试点, 参数.配置, 参数.输出根, 参数.最小可用字节数)
    except (合同错误, OSError) as 异常:
        print(f"执行失败：{异常}")
        return 2
    print(f"输出批次：{输出}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
