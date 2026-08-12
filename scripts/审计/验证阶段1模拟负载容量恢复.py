#!/usr/bin/env python3
"""任务-000104：验证最终模拟研究负载容量与文件级隔离恢复。"""

from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import resource
import shutil
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence
from itertools import product


版本 = "stage1-simulated-load-capacity-recovery-1.0"
任务相对路径 = Path("docs/研发中心/任务/任务-000104.md")
配置相对路径 = Path("config/审计/任务-000104容量恢复.json")
正式输出相对根 = Path("artifacts/审计/阶段1模拟负载容量恢复")
批次格式 = re.compile(r"^stage1-simulated-load-recovery-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
SHA格式 = re.compile(r"^[0-9a-f]{64}$")


class 合同错误(ValueError):
    """任务合同或安全边界不满足。"""


def _加载原子发布模块() -> Any:
    路径 = Path(__file__).resolve().parents[1] / "数据" / "验证阶段1成本执行.py"
    规格 = importlib.util.spec_from_file_location("task104_publish_base", 路径)
    if 规格 is None or 规格.loader is None:
        raise RuntimeError("PUBLISH_MODULE_UNAVAILABLE")
    模块 = importlib.util.module_from_spec(规格)
    规格.loader.exec_module(模块)
    return 模块


发布模块 = _加载原子发布模块()


def _加载任务103验证器() -> Any:
    路径 = Path(__file__).resolve().parents[1] / "模拟交易" / "验证阶段1委托生命周期.py"
    规格 = importlib.util.spec_from_file_location("task104_source_validator", 路径)
    if 规格 is None or 规格.loader is None:
        raise RuntimeError("SOURCE_VALIDATOR_UNAVAILABLE")
    模块 = importlib.util.module_from_spec(规格)
    规格.loader.exec_module(模块)
    return 模块


任务103验证器 = _加载任务103验证器()
任务103配置相对路径 = Path("config/模拟交易/任务-000103阶段1委托生命周期.json")


def 规范字节(值: Any) -> bytes:
    return (
        json.dumps(值, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def UTC现在() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _解析时间(值: Any) -> dt.datetime:
    if not isinstance(值, str):
        raise 合同错误("TIMELINE_INVALID")
    try:
        时间 = dt.datetime.fromisoformat(值.replace("Z", "+00:00"))
    except ValueError as 异常:
        raise 合同错误("TIMELINE_INVALID") from 异常
    if 时间.tzinfo is None or 时间.utcoffset() is None:
        raise 合同错误("TIMELINE_INVALID")
    return 时间


def JSON指纹(值: Any) -> str:
    return hashlib.sha256(规范字节(值)).hexdigest()


def 文件SHA256(路径: Path) -> str:
    if 路径.is_symlink() or not 路径.is_file():
        raise 合同错误("NON_REGULAR_FILE")
    摘要 = hashlib.sha256()
    with 路径.open("rb") as 文件:
        while 块 := 文件.read(1024 * 1024):
            摘要.update(块)
    return 摘要.hexdigest()


def 读取JSON(路径: Path) -> dict[str, Any]:
    if 路径.is_symlink() or not 路径.is_file():
        raise 合同错误("NON_REGULAR_FILE")
    try:
        值 = json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as 异常:
        raise 合同错误("JSON_INVALID") from 异常
    if not isinstance(值, dict):
        raise 合同错误("JSON_INVALID")
    return 值


def 写JSON专用(路径: Path, 值: Any) -> None:
    数据 = 规范字节(值)
    路径.parent.mkdir(parents=True, exist_ok=True)
    描述符 = os.open(路径, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(描述符, "wb", closefd=False) as 文件:
            文件.write(数据)
            文件.flush()
            os.fsync(文件.fileno())
    finally:
        os.close(描述符)


def 验证配置(配置: Mapping[str, Any]) -> None:
    if set(配置) != {
        "合同版本", "任务编号", "来源批次", "来源相对目录", "来源清单SHA256",
        "来源摘要SHA256", "生命周期结果SHA256", "负载倍数", "预期计数", "资源上限",
    }:
        raise 合同错误("CONFIG_INVALID")
    if 配置.get("合同版本") != 版本 or 配置.get("任务编号") != "任务-000104":
        raise 合同错误("CONFIG_INVALID")
    if 配置.get("负载倍数") != [1, 2, 4]:
        raise 合同错误("CONFIG_INVALID")
    if 配置.get("预期计数") != {
        "BTCUSDT": 256,
        "ETHUSDT": 256,
        "成员": 512,
        "生命周期事件": 6144,
        "分组": 1056,
        "清单内容文件": 10,
    }:
        raise 合同错误("CONFIG_INVALID")
    上限 = 配置.get("资源上限")
    if 上限 != {
        "RSS字节": 268435456,
        "临时副本字节": 67108864,
        "输出字节": 16777216,
        "总时限秒": 600,
        "最小可用磁盘字节": 5368709120,
        "最小可用内存比例": 20,
    }:
        raise 合同错误("CONFIG_INVALID")
    for 字段 in ("来源清单SHA256", "来源摘要SHA256", "生命周期结果SHA256"):
        if not isinstance(配置.get(字段), str) or SHA格式.fullmatch(配置[字段]) is None:
            raise 合同错误("CONFIG_INVALID")


def _普通文件事实(路径: Path) -> dict[str, Any]:
    try:
        信息 = 路径.lstat()
    except OSError as 异常:
        raise 合同错误("FILE_MISSING") from 异常
    if not stat.S_ISREG(信息.st_mode) or 路径.is_symlink() or 信息.st_nlink != 1:
        raise 合同错误("NON_REGULAR_FILE")
    return {"bytes": 信息.st_size, "sha256": 文件SHA256(路径)}


def _流式生命周期重建(冻结输入: Mapping[str, Any]) -> dict[str, Any]:
    成员 = 冻结输入.get("members")
    if not isinstance(成员, list):
        raise 合同错误("FROZEN_MEMBERS_REQUIRED")
    任务103验证器.validate_member_order(成员)
    场景组合 = tuple(product(
        ("做多", "做空"),
        ("进取型市价", "进取型限价", "被动限价撤销"),
        ("基准", "压力"),
    ))
    计数: dict[tuple[str, str, str, str, str], Counter[str]] = {}
    终态 = Counter()
    for 标的, 方向, 场景, 时钟 in product(
        ("BTCUSDT", "ETHUSDT"),
        ("做多", "做空"),
        ("进取型市价", "进取型限价", "被动限价撤销"),
        ("基准", "压力"),
    ):
        for 阶段 in ("created", "sent", "acknowledged", "evaluated", "terminal"):
            计数[(标的, 方向, 场景, 时钟, 阶段)] = Counter()
    for 行 in 成员:
        for 方向, 场景, 时钟 in 场景组合:
            结果 = 任务103验证器.simulate_member(行, 场景, 方向, 时钟)
            终态[结果["terminal_state"]] += 1
            事件状态 = {事件["state"] for 事件 in 结果["events"]}
            for 阶段 in ("created", "sent", "acknowledged", "evaluated"):
                计数[(行["symbol"], 方向, 场景, 时钟, 阶段)][
                    阶段 if 阶段 in 事件状态 else "unknown"
                ] += 1
            计数[(行["symbol"], 方向, 场景, 时钟, "terminal")][结果["terminal_state"]] += 1
    分组 = []
    阶段状态 = (
        ("created", ("created", "unknown")),
        ("sent", ("sent", "unknown")),
        ("acknowledged", ("acknowledged", "unknown")),
        ("evaluated", ("evaluated", "unknown")),
        ("terminal", ("filled", "canceled", "unknown")),
    )
    全状态 = ("created", "sent", "acknowledged", "evaluated", "filled", "canceled", "unknown")
    分母 = Counter(行["symbol"] for 行 in 成员)
    for 标的, 方向, 场景, 时钟, 尺度 in product(
        ("BTCUSDT", "ETHUSDT"),
        ("做多", "做空"),
        ("进取型市价", "进取型限价", "被动限价撤销"),
        ("基准", "压力"),
        ("主研究尺度：4小时", "主研究尺度：8小时", "主研究尺度：24小时", "主研究尺度：48小时"),
    ):
        for 阶段, 结果状态组 in 阶段状态:
            阶段计数 = 计数[(标的, 方向, 场景, 时钟, 阶段)]
            for 结果状态 in 结果状态组:
                状态计数 = {状态: 阶段计数[状态] if 状态 == 结果状态 else 0 for 状态 in 全状态}
                分组.append({
                    "symbol": 标的,
                    "venue": "Binance",
                    "market": "USDⓈ-M永续合约",
                    "contract": f"{标的}永续合约",
                    "direction": 方向,
                    "stage": 阶段,
                    "scenario": 场景,
                    "clock": 时钟,
                    "horizon": 尺度,
                    "result_status": 结果状态,
                    "candidate": 分母[标的],
                    "observed": 阶段计数[结果状态],
                    "state_counts": 状态计数,
                    "filled": 状态计数["filled"],
                    "canceled": 状态计数["canceled"],
                    "unknown": 状态计数["unknown"],
                    "failed": 0,
                    "immature": 0,
                    "invalid": 0,
                })
    摘要 = hashlib.sha256()
    冻结SHA = hashlib.sha256(规范字节(冻结输入)).hexdigest()
    摘要.update(b'{"frozen_input_sha256":')
    摘要.update(json.dumps(冻结SHA, ensure_ascii=False).encode("utf-8"))
    摘要.update(b',"groups":')
    摘要.update(json.dumps(分组, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    摘要.update(b',"member_count":')
    摘要.update(str(len(成员)).encode("ascii"))
    摘要.update(b',"results":[')
    首个 = True
    for 行 in 成员:
        for 方向, 场景, 时钟 in 场景组合:
            if not 首个:
                摘要.update(b",")
            首个 = False
            结果 = 任务103验证器.simulate_member(行, 场景, 方向, 时钟)
            摘要.update(json.dumps(结果, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    场景数 = len(成员) * len(场景组合)
    摘要.update(b'],"scenario_count":')
    摘要.update(str(场景数).encode("ascii"))
    摘要.update(b',"schema_version":"zhishi-simulated-order-lifecycle-result/v1","terminal_counts":')
    摘要.update(json.dumps(dict(sorted(终态.items())), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    摘要.update(b"}\n")
    return {
        "sha256": 摘要.hexdigest(),
        "member_count": len(成员),
        "scenario_count": 场景数,
        "group_count": len(分组),
        "terminal_counts": dict(sorted(终态.items())),
    }


def _来源规范事实(目录: Path, 配置: Mapping[str, Any]) -> dict[str, Any]:
    清单 = 读取JSON(目录 / "manifest.json")
    文件声明 = 清单.get("files")
    if not isinstance(文件声明, dict) or len(文件声明) != 配置["预期计数"]["清单内容文件"]:
        raise 合同错误("MANIFEST_INVALID")
    if (
        清单.get("batch_id") != 配置["来源批次"]
        or 文件SHA256(目录 / "manifest.json") != 配置["来源清单SHA256"]
        or 清单.get("file_count") != len(文件声明)
        or 清单.get("manifest_payload_sha256") != JSON指纹(文件声明)
    ):
        raise 合同错误("MANIFEST_INVALID")
    预期名称 = set(文件声明) | {"manifest.json"}
    实际条目 = list(目录.iterdir())
    if {项.name for 项 in 实际条目} != 预期名称:
        raise 合同错误("FILE_SET_DRIFT")
    全部文件: dict[str, dict[str, Any]] = {}
    for 名称 in sorted(预期名称):
        事实 = _普通文件事实(目录 / 名称)
        if 名称 != "manifest.json":
            声明 = 文件声明.get(名称)
            if not isinstance(声明, dict) or 声明 != 事实:
                raise 合同错误("FILE_DRIFT")
        全部文件[名称] = 事实
    if 清单.get("total_bytes") != sum(全部文件[名]["bytes"] for 名 in 文件声明):
        raise 合同错误("MANIFEST_INVALID")

    摘要 = 读取JSON(目录 / "summary.json")
    冻结输入 = 读取JSON(目录 / "frozen-input.json")
    回放一 = 读取JSON(目录 / "replay-1.json")
    回放二 = 读取JSON(目录 / "replay-2.json")
    仓库根 = Path(__file__).resolve().parents[2]
    任务103配置 = 任务103验证器.read_json(仓库根 / 任务103配置相对路径)
    任务103验证器.validate_config(任务103配置)
    任务103验证器._validate_published_bindings(
        directory=目录,
        intent=任务103验证器.read_json(目录 / "intent.json"),
        config=任务103配置,
    )
    重算证据 = _流式生命周期重建(冻结输入)
    if (
        文件SHA256(目录 / "summary.json") != 配置["来源摘要SHA256"]
        or 文件SHA256(目录 / "lifecycle.json") != 配置["生命周期结果SHA256"]
        or 摘要.get("lifecycle_result_sha256") != 配置["生命周期结果SHA256"]
        or 回放一.get("result_sha256") != 配置["生命周期结果SHA256"]
        or 回放二.get("result_sha256") != 配置["生命周期结果SHA256"]
        or 重算证据.get("sha256") != 配置["生命周期结果SHA256"]
        or 回放一.get("matches_initial") is not True
        or 回放二.get("matches_initial") is not True
    ):
        raise 合同错误("REPLAY_OR_RESULT_DRIFT")
    按标的 = 冻结输入.get("denominators")
    if (
        按标的 != {"BTCUSDT": 256, "ETHUSDT": 256}
        or 冻结输入.get("member_count") != 配置["预期计数"]["成员"]
        or 摘要.get("member_count") != 配置["预期计数"]["成员"]
        or 重算证据.get("member_count") != 配置["预期计数"]["成员"]
        or 重算证据.get("scenario_count") != 配置["预期计数"]["生命周期事件"]
        or 重算证据.get("group_count") != 配置["预期计数"]["分组"]
    ):
        raise 合同错误("SEMANTIC_COUNT_DRIFT")
    安全 = 摘要.get("safety")
    if not isinstance(安全, dict) or any(安全.values()):
        raise 合同错误("SAFETY_FACT_DRIFT")
    规范事实 = {
        "来源批次": 配置["来源批次"],
        "清单SHA256": 全部文件["manifest.json"]["sha256"],
        "摘要SHA256": 全部文件["summary.json"]["sha256"],
        "生命周期结果SHA256": 全部文件["lifecycle.json"]["sha256"],
        "内容文件数": len(文件声明),
        "总文件数": len(全部文件),
        "内容总字节": 清单["total_bytes"],
        "总读取字节": sum(项["bytes"] for 项 in 全部文件.values()),
        "成员数": 配置["预期计数"]["成员"],
        "按标的成员": 按标的,
        "生命周期事件数": 重算证据["scenario_count"],
        "分组数": 重算证据["group_count"],
        "文件": 全部文件,
        "安全": 安全,
    }
    规范事实["结果指纹"] = JSON指纹(规范事实)
    return 规范事实


def 验证来源批次(目录: Path, 配置: Mapping[str, Any], *, 限制正式路径: bool = True) -> dict[str, Any]:
    验证配置(配置)
    目录 = 目录.resolve(strict=True)
    if 限制正式路径:
        仓库根 = Path(__file__).resolve().parents[2]
        预期 = (仓库根 / 配置["来源相对目录"]).resolve(strict=True)
        if 目录 != 预期:
            raise 合同错误("SOURCE_PATH_INVALID")
    return _来源规范事实(目录, 配置)


def _峰值RSS字节() -> int:
    值 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(值 if sys.platform == "darwin" else 值 * 1024)


def _内存可用比例() -> float:
    if sys.platform == "darwin":
        import subprocess

        文本 = subprocess.check_output(["vm_stat"], text=True, timeout=5)
        页 = int(re.search(r"page size of ([0-9]+) bytes", 文本).group(1))
        值 = {键: int(数字.replace(".", "")) for 键, 数字 in re.findall(r"^([^:]+):\s+([0-9.]+)\.$", 文本, re.M)}
        可用 = sum(值.get(键, 0) for 键 in ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable")) * 页
        总量 = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=5))
        return round(可用 / 总量 * 100, 2)
    信息 = {}
    for 行 in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        键, 值 = 行.split(":", 1)
        信息[键] = int(值.strip().split()[0]) * 1024
    return round(信息["MemAvailable"] / 信息["MemTotal"] * 100, 2)


def 检查资源(路径: Path, 配置: Mapping[str, Any], 开始: float) -> dict[str, Any]:
    上限 = 配置["资源上限"]
    磁盘 = shutil.disk_usage(路径).free
    内存比例 = _内存可用比例()
    RSS = _峰值RSS字节()
    耗时 = time.monotonic() - 开始
    if 磁盘 < 上限["最小可用磁盘字节"]:
        raise 合同错误("DISK_LIMIT_EXCEEDED")
    if 内存比例 < 上限["最小可用内存比例"]:
        raise 合同错误("MEMORY_AVAILABLE_LIMIT_EXCEEDED")
    if RSS <= 0 or RSS > 上限["RSS字节"]:
        raise 合同错误("RSS_LIMIT_EXCEEDED")
    if 耗时 > 上限["总时限秒"]:
        raise 合同错误("TIME_LIMIT_EXCEEDED")
    return {"可用磁盘字节": 磁盘, "可用内存比例": 内存比例, "峰值RSS字节": RSS, "累计耗时秒": round(耗时, 6)}


def 测量负载(来源: Path, 配置: Mapping[str, Any], 倍数列表: Sequence[int] | None = None) -> list[dict[str, Any]]:
    倍数列表 = list(配置["负载倍数"] if 倍数列表 is None else 倍数列表)
    if any(倍数 not in (1, 2, 4) for 倍数 in 倍数列表):
        raise 合同错误("LOAD_MULTIPLIER_INVALID")
    结果 = []
    基准指纹 = None
    for 倍数 in 倍数列表:
        开始UTC = UTC现在()
        开始 = time.monotonic_ns()
        末次 = None
        for _ in range(倍数):
            末次 = 验证来源批次(来源, 配置)
        assert 末次 is not None
        耗时 = max((time.monotonic_ns() - 开始) / 1_000_000_000, 0.000001)
        if 基准指纹 is None:
            基准指纹 = 末次["结果指纹"]
        if 末次["结果指纹"] != 基准指纹:
            raise 合同错误("LOAD_RESULT_DRIFT")
        处理字节 = 末次["总读取字节"] * 倍数
        结果.append({
            "倍数": 倍数,
            "重复语义": "同一不可变负载串行重复，不新增市场样本",
            "正式成员分母": 末次["成员数"],
            "处理成员次数": 末次["成员数"] * 倍数,
            "处理生命周期事件次数": 末次["生命周期事件数"] * 倍数,
            "处理字节": 处理字节,
            "耗时秒": round(耗时, 6),
            "开始时间": 开始UTC,
            "完成时间": UTC现在(),
            "吞吐字节每秒": round(处理字节 / 耗时, 3),
            "峰值RSS字节": _峰值RSS字节(),
            "结果指纹": 末次["结果指纹"],
        })
    return 结果


def _复制普通文件集(来源: Path, 目标: Path, 文件名: Sequence[str], 字节上限: int) -> int:
    目标.mkdir()
    总数 = 0
    for 名称 in 文件名:
        if Path(名称).name != 名称 or 名称 in ("", ".", ".."):
            raise 合同错误("PATH_ESCAPE")
        事实前 = _普通文件事实(来源 / 名称)
        总数 += 事实前["bytes"]
        if 总数 > 字节上限:
            raise 合同错误("TEMP_COPY_LIMIT_EXCEEDED")
        shutil.copyfile(来源 / 名称, 目标 / 名称)
        if _普通文件事实(来源 / 名称) != 事实前 or _普通文件事实(目标 / 名称) != 事实前:
            raise 合同错误("COPY_DRIFT")
    return 总数


def 创建安全工作目录(父目录: Path) -> tuple[Path, str]:
    父目录 = 父目录.resolve(strict=True)
    工作目录 = Path(tempfile.mkdtemp(prefix="zhishi-task000104-", dir=父目录))
    标识 = uuid.uuid4().hex
    写JSON专用(工作目录 / ".task-000104-sentinel", {"task": "000104", "id": 标识})
    return 工作目录, 标识


def 安全清理(工作目录: Path, 父目录: Path, 标识: str) -> None:
    父解析 = 父目录.resolve(strict=True)
    工作解析 = 工作目录.resolve(strict=True)
    try:
        工作解析.relative_to(父解析)
    except ValueError as 异常:
        raise 合同错误("CLEANUP_SCOPE_INVALID") from 异常
    if not 工作解析.name.startswith("zhishi-task000104-"):
        raise 合同错误("CLEANUP_SCOPE_INVALID")
    哨兵 = 读取JSON(工作解析 / ".task-000104-sentinel")
    if 哨兵 != {"task": "000104", "id": 标识}:
        raise 合同错误("CLEANUP_SENTINEL_INVALID")
    shutil.rmtree(工作解析)
    if 工作目录.exists():
        raise 合同错误("CLEANUP_FAILED")


def 隔离恢复演练(来源: Path, 配置: Mapping[str, Any], 临时父: Path, *, 自动清理: bool = True) -> dict[str, Any]:
    源事实 = 验证来源批次(来源, 配置)
    文件名 = sorted(源事实["文件"])
    工作, 标识 = 创建安全工作目录(临时父)
    try:
        单份上限 = 配置["资源上限"]["临时副本字节"] // 3
        备份字节 = _复制普通文件集(来源, 工作 / "backup", 文件名, 单份上限)
        _复制普通文件集(工作 / "backup", 工作 / "fault", 文件名, 单份上限)
        with (工作 / "fault" / "summary.json").open("ab") as 文件:
            文件.write(b"fault")
        故障已检测 = False
        try:
            验证来源批次(工作 / "fault", 配置, 限制正式路径=False)
        except 合同错误:
            故障已检测 = True
        if not 故障已检测:
            raise 合同错误("FAULT_NOT_DETECTED")
        恢复字节 = _复制普通文件集(工作 / "backup", 工作 / "restore", 文件名, 单份上限)
        恢复事实 = 验证来源批次(工作 / "restore", 配置, 限制正式路径=False)
        if 恢复事实["结果指纹"] != 源事实["结果指纹"]:
            raise 合同错误("RESTORE_SEMANTIC_DRIFT")
        结果 = {
            "故障已检测": True,
            "故障类型": "一次性副本summary.json字节追加",
            "源批次未修改": 验证来源批次(来源, 配置)["结果指纹"] == 源事实["结果指纹"],
            "恢复逐文件一致": 恢复事实["文件"] == 源事实["文件"],
            "恢复总文件数": 恢复事实["总文件数"],
            "备份字节": 备份字节,
            "恢复字节": 恢复字节,
            "恢复语义": {键: 恢复事实[键] for 键 in ("成员数", "按标的成员", "生命周期事件数", "分组数", "结果指纹")},
            "工作目录已清理": False,
        }
        if not all((结果["源批次未修改"], 结果["恢复逐文件一致"])):
            raise 合同错误("RESTORE_FILE_DRIFT")
        if 自动清理:
            安全清理(工作, 临时父, 标识)
            结果["工作目录已清理"] = not 工作.exists()
        else:
            结果["工作目录身份"] = 标识
            结果["工作目录对象"] = 工作
        return 结果
    except Exception:
        if 工作.exists():
            安全清理(工作, 临时父, 标识)
        raise


def _任务合同指纹(路径: Path) -> str:
    易变前缀 = ("- 状态：", "- 执行分支：", "- 开始时间：", "- 提交SHA：", "- 实现提交SHA：", "- Pull Request：", "- 合并时间：", "- 合并提交SHA：")
    行 = 路径.read_text(encoding="utf-8").splitlines()
    截止 = next((序号 for 序号, 内容 in enumerate(行) if 内容 == "## 执行记录"), len(行))
    稳定 = [内容 for 内容 in 行[:截止] if not 内容.startswith(易变前缀)]
    while 稳定 and not 稳定[-1]:
        稳定.pop()
    return hashlib.sha256(("\n".join(稳定) + "\n").encode("utf-8")).hexdigest()


def 验证已发布批次(
    目录: Path,
    配置: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, Any]:
    验证配置(配置)
    if 批次格式.fullmatch(目录.name) is None or 目录.is_symlink() or not 目录.is_dir():
        raise 合同错误("PUBLISHED_BATCH_INVALID")
    条目 = list(目录.iterdir())
    if {路径.name for 路径 in 条目} != {"intent.json", "measurements.json", "recovery.json", "summary.json", "manifest.json"}:
        raise 合同错误("PUBLISHED_FILE_SET_DRIFT")
    清单 = 读取JSON(目录 / "manifest.json")
    声明 = 清单.get("files")
    if (
        清单.get("schema_version") != "zhishi-stage1-load-capacity-recovery-manifest/v1"
        or 清单.get("batch_id") != 目录.name
        or not isinstance(声明, dict)
        or set(声明) != {"intent.json", "measurements.json", "recovery.json", "summary.json"}
        or 清单.get("file_count") != 4
        or 清单.get("manifest_payload_sha256") != JSON指纹(声明)
    ):
        raise 合同错误("PUBLISHED_MANIFEST_INVALID")
    for 名称, 预期 in 声明.items():
        if _普通文件事实(目录 / 名称) != 预期:
            raise 合同错误("PUBLISHED_FILE_DRIFT")
    if 清单.get("total_bytes") != sum(项["bytes"] for 项 in 声明.values()):
        raise 合同错误("PUBLISHED_MANIFEST_INVALID")
    意图 = 读取JSON(目录 / "intent.json")
    测量 = 读取JSON(目录 / "measurements.json")
    恢复 = 读取JSON(目录 / "recovery.json")
    摘要 = 读取JSON(目录 / "summary.json")
    if repo_root is not None or config_path is not None:
        if repo_root is None or config_path is None:
            raise 合同错误("DELIVERY_BINDING_DRIFT")
        if (
            意图.get("config_sha256") != 文件SHA256(config_path)
            or 意图.get("executor_sha256") != 文件SHA256(Path(__file__))
            or 意图.get("task_contract_sha256") != _任务合同指纹(repo_root / 任务相对路径)
        ):
            raise 合同错误("DELIVERY_BINDING_DRIFT")
    档位 = 测量.get("profiles")
    if isinstance(档位, list):
        预备时间 = _解析时间(意图.get("prepared_at"))
        上一完成 = 预备时间
        for 项 in 档位:
            if not isinstance(项, dict):
                raise 合同错误("TIMELINE_INVALID")
            开始时间 = _解析时间(项.get("开始时间"))
            完成时间 = _解析时间(项.get("完成时间"))
            if 开始时间 < 上一完成 or 完成时间 < 开始时间:
                raise 合同错误("TIMELINE_INVALID")
            上一完成 = 完成时间
        清理时间 = _解析时间(恢复.get("清理完成时间"))
        发布时间 = _解析时间(清单.get("published_at"))
        if 清理时间 < 上一完成 or 发布时间 < 清理时间:
            raise 合同错误("TIMELINE_INVALID")
    if (
        意图.get("batch_id") != 目录.name
        or 意图.get("source_batch") != 配置["来源批次"]
        or 意图.get("load_multipliers") != [1, 2, 4]
        or 意图.get("source_fingerprints")
        != {
            "manifest_sha256": 配置["来源清单SHA256"],
            "summary_sha256": 配置["来源摘要SHA256"],
            "lifecycle_sha256": 配置["生命周期结果SHA256"],
        }
        or not isinstance(档位, list)
        or [项.get("倍数") for 项 in 档位] != [1, 2, 4]
        or len({项.get("结果指纹") for 项 in 档位}) != 1
        or any(项.get("正式成员分母") != 512 for 项 in 档位)
        or 恢复.get("故障已检测") is not True
        or 恢复.get("恢复逐文件一致") is not True
        or 恢复.get("工作目录已清理") is not True
        or 恢复.get("任务临时根无残留") is not True
        or 摘要.get("source_member_denominator") != 512
        or 摘要.get("cleanup_completed_before_publish") is not True
        or 摘要.get("stage1_complete") is not False
        or 摘要.get("stage2_released") is not False
    ):
        raise 合同错误("PUBLISHED_SEMANTIC_DRIFT")
    if any(摘要.get("safety", {}).values()):
        raise 合同错误("PUBLISHED_SAFETY_DRIFT")
    return {
        "批次": 目录.name,
        "清单SHA256": 文件SHA256(目录 / "manifest.json"),
        "摘要SHA256": 文件SHA256(目录 / "summary.json"),
        "正式成员分母": 摘要["source_member_denominator"],
        "清理早于发布": 摘要["cleanup_completed_before_publish"],
    }


def 重建发布清单仅供测试(目录: Path) -> None:
    """只供负向测试在临时目录重签文件集合，证明语义绑定不能被清单掩盖。"""
    清单路径 = 目录 / "manifest.json"
    清单 = 读取JSON(清单路径)
    文件 = {
        名称: {"bytes": (目录 / 名称).stat().st_size, "sha256": 文件SHA256(目录 / 名称)}
        for 名称 in ("intent.json", "measurements.json", "recovery.json", "summary.json")
    }
    清单["files"] = 文件
    清单["file_count"] = len(文件)
    清单["total_bytes"] = sum(项["bytes"] for 项 in 文件.values())
    清单["manifest_payload_sha256"] = JSON指纹(文件)
    清单路径.unlink()
    写JSON专用(清单路径, 清单)


def 执行正式批次(仓库根: Path, 配置路径: Path, 输出根: Path, 批次: str, *, 测试模式: bool = False) -> Path:
    开始 = time.monotonic()
    仓库根 = 仓库根.resolve(strict=True)
    配置路径 = 配置路径.resolve(strict=True)
    配置 = 读取JSON(配置路径)
    验证配置(配置)
    if 批次格式.fullmatch(批次) is None:
        raise 合同错误("BATCH_ID_INVALID")
    if not 测试模式:
        if 配置路径 != (仓库根 / 配置相对路径).resolve(strict=True):
            raise 合同错误("CONFIG_PATH_INVALID")
        if 输出根.resolve() != (仓库根 / 正式输出相对根).resolve():
            raise 合同错误("OUTPUT_PATH_INVALID")
    输出根.mkdir(parents=True, exist_ok=True)
    检查资源(输出根, 配置, 开始)
    来源 = (仓库根 / 配置["来源相对目录"]).resolve(strict=True)
    来源事实 = 验证来源批次(来源, 配置)
    意图 = {
        "schema_version": "zhishi-stage1-load-capacity-recovery-intent/v1",
        "task_id": "000104",
        "batch_id": 批次,
        "prepared_at": UTC现在(),
        "source_batch": 配置["来源批次"],
        "source_fingerprints": {
            "manifest_sha256": 配置["来源清单SHA256"],
            "summary_sha256": 配置["来源摘要SHA256"],
            "lifecycle_sha256": 配置["生命周期结果SHA256"],
        },
        "load_multipliers": 配置["负载倍数"],
        "load_semantics": "同一不可变负载串行重复，不新增市场样本",
        "config_sha256": 文件SHA256(配置路径),
        "executor_sha256": 文件SHA256(Path(__file__)),
        "task_contract_sha256": _任务合同指纹(仓库根 / 任务相对路径),
        "resource_limits": 配置["资源上限"],
        "remote_access": False,
        "database_access": False,
        "market_data_access": False,
    }
    测量 = 测量负载(来源, 配置)
    临时父 = Path(tempfile.mkdtemp(prefix="zhishi-task000104-parent-"))
    恢复 = None
    try:
        恢复 = 隔离恢复演练(来源, 配置, 临时父, 自动清理=False)
        工作 = 恢复.pop("工作目录对象")
        标识 = 恢复.pop("工作目录身份")
        安全清理(工作, 临时父, 标识)
        if any(临时父.iterdir()):
            raise 合同错误("CLEANUP_RESIDUE")
        临时父.rmdir()
        恢复["工作目录已清理"] = True
        恢复["任务临时根无残留"] = not 临时父.exists()
        恢复["清理完成时间"] = UTC现在()
    except Exception:
        if 临时父.exists() and not any(临时父.iterdir()):
            临时父.rmdir()
        raise
    if 恢复 is None or not 恢复.get("任务临时根无残留"):
        raise 合同错误("CLEANUP_FAILED")

    资源 = 检查资源(输出根, 配置, 开始)
    摘要 = {
        "schema_version": "zhishi-stage1-load-capacity-recovery-summary/v1",
        "task_id": "000104",
        "batch_id": 批次,
        "source_batch": 配置["来源批次"],
        "source_member_denominator": 来源事实["成员数"],
        "source_counts": {键: 来源事实[键] for 键 in ("成员数", "按标的成员", "生命周期事件数", "分组数")},
        "load_profiles": len(测量),
        "all_result_fingerprints_equal": len({项["结果指纹"] for 项 in 测量}) == 1,
        "fault_detected": 恢复["故障已检测"],
        "restore_file_exact": 恢复["恢复逐文件一致"],
        "cleanup_completed_before_publish": 恢复["工作目录已清理"] and 恢复["任务临时根无残留"],
        "capacity_scope": "当前512成员、6144生命周期事件、1056分组的仓库内正式负载",
        "multi_year_capacity_status": "unknown",
        "real_exchange_latency_status": "unknown",
        "production_disaster_recovery_status": "unknown",
        "stage1_complete": False,
        "stage2_released": False,
        "safety": {
            "remote_access": False,
            "database_access": False,
            "market_data_access": False,
            "source_write": False,
            "other_project_write": False,
            "model_or_backtest": False,
            "trade_decision": False,
        },
        "resource_facts": 资源,
    }
    待发布 = Path(tempfile.mkdtemp(prefix=f".{批次}-", dir=输出根))
    try:
        写JSON专用(待发布 / "intent.json", 意图)
        写JSON专用(待发布 / "measurements.json", {"schema_version": "zhishi-stage1-load-measurements/v1", "profiles": 测量})
        写JSON专用(待发布 / "recovery.json", {"schema_version": "zhishi-stage1-isolated-recovery/v1", **恢复})
        写JSON专用(待发布 / "summary.json", 摘要)
        文件 = {路径.name: {"bytes": 路径.stat().st_size, "sha256": 文件SHA256(路径)} for 路径 in sorted(待发布.iterdir())}
        if sum(项["bytes"] for 项 in 文件.values()) > 配置["资源上限"]["输出字节"]:
            raise 合同错误("OUTPUT_LIMIT_EXCEEDED")
        清单 = {
            "schema_version": "zhishi-stage1-load-capacity-recovery-manifest/v1",
            "batch_id": 批次,
            "published_at": UTC现在(),
            "file_count": len(文件),
            "total_bytes": sum(项["bytes"] for 项 in 文件.values()),
            "files": 文件,
            "manifest_payload_sha256": JSON指纹(文件),
        }
        写JSON专用(待发布 / "manifest.json", 清单)
        目标 = 输出根 / 批次
        发布模块.publish_directory_no_replace(待发布, 目标)
        验证已发布批次(目标, 配置, repo_root=仓库根, config_path=配置路径)
        return 目标
    except Exception:
        if 待发布.exists():
            shutil.rmtree(待发布)
        raise


def main() -> int:
    解析器 = argparse.ArgumentParser(description=__doc__)
    解析器.add_argument("--repo-root", type=Path, default=Path.cwd())
    解析器.add_argument("--config", type=Path, default=配置相对路径)
    解析器.add_argument("--batch", required=True)
    参数 = 解析器.parse_args()
    根 = 参数.repo_root.resolve()
    配置 = 参数.config if 参数.config.is_absolute() else 根 / 参数.config
    目标 = 执行正式批次(根, 配置, 根 / 正式输出相对根, 参数.batch)
    结果 = 验证已发布批次(目标, 读取JSON(配置), repo_root=根, config_path=配置) | {
        "status": "ok",
        "batch_id": 目标.name,
    }
    print(规范字节(结果).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (合同错误, FileExistsError, OSError, RuntimeError) as 异常:
        print(f"阶段1模拟负载容量恢复验证失败：{异常}", file=sys.stderr)
        raise SystemExit(1)
