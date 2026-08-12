#!/usr/bin/env python3
"""只读复算当前阶段1八叶子最终门禁。"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class 合同错误(ValueError):
    pass


预期配置 = Path("config/审计/任务-000105阶段1最终审计.json")
预期输出根 = Path("artifacts/审计/阶段1当前最终门禁")
必需任务 = ("000094", "000099", "000100", "000103", "000104")
门顺序 = ("来源身份", "三类时间", "质量", "血缘", "历史重放", "成本与执行", "模拟生命周期", "容量", "恢复")


def 规范JSON(值: Any) -> str:
    return json.dumps(值, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def 文件SHA256(路径: Path) -> str:
    摘要 = hashlib.sha256()
    with 路径.open("rb") as 文件:
        for 块 in iter(lambda: 文件.read(1024 * 1024), b""):
            摘要.update(块)
    return 摘要.hexdigest()


def 读取JSON(路径: Path) -> Any:
    try:
        return json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as 错误:
        raise 合同错误(f"JSON_INVALID:{路径.name}") from 错误


def 读取配置(路径: Path) -> dict[str, Any]:
    配置 = 读取JSON(路径)
    if (
        配置.get("合同版本") != "stage1-current-final-gate-1.0"
        or tuple(配置.get("正式输入", {})) != 必需任务
        or 配置.get("主研究尺度小时") != [4, 8, 24, 48]
        or 配置.get("事后观察窗口分钟") != [15, 60]
    ):
        raise 合同错误("CONFIG_INVALID")
    return 配置


def _安全输入目录(仓库: Path, 相对: str) -> Path:
    路径 = Path(相对)
    if 路径.is_absolute() or ".." in 路径.parts:
        raise 合同错误("INPUT_PATH_INVALID")
    目标 = 仓库 / 路径
    try:
        目标.resolve(strict=True).relative_to(仓库.resolve(strict=True))
    except (OSError, ValueError) as 错误:
        raise 合同错误("INPUT_PATH_INVALID") from 错误
    if not 目标.is_dir() or 目标.is_symlink():
        raise 合同错误("INPUT_PATH_INVALID")
    return 目标


def _读取固定文件(目录: Path, 名称: str, 期望SHA: str, 字节预算: list[int], 上限: int) -> Any:
    路径 = 目录 / 名称
    try:
        路径.resolve(strict=True).relative_to(目录.resolve(strict=True))
    except (OSError, ValueError) as 错误:
        raise 合同错误("INPUT_FILE_INVALID") from 错误
    if not 路径.is_file() or 路径.is_symlink() or os.stat(路径).st_nlink != 1:
        raise 合同错误("INPUT_FILE_INVALID")
    字节预算[0] += 路径.stat().st_size
    if 字节预算[0] > 上限:
        raise 合同错误("INPUT_LIMIT_EXCEEDED")
    if 文件SHA256(路径) != 期望SHA:
        raise 合同错误("INPUT_FILE_DRIFT")
    return 读取JSON(路径)


def _加载模块(路径: Path, 名称: str) -> Any:
    规格 = importlib.util.spec_from_file_location(名称, 路径)
    if 规格 is None or 规格.loader is None:
        raise 合同错误("VALIDATOR_LOAD_FAILED")
    模块 = importlib.util.module_from_spec(规格)
    规格.loader.exec_module(模块)
    return 模块


def _运行上游验证器(仓库: Path, 文档: dict[str, dict[str, Any]], 配置: Mapping[str, Any]) -> None:
    # 000094/000099的最终可信语义由任务-000099验证器复核，避免重新扫描854GB正文。
    重放 = _加载模块(仓库 / "scripts/审计/重放阶段1精确冻结点数据资格决策.py", "任务99最终验证器")
    重放配置 = 重放.load_config(仓库 / 重放.EXPECTED_CONFIG_RELATIVE_PATH)
    批次根 = 仓库 / 配置["正式输入"]["000099"]["目录"]
    意图 = 重放.load_json_strict(批次根 / "intent" / "intent.json")
    决策 = 文档["000099"]["文件"]["decision/decision.json"]
    重放1 = 文档["000099"]["文件"]["replay-1/replay.json"]
    重放2 = 文档["000099"]["文件"]["replay-2/replay.json"]
    意图SHA = 重放.sha256_file(批次根 / "intent" / "intent.json")
    决策SHA = 重放.sha256_file(批次根 / "decision" / "decision.json")
    重放._validate_summary(
        文档["000094"]["文件"]["summary.json"], 重放配置
    )
    重放._validate_intent_identity(仓库, 文档["000099"]["批次"], 意图, 重放配置)
    重放._validate_decision_identity(文档["000099"]["批次"], 决策, 意图, 意图SHA)
    重放._validate_replay_identity(文档["000099"]["批次"], 重放1, 1, 意图, 意图SHA, 决策, 决策SHA)
    重放._validate_replay_identity(文档["000099"]["批次"], 重放2, 2, 意图, 意图SHA, 决策, 决策SHA)
    文档["000094"]["验证器状态"] = "通过"
    文档["000099"]["验证器状态"] = "通过"

    成本 = _加载模块(仓库 / "scripts/数据/验证阶段1成本执行.py", "任务100最终验证器")
    成本.validate_batch(仓库, 文档["000100"]["批次"])
    文档["000100"]["验证器状态"] = "通过"

    生命周期 = _加载模块(仓库 / "scripts/模拟交易/验证阶段1委托生命周期.py", "任务103最终验证器")
    生命周期.validate_batch(仓库, 文档["000103"]["批次"])
    文档["000103"]["验证器状态"] = "通过"

    容量 = _加载模块(仓库 / "scripts/审计/验证阶段1模拟负载容量恢复.py", "任务104最终验证器")
    容量配置路径 = 仓库 / "config/审计/任务-000104容量恢复.json"
    容量.验证已发布批次(
        仓库 / 配置["正式输入"]["000104"]["目录"],
        容量.读取JSON(容量配置路径), repo_root=仓库, config_path=容量配置路径,
    )
    文档["000104"]["验证器状态"] = "通过"


def 验证正式输入(仓库: Path, 配置: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    仓库 = 仓库.resolve(strict=True)
    预算 = [0]
    上限 = int(配置["资源上限"]["输入字节"])
    文档: dict[str, dict[str, Any]] = {}
    for 任务 in 必需任务:
        声明 = 配置["正式输入"][任务]
        目录 = _安全输入目录(仓库, str(声明["目录"]))
        文件 = {
            名称: _读取固定文件(目录, 名称, 指纹, 预算, 上限)
            for 名称, 指纹 in 声明["文件指纹"].items()
        }
        文档[任务] = {"目录": str(目录.relative_to(仓库)), "批次": 声明["批次"], "文件": 文件}

    时间摘要 = 文档["000094"]["文件"]["summary.json"]
    决策 = 文档["000099"]["文件"]["decision/decision.json"]
    重放1 = 文档["000099"]["文件"]["replay-1/replay.json"]
    重放2 = 文档["000099"]["文件"]["replay-2/replay.json"]
    成本 = 文档["000100"]["文件"]["summary.json"]
    生命周期 = 文档["000103"]["文件"]["summary.json"]
    容量 = 文档["000104"]["文件"]["summary.json"]
    if 时间摘要.get("formal_member_count") != 5180 or 时间摘要.get("leaf_count") != 8:
        raise 合同错误("TIME_QUALITY_SEMANTICS_DRIFT")
    结果SHA = 配置["正式输入"]["000099"]["结果指纹"]
    if any(项.get("result_sha256") != 结果SHA for 项 in (决策, 重放1, 重放2)):
        raise 合同错误("REPLAY_RESULT_DRIFT")
    if 规范JSON(决策.get("result")) != 规范JSON(重放1.get("result")) or 规范JSON(决策.get("result")) != 规范JSON(重放2.get("result")):
        raise 合同错误("REPLAY_RESULT_DRIFT")
    if 成本.get("candidate_group_count") != 32 or 成本.get("cost_execution_gate") != "无法判定":
        raise 合同错误("COST_EXECUTION_SEMANTICS_DRIFT")
    if (
        生命周期.get("member_count") != 512
        or 生命周期.get("lifecycle_result_sha256") != 配置["正式输入"]["000103"]["生命周期指纹"]
        or not 生命周期.get("simulation_lifecycle_runnable")
    ):
        raise 合同错误("LIFECYCLE_SEMANTICS_DRIFT")
    if not all(容量.get(键) for 键 in ("all_result_fingerprints_equal", "restore_file_exact", "fault_detected", "cleanup_completed_before_publish")):
        raise 合同错误("CAPACITY_RECOVERY_SEMANTICS_DRIFT")
    try:
        _运行上游验证器(仓库, 文档, 配置)
    except 合同错误:
        raise
    except Exception as 错误:
        raise 合同错误(f"UPSTREAM_VALIDATOR_FAILED:{type(错误).__name__}") from 错误
    文档["000094"]["正式成员数"] = 5180
    文档["000099"]["正式成员数"] = 5180
    文档["000103"]["模拟成员数"] = 512
    return 文档


def _门(状态: str, 原因码: str, 证据: list[str], 解除条件: str) -> dict[str, Any]:
    return {"status": 状态, "reason_code": 原因码, "evidence_refs": 证据, "release_conditions": [解除条件]}


def 生成裁决(事实: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    决策结果 = 事实["000099"]["文件"]["decision/decision.json"]["result"]
    基础叶子 = {(项["underlying"], 项["horizon_hours"]): 项 for 项 in 决策结果["leaves"]}
    叶子们 = []
    for 标的 in ("BTC", "ETH"):
        for 尺度 in (4, 8, 24, 48):
            上游 = 基础叶子[(标的, 尺度)]
            上游门 = 上游["gates"]
            门 = {
                "来源身份": 上游门["来源身份"],
                "三类时间": 上游门["三类时间"],
                "质量": 上游门["质量"],
                "血缘": 上游门["血缘"],
                "历史重放": 上游门["历史重放"],
                "成本与执行": _门(
                    "无法判定", "COST_EXECUTION_COVERAGE_INCOMPLETE",
                    ["task-000100/summary.json#/cost_execution_gate", "task-000103/summary.json#/multi_year_cost_status", "task-000103/summary.json#/real_exchange_latency_status"],
                    "按BTCUSDT、ETHUSDT及四个主研究尺度补齐多年手续费、资金费率、价差、深度、冲击和真实执行延迟的同版本覆盖证据",
                ),
                "模拟生命周期": _门(
                    "通过", "SIMULATED_LIFECYCLE_REPLAYED",
                    ["task-000103/summary.json#/lifecycle_result_sha256"],
                    "版本化模拟生命周期及两次重放持续全等",
                ),
                "容量": _门(
                    "通过", "CURRENT_SIMULATED_LOAD_CAPACITY_PROVEN",
                    ["task-000104/summary.json#/all_result_fingerprints_equal"],
                    "当前512成员正式模拟负载变化时重新冻结容量证据",
                ),
                "恢复": _门(
                    "通过", "REPOSITORY_EVIDENCE_RECOVERY_PROVEN",
                    ["task-000104/summary.json#/restore_file_exact", "task-000104/summary.json#/fault_detected"],
                    "仓库正式证据集合变化时重新执行隔离恢复演练",
                ),
            }
            if tuple(门) != 门顺序:
                raise 合同错误("GATE_ORDER_INVALID")
            叶子们.append({
                "underlying": 标的,
                "venue": "Binance",
                "market_type": "USDⓈ-M合约",
                "horizon_hours": 尺度,
                "post_event_observation_minutes": [15, 60],
                "formal_member_count": 2937 if 标的 == "BTC" else 2243,
                "simulated_member_count": 256,
                "gates": 门,
                "decision": "通过" if all(值["status"] == "通过" for 值 in 门.values()) else "阻塞",
            })
    完成 = all(项["decision"] == "通过" for 项 in 叶子们)
    缺口 = {
        "gap_id": "ZS-DATA-GAP-008",
        "priority": "P0",
        "reason_code": "COST_EXECUTION_COVERAGE_INCOMPLETE",
        "title": "多年成本与真实执行延迟同版本覆盖不足",
        "affected_leaf_count": 8,
        "release_condition": "按双标的、四个主研究尺度补齐多年手续费、资金费率、价差、深度、冲击和真实执行延迟的版本化证据；不得用模拟延迟或短期快照替代",
    }
    return {
        "schema_version": "zhishi-stage1-current-final-gate-result/v1",
        "formal_member_count": 5180,
        "quality_proved_count": 4789,
        "quality_rejected_count": 391,
        "simulated_member_count": 512,
        "leaf_count": len(叶子们),
        "allowed_research_leaf_count": sum(项["decision"] == "通过" for 项 in 叶子们),
        "leaves": 叶子们,
        "remaining_gaps": [] if 完成 else [缺口],
        "successor_recommendation": {"count": 0 if 完成 else 1, "title": None if 完成 else "闭合阶段1多年成本与真实执行延迟证据"},
        "stage1_complete": 完成,
        "stage2_released": 完成,
    }


def _当前RSS字节() -> int:
    值 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(值 if os.uname().sysname == "Darwin" else 值 * 1024)


def _可用内存比例() -> float:
    if sys.platform == "darwin":
        结果 = subprocess.run(
            ["memory_pressure", "-Q"], capture_output=True, text=True,
            timeout=10, check=True,
        )
        匹配 = re.search(r"free percentage: ([0-9.]+)%", 结果.stdout)
        if 匹配 is None:
            raise 合同错误("MEMORY_FACT_UNAVAILABLE")
        return float(匹配.group(1))
    内存 = {}
    try:
        for 行 in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            键, 值 = 行.split(":", 1)
            内存[键] = int(值.strip().split()[0])
        return round(内存["MemAvailable"] / 内存["MemTotal"] * 100, 2)
    except (OSError, KeyError, ValueError) as 错误:
        raise 合同错误("MEMORY_FACT_UNAVAILABLE") from 错误


def _资源快照(输出根: Path) -> dict[str, Any]:
    磁盘 = shutil.disk_usage(输出根)
    return {
        "memory_available_percent": _可用内存比例(),
        "disk_available_bytes": 磁盘.free,
        "rss_bytes": _当前RSS字节(),
    }


def _验证资源(快照: Mapping[str, Any], 限制: Mapping[str, Any], 开始: float) -> None:
    if float(快照["memory_available_percent"]) < float(限制["最小可用内存比例"]):
        raise 合同错误("MEMORY_AVAILABLE_LIMIT")
    if int(快照["disk_available_bytes"]) < int(限制["最小可用磁盘字节"]):
        raise 合同错误("DISK_AVAILABLE_LIMIT")
    if int(快照["rss_bytes"]) > int(限制["RSS字节"]):
        raise 合同错误("RSS_LIMIT_EXCEEDED")
    if time.monotonic() - 开始 > float(限制["总时限秒"]):
        raise 合同错误("TIME_LIMIT_EXCEEDED")


def _原子不覆盖发布(来源: Path, 目标: Path) -> None:
    if 来源.parent.stat().st_dev != 目标.parent.stat().st_dev:
        raise 合同错误("PUBLISH_FILESYSTEM_MISMATCH")
    库 = ctypes.CDLL(None, use_errno=True)
    源字节, 目标字节 = os.fsencode(来源), os.fsencode(目标)
    if sys.platform == "darwin" and hasattr(库, "renamex_np"):
        操作 = 库.renamex_np
        操作.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        操作.restype = ctypes.c_int
        返回 = 操作(源字节, 目标字节, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(库, "renameat2"):
        操作 = 库.renameat2
        操作.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        操作.restype = ctypes.c_int
        返回 = 操作(-100, 源字节, -100, 目标字节, 0x00000001)
    else:
        raise 合同错误("ATOMIC_NOREPLACE_UNAVAILABLE")
    if 返回 == 0:
        return
    错号 = ctypes.get_errno()
    if 错号 in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(目标)
    raise OSError(错号, os.strerror(错号), 目标)


def _新建受控临时根(父目录: Path, 前缀: str) -> tuple[Path, str]:
    根 = Path(tempfile.mkdtemp(prefix=前缀, dir=父目录))
    令牌 = hashlib.sha256(os.urandom(32)).hexdigest()
    根.with_name(根.name + ".sentinel").write_text(令牌, encoding="ascii")
    return 根, 令牌


def _安全清理(目标: Path, 允许父目录: Path, 令牌: str) -> None:
    try:
        目标.resolve(strict=True).relative_to(允许父目录.resolve(strict=True))
    except (OSError, ValueError) as 错误:
        raise 合同错误("CLEANUP_PATH_INVALID") from 错误
    哨兵 = 目标.with_name(目标.name + ".sentinel")
    if 目标.is_symlink() or not 目标.name.startswith(".task105-") or not 哨兵.is_file() or 哨兵.is_symlink():
        raise 合同错误("CLEANUP_IDENTITY_INVALID")
    if 哨兵.read_text(encoding="ascii") != 令牌:
        raise 合同错误("CLEANUP_IDENTITY_INVALID")
    shutil.rmtree(目标)
    哨兵.unlink()


def _独立重算(仓库: Path, 配置路径: Path, 批次: str, 槽位: int, 超时: float, RSS上限: int) -> dict[str, Any]:
    命令 = [
        sys.executable, str(Path(__file__).resolve()), "replay-worker",
        "--repo-root", str(仓库), "--config", str(配置路径), "--batch", 批次,
        "--slot", str(槽位),
    ]
    环境 = {**os.environ, "PYTHONHASHSEED": "0"}
    完成 = subprocess.run(
        命令, cwd=仓库, env=环境, capture_output=True, text=True,
        timeout=max(1.0, 超时), check=False,
    )
    if 完成.returncode != 0 or len(完成.stdout.encode()) > 16 * 1024 * 1024:
        raise 合同错误(f"REPLAY_PROCESS_FAILED:{槽位}")
    try:
        结果 = json.loads(完成.stdout)
    except json.JSONDecodeError as 错误:
        raise 合同错误(f"REPLAY_PROCESS_INVALID:{槽位}") from 错误
    if (
        结果.get("slot") != 槽位
        or not isinstance(结果.get("process_id"), int)
        or not isinstance(结果.get("rss_bytes"), int)
        or 结果["rss_bytes"] <= 0
    ):
        raise 合同错误(f"REPLAY_PROCESS_INVALID:{槽位}")
    if 结果["rss_bytes"] > RSS上限:
        raise 合同错误(f"REPLAY_RSS_LIMIT_EXCEEDED:{槽位}")
    return 结果


def _任务合同指纹(路径: Path) -> str:
    易变前缀 = (
        "- 状态：", "- 执行分支：", "- 开始时间：", "- 实现提交SHA：",
        "- Pull Request：", "- 合并时间：", "- 合并提交SHA：",
    )
    行 = 路径.read_text(encoding="utf-8").splitlines()
    截止 = next((序号 for 序号, 内容 in enumerate(行) if 内容 == "## 执行记录"), len(行))
    稳定 = [内容 for 内容 in 行[:截止] if not 内容.startswith(易变前缀)]
    while 稳定 and not 稳定[-1]:
        稳定.pop()
    return hashlib.sha256(("\n".join(稳定) + "\n").encode()).hexdigest()


def _固定输入总字节(仓库: Path, 配置: Mapping[str, Any]) -> int:
    总计 = 0
    文件数 = 0
    for 任务 in 必需任务:
        根 = _安全输入目录(仓库, str(配置["正式输入"][任务]["目录"]))
        for 当前根, 目录名, 文件名 in os.walk(根, followlinks=False):
            目录名.sort()
            文件名.sort()
            if len(Path(当前根).relative_to(根).parts) > 2:
                raise 合同错误("INPUT_TREE_TOO_DEEP")
            for 名称 in 文件名:
                路径 = Path(当前根) / 名称
                if 路径.is_symlink() or not 路径.is_file() or os.stat(路径).st_nlink != 1:
                    raise 合同错误("INPUT_FILE_INVALID")
                文件数 += 1
                总计 += 路径.stat().st_size
                if 文件数 > 128 or 总计 > int(配置["资源上限"]["输入字节"]):
                    raise 合同错误("INPUT_LIMIT_EXCEEDED")
    return 总计


def _发布清单(目录: Path, 发布时间: str) -> dict[str, Any]:
    文件 = {}
    for 路径 in sorted(目录.iterdir()):
        if 路径.name == "manifest.json" or not 路径.is_file():
            continue
        文件[路径.name] = {"bytes": 路径.stat().st_size, "sha256": 文件SHA256(路径)}
    return {"schema_version": "zhishi-stage1-current-final-gate-manifest/v1", "published_at": 发布时间, "file_count": len(文件), "files": 文件}


def 执行正式批次(仓库: Path, 配置路径: Path, 输出根: Path, 批次: str, *, 测试模式: bool = False) -> Path:
    if re.fullmatch(r"stage1-current-final-gate-[0-9TZ-]+-[0-9a-f]{12}", 批次) is None:
        raise 合同错误("BATCH_ID_INVALID")
    开始 = time.monotonic()
    配置 = 读取配置(配置路径)
    输出根.mkdir(parents=True, exist_ok=True)
    限制 = 配置["资源上限"]
    起始资源 = _资源快照(输出根)
    _验证资源(起始资源, 限制, 开始)
    当前 = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    主分支SHA = os.environ.get("ZHISHI_MAIN_SHA", "test" if 测试模式 else "")
    if not 测试模式 and re.fullmatch(r"[0-9a-f]{40}", 主分支SHA) is None:
        raise 合同错误("MAIN_SHA_REQUIRED")
    意图 = {
        "schema_version": "zhishi-stage1-current-final-gate-intent/v1", "task_id": "000105", "batch_id": 批次,
        "prepared_at": 当前, "main_sha": 主分支SHA,
        "config_sha256": 文件SHA256(配置路径),
        "executor_sha256": 文件SHA256(Path(__file__)),
        "task_contract_sha256": _任务合同指纹(仓库 / "docs/研发中心/任务/任务-000105.md"),
        "input_batches": {任务: 配置["正式输入"][任务]["批次"] for 任务 in 必需任务},
        "resource_limits": 配置["资源上限"], "remote_access": False, "database_access": False, "market_data_access": False,
    }
    工作根, 工作令牌 = _新建受控临时根(输出根, ".task105-work-")
    工作批次 = 工作根 / "batch"
    工作批次.mkdir()
    (工作批次 / "intent.json").write_text(规范JSON(意图) + "\n", encoding="utf-8")
    try:
        事实 = 验证正式输入(仓库, 配置)
        裁决 = 生成裁决(事实)
        结果指纹 = hashlib.sha256(规范JSON(裁决).encode()).hexdigest()
        剩余 = float(限制["总时限秒"]) - (time.monotonic() - 开始)
        重放1 = _独立重算(仓库, 配置路径, 批次, 1, 剩余, int(限制["RSS字节"]))
        _验证资源(_资源快照(输出根), 限制, 开始)
        剩余 = float(限制["总时限秒"]) - (time.monotonic() - 开始)
        重放2 = _独立重算(仓库, 配置路径, 批次, 2, 剩余, int(限制["RSS字节"]))
        if (
            重放1["process_id"] == 重放2["process_id"]
            or 重放1["process_id"] == os.getpid()
            or any(项.get("result_sha256") != 结果指纹 or 规范JSON(项.get("result")) != 规范JSON(裁决) for 项 in (重放1, 重放2))
        ):
            raise 合同错误("REPLAY_PROCESS_DRIFT")
        文件值 = {
            "input-validation.json": {任务: {"batch": 事实[任务]["批次"], "validator_status": 事实[任务]["验证器状态"]} for 任务 in 必需任务},
            "decision.json": 裁决, "replay-1.json": 重放1, "replay-2.json": 重放2,
        }
        for 名称, 值 in 文件值.items():
            (工作批次 / 名称).write_text(规范JSON(值) + "\n", encoding="utf-8")
        结束资源 = _资源快照(输出根)
        _验证资源(结束资源, 限制, 开始)
        摘要 = {
        "schema_version": "zhishi-stage1-current-final-gate-summary/v1", "task_id": "000105", "batch_id": 批次,
        "result_sha256": 结果指纹, "replays_equal": True, "leaf_count": 8, "allowed_research_leaf_count": 0,
        "remaining_gap_count": len(裁决["remaining_gaps"]), "remaining_gaps": 裁决["remaining_gaps"],
        "stage1_complete": 裁决["stage1_complete"], "stage2_released": 裁决["stage2_released"],
        "resource_facts": {
            "elapsed_seconds": round(time.monotonic() - 开始, 6),
            "rss_bytes": 结束资源["rss_bytes"],
            "input_bytes": _固定输入总字节(仓库, 配置),
            "memory_available_percent": 结束资源["memory_available_percent"],
            "disk_available_bytes": 结束资源["disk_available_bytes"],
            "replay_rss_bytes": [重放1["rss_bytes"], 重放2["rss_bytes"]],
        },
        "input_validators": {任务: 事实[任务]["验证器状态"] for 任务 in 必需任务},
        "cleanup_completed_before_publish": True,
        "safety": {"remote_access": False, "database_access": False, "market_data_access": False, "source_write": False, "model_or_backtest": False, "trade_decision": False},
        }
        (工作批次 / "summary.json").write_text(规范JSON(摘要) + "\n", encoding="utf-8")
        发布 = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        清单 = _发布清单(工作批次, 发布)
        (工作批次 / "manifest.json").write_text(规范JSON(清单) + "\n", encoding="utf-8")
        if sum(项.stat().st_size for 项 in 工作批次.iterdir()) > int(限制["输出字节"]):
            raise 合同错误("OUTPUT_LIMIT_EXCEEDED")
        验证已发布批次(仓库, 配置路径, 工作批次)
        发布字节 = {项.name: 项.read_bytes() for 项 in sorted(工作批次.iterdir())}
    finally:
        if 工作根.exists():
            _安全清理(工作根, 输出根, 工作令牌)
    发布暂存, 发布令牌 = _新建受控临时根(输出根, ".task105-publish-")
    try:
        for 名称, 内容 in 发布字节.items():
            (发布暂存 / 名称).write_bytes(内容)
        验证已发布批次(仓库, 配置路径, 发布暂存)
        _验证资源(_资源快照(输出根), 限制, 开始)
        发布哨兵 = 发布暂存.with_name(发布暂存.name + ".sentinel")
        发布哨兵.unlink()
        目标 = 输出根 / 批次
        _原子不覆盖发布(发布暂存, 目标)
    except Exception:
        if 发布暂存.exists():
            # 若哨兵已移除但发布尚未成功，恢复哨兵后按固定边界清理。
            哨兵 = 发布暂存.with_name(发布暂存.name + ".sentinel")
            if not 哨兵.exists():
                哨兵.write_text(发布令牌, encoding="ascii")
            _安全清理(发布暂存, 输出根, 发布令牌)
        raise
    验证已发布批次(仓库, 配置路径, 目标)
    return 目标


def 验证已发布批次(仓库: Path, 配置路径: Path, 目录: Path) -> dict[str, Any]:
    配置 = 读取配置(配置路径)
    事实 = 验证正式输入(仓库, 配置)
    期望裁决 = 生成裁决(事实)
    清单 = 读取JSON(目录 / "manifest.json")
    if set(清单.get("files", {})) != {项.name for 项 in 目录.iterdir() if 项.is_file() and 项.name != "manifest.json"}:
        raise 合同错误("PUBLISHED_FILE_SET_DRIFT")
    for 名称, 声明 in 清单["files"].items():
        路径 = 目录 / 名称
        if 路径.stat().st_size != 声明["bytes"] or 文件SHA256(路径) != 声明["sha256"]:
            raise 合同错误("PUBLISHED_FILE_DRIFT")
    决策 = 读取JSON(目录 / "decision.json")
    if 规范JSON(决策) != 规范JSON(期望裁决):
        raise 合同错误("DECISION_FACT_DRIFT")
    指纹 = hashlib.sha256(规范JSON(决策).encode()).hexdigest()
    for 名称 in ("replay-1.json", "replay-2.json"):
        重放 = 读取JSON(目录 / 名称)
        if 重放.get("result_sha256") != 指纹 or 规范JSON(重放.get("result")) != 规范JSON(决策):
            raise 合同错误("REPLAY_DRIFT")
    重放们 = [读取JSON(目录 / 名称) for 名称 in ("replay-1.json", "replay-2.json")]
    if (
        [项.get("slot") for 项 in 重放们] != [1, 2]
        or any(not isinstance(项.get("process_id"), int) or 项["process_id"] <= 0 for 项 in 重放们)
        or any(not isinstance(项.get("rss_bytes"), int) or 项["rss_bytes"] <= 0 or 项["rss_bytes"] > int(配置["资源上限"]["RSS字节"]) for 项 in 重放们)
        or 重放们[0]["process_id"] == 重放们[1]["process_id"]
    ):
        raise 合同错误("REPLAY_PROCESS_DRIFT")
    摘要 = 读取JSON(目录 / "summary.json")
    期望摘要 = {
        "result_sha256": 指纹,
        "leaf_count": 期望裁决["leaf_count"],
        "allowed_research_leaf_count": 期望裁决["allowed_research_leaf_count"],
        "remaining_gap_count": len(期望裁决["remaining_gaps"]),
        "remaining_gaps": 期望裁决["remaining_gaps"],
        "stage1_complete": 期望裁决["stage1_complete"],
        "stage2_released": 期望裁决["stage2_released"],
        "replays_equal": True,
    }
    if any(摘要.get(键) != 值 for 键, 值 in 期望摘要.items()):
        raise 合同错误("SUMMARY_DRIFT")
    意图 = 读取JSON(目录 / "intent.json")
    if (
        意图.get("config_sha256") != 文件SHA256(配置路径)
        or 意图.get("executor_sha256") != 文件SHA256(Path(__file__))
        or 意图.get("task_contract_sha256") != _任务合同指纹(仓库 / "docs/研发中心/任务/任务-000105.md")
        or 摘要.get("cleanup_completed_before_publish") is not True
        or set(摘要.get("input_validators", {}).values()) != {"通过"}
        or 摘要.get("resource_facts", {}).get("replay_rss_bytes") != [项["rss_bytes"] for 项 in 重放们]
    ):
        raise 合同错误("DELIVERY_BINDING_DRIFT")
    return 摘要


def main() -> int:
    解析器 = argparse.ArgumentParser(description=__doc__)
    解析器.add_argument("command", choices=("run", "validate", "replay-worker"))
    解析器.add_argument("--repo-root", type=Path, default=Path.cwd())
    解析器.add_argument("--config", type=Path, default=预期配置)
    解析器.add_argument("--output-root", type=Path, default=预期输出根)
    解析器.add_argument("--batch", required=True)
    解析器.add_argument("--slot", type=int, choices=(1, 2))
    参数 = 解析器.parse_args()
    仓库 = 参数.repo_root.resolve(strict=True)
    配置路径 = 参数.config if 参数.config.is_absolute() else 仓库 / 参数.config
    输出根 = 参数.output_root if 参数.output_root.is_absolute() else 仓库 / 参数.output_root
    if 配置路径.resolve(strict=True) != (仓库 / 预期配置).resolve(strict=True) or 输出根.resolve(strict=False) != (仓库 / 预期输出根).resolve(strict=False):
        raise 合同错误("PATH_INVALID")
    目录 = 输出根 / 参数.batch
    if 参数.command == "replay-worker":
        if 参数.slot is None:
            raise 合同错误("REPLAY_SLOT_REQUIRED")
        事实 = 验证正式输入(仓库, 读取配置(配置路径))
        裁决 = 生成裁决(事实)
        结果 = {
            "slot": 参数.slot, "process_id": os.getpid(),
            "process_started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "rss_bytes": _当前RSS字节(),
            "result": 裁决,
            "result_sha256": hashlib.sha256(规范JSON(裁决).encode()).hexdigest(),
        }
        print(规范JSON(结果))
        return 0
    结果 = 执行正式批次(仓库, 配置路径, 输出根, 参数.batch) if 参数.command == "run" else 验证已发布批次(仓库, 配置路径, 目录)
    print(规范JSON({"batch": 参数.batch, "result": str(结果)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
