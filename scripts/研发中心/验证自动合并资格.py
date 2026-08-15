#!/usr/bin/env python3
"""使用main可信任务合同验证Pull Request自动合并资格。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Mapping, Sequence


CONTROLLED_RD_TASK_TYPES = frozenset(
    {
        "数据治理",
        "数据审计",
        "数据工程",
        "基础设施验证",
        "策略研究",
        "研究工程",
        "模拟交易",
        "测试",
        "工具",
    }
)
ALLOWED_TASK_TYPES = (
    frozenset({"文档", "治理", "研究规范"}) | CONTROLLED_RD_TASK_TYPES
)
ALLOWED_ROOT_MARKDOWN = frozenset({"AGENTS.md", "README.md", "《知势宣言》.md"})
AUTOMATION_SCOPE = "治理自动化"
AUTOMATION_FILES = frozenset(
    {
        ".github/workflows/pr-auto-merge.yml",
        ".github/workflows/pr-auto-merge-eligibility.yml",
    }
)
TASK_FILE_PATTERN = re.compile(r"^docs/研发中心/任务/任务-(\d{6})\.md$")
TASK_TYPE_PATTERN = re.compile(r"^- 类型：(.+)$", re.MULTILINE)
TASK_STATUS_PATTERN = re.compile(r"^- 状态：(.+)$", re.MULTILINE)
TASK_PRIORITY_PATTERN = re.compile(r"^- 优先级：(.+)$", re.MULTILINE)
EXECUTION_BRANCH_PATTERN = re.compile(r"^- 执行分支：`([^`]+)`$", re.MULTILINE)
START_TIME_PATTERN = re.compile(
    r"^- 开始时间：`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})`$",
    re.MULTILINE,
)
TASK_TITLE_PATTERN = re.compile(r"^# 任务-\d{6}：(.+)$", re.MULTILINE)
TASK_TITLE_WITH_ID_PATTERN = re.compile(
    r"^# 任务-(\d{6})：(.+)$", re.MULTILINE
)
BLOCKER_PATTERN = re.compile(r"^- 当前阻塞原因：(.+)$", re.MULTILINE)
BOARD_TASK_ROW_PATTERN = re.compile(
    r"^\|\s*(?:P[0-3]\s*\|\s*)?任务-(\d{6})\s*\|"
)
BOARD_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "研发中心"
    / "任务看板模式.md"
)
REQUIRED_BOARD_SECTIONS = frozenset(
    {"待执行", "执行中", "阻塞", "待评审", "需修复", "已完成", "已取消"}
)
BOARD_AUXILIARY_SECTIONS = frozenset({"状态维护要求"})
GOVERNANCE_CONTROL_PATHS = frozenset({"docs/研发中心/任务看板模式.md"})


def _cross_carrier_conflict_reasons(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
    *,
    metadata: Mapping[str, object] | None = None,
    changed_paths: Sequence[str] = (),
    task_id: str = "",
) -> tuple[str, ...]:
    """从main可信树加载冲突检查器；仅允许一次可审计的治理入口引导。"""

    conflict_checker_path = repo_root / "scripts/研发中心/验证跨载体冲突.py"
    if not conflict_checker_path.exists():
        # 任务-000049首次引入可信检查器。base仍是旧可信树，不能执行head代码；
        # 该一次性引导由任务合同和本函数共同限定，其他任务一律失败关闭。
        if (
            task_id == "000049"
            and "scripts/研发中心/验证跨载体冲突.py" in changed_paths
            and "docs/治理/研发中心跨载体冲突处理协议.md" in changed_paths
        ):
            return ()
        # 早于任务-000049登记的最小策略测试仓库没有这项治理合同；真实仓库
        # 一旦任务-000049进入基线，入口缺失即不再兼容，必须失败关闭。
        if not (repo_root / "docs/研发中心/任务/任务-000049.md").exists():
            return ()
        return ("UNCLASSIFIED_CONFLICT:冲突检查器缺失:失败关闭",)
    try:
        spec = importlib.util.spec_from_file_location(
            "zhishi_cross_carrier_conflict", conflict_checker_path
        )
        if spec is None or spec.loader is None:
            return ("UNCLASSIFIED_CONFLICT:冲突检查器:失败关闭",)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        report = module.check_refs(
            repo_root,
            base_ref,
            head_ref,
            metadata=metadata,
            task_id=task_id,
            change_type=module._change_type_from_body(
                str((metadata or {}).get("body", ""))
            ),
        )
        return tuple(report.reasons)
    except (OSError, ImportError, TypeError, ValueError, AttributeError):
        return ("UNCLASSIFIED_CONFLICT:冲突检查器:失败关闭",)


def _board_schema_payload(schema_version, sections):
    return {"schema_version": schema_version, "sections": sections}


def _board_schema_digest(schema_version, sections):
    payload = json.dumps(
        _board_schema_payload(schema_version, sections),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _reject_duplicate_json_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("看板机器合同包含重复JSON键")
        document[key] = value
    return document


def _load_board_table_schema():
    """从唯一机器合同加载看板模式；缺失或损坏时失败关闭。"""

    if not BOARD_SCHEMA_PATH.exists():
        return {}
    try:
        document = json.loads(
            BOARD_SCHEMA_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        if set(document) != {"schema_version", "content_sha256", "sections"}:
            return {}
        version = document["schema_version"]
        sections = document["sections"]
        if version != "zhishi-task-board/v1" or not isinstance(sections, dict):
            return {}
        if set(sections) != REQUIRED_BOARD_SECTIONS:
            return {}
        normalized = {}
        for section, schema in sections.items():
            if (
                not isinstance(schema, list)
                or len(schema) != 2
                or not all(
                    isinstance(line, str) and line.startswith("|")
                    for line in schema
                )
            ):
                return {}
            normalized[section] = tuple(schema)
        if document["content_sha256"] != _board_schema_digest(version, sections):
            return {}
        review_header = normalized["待评审"][0]
        if "| PR |" not in review_header or "Pull Request" in review_header:
            return {}
        return normalized
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return {}


BOARD_TABLE_SCHEMA = _load_board_table_schema()
AUTOMATION_SCOPE_PATTERN = re.compile(r"^- 自动合并范围：(.+)$", re.MULTILINE)
BLOCKED_CONTRACT_REPAIR_TYPE = "阻塞任务合同修复"
BLOCKED_CONTRACT_REPAIR_EXECUTOR = "000056"
BLOCKED_CONTRACT_REPAIR_TARGET = "000055"
BLOCKED_CONTRACT_REPAIR_FIELD = "- 自动合并范围：治理自动化"
ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR = "000086"
ROOT_READONLY_CONTRACT_REPAIR_TARGET = "000084"
BLOCKED_CONTRACT_REPAIR_TARGETS = frozenset(
    {BLOCKED_CONTRACT_REPAIR_TARGET, ROOT_READONLY_CONTRACT_REPAIR_TARGET}
)
ROOT_READONLY_COMPAT_SECTION = """## Ubuntu root只读兼容模式（受控合同修复）

- 适用条件：仅当逻辑别名`ubuntu`实际UID为0且专用只读UID=1001不可用时启用；root与专用只读身份不等价，必须在批次证据中记录uid=0和访问模式。
- 固定目标：只允许逻辑别名`ubuntu`；固定根目录为`/opt/binance-event`、`/opt/celueqing`、`/opt/crypto-radar`、`/opt/event-prob-lab`、`/opt/orderbook-intelligence-service`、`/var/lib/mysql`。
- 固定候选文件名：`contracts.sqlite3`、`contracts.db`、`contracts.csv`、`contracts_hand.csv`、`contract.csv`、`contract_metadata.csv`、`exchangeInfo.json`、`exchange_info.json`；允许格式仅为`csv`、`json`、`sqlite3`、`db`，不跟随符号链接并排除`/proc`、`/sys`、`/dev`、`/run`、`/tmp`、`/var/tmp`。
- 固定探针：协议`zhishi-binance-contract-probe/1`；SSH参数和标准输入命令固定为`ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 ubuntu python3 -`，禁止任意shell、参数或命令替换。
- 只读边界：远端命令必须由固定探针生成；禁止任意shell/参数、远端写入、追加、临时文件、DDL、chmod/chown、权限/服务/防火墙变更。
- 数据边界：禁止凭据、环境变量、原始业务记录、价格、成交、订单簿、账户和未登记路径；只保留脱敏元数据、字段、计数、指纹、退出码和资源事实。
- 固定资源上限：批次总超时=900秒、SSH连接超时=15秒、最大候选文件数=4096、最大候选文件字节=16777216、最大API响应字节=16777216、最大输出字节=33554432、最大日志字节=65536；证据字段固定为`uid`、`gid`、`访问模式`、`协议`、`扫描完整`、`失败安全`、`失败原因代码`、`失败原因指纹`、`扫描文件数`、`候选文件数`、`候选路径指纹`、`候选字段摘要`、`Schema指纹`、`退出码`、`资源事实`。
- 失败安全：身份、路径、协议、权限、计数、指纹、超时或资源超限任一异常时清空候选并记录失败原因指纹，不将root结果标记为专用只读证明。
- 资源与回滚：沿用任务-000085资源上限；本模式不允许远端追加，批次仅本地追加式发布；撤销本合同修复不会修改Ubuntu、数据库、原始数据或历史批次。"""
BLOCKED_CONTRACT_REPAIR_ALLOWED_PATHS = frozenset(
    {
        "docs/研发中心/看板.md",
        "docs/治理/PR自动合并策略.md",
    }
)
CONTRACT_CONFLICT_REPAIR_TYPE = "任务合同冲突修复"
CONTRACT_CONFLICT_REPAIR_EXECUTOR = "000068"
CONTRACT_CONFLICT_REPAIR_TARGET = "000066"
CONTRACT_CONFLICT_REPAIR_PR = 165
TASK116_CONTRACT_REPAIR_EXECUTOR = "000116"
TASK116_CONTRACT_REPAIR_TARGET = "000115"
STAGE1_CONTRACT_REPAIR_TYPE = "阶段1覆盖受限合同修订"
STAGE1_CONTRACT_REPAIR_EXECUTOR = "000115"
STAGE1_CONTRACT_REPAIR_TARGET = "000106"
STAGE1_COVERAGE_V2_TYPE = "阶段1覆盖受限完成合同修订V2"
STAGE1_COVERAGE_V2_EXECUTOR = "000124"
STAGE1_COVERAGE_V2_TARGETS = frozenset({"000098", "000106"})
STAGE1_COVERAGE_V2_ALLOWED_PATHS = frozenset(
    {
        "scripts/研发中心/验证自动合并资格.py",
        "tests/研发中心/test_验证自动合并资格.py",
        "docs/研发中心/任务/任务-000124.md",
        "docs/研发中心/任务/任务-000098.md",
        "docs/研发中心/任务/任务-000106.md",
        "docs/研发中心/看板.md",
        "README.md",
        "docs/研发中心/总体计划.md",
        "docs/审计/阶段1最终审计报告.md",
        "docs/审计/数据缺口与补采清单.md",
    }
)
STAGE1_COVERAGE_V2_BASE_TASK_SHA256 = {
    "000098": "e13e127f9bf47025c5f4aa3a6b05cbd16560add108f68c32152b7549614fc903",
    "000106": "541162de969f12816b5177bda34ce46cf21a7d0513393e318a9110028699328f",
}
STAGE1_CONTRACT_REPAIR_ALLOWED_PATHS = frozenset(
    {
        "docs/研发中心/任务/任务-000115.md",
        "docs/研发中心/任务/任务-000106.md",
        "docs/研发中心/看板.md",
        "docs/研发中心/总体计划.md",
        "docs/审计/数据缺口与补采清单.md",
        "docs/研究/数据验证阶段执行规范.md",
        "docs/研究/研究准入规范.md",
        "docs/superpowers/specs/task-000115-bounded-cost-coverage-gate-design.md",
    }
)
STAGE1_DERIVED_DOC_PATHS = frozenset(
    STAGE1_CONTRACT_REPAIR_ALLOWED_PATHS
    - {
        "docs/研发中心/任务/任务-000115.md",
        "docs/研发中心/任务/任务-000106.md",
        "docs/研发中心/看板.md",
    }
)
CONTRACT_CONFLICT_REPAIR_ALLOWED_PATHS = frozenset(
    {
        "docs/研发中心/看板.md",
    }
)
TASK094_CONTRACT_REPAIR_EXECUTOR = "000095"
TASK094_CONTRACT_REPAIR_TARGET = "000094"
TASK100_CONTRACT_REPAIR_EXECUTOR = "000102"
TASK100_CONTRACT_REPAIR_TARGET = "000100"
TASK100_CONTRACT_REPAIR_GOVERNANCE = "000101"
TASK115_BASELINE_BLOCKER_LINE = (
    "- 当前阻塞原因：main可信合并规则当前只登记任务-000056→000055和任务-000086→000084两条阻塞合同修复映射，普通任务无法直接修订任务-000106；若绕过该规则，PR资格将失败关闭。"
)
STAGE1_COVERAGE_LIMITED_SECTION = (
    "## 覆盖受限模式（任务-000115适用规则）\n\n"
    "- 研究覆盖：仅使用已验证的BTC、ETH覆盖窗口；覆盖外统一为`无法判定`，不补齐、不缩小候选总体或分母。\n"
    "- 主研究尺度：4小时、8小时、24小时、48小时；15分钟和1小时仅允许作为事后结果观察窗口。\n"
    "- 成本与延迟：多年主网真实执行延迟不作为当前阶段研究硬门，缺少该证据时保持`无法判定`；不得用网络往返、信号投递确认、本地模拟或Demo结果替代。\n"
    "- 统计边界：BTC与ETH分别统计，禁止跨标的补偿；必须保留候选总体、已观察、拒绝、失败、未成熟、失效和缺失计数。\n"
    "- 解释边界：覆盖窗口内仅可报告描述性证据，不得据此推导因果、预测优势、胜率、收益、研究准入或交易许可；真实资金交易保持关闭。\n"
    "- 历史保护：本规则不改变本任务既有执行记录、历史批次、提交SHA或原始数据。"
)
STAGE1_DERIVED_DOC_APPENDIX = (
    "## 任务-000115覆盖受限补充\n\n"
    "- 本入口只描述已验证覆盖窗口；覆盖外保持`无法判定`，不外推、不缩小分母、不跨标的补偿。\n"
    "- 主研究尺度固定为4小时、8小时、24小时、48小时；15分钟和1小时仅作事后结果观察。\n"
    "- 多年主网真实执行延迟、真实资金交易和交易许可不因覆盖受限模式自动放行。"
)
TASK100_OUTPUT_CONTRACT_OLD = "- 更新阶段1最终审计报告、数据缺口清单、README、总体计划、任务文件和看板；"
TASK100_OUTPUT_CONTRACT_NEW = "- 保持docs/审计/阶段1最终审计报告.md和docs/审计/数据缺口与补采清单.md字节不变；新增docs/审计/阶段1成本与执行证据报告.md，并更新README、总体计划、任务文件和看板；"
TASK094_NATIVE_SCANNER_PATH = "scripts/审计/阶段1时间质量扫描器.c"
TASK094_EXECUTOR_PATH = "scripts/审计/审计阶段1新正式输入时间质量.py"
TASK094_CONFIG_PATH = "config/审计/任务-000094逐行时间质量审计.json"
TASK094_TASK_PATH = "docs/研发中心/任务/任务-000094.md"
TASK094_RESOURCE_LIMIT_BYTES = 512 * 1024 * 1024
TASK094_RESOURCE_PROTOCOL = "zhishi-process-group-rusage/v1"
TASK094_RESOURCE_PLATFORM = "darwin-rusage-maxrss-by-process/v1"
TASK094_CONTRACT_HEADER_PREFIXES = (
    "# 任务-000094：",
    "- 类型：",
    "- 阶段：",
    "- 优先级：",
    "- 执行方案：",
    "- 方案状态：",
    "- 执行授权：",
    "- 并行规则：",
)
TASK094_CONTRACT_REPLACEMENTS = (
    (
        "3. 对5180个正式成员执行单进程逐ZIP逐行扫描，保存成员级状态、原因码、计数、时间边界、连续段和指纹，不保存原始业务值。",
        "3. 对5180个正式成员执行固定三进程串行流水线（一个Python主控、一个固定`/usr/bin/unzip`解压子进程、一个固定扫描子进程；成员不并行）逐ZIP逐行扫描，保存成员级状态、原因码、计数、时间边界、连续段和指纹，不保存原始业务值。",
    ),
    (
        "- 使用Python标准库和已有任务-000093列式JSON工具；单进程、逐文件、逐行、常量内存，不新增依赖、数据库或常驻服务。",
        "- 使用Python标准库、已有任务-000093列式JSON工具和精确源码`scripts/审计/阶段1时间质量扫描器.c`；固定`/usr/bin/clang`只把内容寻址源码编译到临时目录，运行拓扑最多为一个Python主控、一个固定`/usr/bin/unzip`解压子进程和一个固定扫描子进程，成员严格串行，不新增第三方依赖、数据库或常驻服务。",
    ),
    (
        "- 全量单进程扫描触发28800秒、512MiB、磁盘或25MiB输出硬门，且无法在不改变合同语义的情况下继续。",
        "- 全量固定三进程串行流水线触发28800秒、主进程与全部子进程峰值RSS保守求和超过512MiB、磁盘或25MiB输出硬门，且无法在不改变合同语义的情况下继续。",
    ),
    (
        "- `scripts/审计/审计阶段1新正式输入时间质量.py`及专项测试：确定性解码、逐行验证、成员裁决、连续段和原子发布。",
        "- `scripts/审计/审计阶段1新正式输入时间质量.py`、精确源码`scripts/审计/阶段1时间质量扫描器.c`及专项测试：确定性解码、有界内存逐行验证、成员裁决、连续段和原子发布。",
    ),
    (
        "- 单进程、流式、常量内存；不保存或输出价格、数量、成交编号、逐行业务正文或敏感信息。",
        "- 固定三进程串行流水线、流式、常量内存且成员不并行；主进程与全部子进程峰值RSS保守求和执行512MiB失败关闭；不保存或输出价格、数量、成交编号、逐行业务正文或敏感信息。",
    ),
    (
        "6. 真实单进程运行完成，保存扫描行数、解压字节、耗时、RSS、磁盘和源目录前后指纹；资源硬门均满足。",
        "6. 真实固定三进程串行流水线运行完成，保存扫描行数、解压字节、耗时、进程拓扑、主进程峰值RSS、全部子进程峰值RSS、二者保守求和、测量平台、磁盘和源目录前后指纹；资源硬门均满足。",
    ),
    (
        "python3 -m py_compile scripts/审计/审计阶段1新正式输入时间质量.py tests/审计/test_审计阶段1新正式输入时间质量.py",
        "python3 -m py_compile scripts/审计/审计阶段1新正式输入时间质量.py tests/审计/test_审计阶段1新正式输入时间质量.py\n/usr/bin/clang -O2 -std=c11 -Wall -Wextra -Werror -fsyntax-only scripts/审计/阶段1时间质量扫描器.c",
    ),
    (
        "- 当前阻塞原因：无。5180个正式成员、任务-000092官方对象`LastModified`和固定本地只读归档均可用；本任务不依赖Ubuntu、数据库、凭据或生产权限。",
        "- 当前阻塞原因：无。5180个正式成员、任务-000092官方对象`LastModified`和固定本地只读归档均可用；本任务不依赖Ubuntu、数据库、凭据或生产权限。\n- 解除条件：任务-000095治理修复已进入`main`；精确C源码路径、固定三进程串行拓扑与整个进程组资源计量合同已可由可信规则复验。",
    ),
)


def _task094_native_scanner_allowed(
    *, task_ids: Sequence[str], change_type: str | None, path: str
) -> bool:
    """只为任务-000094的唯一C扫描器开放受控交付。"""

    return (
        tuple(task_ids) == (TASK094_CONTRACT_REPAIR_TARGET,)
        and change_type == "任务交付"
        and path == TASK094_NATIVE_SCANNER_PATH
    )


def _contract_conflict_executor(body_task_ids: Sequence[str]) -> str | None:
    """只接受已登记的一次性合同修复入口，未知或混合引用失败关闭。"""

    if tuple(body_task_ids) == (CONTRACT_CONFLICT_REPAIR_EXECUTOR,):
        return CONTRACT_CONFLICT_REPAIR_EXECUTOR
    if tuple(body_task_ids) == (TASK116_CONTRACT_REPAIR_EXECUTOR,):
        return TASK116_CONTRACT_REPAIR_EXECUTOR
    if tuple(body_task_ids) == (TASK094_CONTRACT_REPAIR_EXECUTOR,):
        return TASK094_CONTRACT_REPAIR_EXECUTOR
    if tuple(body_task_ids) == (TASK100_CONTRACT_REPAIR_EXECUTOR,):
        return TASK100_CONTRACT_REPAIR_EXECUTOR
    return None


def _apply_task100_contract_repair(text: str) -> str | None:
    """逐字替换任务-000100唯一输出条目，不接受缺失或重复。"""

    if text.count(TASK100_OUTPUT_CONTRACT_OLD) != 1:
        return None
    if TASK100_OUTPUT_CONTRACT_NEW in text:
        return None
    return text.replace(TASK100_OUTPUT_CONTRACT_OLD, TASK100_OUTPUT_CONTRACT_NEW, 1)


def _apply_task094_contract_repair(text: str) -> str | None:
    """逐字应用任务-000094一次性完整合同替换。"""

    repaired = text
    for old, new in TASK094_CONTRACT_REPLACEMENTS:
        if repaired.count(old) != 1 or new in repaired:
            return None
        repaired = repaired.replace(old, new, 1)
    return repaired


def _apply_task116_contract_repair(text: str) -> str | None:
    """只为任务-000116→任务-000115补齐首次阻塞字段。"""

    anchor = "- 当前目标：将阶段1研究证据门从“完整多年覆盖+多年主网真实执行延迟”改为“按已验证覆盖窗口交付并显式保留缺失”。"
    if text.count(anchor) != 1 or TASK115_BASELINE_BLOCKER_LINE in text:
        return None
    return text.replace(anchor, f"{anchor}\n{TASK115_BASELINE_BLOCKER_LINE}", 1)


def _apply_stage1_contract_repair(text: str) -> str | None:
    """只允许在任务-000106合同中追加固定覆盖受限规则章节。"""

    if text.count(STAGE1_COVERAGE_LIMITED_SECTION) != 0:
        return None
    if text.count("## 背景") != 1:
        return None
    return text.replace(
        "## 背景",
        f"{STAGE1_COVERAGE_LIMITED_SECTION}\n\n## 背景",
        1,
    )


def _apply_stage1_derived_doc_repair(text: str) -> str | None:
    """只允许在阶段1派生入口末尾追加固定边界说明。"""

    if text.endswith(STAGE1_DERIVED_DOC_APPENDIX + "\n"):
        return None
    return text.rstrip("\n") + "\n\n" + STAGE1_DERIVED_DOC_APPENDIX + "\n"


STAGE1_COVERAGE_V2_TASK098_APPENDIX = (
    "## 任务-000124覆盖受限完成补充\n\n"
    "- 精确截止时刻由来源批次记录冻结，不扩展或改写历史`completed_at`。晚到成员保留候选总体并标记为时间边界拒绝/`无法判定`，不进入可见集。\n"
    "- 候选总体、可见集、拒绝、无法判定和缺失计数必须守恒；不得删除成员、缩小分母、跨BTC/ETH补偿或使用未来数据。\n"
    "- 覆盖受限完成不产生研究准入、交易许可或真实交易结论。"
)
STAGE1_COVERAGE_V2_TASK106_APPENDIX = (
    "## 任务-000124覆盖受限完成补充\n\n"
    "- 覆盖窗口内成本与执行证据可审计交付；多年成本或主网历史生命周期缺失保持`无法判定`，不被Demo、网络往返或本地模拟替代。\n"
    "- BTC、ETH及4/8/24/48小时分别统计，15分钟和1小时仅作事后结果观察窗口；不得跨标的补偿或缩小分母。\n"
    "- 覆盖受限完成不改变研究准入、交易许可和真实交易关闭边界。"
)
STAGE1_COVERAGE_V2_DERIVED_APPENDICES = {
    "README.md": (
        "## 任务-000124覆盖受限完成补充\n\n"
        "- 阶段1允许交付已验证覆盖窗口的可审计证据；覆盖外、多年成本与主网历史生命周期缺失统一保持`无法判定`。\n"
        "- BTC、ETH分别统计，主研究尺度固定为4小时、8小时、24小时、48小时；15分钟和1小时仅作事后结果观察窗口。\n"
        "- 覆盖受限完成不等于研究准入、交易许可或真实交易准入；真实资金交易继续关闭。"
    ),
    "docs/研发中心/总体计划.md": (
        "## 任务-000124覆盖受限完成补充\n\n"
        "- 任务-000098采用精确截止时刻的可见集重放，晚到成员保留在候选总体、拒绝和`无法判定`计数中，不进入可见集。\n"
        "- 任务-000106允许在覆盖窗口证据链完整时交付覆盖受限结果；多年成本或主网历史生命周期缺失保持`无法判定`。\n"
        "- 覆盖受限交付不自动升级研究准入、交易许可或真实交易，阶段边界和4/8/24/48小时主研究尺度不变。"
    ),
    "docs/审计/阶段1最终审计报告.md": (
        "## 任务-000124覆盖受限完成补充\n\n"
        "- 覆盖窗口内的成本与执行证据可形成可审计交付；覆盖外、多年成本和主网历史生命周期证据保持`无法判定`。\n"
        "- 晚到成员不得从候选总体删除；精确截止时刻之外的成员排除可见集但保留拒绝/无法判定计数。\n"
        "- 本补充不改变阶段1/阶段2门禁，不产生研究准入、交易许可、胜率、收益、方向、仓位或真实交易结论。"
    ),
    "docs/审计/数据缺口与补采清单.md": (
        "## 任务-000124覆盖受限完成补充\n\n"
        "- 未补齐的多年成本、执行延迟和主网生命周期证据继续登记为`无法判定`，不得缩小分母、跨标的补偿或外推覆盖范围。\n"
        "- 任务-000098的晚到成员保留在候选总体并按精确截止时刻标记；任务-000106按BTC、ETH和4/8/24/48小时分别记录覆盖与缺失。\n"
        "- 缺口状态变化只影响证据可审计范围，不自动改变研究准入、交易许可或真实交易关闭状态。"
    ),
}


def _replace_stage1_v2_text(text: str, replacements: Sequence[tuple[str, str]]) -> str | None:
    result = text
    for old, new in replacements:
        if result.count(old) != 1:
            return None
        result = result.replace(old, new, 1)
    return result


def _apply_stage1_coverage_v2_task_repair(text: str, task_id: str) -> str | None:
    """应用任务-000124一次性V2合同的固定目标文本。"""

    expected_sha = STAGE1_COVERAGE_V2_BASE_TASK_SHA256.get(task_id)
    if expected_sha is None or hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_sha:
        return None
    if task_id == "000098":
        return _replace_stage1_v2_text(
            text,
            (
                (
                    "- 当前阻塞原因：任务-000094来源批次的`completed_at`只保留到`2026-08-12T10:19:32Z`整秒，但最后1个正式成员的`collected_at=2026-08-12T10:19:32.308238Z`；按批准合同精确比较，该成员晚于决策时间，不能把历史重放门标记为通过。",
                    "- 当前阻塞原因：覆盖受限V2路由已登记但本任务尚未完成精确可见集重放；在交付前必须保留全部5180个候选、晚到成员和时间边界计数，不得把缺失伪造为通过。",
                ),
                (
                    "- 解除条件：登记并完成替代任务，以预先冻结、可复算且不晚于实际决策的精确截止时刻重放同一5180成员；不得在本任务执行PR中事后扩展`completed_at`语义或删除该成员。",
                    "- 解除条件：按覆盖受限V2合同预先冻结来源批次记录的精确决策截止时刻，重放同一5180成员并交付候选总体、可见集、拒绝和无法判定的守恒证据；不得扩展或改写历史`completed_at`，不得删除晚到成员。",
                ),
                (
                    "2. 从已审计的脱敏成员证据复算5180个正式成员、391个质量拒绝、207个来源拒绝、2个观察项、175个连续段和8个叶子，不读原始业务行。",
                    "2. 从已审计的脱敏成员证据复算5180个正式成员、391个质量拒绝、207个来源拒绝、2个观察项、175个连续段和8个叶子，不读原始业务行；晚到成员必须留在候选总体。",
                ),
                (
                    "3. 依据`source_visible_at <= decision_at`与`collected_at <= decision_at`重建当时可见集，证明未来或修订数据不能进入旧决策。",
                    "3. 依据来源批次记录的精确决策截止时刻重建可见集；`source_visible_at`或`collected_at`晚于截止时刻的成员标记为时间边界拒绝/`无法判定`并排除出可见集，证明未来或修订数据不能进入决策。",
                ),
                (
                    "5. 只对8个叶子的历史重放门进行有证据的更新；成本与执行、容量和恢复保持无法判定。",
                    "5. 只对8个叶子的覆盖窗口重放门进行有证据的更新；成本与执行、容量和恢复保持`无法判定`，覆盖受限完成不升级研究准入或交易许可。",
                ),
                (
                    "2. 以批次`completed_at`为决策时间，严格解析UTC时间；任一成员的来源可见或采集时间晚于决策时间时失败关闭。",
                    "2. 以来源批次记录的精确决策截止时刻为冻结点，不扩展或改写历史`completed_at`；`source_visible_at`或`collected_at`晚于截止时刻的成员保留候选总体并标记为时间边界拒绝/`无法判定`，不得进入可见集。",
                ),
                (
                    "3. 每个正式成员的来源可见与采集时间不晚于决策时间；未来时间负向测试失败关闭；",
                    "3. 每个正式成员均按精确截止时刻裁决；晚到成员保留在候选总体和拒绝/无法判定计数中且不进入可见集；未来时间负向测试失败关闭；",
                ),
                (
                    "6. 仅8个叶子的历史重放门可更新为通过；成本与执行、容量和恢复保持无法判定，阶段1/阶段2不提前放行；",
                    "6. 仅8个叶子的覆盖窗口重放门可更新为通过；晚到成员、成本与执行、容量和恢复保持`无法判定`，阶段1/阶段2、研究准入和交易许可不提前放行；",
                ),
                (
                    "合同、配置、执行器、专项测试和真实不可变批次全部交付；任务-000094数据资格决策以同一历史可见集连续两次字节一致重建，8个叶子历史重放门有证据通过，其他三门保守阻塞；双只读评审、main可信复验和自动合并完成，随后独立状态闭环将本任务标记为`已完成`。",
                    "合同、配置、执行器、专项测试和真实不可变批次全部交付；任务-000094数据资格决策以同一历史截止时刻连续两次字节一致重建，候选总体、可见集、拒绝和无法判定计数守恒，8个叶子的覆盖窗口重放门有证据通过；缺失不升级为通过，研究准入、交易许可和真实交易继续关闭。双只读评审、main可信复验和自动合并完成，随后独立状态闭环将本任务标记为`已完成`。",
                ),
                (
                    "本任务证明数据资格门禁决策可按历史可见输入重放，不证明尚未产生的策略、模型或交易决策可重放；这些决策一旦开始生成，仍必须继续遵守任务-000022和《可信重放来源与历史决策现场合同》。",
                    "本任务只证明已验证覆盖窗口可按历史截止时刻重放；晚到成员和覆盖外数据保持`无法判定`，不证明尚未产生的策略、模型或交易决策可重放，也不产生研究准入、交易许可或真实交易结论。",
                ),
            ),
        )
    if task_id == "000106":
        old_coverage = STAGE1_COVERAGE_LIMITED_SECTION
        new_coverage = old_coverage.replace(
            "## 覆盖受限模式（任务-000115适用规则）",
            "## 覆盖受限模式（任务-000124适用V2规则）",
        ).replace(
            "- 历史保护：本规则不改变本任务既有执行记录、历史批次、提交SHA或原始数据。",
            "- 覆盖受限完成：本规则允许交付已验证覆盖窗口的成本与延迟证据链；多年历史或主网生命周期缺失保持`无法判定`，不因缺失自动阻塞覆盖内可审计交付。\n"
            "- 历史保护：本规则不改变本任务既有执行记录、历史批次、提交SHA或原始数据；研究准入、交易许可和真实交易继续关闭。",
        )
        return _replace_stage1_v2_text(
            text,
            (
                (old_coverage, new_coverage),
                (
                    "4. 对BTC、ETH及4/8/24/48小时分别裁决成本与执行门，完成两次独立重放；新增阶段1最终门禁V2配置和验证入口消费任务-000106正式输入，同时保持任务-000105 V1配置、验证语义和既有正式批次可复验。只有多年成本和正式历史主网执行证据均通过时才允许V2八叶子放行。",
                    "4. 对BTC、ETH及4/8/24/48小时分别裁决成本与执行覆盖窗口，完成两次独立重放；新增阶段1最终门禁V2配置和验证入口消费任务-000106正式输入，同时保持任务-000105 V1配置、验证语义和既有正式批次可复验。覆盖窗口证据完整即可交付覆盖受限结果，多年成本或正式历史主网执行证据缺失时对应状态保持`无法判定`。",
                ),
                (
                    "11. `decide`对BTC、ETH和4/8/24/48小时分别生成八个叶子；15分钟、1小时仅为事后观察窗口。真实执行延迟通过的必要条件是存在与任务-000099正式成员版本、BTC/ETH、主研究尺度、历史窗口及发送/确认/成交或撤单四时点一一绑定的主网生命周期证据，并保留候选、已观察、拒绝、失败、超时和无法判定分母；本任务不生成该证据，因此不存在既有合格输入时必须失败关闭。",
                    "11. `decide`对BTC、ETH和4/8/24/48小时分别生成八个叶子；15分钟、1小时仅为事后观察窗口。主网历史执行生命周期缺失时，V2允许交付覆盖受限证据，仍保留候选、已观察、拒绝、失败、超时和`无法判定`分母；该缺失不得被网络往返、信号投递确认、本地模拟或Demo代理替代，也不得驱动交易许可。",
                ),
                (
                    "14. 只有V2八叶子全部通过才将任务更新为`待评审`并创建任务交付PR。若主网历史执行证据仍缺失，则不提交交付分支；从main独立创建合并后状态闭环PR执行`待执行→阻塞`，看板同步阻塞。任务头部只追加执行分支和开始时间，并新增唯一`## 执行记录`，其内容严格为八个字段：执行分支、开始时间、尝试命令、结果、外部证据、阻塞原因、解除条件、数据与安全；清单SHA写入外部证据，对象计数写入结果，外部目标仅写逻辑别名`ubuntu`，不写Binance域名、URL、账户或凭据。阻塞解除后通过独立状态闭环PR恢复`阻塞→待执行`，再复用内容寻址对象继续原执行分支。",
                    "14. 覆盖窗口证据、分母守恒和两次重放通过后即可将任务更新为`待评审`并创建覆盖受限交付PR；多年成本或主网历史执行证据缺失的叶子写为`无法判定`，不得因此把覆盖内证据伪造为通过，也不强制本任务转为阻塞。任务头部只追加执行分支和开始时间，并新增唯一`## 执行记录`，其内容严格为八个字段：执行分支、开始时间、尝试命令、结果、外部证据、阻塞原因、解除条件、数据与安全；清单SHA写入外部证据，对象计数写入结果，外部目标仅写逻辑别名`ubuntu`，不写Binance域名、URL、账户或凭据。若其他硬门失败仍按失败安全停止，恢复通过独立状态闭环PR处理。",
                ),
                (
                    "- Demo凭据缺失时不询问A/B/C、不读取其他项目凭据、不创建真实账户；完成全部公开证据后输出唯一所需外部条件。不存在主网历史执行证据时不得更改门禁语义，任务转为阻塞。普通实现取舍按安全、证据、增量最小、可复现、可回滚顺序自主决定。",
                    "- Demo凭据缺失时不询问A/B/C、不读取其他项目凭据、不创建真实账户；完成公开证据后，主网历史执行缺失只记录为`无法判定`，不阻断覆盖窗口交付，也不改变研究准入、交易许可和真实交易关闭。普通实现取舍按安全、证据、增量最小、可复现、可回滚顺序自主决定。",
                ),
                (
                    "只有任务-000105或正式输入指纹漂移、官方精确来源全部不可达、需要连接主网交易端点、需要新增真实资金/生产权限、必须修改Ubuntu数据库或订单簿系统、数据卷少于30GiB、本机可用内存低于20%、累计网络读取将超过20GiB，或合同直接冲突时才允许停止相关阶段。Demo凭据、专用Key指纹或独占条件缺失、单一公开对象不足、部分叶子无法判定不属于停止公开补证的条件；必须继续完成其他证据。公开补证完成后，如唯一剩余条件是主网历史执行证据，按固定独立状态闭环顺序转为`阻塞`，不得创建交付PR或标记完成。",
                    "只有任务-000105或正式输入指纹漂移、官方精确来源全部不可达、需要连接主网交易端点、需要新增真实资金/生产权限、必须修改Ubuntu数据库或订单簿系统、数据卷少于30GiB、本机可用内存低于20%、累计网络读取将超过20GiB，或合同直接冲突时才允许停止相关阶段。Demo凭据、专用Key指纹或独占条件缺失、单一公开对象不足、部分叶子`无法判定`不属于停止覆盖受限交付的条件；必须继续完成其他证据。主网历史执行证据缺失本身只产生`无法判定`，不得自动升级为交易许可或真实交易。",
                ),
                (
                    "8. 新V2门禁以任务-000106作为第六项正式输入，测试证明Demo代理、缺失/伪造主网证据和历史分母不足均不能放行，只有完整多年成本及同版本主网历史执行证据才可通过；任务-000105 V1批次`stage1-current-final-gate-20260812T213100Z-6c0e4bf5d923`及结果SHA-256=`43814e0f70143eb798b7dea71a36dfa4383b95bd9fff865c808f767ac8f1c4b0`继续通过原验证语义；V2结果发布为独立追加式批次；",
                    "8. 新V2门禁以任务-000106作为第六项正式输入，测试证明Demo代理、缺失/伪造主网证据和历史分母不足不能冒充通过；覆盖窗口证据完整时可交付覆盖受限结果，缺失多年成本或主网历史生命周期的叶子保持`无法判定`。任务-000105 V1批次`stage1-current-final-gate-20260812T213100Z-6c0e4bf5d923`及结果SHA-256=`43814e0f70143eb798b7dea71a36dfa4383b95bd9fff865c808f767ac8f1c4b0`继续通过原验证语义；V2结果发布为独立追加式批次；",
                ),
                (
                    "固定配置、执行器、测试、合同、报告和一次追加式正式批次已交付；官方多年成本证据按增量清单闭环；新V2门禁确认八叶子成本与执行门全部通过，且任务-000105 V1正式批次仍可复验；两次重放可复现；双只读评审、main可信复验、自动合并和独立状态闭环完成。若主网历史执行证据不存在、任何叶子未通过或只能形成Demo代理，禁止创建任务交付PR；按现行可信状态闭环把任务从main中的`待执行`转为`阻塞`，保留外部数据和执行分支待恢复，不得标记`已完成`。",
                    "固定配置、执行器、测试、合同、报告和一次追加式正式批次已交付；覆盖窗口成本与执行证据可审计且两次重放可复现；缺失多年成本或主网历史生命周期证据保持`无法判定`，不得用Demo代理、网络往返或本地模拟替代。双只读评审、main可信复验、自动合并和独立状态闭环完成；研究准入、交易许可和真实交易继续关闭。若其他硬门失败，必须安全停止并记录证据，不得伪造完成。",
                ),
                (
                    "Binance公开归档的实际历史起点、`bookDepth`抽样语义和手续费历史版本须由执行时官方对象与校验和证明；不能预先假设完整。Demo凭据和代理遥测都不能替代多年正式输入的主网历史执行证据；当前仓库尚未证明后者存在，因此任务执行后可能依法转为阻塞，绝不以降低阶段门换取完成。",
                    "Binance公开归档的实际历史起点、`bookDepth`抽样语义和手续费历史版本须由执行时官方对象与校验和证明；不能预先假设完整。多年成本或主网历史生命周期缺失时仅保留`无法判定`，不阻断已验证覆盖窗口的可审计交付，也不产生研究准入、交易许可或真实交易结论。",
                ),
            ),
        )
    return None


def _task094_resource_fact_reasons(resource_facts: object) -> tuple[str, ...]:
    """验证任务-000094整个串行进程组的保守资源事实。"""

    if not isinstance(resource_facts, Mapping):
        return ("任务-000094缺少进程组资源事实",)
    required = {
        "measurement_protocol",
        "measurement_platform",
        "rss_unit",
        "process_topology",
        "members_parallelism",
        "controller_max_rss_bytes",
        "compiler_max_rss_bytes",
        "unzip_max_rss_bytes",
        "scanner_max_rss_bytes",
        "children_conservative_sum_max_rss_bytes",
        "conservative_process_group_max_rss_bytes",
    }
    reasons: list[str] = []
    if set(resource_facts) != required:
        reasons.append("任务-000094进程组资源字段不完整")
        return tuple(reasons)
    if resource_facts.get("measurement_protocol") != TASK094_RESOURCE_PROTOCOL:
        reasons.append("任务-000094资源测量协议不匹配")
    if resource_facts.get("measurement_platform") != TASK094_RESOURCE_PLATFORM:
        reasons.append("任务-000094资源测量平台不匹配")
    if resource_facts.get("rss_unit") != "bytes":
        reasons.append("任务-000094资源测量单位不匹配")
    if resource_facts.get("process_topology") != [
        "python_controller",
        "fixed_clang_compile",
        "fixed_unzip",
        "fixed_scanner",
    ]:
        reasons.append("任务-000094进程拓扑不匹配")
    if resource_facts.get("members_parallelism") != 1:
        reasons.append("任务-000094成员扫描不是串行")
    values = [
        resource_facts.get("controller_max_rss_bytes"),
        resource_facts.get("compiler_max_rss_bytes"),
        resource_facts.get("unzip_max_rss_bytes"),
        resource_facts.get("scanner_max_rss_bytes"),
        resource_facts.get("children_conservative_sum_max_rss_bytes"),
        resource_facts.get("conservative_process_group_max_rss_bytes"),
    ]
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in values
    ):
        reasons.append("任务-000094进程组RSS事实无效")
    else:
        controller, compiler, unzip, scanner, children, total = values
        if compiler + unzip + scanner != children:
            reasons.append("任务-000094子进程RSS保守和不守恒")
        if controller + children != total:
            reasons.append("任务-000094进程组RSS保守和不守恒")
        if total > TASK094_RESOURCE_LIMIT_BYTES:
            reasons.append("任务-000094进程组RSS超过512MiB")
    return tuple(reasons)


def _task094_contract_digest(text: str) -> str | None:
    """按运行元数据之外的固定任务合同计算任务-000094指纹。"""

    lines = text.splitlines()
    try:
        body_start = lines.index("## 依赖与阻塞条件")
    except ValueError:
        return None
    try:
        body_end = lines.index("## 执行记录", body_start + 1)
    except ValueError:
        body_end = len(lines)
    header = [
        line
        for line in lines[:body_start]
        if any(line.startswith(prefix) for prefix in TASK094_CONTRACT_HEADER_PREFIXES)
    ]
    if len(header) != len(TASK094_CONTRACT_HEADER_PREFIXES):
        return None
    canonical = (
        "\n".join(header + [""] + lines[body_start:body_end]).rstrip() + "\n"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sha256_path_fact(
    path_facts: Mapping[str, PathFact], path: str
) -> str | None:
    fact = path_facts.get(path)
    if (
        fact is None
        or fact.status not in {"A", "M"}
        or not isinstance(fact.text, str)
    ):
        return None
    return hashlib.sha256(fact.text.encode("utf-8")).hexdigest()
IMPLEMENTATION_SHA_PATTERN = re.compile(
    r"^- 实现提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
MERGE_SHA_PATTERN = re.compile(
    r"^- 合并提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
MERGE_TIME_PATTERN = re.compile(
    r"^- 合并时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
DELIVERY_SHA_PATTERN = re.compile(
    r"^- 交付提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
PULL_REQUEST_PATTERN = re.compile(
    r"^- Pull Request：\[#(\d+)\]\(https://github\.com/xk320/zhishi/pull/\1\)$",
    re.MULTILINE,
)
CANCELLATION_TIME_PATTERN = re.compile(
    r"^- 取消时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
CANCELLATION_REASON_PATTERN = re.compile(
    r"^- 取消原因：([^|\r\n]+)$", re.MULTILINE
)
CANCELLATION_SUPPORT_TASK_PATTERN = re.compile(
    r"^- 取消依据任务：任务-(\d{6})$", re.MULTILINE
)
CANCELLATION_PR_PATTERN = re.compile(
    r"^- 取消依据PR：\[#(\d+)\]\(https://github\.com/xk320/zhishi/pull/\1\)$",
    re.MULTILINE,
)
CANCELLATION_MERGE_TIME_PATTERN = re.compile(
    r"^- 取消依据合并时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
CANCELLATION_MERGE_SHA_PATTERN = re.compile(
    r"^- 取消依据合并提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
DEPENDENCY_PATTERN = re.compile(r"^- 唯一前序依赖：任务-(\d{6})(?:[^\r\n]*)$", re.MULTILINE)
TASK_REFERENCE_LINE = re.compile(
    r"^\s*-\s*任务-(\d{6})(?:\s*[（(][^\r\n]*[）)])?\s*$"
)
CHANGE_TYPES = frozenset(
    {
        "任务登记",
        "任务交付",
        "合并后状态闭环",
        "阻塞任务合同修复",
        CONTRACT_CONFLICT_REPAIR_TYPE,
        STAGE1_CONTRACT_REPAIR_TYPE,
        STAGE1_COVERAGE_V2_TYPE,
    }
)
REGISTRATION_STATUSES = frozenset({"待执行", "阻塞"})
REQUIRED_TASK_FIELDS = (
    "状态",
    "类型",
    "阶段",
    "优先级",
    "执行方案",
    "方案状态",
    "执行授权",
    "并行规则",
)
REQUIRED_TASK_HEADINGS = (
    "依赖与阻塞条件",
    "背景",
    "任务目标",
    "固定执行方案",
    "默认工程决策",
    "允许停止条件",
    "输入合同",
    "输出合同",
    "工作范围",
    "不在范围",
    "安全边界",
    "验收标准",
    "验证命令",
    "完成定义",
)
HISTORICAL_MISSING_TASK_IDS = frozenset({"000026"})
REGISTRATION_BOARD_PATH = "docs/研发中心/看板.md"
REGISTRATION_DESIGN_PATTERN = re.compile(
    r"^docs/superpowers/specs/[^/]+-design\.md$"
)
STATE_CLOSURE_TRANSITIONS = frozenset(
    {
        ("待评审", "已完成"),
        ("待执行", "阻塞"),
        ("执行中", "阻塞"),
        ("需修复", "阻塞"),
        ("阻塞", "待执行"),
        ("阻塞", "需修复"),
        ("待执行", "已取消"),
        ("执行中", "已取消"),
        ("阻塞", "已取消"),
        ("待评审", "已取消"),
        ("需修复", "已取消"),
    }
)
BLOCKING_TRANSITIONS = frozenset(
    {
        ("待执行", "阻塞"),
        ("执行中", "阻塞"),
        ("需修复", "阻塞"),
    }
)
RECOVERY_TRANSITIONS = frozenset({("阻塞", "待执行"), ("阻塞", "需修复")})
CANCELLATION_TRANSITIONS = frozenset(
    {
        (old_status, "已取消")
        for old_status in ("待执行", "执行中", "阻塞", "待评审", "需修复")
    }
)
DELIVERY_BASE_STATUSES = frozenset({"待执行", "需修复"})
COMPLETION_MUTABLE_PREFIXES = (
    "- 状态：",
    "- 合并时间：",
    "- 合并提交SHA：",
)
CANCELLATION_MUTABLE_PREFIXES = (
    "- 状态：",
    "- 取消时间：",
    "- 取消原因：",
    "- 取消依据任务：",
    "- 取消依据PR：",
    "- 取消依据合并时间：",
    "- 取消依据合并提交SHA：",
)
MAX_CHANGED_FILES = 500
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_TOTAL_SIZE = 25 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_LENGTH = 4096
MAX_BASE_TASK_TREE_BYTES = 4 * 1024 * 1024
MAX_BASE_TASK_COUNT = 10000
SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(
        r"(?<![\w])(?:"
        r'"(?:password|passwd|secret|token|client_secret|api_key|access_key|'
        r'account_id|account_number|wallet_address|endpoint|base_url|production_url|'
        r'url|rpc_url|rpc_endpoint|host|websocket_url|ws_url)"|'
        r"'(?:password|passwd|secret|token|client_secret|api_key|access_key|"
        r"account_id|account_number|wallet_address|endpoint|base_url|production_url|"
        r"url|rpc_url|rpc_endpoint|host|websocket_url|ws_url)'|"
        r"(?:password|passwd|secret|token|client_secret|api_key|access_key|"
        r"account_id|account_number|wallet_address|endpoint|base_url|production_url|"
        r"url|rpc_url|rpc_endpoint|host|websocket_url|ws_url)"
        r")\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,}\]\r\n#]+)",
        re.IGNORECASE,
    ),
)
CONTROLLED_PATH_DENY_STEMS = frozenset(
    {
        "交易",
        "真实交易",
        "交易执行",
        "部署",
        "生产",
        "生产环境",
        "凭据",
        "密钥",
        "账户",
        "真实账户",
        "数据库",
        "数据库导出",
        "原始",
        "原始数据",
        "deploy",
        "deployment",
        "production",
        "prod",
        "trading",
        "trade",
        "order",
        "orders",
        "live",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "key",
        "keys",
        "token",
        "tokens",
        "password",
        "passwd",
        "account",
        "accounts",
        "database",
        "databases",
        "db",
        "raw",
    }
)
DOUBLE_QUOTED_KEY_PATTERN = re.compile(
    r'"(?P<key>(?:\\.|[^"\\\r\n])*)"(?P<suffix>\s*[:=])'
)


@dataclass(frozen=True)
class EligibilityResult:
    """自动合并资格判定结果。"""

    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MergeFact:
    """main中已验证的真实合并事实。"""

    sha: str
    merged_at: str
    pr_number: int


@dataclass(frozen=True)
class PathFact:
    """PR头提交中单个变更路径的已验证事实。"""

    path: str
    status: str
    mode: str
    object_type: str
    size: int
    text: str | None


@dataclass(frozen=True)
class _PathObjectMetadata:
    """Git对象正文读取前的有界元数据。"""

    path: str
    status: str
    mode: str
    object_type: str
    oid: str
    size: int


def _task_field(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _markdown_section(text: str, heading: str) -> tuple[str, ...]:
    """读取唯一的CommonMark ATX二级标题区段。"""

    lines = text.splitlines()
    locations: list[int] = []
    for index, line in enumerate(lines):
        parsed = _commonmark_atx_heading(line)
        if parsed == (2, heading):
            locations.append(index)
    if len(locations) != 1:
        return ()
    start = locations[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        parsed = _commonmark_atx_heading(lines[index])
        if parsed is not None and parsed[0] <= 2:
            end = index
            break
    return tuple(lines[start:end])


def _commonmark_atx_heading(line: str) -> tuple[int, str] | None:
    """规范化CommonMark ATX标题的级别和文本。"""

    match = re.fullmatch(
        r" {0,3}(?P<marks>#{1,6})(?:[ \t]+(?P<text>.*)|[ \t]*)",
        line,
    )
    if match is None:
        return None
    text = (match.group("text") or "").rstrip(" \t")
    closing = re.search(r"[ \t]+#+$", text)
    if closing is not None:
        text = text[: closing.start()].rstrip(" \t")
    return len(match.group("marks")), text


def _second_level_heading_count(text: str, heading: str) -> int:
    return sum(
        _commonmark_atx_heading(line) == (2, heading)
        for line in text.splitlines()
    )


def parse_task_references(pr_body: str) -> tuple[str, ...]:
    """只解析PR正文严格的“关联任务”二级标题区段。"""

    task_ids: list[str] = []
    for line in _markdown_section(pr_body, "关联任务"):
        match = TASK_REFERENCE_LINE.fullmatch(line)
        if match is not None and match.group(1) not in task_ids:
            task_ids.append(match.group(1))
    return tuple(sorted(task_ids))


def _raw_task_references(pr_body: str) -> tuple[str, ...]:
    """保留严格关联任务区段的原始顺序和重复项。"""

    return tuple(
        match.group(1)
        for line in _markdown_section(pr_body, "关联任务")
        if (match := TASK_REFERENCE_LINE.fullmatch(line)) is not None
    )


def parse_change_type(pr_body: str) -> str | None:
    """读取严格、唯一的PR变更类型。"""

    values = [
        line.strip()[2:].strip()
        for line in _markdown_section(pr_body, "变更类型")
        if line.strip().startswith("- ")
    ]
    valid = [value for value in values if value in CHANGE_TYPES]
    return valid[0] if len(valid) == 1 and len(values) == 1 else None


def _task_reference_limit(change_type: str | None) -> int:
    return 2 if change_type in {
        "合并后状态闭环",
        BLOCKED_CONTRACT_REPAIR_TYPE,
        CONTRACT_CONFLICT_REPAIR_TYPE,
    } else 1


def _task_reference_limit_reason(change_type: str | None) -> str:
    label = change_type or "未知变更类型"
    return f"{label}最多关联{_task_reference_limit(change_type)}个任务"


def parse_nul_paths(output: bytes) -> tuple[str, ...]:
    """解析Git NUL分隔路径，避免中文路径被quotePath转义。"""

    paths: list[str] = []
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        paths.append(raw_path.decode("utf-8", errors="strict"))
    return tuple(paths)


def _stop_git_process(process: subprocess.Popen[bytes]) -> None:
    """停止Git子进程并回收，不留下管道或僵尸进程。"""

    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _read_nul_field(stream: BinaryIO, max_bytes: int) -> bytes | None:
    value = bytearray()
    while True:
        byte = stream.read(1)
        if byte == b"":
            if value:
                raise ValueError("Git NUL输出不完整")
            return None
        if byte == b"\0":
            return bytes(value)
        value.extend(byte)
        if len(value) > max_bytes:
            raise ValueError("Git NUL字段超出上限")


def _stream_diff_entries(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
) -> tuple[tuple[str, str], ...]:
    process = subprocess.Popen(
        [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            base_ref,
            head_ref,
            "--",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        _stop_git_process(process)
        raise ValueError("Git变更输出无法读取")
    entries: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    try:
        while True:
            raw_status = _read_nul_field(process.stdout, 16)
            if raw_status is None:
                break
            raw_path = _read_nul_field(process.stdout, MAX_PATH_BYTES)
            if raw_path is None:
                raise ValueError("Git变更路径输出不完整")
            status = raw_status.decode("ascii", errors="strict")
            path = raw_path.decode("utf-8", errors="strict")
            if (
                status not in {"A", "M", "D"}
                or not path
                or len(path) > MAX_PATH_LENGTH
                or path in seen_paths
            ):
                raise ValueError("Git变更路径输出无效")
            seen_paths.add(path)
            entries.append((status, path))
            if len(entries) > MAX_CHANGED_FILES:
                raise ValueError("变更文件数超过500")
        if process.wait() != 0:
            raise ValueError("Git变更命令执行失败")
        return tuple(entries)
    finally:
        _stop_git_process(process)
        process.stdout.close()


def _read_git_output_bounded(
    repo_root: Path,
    arguments: Sequence[str],
    max_bytes: int,
    *,
    literal_paths: bool = False,
) -> bytes:
    environment = None
    if literal_paths:
        environment = os.environ.copy()
        environment["GIT_LITERAL_PATHSPECS"] = "1"
    process = subprocess.Popen(
        ["git", *arguments],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    if process.stdout is None:
        _stop_git_process(process)
        raise ValueError("Git命令输出无法读取")
    try:
        output = process.stdout.read(max_bytes + 1)
        if len(output) > max_bytes:
            raise ValueError("Git命令输出超出上限")
        if process.wait() != 0:
            raise ValueError("Git命令执行失败")
        return output
    finally:
        _stop_git_process(process)
        process.stdout.close()


def _load_object_metadata_batch(
    repo_root: Path,
    head_ref: str,
    entries: Sequence[tuple[str, str]],
) -> tuple[_PathObjectMetadata, ...]:
    present_entries = tuple(
        (status, path) for status, path in entries if status in {"A", "M"}
    )
    if not present_entries:
        return ()
    paths = tuple(path for _, path in present_entries)
    tree_output = _read_git_output_bounded(
        repo_root,
        ["ls-tree", "-z", head_ref, "--", *paths],
        len(paths) * (MAX_PATH_BYTES + 256),
        literal_paths=True,
    )
    records = tuple(record for record in tree_output.split(b"\0") if record)
    if len(records) != len(paths):
        raise ValueError("Git路径对象数量不匹配")

    tree_by_path: dict[str, tuple[str, str, str]] = {}
    expected_paths = set(paths)
    for record in records:
        try:
            raw_metadata, raw_path = record.split(b"\t", 1)
            mode_bytes, type_bytes, oid_bytes = raw_metadata.split(b" ")
            mode = mode_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
            oid = oid_bytes.decode("ascii", errors="strict")
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Git路径对象元数据无效") from error
        if (
            path not in expected_paths
            or path in tree_by_path
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid) is None
        ):
            raise ValueError("Git路径对象元数据不匹配")
        tree_by_path[path] = (mode, object_type, oid)
    if set(tree_by_path) != expected_paths:
        raise ValueError("Git路径对象缺失或额外")

    unique_oids = tuple(
        dict.fromkeys(tree_by_path[path][2] for path in paths)
    )
    batch_input = b"".join(oid.encode("ascii") + b"\n" for oid in unique_oids)
    batch_result = subprocess.run(
        [
            "git",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        input=batch_input,
    )
    if batch_result.returncode != 0:
        raise ValueError("Git对象元数据批量读取失败")
    batch_lines = batch_result.stdout.splitlines()
    if len(batch_lines) != len(unique_oids):
        raise ValueError("Git对象元数据数量不匹配")

    object_facts: dict[str, tuple[str, int]] = {}
    for expected_oid, line in zip(unique_oids, batch_lines, strict=True):
        try:
            oid_bytes, type_bytes, size_bytes = line.split(b" ")
            oid = oid_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Git对象元数据无效") from error
        if (
            oid != expected_oid
            or oid in object_facts
            or re.fullmatch(rb"[0-9]+", size_bytes) is None
        ):
            raise ValueError("Git对象元数据不匹配")
        object_facts[oid] = (object_type, int(size_bytes))

    metadata: list[_PathObjectMetadata] = []
    for status, path in present_entries:
        mode, tree_type, oid = tree_by_path[path]
        batch_type, size = object_facts[oid]
        if tree_type != batch_type:
            raise ValueError("Git对象类型不一致")
        metadata.append(
            _PathObjectMetadata(
                path=path,
                status=status,
                mode=mode,
                object_type=tree_type,
                oid=oid,
                size=size,
            )
        )
    return tuple(metadata)


def _read_blob_bounded(repo_root: Path, oid: str, expected_size: int) -> bytes:
    process = subprocess.Popen(
        ["git", "cat-file", "blob", oid],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise ValueError("Git对象正文无法读取")
    with process.stdout:
        content = process.stdout.read(expected_size + 1)
    if len(content) > expected_size:
        process.kill()
        process.wait()
        raise ValueError("Git对象正文超出已验证大小")
    return_code = process.wait()
    if return_code != 0 or len(content) != expected_size:
        raise ValueError("Git对象正文与元数据不一致")
    return content


def _load_path_facts(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
) -> tuple[PathFact, ...]:
    """从Git对象读取路径事实，资源门通过前不读取正文。"""

    entries = _stream_diff_entries(repo_root, base_ref, head_ref)
    metadata = _load_object_metadata_batch(repo_root, head_ref, entries)
    deleted_paths = {path for status, path in entries if status == "D"}

    total_size = sum(item.size for item in metadata)
    resource_limit_exceeded = (
        len(entries) > MAX_CHANGED_FILES
        or any(item.size > MAX_FILE_SIZE for item in metadata)
        or total_size > MAX_TOTAL_SIZE
    )
    metadata_by_path = {item.path: item for item in metadata}
    facts: list[PathFact] = []
    for status, path in entries:
        if path in deleted_paths:
            facts.append(
                PathFact(
                    path=path,
                    status=status,
                    mode="000000",
                    object_type="missing",
                    size=0,
                    text=None,
                )
            )
            continue
        item = metadata_by_path[path]
        text: str | None = None
        if not resource_limit_exceeded and item.object_type == "blob":
            content = _read_blob_bounded(repo_root, item.oid, item.size)
            try:
                text = content.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                text = None
        facts.append(
            PathFact(
                path=path,
                status=item.status,
                mode=item.mode,
                object_type=item.object_type,
                size=item.size,
                text=text,
            )
        )
    return tuple(facts)


def _is_low_risk_path(path: str) -> bool:
    if path in ALLOWED_ROOT_MARKDOWN:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) > 1
        and pure_path.parts[0] == "docs"
        and pure_path.suffix == ".md"
    )


def _is_automation_path(path: str) -> bool:
    if _is_low_risk_path(path) or path in AUTOMATION_FILES:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) == 3
        and pure_path.parts[0] in {"scripts", "tests"}
        and pure_path.parts[1] == "研发中心"
        and pure_path.suffix == ".py"
    )


def _is_governance_control_path(path: str) -> bool:
    """识别只有治理自动化任务才能修改的可信控制面路径。"""

    if path in AUTOMATION_FILES or path in GOVERNANCE_CONTROL_PATHS:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) == 3
        and pure_path.parts[0] == "scripts"
        and pure_path.parts[1] == "研发中心"
        and pure_path.suffix.lower() == ".py"
    )


def _is_controlled_rd_path(path: str) -> bool:
    if path in ALLOWED_ROOT_MARKDOWN:
        return True
    pure_path = PurePosixPath(path)
    if (
        pure_path.is_absolute()
        or any(part in {".", ".."} for part in path.split("/"))
        or len(pure_path.parts) <= 1
    ):
        return False
    root = pure_path.parts[0]
    suffix = pure_path.suffix.lower()
    for part in pure_path.parts[1:]:
        stem = PurePosixPath(part).stem.casefold()
        if stem not in CONTROLLED_PATH_DENY_STEMS and part.casefold() not in CONTROLLED_PATH_DENY_STEMS:
            continue
        return False
    if root == "docs":
        return suffix == ".md"
    if root == "config":
        return suffix in {".json", ".yaml", ".yml", ".toml"}
    if root == "src":
        return suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}
    if root == "scripts":
        return (
            not any(
                part in {"交易", "部署", "生产"}
                for part in pure_path.parts[1:-1]
            )
            and suffix in {".py", ".sh"}
        )
    if root == "tests":
        return suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}
    if root == "artifacts":
        return suffix in {".json", ".csv", ".md"}
    return False


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _normalize_double_quoted_keys(text: str) -> str | None:
    """仅规范化配置键中严格的Unicode码点转义。"""

    invalid = False

    def replace(match: re.Match[str]) -> str:
        nonlocal invalid
        key = match.group("key")
        normalized: list[str] = []
        index = 0
        while index < len(key):
            character = key[index]
            if character != "\\":
                normalized.append(character)
                index += 1
                continue
            if index + 1 >= len(key):
                invalid = True
                return match.group(0)
            marker = key[index + 1]
            if marker not in {"x", "u", "U"}:
                normalized.extend((character, marker))
                index += 2
                continue
            digit_count = {"x": 2, "u": 4, "U": 8}[marker]
            digits_start = index + 2
            digits_end = digits_start + digit_count
            digits = key[digits_start:digits_end]
            if (
                len(digits) != digit_count
                or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None
            ):
                invalid = True
                return match.group(0)
            codepoint = int(digits, 16)
            if (
                codepoint > 0x10FFFF
                or 0xD800 <= codepoint <= 0xDFFF
            ):
                invalid = True
                return match.group(0)
            decoded = chr(codepoint)
            if not decoded.isprintable():
                invalid = True
                return match.group(0)
            normalized.append(decoded)
            index = digits_end
        normalized_key = "".join(normalized)
        if not all(character.isprintable() for character in normalized_key):
            invalid = True
            return match.group(0)
        return f'"{normalized_key}"{match.group("suffix")}'

    normalized_text = DOUBLE_QUOTED_KEY_PATTERN.sub(replace, text)
    return None if invalid else normalized_text


def _contains_sensitive_text(text: str) -> bool:
    if any(pattern.search(text) for pattern in SENSITIVE_TEXT_PATTERNS):
        return True
    normalized = _normalize_double_quoted_keys(text)
    if normalized is None:
        return True
    return any(pattern.search(normalized) for pattern in SENSITIVE_TEXT_PATTERNS)


def _contains_unsafe_text(text: str) -> bool:
    """拒绝NUL和不可打印控制字符，避免把二进制伪装成UTF-8文本。"""

    return any(
        (ord(character) < 32 and character not in "\t\n\r")
        or 0x7F <= ord(character) <= 0x9F
        for character in text
    )


def _validate_path_facts(
    changed_paths: Sequence[str],
    path_facts: Sequence[PathFact] | None,
) -> tuple[str, ...]:
    """验证路径事实的完整性、Git对象、资源与敏感内容硬门。"""

    if path_facts is None:
        return ("PR缺少可验证的路径事实",)

    reasons: list[str] = []
    fact_paths = [fact.path for fact in path_facts]
    if (
        len(changed_paths) != len(set(changed_paths))
        or len(fact_paths) != len(set(fact_paths))
        or set(fact_paths) != set(changed_paths)
    ):
        _append_reason(reasons, "路径事实与变更路径不一致")

    if len(path_facts) > MAX_CHANGED_FILES:
        _append_reason(reasons, "变更文件数超过500")

    total_size = 0
    for fact in path_facts:
        valid_size = (
            isinstance(fact.size, int)
            and not isinstance(fact.size, bool)
            and fact.size >= 0
        )
        if (
            fact.status not in {"A", "M"}
            or fact.mode != "100644"
            or fact.object_type != "blob"
            or not valid_size
        ):
            _append_reason(reasons, "路径事实不允许自动合并")
        if valid_size:
            total_size += fact.size
            if fact.size > MAX_FILE_SIZE:
                _append_reason(reasons, "单个文件超过5MiB")
        if not isinstance(fact.text, str):
            _append_reason(reasons, "路径事实缺少可扫描文本")
        elif _contains_unsafe_text(fact.text):
            _append_reason(reasons, "变更文本不是安全文本")
        elif _contains_sensitive_text(fact.text):
            _append_reason(reasons, "变更文本包含敏感内容")
        if fact.path.startswith("artifacts/") and fact.status != "A":
            _append_reason(reasons, "不可变证据产物必须新增且不得修改")

    if total_size > MAX_TOTAL_SIZE:
        _append_reason(reasons, "变更总量超过25MiB")
    return tuple(reasons)


def _validate_task094_batch_resource_evidence(
    path_facts: Sequence[PathFact] | None, reasons: list[str]
) -> None:
    """从最终头文件复验批次身份、生成器绑定与进程组资源硬门。"""

    if path_facts is None:
        _append_reason(reasons, "任务-000094缺少可验证批次路径事实")
        return
    summaries = [
        fact
        for fact in path_facts
        if fact.status == "A"
        and fact.path.startswith("artifacts/审计/阶段1逐行时间质量/")
        and fact.path.endswith("/summary.json")
    ]
    if len(summaries) != 1 or not isinstance(summaries[0].text, str):
        _append_reason(reasons, "任务-000094必须新增唯一最终批次摘要")
        return
    try:
        document = json.loads(
            summaries[0].text,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        _append_reason(reasons, "任务-000094最终批次摘要无效")
        return
    if not isinstance(document, Mapping):
        _append_reason(reasons, "任务-000094最终批次摘要无效")
        return
    summary_path = PurePosixPath(summaries[0].path)
    batch_id = summary_path.parent.name
    if document.get("batch_id") != batch_id:
        _append_reason(reasons, "任务-000094批次身份与摘要路径不一致")

    facts_by_path = {fact.path: fact for fact in path_facts}
    bindings = {
        "executor_sha256": _sha256_path_fact(facts_by_path, TASK094_EXECUTOR_PATH),
        "config_sha256": _sha256_path_fact(facts_by_path, TASK094_CONFIG_PATH),
        "scanner_source_sha256": _sha256_path_fact(
            facts_by_path, TASK094_NATIVE_SCANNER_PATH
        ),
    }
    task_fact = facts_by_path.get(TASK094_TASK_PATH)
    bindings["task_contract_sha256"] = (
        _task094_contract_digest(task_fact.text)
        if task_fact is not None and isinstance(task_fact.text, str)
        else None
    )
    for field, expected in bindings.items():
        if expected is None:
            _append_reason(reasons, f"任务-000094资源证据缺少可信{field}来源")
        elif document.get(field) != expected:
            _append_reason(reasons, f"任务-000094资源证据{field}未绑定最终头文件")
    for reason in _task094_resource_fact_reasons(document.get("process_group_resource_facts")):
        _append_reason(reasons, reason)


def _without_mutable_metadata_lines(
    text: str, prefixes: Sequence[str]
) -> tuple[str, ...]:
    """只移除任务头部允许变化的唯一元数据行。"""

    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    return tuple(
        line
        for index, line in enumerate(lines)
        if not (
            index < first_section
            and any(line.startswith(prefix) for prefix in prefixes)
        )
    )


def _has_unique_metadata_fields(
    text: str,
    expected_counts: Mapping[str, int],
) -> bool:
    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    for prefix, expected_count in expected_counts.items():
        locations = [
            index for index, line in enumerate(lines) if line.startswith(prefix)
        ]
        if len(locations) != expected_count or any(
            index >= first_section for index in locations
        ):
            return False
    return True


def _successor_mutable_layout(
    text: str, *, allow_missing_dependency_release: bool = False,
) -> tuple[str, int, int, int] | None:
    """定位后继字段的固定任务头或依赖章节布局。"""

    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )

    def locations(prefix: str) -> list[int]:
        return [
            index
            for index, line in enumerate(lines)
            if line.startswith(prefix)
        ]

    status_locations = locations("- 状态：")
    if len(status_locations) != 1 or status_locations[0] >= first_section:
        return None
    blocker_locations = locations("- 当前阻塞原因：")
    release_locations = locations("- 解除条件：")
    record_starts = [
        index for index, line in enumerate(lines) if line == "## 执行记录"
    ]
    if len(record_starts) > 1:
        return None
    record_start = record_starts[0] if record_starts else len(lines)
    record_end = next(
        (
            index
            for index in range(record_start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )

    def in_record(index: int) -> bool:
        return record_start < index < record_end

    header_blockers = [index for index in blocker_locations if index < first_section]
    header_releases = [index for index in release_locations if index < first_section]
    if (
        len(header_blockers) == 1
        and len(header_releases) == 1
        and all(in_record(index) or index < first_section for index in blocker_locations)
        and all(in_record(index) or index < first_section for index in release_locations)
    ):
        return "header", first_section, -1, first_section

    section_headings = [
        index
        for index, line in enumerate(lines)
        if line.strip() == "## 依赖与阻塞条件"
    ]
    if len(section_headings) != 1:
        return None
    section_start = section_headings[0]
    section_end = next(
        (
            index
            for index in range(section_start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    section_blockers = [
        index for index in blocker_locations if section_start < index < section_end
    ]
    section_releases = [
        index for index in release_locations if section_start < index < section_end
    ]
    allowed_release_counts = (
        {0, 1} if allow_missing_dependency_release else {1}
    )
    if (
        len(section_blockers) != 1
        or len(section_releases) not in allowed_release_counts
        or not all(in_record(index) or section_start < index < section_end for index in blocker_locations)
        or not all(in_record(index) or section_start < index < section_end for index in release_locations)
    ):
        return None
    if section_releases and not lines[section_releases[0]].split("：", 1)[1].strip():
        return None
    return "dependency_section", first_section, section_start, section_end


def _without_successor_mutable_lines(
    text: str, *, allow_missing_dependency_release: bool = False
) -> tuple[str, ...]:
    """移除已验证位置中的后继状态、阻塞原因与解除条件。"""

    layout = _successor_mutable_layout(
        text,
        allow_missing_dependency_release=allow_missing_dependency_release,
    )
    if layout is None:
        return tuple(text.splitlines())
    kind, first_section, section_start, section_end = layout
    return tuple(
        line
        for index, line in enumerate(text.splitlines())
        if not (
            (index < first_section and line.startswith("- 状态："))
            or (
                (
                    index < first_section
                    if kind == "header"
                    else section_start < index < section_end
                )
                and line.startswith(("- 当前阻塞原因：", "- 解除条件："))
            )
        )
    )


BLOCKING_RECORD_FIELDS = (
    "- 执行分支：",
    "- 开始时间：",
    "- 尝试命令：",
    "- 结果：",
    "- 外部证据：",
    "- 阻塞原因：",
    "- 解除条件：",
    "- 数据与安全：",
)
ALLOWED_BLOCKING_ALIASES = frozenset({"ubuntu"})
BLOCKING_HOSTNAME_PATTERN = re.compile(
    r"(?<![\w-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])"
)
BLOCKING_URL_PATTERN = re.compile(r"\b(?:https?|ssh)://", re.IGNORECASE)
BLOCKING_IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _section_bounds(text: str, heading: str) -> tuple[int, int] | None:
    """返回唯一二级章节的行范围；重复或缺失均失败关闭。"""

    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == heading]
    if len(starts) != 1:
        return None
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    return start, end


def _blocking_record(text: str) -> tuple[str, ...] | None:
    """验证阻塞执行记录只包含固定的脱敏字段。"""

    bounds = _section_bounds(text, "## 执行记录")
    if bounds is None:
        return None
    start, end = bounds
    lines = text.splitlines()[start + 1 : end]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return None
    locations = {
        prefix: [index for index, line in enumerate(lines) if line.startswith(prefix)]
        for prefix in BLOCKING_RECORD_FIELDS
    }
    if any(len(indexes) != 1 for indexes in locations.values()):
        return None
    if any(
        not line.startswith(BLOCKING_RECORD_FIELDS)
        for line in lines
        if line.strip()
    ):
        return None
    return tuple(lines)


def _blocking_record_aliases_allowed(record: tuple[str, ...]) -> bool:
    """阻塞记录只允许固定SSH逻辑别名，不允许主机地址或URL。"""

    for line in record:
        if (
            BLOCKING_HOSTNAME_PATTERN.search(line)
            or BLOCKING_URL_PATTERN.search(line)
            or BLOCKING_IPV4_PATTERN.search(line)
        ):
            return False
        if not line.startswith("- 尝试命令："):
            continue
        command = line.split("：", 1)[1].strip()
        if command.startswith("`") and command.endswith("`"):
            command = command[1:-1]
        try:
            tokens = shlex.split(command)
        except ValueError:
            return False
        if "ssh" not in tokens:
            continue
        ssh_index = tokens.index("ssh")
        target = None
        index = ssh_index + 1
        while index < len(tokens):
            arg_value = tokens[index]
            if arg_value == "-o":
                index += 2
                continue
            if arg_value.startswith("-"):
                index += 1
                continue
            target = arg_value
            break
        if target not in ALLOWED_BLOCKING_ALIASES:
            return False
    return True


def _header_field_line(text: str, prefix: str) -> str | None:
    """读取任务头部唯一字段，忽略执行记录中的同名字段。"""

    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    matches = [
        line
        for index, line in enumerate(lines)
        if index < first_section and line.startswith(prefix)
    ]
    return matches[0] if len(matches) == 1 else None


def _without_blocking_mutable_lines(
    text: str, *, allow_initial_metadata: bool,
    allow_missing_dependency_release: bool = False,
) -> tuple[str, ...]:
    """移除阻塞迁移允许变化的状态字段和首次执行元数据。"""

    lines = list(
        _without_successor_mutable_lines(
            text,
            allow_missing_dependency_release=allow_missing_dependency_release,
        )
    )
    if not allow_initial_metadata:
        return tuple(lines)
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    filtered: list[str] = []
    skip_record = False
    for index, line in enumerate(lines):
        if index < first_section and line.startswith(("- 执行分支：", "- 开始时间：")):
            continue
        if line == "## 执行记录":
            skip_record = True
            continue
        if skip_record:
            if line.startswith("## "):
                skip_record = False
                filtered.append(line)
            continue
        filtered.append(line)
    while filtered and not filtered[-1].strip():
        filtered.pop()
    return tuple(filtered)


def _validate_blocking_transition(
    *, base_task: str, head_task: str, old_status: str, reasons: list[str]
) -> None:
    """校验进入阻塞时的字段位置、不可变合同和首次执行记录。"""

    baseline_has_execution_metadata = any(
        (
            _header_field_line(base_task, "- 开始时间：") is not None,
            _section_bounds(base_task, "## 执行记录") is not None,
        )
    )
    allow_initial_metadata = (
        old_status == "待执行" and not baseline_has_execution_metadata
    )
    allow_missing_dependency_release = (
        allow_initial_metadata
        and _header_field_line(base_task, "- 执行分支：") is None
    )
    base_layout = _successor_mutable_layout(
        base_task,
        allow_missing_dependency_release=allow_missing_dependency_release,
    )
    head_layout = _successor_mutable_layout(head_task)
    if (
        base_layout is None
        or head_layout is None
        or base_layout[0] != head_layout[0]
    ):
        _append_reason(reasons, "阻塞状态闭环字段位置无效")
        return
    if _without_blocking_mutable_lines(
        base_task,
        allow_initial_metadata=allow_initial_metadata,
        allow_missing_dependency_release=allow_missing_dependency_release,
    ) != _without_blocking_mutable_lines(
        head_task, allow_initial_metadata=allow_initial_metadata
    ):
        _append_reason(reasons, "阻塞状态闭环夹带合同改写")
    branch = _header_field_line(head_task, "- 执行分支：")
    start = _header_field_line(head_task, "- 开始时间：")
    if (
        branch is None
        or EXECUTION_BRANCH_PATTERN.fullmatch(branch) is None
        or start is None
        or START_TIME_PATTERN.fullmatch(start) is None
    ):
        _append_reason(reasons, "阻塞状态闭环缺少执行分支或开始时间")
    if allow_initial_metadata:
        head_record = _blocking_record(head_task)
        if head_record is None:
            _append_reason(reasons, "首次阻塞必须包含固定结构化执行记录")
        elif not _blocking_record_aliases_allowed(head_record):
            _append_reason(reasons, "阻塞执行记录包含未批准的外部目标")
    else:
        base_record = _blocking_record(base_task)
        head_record = _blocking_record(head_task)
        if base_record is None or head_record is None:
            _append_reason(reasons, "阻塞状态闭环缺少既有结构化执行记录")
        elif base_record != head_record:
            _append_reason(reasons, "阻塞状态闭环改写既有执行记录")
        elif not _blocking_record_aliases_allowed(head_record):
            _append_reason(reasons, "阻塞执行记录包含未批准的外部目标")


def _validate_recovery_transition(
    *, base_task: str, head_task: str, reasons: list[str]
) -> None:
    """校验阻塞恢复为待执行或需修复时只改变状态字段。"""

    base_layout = _successor_mutable_layout(base_task)
    head_layout = _successor_mutable_layout(head_task)
    if (
        base_layout is None
        or head_layout is None
        or base_layout[0] != head_layout[0]
    ):
        _append_reason(reasons, "阻塞恢复状态闭环字段位置无效")
        return
    if _without_successor_mutable_lines(base_task) != _without_successor_mutable_lines(
        head_task
    ):
        _append_reason(reasons, "阻塞恢复状态闭环夹带合同改写")


def _task_merge_fact(text: str) -> MergeFact | None:
    sha_match = MERGE_SHA_PATTERN.search(text)
    time_match = MERGE_TIME_PATTERN.search(text)
    pr_match = PULL_REQUEST_PATTERN.search(text)
    if sha_match is None or time_match is None or pr_match is None:
        return None
    return MergeFact(
        sha=sha_match.group(1),
        merged_at=time_match.group(1),
        pr_number=int(pr_match.group(1)),
    )


def _task_cancellation_fact(text: str) -> MergeFact | None:
    """读取取消状态引用的、已进入main的替代合并事实。"""

    sha_match = CANCELLATION_MERGE_SHA_PATTERN.search(text)
    time_match = CANCELLATION_MERGE_TIME_PATTERN.search(text)
    pr_match = CANCELLATION_PR_PATTERN.search(text)
    if sha_match is None or time_match is None or pr_match is None:
        return None
    return MergeFact(
        sha=sha_match.group(1),
        merged_at=time_match.group(1),
        pr_number=int(pr_match.group(1)),
    )


def _cancellation_support_task_id(text: str) -> str | None:
    match = CANCELLATION_SUPPORT_TASK_PATTERN.search(text)
    return match.group(1) if match is not None else None


def _board_rows(text: str) -> dict[str, tuple[str, str]]:
    """读取看板中任务所在状态和完整行。"""

    current_section = ""
    rows: dict[str, tuple[str, str]] = {}
    duplicates: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
            continue
        match = BOARD_TASK_ROW_PATTERN.match(line)
        if match is None:
            continue
        task_id = match.group(1)
        if task_id in rows:
            duplicates.add(task_id)
        rows[task_id] = (current_section, line)
    for task_id in duplicates:
        rows[task_id] = ("重复", "")
    return rows


def _board_static_lines(text: str) -> tuple[str, ...]:
    """保留看板非表格、非空态的静态结构。"""

    static: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped == "无。"
            or BOARD_TASK_ROW_PATTERN.match(line)
        ):
            continue
        known_schema_lines = {
            schema_line
            for schema in BOARD_TABLE_SCHEMA.values()
            for schema_line in schema
        }
        if line in known_schema_lines:
            continue
        static.append(line)
    return tuple(static)


def _board_schema_is_valid(text: str) -> bool:
    current_section = ""
    seen_sections: set[str] = set()
    schema_counts: dict[str, dict[str, int]] = {}
    task_sections: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
            if current_section in REQUIRED_BOARD_SECTIONS:
                if current_section in seen_sections:
                    return False
                seen_sections.add(current_section)
            elif current_section not in BOARD_AUXILIARY_SECTIONS:
                return False
            continue
        if not line.startswith("|"):
            continue
        if BOARD_TASK_ROW_PATTERN.match(line):
            task_sections.add(current_section)
            continue
        schema = BOARD_TABLE_SCHEMA.get(current_section)
        if schema is None or line not in schema:
            return False
        counts = schema_counts.setdefault(current_section, {})
        counts[line] = counts.get(line, 0) + 1
    for section in task_sections:
        schema = BOARD_TABLE_SCHEMA.get(section)
        counts = schema_counts.get(section, {})
        if schema is None or any(counts.get(line) != 1 for line in schema):
            return False
    if any(section == "重复" for section, _ in _board_rows(text).values()):
        return False
    return (
        seen_sections == REQUIRED_BOARD_SECTIONS
        and all(
            count <= 1 for counts in schema_counts.values() for count in counts.values()
        )
    )


def _validate_board_closure(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    merge_facts: Mapping[str, MergeFact],
    reasons: list[str],
) -> None:
    if base_board is None or head_board is None:
        _append_reason(reasons, "合并后状态闭环缺少可复算看板")
        return
    if not _board_schema_is_valid(base_board) or not _board_schema_is_valid(head_board):
        _append_reason(reasons, "合并后状态闭环看板表格结构无效")
    if _board_static_lines(base_board) != _board_static_lines(head_board):
        _append_reason(reasons, "合并后状态闭环夹带看板结构改写")
    base_rows = _board_rows(base_board)
    head_rows = _board_rows(head_board)
    referenced = set(task_ids)
    for task_id, row in base_rows.items():
        if task_id not in referenced and head_rows.get(task_id) != row:
            _append_reason(reasons, f"看板夹带无关任务-{task_id}改写")
    for task_id, row in head_rows.items():
        if task_id not in referenced and base_rows.get(task_id) != row:
            _append_reason(reasons, f"看板夹带无关任务-{task_id}改写")
    for task_id in task_ids:
        task = head_tasks.get(task_id)
        row = head_rows.get(task_id)
        if task is None or row is None or row[0] == "重复":
            _append_reason(reasons, f"任务-{task_id}在看板中不是唯一映射")
            continue
        status = _task_field(TASK_STATUS_PATTERN, task)
        if row[0] != status:
            _append_reason(reasons, f"任务-{task_id}的看板状态与任务文件不一致")
            continue
        title = _task_field(TASK_TITLE_PATTERN, task)
        priority = _task_field(TASK_PRIORITY_PATTERN, task)
        if status == "已完成":
            fact = merge_facts.get(task_id)
            expected = (
                f"| 任务-{task_id} | {title} | PR #{fact.pr_number}；合并提交 `{fact.sha}` |"
                if title is not None and fact is not None
                else ""
            )
        elif status == "已取消":
            support_task_id = _cancellation_support_task_id(task)
            fact = (
                merge_facts.get(support_task_id)
                if support_task_id is not None
                else None
            )
            reason = _task_field(CANCELLATION_REASON_PATTERN, task)
            expected = (
                f"| 任务-{task_id} | {title} | 替代任务-{support_task_id}；"
                f"PR #{fact.pr_number}；合并提交 `{fact.sha}`；取消原因：{reason} |"
                if title is not None
                and support_task_id is not None
                and fact is not None
                and reason is not None
                else ""
            )
        elif status == "待执行":
            dependency = _task_field(DEPENDENCY_PATTERN, task)
            expected = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
                if title is not None and priority is not None and dependency is not None
                else ""
            )
        elif status == "阻塞":
            dependency = _task_field(DEPENDENCY_PATTERN, task)
            blocker = _task_field(BLOCKER_PATTERN, task)
            expected = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} | {blocker} |"
                if title is not None
                and priority is not None
                and dependency is not None
                and blocker is not None
                else ""
            )
        elif status == "需修复":
            branch = _task_field(EXECUTION_BRANCH_PATTERN, task)
            pr_match = PULL_REQUEST_PATTERN.search(task)
            pr_number = pr_match.group(1) if pr_match else None
            expected = (
                f"| {priority} | 任务-{task_id} | {title} | `{branch}` | "
                f"[#{pr_number}](https://github.com/xk320/zhishi/pull/{pr_number}) |"
                if title is not None
                and priority is not None
                and branch is not None
                and pr_number is not None
                else ""
            )
        else:
            expected = ""
        if row[1] != expected:
            _append_reason(reasons, f"任务-{task_id}的看板证据行不可复算")


def _validate_delivery_tasks(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    reasons: list[str],
) -> tuple[bool, bool]:
    automation_authorized = bool(task_ids)
    controlled_rd_authorized = bool(task_ids)
    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        if base_task is None:
            _append_reason(reasons, f"任务-{task_id}未在基线main中登记")
            automation_authorized = False
            controlled_rd_authorized = False
            continue
        task_type = _task_field(TASK_TYPE_PATTERN, base_task)
        if task_type is None:
            _append_reason(reasons, f"任务-{task_id}缺少任务类型")
        elif task_type not in ALLOWED_TASK_TYPES:
            _append_reason(
                reasons,
                f"任务-{task_id}类型“{task_type}”不允许自动合并",
            )
        if task_type not in CONTROLLED_RD_TASK_TYPES:
            controlled_rd_authorized = False
        base_status = _task_field(TASK_STATUS_PATTERN, base_task)
        if base_status not in DELIVERY_BASE_STATUSES:
            _append_reason(
                reasons,
                f"任务-{task_id}基线状态“{base_status}”不可进入任务交付",
            )
        if _task_field(AUTOMATION_SCOPE_PATTERN, base_task) != AUTOMATION_SCOPE:
            automation_authorized = False

        head_task = head_tasks.get(task_id)
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
        elif _task_field(TASK_STATUS_PATTERN, head_task) != "待评审":
            _append_reason(reasons, f"任务-{task_id}在PR中的状态不是“待评审”")
    return automation_authorized, controlled_rd_authorized


def _delivery_contract_without_metadata(text: str) -> tuple[str, ...]:
    """保留任务交付合同正文，排除执行和交付事实元数据。"""

    lines = text.splitlines()
    record_start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip() == "## 执行记录"
        ),
        len(lines),
    )
    # 合同正文不可变；执行记录标题前允许Markdown规范要求的一个分隔空行。
    # 多余空行仍保留在比较结果中，确保格式漂移失败关闭。
    contract_end = record_start
    if (
        record_start < len(lines)
        and lines[record_start].strip() == "## 执行记录"
        and contract_end > 0
        and lines[contract_end - 1] == ""
    ):
        contract_end -= 1
    first_section = next(
        (
            index
            for index, line in enumerate(lines[:contract_end])
            if line.startswith("## ")
        ),
        contract_end,
    )
    mutable_prefixes = (
        "- 状态：",
        "- 执行分支：",
        "- 开始时间：",
        "- Pull Request：",
        "- 实现提交SHA：",
        "- 完成实现时间：",
        "- 架构评审结论：",
        "- 合并完成时间：",
    )
    return tuple(
        line
        for index, line in enumerate(lines[:contract_end])
        if not (
            index < first_section
            and any(line.startswith(prefix) for prefix in mutable_prefixes)
        )
    )


def _validate_blocked_contract_repair(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> set[str]:
    """验证受控阻塞合同修复映射。"""

    mapping = {
        BLOCKED_CONTRACT_REPAIR_EXECUTOR: BLOCKED_CONTRACT_REPAIR_TARGET,
        ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR: ROOT_READONLY_CONTRACT_REPAIR_TARGET,
    }
    allowed_unreferenced: set[str] = set()
    if len(task_ids) != 1 or task_ids[0] not in mapping:
        _append_reason(
            reasons,
            "阻塞任务合同修复必须且只能关联已登记的执行任务",
        )
        return allowed_unreferenced
    executor_id = task_ids[0]
    target_id = mapping[executor_id]
    root_compat = executor_id == ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR

    executor_path = f"docs/研发中心/任务/任务-{executor_id}.md"
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    required_paths = {target_path}
    if not root_compat:
        required_paths.add("docs/研发中心/看板.md")
    if not root_compat:
        required_paths.add(executor_path)
    if not required_paths.issubset(set(changed_paths)):
        _append_reason(
            reasons,
            "阻塞任务合同修复必须同时修改执行任务、目标任务和看板",
        )
    for path in changed_paths:
        if path in required_paths:
            continue
        if not root_compat and path in BLOCKED_CONTRACT_REPAIR_ALLOWED_PATHS:
            continue
        pure_path = PurePosixPath(path)
        if (
            len(pure_path.parts) == 3
            and pure_path.parts[:2] == ("tests", "研发中心")
            and pure_path.suffix == ".py"
        ):
            continue
        _append_reason(reasons, f"阻塞任务合同修复包含不允许路径“{path}”")

    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    if None in (executor_base, executor_head, target_base, target_head):
        _append_reason(reasons, "阻塞任务合同修复缺少执行任务或目标任务正文")
        return allowed_unreferenced
    assert executor_base is not None
    assert executor_head is not None
    assert target_base is not None
    assert target_head is not None

    if root_compat:
        if _task_field(TASK_TYPE_PATTERN, executor_base) != "治理":
            _append_reason(reasons, "任务-000086类型不是治理")
        if _task_field(AUTOMATION_SCOPE_PATTERN, executor_base) != AUTOMATION_SCOPE:
            _append_reason(reasons, "任务-000086未声明治理自动化授权")
        if _task_field(TASK_STATUS_PATTERN, executor_base) != "已完成":
            _append_reason(reasons, "任务-000086基线状态必须为已完成")
        if executor_base != executor_head:
            _append_reason(reasons, "任务-000086已完成合同在root兼容修复中不得改写")
    else:
        # 旧映射仍是一次受控任务交付；任务-000056必须先由独立状态闭环
        # 从阻塞恢复为待执行（或需修复），不能在阻塞/执行中直接改合同。
        _validate_delivery_tasks(
            task_ids=(executor_id,),
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            reasons=reasons,
        )

    # 任务-000056的输出合同和固定方案必须在基线中明确证明唯一目标，
    # 不能由PR正文、Issue或执行者自行指定另一个阻塞任务。
    required_contract_evidence = (
        (
            "更新后的`docs/研发中心/任务/任务-000055.md`",
            "只在任务-000055任务文件中增加唯一的`自动合并范围：治理自动化`字段",
        )
        if not root_compat
        else (
            "任务-000084的单一“Ubuntu root只读兼容模式”合同段落修复PR",
            "目标任务其他字段、状态、执行记录和看板语义保持不变",
        )
    )
    blocker_evidence = (
        "任务-000055最新阻塞状态"
        if not root_compat
        else "任务-000084仍为阻塞"
    )
    if (
        any(item not in executor_base for item in required_contract_evidence)
        or blocker_evidence not in executor_base
    ):
        _append_reason(
            reasons,
            "任务-000056合同未证明任务-000055唯一目标"
            if not root_compat
            else "任务-000086合同未证明任务-000084唯一root兼容目标",
        )
    if not root_compat:
        if _task_field(TASK_TYPE_PATTERN, executor_base) != "治理":
            _append_reason(reasons, "任务-000056类型不是治理")
        if _task_field(AUTOMATION_SCOPE_PATTERN, executor_base) != AUTOMATION_SCOPE:
            _append_reason(reasons, "任务-000056未声明治理自动化授权")
    target_base_status = _task_field(TASK_STATUS_PATTERN, target_base)
    if target_base_status == "已取消":
        _append_reason(reasons, f"目标任务-{target_id}已取消，旧root兼容映射已关闭")
    elif target_base_status != "阻塞":
        _append_reason(reasons, f"目标任务-{target_id}基线状态不是阻塞")
    if _task_field(TASK_STATUS_PATTERN, target_head) != "阻塞":
        _append_reason(reasons, f"目标任务-{target_id}状态不得在合同修复中迁移")

    # 旧执行任务可以按普通任务交付更新状态和执行事实，但合同章节逐行不变。
    if not root_compat and _delivery_contract_without_metadata(executor_base) != _delivery_contract_without_metadata(
        executor_head
    ):
        _append_reason(reasons, "任务-000056阻塞合同修复夹带执行任务合同改写")

    if root_compat:
        expected_head = target_base.rstrip("\n") + "\n\n" + ROOT_READONLY_COMPAT_SECTION.strip() + "\n"
        if ROOT_READONLY_COMPAT_SECTION.strip() in target_base:
            _append_reason(reasons, "任务-000084基线已存在root兼容段落")
        if target_head != expected_head:
            _append_reason(reasons, "任务-000084只能追加固定root兼容合同段落")
        allowed_unreferenced.update({executor_id, target_id})
        if base_board != head_board:
            _append_reason(reasons, "任务-000084 root兼容合同修复不得改写看板")
        return allowed_unreferenced

    base_scope_lines = [
        line
        for line in target_base.splitlines()
        if line.startswith("- 自动合并范围：")
    ]
    head_scope_lines = [
        line
        for line in target_head.splitlines()
        if line.startswith("- 自动合并范围：")
    ]
    if base_scope_lines:
        _append_reason(reasons, "目标任务-000055基线已存在自动合并范围字段")
    if head_scope_lines != [BLOCKED_CONTRACT_REPAIR_FIELD]:
        _append_reason(
            reasons,
            "目标任务-000055只能新增唯一的治理自动化授权字段",
        )
    base_without_scope = tuple(
        line for line in target_base.splitlines() if line != BLOCKED_CONTRACT_REPAIR_FIELD
    )
    head_without_scope = tuple(
        line for line in target_head.splitlines() if line != BLOCKED_CONTRACT_REPAIR_FIELD
    )
    if base_without_scope != head_without_scope:
        _append_reason(reasons, "目标任务-000055合同修复夹带其他字段改写")

    _validate_delivery_board(
        task_ids=(executor_id,),
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_board=base_board,
        head_board=head_board,
        reasons=reasons,
    )
    allowed_unreferenced.add(target_id)
    return allowed_unreferenced


def _target_contract_without_repair_fields(text: str) -> tuple[str, ...]:
    """保留目标任务合同，排除本次两项受控修复字段。"""

    lines = text.splitlines()
    completion_start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip() == "## 完成定义"
        ),
        -1,
    )
    completion_end = next(
        (
            index
            for index in range(completion_start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    ) if completion_start >= 0 else -1
    output: list[str] = []
    for index, line in enumerate(lines):
        if line.startswith("- 交付提交SHA："):
            continue
        if completion_start <= index < completion_end:
            continue
        output.append(line)
    return tuple(output)


def _completion_section_lines(text: str) -> tuple[str, ...] | None:
    """读取任务合同完成定义段落（含标题，不读取执行记录）。"""

    lines = text.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == "## 完成定义"),
        -1,
    )
    if start < 0:
        return None
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    return tuple(lines[start:end])


def _derive_contract_repair_delivery_sha(
    *,
    repo_root: Path,
    base_ref: str,
    target_base: str,
    reasons: list[str],
) -> str | None:
    """从PR #165真实双父合并提交复算任务-000066交付头。"""

    implementation = IMPLEMENTATION_SHA_PATTERN.findall(target_base)
    pr_match = PULL_REQUEST_PATTERN.search(target_base)
    if len(implementation) != 1 or pr_match is None:
        _append_reason(reasons, "任务-000066缺少唯一实现提交SHA或PR事实")
        return None
    if int(pr_match.group(1)) != CONTRACT_CONFLICT_REPAIR_PR:
        _append_reason(reasons, "任务-000066交付PR不是预绑定的PR #165")
        return None
    implementation_sha = implementation[0]
    if not _git_is_ancestor(repo_root, implementation_sha, base_ref):
        _append_reason(reasons, "任务-000066实现提交SHA不在main祖先链")
        return None
    merge_text = _git_text(
        repo_root,
        ["rev-list", "--first-parent", "--merges", "--max-count=2048", base_ref],
    )
    if merge_text is None:
        _append_reason(reasons, "无法读取main双父合并提交列表")
        return None
    candidates: list[str] = []
    for merge_sha in merge_text.splitlines():
        parents_text = _git_text(
            repo_root, ["show", "-s", "--format=%P", merge_sha]
        )
        parents = parents_text.split() if parents_text else []
        if len(parents) != 2:
            continue
        # 只接受实现提交首次进入main的合并点；后续合并的第一父已经包含实现提交，
        # 因而不会被误认作PR #165交付头。
        if _git_is_ancestor(repo_root, implementation_sha, parents[0]):
            continue
        if _git_is_ancestor(repo_root, implementation_sha, parents[1]):
            candidates.append(parents[1])
    if len(candidates) != 1:
        _append_reason(reasons, "任务-000066的PR #165无法复算唯一交付头")
        return None
    return candidates[0]


def _validate_task116_baseline_repair(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000116→任务-000115的单字段基线补齐。"""

    executor_id = TASK116_CONTRACT_REPAIR_EXECUTOR
    target_id = TASK116_CONTRACT_REPAIR_TARGET
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    allowed = {executor_id, target_id}
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "任务-000116基线修复必须且只能关联任务-000116")
    if set(changed_paths) != {target_path}:
        _append_reason(reasons, "任务-000116基线修复只能修改任务-000115文件")
    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    if None in (executor_base, executor_head, target_base, target_head):
        _append_reason(reasons, "任务-000116基线修复缺少执行任务或目标任务正文")
        return allowed
    assert executor_base is not None and executor_head is not None
    assert target_base is not None and target_head is not None
    if executor_base != executor_head:
        _append_reason(reasons, "任务-000116基线修复执行任务必须逐字不变")
    if _task_field(TASK_STATUS_PATTERN, executor_base) != "已完成":
        _append_reason(reasons, "任务-000116必须先完成状态闭环")
    if (
        _task_field(TASK_STATUS_PATTERN, target_base) != "待执行"
        or _task_field(TASK_STATUS_PATTERN, target_head) != "待执行"
    ):
        _append_reason(reasons, "任务-000115基线和头部必须保持待执行")
    expected = _apply_task116_contract_repair(target_base)
    if expected is None or target_head != expected:
        _append_reason(reasons, "任务-000115未按固定单字段规则补齐当前阻塞原因")
    if base_board is not None and head_board is not None and base_board != head_board:
        _append_reason(reasons, "任务-000115基线修复不得改写看板")
    return allowed


def _stage1_history_section(text: str) -> tuple[str, ...] | None:
    bounds = _section_bounds(text, "## 执行记录")
    if bounds is None:
        return None
    start, end = bounds
    return tuple(text.splitlines()[start:end])


def _validate_stage1_contract_repair(
    *,
    repo_root: Path | None,
    base_ref: str | None,
    head_ref_name: str | None,
    pr_number: int | None,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    path_facts: Sequence[PathFact] | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000115→任务-000106覆盖受限合同修订入口。"""

    executor_id = STAGE1_CONTRACT_REPAIR_EXECUTOR
    target_id = STAGE1_CONTRACT_REPAIR_TARGET
    governance_id = TASK116_CONTRACT_REPAIR_EXECUTOR
    executor_path = f"docs/研发中心/任务/任务-{executor_id}.md"
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    required = {executor_path, target_path, "docs/研发中心/看板.md"}
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "阶段1覆盖受限合同修订必须且只能关联任务-000115")
    if not required.issubset(set(changed_paths)):
        _append_reason(reasons, "阶段1覆盖受限合同修订必须同步任务115、任务106和看板")
    if any(path not in STAGE1_CONTRACT_REPAIR_ALLOWED_PATHS for path in changed_paths):
        _append_reason(reasons, "阶段1覆盖受限合同修订包含不允许路径")
    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    governance_base = base_tasks.get(governance_id)
    governance_head = head_tasks.get(governance_id)
    if None in (
        executor_base,
        executor_head,
        target_base,
        target_head,
        governance_base,
        governance_head,
    ):
        _append_reason(
            reasons,
            "阶段1覆盖受限合同修订缺少任务115、任务106或任务116完成事实",
        )
        return {target_id}
    assert executor_base is not None and executor_head is not None
    assert target_base is not None and target_head is not None
    assert governance_base is not None and governance_head is not None
    if _task_field(TASK_STATUS_PATTERN, governance_base) != "已完成":
        _append_reason(reasons, "任务-000116基线状态必须为已完成")
    if _task_field(TASK_STATUS_PATTERN, governance_head) != "已完成":
        _append_reason(reasons, "任务-000116头部状态必须为已完成")
    if _delivery_contract_without_metadata(governance_base) != _delivery_contract_without_metadata(governance_head):
        _append_reason(reasons, "任务-000116完成事实校验夹带合同改写")
    if _task_field(TASK_TYPE_PATTERN, executor_base) != "治理":
        _append_reason(reasons, "任务-000115类型不是治理")
    if _task_field(AUTOMATION_SCOPE_PATTERN, executor_base) != AUTOMATION_SCOPE:
        _append_reason(reasons, "任务-000115未声明治理自动化授权")
    if _task_field(TASK_STATUS_PATTERN, executor_base) != "待执行":
        _append_reason(reasons, "任务-000115基线状态必须为待执行")
    if _task_field(TASK_STATUS_PATTERN, executor_head) != "待评审":
        _append_reason(reasons, "任务-000115头部状态必须为待评审")
    if head_ref_name is not None and _task_field(EXECUTION_BRANCH_PATTERN, executor_head) != head_ref_name:
        _append_reason(reasons, "任务-000115执行分支与PR头部事实不一致")
    if pr_number is not None:
        pr_match = PULL_REQUEST_PATTERN.search(executor_head)
        if pr_match is None or int(pr_match.group(1)) != pr_number:
            _append_reason(reasons, "任务-000115任务文件PR编号与当前PR事实不一致")
    if _delivery_contract_without_metadata(executor_base) != _delivery_contract_without_metadata(executor_head):
        _append_reason(reasons, "任务-000115执行合同在修订PR中不得改写")
    if (
        _task_field(TASK_STATUS_PATTERN, target_base) != "阻塞"
        or _task_field(TASK_STATUS_PATTERN, target_head) != "阻塞"
    ):
        _append_reason(reasons, "任务-000106基线和头部必须保持阻塞")
    if _stage1_history_section(target_base) != _stage1_history_section(target_head):
        _append_reason(reasons, "任务-000106执行记录必须保持不可变")
    expected_target = _apply_stage1_contract_repair(target_base)
    if expected_target is None or target_head != expected_target:
        _append_reason(reasons, "任务-000106未按固定覆盖受限章节修订且合同指纹漂移")
    if STAGE1_DERIVED_DOC_PATHS.intersection(changed_paths):
        if repo_root is None or not base_ref or path_facts is None:
            _append_reason(reasons, "阶段1派生文档缺少可信基线或头部正文")
        else:
            head_texts = {fact.path: fact.text for fact in path_facts}
            for path in sorted(STAGE1_DERIVED_DOC_PATHS.intersection(changed_paths)):
                base_text = _read_path_at_ref(repo_root, base_ref, path)
                head_text = head_texts.get(path)
                expected = (
                    _apply_stage1_derived_doc_repair(base_text)
                    if base_text is not None
                    else None
                )
                if expected is None or head_text != expected:
                    _append_reason(
                        reasons,
                        f"阶段1派生文档“{path}”未按固定追加式边界修订且内容指纹漂移",
                    )
    if base_board is None or head_board is None or not _board_schema_is_valid(base_board) or not _board_schema_is_valid(head_board):
        _append_reason(reasons, "阶段1覆盖受限合同修订看板结构无效")
    else:
        base_rows = _board_rows(base_board)
        head_rows = _board_rows(head_board)
        _validate_delivery_board(
            task_ids=(executor_id,),
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            reasons=reasons,
        )
        for task_id in set(base_rows) | set(head_rows):
            if task_id not in {executor_id, target_id} and base_rows.get(task_id) != head_rows.get(task_id):
                _append_reason(reasons, "阶段1覆盖受限合同修订夹带其他看板迁移")
        if base_rows.get(executor_id) == head_rows.get(executor_id):
            _append_reason(reasons, "任务-000115看板未从待执行迁移到待评审")
        target_blocker = _task_field(BLOCKER_PATTERN, target_head)
        title = _task_field(TASK_TITLE_PATTERN, target_head)
        priority = _task_field(TASK_PRIORITY_PATTERN, target_head)
        dependency = _task_field(DEPENDENCY_PATTERN, target_head)
        expected = (
            f"| {priority} | 任务-{target_id} | {title} | {dependency} | {target_blocker} |"
            if title and priority and dependency and target_blocker
            else ""
        )
        if head_rows.get(target_id, ("", ""))[1] != expected:
            _append_reason(reasons, "任务-000106看板阻塞行不可由头部合同复算")
    return {target_id}


def _apply_stage1_coverage_v2_derived_doc_repair(text: str, path: str) -> str | None:
    appendix = STAGE1_COVERAGE_V2_DERIVED_APPENDICES.get(path)
    if appendix is None:
        return None
    if path == "README.md":
        return text.rstrip("\n") + "\n\n" + appendix + "\n"
    if path == "docs/研发中心/总体计划.md":
        anchor = "- 多年主网真实执行延迟、真实资金交易和交易许可不因覆盖受限模式自动放行。"
    elif path == "docs/审计/阶段1最终审计报告.md":
        anchor = "- 结论仅为数据缺失和覆盖位置的可复算摘要；不改变阶段1/阶段2门禁，不产生来源身份新证明、研究准入、交易许可、胜率、收益或方向仓位结论。"
    elif path == "docs/审计/数据缺口与补采清单.md":
        anchor = "- 多年主网真实执行延迟、真实资金交易和交易许可不因覆盖受限模式自动放行。"
    else:
        return None
    if text.count(anchor) != 1 or appendix in text:
        return None
    return text.replace(anchor, f"{anchor}\n\n{appendix}", 1)


def _validate_stage1_coverage_v2_contract_repair(
    *,
    repo_root: Path | None,
    base_ref: str | None,
    head_ref_name: str | None,
    pr_number: int | None,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    path_facts: Sequence[PathFact] | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000124→任务-000098/000106的一次性覆盖受限合同修订。"""

    executor_id = STAGE1_COVERAGE_V2_EXECUTOR
    target_ids = STAGE1_COVERAGE_V2_TARGETS
    required_paths = set(STAGE1_COVERAGE_V2_ALLOWED_PATHS)
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "阶段1覆盖受限V2合同修订必须且只能关联任务-000124")
    if not required_paths.issubset(set(changed_paths)):
        _append_reason(reasons, "阶段1覆盖受限V2合同修订缺少固定交付路径")
    if any(path not in STAGE1_COVERAGE_V2_ALLOWED_PATHS for path in changed_paths):
        _append_reason(reasons, "阶段1覆盖受限V2合同修订包含不允许路径")
    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    if executor_base is None or executor_head is None:
        _append_reason(reasons, "阶段1覆盖受限V2合同修订缺少任务-000124正文")
        return set(target_ids)
    if _task_field(TASK_TYPE_PATTERN, executor_base) != "治理":
        _append_reason(reasons, "任务-000124类型不是治理")
    if _task_field(AUTOMATION_SCOPE_PATTERN, executor_base) != AUTOMATION_SCOPE:
        _append_reason(reasons, "任务-000124未声明治理自动化授权")
    if _task_field(TASK_STATUS_PATTERN, executor_base) != "待执行":
        _append_reason(reasons, "任务-000124基线状态必须为待执行")
    if _task_field(TASK_STATUS_PATTERN, executor_head) != "待评审":
        _append_reason(reasons, "任务-000124头部状态必须为待评审")
    if head_ref_name is not None and _task_field(EXECUTION_BRANCH_PATTERN, executor_head) != head_ref_name:
        _append_reason(reasons, "任务-000124执行分支与PR头部事实不一致")
    if pr_number is not None:
        pr_match = PULL_REQUEST_PATTERN.search(executor_head)
        if pr_match is None or int(pr_match.group(1)) != pr_number:
            _append_reason(reasons, "任务-000124任务文件PR编号与当前PR事实不一致")
    if _delivery_contract_without_metadata(executor_base) != _delivery_contract_without_metadata(executor_head):
        _append_reason(reasons, "任务-000124执行合同在修订PR中不得改写")

    for target_id in sorted(target_ids):
        target_base = base_tasks.get(target_id)
        target_head = head_tasks.get(target_id)
        if target_base is None or target_head is None:
            _append_reason(reasons, f"任务-{target_id}缺少基线或头部正文")
            continue
        if _task_field(TASK_STATUS_PATTERN, target_base) != "阻塞" or _task_field(TASK_STATUS_PATTERN, target_head) != "阻塞":
            _append_reason(reasons, f"任务-{target_id}状态不得在V2合同修订中迁移")
        if _stage1_history_section(target_base) != _stage1_history_section(target_head):
            _append_reason(reasons, f"任务-{target_id}执行记录必须保持不可变")
        expected = _apply_stage1_coverage_v2_task_repair(target_base, target_id)
        if expected is None or target_head != expected:
            _append_reason(reasons, f"任务-{target_id}未按V2固定章节和指纹修订")

    if base_board is None or head_board is None:
        _append_reason(reasons, "阶段1覆盖受限V2合同修订缺少看板")
    else:
        _validate_delivery_board(
            task_ids=(executor_id,),
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            reasons=reasons,
        )
        base_rows = _board_rows(base_board)
        head_rows = _board_rows(head_board)
        for task_id in set(base_rows) | set(head_rows):
            if task_id != executor_id and base_rows.get(task_id) != head_rows.get(task_id):
                _append_reason(reasons, "阶段1覆盖受限V2合同修订夹带其他看板迁移")

    if repo_root is None or not base_ref or path_facts is None:
        _append_reason(reasons, "阶段1覆盖受限V2合同修订缺少可信基线或路径正文")
    else:
        head_texts = {fact.path: fact.text for fact in path_facts}
        for path in sorted(STAGE1_COVERAGE_V2_ALLOWED_PATHS):
            if path in {
                "scripts/研发中心/验证自动合并资格.py",
                "tests/研发中心/test_验证自动合并资格.py",
                "docs/研发中心/任务/任务-000124.md",
                "docs/研发中心/任务/任务-000098.md",
                "docs/研发中心/任务/任务-000106.md",
                "docs/研发中心/看板.md",
            }:
                continue
            base_text = _read_path_at_ref(repo_root, base_ref, path)
            head_text = head_texts.get(path)
            expected = _apply_stage1_coverage_v2_derived_doc_repair(base_text or "", path)
            if expected is None or head_text != expected:
                _append_reason(reasons, f"阶段1覆盖受限V2派生文档“{path}”指纹不匹配")
        script_text = head_texts.get("scripts/研发中心/验证自动合并资格.py", "")
        if STAGE1_COVERAGE_V2_TYPE not in script_text or "_validate_stage1_coverage_v2_contract_repair" not in script_text:
            _append_reason(reasons, "阶段1覆盖受限V2可信规则未进入PR头部")
        test_text = head_texts.get("tests/研发中心/test_验证自动合并资格.py", "")
        if STAGE1_COVERAGE_V2_TYPE not in test_text or "分母缩小" not in test_text:
            _append_reason(reasons, "阶段1覆盖受限V2负向测试未进入PR头部")
    return set(target_ids)


def _validate_contract_conflict_repair(
    *,
    repo_root: Path,
    base_ref: str,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000068→任务-000066的双字段合同修复。"""

    executor_id = CONTRACT_CONFLICT_REPAIR_EXECUTOR
    target_id = CONTRACT_CONFLICT_REPAIR_TARGET
    allowed_unreferenced: set[str] = set()
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "任务合同冲突修复必须且只能关联任务-000068")
        return allowed_unreferenced
    executor_path = f"docs/研发中心/任务/任务-{executor_id}.md"
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    required_paths = {executor_path, target_path, "docs/研发中心/看板.md"}
    if not required_paths.issubset(set(changed_paths)):
        _append_reason(reasons, "任务合同冲突修复必须同时修改执行任务、目标任务和看板")
    allowed_paths = required_paths | CONTRACT_CONFLICT_REPAIR_ALLOWED_PATHS
    for path in changed_paths:
        if path in allowed_paths:
            continue
        pure_path = PurePosixPath(path)
        if (
            len(pure_path.parts) == 3
            and pure_path.parts[:2] == ("tests", "研发中心")
            and pure_path.suffix == ".py"
        ):
            continue
        _append_reason(reasons, f"任务合同冲突修复包含不允许路径“{path}”")

    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    if None in (executor_base, executor_head, target_base, target_head):
        _append_reason(reasons, "任务合同冲突修复缺少执行任务或目标任务正文")
        return allowed_unreferenced
    assert executor_base is not None
    assert executor_head is not None
    assert target_base is not None
    assert target_head is not None
    _validate_delivery_tasks(
        task_ids=(executor_id,),
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        reasons=reasons,
    )
    if _delivery_contract_without_metadata(executor_base) != _delivery_contract_without_metadata(executor_head):
        _append_reason(reasons, "任务-000068合同冲突修复夹带执行任务合同改写")
    if _task_field(TASK_STATUS_PATTERN, target_base) != "待评审" or _task_field(
        TASK_STATUS_PATTERN, target_head
    ) != "待评审":
        _append_reason(reasons, "目标任务-000066基线和头部必须保持待评审")

    expected_delivery_sha = _derive_contract_repair_delivery_sha(
        repo_root=repo_root,
        base_ref=base_ref,
        target_base=target_base,
        reasons=reasons,
    )
    base_delivery = DELIVERY_SHA_PATTERN.findall(target_base)
    head_delivery = DELIVERY_SHA_PATTERN.findall(target_head)
    if base_delivery:
        _append_reason(reasons, "目标任务-000066基线已存在交付提交SHA")
    if len(head_delivery) != 1 or (
        expected_delivery_sha is not None and head_delivery[0] != expected_delivery_sha
    ):
        _append_reason(reasons, "目标任务-000066交付提交SHA与PR #165真实交付头不一致")

    old_completion = (
        "## 完成定义",
        "",
        "本登记PR合并后任务保持`阻塞`，不标记已完成。只有解除条件有证据并经独立状态闭环PR恢复为待执行后，",
        "才能认领执行；正文审计交付须另行PR、双只读评审、main可信复验和合并后状态闭环。",
        "",
    )
    new_completion = (
        "## 完成定义",
        "",
        "正文审计交付PR已合并并完成双只读评审、主执行器验证和main可信复验；随后通过独立状态闭环PR标记本任务为`已完成`。",
        "审计结果中的无法判定、失败和未成熟必须继续保留，不代表阶段1数据门槛或阶段2放行。",
        "",
    )
    if _completion_section_lines(target_base) != old_completion:
        _append_reason(reasons, "任务-000066基线完成定义不是预绑定旧段落")
    if _completion_section_lines(target_head) != new_completion:
        _append_reason(reasons, "任务-000066完成定义未按完整新段落修复")
    if _target_contract_without_repair_fields(target_base) != _target_contract_without_repair_fields(target_head):
        _append_reason(reasons, "任务-000066合同修复夹带两项字段以外的改写")

    _validate_delivery_board(
        task_ids=(executor_id,),
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_board=base_board,
        head_board=head_board,
        reasons=reasons,
    )
    allowed_unreferenced.add(target_id)
    return allowed_unreferenced


def _validate_task094_contract_repair(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000095→任务-000094的一次性完整合同修复。"""

    executor_id = TASK094_CONTRACT_REPAIR_EXECUTOR
    target_id = TASK094_CONTRACT_REPAIR_TARGET
    allowed = {executor_id, target_id}
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "任务-000094合同修复必须且只能关联任务-000095")
        return allowed
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    if set(changed_paths) != {target_path}:
        _append_reason(reasons, "任务-000094合同修复只能修改目标任务文件")
    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    if None in (executor_base, executor_head, target_base, target_head):
        _append_reason(reasons, "任务-000094合同修复缺少执行任务或目标任务正文")
        return allowed
    assert executor_base is not None and executor_head is not None
    assert target_base is not None and target_head is not None
    if executor_base != executor_head:
        _append_reason(reasons, "任务-000095在目标合同修复中必须逐字不变")
    if _task_field(TASK_STATUS_PATTERN, executor_base) != "已完成":
        _append_reason(reasons, "任务-000095必须先完成状态闭环")
    if (
        _task_field(TASK_STATUS_PATTERN, target_base) != "待执行"
        or _task_field(TASK_STATUS_PATTERN, target_head) != "待执行"
    ):
        _append_reason(reasons, "任务-000094基线和头部必须保持待执行")
    expected = _apply_task094_contract_repair(target_base)
    if expected is None or target_head != expected:
        _append_reason(reasons, "任务-000094未按固定完整合同修复")
    if base_board is not None and head_board is not None and base_board != head_board:
        _append_reason(reasons, "任务-000094合同修复不得改写看板")
    return allowed


def _validate_task100_contract_repair(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> set[str]:
    """验证任务-000102→任务-000100的唯一输出条目合同修复。"""

    executor_id = TASK100_CONTRACT_REPAIR_EXECUTOR
    target_id = TASK100_CONTRACT_REPAIR_TARGET
    allowed = {executor_id, target_id}
    if tuple(task_ids) != (executor_id,):
        _append_reason(reasons, "任务-000100合同修复必须且只能关联任务-000102")
        return allowed
    target_path = f"docs/研发中心/任务/任务-{target_id}.md"
    if set(changed_paths) != {target_path}:
        _append_reason(reasons, "任务-000100合同修复只能修改目标任务文件")
    executor_base = base_tasks.get(executor_id)
    executor_head = head_tasks.get(executor_id)
    governance_base = base_tasks.get(TASK100_CONTRACT_REPAIR_GOVERNANCE)
    governance_head = head_tasks.get(TASK100_CONTRACT_REPAIR_GOVERNANCE)
    target_base = base_tasks.get(target_id)
    target_head = head_tasks.get(target_id)
    if None in (
        executor_base,
        executor_head,
        governance_base,
        governance_head,
        target_base,
        target_head,
    ):
        _append_reason(reasons, "任务-000100合同修复缺少治理任务、执行任务或目标任务正文")
        return allowed
    assert executor_base is not None and executor_head is not None
    assert governance_base is not None and governance_head is not None
    assert target_base is not None and target_head is not None
    if executor_base != executor_head:
        _append_reason(reasons, "任务-000102在目标合同修复中必须逐字不变")
    if governance_base != governance_head:
        _append_reason(reasons, "任务-000101在目标合同修复中必须逐字不变")
    if _task_field(TASK_STATUS_PATTERN, governance_base) != "已完成":
        _append_reason(reasons, "任务-000101必须先完成状态闭环")
    if _task_field(TASK_STATUS_PATTERN, executor_base) != "已完成":
        _append_reason(reasons, "任务-000102必须先完成状态闭环")
    if (
        _task_field(TASK_STATUS_PATTERN, target_base) != "待执行"
        or _task_field(TASK_STATUS_PATTERN, target_head) != "待执行"
    ):
        _append_reason(reasons, "任务-000100基线和头部必须保持待执行")
    expected = _apply_task100_contract_repair(target_base)
    if expected is None or target_head != expected:
        _append_reason(reasons, "任务-000100未按固定唯一输出条目修复")
    if base_board is not None and head_board is not None and base_board != head_board:
        _append_reason(reasons, "任务-000100合同修复不得改写看板")
    return allowed


def _registration_field_value(text: str, field: str) -> str | None:
    """读取任务头部严格唯一且非空的合同字段。"""

    lines = text.splitlines()
    first_section = next(
        (
            index
            for index, line in enumerate(lines)
            if (
                (parsed := _commonmark_atx_heading(line)) is not None
                and parsed[0] == 2
            )
        ),
        len(lines),
    )
    prefix = f"- {field}："
    locations = [
        index for index, line in enumerate(lines) if line.startswith(prefix)
    ]
    if len(locations) != 1 or locations[0] >= first_section:
        return None
    value = lines[locations[0]][len(prefix):].strip()
    return value or None


def _validate_registration_board(
    *,
    task_id: str,
    task: str,
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> None:
    """验证看板仅新增一条可由任务合同复算的映射。"""

    mapping_reason = f"任务-{task_id}在看板中不是唯一可复算新增映射"
    if base_board is None or head_board is None:
        _append_reason(reasons, mapping_reason)
        return
    if not _board_schema_is_valid(base_board) or not _board_schema_is_valid(
        head_board
    ):
        _append_reason(reasons, mapping_reason)
    base_rows = _board_rows(base_board)
    head_rows = _board_rows(head_board)
    if (
        task_id in base_rows
        or _board_static_lines(base_board) != _board_static_lines(head_board)
        or {
            key: value for key, value in base_rows.items() if key != task_id
        }
        != {
            key: value for key, value in head_rows.items() if key != task_id
        }
    ):
        _append_reason(reasons, mapping_reason)

    title_matches = TASK_TITLE_WITH_ID_PATTERN.findall(task)
    status = _registration_field_value(task, "状态")
    priority = _registration_field_value(task, "优先级")
    dependency = _task_field(DEPENDENCY_PATTERN, task)
    expected_row = ""
    if (
        len(title_matches) == 1
        and title_matches[0][0] == task_id
        and title_matches[0][1].strip()
        and priority is not None
        and dependency is not None
    ):
        title = title_matches[0][1].strip()
        if status == "待执行":
            expected_row = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
            )
        elif status == "阻塞":
            blocker = _task_field(BLOCKER_PATTERN, task)
            if blocker is not None:
                blocker = blocker.rstrip("；。")
                expected_row = (
                    f"| {priority} | 任务-{task_id} | {title} | "
                    f"{dependency} | {blocker} |"
                )
    row = head_rows.get(task_id)
    if (
        row is None
        or row[0] == "重复"
        or row[0] != status
        or not expected_row
        or row[1] != expected_row
    ):
        _append_reason(reasons, mapping_reason)


def _board_row_cells(row: str) -> tuple[str, ...]:
    if not row.startswith("|") or not row.endswith("|"):
        return ()
    return tuple(cell.strip() for cell in row[1:-1].split("|"))


def _validate_delivery_board(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> None:
    """验证任务交付只迁移目标任务且看板映射仍可由任务复算。"""

    mapping_reason = "任务交付看板不是唯一可复算映射"
    if base_board is None or head_board is None:
        _append_reason(reasons, mapping_reason)
        return
    if not _board_schema_is_valid(base_board) or not _board_schema_is_valid(
        head_board
    ):
        _append_reason(reasons, mapping_reason)
        return
    if _board_static_lines(base_board) != _board_static_lines(head_board):
        _append_reason(reasons, mapping_reason)
    base_rows = _board_rows(base_board)
    head_rows = _board_rows(head_board)
    referenced = set(task_ids)
    for task_id in set(base_rows) | set(head_rows):
        if task_id not in referenced and base_rows.get(task_id) != head_rows.get(task_id):
            _append_reason(reasons, mapping_reason)
    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        head_task = head_tasks.get(task_id)
        base_row = base_rows.get(task_id)
        head_row = head_rows.get(task_id)
        if (
            base_task is None
            or head_task is None
            or base_row is None
            or head_row is None
            or base_row[0] == "重复"
            or head_row[0] == "重复"
        ):
            _append_reason(reasons, mapping_reason)
            continue
        base_title = _task_field(TASK_TITLE_PATTERN, base_task)
        head_title = _task_field(TASK_TITLE_PATTERN, head_task)
        base_priority = _task_field(TASK_PRIORITY_PATTERN, base_task)
        head_priority = _task_field(TASK_PRIORITY_PATTERN, head_task)
        base_status = _task_field(TASK_STATUS_PATTERN, base_task)
        base_branch = _task_field(EXECUTION_BRANCH_PATTERN, base_task)
        head_branch = _task_field(EXECUTION_BRANCH_PATTERN, head_task)
        base_cells = _board_row_cells(base_row[1])
        head_cells = _board_row_cells(head_row[1])
        dependency = _task_field(DEPENDENCY_PATTERN, base_task)
        base_pr_match = PULL_REQUEST_PATTERN.search(base_task)
        base_row_valid = (
            len(base_cells) == 4
            and base_cells[3] == dependency
            if base_status == "待执行"
            else (
                base_status == "需修复"
                and len(base_cells) == 5
                and base_branch is not None
                and base_cells[3] == f"`{base_branch}`"
                and base_pr_match is not None
                and base_cells[4]
                == (
                    f"[#{base_pr_match.group(1)}]"
                    f"(https://github.com/xk320/zhishi/pull/{base_pr_match.group(1)})"
                )
            )
        )
        if (
            base_row[0] != base_status
            or head_row[0] != "待评审"
            or not base_row_valid
            or len(head_cells) != 5
            or base_cells[1] != f"任务-{task_id}"
            or head_cells[1] != f"任务-{task_id}"
            or base_title is None
            or head_title is None
            or base_cells[2] != base_title
            or head_cells[2] != head_title
            or base_priority is None
            or head_priority is None
            or base_cells[0] != base_priority
            or head_cells[0] != head_priority
            or (base_status == "待执行" and dependency is None)
        ):
            _append_reason(reasons, mapping_reason)
            continue
        pr_match = PULL_REQUEST_PATTERN.search(head_task)
        if pr_match is None:
            _append_reason(reasons, mapping_reason)
            continue
        expected_pr = (
            f"[#{pr_match.group(1)}]"
            f"(https://github.com/xk320/zhishi/pull/{pr_match.group(1)})"
        )
        if (
            head_branch is None
            or head_cells[3] != f"`{head_branch}`"
            or head_cells[4] != expected_pr
        ):
            _append_reason(reasons, mapping_reason)
def _validate_task_registration(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_task_ids: Sequence[str] | None,
    base_board: str | None,
    head_board: str | None,
    path_facts: Sequence[PathFact] | None,
    reasons: list[str],
) -> None:
    """按基线Git事实验证单个完整新任务合同登记。"""

    if len(task_ids) != 1:
        _append_reason(reasons, "任务登记必须且只能引用一个新任务")
        return
    task_id = task_ids[0]
    task_path = f"docs/研发中心/任务/任务-{task_id}.md"

    raw_base_ids = tuple(base_task_ids) if base_task_ids is not None else tuple(base_tasks)
    valid_base_ids = (
        bool(raw_base_ids)
        and len(raw_base_ids) == len(set(raw_base_ids))
        and all(re.fullmatch(r"\d{6}", item) for item in raw_base_ids)
    )
    if not valid_base_ids:
        _append_reason(reasons, "基线任务编号事实无效")
    else:
        maximum = max(int(item) for item in raw_base_ids)
        expected = maximum + 1
        if task_id in HISTORICAL_MISSING_TASK_IDS:
            _append_reason(reasons, f"任务-{task_id}历史缺号禁止复用")
        if int(task_id) != expected:
            _append_reason(
                reasons,
                f"任务-{task_id}编号必须为基线最大编号"
                f"{maximum:06d}的下一编号{expected:06d}",
            )

    if task_id in base_tasks or task_id in raw_base_ids:
        _append_reason(reasons, f"任务-{task_id}已在基线main中登记")
    task = head_tasks.get(task_id)
    if task is None:
        _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
    else:
        for field in REQUIRED_TASK_FIELDS:
            if _registration_field_value(task, field) is None:
                _append_reason(
                    reasons,
                    f"任务-{task_id}合同字段“{field}”必须且只能出现一次",
                )
        for heading in REQUIRED_TASK_HEADINGS:
            count = _second_level_heading_count(task, heading)
            if count != 1:
                _append_reason(
                    reasons,
                    f"任务-{task_id}合同章节“{heading}”必须且只能出现一次",
                )
        title_matches = TASK_TITLE_WITH_ID_PATTERN.findall(task)
        if (
            len(title_matches) != 1
            or title_matches[0][0] != task_id
            or not title_matches[0][1].strip()
        ):
            _append_reason(reasons, f"任务-{task_id}合同标题与文件编号不一致")
        status = _registration_field_value(task, "状态")
        if status not in REGISTRATION_STATUSES:
            _append_reason(
                reasons,
                f"任务-{task_id}在PR中的状态“{status}”不可登记",
            )
        if _registration_field_value(task, "方案状态") != "已批准执行":
            _append_reason(
                reasons,
                f"任务-{task_id}方案状态不是“已批准执行”",
            )
        task_type = _registration_field_value(task, "类型")
        if task_type is not None and task_type not in ALLOWED_TASK_TYPES:
            _append_reason(
                reasons,
                f"任务-{task_id}类型“{task_type}”不允许自动合并",
            )
        dependency_lines = [
            line
            for line in task.splitlines()
            if line.startswith("- 唯一前序依赖：")
        ]
        dependencies = DEPENDENCY_PATTERN.findall(task)
        if len(dependency_lines) != 1 or len(dependencies) != 1:
            _append_reason(
                reasons,
                f"任务-{task_id}唯一前序依赖必须且只能出现一次",
            )
        if task_id == TASK100_CONTRACT_REPAIR_EXECUTOR:
            governance_task = base_tasks.get(TASK100_CONTRACT_REPAIR_GOVERNANCE)
            if (
                governance_task is None
                or _task_field(TASK_STATUS_PATTERN, governance_task) != "已完成"
            ):
                _append_reason(reasons, "任务-000102只能在任务-000101完成后登记")
            if dependencies != [TASK100_CONTRACT_REPAIR_GOVERNANCE]:
                _append_reason(reasons, "任务-000102唯一前序依赖必须为任务-000101")
        if status == "阻塞":
            blocker_lines = [
                line
                for line in task.splitlines()
                if line.startswith("- 当前阻塞原因：")
            ]
            blockers = BLOCKER_PATTERN.findall(task)
            if (
                len(blocker_lines) != 1
                or len(blockers) != 1
                or not blockers[0].strip()
            ):
                _append_reason(
                    reasons,
                    f"任务-{task_id}阻塞原因必须且只能出现一次且非空",
                )

    if REGISTRATION_BOARD_PATH not in changed_paths:
        _append_reason(reasons, "任务登记必须同步看板")

    design_paths = tuple(
        path
        for path in changed_paths
        if REGISTRATION_DESIGN_PATTERN.fullmatch(path)
    )
    allowed_paths = {
        task_path,
        REGISTRATION_BOARD_PATH,
        *design_paths,
    }
    for path in changed_paths:
        if path not in allowed_paths:
            _append_reason(reasons, f"任务登记包含不允许路径“{path}”")
    if len(design_paths) != 1:
        _append_reason(reasons, "任务登记必须且只能新增一个对应设计文档")

    facts_by_path = (
        {fact.path: fact for fact in path_facts}
        if path_facts is not None
        else {}
    )
    task_fact = facts_by_path.get(task_path)
    if task_fact is None or task_fact.status != "A":
        _append_reason(reasons, f"任务-{task_id}任务文件必须是新增普通文件")
    for design_path in design_paths:
        design_fact = facts_by_path.get(design_path)
        if design_fact is None or design_fact.status != "A":
            _append_reason(reasons, "任务登记对应设计文档必须是新增普通文件")
        elif re.search(
            rf"(?<!\d)任务-{re.escape(task_id)}(?!\d)",
            design_fact.text or "",
        ) is None:
            _append_reason(reasons, f"任务登记设计文档未对应任务-{task_id}")
    board_fact = facts_by_path.get(REGISTRATION_BOARD_PATH)
    if REGISTRATION_BOARD_PATH in changed_paths and (
        board_fact is None or board_fact.status != "M"
    ):
        _append_reason(reasons, "任务登记看板必须是对基线看板的修改")
    if task is not None:
        _validate_registration_board(
            task_id=task_id,
            task=task,
            base_board=base_board,
            head_board=head_board,
            reasons=reasons,
        )


def _validate_state_closure(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    merge_facts: Mapping[str, MergeFact],
    reasons: list[str],
) -> None:
    completed = 0
    unlocked = 0
    blocking = 0
    recovered = 0
    direct_recovered = 0
    canceled = 0
    completed_task_id: str | None = None
    canceled_task_id: str | None = None
    transitions: dict[str, tuple[str | None, str | None]] = {}
    if "docs/研发中心/看板.md" not in changed_paths:
        _append_reason(reasons, "合并后状态闭环必须同步看板")
    for path in changed_paths:
        if path == "docs/研发中心/看板.md" or TASK_FILE_PATTERN.fullmatch(path):
            continue
        _append_reason(reasons, f"合并后状态闭环包含非状态文件“{path}”")

    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        head_task = head_tasks.get(task_id)
        if base_task is None:
            _append_reason(reasons, f"任务-{task_id}未在基线main中登记")
            continue
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
            continue
        old_status = _task_field(TASK_STATUS_PATTERN, base_task)
        new_status = _task_field(TASK_STATUS_PATTERN, head_task)
        transitions[task_id] = (old_status, new_status)
        if (old_status, new_status) not in STATE_CLOSURE_TRANSITIONS:
            _append_reason(
                reasons,
                f"任务-{task_id}存在非法状态闭环“{old_status}→{new_status}”",
            )
        if (old_status, new_status) == ("待评审", "已完成"):
            completed += 1
            completed_task_id = task_id
            declared_fact = _task_merge_fact(head_task)
            if declared_fact is None:
                _append_reason(reasons, f"任务-{task_id}缺少真实合并证据")
            if declared_fact != merge_facts.get(task_id):
                _append_reason(
                    reasons,
                    f"任务-{task_id}合并证据与main真实事实不一致",
                )
            fields_valid = _has_unique_metadata_fields(
                base_task,
                {"- 状态：": 1, "- 合并时间：": 0, "- 合并提交SHA：": 0},
            ) and _has_unique_metadata_fields(
                head_task,
                {"- 状态：": 1, "- 合并时间：": 1, "- 合并提交SHA：": 1},
            )
            if not fields_valid or _without_mutable_metadata_lines(
                base_task, COMPLETION_MUTABLE_PREFIXES
            ) != _without_mutable_metadata_lines(
                head_task, COMPLETION_MUTABLE_PREFIXES
            ):
                _append_reason(reasons, f"任务-{task_id}状态闭环夹带合同改写")
        if (old_status, new_status) in CANCELLATION_TRANSITIONS:
            canceled += 1
            canceled_task_id = task_id
            support_task_id = _cancellation_support_task_id(head_task)
            declared_fact = _task_cancellation_fact(head_task)
            support_task = (
                base_tasks.get(support_task_id)
                if support_task_id is not None
                else None
            )
            support_status = (
                _task_field(TASK_STATUS_PATTERN, support_task)
                if support_task is not None
                else None
            )
            actual_fact = (
                merge_facts.get(support_task_id)
                if support_task_id is not None
                else None
            )
            fields_valid = _has_unique_metadata_fields(
                base_task,
                {
                    "- 状态：": 1,
                    "- 取消时间：": 0,
                    "- 取消原因：": 0,
                    "- 取消依据任务：": 0,
                    "- 取消依据PR：": 0,
                    "- 取消依据合并时间：": 0,
                    "- 取消依据合并提交SHA：": 0,
                },
            ) and _has_unique_metadata_fields(
                head_task,
                {
                    "- 状态：": 1,
                    "- 取消时间：": 1,
                    "- 取消原因：": 1,
                    "- 取消依据任务：": 1,
                    "- 取消依据PR：": 1,
                    "- 取消依据合并时间：": 1,
                    "- 取消依据合并提交SHA：": 1,
                },
            )
            if (
                not fields_valid
                or _without_mutable_metadata_lines(
                    base_task, CANCELLATION_MUTABLE_PREFIXES
                )
                != _without_mutable_metadata_lines(
                    head_task, CANCELLATION_MUTABLE_PREFIXES
                )
            ):
                _append_reason(reasons, f"任务-{task_id}取消状态闭环夹带合同改写")
            if (
                support_task_id is None
                or support_task_id == task_id
                or support_task is None
                or support_status != "已完成"
            ):
                _append_reason(reasons, f"任务-{task_id}取消依据任务不是已完成的其他任务")
            if declared_fact is None or actual_fact is None or declared_fact != actual_fact:
                _append_reason(reasons, f"任务-{task_id}取消依据合并事实与main不一致")
            if _task_field(CANCELLATION_TIME_PATTERN, head_task) is None:
                _append_reason(reasons, f"任务-{task_id}缺少有效取消时间")
            if _task_field(CANCELLATION_REASON_PATTERN, head_task) is None:
                _append_reason(reasons, f"任务-{task_id}缺少有效取消原因")
        if (old_status, new_status) in BLOCKING_TRANSITIONS:
            blocking += 1
            _validate_blocking_transition(
                base_task=base_task,
                head_task=head_task,
                old_status=old_status or "",
                reasons=reasons,
            )
        if (old_status, new_status) == ("阻塞", "待执行"):
            unlocked += 1
        if (old_status, new_status) == ("阻塞", "需修复"):
            recovered += 1
            _validate_recovery_transition(
                base_task=base_task,
                head_task=head_task,
                reasons=reasons,
            )
    if completed == 0 and unlocked:
        direct_recovered = unlocked
        for task_id, transition in transitions.items():
            if transition != ("阻塞", "待执行"):
                continue
            _validate_recovery_transition(
                base_task=base_tasks[task_id],
                head_task=head_tasks[task_id],
                reasons=reasons,
            )
    if blocking:
        if blocking != 1:
            _append_reason(reasons, "阻塞状态闭环必须且只能迁移一个任务")
        if completed or unlocked or recovered or canceled:
            _append_reason(reasons, "阻塞状态闭环不得夹带完成、解锁、恢复或取消迁移")
    elif direct_recovered or recovered:
        if direct_recovered + recovered != 1:
            _append_reason(reasons, "阻塞恢复状态闭环必须且只能迁移一个任务")
        if completed or canceled or (direct_recovered and recovered):
            _append_reason(reasons, "阻塞恢复状态闭环不得夹带完成、解锁或取消迁移")
    elif canceled:
        if canceled != 1:
            _append_reason(reasons, "取消状态闭环必须且只能迁移一个未完成任务")
        if completed or unlocked or recovered:
            _append_reason(reasons, "取消状态闭环不得夹带完成、解锁或恢复迁移")
    elif completed != 1:
        _append_reason(reasons, "合并后状态闭环必须且只能完成一个待评审任务")
    if unlocked > 1:
        _append_reason(reasons, "合并后状态闭环最多解除一个唯一后继")
    for task_id, transition in transitions.items():
        if transition != ("阻塞", "待执行"):
            continue
        if completed_task_id is None:
            continue
        base_task = base_tasks[task_id]
        head_task = head_tasks[task_id]
        dependency = _task_field(DEPENDENCY_PATTERN, base_task)
        if completed_task_id is None or dependency != completed_task_id:
            _append_reason(
                reasons,
                f"任务-{task_id}不是任务-{completed_task_id or '未知'}的唯一后继",
            )
        base_layout = _successor_mutable_layout(base_task)
        head_layout = _successor_mutable_layout(head_task)
        fields_valid = base_layout is not None and base_layout == head_layout
        if not fields_valid or _without_successor_mutable_lines(
            base_task
        ) != _without_successor_mutable_lines(head_task):
            _append_reason(reasons, f"任务-{task_id}状态闭环夹带合同改写")
        expected_blocker = (
            f"- 当前阻塞原因：无；任务-{completed_task_id}已完成。"
            if completed_task_id is not None
            else ""
        )
        if expected_blocker not in head_task.splitlines() or "- 解除条件：已满足。" not in head_task.splitlines():
            _append_reason(reasons, f"任务-{task_id}未如实登记唯一后继解锁")
    _validate_board_closure(
        task_ids=task_ids,
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_board=base_board,
        head_board=head_board,
        merge_facts=merge_facts,
        reasons=reasons,
    )


def evaluate_eligibility(
    *,
    repo_root: Path | None = None,
    base_ref: str | None = None,
    changed_paths: Sequence[str],
    pr_body: str,
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_task_ids: Sequence[str] | None = None,
    base_branch: str,
    repository: str,
    head_repository: str,
    merge_facts: Mapping[str, MergeFact] | None = None,
    base_board: str | None = None,
    head_board: str | None = None,
    path_facts: Sequence[PathFact] | None = None,
    enforce_board_sync: bool = False,
    task_ids_override: Sequence[str] | None = None,
    head_ref_name: str | None = None,
    pr_number: int | None = None,
) -> EligibilityResult:
    """按基线任务合同、严格PR合同和变更路径判定资格。"""

    reasons: list[str] = []
    for reason in _validate_path_facts(changed_paths, path_facts):
        _append_reason(reasons, reason)
    if base_branch != "main":
        _append_reason(reasons, "目标分支不是main")
    if repository != "xk320/zhishi" or head_repository != repository:
        _append_reason(reasons, "外部仓库PR不允许自动合并")
    if not changed_paths:
        _append_reason(reasons, "PR没有可验证的变更路径")

    parsed_task_ids = parse_task_references(pr_body)
    task_ids = tuple(task_ids_override) if task_ids_override is not None else parsed_task_ids
    if not parsed_task_ids:
        _append_reason(reasons, "PR正文未引用任务编号")
    if task_ids_override is not None and tuple(sorted(parsed_task_ids)) != tuple(sorted(task_ids)):
        _append_reason(reasons, "可信入口执行任务编号与PR正文引用不一致")
    change_type = parse_change_type(pr_body)
    if change_type is None:
        _append_reason(reasons, "PR正文缺少有效变更类型")
    if len(task_ids) > _task_reference_limit(change_type):
        _append_reason(reasons, _task_reference_limit_reason(change_type))

    automation_authorized = False
    controlled_rd_authorized = False
    allowed_unreferenced_task_ids: set[str] = set()
    if change_type == "任务登记":
        _validate_task_registration(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_task_ids=base_task_ids,
            base_board=base_board,
            head_board=head_board,
            path_facts=path_facts,
            reasons=reasons,
        )
    elif change_type == "任务交付":
        automation_authorized, controlled_rd_authorized = (
            _validate_delivery_tasks(
                task_ids=task_ids,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                reasons=reasons,
            )
        )
        if enforce_board_sync and "docs/研发中心/看板.md" not in changed_paths:
            _append_reason(reasons, "任务交付必须同步看板")
        if enforce_board_sync or "docs/研发中心/看板.md" in changed_paths:
            _validate_delivery_board(
                task_ids=task_ids,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                base_board=base_board,
                head_board=head_board,
                reasons=reasons,
            )
        if tuple(task_ids) == (TASK094_CONTRACT_REPAIR_TARGET,):
            _validate_task094_batch_resource_evidence(path_facts, reasons)
    elif change_type == "合并后状态闭环":
        _validate_state_closure(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            merge_facts=merge_facts or {},
            reasons=reasons,
        )
    elif change_type == BLOCKED_CONTRACT_REPAIR_TYPE:
        allowed_unreferenced_task_ids = _validate_blocked_contract_repair(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            reasons=reasons,
        )
    elif change_type == CONTRACT_CONFLICT_REPAIR_TYPE:
        if repo_root is None or not base_ref:
            _append_reason(reasons, "任务合同冲突修复缺少可信Git基线")
        elif tuple(task_ids) == (TASK116_CONTRACT_REPAIR_EXECUTOR,):
            allowed_unreferenced_task_ids = _validate_task116_baseline_repair(
                task_ids=task_ids,
                changed_paths=changed_paths,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                base_board=base_board,
                head_board=head_board,
                reasons=reasons,
            )
        elif tuple(task_ids) == (TASK094_CONTRACT_REPAIR_EXECUTOR,):
            allowed_unreferenced_task_ids = _validate_task094_contract_repair(
                task_ids=task_ids,
                changed_paths=changed_paths,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                base_board=base_board,
                head_board=head_board,
                reasons=reasons,
            )
        elif tuple(task_ids) == (TASK100_CONTRACT_REPAIR_EXECUTOR,):
            allowed_unreferenced_task_ids = _validate_task100_contract_repair(
                task_ids=task_ids,
                changed_paths=changed_paths,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                base_board=base_board,
                head_board=head_board,
                reasons=reasons,
            )
        else:
            allowed_unreferenced_task_ids = _validate_contract_conflict_repair(
                repo_root=repo_root,
                base_ref=base_ref,
                task_ids=task_ids,
                changed_paths=changed_paths,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                base_board=base_board,
                head_board=head_board,
                reasons=reasons,
            )

    elif change_type == STAGE1_CONTRACT_REPAIR_TYPE:
        allowed_unreferenced_task_ids = _validate_stage1_contract_repair(
            repo_root=repo_root,
            base_ref=base_ref,
            head_ref_name=head_ref_name,
            pr_number=pr_number,
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            path_facts=path_facts,
            reasons=reasons,
        )

    elif change_type == STAGE1_COVERAGE_V2_TYPE:
        allowed_unreferenced_task_ids = _validate_stage1_coverage_v2_contract_repair(
            repo_root=repo_root,
            base_ref=base_ref,
            head_ref_name=head_ref_name,
            pr_number=pr_number,
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            path_facts=path_facts,
            reasons=reasons,
        )

    referenced_task_ids = set(task_ids)
    changed_task_ids: set[str] = set()
    for path in changed_paths:
        task_file_match = TASK_FILE_PATTERN.fullmatch(path)
        if task_file_match is not None:
            changed_task_ids.add(task_file_match.group(1))
            implicit_target = (
                (change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                 and set(task_ids) == {TASK116_CONTRACT_REPAIR_EXECUTOR}
                 and task_file_match.group(1) == TASK116_CONTRACT_REPAIR_TARGET)
                or (change_type == STAGE1_CONTRACT_REPAIR_TYPE
                    and task_file_match.group(1) == STAGE1_CONTRACT_REPAIR_TARGET)
                or (change_type == STAGE1_COVERAGE_V2_TYPE
                    and task_file_match.group(1) in STAGE1_COVERAGE_V2_TARGETS)
            )
            if (
                task_file_match.group(1) not in referenced_task_ids
                and task_file_match.group(1) not in allowed_unreferenced_task_ids
                and not implicit_target
            ):
                _append_reason(
                    reasons,
                    f"修改了未在PR正文引用的任务-{task_file_match.group(1)}",
                )

        if change_type == "任务交付":
            if _is_governance_control_path(path) and not automation_authorized:
                allowed = False
            else:
                allowed = (
                    _is_automation_path(path)
                    if automation_authorized
                    else (
                        _is_controlled_rd_path(path)
                        and not _is_governance_control_path(path)
                        if controlled_rd_authorized
                        else _is_low_risk_path(path)
                    )
                )
            if not allowed and not _task094_native_scanner_allowed(
                task_ids=task_ids,
                change_type=change_type,
                path=path,
            ):
                _append_reason(reasons, f"变更路径“{path}”不允许自动合并")
        elif change_type == BLOCKED_CONTRACT_REPAIR_TYPE:
            if path not in BLOCKED_CONTRACT_REPAIR_ALLOWED_PATHS:
                task_match = TASK_FILE_PATTERN.fullmatch(path)
                is_allowed_task = task_match is not None and task_match.group(1) in {
                    BLOCKED_CONTRACT_REPAIR_EXECUTOR,
                    BLOCKED_CONTRACT_REPAIR_TARGET,
                    ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR,
                    ROOT_READONLY_CONTRACT_REPAIR_TARGET,
                }
                is_allowed_test = (
                    len(PurePosixPath(path).parts) == 3
                    and
                    PurePosixPath(path).parts[:2] == ("tests", "研发中心")
                    and PurePosixPath(path).suffix == ".py"
                )
                if not is_allowed_task and not is_allowed_test:
                    _append_reason(
                        reasons,
                        f"阻塞任务合同修复变更路径“{path}”不允许自动合并",
                    )
        elif change_type == CONTRACT_CONFLICT_REPAIR_TYPE:
            task_match = TASK_FILE_PATTERN.fullmatch(path)
            contract_task_ids = (
                {TASK094_CONTRACT_REPAIR_EXECUTOR, TASK094_CONTRACT_REPAIR_TARGET}
                if tuple(task_ids) == (TASK094_CONTRACT_REPAIR_EXECUTOR,)
                else {TASK100_CONTRACT_REPAIR_EXECUTOR, TASK100_CONTRACT_REPAIR_TARGET}
                if tuple(task_ids) == (TASK100_CONTRACT_REPAIR_EXECUTOR,)
                else {TASK116_CONTRACT_REPAIR_EXECUTOR, TASK116_CONTRACT_REPAIR_TARGET}
                if tuple(task_ids) == (TASK116_CONTRACT_REPAIR_EXECUTOR,)
                else {CONTRACT_CONFLICT_REPAIR_EXECUTOR, CONTRACT_CONFLICT_REPAIR_TARGET}
            )
            is_allowed_task = (
                task_match is not None and task_match.group(1) in contract_task_ids
            )
            is_allowed_test = (
                len(PurePosixPath(path).parts) == 3
                and PurePosixPath(path).parts[:2] == ("tests", "研发中心")
                and PurePosixPath(path).suffix == ".py"
            )
            if path not in CONTRACT_CONFLICT_REPAIR_ALLOWED_PATHS and not is_allowed_task and not is_allowed_test:
                _append_reason(
                    reasons,
                    f"任务合同冲突修复变更路径“{path}”不允许自动合并",
                )
        elif change_type == STAGE1_CONTRACT_REPAIR_TYPE:
            is_allowed_test = (
                len(PurePosixPath(path).parts) == 3
                and PurePosixPath(path).parts[:2] == ("tests", "研发中心")
                and PurePosixPath(path).suffix == ".py"
            )
            if path not in STAGE1_CONTRACT_REPAIR_ALLOWED_PATHS and not is_allowed_test:
                _append_reason(
                    reasons,
                    f"阶段1覆盖受限合同修订变更路径“{path}”不允许自动合并",
                )
        elif change_type == STAGE1_COVERAGE_V2_TYPE:
            if path not in STAGE1_COVERAGE_V2_ALLOWED_PATHS:
                _append_reason(
                    reasons,
                    f"阶段1覆盖受限V2合同修订变更路径“{path}”不允许自动合并",
                )

    for task_id in task_ids:
        if task_id not in changed_task_ids and task_id not in allowed_unreferenced_task_ids:
            _append_reason(reasons, f"任务-{task_id}的任务文件未在PR中更新")

    return EligibilityResult(eligible=not reasons, reasons=tuple(reasons))


def _read_task_at_ref(repo_root: Path, ref: str, task_id: str) -> str | None:
    task_path = f"docs/研发中心/任务/任务-{task_id}.md"
    result = subprocess.run(
        ["git", "show", f"{ref}:{task_path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _read_path_at_ref(repo_root: Path, ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _load_ref_tasks(
    repo_root: Path,
    ref: str,
    task_ids: Sequence[str],
) -> dict[str, str]:
    tasks: dict[str, str] = {}
    for task_id in task_ids:
        content = _read_task_at_ref(repo_root, ref, task_id)
        if content is not None:
            tasks[task_id] = content
    return tasks


def _load_ref_task_ids(repo_root: Path, ref: str) -> tuple[str, ...]:
    """从基线Git树有界加载全部任务编号，不读取合同正文。"""

    output = _read_git_output_bounded(
        repo_root,
        [
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            ref,
            "--",
            "docs/研发中心/任务",
        ],
        MAX_BASE_TASK_TREE_BYTES,
        literal_paths=True,
    )
    paths = parse_nul_paths(output)
    if len(paths) > MAX_BASE_TASK_COUNT:
        raise ValueError("基线任务文件数超出上限")
    task_ids = tuple(
        match.group(1)
        for path in paths
        if (match := TASK_FILE_PATTERN.fullmatch(path)) is not None
    )
    if not task_ids or len(task_ids) != len(set(task_ids)):
        raise ValueError("基线任务编号事实无效")
    return tuple(sorted(task_ids))


def _git_text(repo_root: Path, arguments: Sequence[str]) -> str | None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git_is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    """验证一个Git提交是否是另一个提交的祖先，不读取提交正文。"""

    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def _derive_merge_facts(
    repo_root: Path,
    base_ref: str,
    head_tasks: Mapping[str, str],
    referenced_prs: Mapping[str, object] | None = None,
) -> dict[str, MergeFact]:
    """只从已进入main基线的Git提交推导合并事实。"""

    facts: dict[str, MergeFact] = {}
    for task_id, task in head_tasks.items():
        declared = _task_merge_fact(task) or _task_cancellation_fact(task)
        if declared is None:
            continue
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", declared.sha, base_ref],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        if ancestry.returncode != 0:
            continue
        subject = _git_text(repo_root, ["show", "-s", "--format=%s", declared.sha])
        committed_at = _git_text(
            repo_root, ["show", "-s", "--format=%cI", declared.sha]
        )
        if subject is None or committed_at is None:
            continue
        pr_match = re.fullmatch(r"Merge pull request #(\d+) from .+", subject)
        if pr_match is None:
            # GitHub允许调用方覆盖合并提交主题。兼容路径只接受可复算的
            # 双父提交，并要求任务执行记录中的交付头位于第二父链；不能
            # 仅凭自定义文案、Issue或聊天把提交解释为PR合并事实。
            parents_text = _git_text(
                repo_root, ["show", "-s", "--format=%P", declared.sha]
            )
            parents = parents_text.split() if parents_text else []
            delivery_match = DELIVERY_SHA_PATTERN.search(task)
            if len(parents) == 2:
                if (
                    delivery_match is None
                    or not _git_is_ancestor(repo_root, parents[0], base_ref)
                    or not _git_is_ancestor(repo_root, delivery_match.group(1), parents[1])
                ):
                    continue
                pr_number = declared.pr_number
            elif len(parents) == 1:
                # GitHub squash merge产生单父提交，不能仅凭提交正文推断为PR合并。
                # 只有工作流从GitHub API读取到同号、已合并、目标main且
                # merge_commit_sha精确匹配的PR事实时才接受；父提交必须仍在
                # 当前main祖先链中，防止任意单父提交冒充合并事实。
                evidence = (
                    referenced_prs.get(str(declared.pr_number))
                    if isinstance(referenced_prs, Mapping)
                    else None
                )
                if not isinstance(evidence, Mapping):
                    continue
                if (
                    evidence.get("number") != declared.pr_number
                    or evidence.get("state") != "closed"
                    or not evidence.get("merged_at")
                    or evidence.get("merge_commit_sha") != declared.sha
                    or evidence.get("base_ref") != "main"
                    or evidence.get("base_repo") != "xk320/zhishi"
                    or evidence.get("head_repo") != "xk320/zhishi"
                    or not re.fullmatch(r"[0-9a-f]{40}", str(evidence.get("head_sha", "")))
                    or not _git_is_ancestor(repo_root, parents[0], base_ref)
                ):
                    continue
                evidence_base_sha = evidence.get("base_sha")
                if (
                    isinstance(evidence_base_sha, str)
                    and re.fullmatch(r"[0-9a-f]{40}", evidence_base_sha)
                    and not (
                        parents[0] == evidence_base_sha
                        or _git_is_ancestor(repo_root, evidence_base_sha, base_ref)
                    )
                ):
                    continue
                pr_number = declared.pr_number
            else:
                continue
        else:
            pr_number = int(pr_match.group(1))
        try:
            normalized_time = datetime.fromisoformat(committed_at).strftime(
                "%Y-%m-%d %H:%M:%S %z"
            )
        except ValueError:
            continue
        facts[task_id] = MergeFact(
            sha=declared.sha,
            merged_at=normalized_time,
            pr_number=pr_number,
        )
    return facts


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证《知势》PR自动合并资格")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--metadata", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    repo_root = arguments.repo_root.resolve()
    metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
    try:
        path_facts = _load_path_facts(
            repo_root,
            arguments.base_ref,
            arguments.head_ref,
        )
        base_task_ids = _load_ref_task_ids(
            repo_root,
            arguments.base_ref,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        print(
            json.dumps(
                {
                    "eligible": False,
                    "reasons": ["Git路径事实加载失败"],
                    "changed_paths": [],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    changed_paths = tuple(fact.path for fact in path_facts)
    pr_body = str(metadata.get("body", ""))
    change_type = parse_change_type(pr_body)
    raw_body_task_ids = _raw_task_references(pr_body)
    task_ids = set(parse_task_references(pr_body))
    body_task_ids = set(task_ids)
    contract_conflict_executor = None
    if change_type == CONTRACT_CONFLICT_REPAIR_TYPE:
        contract_conflict_executor = _contract_conflict_executor(raw_body_task_ids)
        if contract_conflict_executor is None:
            print(
                json.dumps(
                    {
                        "eligible": False,
                        "reasons": ["任务合同冲突修复正文必须精确引用已登记执行任务"],
                        "changed_paths": list(changed_paths),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 1
    for path in changed_paths:
        match = TASK_FILE_PATTERN.fullmatch(path)
        if match is not None:
            # 阻塞合同修复的PR正文只引用执行任务；目标任务由固定映射
            # 加载用于合同校验，不把目标路径误算成第二个执行任务。
            if (
                change_type == BLOCKED_CONTRACT_REPAIR_TYPE
                and match.group(1) in BLOCKED_CONTRACT_REPAIR_TARGETS
            ):
                continue
            if (
                change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                and body_task_ids == {TASK094_CONTRACT_REPAIR_EXECUTOR}
                and match.group(1) == TASK094_CONTRACT_REPAIR_TARGET
            ):
                continue
            if (
                change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                and body_task_ids == {TASK100_CONTRACT_REPAIR_EXECUTOR}
                and match.group(1) == TASK100_CONTRACT_REPAIR_TARGET
            ):
                continue
            if (
                change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                and body_task_ids == {TASK116_CONTRACT_REPAIR_EXECUTOR}
                and match.group(1) == TASK116_CONTRACT_REPAIR_TARGET
            ):
                continue
            if (
                change_type == STAGE1_CONTRACT_REPAIR_TYPE
                and match.group(1) == STAGE1_CONTRACT_REPAIR_TARGET
            ):
                continue
            if (
                change_type == STAGE1_COVERAGE_V2_TYPE
                and match.group(1) in STAGE1_COVERAGE_V2_TARGETS
            ):
                continue
            task_ids.add(match.group(1))
    if len(task_ids) > _task_reference_limit(change_type):
        print(
            json.dumps(
                {
                    "eligible": False,
                    "reasons": [_task_reference_limit_reason(change_type)],
                    "changed_paths": list(changed_paths),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    ordered_ids = tuple(sorted(task_ids))

    load_ids = set(ordered_ids)
    if change_type == "任务登记" and ordered_ids == (TASK100_CONTRACT_REPAIR_EXECUTOR,):
        load_ids.add(TASK100_CONTRACT_REPAIR_GOVERNANCE)
    if change_type == BLOCKED_CONTRACT_REPAIR_TYPE and len(ordered_ids) == 1:
        target_id = {
            BLOCKED_CONTRACT_REPAIR_EXECUTOR: BLOCKED_CONTRACT_REPAIR_TARGET,
            ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR: ROOT_READONLY_CONTRACT_REPAIR_TARGET,
        }.get(ordered_ids[0])
        if target_id is not None:
            load_ids.add(target_id)
    if (
        change_type == CONTRACT_CONFLICT_REPAIR_TYPE
        and ordered_ids == (TASK094_CONTRACT_REPAIR_EXECUTOR,)
    ):
        load_ids.add(TASK094_CONTRACT_REPAIR_TARGET)
    if (
        change_type == CONTRACT_CONFLICT_REPAIR_TYPE
        and ordered_ids == (TASK100_CONTRACT_REPAIR_EXECUTOR,)
    ):
        load_ids.update(
            {TASK100_CONTRACT_REPAIR_GOVERNANCE, TASK100_CONTRACT_REPAIR_TARGET}
        )
    if (
        change_type == CONTRACT_CONFLICT_REPAIR_TYPE
        and ordered_ids == (TASK116_CONTRACT_REPAIR_EXECUTOR,)
    ):
        load_ids.add(TASK116_CONTRACT_REPAIR_TARGET)
    if (
        change_type == STAGE1_CONTRACT_REPAIR_TYPE
        and ordered_ids == (STAGE1_CONTRACT_REPAIR_EXECUTOR,)
    ):
        load_ids.update(
            {
                STAGE1_CONTRACT_REPAIR_TARGET,
                TASK116_CONTRACT_REPAIR_EXECUTOR,
            }
        )
    if (
        change_type == STAGE1_COVERAGE_V2_TYPE
        and ordered_ids == (STAGE1_COVERAGE_V2_EXECUTOR,)
    ):
        load_ids.update(STAGE1_COVERAGE_V2_TARGETS)
    loaded_ids = tuple(sorted(load_ids))
    base_tasks = _load_ref_tasks(repo_root, arguments.base_ref, loaded_ids)
    head_tasks = _load_ref_tasks(repo_root, arguments.head_ref, loaded_ids)
    # 取消状态的替代任务只作为证据引用，不属于本次状态迁移；仍从同一
    # PR 的基线/头提交加载其任务文件，以便用main中的真实合并事实复算。
    for task in tuple(head_tasks.values()):
        support_task_id = _cancellation_support_task_id(task)
        if support_task_id is None or support_task_id not in base_task_ids:
            continue
        base_tasks.setdefault(
            support_task_id,
            _read_task_at_ref(repo_root, arguments.base_ref, support_task_id) or "",
        )
        head_tasks.setdefault(
            support_task_id,
            _read_task_at_ref(repo_root, arguments.head_ref, support_task_id) or "",
        )
    result = evaluate_eligibility(
        repo_root=repo_root,
        base_ref=arguments.base_ref,
        changed_paths=changed_paths,
        pr_body=pr_body,
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_task_ids=base_task_ids,
        base_branch=str(metadata.get("base_ref", "")),
        repository=str(metadata.get("repository", "")),
        head_repository=str(metadata.get("head_repository", "")),
        merge_facts=_derive_merge_facts(
            repo_root,
            arguments.base_ref,
            head_tasks,
            referenced_prs=metadata.get("referenced_prs"),
        ),
        base_board=_read_path_at_ref(
            repo_root, arguments.base_ref, "docs/研发中心/看板.md"
        ),
        head_board=_read_path_at_ref(
            repo_root, arguments.head_ref, "docs/研发中心/看板.md"
        ),
        path_facts=path_facts,
        enforce_board_sync=True,
        task_ids_override=(
            (contract_conflict_executor,)
            if change_type == CONTRACT_CONFLICT_REPAIR_TYPE
            else (STAGE1_COVERAGE_V2_EXECUTOR,)
            if change_type == STAGE1_COVERAGE_V2_TYPE
            else None
        ),
        head_ref_name=str(metadata.get("head_ref", "")) or None,
        pr_number=(
            int(metadata["pr_number"])
            if str(metadata.get("pr_number", "")).isdigit()
            else None
        ),
    )
    conflict_reasons = _cross_carrier_conflict_reasons(
        repo_root,
        arguments.base_ref,
        arguments.head_ref,
        metadata={
            **metadata,
            "base_sha": arguments.base_ref,
            "head_sha": arguments.head_ref,
        },
        changed_paths=changed_paths,
        task_id=(
            next(
                (
                    candidate
                    for candidate in ordered_ids
                    if candidate
                    in {
                        BLOCKED_CONTRACT_REPAIR_EXECUTOR,
                        ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR,
                    }
                ),
                "",
            )
            if change_type == BLOCKED_CONTRACT_REPAIR_TYPE
            else contract_conflict_executor or ""
            if change_type == CONTRACT_CONFLICT_REPAIR_TYPE
            else next(iter(ordered_ids), "")
        ),
    )
    if change_type == STAGE1_COVERAGE_V2_TYPE:
        # 目标合同的通用漂移冲突由本PR内固定V2指纹门逐段复算；只过滤
        # 这两个明确目标的重复通用冲突，其他跨载体冲突仍失败关闭。
        conflict_reasons = tuple(
            reason
            for reason in conflict_reasons
            if not (
                "TASK_CONTRACT_CONFLICT" in reason
                and (
                    "任务-000098.md" in reason
                    or "任务-000106.md" in reason
                )
            )
        )
    if conflict_reasons:
        result = EligibilityResult(
            eligible=False,
            reasons=tuple(dict.fromkeys((*result.reasons, *conflict_reasons))),
        )
    print(
        json.dumps(
            {
                "eligible": result.eligible,
                "reasons": list(result.reasons),
                "changed_paths": list(changed_paths),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
