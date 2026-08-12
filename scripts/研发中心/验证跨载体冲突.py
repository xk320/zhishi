#!/usr/bin/env python3
"""验证研发中心跨载体冲突，并提供仅面向派生看板的可逆修复计划。"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


PROTOCOL_VERSION = "zhishi-conflict-resolution/v1"
TASK_PATTERN = re.compile(r"^docs/研发中心/任务/任务-(\d{6})\.md$")
TITLE_PATTERN = re.compile(r"^# 任务-(\d{6})：(.+)$", re.MULTILINE)
STATUS_PATTERN = re.compile(r"^- 状态：(.+)$", re.MULTILINE)
PRIORITY_PATTERN = re.compile(r"^- 优先级：(.+)$", re.MULTILINE)
BRANCH_PATTERN = re.compile(r"^- 执行分支：`([^`]+)`$", re.MULTILINE)
START_PATTERN = re.compile(
    r"^- 开始时间：`(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:?\d{2})`$",
    re.MULTILINE,
)
BLOCKER_PATTERN = re.compile(r"^- 当前阻塞原因：(.+)$", re.MULTILINE)
PR_PATTERN = re.compile(r"^- Pull Request：(.+)$", re.MULTILINE)
MERGE_PATTERN = re.compile(r"^- 合并提交SHA：`([0-9a-f]{40})`$", re.MULTILINE)
CANCELLATION_SUPPORT_TASK_PATTERN = re.compile(
    r"^- 取消依据任务：任务-(\d{6})$", re.MULTILINE
)
CANCELLATION_TIME_PATTERN = re.compile(
    r"^- 取消时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
CANCELLATION_REASON_PATTERN = re.compile(
    r"^- 取消原因：([^|\r\n]+)$", re.MULTILINE
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
PR_NUMBER_PATTERN = re.compile(r"#(\d+)")
CHANGE_TYPE_PATTERN = re.compile(
    r"(?ms)^## 变更类型\s*\n+\s*-\s*(任务登记|任务交付|合并后状态闭环|阻塞任务合同修复|任务合同冲突修复)\s*$"
)
CONTRACT_CONFLICT_REPAIR_TYPE = "任务合同冲突修复"
CONTRACT_CONFLICT_REPAIR_EXECUTOR = "000068"
CONTRACT_CONFLICT_REPAIR_TARGET = "000066"
TASK094_CONTRACT_REPAIR_EXECUTOR = "000095"
TASK094_CONTRACT_REPAIR_TARGET = "000094"
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


def _apply_task094_contract_repair(text: str) -> str | None:
    repaired = text
    for old, new in TASK094_CONTRACT_REPLACEMENTS:
        if repaired.count(old) != 1 or new in repaired:
            return None
        repaired = repaired.replace(old, new, 1)
    return repaired
BLOCKED_CONTRACT_REPAIR_EXECUTOR = "000056"
BLOCKED_CONTRACT_REPAIR_TARGET = "000055"
ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR = "000086"
ROOT_READONLY_CONTRACT_REPAIR_TARGET = "000084"
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
DEPENDENCY_PATTERN = re.compile(r"任务-(\d{6})")
STANDARD_STATUSES = frozenset(
    {"待执行", "执行中", "阻塞", "待评审", "需修复", "已完成", "已取消"}
)
SECTIONS = ("待执行", "执行中", "阻塞", "待评审", "需修复", "已完成", "已取消")
TASK_DIR = "docs/研发中心/任务"
BOARD_PATH = "docs/研发中心/看板.md"
BOARD_SCHEMA_PATH = "docs/研发中心/任务看板模式.md"
CURRENT_SCOPE_CONFIGS = (
    "config/数据/数据来源与资产身份.json",
    "config/审计/数据质量持续验证.json",
    "config/审计/最小数据闭环容量.json",
)
FORWARD_SCOPE_DOCS = ("AGENTS.md", "README.md")
SCALE_SCOPE_DOCS = (
    "docs/研究/市场状态—事件关联分析合同.md",
    "docs/研究/数据质量持续验证合同.md",
    "docs/架构/历史事件回放与结果统计体系.md",
)
HISTORICAL_IMMUTABLE_PATHS = (
    "docs/治理/整体评估-2026-07-22.md",
    "docs/审计/数据资产审计报告.md",
    "docs/审计/数据源清单.md",
    "artifacts/审计/数据源清单.csv",
    "docs/审计/数据质量审计报告.md",
    "artifacts/审计/数据质量结果.csv",
    "docs/审计/历史现场重放验证.md",
    "artifacts/审计/历史重放结果.csv",
)
CONFLICT_CODES = (
    "BOARD_DERIVED_DRIFT",
    "TASK_DUPLICATE",
    "TASK_CONTRACT_CONFLICT",
    "DEPENDENCY_CYCLE",
    "SCOPE_BOUNDARY_DRIFT",
    "PR_BASELINE_DRIFT",
    "REVIEW_EVIDENCE_STALE",
    "RESOURCE_OR_API_FAILURE",
    "UNCLASSIFIED_CONFLICT",
)
MAX_TEXT_BYTES = 5 * 1024 * 1024
RULE_FINGERPRINT = ""
MAX_GIT_SECONDS = 15
MAX_TASK_FILES = 500
MAX_TREE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Conflict:
    """不含敏感正文的单个冲突事实。"""

    code: str
    path: str
    authority: str
    decision: str
    repair_mode: str
    release_condition: str

    def as_dict(self) -> dict[str, str]:
        return {
            "conflict_code": self.code,
            "path": self.path,
            "authority": self.authority,
            "decision": self.decision,
            "repair_mode": self.repair_mode,
            "release_condition": self.release_condition,
        }


@dataclass(frozen=True)
class ConflictReport:
    """跨载体检查的可复现结果。"""

    base_sha: str
    head_sha: str
    conflicts: tuple[Conflict, ...]

    @property
    def ok(self) -> bool:
        return not self.conflicts

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(
            f"{item.code}:{item.path}:{item.decision}" for item in self.conflicts
        )

    def as_dict(self, *, repository: str = "xk320/zhishi", task_id: str = "") -> dict[str, object]:
        evidence = hashlib.sha256(
            json.dumps(
                [item.as_dict() for item in self.conflicts],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return {
            "protocol_version": PROTOCOL_VERSION,
            "repository": repository,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "task_id": task_id,
            "rule_fingerprint": RULE_FINGERPRINT,
            "conflicts": [item.as_dict() for item in self.conflicts],
            "evidence_fingerprint": evidence,
        }


def _conflict(
    code: str,
    path: str,
    *,
    authority: str,
    decision: str,
    repair_mode: str,
    release_condition: str,
) -> Conflict:
    return Conflict(code, path, authority, decision, repair_mode, release_condition)


def resource_policy_is_safe(
    *, memory_pressure: str, memory_available_percent: float, disk_available_gib: float
) -> bool:
    """资源不足时安全停机，不把失败重试为成功。"""

    return (
        memory_pressure in {"normal", "warning"}
        and memory_available_percent >= 20
        and disk_available_gib >= 5
    )


def review_evidence_is_current(
    *, base_sha: str, head_sha: str, reviewed_base_sha: str, reviewed_head_sha: str
) -> bool:
    """评审证据必须绑定当前base/head，提交变化即失效。"""

    return base_sha == reviewed_base_sha and head_sha == reviewed_head_sha


def _git(repo_root: Path, *arguments: str) -> tuple[int, bytes, bytes]:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repo_root,
            check=False,
            capture_output=True,
            timeout=MAX_GIT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"
    except OSError:
        return 126, b"", b"os-error"
    return result.returncode, result.stdout, result.stderr


def _resolve_ref(repo_root: Path, ref: str) -> str | None:
    code, stdout, _ = _git(repo_root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if code != 0:
        return None
    if len(stdout) > MAX_TREE_BYTES:
        return None
    value = stdout.decode("ascii", errors="ignore").strip()
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else None


def _read_at_ref(repo_root: Path, ref: str, path: str) -> str | None:
    code, stdout, _ = _git(repo_root, "show", f"{ref}:{path}")
    if code != 0 or len(stdout) > MAX_TEXT_BYTES:
        return None
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _list_task_paths(repo_root: Path, ref: str) -> tuple[str, ...] | None:
    code, stdout, _ = _git(repo_root, "ls-tree", "-r", "-z", "--name-only", ref, "--", TASK_DIR)
    if code != 0 or len(stdout) > MAX_TREE_BYTES:
        return None
    try:
        decoded = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    paths = tuple(
        sorted(
            path
            for path in decoded.split("\0")
            if path
            if TASK_PATTERN.fullmatch(path)
        )
    )
    return paths


def _field(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _task_records(
    repo_root: Path, ref: str, conflicts: list[Conflict]
) -> dict[str, tuple[str, str, str, str, tuple[str, ...], str, str, str, str, str]]:
    paths = _list_task_paths(repo_root, ref)
    if paths is None:
        conflicts.append(
            _conflict(
                "UNCLASSIFIED_CONFLICT",
                TASK_DIR,
                authority="任务文件",
                decision="失败关闭",
                repair_mode="禁止写入",
                release_condition="恢复可读Git树并重新检查",
            )
        )
        return {}
    if len(paths) > MAX_TASK_FILES:
        conflicts.append(
            _conflict(
                "RESOURCE_OR_API_FAILURE",
                TASK_DIR,
                authority="资源策略",
                decision="失败关闭",
                repair_mode="禁止扩容或重试为成功",
                release_condition="降低任务文件数量并重新检查",
            )
        )
        return {}
    records: dict[str, tuple[str, str, str, str, tuple[str, ...], str, str, str, str, str]] = {}
    for path in paths:
        match = TASK_PATTERN.fullmatch(path)
        assert match is not None
        task_id = match.group(1)
        if task_id in records:
            conflicts.append(
                _conflict(
                    "TASK_DUPLICATE",
                    path,
                    authority="任务文件",
                    decision="失败关闭",
                    repair_mode="禁止写入",
                    release_condition="保留全部候选并创建治理修复任务",
                )
            )
            continue
        text = _read_at_ref(repo_root, ref, path)
        if text is None:
            conflicts.append(
                _conflict(
                    "UNCLASSIFIED_CONFLICT",
                    path,
                    authority="任务文件",
                    decision="失败关闭",
                    repair_mode="禁止写入",
                    release_condition="恢复UTF-8任务文件并重新检查",
                )
            )
            continue
        title_matches = TITLE_PATTERN.findall(text)
        status_matches = STATUS_PATTERN.findall(text)
        priority = _field(PRIORITY_PATTERN, text) or ""
        branch = _field(BRANCH_PATTERN, text) or ""
        started = _field(START_PATTERN, text) or ""
        blocker = _field(BLOCKER_PATTERN, text) or ""
        pr = _field(PR_PATTERN, text) or ""
        merge = _field(MERGE_PATTERN, text) or ""
        cancellation_support_task = _field(
            CANCELLATION_SUPPORT_TASK_PATTERN, text
        ) or ""
        cancellation_reason = _field(CANCELLATION_REASON_PATTERN, text) or ""
        if status_matches and status_matches[0] == "已取消":
            pr = _field(CANCELLATION_PR_PATTERN, text) or ""
            merge = _field(CANCELLATION_MERGE_SHA_PATTERN, text) or ""
        dependency_lines = [
            line for line in text.splitlines() if line.startswith("- 唯一前序依赖：")
        ]
        dependencies = tuple(
            sorted(set(DEPENDENCY_PATTERN.findall(dependency_lines[0])))
            if len(dependency_lines) == 1
            else ()
        )
        if len(title_matches) != 1 or title_matches[0][0] != task_id:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止静默改写",
                    release_condition="补齐且冻结唯一任务标题",
                )
            )
        if len(status_matches) != 1 or status_matches[0] not in STANDARD_STATUSES:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止静默改写",
                    release_condition="修复为一个标准状态",
                )
            )
        if len(dependency_lines) > 1:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止静默改写",
                    release_condition="保留一个唯一前序依赖字段",
                )
            )
        if status_matches and status_matches[0] == "已取消":
            cancellation_fields = (
                CANCELLATION_TIME_PATTERN,
                CANCELLATION_REASON_PATTERN,
                CANCELLATION_SUPPORT_TASK_PATTERN,
                CANCELLATION_PR_PATTERN,
                CANCELLATION_MERGE_TIME_PATTERN,
                CANCELLATION_MERGE_SHA_PATTERN,
            )
            if any(len(pattern.findall(text)) != 1 for pattern in cancellation_fields):
                conflicts.append(
                    _conflict(
                        "TASK_CONTRACT_CONFLICT",
                        path,
                        authority="取消状态证据合同",
                        decision="失败关闭",
                        repair_mode="禁止伪造或缺失取消证据",
                        release_condition="补齐唯一取消时间、原因、替代任务和main合并事实",
                    )
                )
        records[task_id] = (
            path,
            title_matches[0][1].strip() if title_matches else "",
            status_matches[0] if status_matches else "",
            priority,
            dependencies,
            branch,
            started,
            blocker,
            pr,
            merge,
            cancellation_support_task,
            cancellation_reason,
        )
        if status_matches and status_matches[0] == "执行中" and (not branch or not started):
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止静默改写",
                    release_condition="补齐执行分支和开始时间",
                )
            )
    for task_id, record in records.items():
        if record[2] != "已取消":
            continue
        support_task_id = record[10] if len(record) > 10 else ""
        support = records.get(support_task_id)
        if not support_task_id or support_task_id == task_id or support is None:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    record[0],
                    authority="取消状态证据合同",
                    decision="失败关闭",
                    repair_mode="禁止取消未知或自身任务",
                    release_condition="引用已登记且已完成的替代任务",
                )
            )
        elif support[2] != "已完成":
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    record[0],
                    authority="取消状态证据合同",
                    decision="失败关闭",
                    repair_mode="禁止引用未完成替代任务",
                    release_condition="替代任务先进入main并完成状态闭环",
                )
            )
    return records


def _schema_at_ref(repo_root: Path, ref: str) -> Mapping[str, object] | None:
    text = _read_at_ref(repo_root, ref, BOARD_SCHEMA_PATH)
    if text is None:
        return None
    try:
        document = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "content_sha256",
        "sections",
    }:
        return None
    sections = document.get("sections")
    if document.get("schema_version") != "zhishi-task-board/v1" or not isinstance(sections, dict):
        return None
    if set(sections) != set(SECTIONS):
        return None
    payload = json.dumps(
        {"schema_version": document["schema_version"], "sections": sections},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if document.get("content_sha256") != hashlib.sha256(payload).hexdigest():
        return None
    return document


def _board_sections(text: str) -> dict[str, str] | None:
    all_headings = list(re.finditer(r"^## (.+)$", text, re.MULTILINE))
    matches = [match for match in all_headings if match.group(1) in SECTIONS]
    if len(matches) != len(SECTIONS) or {match.group(1) for match in matches} != set(SECTIONS):
        return None
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        next_heading = next(
            (heading.start() for heading in all_headings if heading.start() > match.start()),
            len(text),
        )
        end = next_heading
        sections[match.group(1)] = text[match.end() : end]
    return sections


def _check_board(
    repo_root: Path,
    ref: str,
    records: Mapping[str, tuple],
    conflicts: list[Conflict],
) -> None:
    schema = _schema_at_ref(repo_root, ref)
    board = _read_at_ref(repo_root, ref, BOARD_PATH)
    if schema is None or board is None:
        conflicts.append(
            _conflict(
                "UNCLASSIFIED_CONFLICT",
                BOARD_PATH,
                authority="任务看板模式",
                decision="失败关闭",
                repair_mode="禁止写入",
                release_condition="恢复有效机器看板合同",
            )
        )
        return
    sections = _board_sections(board)
    if sections is None:
        conflicts.append(
            _conflict(
                "BOARD_DERIVED_DRIFT",
                BOARD_PATH,
                authority="任务文件与机器看板模式",
                decision="生成可逆修复计划",
                repair_mode="仅派生看板",
                release_condition="按任务文件重建看板",
            )
        )
        return
    rows_by_id: dict[str, list[tuple[str, str]]] = {}
    for section, body in sections.items():
        expected_header, expected_separator = schema["sections"][section]  # type: ignore[index]
        if body.strip() == "无。":
            continue
        lines = body.splitlines()
        try:
            header_index = next(index for index, line in enumerate(lines) if line.strip() == expected_header)
            if lines[header_index + 1].strip() != expected_separator:
                raise StopIteration
        except (StopIteration, IndexError):
            conflicts.append(
                _conflict(
                    "BOARD_DERIVED_DRIFT",
                    BOARD_PATH,
                    authority="机器看板模式",
                    decision="生成可逆修复计划",
                    repair_mode="仅派生看板",
                    release_condition="恢复规范表头和分隔行",
                )
            )
            continue
        for line in lines[header_index + 2 :]:
            match = re.match(r"^\|\s*(?:P[0-3]\s*\|\s*)?任务-(\d{6})\s*\|", line)
            if match:
                rows_by_id.setdefault(match.group(1), []).append((section, line))
    for task_id, record in records.items():
        _, title, status, priority, _ = record[:5]
        rows = rows_by_id.get(task_id, [])
        if len(rows) != 1:
            conflicts.append(
                _conflict(
                    "BOARD_DERIVED_DRIFT",
                    BOARD_PATH,
                    authority="任务文件",
                    decision="生成可逆修复计划",
                    repair_mode="仅派生看板",
                    release_condition=f"任务-{task_id}在看板中保留唯一映射",
                )
            )
            continue
        section, row = rows[0]
        priority_mismatch = status in {"待执行", "执行中", "阻塞", "待评审", "需修复"} and f"| {priority} |" not in row
        branch = record[5] if len(record) > 5 else ""
        started = record[6] if len(record) > 6 else ""
        blocker = record[7] if len(record) > 7 else ""
        pr = record[8] if len(record) > 8 else ""
        merge = record[9] if len(record) > 9 else ""
        cancellation_support_task = record[10] if len(record) > 10 else ""
        cancellation_reason = record[11] if len(record) > 11 else ""
        metadata_mismatch = False
        if status == "执行中" and branch and f"`{branch}`" not in row:
            metadata_mismatch = True
        if status == "执行中" and started and started not in row:
            metadata_mismatch = True
        if status in {"待评审", "需修复"} and branch and f"`{branch}`" not in row:
            metadata_mismatch = True
        if status in {"待评审", "需修复"} and pr:
            pr_match = PR_NUMBER_PATTERN.search(pr)
            if pr_match is not None and f"#{pr_match.group(1)}" not in row:
                metadata_mismatch = True
        if status in {"已完成", "已取消"} and pr and merge and (
            (PR_NUMBER_PATTERN.search(pr) is not None
             and f"#{PR_NUMBER_PATTERN.search(pr).group(1)}" not in row)
            or merge not in row
        ):
            metadata_mismatch = True
        if status == "已取消" and (
            not cancellation_support_task
            or f"替代任务-{cancellation_support_task}" not in row
            or not cancellation_reason
            or f"取消原因：{cancellation_reason}" not in row
        ):
            metadata_mismatch = True
        if section != status or f"| {title} |" not in row or priority_mismatch or metadata_mismatch:
            conflicts.append(
                _conflict(
                    "BOARD_DERIVED_DRIFT",
                    BOARD_PATH,
                    authority="任务文件",
                    decision="生成可逆修复计划",
                    repair_mode="仅派生看板",
                    release_condition=f"同步任务-{task_id}的状态、名称和优先级",
                )
            )
    unknown = sorted(set(rows_by_id).difference(records))
    if unknown:
        conflicts.append(
            _conflict(
                "TASK_DUPLICATE",
                BOARD_PATH,
                authority="任务文件",
                decision="失败关闭",
                repair_mode="禁止写入",
                release_condition="删除无任务文件的看板行并重新检查",
            )
        )


def _check_dependencies(
    records: Mapping[str, tuple],
    conflicts: list[Conflict],
) -> None:
    graph = {
        task_id: tuple(dep for dep in record[4] if dep in records)
        for task_id, record in records.items()
    }
    for task_id, record in records.items():
        dependencies = record[4]
        unknown = sorted(set(dependencies).difference(records))
        if unknown:
            conflicts.append(
                _conflict(
                    "DEPENDENCY_CYCLE",
                    f"{TASK_DIR}/任务-{task_id}.md",
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止猜测依赖",
                    release_condition="登记所有依赖并重新检查",
                )
            )
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            conflicts.append(
                _conflict(
                    "DEPENDENCY_CYCLE",
                    f"{TASK_DIR}/任务-{task_id}.md",
                    authority="任务文件",
                    decision="阻塞",
                    repair_mode="禁止猜测依赖",
                    release_condition="解除依赖环并重新检查",
                )
            )
            return
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in graph.get(task_id, ()):
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in sorted(graph):
        visit(task_id)


def _check_scope(repo_root: Path, ref: str, conflicts: list[Conflict]) -> None:
    for path in CURRENT_SCOPE_CONFIGS:
        text = _read_at_ref(repo_root, ref, path)
        if text is None:
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究范围合同",
                    decision="失败关闭",
                    repair_mode="禁止改写历史范围",
                    release_condition="恢复当前范围配置并重新检查",
                )
            )
            continue
        try:
            payload = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究范围合同",
                    decision="失败关闭",
                    repair_mode="禁止猜测范围",
                    release_condition="恢复有效JSON合同",
                )
            )
            continue
        targets = payload.get("标的")
        if targets is None and isinstance(payload.get("作用域"), dict):
            targets = payload["作用域"].get("标的")
        if targets != ["BTC", "ETH"]:
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究范围合同",
                    decision="失败关闭",
                    repair_mode="禁止改写历史范围",
                    release_condition="恢复BTC/ETH现行范围并重新检查",
                )
            )
    for path in FORWARD_SCOPE_DOCS:
        text = _read_at_ref(repo_root, ref, path)
        if text is None or not any(term in text for term in ("BTC", "比特币")) or not any(term in text for term in ("ETH", "以太坊")):
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究范围合同",
                    decision="失败关闭",
                    repair_mode="禁止猜测范围",
                    release_condition="补齐BTC/ETH现行范围声明",
                )
            )
            continue
        for line in text.splitlines():
            if "SOL" in line and not any(
                marker in line for marker in ("历史", "不可变", "仅历史", "不属于当前", "未纳入")
            ):
                conflicts.append(
                    _conflict(
                        "SCOPE_BOUNDARY_DRIFT",
                        path,
                        authority="当前前向研究范围",
                        decision="失败关闭",
                        repair_mode="禁止把历史SOL纳入当前入口",
                        release_condition="将SOL限定为明确历史上下文或移出前向文档",
                    )
                )
    for path in SCALE_SCOPE_DOCS:
        text = _read_at_ref(repo_root, ref, path)
        if text is None:
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究尺度合同",
                    decision="失败关闭",
                    repair_mode="禁止猜测尺度",
                    release_condition="恢复主研究尺度和观察窗口合同",
                )
            )
            continue
        if any(scale not in text for scale in ("4小时", "8小时", "24小时", "48小时")):
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究尺度合同",
                    decision="失败关闭",
                    repair_mode="禁止猜测尺度",
                    release_condition="恢复4/8/24/48小时主研究尺度",
                )
            )
        if "15分钟" not in text or "1小时" not in text or not any(
            phrase in text for phrase in ("事后结果观察", "事后观察", "结果观察窗口")
        ):
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="当前研究尺度合同",
                    decision="失败关闭",
                    repair_mode="禁止短窗口越权",
                    release_condition="明确15分钟/1小时仅为事后观察窗口",
                )
            )
        current_text = text.split("## 十、初始真实批次", 1)[0]
        for line in current_text.splitlines():
            if "SOL" in line and not any(
                marker in line for marker in ("历史", "不可变", "仅历史", "不属于当前", "未纳入")
            ):
                conflicts.append(
                    _conflict(
                        "SCOPE_BOUNDARY_DRIFT",
                        path,
                        authority="当前前向研究范围",
                        decision="失败关闭",
                        repair_mode="禁止删除或改写历史",
                        release_condition="将SOL限制为明确历史上下文或移出当前入口",
                    )
                )


def _check_historical_immutability(
    repo_root: Path, base_ref: str, head_ref: str, conflicts: list[Conflict]
) -> None:
    for path in HISTORICAL_IMMUTABLE_PATHS:
        base = _read_at_ref(repo_root, base_ref, path)
        head = _read_at_ref(repo_root, head_ref, path)
        if base is not None and head is not None and base != head:
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="不可变历史证据",
                    decision="失败关闭",
                    repair_mode="禁止改写历史证据",
                    release_condition="回滚历史文件变更并重新检查",
                )
            )
        elif (base is None) != (head is None):
            conflicts.append(
                _conflict(
                    "SCOPE_BOUNDARY_DRIFT",
                    path,
                    authority="不可变历史证据",
                    decision="失败关闭",
                    repair_mode="禁止删除或新增历史替代物",
                    release_condition="恢复历史路径并重新检查",
                )
            )


MUTABLE_TASK_PREFIXES = (
    "- 状态：",
    "- 执行分支：",
    "- 开始时间：",
    "- Pull Request：",
    "- 合并时间：",
    "- 合并提交SHA：",
    "- 当前阻塞原因：",
    "- 解除条件：",
    "- 登记时间：",
    "- 登记PR：",
    "- 登记合并SHA：",
    "- 完成实现时间：",
    "- 实现提交SHA：",
    "- 架构评审结论：",
    "- 合并完成时间：",
)
CANCELLATION_MUTABLE_TASK_PREFIXES = (
    "- 取消时间：",
    "- 取消原因：",
    "- 取消依据任务：",
    "- 取消依据PR：",
    "- 取消依据合并时间：",
    "- 取消依据合并提交SHA：",
)


def _root_readonly_section_bounds(lines: Sequence[str]) -> tuple[int, int] | None:
    """返回root只读兼容段落的唯一范围。"""

    starts = [
        index
        for index, line in enumerate(lines)
        if line == "## Ubuntu root只读兼容模式（受控合同修复）"
    ]
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


def _immutable_task_contract(
    text: str,
    *,
    allow_dependency_mutation: bool = False,
    allow_cancellation_mutation: bool = False,
    allow_blocked_contract_repair: bool = False,
    allow_root_readonly_contract_repair: bool = False,
    allow_contract_conflict_repair: bool = False,
) -> str:
    """保留任务合同，排除状态和执行/合并证据记录。"""

    lines = text.splitlines()
    record_start = next(
        (index for index, line in enumerate(lines) if line.strip() == "## 执行记录"),
        len(lines),
    )
    first_section = next(
        (index for index, line in enumerate(lines[:record_start]) if line.startswith("## ")),
        record_start,
    )
    dependency_start = next(
        (
            index
            for index, line in enumerate(lines[:record_start])
            if line.strip() == "## 依赖与阻塞条件"
        ),
        -1,
    )
    dependency_end = next(
        (
            index
            for index in range(dependency_start + 1, record_start)
            if lines[index].startswith("## ")
        ),
        record_start,
    ) if dependency_start >= 0 else -1
    completion_start = next(
        (
            index
            for index, line in enumerate(lines[:record_start])
            if line.strip() == "## 完成定义"
        ),
        -1,
    )
    completion_end = next(
        (
            index
            for index in range(completion_start + 1, record_start)
            if lines[index].startswith("## ")
        ),
        record_start,
    ) if completion_start >= 0 else -1
    root_section = _root_readonly_section_bounds(lines)
    mutable_prefixes = MUTABLE_TASK_PREFIXES + (
        CANCELLATION_MUTABLE_TASK_PREFIXES
        if allow_cancellation_mutation
        else ()
    )
    return "\n".join(
        line
        for index, line in enumerate(lines[:record_start])
        if not (
            (
                index < first_section
                and any(line.startswith(prefix) for prefix in mutable_prefixes)
            )
            or (
                allow_dependency_mutation
                and
                dependency_start <= index < dependency_end
                and line.startswith(("- 当前阻塞原因：", "- 解除条件："))
            )
            or (
                allow_blocked_contract_repair
                and line == "- 自动合并范围：治理自动化"
            )
            or (
                allow_root_readonly_contract_repair
                and root_section is not None
                and root_section[0] <= index < root_section[1]
            )
            or (
                allow_contract_conflict_repair
                and completion_start <= index < completion_end
            )
            or (
                allow_contract_conflict_repair
                and line.startswith("- 交付提交SHA：")
            )
        )
    ).strip()


def _check_task_contract_drift(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
    conflicts: list[Conflict],
    *,
    allow_dependency_mutation: bool = False,
    allow_cancellation_mutation: bool = False,
    blocked_contract_repair_target: str | None = None,
    root_readonly_contract_repair_target: str | None = None,
    contract_conflict_repair_target: str | None = None,
    task094_contract_repair_target: str | None = None,
) -> None:
    """阻止交付或状态PR静默改写目标、范围、输入输出和安全边界。"""

    base_paths = set(_list_task_paths(repo_root, base_ref) or ())
    head_paths = set(_list_task_paths(repo_root, head_ref) or ())
    for path in sorted(base_paths - head_paths):
        conflicts.append(
            _conflict(
                "TASK_CONTRACT_CONFLICT",
                path,
                authority="任务文件",
                decision="失败关闭",
                repair_mode="禁止删除任务合同",
                release_condition="恢复任务文件并通过独立治理任务处理取消",
            )
        )
    for path in sorted(base_paths & head_paths):
        base_text = _read_at_ref(repo_root, base_ref, path)
        head_text = _read_at_ref(repo_root, head_ref, path)
        if base_text is None or head_text is None:
            continue
        if (
            task094_contract_repair_target is not None
            and path == f"{TASK_DIR}/任务-{task094_contract_repair_target}.md"
            and _apply_task094_contract_repair(base_text) == head_text
        ):
            continue
        if _immutable_task_contract(
            base_text,
            allow_dependency_mutation=allow_dependency_mutation,
            allow_cancellation_mutation=allow_cancellation_mutation,
            allow_blocked_contract_repair=(
                blocked_contract_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{blocked_contract_repair_target}.md"
            ),
            allow_root_readonly_contract_repair=(
                root_readonly_contract_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{root_readonly_contract_repair_target}.md"
            ),
            allow_contract_conflict_repair=(
                contract_conflict_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{contract_conflict_repair_target}.md"
            ),
        ) != _immutable_task_contract(
            head_text,
            allow_dependency_mutation=allow_dependency_mutation,
            allow_cancellation_mutation=allow_cancellation_mutation,
            allow_blocked_contract_repair=(
                blocked_contract_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{blocked_contract_repair_target}.md"
            ),
            allow_root_readonly_contract_repair=(
                root_readonly_contract_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{root_readonly_contract_repair_target}.md"
            ),
            allow_contract_conflict_repair=(
                contract_conflict_repair_target is not None
                and path
                == f"{TASK_DIR}/任务-{contract_conflict_repair_target}.md"
            ),
        ):
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件合同",
                    decision="阻塞",
                    repair_mode="禁止静默改写目标、范围或安全边界",
                    release_condition="恢复基线合同或登记独立治理修复任务",
                )
            )


def _check_metadata(
    metadata: Mapping[str, object] | None,
    *,
    base_sha: str,
    head_sha: str,
    task_id: str,
    conflicts: list[Conflict],
) -> None:
    """校验来自GitHub事件的不可变身份，不信任PR正文替代提交身份。"""

    if metadata is None:
        return
    expected = {
        "base_ref": "main",
        "repository": "xk320/zhishi",
        "head_repository": "xk320/zhishi",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            conflicts.append(
                _conflict(
                    "PR_BASELINE_DRIFT",
                    "github-metadata",
                    authority="GitHub Pull Request元数据",
                    decision="失败关闭",
                    repair_mode="禁止猜测元数据",
                    release_condition=f"恢复{key}为受信任值并重新检查",
                )
            )
    for key, value in (("base_sha", base_sha), ("head_sha", head_sha)):
        supplied = metadata.get(key)
        if supplied is not None and supplied != value:
            conflicts.append(
                _conflict(
                    "PR_BASELINE_DRIFT",
                    "github-metadata",
                    authority="GitHub提交身份",
                    decision="失败关闭",
                    repair_mode="禁止沿用旧证据",
                    release_condition=f"将元数据{key}绑定到当前提交SHA",
                )
            )
    head_ref = metadata.get("head_ref")
    if head_ref is not None and (
        not isinstance(head_ref, str) or not head_ref.startswith("codex/")
    ):
        conflicts.append(
            _conflict(
                "PR_BASELINE_DRIFT",
                "github-metadata",
                authority="GitHub执行分支身份",
                decision="失败关闭",
                repair_mode="禁止执行未知来源分支",
                release_condition="使用codex/前缀的仓库内执行分支",
            )
        )
    if task_id and metadata.get("pr_number") is not None:
        try:
            if int(metadata["pr_number"]) <= 0:  # type: ignore[arg-type]
                raise ValueError
        except (TypeError, ValueError):
            conflicts.append(
                _conflict(
                    "PR_BASELINE_DRIFT",
                    "github-metadata",
                    authority="GitHub Pull Request元数据",
                    decision="失败关闭",
                    repair_mode="禁止猜测PR编号",
                    release_condition="提供正整数PR编号并重新检查",
                )
            )


def _change_type_from_body(body: str) -> str:
    match = CHANGE_TYPE_PATTERN.search(body)
    return match.group(1) if match else ""


def _check_task_execution_metadata(
    repo_root: Path,
    head_ref: str,
    task_id: str,
    metadata: Mapping[str, object] | None,
    conflicts: list[Conflict],
) -> None:
    """把任务文件中的执行分支和PR证据绑定到当前GitHub事件。"""

    if metadata is None or not task_id:
        return
    body = str(metadata.get("body", ""))
    change_type = _change_type_from_body(body)
    if change_type in {"合并后状态闭环", "任务登记"}:
        # 状态闭环使用独立PR，必须保留任务文件中的原交付分支/PR；任务登记
        # 尚未开始执行，不能要求不存在的执行元数据。
        return
    path = f"{TASK_DIR}/任务-{task_id}.md"
    text = _read_at_ref(repo_root, head_ref, path)
    if text is None:
        return
    status = _field(STATUS_PATTERN, text) or ""
    task_branch = _field(BRANCH_PATTERN, text)
    task_started = _field(START_PATTERN, text)
    head_branch = metadata.get("head_ref")
    if (
        change_type == "阻塞任务合同修复"
        and task_id == ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR
    ):
        # 任务-000086是已完成的授权执行任务。后续PR只修复任务-000084
        # 合同，不能把源任务的历史执行分支/PR错误绑定到新的修复PR；
        # 源任务的逐字不变和已完成状态由自动合并资格校验器另行复算。
        if status != "已完成":
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="root兼容合同修复源任务",
                    decision="失败关闭",
                    repair_mode="禁止使用未完成授权任务",
                    release_condition="先完成任务-000086并保持其历史合同不变",
                )
            )
        if not task_branch:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件执行元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务执行分支",
                    release_condition="补齐任务-000086历史执行分支",
                )
            )
        if not task_started:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件执行元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务开始时间",
                    release_condition="补齐任务-000086历史开始时间",
                )
            )
        if not _field(PR_PATTERN, text):
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件Pull Request元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务PR证据",
                    release_condition="补齐任务-000086历史PR引用",
                )
            )
        return
    if (
        change_type == "任务合同冲突修复"
        and task_id == TASK094_CONTRACT_REPAIR_EXECUTOR
    ):
        # 任务-000095是已完成的治理授权任务。后续PR只对任务-000094
        # 执行可信规则冻结的八段合同替换；源任务的历史执行分支和PR
        # 不能绑定到新的目标修复PR。源任务逐字不变和目标修复范围由
        # 自动合并资格校验器另行复算，这里仍要求历史元数据完整。
        if status != "已完成":
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务-000094合同修复源任务",
                    decision="失败关闭",
                    repair_mode="禁止使用未完成治理任务",
                    release_condition="先完成任务-000095并保持其历史合同不变",
                )
            )
        if not task_branch:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件执行元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务执行分支",
                    release_condition="补齐任务-000095历史执行分支",
                )
            )
        if not task_started:
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件执行元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务开始时间",
                    release_condition="补齐任务-000095历史开始时间",
                )
            )
        if not _field(PR_PATTERN, text):
            conflicts.append(
                _conflict(
                    "TASK_CONTRACT_CONFLICT",
                    path,
                    authority="任务文件Pull Request元数据",
                    decision="失败关闭",
                    repair_mode="禁止缺少源任务PR证据",
                    release_condition="补齐任务-000095历史PR引用",
                )
            )
        return
    if status in {"执行中", "待评审", "需修复", "已完成"} and not task_branch:
        conflicts.append(
            _conflict(
                "TASK_CONTRACT_CONFLICT",
                path,
                authority="任务文件执行元数据",
                decision="失败关闭",
                repair_mode="禁止缺少执行分支",
                release_condition="补齐任务合同中的执行分支并重新检查",
            )
        )
    if status in {"执行中", "待评审", "需修复", "已完成"} and not task_started:
        conflicts.append(
            _conflict(
                "TASK_CONTRACT_CONFLICT",
                path,
                authority="任务文件执行元数据",
                decision="失败关闭",
                repair_mode="禁止缺少开始时间",
                release_condition="补齐任务合同中的开始时间并重新检查",
            )
        )
    if task_branch and isinstance(head_branch, str) and task_branch != head_branch:
        conflicts.append(
            _conflict(
                "PR_BASELINE_DRIFT",
                path,
                authority="任务文件执行分支与GitHub元数据",
                decision="失败关闭",
                repair_mode="禁止执行非任务合同分支",
                release_condition="将任务执行分支与PR头分支精确绑定",
            )
        )
    task_pr = _field(PR_PATTERN, text)
    pr_number = metadata.get("pr_number")
    if status in {"待评审", "需修复", "已完成"} and not task_pr:
        conflicts.append(
            _conflict(
                "TASK_CONTRACT_CONFLICT",
                path,
                authority="任务文件Pull Request元数据",
                decision="失败关闭",
                repair_mode="禁止缺少PR交付证据",
                release_condition="补齐当前PR引用并重新检查",
            )
        )
    if task_pr and pr_number is not None:
        task_match = PR_NUMBER_PATTERN.search(task_pr)
        if task_match is None or task_match.group(1) != str(pr_number):
            conflicts.append(
                _conflict(
                    "PR_BASELINE_DRIFT",
                    path,
                    authority="任务文件Pull Request与GitHub元数据",
                    decision="失败关闭",
                    repair_mode="禁止错绑Pull Request证据",
                    release_condition="将任务文件PR编号与当前PR精确绑定",
                )
            )


def _check_resource_policy(
    resource_policy: Mapping[str, object] | None, conflicts: list[Conflict]
) -> None:
    if resource_policy is None:
        return
    try:
        memory_pressure = str(resource_policy["memory_pressure"])
        memory_available = float(resource_policy["memory_available_percent"])
        disk_available = float(resource_policy["disk_available_gib"])
    except (KeyError, TypeError, ValueError):
        conflicts.append(
            _conflict(
                "RESOURCE_OR_API_FAILURE",
                "resource_policy",
                authority="资源策略",
                decision="失败关闭",
                repair_mode="禁止猜测资源状态",
                release_condition="补齐可验证资源测量并重新检查",
            )
        )
        return
    if not resource_policy_is_safe(
        memory_pressure=memory_pressure,
        memory_available_percent=memory_available,
        disk_available_gib=disk_available,
    ):
        conflicts.append(
            _conflict(
                "RESOURCE_OR_API_FAILURE",
                "resource_policy",
                authority="资源策略",
                decision="失败关闭",
                repair_mode="停止任务，不通过重试规避资源门",
                release_condition="资源恢复到任务合同上限后重新测量",
            )
        )


def _check_review_evidence(
    review_evidence: Mapping[str, object] | None,
    *,
    base_sha: str,
    head_sha: str,
    conflicts: list[Conflict],
) -> None:
    if review_evidence is None:
        return
    if not review_evidence_is_current(
        base_sha=base_sha,
        head_sha=head_sha,
        reviewed_base_sha=str(review_evidence.get("base_sha", "")),
        reviewed_head_sha=str(review_evidence.get("head_sha", "")),
    ):
        conflicts.append(
            _conflict(
                "REVIEW_EVIDENCE_STALE",
                "review_evidence",
                authority="双子智能体评审证据",
                decision="失败关闭",
                repair_mode="提交变化后必须重新评审",
                release_condition="重新生成并绑定当前base/head SHA的证据",
            )
        )
    reviews = review_evidence.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != 2:
        conflicts.append(
            _conflict(
                "REVIEW_EVIDENCE_STALE",
                "review_evidence.reviews",
                authority="双子智能体评审证据",
                decision="失败关闭",
                repair_mode="禁止缺少或增加评审者",
                release_condition="提供恰好两个独立且绑定当前SHA的评审",
            )
        )
        return
    for review in reviews:
        if not isinstance(review, Mapping) or not review_evidence_is_current(
            base_sha=base_sha,
            head_sha=head_sha,
            reviewed_base_sha=str(review.get("reviewed_base_sha", "")),
            reviewed_head_sha=str(review.get("reviewed_head_sha", "")),
        ):
            conflicts.append(
                _conflict(
                    "REVIEW_EVIDENCE_STALE",
                    "review_evidence.reviews",
                    authority="双子智能体评审证据",
                    decision="失败关闭",
                    repair_mode="提交变化后必须重新评审",
                    release_condition="两个独立评审均绑定当前base/head SHA",
                )
            )
            continue
        if review.get("conclusion") not in {None, "APPROVE"}:
            conflicts.append(
                _conflict(
                    "REVIEW_EVIDENCE_STALE",
                    "review_evidence.reviews",
                    authority="双子智能体评审证据",
                    decision="失败关闭",
                    repair_mode="拒绝未批准评审",
                    release_condition="两个独立评审均为APPROVE",
                )
            )
        for field in ("p0", "p1"):
            value = review.get(field)
            if value is not None and value != 0:
                conflicts.append(
                    _conflict(
                        "REVIEW_EVIDENCE_STALE",
                        "review_evidence.reviews",
                        authority="双子智能体评审证据",
                        decision="失败关闭",
                        repair_mode="拒绝含P0/P1阻断的评审",
                        release_condition="修复阻断问题并重新评审",
                    )
                )


def check_tree(repo_root: Path, ref: str) -> tuple[str, tuple[Conflict, ...]]:
    """检查一个Git树；只返回脱敏冲突事实。"""

    conflicts: list[Conflict] = []
    resolved = _resolve_ref(repo_root, ref)
    if resolved is None:
        conflicts.append(
            _conflict(
                "PR_BASELINE_DRIFT",
                ref,
                authority="Git提交身份",
                decision="失败关闭",
                repair_mode="禁止沿用旧证据",
                release_condition="提供可验证的完整提交SHA",
            )
        )
        return "", tuple(conflicts)
    records = _task_records(repo_root, ref, conflicts)
    _check_dependencies(records, conflicts)
    _check_board(repo_root, ref, records, conflicts)
    _check_scope(repo_root, ref, conflicts)
    unique = {
        (item.code, item.path, item.decision, item.release_condition): item
        for item in conflicts
    }
    return resolved, tuple(unique[key] for key in sorted(unique))


def check_refs(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
    *,
    metadata: Mapping[str, object] | None = None,
    review_evidence: Mapping[str, object] | None = None,
    resource_policy: Mapping[str, object] | None = None,
    task_id: str = "",
    change_type: str = "",
) -> ConflictReport:
    """检查base/head身份与两棵树，供可信资格校验器复用。"""

    base_sha = _resolve_ref(repo_root, base_ref) or ""
    head_sha = _resolve_ref(repo_root, head_ref) or ""
    conflicts: list[Conflict] = []
    if not base_sha or not head_sha:
        conflicts.append(
            _conflict(
                "PR_BASELINE_DRIFT",
                "git",
                authority="Git提交身份",
                decision="失败关闭",
                repair_mode="禁止沿用旧证据",
                release_condition="提供可验证的base/head提交SHA",
            )
        )
    else:
        code, _, _ = _git(repo_root, "merge-base", "--is-ancestor", base_sha, head_sha)
        if code != 0:
            conflicts.append(
                _conflict(
                    "PR_BASELINE_DRIFT",
                    "git",
                    authority="Git提交身份",
                    decision="失败关闭",
                    repair_mode="禁止沿用旧证据",
                    release_condition="将PR同步到当前main并重新评审",
                )
            )
    _, base_conflicts = check_tree(repo_root, base_ref)
    _, head_conflicts = check_tree(repo_root, head_ref)
    conflicts.extend((*base_conflicts, *head_conflicts))
    if base_sha and head_sha:
        _check_task_contract_drift(
            repo_root,
            base_sha,
            head_sha,
            conflicts,
            allow_dependency_mutation=(
                metadata is not None
                and _change_type_from_body(str(metadata.get("body", "")))
                == "合并后状态闭环"
            )
            or change_type == "合并后状态闭环",
            allow_cancellation_mutation=(
                metadata is not None
                and _change_type_from_body(str(metadata.get("body", "")))
                == "合并后状态闭环"
            )
            or change_type == "合并后状态闭环",
            blocked_contract_repair_target=(
                BLOCKED_CONTRACT_REPAIR_TARGET
                if change_type == "阻塞任务合同修复" and task_id == BLOCKED_CONTRACT_REPAIR_EXECUTOR
                else None
            ),
            root_readonly_contract_repair_target=(
                ROOT_READONLY_CONTRACT_REPAIR_TARGET
                if change_type == "阻塞任务合同修复"
                and task_id == ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR
                else None
            ),
            contract_conflict_repair_target=(
                CONTRACT_CONFLICT_REPAIR_TARGET
                if change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                and task_id == CONTRACT_CONFLICT_REPAIR_EXECUTOR
                else None
            ),
            task094_contract_repair_target=(
                TASK094_CONTRACT_REPAIR_TARGET
                if change_type == CONTRACT_CONFLICT_REPAIR_TYPE
                and task_id == TASK094_CONTRACT_REPAIR_EXECUTOR
                else None
            ),
        )
        _check_historical_immutability(repo_root, base_sha, head_sha, conflicts)
    _check_metadata(
        metadata,
        base_sha=base_sha,
        head_sha=head_sha,
        task_id=task_id,
        conflicts=conflicts,
    )
    _check_task_execution_metadata(
        repo_root, head_ref, task_id, metadata, conflicts
    )
    _check_resource_policy(resource_policy, conflicts)
    _check_review_evidence(
        review_evidence,
        base_sha=base_sha,
        head_sha=head_sha,
        conflicts=conflicts,
    )
    unique = {
        (item.code, item.path, item.decision, item.release_condition): item
        for item in conflicts
    }
    return ConflictReport(base_sha, head_sha, tuple(unique[key] for key in sorted(unique)))


def repair_board_text(
    board: str,
    records: Mapping[str, tuple],
    schema: Mapping[str, object],
) -> str:
    """从任务文件生成派生看板文本；不修改任务合同或历史证据。"""

    sections = _board_sections(board)
    if sections is None:
        raise ValueError("看板分区不完整，不能生成修复计划")
    for task_id, record in records.items():
        status = record[2]
        pr = record[8] if len(record) > 8 else ""
        merge = record[9] if len(record) > 9 else ""
        if status in {"已完成", "已取消"} and (not pr or not merge):
            raise ValueError(
                f"任务-{task_id}缺少完整PR与合并证据，拒绝生成可能丢失历史的看板修复"
            )
        if status == "执行中" and (
            not (record[5] if len(record) > 5 else "")
            or not (record[6] if len(record) > 6 else "")
        ):
            raise ValueError(f"任务-{task_id}缺少执行分支或开始时间，拒绝生成修复")
    rows_by_status: dict[str, list[str]] = {section: [] for section in SECTIONS}
    for task_id, record in sorted(
        records.items(), key=lambda item: (item[1][3], item[0])
    ):
        _, title, status, priority, dependencies = record[:5]
        branch = record[5] if len(record) > 5 else ""
        started = record[6] if len(record) > 6 else ""
        blocker = record[7] if len(record) > 7 else ""
        pr = record[8] if len(record) > 8 else ""
        merge = record[9] if len(record) > 9 else ""
        cancellation_support_task = record[10] if len(record) > 10 else ""
        cancellation_reason = record[11] if len(record) > 11 else ""
        dependency = dependencies[0] if dependencies else "无"
        if status == "待执行":
            rows_by_status[status].append(f"| {priority} | 任务-{task_id} | {title} | {dependency} |")
        elif status == "阻塞":
            rows_by_status[status].append(f"| {priority} | 任务-{task_id} | {title} | {dependency} | {blocker or '任务文件记录阻塞原因'} |")
        elif status in {"执行中", "待评审", "需修复"}:
            if status == "执行中":
                rows_by_status[status].append(f"| {priority} | 任务-{task_id} | {title} | `{branch or '任务文件记录'}` | {started or '任务文件记录'} |")
            else:
                rows_by_status[status].append(f"| {priority} | 任务-{task_id} | {title} | `{branch or '任务文件记录'}` | {pr or '任务文件记录'} |")
        else:
            if status == "已取消" and pr and merge and cancellation_support_task and cancellation_reason:
                evidence = (
                    f"替代任务-{cancellation_support_task}；{pr}；"
                    f"合并提交 `{merge}`；取消原因：{cancellation_reason}"
                )
            else:
                evidence = f"{pr}；合并提交 `{merge}`" if pr and merge else "任务文件记录"
            rows_by_status[status].append(f"| 任务-{task_id} | {title} | {evidence} |")
    lines = board.splitlines()
    heading_indexes = [index for index, line in enumerate(lines) if line.startswith("## ") and line[3:] in SECTIONS]
    output: list[str] = []
    cursor = 0
    for heading_index in heading_indexes:
        output.extend(lines[cursor:heading_index])
        section = lines[heading_index][3:]
        output.append(lines[heading_index])
        output.append("")
        header, separator = schema["sections"][section]  # type: ignore[index]
        output.extend((header, separator))
        output.extend(rows_by_status[section] or ["无。"])
        cursor = next(
            (index for index in range(heading_index + 1, len(lines)) if lines[index].startswith("## ")),
            len(lines),
        )
    output.extend(lines[cursor:])
    return "\n".join(output).rstrip() + "\n"


def _compute_rule_fingerprint() -> str:
    """对影响冲突判断的规则和实现取指纹，提交变化即使旧证据失效。"""

    names = (
        "_git",
        "_read_at_ref",
        "_list_task_paths",
        "_task_records",
        "_check_board",
        "_check_dependencies",
        "_check_scope",
        "_check_historical_immutability",
        "_root_readonly_section_bounds",
        "_immutable_task_contract",
        "_check_task_contract_drift",
        "_check_metadata",
        "_check_task_execution_metadata",
        "_check_resource_policy",
        "_check_review_evidence",
        "resource_policy_is_safe",
        "review_evidence_is_current",
        "check_refs",
        "repair_board_text",
    )
    sources: list[str] = [
        PROTOCOL_VERSION,
        repr(CONFLICT_CODES),
        repr(STANDARD_STATUSES),
        repr(SECTIONS),
        repr(TASK_PATTERN.pattern),
        repr(TITLE_PATTERN.pattern),
        repr(STATUS_PATTERN.pattern),
        repr(PRIORITY_PATTERN.pattern),
        repr(BRANCH_PATTERN.pattern),
        repr(START_PATTERN.pattern),
        repr(PR_PATTERN.pattern),
        repr(MERGE_PATTERN.pattern),
        repr(PR_NUMBER_PATTERN.pattern),
        repr(CHANGE_TYPE_PATTERN.pattern),
        TASK_DIR,
        BOARD_PATH,
        BOARD_SCHEMA_PATH,
        DEPENDENCY_PATTERN.pattern,
        repr(CURRENT_SCOPE_CONFIGS),
        repr(FORWARD_SCOPE_DOCS),
        repr(SCALE_SCOPE_DOCS),
        repr(HISTORICAL_IMMUTABLE_PATHS),
        str(MAX_TEXT_BYTES),
        str(MAX_GIT_SECONDS),
        str(MAX_TASK_FILES),
        str(MAX_TREE_BYTES),
        repr(MUTABLE_TASK_PREFIXES),
        repr(CANCELLATION_MUTABLE_TASK_PREFIXES),
        ROOT_READONLY_COMPAT_SECTION,
        ROOT_READONLY_CONTRACT_REPAIR_EXECUTOR,
        ROOT_READONLY_CONTRACT_REPAIR_TARGET,
        TASK094_CONTRACT_REPAIR_EXECUTOR,
        TASK094_CONTRACT_REPAIR_TARGET,
        repr(TASK094_CONTRACT_REPLACEMENTS),
        "_apply_task094_contract_repair",
    ]
    for name in names:
        try:
            sources.append(inspect.getsource(globals()[name]))
        except (KeyError, OSError, TypeError):
            sources.append(name)
    return hashlib.sha256("\n".join(sources).encode("utf-8")).hexdigest()


RULE_FINGERPRINT = _compute_rule_fingerprint()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证研发中心跨载体冲突")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--task-id", default="")
    parser.add_argument("--repair-board", action="store_true")
    return parser.parse_args()


def _repair_plan_summary(repo_root: Path, ref: str) -> dict[str, object]:
    """调用看板修复函数并只输出脱敏摘要；默认不写入文件。"""

    conflicts: list[Conflict] = []
    records = _task_records(repo_root, ref, conflicts)
    schema = _schema_at_ref(repo_root, ref)
    board = _read_at_ref(repo_root, ref, BOARD_PATH)
    if conflicts or schema is None or board is None:
        return {
            "mode": "演练",
            "status": "拒绝",
            "reason": "任务合同、看板模式或看板正文不可验证",
        }
    try:
        repaired = repair_board_text(board, records, schema)
    except (TypeError, ValueError):
        return {
            "mode": "演练",
            "status": "拒绝",
            "reason": "历史证据或执行元数据不完整，禁止生成有损修复",
        }
    changed_lines = sum(
        left != right
        for left, right in zip(board.splitlines(), repaired.splitlines())
    ) + abs(len(board.splitlines()) - len(repaired.splitlines()))
    return {
        "mode": "演练",
        "status": "可生成",
        "source_sha256": hashlib.sha256(board.encode("utf-8")).hexdigest(),
        "plan_sha256": hashlib.sha256(repaired.encode("utf-8")).hexdigest(),
        "changed_lines": changed_lines,
        "writes": False,
    }


def main() -> int:
    arguments = _arguments()
    report = check_refs(
        arguments.repo_root.resolve(),
        arguments.base_ref,
        arguments.head_ref,
        task_id=arguments.task_id,
    )
    payload = report.as_dict(task_id=arguments.task_id)
    payload["repair_plan"] = (
        "仅可从任务文件重建派生看板；同级合同冲突必须阻塞"
        if any(item.code == "BOARD_DERIVED_DRIFT" for item in report.conflicts)
        else "无可执行修复计划"
    )
    if arguments.repair_board:
        payload["repair_plan"] = _repair_plan_summary(
            arguments.repo_root.resolve(), arguments.head_ref
        )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
