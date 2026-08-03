#!/usr/bin/env python3
"""使用main可信任务合同验证Pull Request自动合并资格。"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


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
TASK_TITLE_PATTERN = re.compile(r"^# 任务-\d{6}：(.+)$", re.MULTILINE)
BOARD_TASK_ROW_PATTERN = re.compile(
    r"^\|\s*(?:P[0-3]\s*\|\s*)?任务-(\d{6})\s*\|"
)
BOARD_TABLE_SCHEMA = {
    "待执行": (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |",
        "| --- | --- | --- | --- |",
    ),
    "阻塞": (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 | 阻塞原因 |",
        "| --- | --- | --- | --- | --- |",
    ),
    "待评审": (
        "| 优先级 | 任务 | 名称 | 分支 | PR |",
        "| --- | --- | --- | --- | --- |",
    ),
    "已完成": (
        "| 任务 | 名称 | 完成证据 |",
        "| --- | --- | --- |",
    ),
}
AUTOMATION_SCOPE_PATTERN = re.compile(r"^- 自动合并范围：(.+)$", re.MULTILINE)
MERGE_SHA_PATTERN = re.compile(
    r"^- 合并提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
MERGE_TIME_PATTERN = re.compile(
    r"^- 合并时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
PULL_REQUEST_PATTERN = re.compile(
    r"^- Pull Request：\[#(\d+)\]\(https://github\.com/xk320/zhishi/pull/\1\)$",
    re.MULTILINE,
)
DEPENDENCY_PATTERN = re.compile(r"^- 唯一前序依赖：任务-(\d{6})(?:[^\r\n]*)$", re.MULTILINE)
TASK_REFERENCE_LINE = re.compile(
    r"^\s*-\s*任务-(\d{6})(?:\s*[（(][^\r\n]*[）)])?\s*$"
)
CHANGE_TYPES = frozenset({"任务交付", "合并后状态闭环"})
STATE_CLOSURE_TRANSITIONS = frozenset(
    {
        ("待评审", "已完成"),
        ("阻塞", "待执行"),
    }
)
DELIVERY_BASE_STATUSES = frozenset({"待执行", "需修复"})
COMPLETION_MUTABLE_PREFIXES = (
    "- 状态：",
    "- 合并时间：",
    "- 合并提交SHA：",
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


def _task_field(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _markdown_section(text: str, heading: str) -> tuple[str, ...]:
    lines = text.splitlines()
    expected = f"## {heading}"
    start: int | None = None
    for index, line in enumerate(lines):
        if line.strip() == expected:
            start = index + 1
            break
    if start is None:
        return ()
    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break
    return tuple(lines[start:end])


def parse_task_references(pr_body: str) -> tuple[str, ...]:
    """只解析PR正文严格的“关联任务”二级标题区段。"""

    task_ids: list[str] = []
    for line in _markdown_section(pr_body, "关联任务"):
        match = TASK_REFERENCE_LINE.fullmatch(line)
        if match is not None and match.group(1) not in task_ids:
            task_ids.append(match.group(1))
    return tuple(sorted(task_ids))


def parse_change_type(pr_body: str) -> str | None:
    """读取严格、唯一的PR变更类型。"""

    values = [
        line.strip()[2:].strip()
        for line in _markdown_section(pr_body, "变更类型")
        if line.strip().startswith("- ")
    ]
    valid = [value for value in values if value in CHANGE_TYPES]
    return valid[0] if len(valid) == 1 and len(values) == 1 else None


def parse_nul_paths(output: bytes) -> tuple[str, ...]:
    """解析Git NUL分隔路径，避免中文路径被quotePath转义。"""

    paths: list[str] = []
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        paths.append(raw_path.decode("utf-8", errors="strict"))
    return tuple(paths)


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


def _is_controlled_rd_path(path: str) -> bool:
    pure_path = PurePosixPath(path)
    if len(pure_path.parts) <= 1:
        return False
    root = pure_path.parts[0]
    suffix = pure_path.suffix
    if root == "docs":
        return suffix == ".md"
    if root == "config":
        return suffix in {".json", ".yaml", ".yml", ".toml"}
    if root == "src":
        return suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}
    if root == "scripts":
        return (
            pure_path.parts[1] not in {"交易", "部署", "生产"}
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
    text: str,
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
    if len(blocker_locations) != 1 or len(release_locations) != 1:
        return None
    mutable_locations = blocker_locations + release_locations
    if all(index < first_section for index in mutable_locations):
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
    if not all(section_start < index < section_end for index in mutable_locations):
        return None
    return "dependency_section", first_section, section_start, section_end


def _without_successor_mutable_lines(text: str) -> tuple[str, ...]:
    """移除已验证位置中的后继状态、阻塞原因与解除条件。"""

    layout = _successor_mutable_layout(text)
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
        if stripped == "无。" or BOARD_TASK_ROW_PATTERN.match(line):
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
    schema_counts: dict[str, dict[str, int]] = {}
    task_sections: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
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
    return all(count <= 1 for counts in schema_counts.values() for count in counts.values())


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
        elif status == "待执行":
            dependency = _task_field(DEPENDENCY_PATTERN, task)
            expected = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
                if title is not None and priority is not None and dependency is not None
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
    completed_task_id: str | None = None
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
        if (old_status, new_status) == ("阻塞", "待执行"):
            unlocked += 1
    if completed != 1:
        _append_reason(reasons, "合并后状态闭环必须且只能完成一个待评审任务")
    if unlocked > 1:
        _append_reason(reasons, "合并后状态闭环最多解除一个唯一后继")
    for task_id, transition in transitions.items():
        if transition != ("阻塞", "待执行"):
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
    changed_paths: Sequence[str],
    pr_body: str,
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_branch: str,
    repository: str,
    head_repository: str,
    merge_facts: Mapping[str, MergeFact] | None = None,
    base_board: str | None = None,
    head_board: str | None = None,
) -> EligibilityResult:
    """按基线任务合同、严格PR合同和变更路径判定资格。"""

    reasons: list[str] = []
    if base_branch != "main":
        _append_reason(reasons, "目标分支不是main")
    if repository != "xk320/zhishi" or head_repository != repository:
        _append_reason(reasons, "外部仓库PR不允许自动合并")
    if not changed_paths:
        _append_reason(reasons, "PR没有可验证的变更路径")

    task_ids = parse_task_references(pr_body)
    if not task_ids:
        _append_reason(reasons, "PR正文未引用任务编号")
    change_type = parse_change_type(pr_body)
    if change_type is None:
        _append_reason(reasons, "PR正文缺少有效变更类型")

    automation_authorized = False
    controlled_rd_authorized = False
    if change_type == "任务交付":
        automation_authorized, controlled_rd_authorized = (
            _validate_delivery_tasks(
                task_ids=task_ids,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                reasons=reasons,
            )
        )
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

    referenced_task_ids = set(task_ids)
    changed_task_ids: set[str] = set()
    for path in changed_paths:
        task_file_match = TASK_FILE_PATTERN.fullmatch(path)
        if task_file_match is not None:
            changed_task_ids.add(task_file_match.group(1))
            if task_file_match.group(1) not in referenced_task_ids:
                _append_reason(
                    reasons,
                    f"修改了未在PR正文引用的任务-{task_file_match.group(1)}",
                )

        if change_type == "任务交付":
            allowed = (
                _is_automation_path(path)
                if automation_authorized
                else (
                    _is_controlled_rd_path(path)
                    if controlled_rd_authorized
                    else _is_low_risk_path(path)
                )
            )
            if not allowed:
                _append_reason(reasons, f"变更路径“{path}”不允许自动合并")

    for task_id in task_ids:
        if task_id not in changed_task_ids:
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


def _git_text(repo_root: Path, arguments: Sequence[str]) -> str | None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _derive_merge_facts(
    repo_root: Path,
    base_ref: str,
    head_tasks: Mapping[str, str],
) -> dict[str, MergeFact]:
    """只从已进入main基线的Git提交推导合并事实。"""

    facts: dict[str, MergeFact] = {}
    for task_id, task in head_tasks.items():
        declared = _task_merge_fact(task)
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
            continue
        try:
            normalized_time = datetime.fromisoformat(committed_at).strftime(
                "%Y-%m-%d %H:%M:%S %z"
            )
        except ValueError:
            continue
        facts[task_id] = MergeFact(
            sha=declared.sha,
            merged_at=normalized_time,
            pr_number=int(pr_match.group(1)),
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
    diff = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "-z",
            arguments.base_ref,
            arguments.head_ref,
            "--",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    changed_paths = parse_nul_paths(diff.stdout)
    task_ids = set(parse_task_references(str(metadata.get("body", ""))))
    for path in changed_paths:
        match = TASK_FILE_PATTERN.fullmatch(path)
        if match is not None:
            task_ids.add(match.group(1))
    ordered_ids = tuple(sorted(task_ids))

    base_tasks = _load_ref_tasks(repo_root, arguments.base_ref, ordered_ids)
    head_tasks = _load_ref_tasks(repo_root, arguments.head_ref, ordered_ids)
    result = evaluate_eligibility(
        changed_paths=changed_paths,
        pr_body=str(metadata.get("body", "")),
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_branch=str(metadata.get("base_ref", "")),
        repository=str(metadata.get("repository", "")),
        head_repository=str(metadata.get("head_repository", "")),
        merge_facts=_derive_merge_facts(
            repo_root,
            arguments.base_ref,
            head_tasks,
        ),
        base_board=_read_path_at_ref(
            repo_root, arguments.base_ref, "docs/研发中心/看板.md"
        ),
        head_board=_read_path_at_ref(
            repo_root, arguments.head_ref, "docs/研发中心/看板.md"
        ),
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
