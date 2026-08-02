#!/usr/bin/env python3
"""使用main可信任务合同验证Pull Request自动合并资格。"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


ALLOWED_TASK_TYPES = frozenset({"文档", "治理", "研究规范"})
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
AUTOMATION_SCOPE_PATTERN = re.compile(r"^- 自动合并范围：(.+)$", re.MULTILINE)
MERGE_SHA_PATTERN = re.compile(r"^- 合并提交SHA：`[0-9a-f]{40}`$", re.MULTILINE)
MERGE_TIME_PATTERN = re.compile(
    r"^- 合并时间：\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$",
    re.MULTILINE,
)
PULL_REQUEST_PATTERN = re.compile(r"^- Pull Request：\[#\d+\]\(https://github\.com/xk320/zhishi/pull/\d+\)$", re.MULTILINE)
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


@dataclass(frozen=True)
class EligibilityResult:
    """自动合并资格判定结果。"""

    eligible: bool
    reasons: tuple[str, ...]


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


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _validate_delivery_tasks(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    reasons: list[str],
) -> bool:
    automation_authorized = bool(task_ids)
    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        if base_task is None:
            _append_reason(reasons, f"任务-{task_id}未在基线main中登记")
            automation_authorized = False
            continue
        task_type = _task_field(TASK_TYPE_PATTERN, base_task)
        if task_type is None:
            _append_reason(reasons, f"任务-{task_id}缺少任务类型")
        elif task_type not in ALLOWED_TASK_TYPES:
            _append_reason(
                reasons,
                f"任务-{task_id}类型“{task_type}”不允许自动合并",
            )
        if _task_field(AUTOMATION_SCOPE_PATTERN, base_task) != AUTOMATION_SCOPE:
            automation_authorized = False

        head_task = head_tasks.get(task_id)
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
        elif _task_field(TASK_STATUS_PATTERN, head_task) != "待评审":
            _append_reason(reasons, f"任务-{task_id}在PR中的状态不是“待评审”")
    return automation_authorized


def _validate_state_closure(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    reasons: list[str],
) -> None:
    completed = 0
    unlocked = 0
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
        if (old_status, new_status) not in STATE_CLOSURE_TRANSITIONS:
            _append_reason(
                reasons,
                f"任务-{task_id}存在非法状态闭环“{old_status}→{new_status}”",
            )
        if (old_status, new_status) == ("待评审", "已完成"):
            completed += 1
            if (
                MERGE_SHA_PATTERN.search(head_task) is None
                or MERGE_TIME_PATTERN.search(head_task) is None
                or PULL_REQUEST_PATTERN.search(head_task) is None
            ):
                _append_reason(reasons, f"任务-{task_id}缺少真实合并证据")
        if (old_status, new_status) == ("阻塞", "待执行"):
            unlocked += 1
    if completed != 1:
        _append_reason(reasons, "合并后状态闭环必须且只能完成一个待评审任务")
    if unlocked > 1:
        _append_reason(reasons, "合并后状态闭环最多解除一个唯一后继")


def evaluate_eligibility(
    *,
    changed_paths: Sequence[str],
    pr_body: str,
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_branch: str,
    repository: str,
    head_repository: str,
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
    if change_type == "任务交付":
        automation_authorized = _validate_delivery_tasks(
            task_ids=task_ids,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            reasons=reasons,
        )
    elif change_type == "合并后状态闭环":
        _validate_state_closure(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
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
                else _is_low_risk_path(path)
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

    result = evaluate_eligibility(
        changed_paths=changed_paths,
        pr_body=str(metadata.get("body", "")),
        base_tasks=_load_ref_tasks(repo_root, arguments.base_ref, ordered_ids),
        head_tasks=_load_ref_tasks(repo_root, arguments.head_ref, ordered_ids),
        base_branch=str(metadata.get("base_ref", "")),
        repository=str(metadata.get("repository", "")),
        head_repository=str(metadata.get("head_repository", "")),
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
