#!/usr/bin/env python3
"""验证 Pull Request 是否满足《知势》当前阶段的自动合并资格。"""

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
TASK_REFERENCE_PATTERN = re.compile(r"任务-(\d{6})")
TASK_FILE_PATTERN = re.compile(
    r"^docs/研发中心/任务/任务-(\d{6})\.md$"
)
TASK_TYPE_PATTERN = re.compile(r"^- 类型：(.+)$", re.MULTILINE)
TASK_STATUS_PATTERN = re.compile(r"^- 状态：(.+)$", re.MULTILINE)


@dataclass(frozen=True)
class EligibilityResult:
    """自动合并资格判定结果。"""

    eligible: bool
    reasons: tuple[str, ...]


def _task_field(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _is_allowed_path(path: str) -> bool:
    if path in ALLOWED_ROOT_MARKDOWN:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) > 1
        and pure_path.parts[0] == "docs"
        and pure_path.suffix == ".md"
    )


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


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
    """按基线任务合同和变更路径判定自动合并资格。"""

    reasons: list[str] = []
    if base_branch != "main":
        _append_reason(reasons, "目标分支不是main")
    if head_repository != repository:
        _append_reason(reasons, "外部仓库PR不允许自动合并")
    if not changed_paths:
        _append_reason(reasons, "PR没有可验证的变更路径")

    task_ids = tuple(sorted(set(TASK_REFERENCE_PATTERN.findall(pr_body))))
    if not task_ids:
        _append_reason(reasons, "PR正文未引用任务编号")

    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        if base_task is None:
            _append_reason(
                reasons,
                f"任务-{task_id}未在基线main中登记",
            )
            continue

        task_type = _task_field(TASK_TYPE_PATTERN, base_task)
        if task_type is None:
            _append_reason(reasons, f"任务-{task_id}缺少任务类型")
        elif task_type not in ALLOWED_TASK_TYPES:
            _append_reason(
                reasons,
                f"任务-{task_id}类型“{task_type}”不允许自动合并",
            )

        head_task = head_tasks.get(task_id)
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
            continue
        if _task_field(TASK_STATUS_PATTERN, head_task) != "待评审":
            _append_reason(
                reasons,
                f"任务-{task_id}在PR中的状态不是“待评审”",
            )

    referenced_task_ids = set(task_ids)
    changed_task_ids: set[str] = set()
    for path in changed_paths:
        if not _is_allowed_path(path):
            _append_reason(
                reasons,
                f"变更路径“{path}”不允许自动合并",
            )
        task_file_match = TASK_FILE_PATTERN.fullmatch(path)
        if task_file_match is not None:
            changed_task_ids.add(task_file_match.group(1))
        if task_file_match is not None and (
            task_file_match.group(1) not in referenced_task_ids
        ):
            _append_reason(
                reasons,
                f"修改了未在PR正文引用的任务-{task_file_match.group(1)}",
            )

    for task_id in task_ids:
        if task_id not in changed_task_ids:
            _append_reason(
                reasons,
                f"任务-{task_id}的任务文件未在PR中更新",
            )

    return EligibilityResult(eligible=not reasons, reasons=tuple(reasons))


def _run_git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _read_task_at_ref(
    repo_root: Path,
    ref: str,
    task_id: str,
) -> str | None:
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
    parser = argparse.ArgumentParser(
        description="验证《知势》Pull Request自动合并资格"
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument(
        "--metadata",
        required=True,
        type=Path,
        help="包含body、base_ref、repository和head_repository的JSON文件",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    repo_root = arguments.repo_root.resolve()
    metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
    changed_paths = [
        path
        for path in _run_git(
            repo_root,
            "diff",
            "--name-only",
            arguments.base_ref,
            arguments.head_ref,
            "--",
        ).splitlines()
        if path
    ]
    referenced_ids = set(
        TASK_REFERENCE_PATTERN.findall(str(metadata.get("body", "")))
    )
    for path in changed_paths:
        match = TASK_FILE_PATTERN.fullmatch(path)
        if match is not None:
            referenced_ids.add(match.group(1))
    task_ids = tuple(sorted(referenced_ids))

    result = evaluate_eligibility(
        changed_paths=changed_paths,
        pr_body=str(metadata.get("body", "")),
        base_tasks=_load_ref_tasks(
            repo_root,
            arguments.base_ref,
            task_ids,
        ),
        head_tasks=_load_ref_tasks(
            repo_root,
            arguments.head_ref,
            task_ids,
        ),
        base_branch=str(metadata.get("base_ref", "")),
        repository=str(metadata.get("repository", "")),
        head_repository=str(metadata.get("head_repository", "")),
    )
    print(
        json.dumps(
            {
                "eligible": result.eligible,
                "reasons": list(result.reasons),
                "changed_paths": changed_paths,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
