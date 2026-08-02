#!/usr/bin/env python3
"""验证Codex双子智能体评审证据是否绑定当前Pull Request。"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_ROLES = frozenset({"治理与架构", "范围与安全"})


@dataclass(frozen=True)
class EvidenceResult:
    """结构化评审证据验证结果。"""

    valid: bool
    reasons: tuple[str, ...]


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _safe_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def validate_evidence(
    evidence: Mapping[str, Any],
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
) -> EvidenceResult:
    """验证评审身份、阻断结论、验证结果和资源预算。"""

    reasons: list[str] = []
    if evidence.get("schema_version") != "zhishi-agent-review/v1":
        _append_reason(reasons, "评审证据版本无效")
    if evidence.get("repository") != repository:
        _append_reason(reasons, "评审证据仓库不匹配")
    if evidence.get("pr_number") != pr_number:
        _append_reason(reasons, "评审证据PR编号不匹配")
    if evidence.get("base_sha") != base_sha or not SHA_PATTERN.fullmatch(base_sha):
        _append_reason(reasons, "评审证据基线SHA不匹配")
    if evidence.get("head_sha") != head_sha or not SHA_PATTERN.fullmatch(head_sha):
        _append_reason(reasons, "评审证据头提交SHA不匹配")

    repair_round = _safe_integer(evidence.get("repair_round"))
    if repair_round is None or not 0 <= repair_round <= 3:
        _append_reason(reasons, "自动修复轮次超过3")

    reviews = evidence.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != 2:
        _append_reason(reasons, "必须提供两个独立评审")
        reviews = []

    roles: list[str] = []
    reviewer_ids: list[str] = []
    for review in reviews:
        if not isinstance(review, Mapping):
            _append_reason(reasons, "评审记录结构无效")
            continue
        role = review.get("role")
        reviewer_id = review.get("reviewer_id")
        if isinstance(role, str):
            roles.append(role)
        if isinstance(reviewer_id, str) and reviewer_id.strip():
            reviewer_ids.append(reviewer_id)
        p0 = _safe_integer(review.get("p0"))
        p1 = _safe_integer(review.get("p1"))
        p2 = _safe_integer(review.get("p2"))
        if p0 != 0 or p1 != 0:
            _append_reason(reasons, "评审存在P0或P1阻断问题")
        if p2 is None or p2 < 0:
            _append_reason(reasons, "评审P2计数无效")
        if review.get("conclusion") != "APPROVE":
            _append_reason(reasons, "评审结论不是APPROVE")

    if frozenset(roles) != REQUIRED_ROLES:
        _append_reason(reasons, "评审角色不完整")
    if len(reviewer_ids) != 2 or len(set(reviewer_ids)) != 2:
        _append_reason(reasons, "评审者必须相互独立")

    validation = evidence.get("validation")
    if not isinstance(validation, Mapping):
        _append_reason(reasons, "主执行器验证记录无效")
        validation = {}
    if validation.get("passed") is not True:
        _append_reason(reasons, "主执行器验证未通过")
    commands = validation.get("commands")
    if (
        not isinstance(commands, list)
        or not commands
        or any(not isinstance(command, str) or not command.strip() for command in commands)
    ):
        _append_reason(reasons, "缺少实际验证命令")

    resource = evidence.get("resource_policy")
    if not isinstance(resource, Mapping):
        _append_reason(reasons, "资源策略记录无效")
        resource = {}
    max_reviewers = _safe_integer(resource.get("max_reviewers"))
    if max_reviewers is None or max_reviewers > 2 or max_reviewers < 1:
        _append_reason(reasons, "评审者并发上限超过2")
    if _safe_integer(resource.get("test_processes")) != 1:
        _append_reason(reasons, "测试必须单进程")
    node_heap = _safe_integer(resource.get("node_heap_mib"))
    if node_heap is None or node_heap > 256 or node_heap < 1:
        _append_reason(reasons, "Node堆上限必须不超过256 MiB")
    if _safe_integer(resource.get("worktrees_created")) != 0:
        _append_reason(reasons, "禁止创建额外工作树")

    return EvidenceResult(valid=not reasons, reasons=tuple(reasons))


def validate_file(
    path: Path,
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
) -> EvidenceResult:
    """从文件读取证据；错误信息不回显原始不可信正文。"""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return EvidenceResult(False, ("无法读取结构化评审证据",))
    if not isinstance(payload, Mapping):
        return EvidenceResult(False, ("评审证据根对象无效",))
    return validate_evidence(
        payload,
        repository=repository,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证《知势》自动评审证据")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    result = validate_file(
        arguments.evidence,
        repository=arguments.repository,
        pr_number=arguments.pr_number,
        base_sha=arguments.base_sha,
        head_sha=arguments.head_sha,
    )
    print(
        json.dumps(
            {"valid": result.valid, "reasons": list(result.reasons)},
            ensure_ascii=False,
        )
    )
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
