#!/usr/bin/env python3
"""严格验证Codex双子智能体评审证据是否绑定当前Pull Request。"""

from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
FINDING_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
REQUIRED_ROLES = frozenset({"治理与架构", "范围与安全"})
ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "pr_number",
        "base_sha",
        "head_sha",
        "repair_round",
        "reviews",
        "validation",
        "resource_policy",
    }
)
REVIEW_FIELDS = frozenset(
    {
        "role",
        "reviewer_id",
        "run_id",
        "reviewed_base_sha",
        "reviewed_head_sha",
        "reviewed_at",
        "conclusion",
        "p0",
        "p1",
        "p2",
        "findings",
    }
)
FINDING_FIELDS = frozenset({"id", "severity"})
VALIDATION_FIELDS = frozenset({"passed", "head_sha", "completed_at", "commands"})
COMMAND_FIELDS = frozenset({"command", "exit_code"})
RESOURCE_FIELDS = frozenset(
    {
        "max_reviewers",
        "test_processes",
        "node_heap_mib",
        "worktrees_created",
        "memory_pressure",
        "memory_available_percent",
        "disk_available_gib",
        "measured_at",
        "head_sha",
    }
)
SENSITIVE_TEXT = re.compile(
    r"(?i)(password|passwd|secret|token\s*=|authorization:|gh[pousr]_[A-Za-z0-9]|-----BEGIN)"
)


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


def _safe_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _valid_rfc3339(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(
            f"{value[:-1]}+00:00" if value.endswith("Z") else value
        )
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _parse_rfc3339(value: object) -> datetime | None:
    if not _valid_rfc3339(value):
        return None
    assert isinstance(value, str)
    return datetime.fromisoformat(f"{value[:-1]}+00:00" if value.endswith("Z") else value)


def _exact_fields(
    value: Mapping[str, Any],
    expected: frozenset[str],
    *,
    reason: str,
    reasons: list[str],
) -> None:
    if frozenset(value) != expected:
        _append_reason(reasons, reason)


def validate_evidence(
    evidence: Mapping[str, Any],
    *,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    current_time: datetime | None = None,
) -> EvidenceResult:
    """验证评审身份、逐项绑定、验证结果和实测资源预算。"""

    reasons: list[str] = []
    _exact_fields(
        evidence,
        ROOT_FIELDS,
        reason="评审证据包含未知字段",
        reasons=reasons,
    )
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
    run_ids: list[str] = []
    review_times: list[datetime] = []
    for review in reviews:
        if not isinstance(review, Mapping):
            _append_reason(reasons, "评审记录结构无效")
            continue
        _exact_fields(
            review,
            REVIEW_FIELDS,
            reason="评审记录包含未知字段",
            reasons=reasons,
        )
        role = review.get("role")
        if isinstance(role, str):
            roles.append(role)

        reviewer_id = review.get("reviewer_id")
        if (
            not isinstance(reviewer_id, str)
            or reviewer_id != reviewer_id.strip()
            or IDENTIFIER_PATTERN.fullmatch(reviewer_id) is None
        ):
            _append_reason(reasons, "评审者标识格式无效")
        else:
            reviewer_ids.append(reviewer_id)

        run_id = review.get("run_id")
        if (
            not isinstance(run_id, str)
            or run_id != run_id.strip()
            or IDENTIFIER_PATTERN.fullmatch(run_id) is None
        ):
            _append_reason(reasons, "评审运行标识格式无效")
        else:
            run_ids.append(run_id)

        if (
            review.get("reviewed_base_sha") != base_sha
            or review.get("reviewed_head_sha") != head_sha
        ):
            _append_reason(reasons, "评审记录未绑定当前base/head SHA")
        reviewed_at = _parse_rfc3339(review.get("reviewed_at"))
        if reviewed_at is None:
            _append_reason(reasons, "评审时间必须为带时区RFC3339")
        else:
            review_times.append(reviewed_at)

        p0 = _safe_integer(review.get("p0"))
        p1 = _safe_integer(review.get("p1"))
        p2 = _safe_integer(review.get("p2"))
        if p0 != 0 or p1 != 0:
            _append_reason(reasons, "评审存在P0或P1阻断问题")
        if p2 is None or p2 < 0:
            _append_reason(reasons, "评审P2计数无效")
        if review.get("conclusion") != "APPROVE":
            _append_reason(reasons, "评审结论不是APPROVE")

        findings = review.get("findings")
        finding_counts = {"P0": 0, "P1": 0, "P2": 0}
        if not isinstance(findings, list):
            _append_reason(reasons, "评审发现清单无效")
            findings = []
        for finding in findings:
            if not isinstance(finding, Mapping):
                _append_reason(reasons, "评审发现项结构无效")
                continue
            _exact_fields(
                finding,
                FINDING_FIELDS,
                reason="评审发现项包含未知字段",
                reasons=reasons,
            )
            finding_id = finding.get("id")
            severity = finding.get("severity")
            if not isinstance(finding_id, str) or FINDING_ID_PATTERN.fullmatch(finding_id) is None:
                _append_reason(reasons, "评审发现标识格式无效")
            if severity not in finding_counts:
                _append_reason(reasons, "评审发现严重级别无效")
            else:
                finding_counts[severity] += 1
        if (p0, p1, p2) != (
            finding_counts["P0"],
            finding_counts["P1"],
            finding_counts["P2"],
        ):
            _append_reason(reasons, "评审发现清单与P0/P1/P2计数不一致")

    if frozenset(roles) != REQUIRED_ROLES:
        _append_reason(reasons, "评审角色不完整")
    if len(reviewer_ids) != 2 or len(set(reviewer_ids)) != 2:
        _append_reason(reasons, "评审者必须相互独立")
    if len(run_ids) != 2 or len(set(run_ids)) != 2:
        _append_reason(reasons, "评审运行标识必须相互独立")

    validation = evidence.get("validation")
    if not isinstance(validation, Mapping):
        _append_reason(reasons, "主执行器验证记录无效")
        validation = {}
    else:
        _exact_fields(
            validation,
            VALIDATION_FIELDS,
            reason="验证记录包含未知字段",
            reasons=reasons,
        )
    if validation.get("passed") is not True:
        _append_reason(reasons, "主执行器验证未通过")
    if validation.get("head_sha") != head_sha:
        _append_reason(reasons, "验证记录未绑定当前头提交")
    completed_at = _parse_rfc3339(validation.get("completed_at"))
    if completed_at is None:
        _append_reason(reasons, "验证完成时间必须为带时区RFC3339")
    elif any(reviewed_at > completed_at for reviewed_at in review_times):
        _append_reason(reasons, "主执行器验证时间早于评审时间")
    commands = validation.get("commands")
    if not isinstance(commands, list) or not commands:
        _append_reason(reasons, "缺少实际验证命令")
        commands = []
    for command in commands:
        if not isinstance(command, Mapping):
            _append_reason(reasons, "验证命令记录无效")
            continue
        _exact_fields(
            command,
            COMMAND_FIELDS,
            reason="验证命令包含未知字段",
            reasons=reasons,
        )
        text = command.get("command")
        if not isinstance(text, str) or not text.strip():
            _append_reason(reasons, "验证命令为空")
        elif SENSITIVE_TEXT.search(text):
            _append_reason(reasons, "验证命令疑似包含敏感信息")
        if _safe_integer(command.get("exit_code")) != 0:
            _append_reason(reasons, "验证命令存在非零退出码")

    resource = evidence.get("resource_policy")
    if not isinstance(resource, Mapping):
        _append_reason(reasons, "资源策略记录无效")
        resource = {}
    else:
        _exact_fields(
            resource,
            RESOURCE_FIELDS,
            reason="资源策略包含未知字段",
            reasons=reasons,
        )
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

    pressure = resource.get("memory_pressure")
    if pressure not in {"normal", "warning"}:
        _append_reason(reasons, "内存压力不允许启动合并")
    if pressure == "warning" and max_reviewers != 1:
        _append_reason(reasons, "内存压力警告时只能使用一个评审者")
    available_memory = _safe_number(resource.get("memory_available_percent"))
    if available_memory is None or available_memory < 20:
        _append_reason(reasons, "可用内存低于20%")
    available_disk = _safe_number(resource.get("disk_available_gib"))
    if available_disk is None or available_disk < 5:
        _append_reason(reasons, "可用磁盘低于5 GiB")
    if resource.get("head_sha") != head_sha:
        _append_reason(reasons, "资源测量未绑定当前头提交")
    measured_at = _parse_rfc3339(resource.get("measured_at"))
    if measured_at is None:
        _append_reason(reasons, "资源测量时间必须为带时区RFC3339")
    elif completed_at is not None and (
        measured_at > completed_at or completed_at - measured_at > timedelta(hours=24)
    ):
        _append_reason(reasons, "资源测量与验证时间顺序或新鲜度无效")

    now = current_time or datetime.now().astimezone()
    if now.tzinfo is None or now.utcoffset() is None:
        _append_reason(reasons, "当前时间缺少时区")
    elif completed_at is not None and (
        completed_at > now + timedelta(minutes=5)
        or now - completed_at > timedelta(hours=24)
    ):
        _append_reason(reasons, "验证证据时间过期或来自未来")

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
