#!/usr/bin/env python3
"""验证外部状态词汇、证据新鲜度和唯一恢复路径的纯函数合同。"""

from __future__ import annotations

from datetime import datetime, timedelta


STATE_VOCABULARY = (
    "未验证",
    "可达（仅连接）",
    "不可达",
    "可达但审计未完成",
)
MAX_EVIDENCE_AGE = timedelta(hours=1)
RECOVERY_TRANSITIONS = frozenset({"阻塞→待执行", "阻塞→需修复"})


def evidence_is_fresh(
    evidence_at: datetime,
    observed_at: datetime,
    *,
    max_age: timedelta = MAX_EVIDENCE_AGE,
) -> bool:
    """要求带时区、非未来且不超过固定年龄上限的证据。"""

    if evidence_at.tzinfo is None or observed_at.tzinfo is None:
        return False
    if observed_at < evidence_at:
        return False
    return observed_at - evidence_at <= max_age


def recovery_is_permitted(
    *,
    current_state: str,
    transition: str,
    probe_reachable: bool,
    audit_evidence: bool,
    evidence_fresh: bool,
) -> bool:
    """只允许有新鲜证据的阻塞任务走唯一状态闭环恢复路径。"""

    return (
        current_state == "阻塞"
        and transition in RECOVERY_TRANSITIONS
        and probe_reachable
        and audit_evidence
        and evidence_fresh
    )


if __name__ == "__main__":
    print("状态词汇、证据新鲜度和恢复路径合同已加载")
