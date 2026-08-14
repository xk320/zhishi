from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from types import ModuleType, SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "研发中心" / "验证自动合并资格.py"
CONTRACT_REPAIR_BASE_SHA = "9b89057fcd58407701b972369e85ea57969b0483"


def load_policy_module() -> ModuleType:
    if not MODULE_PATH.exists():
        raise AssertionError(f"实现文件尚不存在：{MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("auto_merge_policy", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def task_text(
    *,
    status: str,
    task_type: str | None = "治理",
    automation_scope: bool = False,
    dependency: str | None = None,
    title: str = "建立 PR 自动合并策略与审批规则",
    pr_number: str = "40",
    branch: str = "branch",
    extra_contract: str = "",
) -> str:
    type_line = f"- 类型：{task_type}\n" if task_type is not None else ""
    scope_line = "- 自动合并范围：治理自动化\n" if automation_scope else ""
    review_lines = (
        f"- Pull Request：[#{pr_number}](https://github.com/xk320/zhishi/pull/{pr_number})\n"
        if status in {"需修复", "待评审", "已完成"}
        else ""
    )
    completion_lines = (
        "- 合并时间：2026-08-03 08:00:00 +0800\n"
        "- 合并提交SHA：`0123456789abcdef0123456789abcdef01234567`\n"
        if status == "已完成"
        else ""
    )
    dependency_lines = ""
    if dependency is not None:
        dependency_lines = f"- 唯一前序依赖：任务-{dependency}；\n"
        if status == "阻塞":
            dependency_lines += (
                f"- 当前阻塞原因：任务-{dependency}尚未完成。\n"
                f"- 解除条件：任务-{dependency}完成后解除。\n"
            )
        elif status == "待执行":
            dependency_lines += (
                f"- 当前阻塞原因：无；任务-{dependency}已完成。\n"
                "- 解除条件：已满足。\n"
            )
    branch_line = f"- 执行分支：`{branch}`\n"
    return (
        f"# 任务-000013：{title}\n\n"
        f"- 状态：{status}\n"
        f"{type_line}"
        f"{scope_line}"
        "- 优先级：P1\n"
        f"{branch_line}"
        f"{review_lines}"
        f"{completion_lines}"
        f"{dependency_lines}"
        f"{extra_contract}"
    )


def synthetic_task115_pre_execution(text: str) -> str:
    """构造与真实生命周期无关的任务115待执行合同基线。"""

    lines = text.splitlines()
    record_start = next(
        (index for index, line in enumerate(lines) if line.strip() == "## 执行记录"),
        len(lines),
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
        "- 合并时间：",
        "- 合并提交SHA：",
    )
    contract_lines = lines[:record_start]
    normalized = [
        line
        for index, line in enumerate(contract_lines)
        if not (
            index < next(
                (i for i, candidate in enumerate(contract_lines) if candidate.startswith("## ")),
                len(contract_lines),
            )
            and any(line.startswith(prefix) for prefix in mutable_prefixes)
        )
    ]
    normalized.insert(3, "- 状态：待执行")
    return "\n".join(normalized).rstrip() + "\n"


def synthetic_task106_unrevised(text: str, policy: ModuleType) -> str:
    """从当前任务106正文逆向得到未追加覆盖受限章节的测试基线。"""

    section = policy.STAGE1_COVERAGE_LIMITED_SECTION
    return text.replace(section + "\n\n", "", 1)


def task094_contract_versions(policy, current: str | None = None) -> tuple[str, str]:
    """严格接受任务-000094完整修复前或完整修复后合同。"""

    if current is None:
        current = (
            REPO_ROOT / "docs/研发中心/任务/任务-000094.md"
        ).read_text(encoding="utf-8")
    # 该夹具复算的是历史合同修复PR，其目标在当时必须保持“待执行”。
    # 后续真实执行会把仓库中的现行状态推进为“执行中/待评审/已完成”，
    # 不应反向使已经合并的历史治理场景自失效。
    current = re.sub(r"(?m)^- 状态：[^\n]+$", "- 状态：待执行", current, count=1)
    replacements = policy.TASK094_CONTRACT_REPLACEMENTS
    lines = current.splitlines()

    def exact_block_count(block: str) -> int:
        block_lines = block.splitlines()
        width = len(block_lines)
        return sum(
            lines[index : index + width] == block_lines
            for index in range(len(lines) - width + 1)
        )

    old_complete = all(exact_block_count(old) == 1 for old, _ in replacements)
    new_complete = all(exact_block_count(new) == 1 for _, new in replacements)
    repaired = policy._apply_task094_contract_repair(current) if old_complete else None
    if repaired is not None and not new_complete:
        return current, repaired

    if not new_complete:
        raise AssertionError("任务-000094合同不是完整修复前或完整修复后版本")
    base = current
    for old, new in reversed(replacements):
        base = base.replace(new, old, 1)
    if policy._apply_task094_contract_repair(base) != current:
        raise AssertionError("任务-000094新合同无法逐字反向复证")
    return base, current


def blocked_contract_repair_executor_text(
    *, status: str, blocker_evidence: str = "任务-000055最新阻塞状态"
) -> str:
    """任务-000056的最小可验证合同夹具。"""

    review = (
        "- Pull Request：[#200](https://github.com/xk320/zhishi/pull/200)\n"
        if status == "待评审"
        else ""
    )
    return (
        "# 任务-000056：修复治理任务测试路径授权冲突\n\n"
        f"- 状态：{status}\n"
        "- 类型：治理\n"
        "- 自动合并范围：治理自动化\n"
        "- 优先级：P0\n"
        "- 执行分支：`codex/task-000056-repair`\n"
        "- 开始时间：`2026-08-05T07:00:00+08:00`\n"
        f"{review}"
        "- 唯一前序依赖：任务-000033已完成；\n\n"
        "## 背景\n\n- 治理授权冲突。\n\n"
        "## 任务目标\n\n- 修复唯一授权。\n\n"
        "## 固定执行方案\n\n"
        "- 只在任务-000055任务文件中增加唯一的`自动合并范围：治理自动化`字段；\n\n"
        "## 默认工程决策\n\n- 最小字段授权。\n\n"
        "## 允许停止条件\n\n- 需要生产权限时停止。\n\n"
        f"## 输入合同\n\n- {blocker_evidence}。\n\n"
        "## 输出合同\n\n"
        "- 更新后的`docs/研发中心/任务/任务-000055.md`，仅增加受控治理自动化授权字段；\n\n"
        "## 工作范围\n\n- 对齐任务-000055合同。\n\n"
        "## 不在范围\n\n- 不执行任务-000055。\n\n"
        "## 安全边界\n\n- 不访问服务器或数据。\n\n"
        "## 验收标准\n\n- 目标任务仍为阻塞。\n\n"
        "## 验证命令\n\n```bash\npython3 -m unittest\n```\n\n"
        "## 完成定义\n\n- 授权字段进入main。\n\n"
        "## 执行记录\n\n- 交付状态：待评审。\n"
    )


def blocked_contract_repair_target_text(*, authorized: bool = False) -> str:
    scope = "- 自动合并范围：治理自动化\n" if authorized else ""
    return (
        "# 任务-000055：修复现行外部状态与双标的范围文档漂移\n\n"
        "- 状态：阻塞\n"
        "- 类型：治理\n"
        f"{scope}"
        "- 优先级：P0\n"
        "- 执行分支：`codex/task-000055-repair`\n"
        "- 开始时间：`2026-08-05T07:00:00+08:00`\n"
        "- 当前阻塞原因：等待治理规则修复。\n"
        "- 解除条件：治理规则修复进入main。\n\n"
        "## 背景\n\n- 现行入口存在范围漂移。\n\n"
        "## 任务目标\n\n- 修复文档。\n\n"
        "## 固定执行方案\n\n- 绑定最新脱敏事实。\n\n"
        "## 默认工程决策\n\n- 保守处理。\n\n"
        "## 允许停止条件\n\n- 需要服务器写入时停止。\n\n"
        "## 输入合同\n\n- 现行入口。\n\n"
        "## 输出合同\n\n- 文档与测试。\n\n"
        "## 工作范围\n\n- 治理文档。\n\n"
        "## 不在范围\n\n- 不修改数据。\n\n"
        "## 安全边界\n\n- 只读。\n\n"
        "## 验收标准\n\n- 状态一致。\n\n"
        "## 验证命令\n\n```bash\npython3 -m unittest\n```\n\n"
        "## 完成定义\n\n- 通过评审。\n"
    )


def cancellation_task_text(*, status: str = "已取消", support_task: str = "000014", reason: str = "任务-000013的原交付路径已被任务-000014替代。") -> str:
    base = task_text(status="待执行", dependency="000012")
    if status != "已取消":
        return base.replace("- 状态：待执行", f"- 状态：{status}", 1)
    base = base.replace("- 状态：待执行", "- 状态：已取消", 1)
    return base + (
        "- 取消时间：2026-08-04 11:20:00 +0800\n"
        f"- 取消原因：{reason}\n"
        f"- 取消依据任务：任务-{support_task}\n"
        "- 取消依据PR：[#41](https://github.com/xk320/zhishi/pull/41)\n"
        "- 取消依据合并时间：2026-08-03 08:00:00 +0800\n"
        "- 取消依据合并提交SHA：`0123456789abcdef0123456789abcdef01234567`\n"
    )


def closure_board(*, completed: bool) -> str:
    pending_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
        "| --- | --- | --- | --- |\n"
    )
    blocked_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 | 阻塞原因 |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    review_schema = (
        "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    done_schema = (
        "| 任务 | 名称 | 完成证据 |\n"
        "| --- | --- | --- |\n"
    )
    if completed:
        pending = pending_schema + (
            "| P1 | 任务-000014 | 建立 PR 自动合并策略与审批规则 | 000013 |"
        )
        blocked = "无。"
        review = "无。"
        done = done_schema + (
            "| 任务-000013 | 建立 PR 自动合并策略与审批规则 | "
            "PR #40；合并提交 `0123456789abcdef0123456789abcdef01234567` |"
        )
    else:
        pending = "无。"
        blocked = blocked_schema + (
            "| P1 | 任务-000014 | 建立 PR 自动合并策略与审批规则 | "
            "000013 | 任务-000013尚未完成 |"
        )
        review = review_schema + (
            "| P1 | 任务-000013 | 建立 PR 自动合并策略与审批规则 | "
            "branch | PR #40 |"
        )
        done = "无。"
    return (
        "# 看板\n\n"
        f"## 待执行\n\n{pending}\n\n"
        "## 执行中\n\n无。\n\n"
        f"## 阻塞\n\n{blocked}\n\n"
        f"## 待评审\n\n{review}\n\n"
        "## 需修复\n\n无。\n\n"
        f"## 已完成\n\n{done}\n"
        "\n## 已取消\n\n无。\n"
    )


def blocked_transition_board(*, blocked: bool) -> str:
    pending_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
        "| --- | --- | --- | --- |\n"
    )
    blocked_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 | 阻塞原因 |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    row = "| P1 | 任务-000013 | 建立 PR 自动合并策略与审批规则 | 000012 |"
    blocked_row = row + " 任务-000012尚未完成。 |"
    return (
        "# 看板\n\n"
        f"## 待执行\n\n{pending_schema + ('' if blocked else row)}\n\n"
        "## 执行中\n\n无。\n\n"
        f"## 阻塞\n\n{blocked_schema + (blocked_row if blocked else '')}\n\n"
        "## 待评审\n\n"
        "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
        "| --- | --- | --- | --- | --- |\n\n"
        "## 需修复\n\n无。\n\n"
        "## 已完成\n\n"
        "| 任务 | 名称 | 完成证据 |\n| --- | --- | --- |\n\n"
        "## 已取消\n\n无。\n"
    )


def cancellation_board(*, canceled: bool) -> str:
    pending_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
        "| --- | --- | --- | --- |\n"
    )
    done_schema = (
        "| 任务 | 名称 | 完成证据 |\n"
        "| --- | --- | --- |\n"
    )
    canceled_schema = (
        "| 任务 | 名称 | 取消证据 |\n"
        "| --- | --- | --- |\n"
    )
    pending = (
        "无。"
        if canceled
        else pending_schema
        + "| P1 | 任务-000013 | 建立 PR 自动合并策略与审批规则 | 000012 |"
    )
    canceled_rows = (
        canceled_schema
        + "| 任务-000013 | 建立 PR 自动合并策略与审批规则 | "
        "替代任务-000014；PR #41；合并提交 `0123456789abcdef0123456789abcdef01234567`；"
        "取消原因：任务-000013的原交付路径已被任务-000014替代。 |"
        if canceled
        else "无。"
    )
    return (
        "# 看板\n\n"
        f"## 待执行\n\n{pending}\n\n"
        "## 执行中\n\n无。\n\n"
        "## 阻塞\n\n无。\n\n"
        "## 待评审\n\n无。\n\n"
        "## 需修复\n\n无。\n\n"
        "## 已完成\n\n"
        f"{done_schema}| 任务-000014 | 建立 PR 自动合并策略与审批规则 | "
        "PR #41；合并提交 `0123456789abcdef0123456789abcdef01234567` |\n\n"
        f"## 已取消\n\n{canceled_rows}\n"
    )


def delivery_board(
    *,
    head: bool,
    task_id: str = "000013",
    title: str = "建立 PR 自动合并策略与审批规则",
    priority: str = "P1",
    dependency: str = "000012",
    pr_number: str = "40",
    base_status: str = "待执行",
    branch: str = "branch",
) -> str:
    pending_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
        "| --- | --- | --- | --- |\n"
    )
    review_schema = (
        "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    if head:
        pending = "无。"
        repair = "无。"
    elif base_status == "需修复":
        pending = "无。"
        repair = (
            review_schema
            + f"| {priority} | 任务-{task_id} | {title} | `{branch}` | [#{pr_number}](https://github.com/xk320/zhishi/pull/{pr_number}) |"
        )
    else:
        repair = "无。"
        pending = (
            pending_schema
            + f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
        )
    review = (
        review_schema + f"| {priority} | 任务-{task_id} | {title} | `{branch}` | [#{pr_number}](https://github.com/xk320/zhishi/pull/{pr_number}) |"
        if head
        else "无。"
    )
    return (
        "# 看板\n\n"
        f"## 待执行\n\n{pending}\n\n"
        "## 执行中\n\n无。\n\n"
        "## 阻塞\n\n无。\n\n"
        f"## 待评审\n\n{review}\n\n"
        f"## 需修复\n\n{repair}\n\n"
        "## 已完成\n\n| 任务 | 名称 | 完成证据 |\n| --- | --- | --- |\n| 任务-000001 | 基线任务 | 基线证据 |\n\n"
        "## 已取消\n\n无。\n"
    )


REGISTRATION_REQUIRED_FIELDS = (
    "状态",
    "类型",
    "阶段",
    "优先级",
    "执行方案",
    "方案状态",
    "执行授权",
    "并行规则",
)
REGISTRATION_REQUIRED_HEADINGS = (
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


def registration_task(
    *,
    task_id: str = "000040",
    status: str = "待执行",
    title: str = "新增自动任务登记资格",
    task_type: str = "治理",
) -> str:
    blocker = (
        "- 当前阻塞原因：任务-000039尚未完成\n"
        if status == "阻塞"
        else "- 当前阻塞原因：无\n"
    )
    sections = {
        "依赖与阻塞条件": (
            "- 唯一前序依赖：任务-000039完成后执行\n" + blocker
        ),
        **{
            heading: f"- {heading}的可验证合同。\n"
            for heading in REGISTRATION_REQUIRED_HEADINGS[1:]
        },
    }
    return (
        f"# 任务-{task_id}：{title}\n\n"
        f"- 状态：{status}\n"
        f"- 类型：{task_type}\n"
        "- 阶段：阶段1研发自动化治理\n"
        "- 优先级：P1\n"
        "- 执行方案：方案A“完整合同登记”\n"
        "- 方案状态：已批准执行\n"
        "- 执行授权：Codex直接执行\n"
        "- 并行规则：禁止并行\n"
        + "".join(
            f"\n## {heading}\n\n{sections[heading]}"
            for heading in REGISTRATION_REQUIRED_HEADINGS
        )
    )


def registration_board(
    *,
    status: str | None,
    task_id: str = "000040",
    title: str = "新增自动任务登记资格",
    priority: str = "P1",
    duplicate: bool = False,
) -> str:
    pending_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
        "| --- | --- | --- | --- |\n"
    )
    blocked_schema = (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 | 阻塞原因 |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    if status == "待执行":
        row = f"| {priority} | 任务-{task_id} | {title} | 000039 |"
        pending = pending_schema + row
        blocked = "无。"
    elif status == "阻塞":
        row = (
            f"| {priority} | 任务-{task_id} | {title} | 000039 | "
            "任务-000039尚未完成 |"
        )
        pending = "无。"
        blocked = blocked_schema + row
    else:
        row = ""
        pending = "无。"
        blocked = "无。"
    if duplicate and row:
        pending = pending_schema + row + "\n" + row
        blocked = "无。"
    return (
        "# 看板\n\n"
        f"## 待执行\n\n{pending}\n\n"
        "## 执行中\n\n无。\n\n"
        f"## 阻塞\n\n{blocked}\n\n"
        "## 待评审\n\n无。\n\n"
        "## 需修复\n\n无。\n\n"
        "## 已完成\n\n"
        "| 任务 | 名称 | 完成证据 |\n"
        "| --- | --- | --- |\n"
        "| 任务-000039 | 基线任务 | 基线证据 |\n"
        "\n## 已取消\n\n无。\n"
    )


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


@unittest.skipUnless(MODULE_PATH.exists(), "等待资格判定实现")
class AutoMergeEligibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy_module()

    def evaluate(self, **overrides):
        inputs = {
            "changed_paths": [
                "docs/治理/PR自动合并策略.md",
                "docs/研发中心/任务/任务-000013.md",
            ],
            "pr_body": (
                "## 关联任务\n\n"
                "- 任务-000013\n\n"
                "## 变更类型\n\n"
                "- 任务交付\n"
            ),
            "base_tasks": {
                "000013": task_text(status="待执行", dependency="000012"),
            },
            "head_tasks": {
                "000013": task_text(status="待评审", dependency="000012"),
            },
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
            "base_board": delivery_board(head=False),
            "head_board": delivery_board(head=True),
        }
        inputs.update(overrides)
        if "path_facts" not in inputs:
            inputs["path_facts"] = [
                self.policy.PathFact(
                    path=path,
                    status="M",
                    mode="100644",
                    object_type="blob",
                    size=0,
                    text="safe text",
                )
                for path in inputs["changed_paths"]
            ]
        return self.policy.evaluate_eligibility(**inputs)

    def path_fact(self, path: str, **overrides):
        values = {
            "status": "M",
            "mode": "100644",
            "object_type": "blob",
            "size": 0,
            "text": "safe text",
        }
        values.update(overrides)
        return self.policy.PathFact(path=path, **values)

    def test_任务094精确C扫描器白名单不扩散(self):
        path = "scripts/审计/阶段1时间质量扫描器.c"
        self.assertTrue(
            self.policy._task094_native_scanner_allowed(
                task_ids=("000094",), change_type="任务交付", path=path
            )
        )
        for task_ids, change_type, candidate in (
            (("000095",), "任务交付", path),
            (("000094",), "任务登记", path),
            (("000094",), "任务交付", "scripts/审计/其他扫描器.c"),
            (("000094",), "任务交付", "src/阶段1时间质量扫描器.c"),
            (("000094",), "任务交付", "scripts/审计/阶段1时间质量扫描器.o"),
        ):
            with self.subTest(task_ids=task_ids, change_type=change_type, path=candidate):
                self.assertFalse(
                    self.policy._task094_native_scanner_allowed(
                        task_ids=task_ids,
                        change_type=change_type,
                        path=candidate,
                    )
                )

    def test_任务094合同修复必须完整且逐字(self):
        base, repaired = task094_contract_versions(self.policy)
        self.assertEqual(8, len(self.policy.TASK094_CONTRACT_REPLACEMENTS))
        self.assertIn("固定三进程串行流水线", repaired)
        self.assertIn("阶段1时间质量扫描器.c", repaired)
        self.assertIn("主进程与全部子进程峰值RSS保守求和", repaired)
        self.assertIn("- 解除条件：任务-000095", repaired)
        self.assertEqual(1, repaired.count("- 解除条件："))
        self.assertIsNone(
            self.policy._apply_task094_contract_repair(
                base.replace("单进程逐ZIP逐行扫描", "抽样扫描", 1)
            )
        )
        self.assertEqual(
            (base, repaired),
            task094_contract_versions(self.policy, repaired),
        )
        mixed = base.replace(
            *self.policy.TASK094_CONTRACT_REPLACEMENTS[0],
            1,
        )
        first_old, _ = self.policy.TASK094_CONTRACT_REPLACEMENTS[0]
        invalid_contracts = (
            mixed,
            "",
            base.replace(first_old, "", 1),
            base.replace(first_old, f"{first_old}\n{first_old}", 1),
            base.replace(first_old, f"{first_old}额外字符", 1),
        )
        for invalid_contract in invalid_contracts:
            with self.subTest(invalid_contract=invalid_contract):
                with self.assertRaisesRegex(
                    AssertionError, "不是完整修复前或完整修复后"
                ):
                    task094_contract_versions(self.policy, invalid_contract)

    def test_任务094进程组资源事实严格守恒(self):
        valid = {
            "measurement_protocol": "zhishi-process-group-rusage/v1",
            "measurement_platform": "darwin-rusage-maxrss-by-process/v1",
            "rss_unit": "bytes",
            "process_topology": [
                "python_controller",
                "fixed_clang_compile",
                "fixed_unzip",
                "fixed_scanner",
            ],
            "members_parallelism": 1,
            "controller_max_rss_bytes": 120000000,
            "compiler_max_rss_bytes": 10000000,
            "unzip_max_rss_bytes": 20000000,
            "scanner_max_rss_bytes": 50000000,
            "children_conservative_sum_max_rss_bytes": 80000000,
            "conservative_process_group_max_rss_bytes": 200000000,
        }
        self.assertEqual((), self.policy._task094_resource_fact_reasons(valid))
        for mutation in (
            {**valid, "members_parallelism": 2},
            {**valid, "scanner_max_rss_bytes": 0},
            {**valid, "measurement_platform": "self-reported"},
            {**valid, "measurement_protocol": "unknown"},
            {
                key: value
                for key, value in valid.items()
                if key != "unzip_max_rss_bytes"
            },
            {**valid, "children_conservative_sum_max_rss_bytes": 79999999},
            {**valid, "conservative_process_group_max_rss_bytes": 199999999},
            {**valid, "conservative_process_group_max_rss_bytes": 536870913},
        ):
            with self.subTest(mutation=mutation):
                self.assertTrue(self.policy._task094_resource_fact_reasons(mutation))

    def test_任务094资源证据绑定最终头文件与批次(self):
        _, task_text_value = task094_contract_versions(self.policy)
        texts = {
            self.policy.TASK094_EXECUTOR_PATH: "executor\n",
            self.policy.TASK094_CONFIG_PATH: "config\n",
            self.policy.TASK094_NATIVE_SCANNER_PATH: "scanner\n",
            self.policy.TASK094_TASK_PATH: task_text_value,
        }
        batch_id = "stage1-time-quality-test-deadbeef"
        summary = {
            "batch_id": batch_id,
            "executor_sha256": hashlib.sha256(b"executor\n").hexdigest(),
            "config_sha256": hashlib.sha256(b"config\n").hexdigest(),
            "scanner_source_sha256": hashlib.sha256(b"scanner\n").hexdigest(),
            "task_contract_sha256": self.policy._task094_contract_digest(
                task_text_value
            ),
            "process_group_resource_facts": {
                "measurement_protocol": "zhishi-process-group-rusage/v1",
                "measurement_platform": "darwin-rusage-maxrss-by-process/v1",
                "rss_unit": "bytes",
                "process_topology": [
                    "python_controller",
                    "fixed_clang_compile",
                    "fixed_unzip",
                    "fixed_scanner",
                ],
                "members_parallelism": 1,
                "controller_max_rss_bytes": 100,
                "compiler_max_rss_bytes": 20,
                "unzip_max_rss_bytes": 30,
                "scanner_max_rss_bytes": 40,
                "children_conservative_sum_max_rss_bytes": 90,
                "conservative_process_group_max_rss_bytes": 190,
            },
        }
        facts = [
            self.path_fact(path, status="A", text=text)
            for path, text in texts.items()
        ]
        summary_path = (
            "artifacts/审计/阶段1逐行时间质量/"
            f"{batch_id}/summary.json"
        )
        facts.append(
            self.path_fact(
                summary_path,
                status="A",
                text=json.dumps(summary, ensure_ascii=False),
            )
        )
        reasons = []
        self.policy._validate_task094_batch_resource_evidence(facts, reasons)
        self.assertEqual([], reasons)

        summary["executor_sha256"] = "0" * 64
        facts[-1] = self.path_fact(
            summary_path,
            status="A",
            text=json.dumps(summary, ensure_ascii=False),
        )
        reasons = []
        self.policy._validate_task094_batch_resource_evidence(facts, reasons)
        self.assertIn(
            "任务-000094资源证据executor_sha256未绑定最终头文件", reasons
        )

        valid_summary_text = json.dumps(summary, ensure_ascii=False).replace(
            '"executor_sha256": "' + "0" * 64 + '"',
            '"executor_sha256": "'
            + hashlib.sha256(b"executor\n").hexdigest()
            + '"',
            1,
        )
        duplicate_documents = (
            valid_summary_text.replace(
                f'"batch_id": "{batch_id}"',
                f'"batch_id": "{batch_id}", "batch_id": "{batch_id}"',
                1,
            ),
            valid_summary_text.replace(
                '"members_parallelism": 1',
                '"members_parallelism": 1, "members_parallelism": 1',
                1,
            ),
        )
        for duplicate_document in duplicate_documents:
            with self.subTest(duplicate_document=duplicate_document):
                facts[-1] = self.path_fact(
                    summary_path,
                    status="A",
                    text=duplicate_document,
                )
                reasons = []
                self.policy._validate_task094_batch_resource_evidence(
                    facts, reasons
                )
                self.assertIn("任务-000094最终批次摘要无效", reasons)

    def test_任务095到094一次性合同修复不允许夹带(self):
        target_base, target_head = task094_contract_versions(self.policy)
        executor = task_text(status="已完成", task_type="治理")
        reasons = []
        allowed = self.policy._validate_task094_contract_repair(
            task_ids=("000095",),
            changed_paths=("docs/研发中心/任务/任务-000094.md",),
            base_tasks={"000095": executor, "000094": target_base},
            head_tasks={"000095": executor, "000094": target_head},
            base_board="same",
            head_board="same",
            reasons=reasons,
        )
        self.assertEqual({"000094", "000095"}, allowed)
        self.assertEqual([], reasons)
        tampered = target_head.replace("512MiB", "513MiB", 1)
        tampered_reasons = []
        self.policy._validate_task094_contract_repair(
            task_ids=("000095",),
            changed_paths=("docs/研发中心/任务/任务-000094.md",),
            base_tasks={"000095": executor, "000094": target_base},
            head_tasks={"000095": executor, "000094": tampered},
            base_board="same",
            head_board="same",
            reasons=tampered_reasons,
        )
        self.assertIn("任务-000094未按固定完整合同修复", tampered_reasons)

    def test_任务102到100只允许唯一输出条目替换(self):
        old = self.policy.TASK100_OUTPUT_CONTRACT_OLD
        new = self.policy.TASK100_OUTPUT_CONTRACT_NEW
        target_base = (
            "# 任务-000100：闭合阶段1成本与执行证据\n\n"
            "- 状态：待执行\n- 类型：数据审计\n\n"
            f"## 输出合同\n\n{old}\n\n"
            "## 验收标准\n\n1. 既有八项验收标准逐字不变。\n"
        )
        target_head = target_base.replace(old, new, 1)
        executor = task_text(status="已完成", task_type="治理")
        governance = task_text(status="已完成", task_type="治理")
        common_base = {
            "000102": executor,
            "000101": governance,
            "000100": target_base,
        }
        common_head = {
            "000102": executor,
            "000101": governance,
            "000100": target_head,
        }
        reasons = []
        allowed = self.policy._validate_task100_contract_repair(
            task_ids=("000102",),
            changed_paths=("docs/研发中心/任务/任务-000100.md",),
            base_tasks=common_base,
            head_tasks=common_head,
            base_board="same",
            head_board="same",
            reasons=reasons,
        )
        self.assertEqual({"000100", "000102"}, allowed)
        self.assertEqual([], reasons)

        cases = {
            "夹带验收改写": target_head.replace("逐字不变", "允许变化"),
            "重复旧条目": target_base.replace(old, f"{old}\n{old}"),
            "目标状态迁移": target_head.replace("- 状态：待执行", "- 状态：执行中"),
        }
        for name, tampered in cases.items():
            with self.subTest(name=name):
                tampered_reasons = []
                self.policy._validate_task100_contract_repair(
                    task_ids=("000102",),
                    changed_paths=("docs/研发中心/任务/任务-000100.md",),
                    base_tasks=common_base,
                    head_tasks={**common_head, "000100": tampered},
                    base_board="same",
                    head_board="same",
                    reasons=tampered_reasons,
                )
                self.assertTrue(tampered_reasons, name)

        not_completed = task_text(status="待评审", task_type="治理")
        incomplete_reasons = []
        self.policy._validate_task100_contract_repair(
            task_ids=("000102",),
            changed_paths=("docs/研发中心/任务/任务-000100.md",),
            base_tasks={**common_base, "000102": not_completed},
            head_tasks={**common_head, "000102": not_completed},
            base_board="same",
            head_board="same",
            reasons=incomplete_reasons,
        )
        self.assertIn("任务-000102必须先完成状态闭环", incomplete_reasons)

        governance_incomplete = task_text(status="待评审", task_type="治理")
        governance_reasons = []
        self.policy._validate_task100_contract_repair(
            task_ids=("000102",),
            changed_paths=("docs/研发中心/任务/任务-000100.md",),
            base_tasks={**common_base, "000101": governance_incomplete},
            head_tasks={**common_head, "000101": governance_incomplete},
            base_board="same",
            head_board="same",
            reasons=governance_reasons,
        )
        self.assertIn("任务-000101必须先完成状态闭环", governance_reasons)

        source_drift_reasons = []
        self.policy._validate_task100_contract_repair(
            task_ids=("000102",),
            changed_paths=("docs/研发中心/任务/任务-000100.md",),
            base_tasks=common_base,
            head_tasks={**common_head, "000102": executor + "\n夹带改写\n"},
            base_board="same",
            head_board="same",
            reasons=source_drift_reasons,
        )
        self.assertIn(
            "任务-000102在目标合同修复中必须逐字不变", source_drift_reasons
        )

        for name, extra_path in {
            "历史审计": "docs/审计/阶段1最终审计报告.md",
            "旧批次": "artifacts/审计/历史批次/summary.json",
            "数据": "data/raw.csv",
            "生产": "deploy/production.yml",
        }.items():
            with self.subTest(name=name):
                path_reasons = []
                self.policy._validate_task100_contract_repair(
                    task_ids=("000102",),
                    changed_paths=(
                        "docs/研发中心/任务/任务-000100.md",
                        extra_path,
                    ),
                    base_tasks=common_base,
                    head_tasks=common_head,
                    base_board="same",
                    head_board="same",
                    reasons=path_reasons,
                )
                self.assertIn("任务-000100合同修复只能修改目标任务文件", path_reasons)

        board_reasons = []
        self.policy._validate_task100_contract_repair(
            task_ids=("000102",),
            changed_paths=("docs/研发中心/任务/任务-000100.md",),
            base_tasks=common_base,
            head_tasks=common_head,
            base_board="base",
            head_board="drift",
            reasons=board_reasons,
        )
        self.assertIn("任务-000100合同修复不得改写看板", board_reasons)

    def test_任务102合同修复入口精确单引用且真实目标可替换(self):
        self.assertEqual(
            "000102", self.policy._contract_conflict_executor(("000102",))
        )
        for references in ((), ("000100",), ("000102", "000095"), ("000102", "000102")):
            with self.subTest(references=references):
                self.assertIsNone(self.policy._contract_conflict_executor(references))
        target = (
            REPO_ROOT / "docs/研发中心/任务/任务-000100.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn(self.policy.TASK100_OUTPUT_CONTRACT_OLD, target)
        self.assertEqual(1, target.count(self.policy.TASK100_OUTPUT_CONTRACT_NEW))
        legacy = target.replace(
            self.policy.TASK100_OUTPUT_CONTRACT_NEW,
            self.policy.TASK100_OUTPUT_CONTRACT_OLD,
        )
        repaired = self.policy._apply_task100_contract_repair(legacy)
        self.assertIsNotNone(repaired)
        assert repaired is not None
        self.assertNotIn(self.policy.TASK100_OUTPUT_CONTRACT_OLD, repaired)
        self.assertEqual(1, repaired.count(self.policy.TASK100_OUTPUT_CONTRACT_NEW))
        self.assertEqual(target, repaired)
        self.assertIsNone(self.policy._apply_task100_contract_repair(target))

    def test_任务102登记必须等待并依赖已完成任务101(self):
        task = registration_task(task_id="000102").replace(
            "任务-000039", "任务-000101"
        )
        base_tasks = {
            f"{number:06d}": "基线任务\n"
            for number in range(1, 102)
        }
        base_tasks["000101"] = task_text(status="已完成", task_type="治理")
        result = self.evaluate_registration(
            task_id="000102",
            task=task,
            base_tasks=base_tasks,
            head_tasks={"000102": task},
            base_board=registration_board(status=None),
            head_board=registration_board(
                status="待执行", task_id="000102"
            ).replace(
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000039 |",
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000101 |",
            ),
        )
        self.assertTrue(result.eligible, result.reasons)

        incomplete = {**base_tasks, "000101": task_text(status="待评审")}
        blocked = self.evaluate_registration(
            task_id="000102",
            task=task,
            base_tasks=incomplete,
            head_tasks={"000102": task},
            base_board=registration_board(status=None),
            head_board=registration_board(
                status="待执行", task_id="000102"
            ).replace(
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000039 |",
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000101 |",
            ),
        )
        self.assertIn("任务-000102只能在任务-000101完成后登记", blocked.reasons)

        wrong_dependency = task.replace("任务-000101", "任务-000099")
        wrong = self.evaluate_registration(
            task_id="000102",
            task=wrong_dependency,
            base_tasks=base_tasks,
            head_tasks={"000102": wrong_dependency},
            base_board=registration_board(status=None),
            head_board=registration_board(
                status="待执行", task_id="000102"
            ).replace(
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000039 |",
                "| P1 | 任务-000102 | 新增自动任务登记资格 | 000099 |",
            ),
        )
        self.assertIn("任务-000102唯一前序依赖必须为任务-000101", wrong.reasons)

    def registration_inputs(
        self,
        *,
        task_id: str = "000040",
        status: str = "待执行",
        task: str | None = None,
        changed_paths: list[str] | None = None,
        base_tasks: dict[str, str] | None = None,
        head_tasks: dict[str, str] | None = None,
        base_board: str | None = None,
        head_board: str | None = None,
        path_facts=None,
        pr_body: str | None = None,
    ) -> dict:
        task_path = f"docs/研发中心/任务/任务-{task_id}.md"
        design_path = (
            f"docs/superpowers/specs/2026-08-04-task-{task_id}-design.md"
        )
        task = task if task is not None else registration_task(
            task_id=task_id,
            status=status,
        )
        changed_paths = changed_paths or [
            task_path,
            "docs/研发中心/看板.md",
            design_path,
        ]
        base_tasks = base_tasks if base_tasks is not None else {
            f"{number:06d}": "基线任务\n"
            for number in range(1, 40)
            if number != 26
        }
        head_tasks = head_tasks if head_tasks is not None else {task_id: task}
        base_board = (
            registration_board(status=None)
            if base_board is None
            else base_board
        )
        head_board = (
            registration_board(status=status, task_id=task_id)
            if head_board is None
            else head_board
        )
        if path_facts is None:
            texts = {
                task_path: task,
                "docs/研发中心/看板.md": head_board,
                design_path: f"# 任务-{task_id}设计\n",
            }
            path_facts = [
                self.path_fact(
                    path,
                    status=(
                        "A"
                        if path in {task_path, design_path}
                        else "M"
                    ),
                    size=len(texts.get(path, "safe text").encode()),
                    text=texts.get(path, "safe text"),
                )
                for path in changed_paths
            ]
        return {
            "changed_paths": changed_paths,
            "pr_body": pr_body or (
                "## 关联任务\n\n"
                f"- 任务-{task_id}\n\n"
                "## 变更类型\n\n"
                "- 任务登记\n"
            ),
            "base_tasks": base_tasks,
            "head_tasks": head_tasks,
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
            "base_board": base_board,
            "head_board": head_board,
            "path_facts": path_facts,
        }

    def evaluate_registration(self, **overrides):
        return self.policy.evaluate_eligibility(
            **self.registration_inputs(**overrides)
        )

    def test_完整单任务登记允许(self):
        for status in ("待执行", "阻塞"):
            with self.subTest(status=status):
                result = self.evaluate_registration(status=status)

                self.assertTrue(result.eligible, result.reasons)
                self.assertEqual((), result.reasons)

    def test_任务登记拒绝夹带和不完整合同(self):
        multiple_body = (
            "## 关联任务\n\n"
            "- 任务-000040\n"
            "- 任务-000041\n\n"
            "## 变更类型\n\n"
            "- 任务登记\n"
        )
        result = self.evaluate_registration(pr_body=multiple_body)
        self.assertFalse(result.eligible)
        self.assertIn("任务登记必须且只能引用一个新任务", result.reasons)

        existing_tasks = self.registration_inputs()["base_tasks"]
        existing_tasks["000040"] = registration_task()
        result = self.evaluate_registration(base_tasks=existing_tasks)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000040已在基线main中登记", result.reasons)

        result = self.evaluate_registration(head_tasks={})
        self.assertFalse(result.eligible)
        self.assertIn("任务-000040未包含在PR头提交中", result.reasons)

        for status in ("执行中", "待评审", "已完成"):
            with self.subTest(status=status):
                result = self.evaluate_registration(status=status)
                self.assertFalse(result.eligible)
                self.assertIn(
                    f"任务-000040在PR中的状态“{status}”不可登记",
                    result.reasons,
                )

        complete_task = registration_task()
        for field in REGISTRATION_REQUIRED_FIELDS:
            field_line = next(
                line
                for line in complete_task.splitlines()
                if line.startswith(f"- {field}：")
            )
            for mutation, task in (
                ("缺失", complete_task.replace(field_line + "\n", "", 1)),
                (
                    "重复",
                    complete_task.replace(
                        "\n## 依赖与阻塞条件",
                        f"\n{field_line}\n## 依赖与阻塞条件",
                        1,
                    ),
                ),
            ):
                with self.subTest(field=field, mutation=mutation):
                    result = self.evaluate_registration(task=task)
                    self.assertFalse(result.eligible)
                    self.assertIn(
                        f"任务-000040合同字段“{field}”必须且只能出现一次",
                        result.reasons,
                    )

        for heading in REGISTRATION_REQUIRED_HEADINGS:
            marker = f"## {heading}"
            section_pattern = re.compile(
                rf"\n{re.escape(marker)}\n.*?(?=\n## |\Z)",
                re.DOTALL,
            )
            for mutation, task in (
                ("缺失", section_pattern.sub("", complete_task, count=1)),
                ("重复", complete_task + f"\n## {heading}\n\n- 伪造重复章节。\n"),
            ):
                with self.subTest(heading=heading, mutation=mutation):
                    result = self.evaluate_registration(task=task)
                    self.assertFalse(result.eligible)
                    self.assertIn(
                        f"任务-000040合同章节“{heading}”必须且只能出现一次",
                        result.reasons,
                    )

        unapproved = complete_task.replace(
            "- 方案状态：已批准执行",
            "- 方案状态：待批准",
        )
        result = self.evaluate_registration(task=unapproved)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000040方案状态不是“已批准执行”", result.reasons)

        result = self.evaluate_registration(task_id="000041")
        self.assertFalse(result.eligible)
        self.assertIn(
            "任务-000041编号必须为基线最大编号000039的下一编号000040",
            result.reasons,
        )

        result = self.evaluate_registration(task_id="000026")
        self.assertFalse(result.eligible)
        self.assertIn("任务-000026历史缺号禁止复用", result.reasons)

        for rejected_path in (
            "scripts/研发中心/夹带实现.py",
            "config/研发/夹带配置.json",
            "artifacts/研发/夹带产物.json",
            "docs/治理/非设计文档.md",
            "tests/研发中心/test_验证自动合并资格.py",
            "tests/研发中心/test_项目范围与阶段状态.py",
        ):
            with self.subTest(rejected_path=rejected_path):
                paths = self.registration_inputs()["changed_paths"] + [rejected_path]
                result = self.evaluate_registration(changed_paths=paths)
                self.assertFalse(result.eligible)
                self.assertIn(
                    f"任务登记包含不允许路径“{rejected_path}”",
                    result.reasons,
                )

        result = self.evaluate_registration(
            changed_paths=[
                "docs/研发中心/任务/任务-000040.md",
                "docs/研发中心/看板.md",
            ]
        )
        self.assertFalse(result.eligible)
        self.assertIn(
            "任务登记必须且只能新增一个对应设计文档",
            result.reasons,
        )

        inputs = self.registration_inputs()
        design_path = "docs/superpowers/specs/2026-08-04-task-000040-design.md"
        inputs["path_facts"] = [
            self.path_fact(
                fact.path,
                status=fact.status,
                size=fact.size,
                text=(
                    "# 未关联任务的设计\n"
                    if fact.path == design_path
                    else fact.text
                ),
            )
            for fact in inputs["path_facts"]
        ]
        result = self.policy.evaluate_eligibility(**inputs)
        self.assertFalse(result.eligible)
        self.assertIn("任务登记设计文档未对应任务-000040", result.reasons)

        result = self.evaluate_registration(
            changed_paths=[
                "docs/研发中心/任务/任务-000040.md",
                "docs/superpowers/specs/2026-08-04-task-000040-design.md",
            ]
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务登记必须同步看板", result.reasons)

        board_cases = (
            ("缺行", registration_board(status=None)),
            ("重复行", registration_board(status="待执行", duplicate=True)),
            ("分区错误", registration_board(status="阻塞")),
            (
                "名称不一致",
                registration_board(status="待执行", title="被篡改的名称"),
            ),
            (
                "优先级不一致",
                registration_board(status="待执行", priority="P0"),
            ),
            (
                "依赖不一致",
                registration_board(status="待执行").replace(
                    "| 000039 |", "| 000038 |", 1
                ),
            ),
            (
                "夹带无关看板行改写",
                registration_board(status="待执行").replace(
                    "基线证据", "被篡改的证据"
                ),
            ),
        )
        for case, head_board in board_cases:
            with self.subTest(board=case):
                result = self.evaluate_registration(head_board=head_board)
                self.assertFalse(result.eligible)
                self.assertIn(
                    "任务-000040在看板中不是唯一可复算新增映射",
                    result.reasons,
                )

        result = self.evaluate_registration(
            status="阻塞",
            head_board=registration_board(status="阻塞").replace(
                "任务-000039尚未完成", "伪造阻塞原因", 1
            ),
        )
        self.assertFalse(result.eligible)
        self.assertIn(
            "任务-000040在看板中不是唯一可复算新增映射",
            result.reasons,
        )

        inputs = self.registration_inputs()
        task_path = "docs/研发中心/任务/任务-000040.md"
        inputs["path_facts"] = [
            self.path_fact(
                fact.path,
                status=("M" if fact.path == task_path else fact.status),
                size=fact.size,
                text=fact.text,
            )
            for fact in inputs["path_facts"]
        ]
        result = self.policy.evaluate_eligibility(**inputs)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000040任务文件必须是新增普通文件", result.reasons)

    def test_pr合同按commonmark标题唯一解析(self):
        equivalent_body = (
            "  ##\t关联任务 ### \t\n\n"
            "- 任务-000013\n\n"
            "## 变更类型 #\n\n"
            "- 任务交付\n"
        )
        result = self.evaluate(pr_body=equivalent_body)
        self.assertTrue(result.eligible, result.reasons)

        duplicate_variants = (
            "## 变更类型\n\n- 任务交付\n",
            "## 变更类型 \t\n\n- 任务交付\n",
            "## 变更类型 #\n\n- 任务交付\n",
        )
        for duplicate in duplicate_variants:
            with self.subTest(change_type_heading=duplicate.splitlines()[0]):
                body = (
                    "## 关联任务\n\n- 任务-000013\n\n"
                    "## 变更类型\n\n- 任务交付\n\n"
                    + duplicate
                )
                result = self.evaluate(pr_body=body)
                self.assertFalse(result.eligible)
                self.assertIn("PR正文缺少有效变更类型", result.reasons)

        for duplicate_heading in (
            "## 关联任务",
            "## 关联任务 \t",
            "## 关联任务 #",
        ):
            with self.subTest(task_heading=duplicate_heading):
                body = (
                    "## 关联任务\n\n- 任务-000013\n\n"
                    f"{duplicate_heading}\n\n- 任务-000013\n\n"
                    "## 变更类型\n\n- 任务交付\n"
                )
                result = self.evaluate(pr_body=body)
                self.assertFalse(result.eligible)
                self.assertIn("PR正文未引用任务编号", result.reasons)

    def test_任务登记按commonmark统计必需二级章节(self):
        complete_task = registration_task()
        for equivalent in ("## 背景 ", "## 背景\t", "## 背景 #"):
            with self.subTest(single_equivalent=equivalent):
                task = complete_task.replace("## 背景", equivalent, 1)
                result = self.evaluate_registration(task=task)
                self.assertTrue(result.eligible, result.reasons)

        for duplicate in ("## 背景 ", "## 背景\t", "## 背景 #"):
            with self.subTest(duplicate=duplicate):
                task = complete_task + f"\n{duplicate}\n\n- 伪造重复背景。\n"
                result = self.evaluate_registration(task=task)
                self.assertFalse(result.eligible)
                self.assertIn(
                    "任务-000040合同章节“背景”必须且只能出现一次",
                    result.reasons,
                )

    def test_任务登记元数据必须位于commonmark首个二级章节前(self):
        complete_task = registration_task()
        background = "## 背景\n\n- 背景的可验证合同。\n"
        without_background = complete_task.replace(
            "\n" + background,
            "",
            1,
        )
        title, remainder = without_background.split("\n\n", maxsplit=1)
        task = (
            title
            + "\n\n   ## 背景 #\n\n- 背景的可验证合同。\n\n"
            + remainder
        )

        result = self.evaluate_registration(task=task)

        self.assertFalse(result.eligible)
        for field in REGISTRATION_REQUIRED_FIELDS:
            self.assertIn(
                f"任务-000040合同字段“{field}”必须且只能出现一次",
                result.reasons,
            )

    def test_任务登记依赖和阻塞原因必须唯一(self):
        complete_task = registration_task()
        dependency_line = "- 唯一前序依赖：任务-000039完成后执行"
        for mutation, task in (
            ("缺失", complete_task.replace(dependency_line + "\n", "", 1)),
            ("重复", complete_task.replace(dependency_line, dependency_line + "\n" + dependency_line, 1)),
            (
                "冲突",
                complete_task.replace(
                    dependency_line,
                    dependency_line + "\n- 唯一前序依赖：任务-000038",
                    1,
                ),
            ),
            (
                "伪装非任务重复",
                complete_task.replace(
                    dependency_line,
                    dependency_line + "\n- 唯一前序依赖：无",
                    1,
                ),
            ),
        ):
            with self.subTest(dependency=mutation):
                result = self.evaluate_registration(task=task)
                self.assertFalse(result.eligible)
                self.assertIn(
                    "任务-000040唯一前序依赖必须且只能出现一次",
                    result.reasons,
                )

        blocked_task = registration_task(status="阻塞")
        blocker_line = "- 当前阻塞原因：任务-000039尚未完成"
        for mutation, task in (
            ("缺失", blocked_task.replace(blocker_line + "\n", "", 1)),
            ("空值", blocked_task.replace(blocker_line, "- 当前阻塞原因：   ", 1)),
            ("重复", blocked_task.replace(blocker_line, blocker_line + "\n" + blocker_line, 1)),
            (
                "冲突",
                blocked_task.replace(
                    blocker_line,
                    blocker_line + "\n- 当前阻塞原因：伪造原因",
                    1,
                ),
            ),
            (
                "伪装空值重复",
                blocked_task.replace(
                    blocker_line,
                    blocker_line + "\n- 当前阻塞原因：",
                    1,
                ),
            ),
        ):
            with self.subTest(blocker=mutation):
                result = self.evaluate_registration(status="阻塞", task=task)
                self.assertFalse(result.eligible)
                self.assertIn(
                    "任务-000040阻塞原因必须且只能出现一次且非空",
                    result.reasons,
                )

    def test_任务登记看板基线和头部表格结构必须合法(self):
        base_board = registration_board(status=None)
        head_board = registration_board(status="待执行")
        invalid_cases = (
            (
                "base缺失表头",
                base_board.replace("| 任务 | 名称 | 完成证据 |\n", "", 1),
                head_board,
            ),
            (
                "head缺失表头",
                base_board,
                head_board.replace("| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n", "", 1),
            ),
            (
                "head缺失分隔行",
                base_board,
                head_board.replace("| --- | --- | --- | --- |\n", "", 1),
            ),
        )
        for case, invalid_base, invalid_head in invalid_cases:
            with self.subTest(case=case):
                result = self.evaluate_registration(
                    base_board=invalid_base,
                    head_board=invalid_head,
                )
                self.assertFalse(result.eligible)
                self.assertIn(
                    "任务-000040在看板中不是唯一可复算新增映射",
                    result.reasons,
                )

    def test_任务登记拒绝未知和高风险类型(self):
        for task_type in (
            "真实交易",
            "资金管理",
            "生产运维",
            "凭据管理",
            "未知",
        ):
            with self.subTest(task_type=task_type):
                result = self.evaluate_registration(
                    task=registration_task(task_type=task_type)
                )
                self.assertFalse(result.eligible)
                self.assertIn(
                    f"任务-000040类型“{task_type}”不允许自动合并",
                    result.reasons,
                )

    def test_低风险治理文档且任务待评审时允许(self):
        result = self.evaluate()

        self.assertTrue(result.eligible)
        self.assertEqual((), result.reasons)

    def blocked_repair_inputs(self, **overrides):
        base_executor = blocked_contract_repair_executor_text(status="待执行")
        head_executor = blocked_contract_repair_executor_text(status="待评审")
        base_target = blocked_contract_repair_target_text()
        head_target = blocked_contract_repair_target_text(authorized=True)
        inputs = {
            "changed_paths": [
                "docs/研发中心/任务/任务-000056.md",
                "docs/研发中心/任务/任务-000055.md",
                "docs/研发中心/看板.md",
                "docs/治理/PR自动合并策略.md",
                "tests/研发中心/test_验证自动合并资格.py",
            ],
            "pr_body": (
                "## 关联任务\n\n- 任务-000056\n\n"
                "## 变更类型\n\n- 阻塞任务合同修复\n"
            ),
            "base_tasks": {
                "000056": base_executor,
                "000055": base_target,
            },
            "head_tasks": {
                "000056": head_executor,
                "000055": head_target,
            },
            "base_board": delivery_board(
                head=False,
                task_id="000056",
                title="修复治理任务测试路径授权冲突",
                priority="P0",
                dependency="000033",
                pr_number="200",
            ),
            "head_board": delivery_board(
                head=True,
                task_id="000056",
                title="修复治理任务测试路径授权冲突",
                priority="P0",
                dependency="000033",
                pr_number="200",
                branch="codex/task-000056-repair",
            ),
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
        }
        inputs["path_facts"] = [
            self.path_fact(path, text="安全治理文本")
            for path in inputs["changed_paths"]
        ]
        inputs.update(overrides)
        return inputs

    def evaluate_blocked_repair(self, **overrides):
        return self.policy.evaluate_eligibility(**self.blocked_repair_inputs(**overrides))

    def root_readonly_contract_repair_inputs(
        self, *, mutate_target: str = "", target_status: str = "阻塞"
    ):
        executor = re.sub(
            r"^- 状态：[^\n]+$",
            "- 状态：已完成",
            (REPO_ROOT / "docs/研发中心/任务/任务-000086.md").read_text(encoding="utf-8"),
            count=1,
            flags=re.MULTILINE,
        )
        target_base = (
            REPO_ROOT / "docs/研发中心/任务/任务-000084.md"
        ).read_text(encoding="utf-8")
        # 测试夹具固定为合同修复前的基线；当前工作树可能已包含待验证的
        # root兼容段落，不能把头部合同误当作基线输入。
        root_section = self.policy.ROOT_READONLY_COMPAT_SECTION.strip()
        if root_section in target_base:
            target_base = target_base.split(root_section, 1)[0].rstrip("\n") + "\n"
        target_base = re.sub(
            r"^- 状态：[^\n]+$",
            f"- 状态：{target_status}",
            target_base,
            count=1,
            flags=re.MULTILINE,
        )
        target_head = target_base.rstrip("\n") + "\n\n" + self.policy.ROOT_READONLY_COMPAT_SECTION.strip() + "\n"
        if mutate_target == "status":
            target_head = target_head.replace("- 状态：阻塞", "- 状态：待执行", 1)
        elif mutate_target == "drift":
            target_head = target_head.replace("UID为0", "UID为1001", 1)
        changed_paths = [
            "docs/研发中心/任务/任务-000084.md",
            "tests/研发中心/test_验证自动合并资格.py",
        ]
        return {
            "changed_paths": changed_paths,
            "pr_body": (
                "## 关联任务\n\n- 任务-000086\n\n"
                "## 变更类型\n\n- 阻塞任务合同修复\n"
            ),
            "base_tasks": {"000086": executor, "000084": target_base},
            "head_tasks": {"000086": executor, "000084": target_head},
            "base_board": (
                REPO_ROOT / "docs/研发中心/看板.md"
            ).read_text(encoding="utf-8"),
            "head_board": (
                REPO_ROOT / "docs/研发中心/看板.md"
            ).read_text(encoding="utf-8"),
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
            "path_facts": [self.path_fact(path, text="安全治理文本") for path in changed_paths],
        }

    def evaluate_root_readonly_contract_repair(self, **overrides):
        return self.policy.evaluate_eligibility(
            **self.root_readonly_contract_repair_inputs(**overrides)
        )

    def test_root只读兼容合同修复固定映射允许且不改看板(self):
        result = self.evaluate_root_readonly_contract_repair()
        self.assertTrue(result.eligible, result.reasons)
        self.assertEqual((), result.reasons)

        migrated = self.evaluate_root_readonly_contract_repair(mutate_target="status")
        self.assertFalse(migrated.eligible)
        self.assertIn("目标任务-000084状态不得在合同修复中迁移", migrated.reasons)

        drifted = self.evaluate_root_readonly_contract_repair(mutate_target="drift")
        self.assertFalse(drifted.eligible)
        self.assertIn("任务-000084只能追加固定root兼容合同段落", drifted.reasons)

    def test_root只读兼容合同修复拒绝已取消目标(self):
        result = self.evaluate_root_readonly_contract_repair(
            target_status="已取消"
        )
        self.assertFalse(result.eligible)
        self.assertIn("目标任务-000084已取消，旧root兼容映射已关闭", result.reasons)

    def test_root合同修复禁止治理策略和看板路径(self):
        inputs = self.root_readonly_contract_repair_inputs()
        inputs["changed_paths"] = [
            *inputs["changed_paths"],
            "docs/治理/PR自动合并策略.md",
            "docs/研发中心/看板.md",
        ]
        inputs["path_facts"] = [
            self.path_fact(path, text="安全治理文本")
            for path in inputs["changed_paths"]
        ]
        result = self.policy.evaluate_eligibility(**inputs)
        self.assertFalse(result.eligible)
        self.assertIn(
            "阻塞任务合同修复包含不允许路径“docs/治理/PR自动合并策略.md”",
            result.reasons,
        )

    def contract_conflict_repair_inputs(self, *, mutate_target: str = ""):
        executor_title = "执行任务-000068合同冲突修复"
        executor_base = task_text(
            status="待执行",
            dependency=None,
            title=executor_title,
            pr_number="168",
            branch="codex/task-000068-contract-conflict-v1",
            extra_contract=(
                "- 唯一前序依赖：任务-000067；\n"
                "- 当前阻塞原因：无；任务-000067已完成。\n"
                "- 解除条件：已满足。\n"
            ),
        )
        executor_head = task_text(
            status="待评审",
            dependency=None,
            title=executor_title,
            pr_number="168",
            branch="codex/task-000068-contract-conflict-v1",
            extra_contract=(
                "- 唯一前序依赖：任务-000067；\n"
                "- 当前阻塞原因：无；任务-000067已完成。\n"
                "- 解除条件：已满足。\n"
            ),
        )
        target_base = subprocess.check_output(
            [
                "git",
                "show",
                f"{CONTRACT_REPAIR_BASE_SHA}:docs/研发中心/任务/任务-000066.md",
            ],
            cwd=REPO_ROOT,
            text=True,
        )
        old_completion = (
            "本登记PR合并后任务保持`阻塞`，不标记已完成。只有解除条件有证据并经独立状态闭环PR恢复为待执行后，\n"
            "才能认领执行；正文审计交付须另行PR、双只读评审、main可信复验和合并后状态闭环。"
        )
        new_completion = (
            "正文审计交付PR已合并并完成双只读评审、主执行器验证和main可信复验；随后通过独立状态闭环PR标记本任务为`已完成`。\n"
            "审计结果中的无法判定、失败和未成熟必须继续保留，不代表阶段1数据门槛或阶段2放行。"
        )
        target_head = target_base.replace(
            "- 实现提交SHA：`eb632a33d3d0c08893dfe4bcee1f4dc549e03f4e`\n",
            "- 实现提交SHA：`eb632a33d3d0c08893dfe4bcee1f4dc549e03f4e`\n"
            "- 交付提交SHA：`c5a5f838f3c09b352150508388d15c3d7935818c`\n",
            1,
        ).replace(old_completion, new_completion, 1)
        if mutate_target == "status":
            target_head = target_head.replace("- 状态：待评审", "- 状态：已完成", 1)
        if mutate_target == "extra":
            target_head = target_head.replace("- 类型：数据审计", "- 类型：治理", 1)
        if mutate_target == "record":
            target_head = target_head.replace(
                "最终批次：`批次-20260806T045500Z-v7`",
                "最终批次：`批次-20260806T045500Z-v8`",
                1,
            )
        title = executor_title
        changed_paths = [
            "docs/研发中心/任务/任务-000068.md",
            "docs/研发中心/任务/任务-000066.md",
            "docs/研发中心/看板.md",
        ]
        return {
            "repo_root": REPO_ROOT,
            "base_ref": "HEAD",
            "changed_paths": changed_paths,
            "pr_body": (
                "## 关联任务\n\n- 任务-000068\n\n"
                "## 变更类型\n\n- 任务合同冲突修复\n"
            ),
            "base_tasks": {"000068": executor_base, "000066": target_base},
            "head_tasks": {"000068": executor_head, "000066": target_head},
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
            "base_board": delivery_board(
                head=False,
                task_id="000068",
                title=title,
                dependency="000067",
                pr_number="168",
            ),
            "head_board": delivery_board(
                head=True,
                task_id="000068",
                title=title,
                dependency="000067",
                pr_number="168",
                branch="codex/task-000068-contract-conflict-v1",
            ),
            "path_facts": [self.path_fact(path) for path in changed_paths],
        }

    def test_任务合同冲突修复两步入口正向与越权失败(self):
        inputs = self.contract_conflict_repair_inputs()
        with mock.patch.object(
            self.policy,
            "_derive_contract_repair_delivery_sha",
            return_value="c5a5f838f3c09b352150508388d15c3d7935818c",
        ):
            result = self.policy.evaluate_eligibility(**inputs)
            self.assertTrue(result.eligible, result.reasons)

            migrated = self.contract_conflict_repair_inputs(mutate_target="status")
            result = self.policy.evaluate_eligibility(**migrated)
            self.assertFalse(result.eligible)
            self.assertIn("目标任务-000066基线和头部必须保持待评审", result.reasons)

            extra = self.contract_conflict_repair_inputs(mutate_target="extra")
            result = self.policy.evaluate_eligibility(**extra)
            self.assertFalse(result.eligible)
            self.assertIn("任务-000066合同修复夹带两项字段以外的改写", result.reasons)

            record = self.contract_conflict_repair_inputs(mutate_target="record")
            result = self.policy.evaluate_eligibility(**record)
            self.assertFalse(result.eligible)
            self.assertIn("任务-000066合同修复夹带两项字段以外的改写", result.reasons)

    def test_任务116基线补齐映射固定单字段且失败关闭(self):
        target_base = synthetic_task115_pre_execution(
            (REPO_ROOT / "docs/研发中心/任务/任务-000115.md").read_text(
                encoding="utf-8"
            )
        )
        target_head = self.policy._apply_task116_contract_repair(target_base)
        self.assertIsNotNone(target_head)
        executor = task_text(status="已完成", title="建立阶段1合同修订的受控资格路径")
        board = (REPO_ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        inputs = {
            "changed_paths": ["docs/研发中心/任务/任务-000115.md"],
            "pr_body": (
                "## 关联任务\n\n- 任务-000116\n\n"
                "## 变更类型\n\n- 任务合同冲突修复\n"
            ),
            "base_tasks": {"000116": executor, "000115": target_base},
            "head_tasks": {"000116": executor, "000115": target_head},
            "base_board": board,
            "head_board": board,
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
            "repo_root": REPO_ROOT,
            "base_ref": "HEAD",
        }
        inputs["path_facts"] = [self.path_fact(inputs["changed_paths"][0])]
        result = self.policy.evaluate_eligibility(**inputs)
        self.assertTrue(result.eligible, result.reasons)

        drifted = dict(inputs)
        drifted["head_tasks"] = {
            "000116": executor,
            "000115": target_head + "\n- 越权字段：拒绝\n",
        }
        result = self.policy.evaluate_eligibility(**drifted)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000115未按固定单字段规则补齐当前阻塞原因", result.reasons)

    def test_阶段1覆盖受限合同修订固定115到106且拒绝目标状态迁移(self):
        executor_base = synthetic_task115_pre_execution(
            (REPO_ROOT / "docs/研发中心/任务/任务-000115.md").read_text(
                encoding="utf-8"
            )
        )
        executor_head = executor_base.replace(
            "- 状态：待执行", "- 状态：待评审", 1
        )
        executor_head = executor_head.replace(
            "\n\n## 依赖与阻塞条件",
            "\n- 开始时间：`2026-08-15T01:00:00+08:00`\n"
            "- 执行分支：`codex/task-000115-test`\n"
            "- Pull Request：[#999](https://github.com/xk320/zhishi/pull/999)\n"
            "- 实现提交SHA：`0123456789abcdef0123456789abcdef01234567`\n"
            "\n## 依赖与阻塞条件",
            1,
        )
        target_base = synthetic_task106_unrevised(
            (REPO_ROOT / "docs/研发中心/任务/任务-000106.md").read_text(
                encoding="utf-8"
            ),
            self.policy,
        )
        target_head = self.policy._apply_stage1_contract_repair(target_base)
        self.assertIsNotNone(target_head)
        board = (REPO_ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        # 任务116完成后会从真实看板的待评审分区移除；本测试需要固定的
        # 阶段1基线，因此显式合成一条与当前状态无关的待评审行。
        board = re.sub(
            r"(?m)^\|\s*(?:P[0-3]\s*\|\s*)?任务-000116\s*\|[^\n]*\n",
            "",
            board,
        )
        synthetic_task116_row = (
            "| P0 | 任务-000116 | 建立阶段1合同修订的受控资格路径 | "
            "`codex/task-000116-fixture-base` | "
            "[#998](https://github.com/xk320/zhishi/pull/998) |\n"
        )
        board = board.replace(
            "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
            "| --- | --- | --- | --- | --- |\n",
            "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
            "| --- | --- | --- | --- | --- |\n"
            + synthetic_task116_row,
            1,
        )
        # 任务115真实执行后会出现在执行中；阶段1基线固定为待执行四列表。
        board = re.sub(
            r"(?m)^\| P0 \| 任务-000115 \|[^\n]*\n",
            "",
            board,
        )
        base_task115_row = (
            "| P0 | 任务-000115 | 将阶段1成本证据门改为覆盖受限模式 | 000105 |\n"
        )
        board = board.replace(
            "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
            "| --- | --- | --- | --- |\n",
            "| 优先级 | 任务 | 名称 | 唯一前序依赖 |\n"
            "| --- | --- | --- | --- |\n"
            + base_task115_row,
            1,
        )
        old_row = next(
            line for line in board.splitlines()
            if line.startswith("| P0 | 任务-000115 |")
        )
        title = self.policy._task_field(
            self.policy.TASK_TITLE_PATTERN, executor_base
        )
        head_row = (
            f"| P0 | 任务-000115 | {title} | `codex/task-000115-test` | "
            "[#999](https://github.com/xk320/zhishi/pull/999) |"
        )
        head_board = board.replace(old_row + "\n", "", 1)
        current_review_row = next(
            line for line in head_board.splitlines()
            if line.startswith("| P0 | 任务-000116 |")
        )
        head_board = head_board.replace(
            current_review_row + "\n",
            current_review_row + "\n" + head_row + "\n",
            1,
        )
        paths = [
            "docs/研发中心/任务/任务-000115.md",
            "docs/研发中心/任务/任务-000106.md",
            "docs/研发中心/看板.md",
        ]
        inputs = {
            "changed_paths": paths,
            "pr_body": (
                "## 关联任务\n\n- 任务-000115\n\n"
                "## 变更类型\n\n- 阶段1覆盖受限合同修订\n"
            ),
            "base_tasks": {
                "000115": executor_base,
                "000106": target_base,
                "000116": task_text(status="已完成"),
            },
            "head_tasks": {
                "000115": executor_head,
                "000106": target_head,
                "000116": task_text(status="已完成"),
            },
            "base_board": board,
            "head_board": head_board,
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
        }
        inputs["path_facts"] = [self.path_fact(path) for path in paths]
        result = self.policy.evaluate_eligibility(**inputs)
        self.assertTrue(result.eligible, result.reasons)

        governance_pending = dict(inputs)
        governance_pending["base_tasks"] = {
            **inputs["base_tasks"],
            "000116": task_text(status="待评审"),
        }
        result = self.policy.evaluate_eligibility(**governance_pending)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000116基线状态必须为已完成", result.reasons)

        extra_workflow = dict(inputs)
        extra_workflow["changed_paths"] = paths + [
            ".github/workflows/pr-auto-merge.yml"
        ]
        extra_workflow["path_facts"] = [
            self.path_fact(path) for path in extra_workflow["changed_paths"]
        ]
        result = self.policy.evaluate_eligibility(**extra_workflow)
        self.assertFalse(result.eligible)
        self.assertIn(
            "阶段1覆盖受限合同修订变更路径“.github/workflows/pr-auto-merge.yml”不允许自动合并",
            result.reasons,
        )

        mismatched_metadata = dict(inputs)
        mismatched_metadata["head_ref_name"] = "codex/other-branch"
        mismatched_metadata["pr_number"] = 325
        result = self.policy.evaluate_eligibility(**mismatched_metadata)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000115执行分支与PR头部事实不一致", result.reasons)

        migrated = dict(inputs)
        migrated["head_tasks"] = {
            "000115": executor_head,
            "000106": target_head.replace("- 状态：阻塞", "- 状态：待执行", 1),
            "000116": task_text(status="已完成"),
        }
        result = self.policy.evaluate_eligibility(**migrated)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000106基线和头部必须保持阻塞", result.reasons)

        drifted = dict(inputs)
        drifted["head_tasks"] = {
            "000115": executor_head,
            "000106": target_head.replace("禁止跨标的补偿", "允许跨标的补偿", 1),
            "000116": task_text(status="已完成"),
        }
        result = self.policy.evaluate_eligibility(**drifted)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000106未按固定覆盖受限章节修订且合同指纹漂移", result.reasons)

    def test_阻塞任务合同修复只允许单字段目标映射(self):
        result = self.evaluate_blocked_repair()
        self.assertTrue(result.eligible, result.reasons)

        existing_contract = self.blocked_repair_inputs()
        result = self.policy.evaluate_eligibility(**existing_contract)
        self.assertTrue(result.eligible, result.reasons)

        legacy_contract = self.blocked_repair_inputs(
            base_tasks={
                "000056": blocked_contract_repair_executor_text(
                    status="待执行", blocker_evidence="任务-000055当前阻塞合同"
                ),
                "000055": blocked_contract_repair_target_text(),
            },
            head_tasks={
                "000056": blocked_contract_repair_executor_text(
                    status="待评审", blocker_evidence="任务-000055当前阻塞合同"
                ),
                "000055": blocked_contract_repair_target_text(authorized=True),
            },
        )
        result = self.policy.evaluate_eligibility(**legacy_contract)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000056合同未证明任务-000055唯一目标", result.reasons)

        missing_blocker_evidence = self.blocked_repair_inputs(
            base_tasks={
                "000056": blocked_contract_repair_executor_text(
                    status="待执行", blocker_evidence="未指定阻塞对象"
                ),
                "000055": blocked_contract_repair_target_text(),
            },
            head_tasks={
                "000056": blocked_contract_repair_executor_text(
                    status="待评审", blocker_evidence="未指定阻塞对象"
                ),
                "000055": blocked_contract_repair_target_text(authorized=True),
            },
        )
        result = self.policy.evaluate_eligibility(**missing_blocker_evidence)
        self.assertFalse(result.eligible)
        self.assertIn("任务-000056合同未证明任务-000055唯一目标", result.reasons)

        blocked_executor = self.blocked_repair_inputs(
            base_tasks={
                "000056": blocked_contract_repair_executor_text(status="阻塞"),
                "000055": blocked_contract_repair_target_text(),
            }
        )
        result = self.policy.evaluate_eligibility(**blocked_executor)
        self.assertFalse(result.eligible)
        self.assertIn(
            "任务-000056基线状态“阻塞”不可进入任务交付",
            result.reasons,
        )

        wrong_target = self.blocked_repair_inputs(
            head_tasks={
                "000056": blocked_contract_repair_executor_text(status="待评审"),
                "000055": blocked_contract_repair_target_text(),
                "000054": blocked_contract_repair_target_text(authorized=True),
            },
            changed_paths=self.blocked_repair_inputs()["changed_paths"]
            + ["docs/研发中心/任务/任务-000054.md"],
        )
        result = self.policy.evaluate_eligibility(**wrong_target)
        self.assertFalse(result.eligible)
        self.assertTrue(
            any("阻塞任务合同修复包含不允许路径" in reason for reason in result.reasons),
            result.reasons,
        )

        multi_field = self.blocked_repair_inputs(
            head_tasks={
                "000056": blocked_contract_repair_executor_text(status="待评审"),
                "000055": blocked_contract_repair_target_text(authorized=True).replace(
                    "- 类型：治理", "- 类型：文档", 1
                ),
            }
        )
        result = self.policy.evaluate_eligibility(**multi_field)
        self.assertFalse(result.eligible)
        self.assertIn("目标任务-000055合同修复夹带其他字段改写", result.reasons)

        migrated = self.blocked_repair_inputs(
            head_tasks={
                "000056": blocked_contract_repair_executor_text(status="待评审"),
                "000055": blocked_contract_repair_target_text(authorized=True).replace(
                    "- 状态：阻塞", "- 状态：待执行", 1
                ),
            }
        )
        result = self.policy.evaluate_eligibility(**migrated)
        self.assertFalse(result.eligible)
        self.assertIn("目标任务-000055状态不得在合同修复中迁移", result.reasons)

    def test_阻塞任务合同修复拒绝未知变更类型和高风险路径(self):
        unknown = self.blocked_repair_inputs(
            pr_body=(
                "## 关联任务\n\n- 任务-000056\n\n"
                "## 变更类型\n\n- 任务交付\n"
            )
        )
        result = self.policy.evaluate_eligibility(**unknown)
        self.assertFalse(result.eligible)

        unsafe = self.blocked_repair_inputs(
            changed_paths=self.blocked_repair_inputs()["changed_paths"]
            + ["src/交易/订单.py"]
        )
        result = self.evaluate_blocked_repair(**unsafe)
        self.assertFalse(result.eligible)
        self.assertTrue(
            any("不允许路径" in reason for reason in result.reasons),
            result.reasons,
        )

    def test_任务交付必须验证看板模式和唯一映射(self):
        changed_paths = [
            "docs/研发中心/任务/任务-000013.md",
            "docs/研发中心/看板.md",
        ]
        legacy_board = delivery_board(head=True).replace(
            "| 优先级 | 任务 | 名称 | 分支 | PR |",
            "| 优先级 | 任务 | 名称 | 分支 | Pull Request |",
            1,
        )
        result = self.evaluate(
            changed_paths=changed_paths,
            head_board=legacy_board,
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务交付看板不是唯一可复算映射", result.reasons)

        result = self.evaluate(
            changed_paths=["docs/研发中心/任务/任务-000013.md"],
            enforce_board_sync=True,
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务交付必须同步看板", result.reasons)

        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            head_board=delivery_board(head=True, branch="wrong-branch"),
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务交付看板不是唯一可复算映射", result.reasons)

    def test_需修复任务可以在看板校验后进入待评审(self):
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            base_tasks={
                "000013": task_text(
                    status="需修复", dependency="000012", pr_number="40"
                )
            },
            head_tasks={
                "000013": task_text(
                    status="待评审", dependency="000012", pr_number="40"
                )
            },
            base_board=delivery_board(head=False, base_status="需修复"),
            head_board=delivery_board(head=True),
        )
        self.assertTrue(result.eligible, result.reasons)

        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            base_tasks={
                "000013": task_text(
                    status="需修复", dependency="000012", pr_number="40"
                )
            },
            head_tasks={
                "000013": task_text(
                    status="待评审", dependency="000012", pr_number="40"
                )
            },
            base_board=delivery_board(
                head=False, base_status="需修复", branch="wrong-branch"
            ),
            head_board=delivery_board(head=True),
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务交付看板不是唯一可复算映射", result.reasons)

    def test_缺少路径事实时失败关闭(self):
        result = self.evaluate(path_facts=None)

        self.assertFalse(result.eligible)
        self.assertIn("PR缺少可验证的路径事实", result.reasons)

    def test_路径事实必须与变更路径完全一致且不重复(self):
        changed_paths = [
            "docs/治理/PR自动合并策略.md",
            "docs/研发中心/任务/任务-000013.md",
        ]
        cases = (
            [self.path_fact(changed_paths[0])],
            [
                self.path_fact(changed_paths[0]),
                self.path_fact(changed_paths[0]),
                self.path_fact(changed_paths[1]),
            ],
            [
                self.path_fact(changed_paths[0]),
                self.path_fact(changed_paths[1]),
                self.path_fact("docs/治理/额外.md"),
            ],
        )

        for path_facts in cases:
            with self.subTest(path_facts=path_facts):
                result = self.evaluate(
                    changed_paths=changed_paths,
                    path_facts=path_facts,
                )
                self.assertFalse(result.eligible)
                self.assertIn("路径事实与变更路径不一致", result.reasons)

    def test_只允许普通文件新增或修改(self):
        invalid_facts = (
            self.path_fact("docs/治理/PR自动合并策略.md", status="D"),
            self.path_fact("docs/治理/PR自动合并策略.md", status="R"),
            self.path_fact("docs/治理/PR自动合并策略.md", mode="120000"),
            self.path_fact("docs/治理/PR自动合并策略.md", mode="160000"),
            self.path_fact("docs/治理/PR自动合并策略.md", mode="100755"),
            self.path_fact(
                "docs/治理/PR自动合并策略.md", object_type="tree"
            ),
            self.path_fact("docs/治理/PR自动合并策略.md", size=-1),
        )

        for invalid_fact in invalid_facts:
            with self.subTest(invalid_fact=invalid_fact):
                result = self.evaluate(
                    path_facts=[
                        invalid_fact,
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ]
                )
                self.assertFalse(result.eligible)
                self.assertIn("路径事实不允许自动合并", result.reasons)

        for status in ("A", "M"):
            with self.subTest(status=status):
                result = self.evaluate(
                    path_facts=[
                        self.path_fact(
                            "docs/治理/PR自动合并策略.md",
                            status=status,
                        ),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ]
                )
                self.assertTrue(result.eligible, result.reasons)

    def test_所有允许的文本对象必须有可扫描文本(self):
        result = self.evaluate(
            path_facts=[
                self.path_fact(
                    "docs/治理/PR自动合并策略.md",
                    text=None,
                ),
                self.path_fact("docs/研发中心/任务/任务-000013.md"),
            ]
        )

        self.assertFalse(result.eligible)
        self.assertIn("路径事实缺少可扫描文本", result.reasons)

    def test_文件数上限500恰好允许且加一拒绝(self):
        for count, expected in ((500, True), (501, False)):
            changed_paths = [
                "docs/研发中心/任务/任务-000013.md",
                *(f"docs/治理/资源-{index:03d}.md" for index in range(count - 1)),
            ]
            with self.subTest(count=count):
                result = self.evaluate(changed_paths=changed_paths)
                self.assertEqual(expected, result.eligible, result.reasons)
                if not expected:
                    self.assertIn("变更文件数超过500", result.reasons)

    def test_单文件5MiB恰好允许且加一拒绝(self):
        limit = 5 * 1024 * 1024
        for size, expected in ((limit, True), (limit + 1, False)):
            with self.subTest(size=size):
                result = self.evaluate(
                    path_facts=[
                        self.path_fact(
                            "docs/治理/PR自动合并策略.md",
                            size=size,
                        ),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ]
                )
                self.assertEqual(expected, result.eligible, result.reasons)
                if not expected:
                    self.assertIn("单个文件超过5MiB", result.reasons)

    def test_总量25MiB恰好允许且加一拒绝(self):
        limit = 5 * 1024 * 1024
        changed_paths = [
            "docs/研发中心/任务/任务-000013.md",
            *(f"docs/治理/大文件-{index}.md" for index in range(5)),
        ]
        for extra_size, expected in ((0, True), (1, False)):
            with self.subTest(extra_size=extra_size):
                result = self.evaluate(
                    changed_paths=changed_paths,
                    path_facts=[
                        self.path_fact(changed_paths[0], size=extra_size),
                        *(
                            self.path_fact(path, size=limit)
                            for path in changed_paths[1:]
                        ),
                    ],
                )
                self.assertEqual(expected, result.eligible, result.reasons)
                if not expected:
                    self.assertIn("变更总量超过25MiB", result.reasons)

    def test_敏感内容全部拒绝且原因不回显正文(self):
        sensitive_values = (
            "-----BEGIN " + "PRIVATE KEY-----",
            "ssh ubuntu " + "192" + ".168.31.201",
            "g" + "hp_" + "a" * 36,
            "github_" + "pat_" + "a" * 82,
            "A" + "KIA" + "1" * 16,
            "pass" + "word = hunter2",
            "pass" + "wd: hunter2",
            "sec" + "ret='hunter2'",
            "to" + "ken: hunter2",
        )

        for sensitive_value in sensitive_values:
            with self.subTest(kind=sensitive_value[:8]):
                result = self.evaluate(
                    path_facts=[
                        self.path_fact(
                            "docs/治理/PR自动合并策略.md",
                            text=sensitive_value,
                        ),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ]
                )
                self.assertFalse(result.eligible)
                self.assertIn("变更文本包含敏感内容", result.reasons)
                self.assertNotIn(sensitive_value, "\n".join(result.reasons))

    def test_受控研发任务类型可修改受控源码路径(self):
        allowed_types = (
            "数据治理",
            "数据审计",
            "数据工程",
            "基础设施验证",
            "策略研究",
            "研究工程",
            "模拟交易",
            "测试",
            "工具",
        )

        for task_type in allowed_types:
            with self.subTest(task_type=task_type):
                result = self.evaluate(
                    changed_paths=[
                        "src/策略/信号.py",
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type=task_type,
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type=task_type,
                        )
                    },
                )

                self.assertTrue(result.eligible, result.reasons)

    def test_pr44数据治理九条精确路径可自动合并(self):
        changed_paths = [
            (
                "artifacts/数据/来源身份/"
                "source-identity-20260803T131620+0800-e7bc65038f21/"
                "来源身份清单.csv"
            ),
            (
                "artifacts/数据/来源身份/"
                "source-identity-20260803T131620+0800-e7bc65038f21/"
                "身份清单.json"
            ),
            "config/数据/数据来源与资产身份.json",
            "docs/数据/数据来源与资产身份合同.md",
            "docs/研发中心/任务/任务-000029.md",
            "docs/研发中心/看板.md",
            "scripts/数据/冻结数据来源身份.py",
            "tests/数据/test_冻结数据来源身份.py",
            "tests/研发中心/test_项目范围与阶段状态.py",
        ]
        result = self.evaluate(
            changed_paths=changed_paths,
            pr_body=(
                "## 关联任务\n\n"
                "- 任务-000029\n\n"
                "## 变更类型\n\n"
                "- 任务交付\n"
            ),
            base_tasks={
                "000029": task_text(
                    status="待执行",
                    task_type="数据治理",
                    dependency="000028",
                    title="冻结数据来源与资产身份合同",
                    pr_number="44",
                )
            },
            head_tasks={
                "000029": task_text(
                    status="待评审",
                    task_type="数据治理",
                    dependency="000028",
                    title="冻结数据来源与资产身份合同",
                    pr_number="44",
                )
            },
            base_board=delivery_board(
                head=False,
                task_id="000029",
                title="冻结数据来源与资产身份合同",
                priority="P1",
                dependency="000028",
                pr_number="44",
            ),
            head_board=delivery_board(
                head=True,
                task_id="000029",
                title="冻结数据来源与资产身份合同",
                priority="P1",
                dependency="000028",
                pr_number="44",
            ),
            path_facts=[
                self.path_fact(
                    path,
                    status="A" if path.startswith("artifacts/") else "M",
                )
                for path in changed_paths
            ],
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_受控研发路径只允许指定根目录和扩展名(self):
        allowed_paths = (
            "docs/研究/合同.md",
            "config/研究/参数.json",
            "config/研究/参数.yaml",
            "config/研究/参数.yml",
            "config/研究/参数.toml",
            "src/研究/信号.py",
            "src/研究/信号.js",
            "src/研究/信号.jsx",
            "src/研究/信号.ts",
            "src/研究/信号.tsx",
            "src/研究/定义.json",
            "scripts/数据/冻结.py",
            "scripts/数据/冻结.sh",
            "tests/研究/test_信号.py",
            "tests/研究/信号.test.js",
            "tests/研究/信号.test.jsx",
            "tests/研究/信号.test.ts",
            "tests/研究/信号.test.tsx",
            "tests/研究/用例.json",
            "artifacts/研究/结果.json",
            "artifacts/研究/结果.csv",
            "artifacts/研究/结果.md",
        )

        for allowed_path in allowed_paths:
            with self.subTest(path=allowed_path):
                result = self.evaluate(
                    changed_paths=[
                        allowed_path,
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type="数据工程",
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type="数据工程",
                        )
                    },
                    path_facts=[
                        self.path_fact(
                            allowed_path,
                            status=(
                                "A" if allowed_path.startswith("artifacts/") else "M"
                            ),
                        ),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ],
                )

                self.assertTrue(result.eligible, result.reasons)

    def test_高风险和未知任务类型不能获得受控研发资格(self):
        rejected_types = (
            "真实交易",
            "资金管理",
            "生产运维",
            "凭据管理",
            "未知",
        )

        for task_type in rejected_types:
            with self.subTest(task_type=task_type):
                result = self.evaluate(
                    changed_paths=[
                        "src/策略/信号.py",
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type=task_type,
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type=task_type,
                        )
                    },
                )

                self.assertFalse(result.eligible)
                self.assertIn(
                    f"任务-000013类型“{task_type}”不允许自动合并",
                    result.reasons,
                )

    def test_受控研发拒绝越权路径和非法扩展名(self):
        rejected_paths = (
            ".github/workflows/部署.yml",
            "deploy/production.sh",
            "secrets/account.env",
            "artifacts/数据/cache.db",
            "artifacts/模型/model.pt",
            "artifacts/归档/source.zip",
            "artifacts/媒体/chart.png",
        )

        for rejected_path in rejected_paths:
            with self.subTest(path=rejected_path):
                result = self.evaluate(
                    changed_paths=[
                        rejected_path,
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type="数据治理",
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type="数据治理",
                        )
                    },
                )

                self.assertFalse(result.eligible)
                self.assertIn(
                    f"变更路径“{rejected_path}”不允许自动合并",
                    result.reasons,
                )

    def test_受控研发拒绝交易部署和生产脚本目录(self):
        for rejected_path in (
            "scripts/交易/下单.py",
            "scripts/部署/release.sh",
            "scripts/生产/迁移.py",
            "scripts/生产环境/deploy.py",
            "scripts/deploy.py",
            "scripts/order.py",
            "scripts/真实交易.py",
            "config/生产/production.yaml",
            "config/production.yaml",
            "src/生产/runner.py",
            "artifacts/账户/真实账户.json",
            "artifacts/数据/数据库导出.csv",
        ):
            with self.subTest(path=rejected_path):
                result = self.evaluate(
                    changed_paths=[
                        rejected_path,
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type="模拟交易",
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type="模拟交易",
                        )
                    },
                )

                self.assertFalse(result.eligible)
                self.assertIn(
                    f"变更路径“{rejected_path}”不允许自动合并",
                    result.reasons,
                )

    def test_受控研发允许根目录已批准Markdown(self):
        result = self.evaluate(
            changed_paths=[
                "README.md",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(status="待执行", task_type="策略研究")
            },
            head_tasks={
                "000013": task_text(status="待评审", task_type="策略研究")
            },
        )
        self.assertTrue(result.eligible, result.reasons)

    def test_受控研发拒绝二进制控制字符(self):
        for value in ("\x00", "\u0085", "\u009f"):
            with self.subTest(value=repr(value)):
                result = self.evaluate(
                    changed_paths=[
                        "src/研究/信号.py",
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(status="待执行", task_type="研究工程")
                    },
                    head_tasks={
                        "000013": task_text(status="待评审", task_type="研究工程")
                    },
                    path_facts=[
                        self.path_fact("src/研究/信号.py", text=value),
                        self.path_fact("docs/研发中心/任务/任务-000013.md"),
                    ],
                )
                self.assertFalse(result.eligible)
                self.assertIn("变更文本不是安全文本", result.reasons)

    def test_不可变证据产物不得修改(self):
        result = self.evaluate(
            changed_paths=[
                "artifacts/研究/结果.json",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(status="待执行", task_type="数据治理")
            },
            head_tasks={
                "000013": task_text(status="待评审", task_type="数据治理")
            },
            path_facts=[
                self.path_fact("artifacts/研究/结果.json", status="M"),
                self.path_fact("docs/研发中心/任务/任务-000013.md"),
            ],
        )
        self.assertFalse(result.eligible)
        self.assertIn("不可变证据产物必须新增且不得修改", result.reasons)

    def test_受控研发拒绝真实账户标识和网络目标正文(self):
        for text in (
            "account" + "_id: real-123",
            "endpoint" + ": https://production.example.invalid/api",
            "url" + ": https://production.example.invalid/api",
            "rpc_url" + ": https://production.example.invalid/ws",
        ):
            with self.subTest(text=text):
                result = self.evaluate(
                    changed_paths=[
                        "config/研究/参数.yaml",
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行", task_type="数据治理"
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审", task_type="数据治理"
                        )
                    },
                    path_facts=[
                        self.path_fact("config/研究/参数.yaml", text=text),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ],
                )
                self.assertFalse(result.eligible)
                self.assertIn("变更文本包含敏感内容", result.reasons)

    def test_受控研发拒绝路径越界与非法路径形式(self):
        rejected_paths = (
            "scripts/研究/部署/release.sh",
            "scripts/研究/生产/migrate.py",
            "scripts/模拟/交易/order.py",
            "scripts/模拟/交易所/order.py",
            "/src/研究/信号.py",
            "src/研究/./信号.py",
            "src/研究/../信号.py",
            "artifacts/研究/result.json.gz",
        )

        for rejected_path in rejected_paths:
            with self.subTest(path=rejected_path):
                result = self.evaluate(
                    changed_paths=[
                        rejected_path,
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type="研究工程",
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type="研究工程",
                        )
                    },
                )

                self.assertFalse(result.eligible)
                self.assertIn(
                    f"变更路径“{rejected_path}”不允许自动合并",
                    result.reasons,
                )

    def test_受控研发扩展名大小写不敏感且只看最后后缀(self):
        allowed_paths = (
            "docs/研究/合同.MD",
            "config/研究/参数.YAML",
            "src/研究/信号.PY",
            "scripts/研究/冻结.SH",
            "tests/研究/信号.TSX",
            "artifacts/研究/结果.CSV",
            "artifacts/研究/result.tar.JSON",
            "scripts/研究/部署工具/release.sh",
            "scripts/研究/生产者/migrate.py",
        )

        for allowed_path in allowed_paths:
            with self.subTest(path=allowed_path):
                result = self.evaluate(
                    changed_paths=[
                        allowed_path,
                        "docs/研发中心/任务/任务-000013.md",
                    ],
                    base_tasks={
                        "000013": task_text(
                            status="待执行",
                            task_type="研究工程",
                        )
                    },
                    head_tasks={
                        "000013": task_text(
                            status="待评审",
                            task_type="研究工程",
                        )
                    },
                    path_facts=[
                        self.path_fact(
                            allowed_path,
                            status=(
                                "A" if allowed_path.startswith("artifacts/") else "M"
                            ),
                        ),
                        self.path_fact(
                            "docs/研发中心/任务/任务-000013.md"
                        ),
                    ],
                )

                self.assertTrue(result.eligible, result.reasons)

    def test_任务交付只允许一个任务(self):
        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 任务交付\n"
        )
        changed_paths = [
            "src/策略/信号.py",
            "docs/研发中心/任务/任务-000013.md",
            "docs/研发中心/任务/任务-000014.md",
        ]
        result = self.evaluate(
            changed_paths=changed_paths,
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待执行", task_type="数据治理"),
                "000014": task_text(status="待执行", task_type="治理"),
            },
            head_tasks={
                "000013": task_text(status="待评审", task_type="数据治理"),
                "000014": task_text(status="待评审", task_type="治理"),
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“src/策略/信号.py”不允许自动合并",
            result.reasons,
        )

        result = self.evaluate(
            changed_paths=changed_paths,
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待执行", task_type="数据治理"),
                "000014": task_text(status="待执行", task_type="测试"),
            },
            head_tasks={
                "000013": task_text(status="待评审", task_type="数据治理"),
                "000014": task_text(status="待评审", task_type="测试"),
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务交付最多关联1个任务", result.reasons)

    def test_多任务治理自动化授权必须来自全部基线任务(self):
        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 任务交付\n"
        )
        result = self.evaluate(
            changed_paths=[
                ".github/workflows/pr-auto-merge.yml",
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(
                    status="待执行",
                    automation_scope=True,
                ),
                "000014": task_text(status="待执行"),
            },
            head_tasks={
                "000013": task_text(
                    status="待评审",
                    automation_scope=True,
                ),
                "000014": task_text(status="待评审"),
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“.github/workflows/pr-auto-merge.yml”不允许自动合并",
            result.reasons,
        )

    def test_治理自动化授权不允许第三个工作流(self):
        result = self.evaluate(
            changed_paths=[
                ".github/workflows/部署.yml",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(
                    status="待执行",
                    automation_scope=True,
                )
            },
            head_tasks={
                "000013": task_text(
                    status="待评审",
                    automation_scope=True,
                )
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“.github/workflows/部署.yml”不允许自动合并",
            result.reasons,
        )

    def test_缺少任务编号时拒绝(self):
        result = self.evaluate(
            pr_body="## 变更类型\n\n- 任务交付\n\n仅包含变更说明"
        )

        self.assertFalse(result.eligible)
        self.assertIn("PR正文未引用任务编号", result.reasons)

    def test_只解析严格关联任务区段(self):
        result = self.evaluate(
            pr_body=(
                "## 关联任务\n\n"
                "- 任务-000013（任务交付）\n\n"
                "## 已知限制\n\n"
                "任务-000014尚未执行。\n\n"
                "## 变更类型\n\n"
                "- 任务交付\n"
            )
        )

        self.assertTrue(result.eligible)
        self.assertNotIn("任务-000014未在基线main中登记", result.reasons)

    def test_缺少严格变更类型时拒绝(self):
        result = self.evaluate(
            pr_body="## 关联任务\n\n- 任务-000013\n"
        )

        self.assertFalse(result.eligible)
        self.assertIn("PR正文缺少有效变更类型", result.reasons)

    def test_基线任务类型缺失时拒绝(self):
        result = self.evaluate(
            base_tasks={"000013": task_text(status="待执行", task_type=None)}
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013缺少任务类型", result.reasons)

    def test_pr不能通过修改任务类型获得资格(self):
        result = self.evaluate(
            base_tasks={"000013": task_text(status="待执行", task_type="工程")},
            head_tasks={"000013": task_text(status="待评审", task_type="治理")},
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013类型“工程”不允许自动合并", result.reasons)

    def test_修改工作流时拒绝(self):
        result = self.evaluate(
            changed_paths=[
                ".github/workflows/pr-auto-merge.yml",
                "docs/研发中心/任务/任务-000013.md",
            ]
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“.github/workflows/pr-auto-merge.yml”不允许自动合并",
            result.reasons,
        )

    def test_普通受控研发不能修改可信研发中心脚本(self):
        result = self.evaluate(
            changed_paths=[
                "scripts/研发中心/验证自动合并资格.py",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(status="待执行", task_type="工具")
            },
            head_tasks={
                "000013": task_text(status="待评审", task_type="工具")
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“scripts/研发中心/验证自动合并资格.py”不允许自动合并",
            result.reasons,
        )

    def test_普通任务不能修改看板机器合同而治理自动化可以(self):
        changed_paths = [
            "docs/研发中心/任务看板模式.md",
            "docs/研发中心/看板.md",
            "docs/研发中心/任务/任务-000013.md",
        ]
        result = self.evaluate(changed_paths=changed_paths)
        self.assertFalse(result.eligible)
        self.assertIn(
            "变更路径“docs/研发中心/任务看板模式.md”不允许自动合并",
            result.reasons,
        )

        result = self.evaluate(
            changed_paths=changed_paths,
            base_tasks={
                "000013": task_text(
                    status="待执行", dependency="000012", automation_scope=True
                )
            },
            head_tasks={
                "000013": task_text(
                    status="待评审", dependency="000012", automation_scope=True
                )
            },
        )
        self.assertTrue(result.eligible, result.reasons)

    def test_基线明确授权的治理自动化可修改受限自动化路径(self):
        result = self.evaluate(
            changed_paths=[
                ".github/workflows/pr-auto-merge.yml",
                "scripts/研发中心/验证自动合并资格.py",
                "tests/研发中心/test_验证自动合并资格.py",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(
                    status="待执行",
                    automation_scope=True,
                )
            },
            head_tasks={
                "000013": task_text(
                    status="待评审",
                    automation_scope=True,
                )
            },
        )

        self.assertTrue(result.eligible)

    def test_已完成治理自动化任务不能重放控制面授权(self):
        result = self.evaluate(
            changed_paths=[
                ".github/workflows/pr-auto-merge.yml",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(status="已完成", automation_scope=True)
            },
            head_tasks={
                "000013": task_text(status="待评审", automation_scope=True)
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013基线状态“已完成”不可进入任务交付", result.reasons)

    def test_治理自动化授权不能扩大到任意脚本(self):
        result = self.evaluate(
            changed_paths=[
                "scripts/交易/下单.py",
                "docs/研发中心/任务/任务-000013.md",
            ],
            base_tasks={
                "000013": task_text(status="执行中", automation_scope=True)
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("变更路径“scripts/交易/下单.py”不允许自动合并", result.reasons)

    def test_合并后状态闭环允许固定两类状态迁移(self):
        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审", task_type="工程"),
                "000014": task_text(
                    status="阻塞", task_type="数据治理", dependency="000013"
                ),
            },
            head_tasks={
                "000013": task_text(status="已完成", task_type="工程"),
                "000014": task_text(
                    status="待执行", task_type="数据治理", dependency="000013"
                ),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=closure_board(completed=True),
        )

        self.assertTrue(result.eligible)

    def test_合并后状态闭环允许有证据取消未完成任务(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待执行", dependency="000012"),
                "000014": task_text(status="已完成"),
            },
            head_tasks={
                "000013": cancellation_task_text(),
                "000014": task_text(status="已完成"),
            },
            merge_facts={
                "000014": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=41,
                )
            },
            base_board=cancellation_board(canceled=False),
            head_board=cancellation_board(canceled=True),
        )
        self.assertTrue(result.eligible, result.reasons)

    def test_取消状态闭环拒绝缺失替代合并事实(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待执行", dependency="000012"),
                "000014": task_text(status="已完成"),
            },
            head_tasks={
                "000013": cancellation_task_text(),
                "000014": task_text(status="已完成"),
            },
            merge_facts={},
            base_board=cancellation_board(canceled=False),
            head_board=cancellation_board(canceled=True),
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务-000013取消依据合并事实与main不一致", result.reasons)

    def test_取消状态闭环拒绝已完成任务(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="已完成", dependency="000012"),
                "000014": task_text(status="已完成"),
            },
            head_tasks={
                "000013": cancellation_task_text(),
                "000014": task_text(status="已完成"),
            },
            merge_facts={
                "000014": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=41,
                )
            },
            base_board=cancellation_board(canceled=False),
            head_board=cancellation_board(canceled=True),
        )
        self.assertFalse(result.eligible)
        self.assertIn("任务-000013存在非法状态闭环“已完成→已取消”", result.reasons)

    def test_合并后状态闭环允许待执行任务记录脱敏阻塞(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        base_task = task_text(
            status="待执行", task_type="数据审计", dependency="000012"
        )
        head_task = task_text(
            status="阻塞", task_type="数据审计", dependency="000012",
            extra_contract=(
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n\n"
                "## 执行记录\n\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n"
                "- 尝试命令：`ssh ubuntu printf ready`\n"
                "- 结果：目标不可达，未生成批次。\n"
                "- 外部证据：SSH返回Host is down。\n"
                "- 阻塞原因：获批目标当前不可达。\n"
                "- 解除条件：目标恢复后重新执行。\n"
                "- 数据与安全：未读取或修改远端数据。\n"
            ),
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_合并后状态闭环允许首次补齐同章节唯一解除条件(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        base_task = task_text(
            status="待执行", task_type="数据审计", dependency=None
        ).replace("- 执行分支：`branch`\n", "") + (
            "\n## 依赖与阻塞条件\n\n"
            "- 唯一前序依赖：任务-000012；\n"
            "- 当前阻塞原因：无；公开补证可执行。\n"
        )
        head_task = (
            base_task.replace("- 状态：待执行", "- 状态：阻塞", 1)
            .replace(
                "- 优先级：P1\n",
                "- 优先级：P1\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n",
                1,
            )
            .replace(
                "- 当前阻塞原因：无；公开补证可执行。\n",
                "- 当前阻塞原因：任务-000012尚未完成。\n"
                "- 解除条件：任务-000012完成后重新执行。\n",
                1,
            )
            + (
                "\n## 执行记录\n\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n"
                "- 尝试命令：`ssh ubuntu printf ready`\n"
                "- 结果：目标不可达，未生成批次。\n"
                "- 外部证据：只读探针失败。\n"
                "- 阻塞原因：任务-000012尚未完成。\n"
                "- 解除条件：任务-000012完成后重新执行。\n"
                "- 数据与安全：未读取或修改远端数据。\n"
            )
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_合并后状态闭环拒绝首次补齐多个解除条件(self):
        base_task, head_task = self._首次补齐解除条件任务对()
        head_task = head_task.replace(
            "- 解除条件：任务-000012完成后重新执行。\n",
            "- 解除条件：条件一。\n- 解除条件：条件二。\n",
            1,
        )
        result = self._评估首次补齐解除条件(base_task, head_task)

        self.assertFalse(result.eligible)
        self.assertIn("阻塞状态闭环字段位置无效", result.reasons)

    def test_合并后状态闭环拒绝首次补齐空解除条件(self):
        base_task, head_task = self._首次补齐解除条件任务对()
        head_task = head_task.replace(
            "- 解除条件：任务-000012完成后重新执行。\n",
            "- 解除条件：\n",
            1,
        )
        result = self._评估首次补齐解除条件(base_task, head_task)

        self.assertFalse(result.eligible)
        self.assertIn("阻塞状态闭环字段位置无效", result.reasons)

    def test_合并后状态闭环拒绝已有执行分支被覆盖(self):
        base_task, head_task = self._首次补齐解除条件任务对()
        base_task = base_task.replace(
            "- 优先级：P1\n", "- 优先级：P1\n- 执行分支：`old-branch`\n", 1
        )
        result = self._评估首次补齐解除条件(base_task, head_task)

        self.assertFalse(result.eligible)
        self.assertIn("阻塞状态闭环字段位置无效", result.reasons)

    def test_合并后状态闭环拒绝首次补齐解除条件时改写合同(self):
        base_task, head_task = self._首次补齐解除条件任务对()
        head_task = head_task.replace("- 优先级：P1", "- 优先级：P0", 1)
        result = self._评估首次补齐解除条件(base_task, head_task)

        self.assertFalse(result.eligible)
        self.assertIn("阻塞状态闭环夹带合同改写", result.reasons)

    def _首次补齐解除条件任务对(self):
        base_task = task_text(
            status="待执行", task_type="数据审计", dependency=None
        ).replace("- 执行分支：`branch`\n", "") + (
            "\n## 依赖与阻塞条件\n\n"
            "- 唯一前序依赖：任务-000012；\n"
            "- 当前阻塞原因：无；公开补证可执行。\n"
        )
        head_task = (
            base_task.replace("- 状态：待执行", "- 状态：阻塞", 1)
            .replace(
                "- 优先级：P1\n",
                "- 优先级：P1\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n",
                1,
            )
            .replace(
                "- 当前阻塞原因：无；公开补证可执行。\n",
                "- 当前阻塞原因：任务-000012尚未完成。\n"
                "- 解除条件：任务-000012完成后重新执行。\n",
                1,
            )
            + (
                "\n## 执行记录\n\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n"
                "- 尝试命令：`ssh ubuntu printf ready`\n"
                "- 结果：失败关闭。\n"
                "- 外部证据：只读探针失败。\n"
                "- 阻塞原因：任务-000012尚未完成。\n"
                "- 解除条件：任务-000012完成后重新执行。\n"
                "- 数据与安全：未读取或修改远端数据。\n"
            )
        )
        return base_task, head_task

    def _评估首次补齐解除条件(self, base_task, head_task):
        return self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=(
                "## 关联任务\n\n- 任务-000013\n\n"
                "## 变更类型\n\n- 合并后状态闭环\n"
            ),
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

    def test_合并后状态闭环拒绝已完成任务进入阻塞(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": task_text(status="已完成", dependency="000012")},
            head_tasks={"000013": task_text(status="阻塞", dependency="000012")},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013存在非法状态闭环“已完成→阻塞”", result.reasons)

    def test_合并后状态闭环拒绝首次阻塞覆盖既有执行元数据(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        record = (
            "- 开始时间：`2026-08-04T09:00:00+08:00`\n\n"
            "## 执行记录\n\n"
            "- 执行分支：`branch`\n"
            "- 开始时间：`2026-08-04T09:00:00+08:00`\n"
            "- 尝试命令：`ssh ubuntu printf ready`\n"
            "- 结果：此前未生成批次。\n"
            "- 外部证据：SSH返回Host is down。\n"
            "- 阻塞原因：获批目标不可达。\n"
            "- 解除条件：目标恢复后重新执行。\n"
            "- 数据与安全：未读取或修改远端数据。\n"
        )
        base_task = task_text(
            status="待执行", task_type="数据审计", dependency="000012",
            extra_contract=record,
        )
        head_task = (
            base_task.replace("- 状态：待执行", "- 状态：阻塞", 1)
            .replace("- 当前阻塞原因：无；任务-000012已完成。", "- 当前阻塞原因：获批目标不可达。")
            .replace("- 解除条件：已满足。", "- 解除条件：目标恢复后重新执行。")
            .replace("`branch`", "`rewritten-branch`")
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("阻塞状态闭环夹带合同改写", result.reasons)

    def test_合并后状态闭环拒绝未登记逻辑别名(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        base_task = task_text(
            status="待执行", task_type="数据审计", dependency="000012"
        )
        head_task = task_text(
            status="阻塞", task_type="数据审计", dependency="000012",
            extra_contract=(
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n\n"
                "## 执行记录\n\n"
                "- 执行分支：`branch`\n"
                "- 开始时间：`2026-08-04T10:00:00+08:00`\n"
                "- 尝试命令：`ssh attacker.example.com printf ready`\n"
                "- 结果：目标不可达，未生成批次。\n"
                "- 外部证据：SSH返回Host is down。\n"
                "- 阻塞原因：获批目标当前不可达。\n"
                "- 解除条件：目标恢复后重新执行。\n"
                "- 数据与安全：未读取或修改远端数据。\n"
            ),
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=False),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("阻塞执行记录包含未批准的外部目标", result.reasons)

    def test_合并后状态闭环允许阻塞任务转为需修复(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        execution_record = (
            "- 开始时间：`2026-08-04T10:00:00+08:00`\n\n"
            "## 执行记录\n\n"
            "- 执行分支：`branch`\n"
            "- 开始时间：`2026-08-04T10:00:00+08:00`\n"
            "- 尝试命令：`ssh ubuntu printf ready`\n"
            "- 结果：目标不可达，未生成批次。\n"
            "- 外部证据：SSH返回Host is down。\n"
            "- 阻塞原因：获批目标当前不可达。\n"
            "- 解除条件：目标恢复后重新执行。\n"
            "- 数据与安全：未读取或修改远端数据。\n"
            "\n- Pull Request：[ #40](https://github.com/xk320/zhishi/pull/40)\n"
        ).replace("[ #40]", "[#40]")
        base_task = task_text(
            status="阻塞", task_type="数据审计", dependency="000012",
            extra_contract=execution_record,
        )
        head_task = base_task.replace("- 状态：阻塞", "- 状态：需修复", 1)
        repair_board = (
            "# 看板\n\n"
            "## 待执行\n\n无。\n\n"
            "## 执行中\n\n无。\n\n"
            "## 阻塞\n\n无。\n\n"
            "## 待评审\n\n"
            "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
            "| --- | --- | --- | --- | --- |\n\n"
            "## 需修复\n\n"
            "| 优先级 | 任务 | 名称 | 分支 | PR |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| P1 | 任务-000013 | 建立 PR 自动合并策略与审批规则 | `branch` | "
            "[#40](https://github.com/xk320/zhishi/pull/40) |\n\n"
            "## 已完成\n\n"
            "| 任务 | 名称 | 完成证据 |\n"
            "| --- | --- | --- |\n\n"
            "## 已取消\n\n无。\n"
        )
        blocked_board = blocked_transition_board(blocked=True)
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_board,
            head_board=repair_board,
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_合并后状态闭环允许阻塞任务直接恢复为待执行(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        base_task = task_text(
            status="阻塞", task_type="数据审计", dependency="000012"
        )
        head_task = task_text(
            status="待执行", task_type="数据审计", dependency="000012"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=True),
            head_board=blocked_transition_board(blocked=False),
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_合并后状态闭环拒绝直接恢复夹带完成任务(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n- 任务-000014\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="阻塞", dependency="000012"),
                "000014": task_text(status="待评审"),
            },
            head_tasks={
                "000013": task_text(status="待执行", dependency="000012"),
                "000014": task_text(status="已完成"),
            },
            merge_facts={
                "000014": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=41,
                )
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("合并后状态闭环必须同步看板", result.reasons)

    def test_合并后状态闭环拒绝阻塞恢复夹带合同改写(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        base_task = task_text(status="阻塞", dependency="000012")
        head_task = base_task.replace("- 状态：阻塞", "- 状态：需修复", 1)
        head_task += "\n\n额外改写。\n"
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={"000013": base_task},
            head_tasks={"000013": head_task},
            base_board=blocked_transition_board(blocked=True),
            head_board=blocked_transition_board(blocked=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("阻塞恢复状态闭环夹带合同改写", result.reasons)

    def test_状态闭环接受依赖章节中的后继解锁字段(self):
        def move_dependency_fields_to_section(text: str) -> str:
            prefixes = (
                "- 唯一前序依赖：",
                "- 当前阻塞原因：",
                "- 解除条件：",
            )
            lines = text.splitlines()
            dependency_lines = [
                line for line in lines if line.startswith(prefixes)
            ]
            header_lines = [
                line for line in lines if not line.startswith(prefixes)
            ]
            return (
                "\n".join(header_lines).rstrip()
                + "\n\n## 依赖与阻塞条件\n\n"
                + "\n".join(dependency_lines)
                + "\n"
            )

        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审", task_type="工程"),
                "000014": move_dependency_fields_to_section(
                    task_text(
                        status="阻塞",
                        task_type="数据治理",
                        dependency="000013",
                    )
                ),
            },
            head_tasks={
                "000013": task_text(status="已完成", task_type="工程"),
                "000014": move_dependency_fields_to_section(
                    task_text(
                        status="待执行",
                        task_type="数据治理",
                        dependency="000013",
                    )
                ),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=closure_board(completed=True),
        )

        self.assertTrue(result.eligible, result.reasons)

    def test_状态闭环拒绝依赖字段在其他章节重复出现(self):
        def move_dependency_fields_to_section(text: str) -> str:
            prefixes = (
                "- 唯一前序依赖：",
                "- 当前阻塞原因：",
                "- 解除条件：",
            )
            lines = text.splitlines()
            dependency_lines = [
                line for line in lines if line.startswith(prefixes)
            ]
            header_lines = [
                line for line in lines if not line.startswith(prefixes)
            ]
            return (
                "\n".join(header_lines).rstrip()
                + "\n\n## 依赖与阻塞条件\n\n"
                + "\n".join(dependency_lines)
                + "\n\n## 输出合同\n\n"
                + "- 当前阻塞原因：伪装夹带。\n"
            )

        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审"),
                "000014": move_dependency_fields_to_section(
                    task_text(status="阻塞", dependency="000013")
                ),
            },
            head_tasks={
                "000013": task_text(status="已完成"),
                "000014": move_dependency_fields_to_section(
                    task_text(status="待执行", dependency="000013")
                ),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=closure_board(completed=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000014状态闭环夹带合同改写", result.reasons)

    def test_状态闭环拒绝字段在两个同名依赖章节间迁移(self):
        def duplicate_section_task(status: str) -> str:
            task = task_text(status=status, dependency="000013")
            immutable_lines = [
                line
                for line in task.splitlines()
                if not line.startswith(("- 当前阻塞原因：", "- 解除条件："))
            ]
            if status == "阻塞":
                sections = (
                    "## 依赖与阻塞条件\n"
                    "- 当前阻塞原因：任务-000013尚未完成。\n"
                    "- 解除条件：任务-000013完成后解除。\n"
                    "## 依赖与阻塞条件\n"
                )
            else:
                sections = (
                    "## 依赖与阻塞条件\n"
                    "## 依赖与阻塞条件\n"
                    "- 当前阻塞原因：无；任务-000013已完成。\n"
                    "- 解除条件：已满足。\n"
                )
            return "\n".join(immutable_lines).rstrip() + "\n" + sections

        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n"
            "- 任务-000014\n\n"
            "## 变更类型\n\n"
            "- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审"),
                "000014": duplicate_section_task("阻塞"),
            },
            head_tasks={
                "000013": task_text(status="已完成"),
                "000014": duplicate_section_task("待执行"),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=closure_board(completed=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000014状态闭环夹带合同改写", result.reasons)

    def test_合并后状态闭环拒绝其他文件和状态迁移(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "README.md",
                "docs/研发中心/任务/任务-000013.md",
            ],
            pr_body=body,
            base_tasks={"000013": task_text(status="执行中")},
            head_tasks={"000013": task_text(status="已完成")},
            merge_facts={},
        )

        self.assertFalse(result.eligible)
        self.assertIn("合并后状态闭环包含非状态文件“README.md”", result.reasons)
        self.assertIn("任务-000013存在非法状态闭环“执行中→已完成”", result.reasons)

    def test_合并后状态闭环必须同步看板且只能解除一个后继(self):
        body = (
            "## 关联任务\n\n"
            "- 任务-000013\n- 任务-000014\n- 任务-000015\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/任务/任务-000015.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审"),
                "000014": task_text(status="阻塞", dependency="000013"),
                "000015": task_text(status="阻塞", dependency="000013"),
            },
            head_tasks={
                "000013": task_text(status="已完成"),
                "000014": task_text(status="待执行", dependency="000013"),
                "000015": task_text(status="待执行", dependency="000013"),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("合并后状态闭环必须同步看板", result.reasons)
        self.assertIn("合并后状态闭环最多解除一个唯一后继", result.reasons)

    def test_状态闭环拒绝合同改写伪造事实和无关后继(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n- 任务-000014\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        completed = task_text(
            status="已完成",
            task_type="工程",
            extra_contract="## 输出合同\n\n- 被闭环PR篡改。\n",
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审", task_type="工程"),
                "000014": task_text(status="阻塞", dependency="999999"),
            },
            head_tasks={
                "000013": completed,
                "000014": task_text(status="待执行", dependency="999999"),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="f" * 40,
                    merged_at="2099-01-01 00:00:00 +0800",
                    pr_number=999,
                )
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013状态闭环夹带合同改写", result.reasons)
        self.assertIn("任务-000013合并证据与main真实事实不一致", result.reasons)
        self.assertIn("任务-000014不是任务-000013的唯一后继", result.reasons)

    def test_状态闭环拒绝看板结构和完成证据改写(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n- 任务-000014\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        head_board = closure_board(completed=True).replace(
            "# 看板", "# 被改写的看板"
        ).replace("PR #40", "PR #999")
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审"),
                "000014": task_text(status="阻塞", dependency="000013"),
            },
            head_tasks={
                "000013": task_text(status="已完成"),
                "000014": task_text(status="待执行", dependency="000013"),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=head_board,
        )

        self.assertFalse(result.eligible)
        self.assertIn("合并后状态闭环夹带看板结构改写", result.reasons)
        self.assertIn("任务-000013的看板证据行不可复算", result.reasons)

    def test_看板任务行中的其他任务引用不影响主键(self):
        rows = self.policy._board_rows(
            "## 已完成\n\n"
            "| 任务-000001 | 总任务 | 拆分为任务-000003至任务-000006 |\n"
        )

        self.assertEqual("已完成", rows["000001"][0])
        self.assertNotIn("000003", rows)

    def test_看板表格拒绝无法解析的夹带行(self):
        board = closure_board(completed=True).replace(
            "| 任务 | 名称 | 完成证据 |",
            "| 任务 | 名称 | 完成证据 |\n| 伪造任务状态 | 任意夹带内容 |",
        )

        self.assertFalse(self.policy._board_schema_is_valid(board))

    def test_状态闭环拒绝在合同正文伪装可变元数据(self):
        body = (
            "## 关联任务\n\n- 任务-000013\n- 任务-000014\n\n"
            "## 变更类型\n\n- 合并后状态闭环\n"
        )
        result = self.evaluate(
            changed_paths=[
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
                "docs/研发中心/看板.md",
            ],
            pr_body=body,
            base_tasks={
                "000013": task_text(status="待评审"),
                "000014": task_text(status="阻塞", dependency="000013"),
            },
            head_tasks={
                "000013": task_text(
                    status="已完成",
                    extra_contract="## 输出合同\n\n- 状态：伪装夹带\n",
                ),
                "000014": task_text(status="待执行", dependency="000013"),
            },
            merge_facts={
                "000013": self.policy.MergeFact(
                    sha="0123456789abcdef0123456789abcdef01234567",
                    merged_at="2026-08-03 08:00:00 +0800",
                    pr_number=40,
                )
            },
            base_board=closure_board(completed=False),
            head_board=closure_board(completed=True),
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013状态闭环夹带合同改写", result.reasons)

    def test_nul路径解析保留中文路径(self):
        paths = self.policy.parse_nul_paths(
            "docs/研发中心/看板.md\0docs/治理/PR自动合并策略.md\0".encode()
        )

        self.assertEqual(
            ("docs/研发中心/看板.md", "docs/治理/PR自动合并策略.md"),
            paths,
        )

    def test_关联任务未进入待评审时拒绝(self):
        result = self.evaluate(
            head_tasks={"000013": task_text(status="执行中")}
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013在PR中的状态不是“待评审”", result.reasons)

    def test_外部仓库pr时拒绝(self):
        result = self.evaluate(head_repository="example/fork")

        self.assertFalse(result.eligible)
        self.assertIn("外部仓库PR不允许自动合并", result.reasons)

    def test_修改未引用任务文件时拒绝(self):
        result = self.evaluate(
            changed_paths=[
                "docs/治理/PR自动合并策略.md",
                "docs/研发中心/任务/任务-000013.md",
                "docs/研发中心/任务/任务-000014.md",
            ]
        )

        self.assertFalse(result.eligible)
        self.assertIn("修改了未在PR正文引用的任务-000014", result.reasons)

    def test_引用任务但未修改任务文件时拒绝(self):
        result = self.evaluate(
            changed_paths=["docs/治理/PR自动合并策略.md"]
        )

        self.assertFalse(result.eligible)
        self.assertIn("任务-000013的任务文件未在PR中更新", result.reasons)

    def test_没有任何变更路径时拒绝(self):
        result = self.evaluate(changed_paths=[])

        self.assertFalse(result.eligible)
        self.assertIn("PR没有可验证的变更路径", result.reasons)

    def test_目标分支不是main时拒绝(self):
        result = self.evaluate(base_branch="develop")

        self.assertFalse(result.eligible)
        self.assertIn("目标分支不是main", result.reasons)


@unittest.skipUnless(MODULE_PATH.exists(), "等待资格判定实现")
class GitPathFactIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy_module()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        self._git("init", "-q")
        self._git("config", "user.name", "自动合并测试")
        self._git("config", "user.email", "auto-merge@example.invalid")
        self._write(
            "docs/研发中心/任务/任务-000013.md",
            task_text(
                status="待执行", task_type="数据治理", dependency="000012"
            ),
        )
        self._write("docs/研发中心/看板.md", delivery_board(head=False))
        self._write("docs/治理/既有.md", "基线内容\n")
        self._write("docs/治理/待删除.md", "待删除\n")
        self._git("add", "--", ".")
        self._git("commit", "-qm", "base")
        self.base_ref = self._git("rev-parse", "HEAD").stdout.decode().strip()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(
        self,
        *arguments: str,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            check=True,
            capture_output=True,
            input=input_bytes,
        )

    def _write(self, relative_path: str, text: str) -> Path:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _prepare_task_delivery(self) -> None:
        self._write(
            "docs/研发中心/任务/任务-000013.md",
            task_text(
                status="待评审",
                task_type="数据治理",
                dependency="000012",
                pr_number="40",
            ),
        )
        self._write("docs/研发中心/看板.md", delivery_board(head=True))

    def _commit_head(self) -> str:
        self._git("commit", "-qm", "head")
        return self._git("rev-parse", "HEAD").stdout.decode().strip()

    def _run_cli(
        self,
        head_ref: str,
        *,
        body: str | None = None,
        base_ref: str | None = None,
        head_branch: str | None = None,
        pr_number: int | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        metadata_path = self.repo / "metadata.json"
        metadata = {
                    "body": body or (
                        "## 关联任务\n\n"
                        "- 任务-000013\n\n"
                        "## 变更类型\n\n"
                        "- 任务交付\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                }
        if head_branch is not None:
            metadata["head_ref"] = head_branch
        if pr_number is not None:
            metadata["pr_number"] = pr_number
        metadata_path.write_text(
            json.dumps(
                metadata,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root",
                str(self.repo),
                "--base-ref",
                base_ref or self.base_ref,
                "--head-ref",
                head_ref,
                "--metadata",
                str(metadata_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        return result, json.loads(result.stdout)

    def test_cli任务登记从基线git树加载全部任务编号(self):
        self._write(
            "docs/研发中心/任务/任务-000039.md",
            task_text(status="已完成"),
        )
        self._write("docs/研发中心/看板.md", registration_board(status=None))
        self._git("add", "--", ".")
        self._git("commit", "-qm", "registration base")
        base_ref = self._git("rev-parse", "HEAD").stdout.decode().strip()

        self._write(
            "docs/研发中心/任务/任务-000040.md",
            registration_task(),
        )
        self._write(
            "docs/研发中心/看板.md",
            registration_board(status="待执行"),
        )
        self._write(
            "docs/superpowers/specs/2026-08-04-task-000040-design.md",
            "# 任务-000040设计\n",
        )
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        result, payload = self._run_cli(
            head_ref,
            base_ref=base_ref,
            body=(
                "## 关联任务\n\n"
                "- 任务-000040\n\n"
                "## 变更类型\n\n"
                "- 任务登记\n"
            ),
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(payload["eligible"], payload["reasons"])

    def test_cli任务引用超限在逐任务读取前失败关闭(self):
        path_fact = self.policy.PathFact(
            path="docs/治理/变更.md",
            status="M",
            mode="100644",
            object_type="blob",
            size=4,
            text="safe",
        )
        cases = (
            (
                "任务交付",
                "- 任务-000013\n- 任务-000014",
                "任务交付最多关联1个任务",
            ),
            (
                "合并后状态闭环",
                "- 任务-000013\n- 任务-000014\n- 任务-000015",
                "合并后状态闭环最多关联2个任务",
            ),
        )
        for change_type, references, expected_reason in cases:
            with self.subTest(change_type=change_type):
                metadata_path = self.repo / f"{change_type}.json"
                metadata_path.write_text(
                    json.dumps(
                        {
                            "body": (
                                "## 关联任务\n\n"
                                f"{references}\n\n"
                                "## 变更类型\n\n"
                                f"- {change_type}\n"
                            ),
                            "base_ref": "main",
                            "repository": "xk320/zhishi",
                            "head_repository": "xk320/zhishi",
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                arguments = SimpleNamespace(
                    repo_root=self.repo,
                    base_ref="base",
                    head_ref="head",
                    metadata=metadata_path,
                )
                output = io.StringIO()
                with (
                    mock.patch.object(
                        self.policy,
                        "_parse_arguments",
                        return_value=arguments,
                    ),
                    mock.patch.object(
                        self.policy,
                        "_load_path_facts",
                        return_value=(path_fact,),
                    ),
                    mock.patch.object(
                        self.policy,
                        "_load_ref_task_ids",
                        return_value=("000001",),
                    ),
                    mock.patch.object(
                        self.policy,
                        "_load_ref_tasks",
                        side_effect=({}, {}),
                    ) as load_tasks,
                    redirect_stdout(output),
                ):
                    return_code = self.policy.main()

                self.assertEqual(1, return_code)
                load_tasks.assert_not_called()
                payload = json.loads(output.getvalue())
                self.assertIn(expected_reason, payload["reasons"])

    def test_cli合法状态闭环两任务不被引用上限提前拒绝(self):
        metadata_path = self.repo / "closure-two.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n"
                        "- 任务-000013\n"
                        "- 任务-000014\n\n"
                        "## 变更类型\n\n"
                        "- 合并后状态闭环\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        path_fact = self.policy.PathFact(
            path="docs/治理/变更.md",
            status="M",
            mode="100644",
            object_type="blob",
            size=4,
            text="safe",
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.policy,
                "_parse_arguments",
                return_value=arguments,
            ),
            mock.patch.object(
                self.policy,
                "_load_path_facts",
                return_value=(path_fact,),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000001",),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_tasks",
                side_effect=({}, {}),
            ) as load_tasks,
            mock.patch.object(
                self.policy,
                "_read_path_at_ref",
                return_value=None,
            ),
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(1, return_code)
        self.assertEqual(2, load_tasks.call_count)
        payload = json.loads(output.getvalue())
        self.assertNotIn(
            "合并后状态闭环最多关联2个任务",
            payload["reasons"],
        )

    def test_cli阻塞合同修复允许正文单任务加目标任务文件(self):
        metadata_path = self.repo / "blocked-repair.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n- 任务-000056\n\n"
                        "## 变更类型\n\n- 阻塞任务合同修复\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        facts = tuple(
            self.policy.PathFact(
                path=path,
                status="M",
                mode="100644",
                object_type="blob",
                size=4,
                text="safe",
            )
            for path in (
                "docs/研发中心/任务/任务-000056.md",
                "docs/研发中心/任务/任务-000055.md",
                "docs/研发中心/看板.md",
            )
        )
        output = io.StringIO()
        with (
            mock.patch.object(self.policy, "_parse_arguments", return_value=arguments),
            mock.patch.object(self.policy, "_load_path_facts", return_value=facts),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000055", "000056"),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_tasks",
                side_effect=({}, {}),
            ) as load_tasks,
            mock.patch.object(self.policy, "_read_path_at_ref", return_value=None),
            mock.patch.object(
                self.policy,
                "_cross_carrier_conflict_reasons",
                return_value=(),
            ) as conflict_check,
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(1, return_code)
        self.assertEqual(2, load_tasks.call_count)
        payload = json.loads(output.getvalue())
        self.assertNotIn("阻塞任务合同修复最多关联1个任务", payload["reasons"])
        self.assertEqual(
            "000056",
            conflict_check.call_args.kwargs["task_id"],
        )

    def test_cliroot合同修复将执行任务传给跨载体检查(self):
        metadata_path = self.repo / "root-blocked-repair.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n- 任务-000086\n\n"
                        "## 变更类型\n\n- 阻塞任务合同修复\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        facts = (
            self.policy.PathFact(
                path="docs/研发中心/任务/任务-000084.md",
                status="M",
                mode="100644",
                object_type="blob",
                size=4,
                text="safe",
            ),
        )
        output = io.StringIO()
        with (
            mock.patch.object(self.policy, "_parse_arguments", return_value=arguments),
            mock.patch.object(self.policy, "_load_path_facts", return_value=facts),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000084", "000085", "000086"),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_tasks",
                side_effect=({}, {}),
            ),
            mock.patch.object(self.policy, "_read_path_at_ref", return_value=None),
            mock.patch.object(
                self.policy,
                "_cross_carrier_conflict_reasons",
                return_value=(),
            ) as conflict_check,
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(1, return_code)
        self.assertEqual(
            "000086",
            conflict_check.call_args.kwargs["task_id"],
        )

    def test_cliroot合同修复按固定映射加载目标任务(self):
        metadata_path = self.repo / "root-target-load.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n- 任务-000086\n\n"
                        "## 变更类型\n\n- 阻塞任务合同修复\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        facts = (
            self.policy.PathFact(
                path="docs/研发中心/任务/任务-000086.md",
                status="M",
                mode="100644",
                object_type="blob",
                size=4,
                text="safe",
            ),
        )
        loaded_ids = []

        def load_tasks(_repo, _ref, task_ids):
            loaded_ids.append(tuple(task_ids))
            return {}

        output = io.StringIO()
        with (
            mock.patch.object(self.policy, "_parse_arguments", return_value=arguments),
            mock.patch.object(self.policy, "_load_path_facts", return_value=facts),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000086",),
            ),
            mock.patch.object(self.policy, "_load_ref_tasks", side_effect=load_tasks),
            mock.patch.object(
                self.policy,
                "evaluate_eligibility",
                return_value=self.policy.EligibilityResult(True, ()),
            ),
            mock.patch.object(
                self.policy,
                "_cross_carrier_conflict_reasons",
                return_value=(),
            ),
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(0, return_code)
        self.assertEqual(
            [("000084", "000086"), ("000084", "000086")],
            loaded_ids,
        )

    def test_cli任务合同冲突修复将执行任务传给跨载体检查(self):
        metadata_path = self.repo / "contract-conflict-repair.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n- 任务-000068\n\n"
                        "## 变更类型\n\n- 任务合同冲突修复\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        facts = tuple(
            self.policy.PathFact(
                path=path,
                status="M",
                mode="100644",
                object_type="blob",
                size=4,
                text="safe",
            )
            for path in (
                "docs/研发中心/任务/任务-000068.md",
                "docs/研发中心/任务/任务-000066.md",
                "docs/研发中心/看板.md",
            )
        )
        output = io.StringIO()
        with (
            mock.patch.object(self.policy, "_parse_arguments", return_value=arguments),
            mock.patch.object(self.policy, "_load_path_facts", return_value=facts),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000066", "000068"),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_tasks",
                side_effect=({}, {}),
            ),
            mock.patch.object(
                self.policy,
                "_validate_contract_conflict_repair",
                return_value={"000066"},
            ) as contract_repair,
            mock.patch.object(self.policy, "_read_path_at_ref", return_value=None),
            mock.patch.object(self.policy, "_derive_merge_facts", return_value={}),
            mock.patch.object(
                self.policy,
                "_cross_carrier_conflict_reasons",
                return_value=(),
            ) as conflict_check,
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(0, return_code)
        self.assertEqual(
            ("000068",),
            contract_repair.call_args.kwargs["task_ids"],
        )
        self.assertEqual(
            "000068",
            conflict_check.call_args.kwargs["task_id"],
        )

    def test_cli任务095合同冲突修复路由到同一执行任务(self):
        metadata_path = self.repo / "task095-contract-conflict-repair.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n- 任务-000095\n\n"
                        "## 变更类型\n\n- 任务合同冲突修复\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        arguments = SimpleNamespace(
            repo_root=self.repo,
            base_ref="base",
            head_ref="head",
            metadata=metadata_path,
        )
        facts = (
            self.policy.PathFact(
                path="docs/研发中心/任务/任务-000094.md",
                status="M",
                mode="100644",
                object_type="blob",
                size=4,
                text="safe",
            ),
        )
        output = io.StringIO()
        with (
            mock.patch.object(self.policy, "_parse_arguments", return_value=arguments),
            mock.patch.object(self.policy, "_load_path_facts", return_value=facts),
            mock.patch.object(
                self.policy,
                "_load_ref_task_ids",
                return_value=("000094", "000095"),
            ),
            mock.patch.object(
                self.policy,
                "_load_ref_tasks",
                side_effect=({}, {}),
            ),
            mock.patch.object(
                self.policy,
                "_validate_task094_contract_repair",
                return_value={"000094", "000095"},
            ) as contract_repair,
            mock.patch.object(self.policy, "_read_path_at_ref", return_value=None),
            mock.patch.object(self.policy, "_derive_merge_facts", return_value={}),
            mock.patch.object(
                self.policy,
                "_cross_carrier_conflict_reasons",
                return_value=(),
            ) as conflict_check,
            redirect_stdout(output),
        ):
            return_code = self.policy.main()

        self.assertEqual(0, return_code)
        self.assertEqual(
            ("000095",),
            contract_repair.call_args.kwargs["task_ids"],
        )
        self.assertEqual(
            "000095",
            conflict_check.call_args.kwargs["task_id"],
        )

    def test_cli任务合同冲突修复拒绝未知与混合正文引用(self):
        for task_lines in (
            "- 任务-000099\n",
            "- 任务-000068\n- 任务-000095\n",
            "- 任务-000095\n- 任务-000095\n",
        ):
            with self.subTest(task_lines=task_lines):
                metadata_path = self.repo / "invalid-contract-conflict-repair.json"
                metadata_path.write_text(
                    json.dumps(
                        {
                            "body": (
                                "## 关联任务\n\n"
                                f"{task_lines}\n"
                                "## 变更类型\n\n- 任务合同冲突修复\n"
                            ),
                            "base_ref": "main",
                            "repository": "xk320/zhishi",
                            "head_repository": "xk320/zhishi",
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                arguments = SimpleNamespace(
                    repo_root=self.repo,
                    base_ref="base",
                    head_ref="head",
                    metadata=metadata_path,
                )
                output = io.StringIO()
                with (
                    mock.patch.object(
                        self.policy, "_parse_arguments", return_value=arguments
                    ),
                    mock.patch.object(self.policy, "_load_path_facts", return_value=()),
                    mock.patch.object(
                        self.policy, "_load_ref_task_ids", return_value=("000068",)
                    ),
                    mock.patch.object(
                        self.policy, "evaluate_eligibility"
                    ) as eligibility,
                    redirect_stdout(output),
                ):
                    return_code = self.policy.main()

                self.assertEqual(1, return_code)
                self.assertFalse(eligibility.called)
                payload = json.loads(output.getvalue())
                self.assertIn(
                    "任务合同冲突修复正文必须精确引用已登记执行任务",
                    payload["reasons"],
                )

    def test_cli任务095到094真实git基线头正向与错误正文失败关闭(self):
        task094_base, task094_head = task094_contract_versions(self.policy)
        task095_complete = (
            REPO_ROOT / "docs/研发中心/任务/任务-000095.md"
        ).read_text(encoding="utf-8").replace("- 状态：待评审", "- 状态：已完成", 1)
        self._write("docs/研发中心/任务/任务-000094.md", task094_base)
        self._write("docs/研发中心/任务/任务-000095.md", task095_complete)
        self._git("add", "--", ".")
        self._git("commit", "-qm", "task095 completed base")
        base_ref = self._git("rev-parse", "HEAD").stdout.decode().strip()

        self._write("docs/研发中心/任务/任务-000094.md", task094_head)
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        valid_body = (
            "## 关联任务\n\n- 任务-000095\n\n"
            "## 变更类型\n\n- 任务合同冲突修复\n"
        )
        result, payload = self._run_cli(
            head_ref,
            body=valid_body,
            base_ref=base_ref,
            head_branch="codex/task-000094-contract-repair-v2",
            pr_number=260,
        )
        self.assertEqual(0, result.returncode, payload)
        self.assertTrue(payload["eligible"], payload["reasons"])

        for invalid_body in (
            valid_body.replace("000095", "000099"),
            valid_body.replace(
                "- 任务-000095", "- 任务-000068\n- 任务-000095"
            ),
            valid_body.replace(
                "- 任务-000095", "- 任务-000095\n- 任务-000095"
            ),
        ):
            with self.subTest(invalid_body=invalid_body):
                result, payload = self._run_cli(
                    head_ref, body=invalid_body, base_ref=base_ref
                )
                self.assertEqual(1, result.returncode)
                self.assertFalse(payload["eligible"])
                self.assertIn(
                    "任务合同冲突修复正文必须精确引用已登记执行任务",
                    payload["reasons"],
                )

    def test_普通中文路径新增修改能生成事实并通过cli(self):
        self._prepare_task_delivery()
        self._write("docs/治理/既有.md", "修改后内容\n")
        self._write("docs/治理/新增.md", "新增内容\n")
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        facts = self.policy._load_path_facts(
            self.repo, self.base_ref, head_ref
        )

        by_path = {fact.path: fact for fact in facts}
        self.assertEqual("M", by_path["docs/治理/既有.md"].status)
        self.assertEqual("A", by_path["docs/治理/新增.md"].status)
        self.assertEqual("100644", by_path["docs/治理/新增.md"].mode)
        self.assertEqual("blob", by_path["docs/治理/新增.md"].object_type)
        self.assertEqual("新增内容\n", by_path["docs/治理/新增.md"].text)

        result, payload = self._run_cli(head_ref)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(payload["eligible"], payload["reasons"])
        self.assertEqual(
            {fact.path for fact in facts}, set(payload["changed_paths"])
        )
        self.assertEqual(
            {"eligible", "reasons", "changed_paths"}, set(payload)
        )

    def test_符号链接可执行文件和删除都失败关闭(self):
        self._prepare_task_delivery()
        os.symlink("既有.md", self.repo / "docs/治理/符号链接.md")
        executable = self._write("docs/治理/可执行.md", "脚本\n")
        executable.chmod(0o755)
        (self.repo / "docs/治理/待删除.md").unlink()
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        facts = self.policy._load_path_facts(
            self.repo, self.base_ref, head_ref
        )
        by_path = {fact.path: fact for fact in facts}

        self.assertEqual("120000", by_path["docs/治理/符号链接.md"].mode)
        self.assertEqual("100755", by_path["docs/治理/可执行.md"].mode)
        self.assertEqual("D", by_path["docs/治理/待删除.md"].status)

        result, payload = self._run_cli(head_ref)

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(payload["eligible"])
        self.assertIn("路径事实不允许自动合并", payload["reasons"])

    def test_非法utf8_blob不回显正文且失败关闭(self):
        self._prepare_task_delivery()
        self._git("add", "--", "docs/研发中心/任务/任务-000013.md")
        oid = self._git(
            "hash-object", "-w", "--stdin", input_bytes=b"\xff\xfe\xfd"
        ).stdout.decode().strip()
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{oid},docs/治理/非法编码.md",
        )
        head_ref = self._commit_head()

        facts = self.policy._load_path_facts(
            self.repo, self.base_ref, head_ref
        )
        invalid_fact = next(
            fact for fact in facts if fact.path == "docs/治理/非法编码.md"
        )
        self.assertIsNone(invalid_fact.text)
        self.assertEqual(3, invalid_fact.size)

        result, payload = self._run_cli(head_ref)

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(payload["eligible"])
        self.assertIn("路径事实缺少可扫描文本", payload["reasons"])
        self.assertEqual(
            {"eligible", "reasons", "changed_paths"}, set(payload)
        )

    def test_json_yaml_toml凭据键不能绕过敏感文本扫描(self):
        self._prepare_task_delivery()
        keys = (
            "token",
            "password",
            "passwd",
            "secret",
            "client_secret",
            "api_key",
            "access_key",
        )
        values = ["hunter" + f"2-{index}" for index in range(len(keys))]
        lines: list[str] = []
        for key, value in zip(keys, values, strict=True):
            samples = (
                f'"{key}": "{value}"',
                f"'{key}': '{value}'",
                f"{key}: {value}",
                f'"{key}" = "{value}"',
                f"'{key}' = '{value}'",
                f"{key}={value}",
            )
            for sample in samples:
                with self.subTest(key=key, sample=sample[:8]):
                    self.assertTrue(
                        any(
                            pattern.search(sample)
                            for pattern in self.policy.SENSITIVE_TEXT_PATTERNS
                        )
                    )
            lines.extend(samples)
        self._write("docs/治理/凭据样本.md", "\n".join(lines) + "\n")
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        result, payload = self._run_cli(head_ref)

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(payload["eligible"])
        self.assertIn("变更文本包含敏感内容", payload["reasons"])
        serialized = json.dumps(payload, ensure_ascii=False)
        for value in values:
            self.assertNotIn(value, serialized)

    def test_501个真实git变更在元数据和正文前失败关闭(self):
        self._prepare_task_delivery()
        for index in range(500):
            self._write(f"docs/治理/资源-{index:03d}.md", "safe\n")
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        with mock.patch.object(
            self.policy,
            "_read_blob_bounded",
            wraps=self.policy._read_blob_bounded,
        ) as read_blob:
            with self.assertRaisesRegex(ValueError, "变更文件数超过500"):
                self.policy._load_path_facts(
                    self.repo, self.base_ref, head_ref
                )
            read_blob.assert_not_called()

        result, payload = self._run_cli(head_ref)

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(payload["eligible"])
        self.assertEqual(
            {"eligible", "reasons", "changed_paths"}, set(payload)
        )

    def _assert_escaped_sensitive_key_rejected(
        self,
        relative_path: str,
        encoded_key: str,
        separator: str,
    ) -> None:
        self._prepare_task_delivery()
        sensitive_value = "hunter" + "2"
        self._write(
            relative_path,
            f'"{encoded_key}" {separator} "{sensitive_value}"\n',
        )
        self._git("add", "--", ".")
        head_ref = self._commit_head()

        result, payload = self._run_cli(head_ref)

        self.assertEqual(1, result.returncode, result.stderr)
        self.assertFalse(payload["eligible"])
        self.assertIn("变更文本包含敏感内容", payload["reasons"])
        self.assertNotIn(
            sensitive_value,
            json.dumps(payload, ensure_ascii=False),
        )

    def test_json_unicode转义token键失败关闭(self):
        slash = "\\"
        encoded_key = "to" + slash + "u006b" + "en"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/凭据.json",
            encoded_key,
            ":",
        )

    def test_toml_unicode转义api_key键失败关闭(self):
        slash = "\\"
        encoded_key = "api" + slash + "u005f" + "key"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/凭据.toml",
            encoded_key,
            "=",
        )

    def test_yaml_unicode转义client_secret键失败关闭(self):
        slash = "\\"
        encoded_key = "client" + slash + "u005f" + "secret"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/凭据.yaml",
            encoded_key,
            ":",
        )

    def test_yaml短转义token键失败关闭(self):
        slash = "\\"
        encoded_key = "to" + slash + "x6b" + "en"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/token.yaml",
            encoded_key,
            ":",
        )

    def test_yaml短转义api_key键失败关闭(self):
        slash = "\\"
        encoded_key = "api" + slash + "x5f" + "key"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/api.yaml",
            encoded_key,
            ":",
        )

    def test_yaml短转义client_secret键失败关闭(self):
        slash = "\\"
        encoded_key = "client" + slash + "x5F" + "secret"

        self._assert_escaped_sensitive_key_rejected(
            "config/研究/client.yaml",
            encoded_key,
            ":",
        )

    def test_unicode键规范化严格验证4位8位和码点(self):
        slash = "\\"
        valid_cases = (
            ('"to' + slash + 'u006B' + 'en": "x"', '"to' + 'ken": "x"'),
            (
                '"api' + slash + 'U0000005F' + 'key" = "x"',
                '"api' + '_key" = "x"',
            ),
            (
                '"client' + slash + 'x5F' + 'secret": "x"',
                '"client' + '_secret": "x"',
            ),
        )
        for text, expected in valid_cases:
            with self.subTest(text=text):
                self.assertEqual(
                    expected,
                    self.policy._normalize_double_quoted_keys(text),
                )

        invalid_keys = (
            "bad" + slash + "u12G4",
            "bad" + slash + "uD800",
            "bad" + slash + "u000A",
            "bad" + slash + "xG1",
            "bad" + slash + "x0A",
        )
        for key in invalid_keys:
            with self.subTest(key=key):
                self.assertIsNone(
                    self.policy._normalize_double_quoted_keys(
                        f'"{key}": "x"'
                    )
                )


if __name__ == "__main__":
    unittest.main()
