from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "研发中心" / "验证自动合并资格.py"


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
) -> str:
    type_line = f"- 类型：{task_type}\n" if task_type is not None else ""
    scope_line = "- 自动合并范围：治理自动化\n" if automation_scope else ""
    completion_lines = (
        "- Pull Request：[#40](https://github.com/xk320/zhishi/pull/40)\n"
        "- 合并时间：2026-08-03 08:00:00 +0800\n"
        "- 合并提交SHA：`0123456789abcdef0123456789abcdef01234567`\n"
        if status == "已完成"
        else ""
    )
    return (
        "# 任务-000013：建立 PR 自动合并策略与审批规则\n\n"
        f"- 状态：{status}\n"
        f"{type_line}"
        f"{scope_line}"
        "- 优先级：P1\n"
        f"{completion_lines}"
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
                "000013": task_text(status="待执行"),
            },
            "head_tasks": {
                "000013": task_text(status="待评审"),
            },
            "base_branch": "main",
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
        }
        inputs.update(overrides)
        return self.policy.evaluate_eligibility(**inputs)

    def test_低风险治理文档且任务待评审时允许(self):
        result = self.evaluate()

        self.assertTrue(result.eligible)
        self.assertEqual((), result.reasons)

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
                    status="执行中",
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
                "000014": task_text(status="阻塞", task_type="数据治理"),
            },
            head_tasks={
                "000013": task_text(status="已完成", task_type="工程"),
                "000014": task_text(status="待执行", task_type="数据治理"),
            },
        )

        self.assertTrue(result.eligible)

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
                "000014": task_text(status="阻塞"),
                "000015": task_text(status="阻塞"),
            },
            head_tasks={
                "000013": task_text(status="已完成"),
                "000014": task_text(status="待执行"),
                "000015": task_text(status="待执行"),
            },
        )

        self.assertFalse(result.eligible)
        self.assertIn("合并后状态闭环必须同步看板", result.reasons)
        self.assertIn("合并后状态闭环最多解除一个唯一后继", result.reasons)

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


if __name__ == "__main__":
    unittest.main()
