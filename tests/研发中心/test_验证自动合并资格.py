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
    dependency: str | None = None,
    extra_contract: str = "",
) -> str:
    type_line = f"- 类型：{task_type}\n" if task_type is not None else ""
    scope_line = "- 自动合并范围：治理自动化\n" if automation_scope else ""
    review_lines = (
        "- Pull Request：[#40](https://github.com/xk320/zhishi/pull/40)\n"
        if status in {"待评审", "已完成"}
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
    return (
        "# 任务-000013：建立 PR 自动合并策略与审批规则\n\n"
        f"- 状态：{status}\n"
        f"{type_line}"
        f"{scope_line}"
        "- 优先级：P1\n"
        f"{review_lines}"
        f"{completion_lines}"
        f"{dependency_lines}"
        f"{extra_contract}"
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
        f"## 阻塞\n\n{blocked}\n\n"
        f"## 待评审\n\n{review}\n\n"
        f"## 已完成\n\n{done}\n"
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
                "000029": task_text(status="待执行", task_type="数据治理")
            },
            head_tasks={
                "000029": task_text(status="待评审", task_type="数据治理")
            },
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

    def test_多任务只有全部受控研发类型才允许受控路径(self):
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

        self.assertTrue(result.eligible, result.reasons)

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


if __name__ == "__main__":
    unittest.main()
