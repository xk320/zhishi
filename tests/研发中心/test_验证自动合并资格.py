from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


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

    def test_低风险治理文档且任务待评审时允许(self):
        result = self.evaluate()

        self.assertTrue(result.eligible)
        self.assertEqual((), result.reasons)

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

    def test_受控研发拒绝路径越界与非法路径形式(self):
        rejected_paths = (
            "scripts/研究/部署/release.sh",
            "scripts/研究/生产/migrate.py",
            "scripts/模拟/交易/order.py",
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
            "scripts/模拟/交易所/order.py",
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
                )

                self.assertTrue(result.eligible, result.reasons)

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
            task_text(status="待执行"),
        )
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
            task_text(status="待评审"),
        )

    def _commit_head(self) -> str:
        self._git("commit", "-qm", "head")
        return self._git("rev-parse", "HEAD").stdout.decode().strip()

    def _run_cli(self, head_ref: str) -> tuple[subprocess.CompletedProcess[str], dict]:
        metadata_path = self.repo / "metadata.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "body": (
                        "## 关联任务\n\n"
                        "- 任务-000013\n\n"
                        "## 变更类型\n\n"
                        "- 任务交付\n"
                    ),
                    "base_ref": "main",
                    "repository": "xk320/zhishi",
                    "head_repository": "xk320/zhishi",
                },
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
                self.base_ref,
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


if __name__ == "__main__":
    unittest.main()
