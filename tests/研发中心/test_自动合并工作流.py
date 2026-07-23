from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"
ELIGIBILITY_WORKFLOW = WORKFLOW_ROOT / "pr-auto-merge-eligibility.yml"
MERGE_WORKFLOW = WORKFLOW_ROOT / "pr-auto-merge.yml"
PINNED_CHECKOUT = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)


class WorkflowPresenceTests(unittest.TestCase):
    def test_资格工作流存在(self):
        self.assertTrue(
            ELIGIBILITY_WORKFLOW.exists(),
            f"工作流尚不存在：{ELIGIBILITY_WORKFLOW}",
        )

    def test_合并工作流存在(self):
        self.assertTrue(
            MERGE_WORKFLOW.exists(),
            f"工作流尚不存在：{MERGE_WORKFLOW}",
        )


@unittest.skipUnless(ELIGIBILITY_WORKFLOW.exists(), "等待资格工作流实现")
class EligibilityWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = ELIGIBILITY_WORKFLOW.read_text(encoding="utf-8")

    def test_使用pull_request且只有读权限(self):
        self.assertIn("pull_request:", self.text)
        self.assertIn("contents: read", self.text)
        self.assertIn("pull-requests: read", self.text)
        self.assertNotIn("contents: write", self.text)
        self.assertNotIn("pull-requests: write", self.text)

    def test_固定checkout版本并运行资格脚本(self):
        self.assertIn(PINNED_CHECKOUT, self.text)
        self.assertIn("name: 验证自动合并资格", self.text)
        self.assertIn("scripts/研发中心/验证自动合并资格.py", self.text)


@unittest.skipUnless(MERGE_WORKFLOW.exists(), "等待合并工作流实现")
class MergeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = MERGE_WORKFLOW.read_text(encoding="utf-8")

    def test_只接受所有者评论事件(self):
        self.assertIn("issue_comment:", self.text)
        self.assertIn("types: [created]", self.text)
        self.assertIn("github.actor == 'xk320'", self.text)
        self.assertIn(
            "github.event.comment.author_association == 'OWNER'",
            self.text,
        )
        self.assertIn("github.event.issue.pull_request", self.text)

    def test_批准指令绑定四十位sha(self):
        self.assertIn("APPROVAL_BODY:", self.text)
        self.assertIn("/架构评审通过", self.text)
        self.assertIn("[0-9a-f]{40}", self.text)
        self.assertIn('-f sha="$HEAD_SHA"', self.text)

    def test_只运行main上的可信脚本(self):
        self.assertIn(PINNED_CHECKOUT, self.text)
        self.assertIn("ref: main", self.text)
        self.assertIn("scripts/研发中心/验证自动合并资格.py", self.text)
        self.assertNotIn("ref: ${{ github.event.pull_request.head", self.text)

    def test_合并前同时复核基线和头提交sha(self):
        trusted_check = self.text.split(
            "- name: 使用main可信规则重新验证资格",
            maxsplit=1,
        )[1].split("- name: 合并前再次确认状态和提交", maxsplit=1)[0]
        final_check = self.text.split(
            "- name: 合并前再次确认状态和提交",
            maxsplit=1,
        )[1].split("- name: 合并批准的精确提交", maxsplit=1)[0]

        self.assertIn(
            "BASE_SHA: ${{ steps.pr.outputs.base_sha }}",
            final_check,
        )
        self.assertIn(
            'pull_request["base"]["sha"] == os.environ["BASE_SHA"]',
            final_check,
        )
        self.assertIn(
            'pull_request["head"]["sha"] == os.environ["HEAD_SHA"]',
            final_check,
        )
        self.assertIn(
            "METADATA_PATH: ${{ runner.temp }}/pr-auto-merge-metadata.json",
            trusted_check,
        )
        self.assertIn(
            "PR_PATH: ${{ runner.temp }}/pull-request.json",
            final_check,
        )

    def test_权限最小且不使用危险事件(self):
        self.assertIn("contents: write", self.text)
        self.assertIn("pull-requests: write", self.text)
        self.assertIn("checks: read", self.text)
        self.assertIn("issues: write", self.text)
        self.assertNotIn("pull_request_target", self.text)

    def test_没有浮动action版本或把评论直接拼进run(self):
        self.assertIsNone(
            re.search(r"uses:\s*[^\\s]+@(v\\d+|main|master)\\s*$", self.text)
        )
        run_blocks = re.findall(
            r"(?ms)^\\s+run:\\s*\\|\\n(?P<body>(?:\\s{8,}.*\\n?)*)",
            self.text,
        )
        self.assertTrue(run_blocks)
        self.assertTrue(
            all("github.event.comment.body" not in block for block in run_blocks)
        )


if __name__ == "__main__":
    unittest.main()
