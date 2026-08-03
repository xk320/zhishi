from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"
ELIGIBILITY_WORKFLOW = WORKFLOW_ROOT / "pr-auto-merge-eligibility.yml"
MERGE_WORKFLOW = WORKFLOW_ROOT / "pr-auto-merge.yml"
GOVERNANCE_FILES = (
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "docs" / "研发中心" / "README.md",
    REPO_ROOT / "docs" / "研发中心" / "任务规范.md",
    REPO_ROOT / "docs" / "研发中心" / "Codex自动执行提示词.md",
    REPO_ROOT / "docs" / "治理" / "PR自动合并策略.md",
)
PINNED_CHECKOUT = (
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
)


def workflow_run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip() != "run: |":
            index += 1
            continue
        indentation = len(line) - len(line.lstrip())
        index += 1
        body: list[str] = []
        while index < len(lines):
            current = lines[index]
            if current.strip() and len(current) - len(current.lstrip()) <= indentation:
                break
            body.append(current)
            index += 1
        blocks.append("\n".join(body))
    return blocks


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


class GovernanceDocumentTests(unittest.TestCase):
    def test_现行规则不再保留逐pr人工批准(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in GOVERNANCE_FILES)
        for stale in (
            "等待仓库所有者评审",
            "所有者批准当前提交SHA",
            "/架构评审通过",
            "其他PR必须人工合并",
            "Codex不得自行给出架构批准",
        ):
            self.assertNotIn(stale, combined)
        self.assertIn("不再等待仓库所有者逐PR批准", combined)

    def test_评审修复证据和资源门在现行规则中一致(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in GOVERNANCE_FILES)
        for required in (
            "两个独立只读子智能体",
            "最多三轮",
            "P0=P1=0",
            "zhishi-agent-review/v1",
            "精确头SHA",
            "测试单进程",
            "256 MiB",
            "可用内存低于20%",
            "可用磁盘低于5 GiB",
            "合并后状态闭环",
        ):
            self.assertIn(required, combined)

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

    def test_固定checkout版本并只运行基线可信资格脚本(self):
        self.assertIn(PINNED_CHECKOUT, self.text)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", self.text)
        self.assertNotIn("ref: ${{ github.event.pull_request.head.sha }}", self.text)
        self.assertIn("git fetch --no-tags origin", self.text)
        self.assertIn("name: 验证自动合并资格", self.text)
        self.assertIn("scripts/研发中心/验证自动合并资格.py", self.text)

    def test_不符合资格时检查失败而不是绿色假通过(self):
        self.assertNotIn("set +e", self.text)
        self.assertNotIn("转人工", self.text)
        self.assertNotIn("status=${PIPESTATUS[0]}", self.text)


@unittest.skipUnless(MERGE_WORKFLOW.exists(), "等待合并工作流实现")
class MergeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = MERGE_WORKFLOW.read_text(encoding="utf-8")

    def test_只接受所有者触发的结构化自动评审证据(self):
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("pr_number:", self.text)
        self.assertIn("head_sha:", self.text)
        self.assertIn("review_evidence:", self.text)
        self.assertIn("github.actor == 'xk320'", self.text)
        self.assertIn("github.repository == 'xk320/zhishi'", self.text)
        self.assertIn("github.ref == 'refs/heads/main'", self.text)
        self.assertIn("github.workflow_ref", self.text)
        self.assertNotIn("issue_comment:", self.text)

    def test_评审证据和合并均绑定四十位sha(self):
        self.assertIn("EXPECTED_HEAD_SHA:", self.text)
        self.assertIn("scripts/研发中心/验证自动评审证据.py", self.text)
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
        )[1].split("- name: 合并评审通过的精确提交", maxsplit=1)[0]

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
        self.assertIn("检查未解决评审和当前提交检查", self.text)
        self.assertIn("reviewThreads", self.text)
        self.assertIn("CHANGES_REQUESTED", self.text)

    def test_权限最小且不使用危险事件(self):
        self.assertIn("contents: write", self.text)
        self.assertIn("pull-requests: read", self.text)
        self.assertNotIn("pull-requests: write", self.text)
        self.assertIn("checks: read", self.text)
        self.assertIn("issues: write", self.text)
        self.assertNotIn("pull_request_target", self.text)

    def test_评审线程检查和reviews必须完整分页(self):
        self.assertGreaterEqual(self.text.count("--paginate --slurp"), 3)
        self.assertIn("pageInfo{hasNextPage,endCursor}", self.text)
        self.assertIn("$endCursor:String", self.text)
        self.assertIn("latest_reviews", self.text)
        self.assertIn("submitted_at", self.text)

    def test_没有浮动action版本或把输入直接拼进run(self):
        self.assertIsNone(
            re.search(r"uses:\s*[^\\s]+@(v\\d+|main|master)\\s*$", self.text)
        )
        run_blocks = workflow_run_blocks(self.text)
        self.assertTrue(run_blocks)
        self.assertTrue(all(block.strip() for block in run_blocks))
        self.assertTrue(
            all("github.event.inputs.review_evidence" not in block for block in run_blocks)
        )


if __name__ == "__main__":
    unittest.main()
