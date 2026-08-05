import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "scripts" / "研发中心" / "验证自动合并资格.py"


def load_policy():
    spec = importlib.util.spec_from_file_location("merge_fact_policy", POLICY_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载可信校验器：{POLICY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class MergeFactDerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy()

    def create_repo(self):
        directory = tempfile.TemporaryDirectory()
        repo = Path(directory.name)
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "test@example.invalid")
        git(repo, "config", "user.name", "test")
        (repo / "README.md").write_text("base\n", encoding="utf-8")
        git(repo, "add", "README.md")
        git(repo, "commit", "-q", "-m", "base")
        return directory, repo

    def test_custom_subject_requires_double_parent_and_delivery_head(self):
        directory, repo = self.create_repo()
        self.addCleanup(directory.cleanup)
        git(repo, "switch", "-q", "-c", "delivery")
        (repo / "README.md").write_text("delivery\n", encoding="utf-8")
        git(repo, "commit", "-qam", "delivery")
        delivery_sha = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "-q", "main")
        git(repo, "merge", "--no-ff", "-q", "delivery", "-m", "custom merge")
        merge_sha = git(repo, "rev-parse", "HEAD")
        merge_time = git(repo, "show", "-s", "--format=%cI", merge_sha)
        normalized_time = self.policy.datetime.fromisoformat(merge_time).strftime(
            "%Y-%m-%d %H:%M:%S %z"
        )
        task = (
            "- Pull Request：[#154](https://github.com/xk320/zhishi/pull/154)\n"
            f"- 合并时间：{normalized_time}\n"
            f"- 合并提交SHA：`{merge_sha}`\n"
            f"- 交付提交SHA：`{delivery_sha}`\n"
        )
        facts = self.policy._derive_merge_facts(repo, "main", {"000001": task})
        self.assertEqual(facts["000001"].pr_number, 154)
        self.assertEqual(facts["000001"].sha, merge_sha)

    def test_custom_subject_without_delivery_head_is_rejected(self):
        directory, repo = self.create_repo()
        self.addCleanup(directory.cleanup)
        git(repo, "switch", "-q", "-c", "delivery")
        (repo / "README.md").write_text("delivery\n", encoding="utf-8")
        git(repo, "commit", "-qam", "delivery")
        git(repo, "switch", "-q", "main")
        git(repo, "merge", "--no-ff", "-q", "delivery", "-m", "custom merge")
        merge_sha = git(repo, "rev-parse", "HEAD")
        merge_time = git(repo, "show", "-s", "--format=%cI", merge_sha)
        normalized_time = self.policy.datetime.fromisoformat(merge_time).strftime(
            "%Y-%m-%d %H:%M:%S %z"
        )
        task = (
            "- Pull Request：[#154](https://github.com/xk320/zhishi/pull/154)\n"
            f"- 合并时间：{normalized_time}\n"
            f"- 合并提交SHA：`{merge_sha}`\n"
        )
        self.assertNotIn(
            "000001",
            self.policy._derive_merge_facts(repo, "main", {"000001": task}),
        )

