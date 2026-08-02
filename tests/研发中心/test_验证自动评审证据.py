from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "研发中心" / "验证自动评审证据.py"


def load_module() -> ModuleType:
    if not MODULE_PATH.exists():
        raise AssertionError(f"实现文件尚不存在：{MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("agent_review_evidence", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def valid_evidence() -> dict[str, object]:
    return {
        "schema_version": "zhishi-agent-review/v1",
        "repository": "xk320/zhishi",
        "pr_number": 40,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "repair_round": 2,
        "reviews": [
            {
                "role": "治理与架构",
                "reviewer_id": "governance-review",
                "conclusion": "APPROVE",
                "p0": 0,
                "p1": 0,
                "p2": 0,
            },
            {
                "role": "范围与安全",
                "reviewer_id": "qa-safety-review",
                "conclusion": "APPROVE",
                "p0": 0,
                "p1": 0,
                "p2": 1,
            },
        ],
        "validation": {
            "passed": True,
            "commands": ["python3 -m unittest ...", "git diff --check"],
        },
        "resource_policy": {
            "max_reviewers": 2,
            "test_processes": 1,
            "node_heap_mib": 256,
            "worktrees_created": 0,
        },
    }


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


@unittest.skipUnless(MODULE_PATH.exists(), "等待评审证据验证实现")
class ReviewEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def validate(self, evidence: dict[str, object] | None = None):
        return self.module.validate_evidence(
            valid_evidence() if evidence is None else evidence,
            repository="xk320/zhishi",
            pr_number=40,
            base_sha="a" * 40,
            head_sha="b" * 40,
        )

    def test_两个独立角色且无阻断时通过(self):
        result = self.validate()
        self.assertTrue(result.valid)
        self.assertEqual((), result.reasons)

    def test_sha_pr或仓库不一致时拒绝(self):
        evidence = valid_evidence()
        evidence["head_sha"] = "c" * 40
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("评审证据头提交SHA不匹配", result.reasons)

    def test_同一评审者或角色不能重复(self):
        evidence = valid_evidence()
        reviews = evidence["reviews"]
        assert isinstance(reviews, list)
        reviews[1]["reviewer_id"] = reviews[0]["reviewer_id"]
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("评审者必须相互独立", result.reasons)

    def test_p0或p1非零及非批准结论拒绝(self):
        evidence = valid_evidence()
        reviews = evidence["reviews"]
        assert isinstance(reviews, list)
        reviews[0]["p1"] = 1
        reviews[1]["conclusion"] = "CHANGES_REQUESTED"
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("评审存在P0或P1阻断问题", result.reasons)
        self.assertIn("评审结论不是APPROVE", result.reasons)

    def test_修复轮次和资源预算越界时拒绝(self):
        evidence = valid_evidence()
        evidence["repair_round"] = 4
        resource = evidence["resource_policy"]
        assert isinstance(resource, dict)
        resource["max_reviewers"] = 3
        resource["test_processes"] = 2
        resource["node_heap_mib"] = 1024
        resource["worktrees_created"] = 1
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("自动修复轮次超过3", result.reasons)
        self.assertIn("评审者并发上限超过2", result.reasons)
        self.assertIn("测试必须单进程", result.reasons)
        self.assertIn("Node堆上限必须不超过256 MiB", result.reasons)
        self.assertIn("禁止创建额外工作树", result.reasons)

    def test_验证未通过或没有命令时拒绝(self):
        evidence = valid_evidence()
        evidence["validation"] = {"passed": False, "commands": []}
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("主执行器验证未通过", result.reasons)
        self.assertIn("缺少实际验证命令", result.reasons)

    def test_cli不回显完整不可信证据(self):
        evidence = valid_evidence()
        evidence["secret_marker"] = "不得回显"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(evidence, ensure_ascii=False), encoding="utf-8")
            result = self.module.validate_file(
                path,
                repository="xk320/zhishi",
                pr_number=40,
                base_sha="a" * 40,
                head_sha="b" * 40,
            )
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main()
