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
                "run_id": "agent-run-governance-0001",
                "reviewed_base_sha": "a" * 40,
                "reviewed_head_sha": "b" * 40,
                "reviewed_at": "2026-08-03T08:00:00+08:00",
                "conclusion": "APPROVE",
                "p0": 0,
                "p1": 0,
                "p2": 0,
                "findings": [],
            },
            {
                "role": "范围与安全",
                "reviewer_id": "qa-safety-review",
                "run_id": "agent-run-safety-0002",
                "reviewed_base_sha": "a" * 40,
                "reviewed_head_sha": "b" * 40,
                "reviewed_at": "2026-08-03T08:01:00+08:00",
                "conclusion": "APPROVE",
                "p0": 0,
                "p1": 0,
                "p2": 1,
                "findings": [{"id": "P2-001", "severity": "P2"}],
            },
        ],
        "validation": {
            "passed": True,
            "head_sha": "b" * 40,
            "completed_at": "2026-08-03T08:02:00+08:00",
            "commands": [
                {"command": "python3 -m unittest ...", "exit_code": 0},
                {"command": "git diff --check", "exit_code": 0},
            ],
        },
        "resource_policy": {
            "max_reviewers": 2,
            "test_processes": 1,
            "node_heap_mib": 256,
            "worktrees_created": 0,
            "memory_pressure": "normal",
            "memory_available_percent": 62.5,
            "disk_available_gib": 7.2,
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

    def test_评审者尾随空格和重复运行标识不能绕过独立性(self):
        evidence = valid_evidence()
        reviews = evidence["reviews"]
        assert isinstance(reviews, list)
        reviews[1]["reviewer_id"] = f"{reviews[0]['reviewer_id']} "
        reviews[1]["run_id"] = reviews[0]["run_id"]
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("评审者标识格式无效", result.reasons)
        self.assertIn("评审运行标识必须相互独立", result.reasons)

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

    def test_内存压力和磁盘硬门必须有真实安全余量(self):
        evidence = valid_evidence()
        resource = evidence["resource_policy"]
        assert isinstance(resource, dict)
        resource["memory_pressure"] = "critical"
        resource["memory_available_percent"] = 19.9
        resource["disk_available_gib"] = 4.9
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("内存压力不允许启动合并", result.reasons)
        self.assertIn("可用内存低于20%", result.reasons)
        self.assertIn("可用磁盘低于5 GiB", result.reasons)

    def test_验证未通过或没有命令时拒绝(self):
        evidence = valid_evidence()
        evidence["validation"] = {
            "passed": False,
            "head_sha": "b" * 40,
            "completed_at": "2026-08-03T08:02:00+08:00",
            "commands": [],
        }
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("主执行器验证未通过", result.reasons)
        self.assertIn("缺少实际验证命令", result.reasons)

    def test_未知或敏感字段必须拒绝且cli不回显正文(self):
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
        self.assertFalse(result.valid)
        self.assertIn("评审证据包含未知字段", result.reasons)

    def test_评审必须逐项绑定当前sha时间和发现清单(self):
        evidence = valid_evidence()
        reviews = evidence["reviews"]
        assert isinstance(reviews, list)
        reviews[0]["reviewed_head_sha"] = "c" * 40
        reviews[0]["reviewed_at"] = "无时区"
        reviews[1]["findings"] = []
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("评审记录未绑定当前base/head SHA", result.reasons)
        self.assertIn("评审时间必须为带时区RFC3339", result.reasons)
        self.assertIn("评审发现清单与P0/P1/P2计数不一致", result.reasons)

    def test_验证命令必须逐项记录零退出码并绑定head(self):
        evidence = valid_evidence()
        validation = evidence["validation"]
        assert isinstance(validation, dict)
        validation["head_sha"] = "c" * 40
        commands = validation["commands"]
        assert isinstance(commands, list)
        commands[0]["exit_code"] = 1
        result = self.validate(evidence)
        self.assertFalse(result.valid)
        self.assertIn("验证记录未绑定当前头提交", result.reasons)
        self.assertIn("验证命令存在非零退出码", result.reasons)


if __name__ == "__main__":
    unittest.main()
