import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/研发中心/验证跨载体冲突.py"
SPEC = importlib.util.spec_from_file_location("cross_carrier_conflict", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONFLICT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONFLICT
SPEC.loader.exec_module(CONFLICT)


class CrossCarrierConflictTests(unittest.TestCase):
    def test_main基线无跨载体冲突(self):
        report = CONFLICT.check_refs(ROOT, "main", "main")
        self.assertTrue(report.ok, report.reasons)
        payload = report.as_dict()
        self.assertEqual("zhishi-conflict-resolution/v1", payload["protocol_version"])
        self.assertEqual([], payload["conflicts"])
        self.assertEqual(64, len(payload["rule_fingerprint"]))

    def test无效提交身份失败关闭(self):
        report = CONFLICT.check_refs(ROOT, "not-a-ref", "main")
        self.assertFalse(report.ok)
        self.assertIn("PR_BASELINE_DRIFT", report.reasons[0])

    def test依赖环失败关闭(self):
        records = {
            "000001": ("a", "A", "待执行", "P0", ("000002",)),
            "000002": ("b", "B", "待执行", "P0", ("000001",)),
        }
        conflicts = []
        CONFLICT._check_dependencies(records, conflicts)
        self.assertTrue(any(item.code == "DEPENDENCY_CYCLE" for item in conflicts))

    def test资源不足安全停机(self):
        self.assertTrue(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="normal",
                memory_available_percent=66,
                disk_available_gib=134,
            )
        )
        self.assertFalse(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="warning",
                memory_available_percent=19,
                disk_available_gib=134,
            )
        )
        self.assertFalse(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="normal",
                memory_available_percent=66,
                disk_available_gib=4.9,
            )
        )

    def test评审证据提交变化即失效(self):
        self.assertTrue(
            CONFLICT.review_evidence_is_current(
                base_sha="a",
                head_sha="b",
                reviewed_base_sha="a",
                reviewed_head_sha="b",
            )
        )
        self.assertFalse(
            CONFLICT.review_evidence_is_current(
                base_sha="a",
                head_sha="c",
                reviewed_base_sha="a",
                reviewed_head_sha="b",
            )
        )

    def test修复计划只重建派生看板(self):
        schema = CONFLICT._schema_at_ref(ROOT, "main")
        board = CONFLICT._read_at_ref(ROOT, "main", CONFLICT.BOARD_PATH)
        self.assertIsNotNone(schema)
        self.assertIsNotNone(board)
        records = {
            "000049": (
                "docs/研发中心/任务/任务-000049.md",
                "研发中心跨载体冲突裁决与安全闭环",
                "待执行",
                "P0",
                ("000048",),
            )
        }
        repaired = CONFLICT.repair_board_text(board, records, schema)
        self.assertIn("任务-000049", repaired)
        self.assertIn("## 待执行", repaired)
        self.assertIn("## 状态维护要求", repaired)
        self.assertEqual(board.count("任务-000049"), 1)


if __name__ == "__main__":
    unittest.main()
