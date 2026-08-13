import importlib.util
import json
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts/审计/审计阶段1数据缺失.py"
SPEC = importlib.util.spec_from_file_location("stage1_missing_audit", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class Stage1MissingAuditTests(unittest.TestCase):
    def test_real_redacted_batch_is_recomputed_without_source_audit(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-missing-audit-") as directory:
            output = MODULE.run(
                REPO_ROOT,
                REPO_ROOT / "config/审计/任务-000084数据缺失审计.json",
                pathlib.Path(directory),
                batch_id="test-batch",
            )
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            groups = json.loads((output / "groups.json").read_text(encoding="utf-8"))
            leaves = json.loads((output / "leaves.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["source_identity_audit_performed"])
            self.assertTrue(summary["source_identity_fact_reused"])
            self.assertEqual(summary["candidate_total"], 5387)
            self.assertEqual(summary["formal_member_count"], 5180)
            self.assertEqual(summary["source_rejected_count"], 207)
            self.assertEqual(summary["formal_status_counts"], {"已证明": 4789, "拒绝": 391, "无法判定": 0, "失败": 0, "未成熟": 0, "失效": 0})
            self.assertEqual(summary["status_counts"], {"已证明": 4789, "拒绝": 598, "无法判定": 0, "失败": 0, "未成熟": 0, "失效": 0})
            self.assertEqual(len(groups), 3)
            self.assertEqual(len(leaves), 8)
            self.assertGreater(summary["missing_date_count"], 0)
            self.assertEqual(sum(group["candidate_total"] for group in groups), 5387)
            self.assertEqual(sum(group["source_rejected_count"] for group in groups), 207)
            self.assertEqual({leaf["underlying"]: leaf["source_rejected_count"] for leaf in leaves}, {"BTC": 8, "ETH": 199})
            self.assertTrue(all(leaf["continuous_segment_count"] > 0 for leaf in leaves))

    def test_date_ranges_are_compressed_deterministically(self):
        self.assertEqual(
            MODULE.compress_dates(["2026-01-03", "2026-01-01", "2026-01-02", "2026-01-05"]),
            [
                {"start_date": "2026-01-01", "end_date": "2026-01-03", "day_count": 3},
                {"start_date": "2026-01-05", "end_date": "2026-01-05", "day_count": 1},
            ],
        )

    def test_input_fingerprint_drift_fails_safe(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-missing-audit-config-") as directory:
            config_path = pathlib.Path(directory) / "config.json"
            config = json.loads((REPO_ROOT / "config/审计/任务-000084数据缺失审计.json").read_text(encoding="utf-8"))
            config["inputs"]["summary.json"] = "0" * 64
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(MODULE.AuditError) as context:
                MODULE.run(REPO_ROOT, config_path, pathlib.Path(directory), batch_id="never-created")
            self.assertIn("INPUT_FINGERPRINT_DRIFT:summary.json", str(context.exception))


if __name__ == "__main__":
    unittest.main()
