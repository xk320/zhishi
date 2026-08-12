import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "审计" / "重放阶段1同版本数据资格决策.py"
CONFIG = ROOT / "config" / "审计" / "任务-000098阶段1同版本历史重放.json"
SOURCE = ROOT / "artifacts" / "审计" / "阶段1逐行时间质量" / "stage1-time-quality-20260812T091000Z-6968246516ef"
FINAL_ROOT = ROOT / "artifacts" / "审计" / "阶段1同版本历史重放"

SPEC = importlib.util.spec_from_file_location("stage1_versioned_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Stage1VersionedReplayTests(unittest.TestCase):
    def test_配置与七个来源文件精确冻结(self):
        config = MODULE.load_config(CONFIG)
        files = MODULE.verify_source_files(SOURCE, config)
        self.assertEqual(config["expected_source_files"], files)
        self.assertEqual("000098", config["task_id"])

        with tempfile.TemporaryDirectory() as directory:
            changed = copy.deepcopy(config)
            changed["decision_at"] = "2099-01-01T00:00:00Z"
            path = Path(directory) / "config.json"
            path.write_text(MODULE.canonical_json(changed) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CONFIG_FINGERPRINT_INVALID"):
                MODULE.load_config(path)

    def test_重复键和列式索引漂移失败关闭(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON_DUPLICATE_KEY"):
                MODULE.load_json_strict(path)

        table = {
            "schema_version": "zhishi-record-table/v1",
            "columns": ["status"],
            "dictionaries": {"status": ["已证明"]},
            "rows": [[1]],
        }
        with self.assertRaisesRegex(ValueError, "RECORD_TABLE_INDEX_INVALID"):
            MODULE.decode_record_table(table)

    def test_未来可见和跨组身份漂移失败关闭(self):
        config = MODULE.load_config(CONFIG)
        member = self.member()
        MODULE.validate_members([member], self.single_member_config(), MODULE.parse_utc(config["decision_at"]))

        future = dict(member, source_visible_at="2026-08-12T10:19:33Z")
        with self.assertRaisesRegex(ValueError, "FUTURE_VISIBLE_MEMBER"):
            MODULE.validate_members([future], self.single_member_config(), MODULE.parse_utc(config["decision_at"]))

        drift = dict(member, contract="ETHUSDT")
        with self.assertRaisesRegex(ValueError, "MEMBER_GROUP_IDENTITY_DRIFT"):
            MODULE.validate_members([drift], self.single_member_config(), MODULE.parse_utc(config["decision_at"]))

    def test_八叶子只更新历史重放门(self):
        config = MODULE.load_config(CONFIG)
        leaves = MODULE.load_json_strict(SOURCE / "leaves.json")
        updated = MODULE.update_replay_gate(leaves, config)
        self.assertEqual(8, len(updated))
        for leaf in updated:
            self.assertEqual("通过", leaf["gates"]["历史重放"]["status"])
            self.assertEqual("无法判定", leaf["gates"]["成本与执行"]["status"])
            self.assertEqual("无法判定", leaf["gates"]["容量"]["status"])
            self.assertEqual("无法判定", leaf["gates"]["恢复"]["status"])
            self.assertEqual("阻塞", leaf["decision"])

    def test_两次独立重放逐字节相等并保留全部分母(self):
        config = MODULE.load_config(CONFIG)
        first = MODULE.replay_once(ROOT, config)
        second = MODULE.replay_once(ROOT, config)
        first_bytes = MODULE.canonical_json(first).encode("utf-8") + b"\n"
        second_bytes = MODULE.canonical_json(second).encode("utf-8") + b"\n"
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(5180, first["counts"]["formal_member_count"])
        self.assertEqual(391, first["counts"]["quality_rejected_count"])
        self.assertEqual(207, first["counts"]["source_rejected_count"])
        self.assertEqual(175, first["counts"]["segment_count"])
        self.assertEqual(8, len(first["leaves"]))
        self.assertFalse(first["stage1_complete"])
        self.assertFalse(first["stage2_released"])

    def test_正式批次满足资源安全和身份合同(self):
        if not FINAL_ROOT.exists():
            self.skipTest("真实批次在专项实现完成后生成")
        batches = sorted(path for path in FINAL_ROOT.iterdir() if path.is_dir())
        self.assertEqual(1, len(batches))
        summary = MODULE.load_json_strict(batches[0] / "summary.json")
        self.assertEqual("已证明", summary["status"])
        self.assertTrue(summary["replays_byte_identical"])
        self.assertEqual(summary["first_replay_sha256"], summary["second_replay_sha256"])
        self.assertLessEqual(summary["resource_facts"]["process_max_rss_bytes"], 512 * 1024 * 1024)
        self.assertLessEqual(summary["resource_facts"]["output_bytes"], 25 * 1024 * 1024)
        self.assertFalse(summary["source_data_modified"])

    @staticmethod
    def member():
        return {
            "collected_at": "2026-08-12T09:14:02Z",
            "contract": "BTCUSDT",
            "dataset": "trades",
            "event_date": "2026-08-01",
            "first_event_time_ms": 1,
            "group": "BTCUSDT-trades",
            "last_event_time_ms": 2,
            "member_id": "BTCUSDT:trades:one.zip",
            "member_identity_sha256": "a" * 64,
            "reason_codes": "",
            "row_count": 1,
            "source_visible_at": "2026-08-02T00:00:00Z",
            "status": "已证明",
            "uncompressed_bytes": 1,
            "underlying": "BTC",
        }

    @staticmethod
    def single_member_config():
        return {
            "allowed_groups": {
                "BTCUSDT-trades": {
                    "contract": "BTCUSDT",
                    "dataset": "trades",
                    "formal_member_count": 1,
                    "quality_proved_count": 1,
                    "quality_rejected_count": 0,
                    "underlying": "BTC",
                }
            },
            "expected_counts": {
                "audited_member_count": 1,
                "quality_proved_count": 1,
                "quality_rejected_count": 0,
                "scanned_row_count": 1,
                "uncompressed_bytes": 1,
            },
            "limits": {"max_member_count": 2},
        }


if __name__ == "__main__":
    unittest.main()
