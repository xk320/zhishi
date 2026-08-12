import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "审计" / "重放阶段1精确冻结点数据资格决策.py"
CONFIG = ROOT / "config" / "审计" / "任务-000099阶段1精确冻结点重放.json"
SOURCE = ROOT / "artifacts" / "审计" / "阶段1逐行时间质量" / "stage1-time-quality-20260812T091000Z-6968246516ef"
FINAL_ROOT = ROOT / "artifacts" / "审计" / "阶段1事前冻结决策重放"

SPEC = importlib.util.spec_from_file_location("stage1_prior_frozen_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Stage1PriorFrozenReplayTests(unittest.TestCase):
    def test_配置与七个来源文件精确冻结(self):
        config = MODULE.load_config(CONFIG)
        self.assertEqual("000099", config["task_id"])
        self.assertEqual(config["expected_source_files"], MODULE.verify_source_files(SOURCE, config))
        self.assertEqual(1_359_574, sum(MODULE.probe_source_without_opening(ROOT, config).values()))

        with tempfile.TemporaryDirectory() as directory:
            changed = copy.deepcopy(config)
            changed["source_completed_at"] = "2099-01-01T00:00:00Z"
            path = Path(directory) / "config.json"
            path.write_text(MODULE.canonical_json(changed) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CONFIG_FINGERPRINT_INVALID"):
                MODULE.load_config(path)

    def test_prepare不打开四类来源载荷(self):
        config = MODULE.load_config(CONFIG)
        original = MODULE.sha256_file
        forbidden = {
            "members-001.json",
            "segments.json",
            "leaves.json",
            "source-rejected.json",
        }

        def guarded(path, *args, **kwargs):
            if Path(path).name in forbidden and SOURCE in Path(path).parents:
                raise AssertionError("prepare打开了禁止载荷")
            return original(path, *args, **kwargs)

        audit_parent = ROOT / "artifacts" / "审计"
        with tempfile.TemporaryDirectory(prefix="task99-prepare-", dir=audit_parent) as directory:
            output_root = Path(directory) / "output"
            with mock.patch.object(MODULE, "sha256_file", side_effect=guarded), mock.patch.object(MODULE.os, "getpid", return_value=91001):
                result = MODULE.prepare(ROOT, output_root, "stage1-prior-frozen-replay-20260812T120000Z-aaaaaaaaaaaa", config)
            intent = MODULE.load_json_strict(output_root / result["batch_id"] / "intent" / "intent.json")
            self.assertFalse(intent["source_payload_opened"])
            self.assertEqual(91001, intent["process_id"])

    def test_未来可见和跨组身份漂移失败关闭(self):
        member = self.member()
        cutoff = MODULE.parse_utc("2026-08-12T10:19:32.500000Z")
        MODULE.validate_members([member], self.single_member_config(), cutoff)
        future = dict(member, collected_at="2026-08-12T10:19:32.500001Z")
        with self.assertRaisesRegex(ValueError, "FUTURE_VISIBLE_MEMBER"):
            MODULE.validate_members([future], self.single_member_config(), cutoff)
        drift = dict(member, contract="ETHUSDT")
        with self.assertRaisesRegex(ValueError, "MEMBER_GROUP_IDENTITY_DRIFT"):
            MODULE.validate_members([drift], self.single_member_config(), cutoff)

    def test_逐级符号链接失败关闭(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            relative = link.relative_to(ROOT) / "missing"
            with self.assertRaisesRegex(ValueError, "PATH_COMPONENT_SYMLINK"):
                MODULE.checked_relative_path(ROOT, str(relative), final_kind="missing_or_directory")

    def test_最终来源漂移与资源超限不发布(self):
        config = MODULE.load_config(CONFIG)
        with tempfile.TemporaryDirectory(dir=ROOT / "artifacts" / "审计") as directory:
            batch_root = Path(directory)
            expected = config["expected_source_files"]
            drifted = dict(expected)
            drifted["summary.json"] = "f" * 64
            with mock.patch.object(MODULE, "verify_source_files", side_effect=[expected, drifted]):
                with self.assertRaisesRegex(ValueError, "SOURCE_FINAL_DRIFT"):
                    MODULE._publish_phase(
                        ROOT,
                        batch_root,
                        "decision",
                        {"decision.json": {"ok": True}},
                        MODULE.time.monotonic(),
                        config,
                        expected,
                    )
            self.assertFalse((batch_root / "decision").exists())

        tiny = copy.deepcopy(config)
        tiny["limits"]["max_output_bytes"] = 0
        with self.assertRaisesRegex(ValueError, "OUTPUT_SIZE_LIMIT_EXCEEDED"):
            MODULE._check_resources(MODULE.time.monotonic(), 1, tiny)

    def test_原子禁止替换保留晚到空目录和非空目录(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "artifacts" / "审计") as directory:
            root = Path(directory)
            for nonempty in (False, True):
                source = root / f"source-{nonempty}"
                target = root / f"target-{nonempty}"
                source.mkdir()
                (source / "new.txt").write_text("new", encoding="utf-8")
                target.mkdir()
                if nonempty:
                    (target / "sentinel.txt").write_text("old", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "OUTPUT_TARGET_EXISTS"):
                    MODULE._atomic_rename_noreplace(source, target)
                self.assertEqual("new", (source / "new.txt").read_text(encoding="utf-8"))
                self.assertTrue(target.is_dir())
                if nonempty:
                    self.assertEqual("old", (target / "sentinel.txt").read_text(encoding="utf-8"))

    def test_检查后晚到目标不会被prepare或phase覆盖(self):
        config = MODULE.load_config(CONFIG)
        original = MODULE._atomic_rename_noreplace
        audit_parent = ROOT / "artifacts" / "审计"

        with tempfile.TemporaryDirectory(dir=audit_parent) as directory:
            output_root = Path(directory) / "prepare-output"
            batch = "stage1-prior-frozen-replay-20260812T120200Z-cccccccccccc"

            def inject_prepare(source, target):
                target.mkdir()
                (target / "sentinel.txt").write_text("old", encoding="utf-8")
                return original(source, target)

            with mock.patch.object(MODULE, "_atomic_rename_noreplace", side_effect=inject_prepare):
                with self.assertRaisesRegex(ValueError, "OUTPUT_TARGET_EXISTS"):
                    MODULE.prepare(ROOT, output_root, batch, config)
            self.assertEqual("old", (output_root / batch / "sentinel.txt").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory(dir=audit_parent) as directory:
            batch_root = Path(directory)
            expected = config["expected_source_files"]

            def inject_phase(source, target):
                target.mkdir()
                (target / "sentinel.txt").write_text("old", encoding="utf-8")
                return original(source, target)

            with mock.patch.object(MODULE, "_atomic_rename_noreplace", side_effect=inject_phase):
                with self.assertRaisesRegex(ValueError, "OUTPUT_TARGET_EXISTS"):
                    MODULE._publish_phase(
                        ROOT,
                        batch_root,
                        "decision",
                        {"decision.json": {"ok": True}},
                        MODULE.time.monotonic(),
                        config,
                        expected,
                    )
            self.assertEqual("old", (batch_root / "decision" / "sentinel.txt").read_text(encoding="utf-8"))

    def test_四个独立阶段规范结果相等且目标不可覆盖(self):
        config = MODULE.load_config(CONFIG)
        audit_parent = ROOT / "artifacts" / "审计"
        batch = "stage1-prior-frozen-replay-20260812T120100Z-bbbbbbbbbbbb"
        with tempfile.TemporaryDirectory(prefix="task99-e2e-", dir=audit_parent) as directory:
            output_root = Path(directory) / "output"
            with mock.patch.object(MODULE.os, "getpid", return_value=92001):
                MODULE.prepare(ROOT, output_root, batch, config)
            with mock.patch.object(MODULE.os, "getpid", return_value=92002):
                decision_result = MODULE.decide(ROOT, output_root, batch, config)
            with mock.patch.object(MODULE.os, "getpid", return_value=92003):
                first = MODULE.replay(ROOT, output_root, batch, 1, config)
            with mock.patch.object(MODULE.os, "getpid", return_value=92004):
                second = MODULE.replay(ROOT, output_root, batch, 2, config)
            self.assertEqual(decision_result["result_sha256"], first["result_sha256"])
            self.assertEqual(first["result_sha256"], second["result_sha256"])
            decision = MODULE.load_json_strict(output_root / batch / "decision" / "decision.json")
            self.assertEqual(5180, decision["result"]["counts"]["formal_member_count"])
            self.assertEqual(391, decision["result"]["counts"]["quality_rejected_count"])
            self.assertEqual(207, decision["result"]["counts"]["source_rejected_count"])
            self.assertEqual(175, decision["result"]["counts"]["segment_count"])
            self.assertEqual(8, len(decision["result"]["leaves"]))
            self.assertFalse(decision["stage1_complete"])
            with mock.patch.object(MODULE.os, "getpid", return_value=92005):
                with self.assertRaisesRegex(ValueError, "OUTPUT_PHASE_EXISTS"):
                    MODULE.replay(ROOT, output_root, batch, 1, config)

    def test_四个真实子进程按发布标记严格排序(self):
        batch = "stage1-prior-frozen-replay-20260812T120300Z-dddddddddddd"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "repo"
            paths = [
                SCRIPT.relative_to(ROOT),
                CONFIG.relative_to(ROOT),
                Path("docs/数据/阶段1精确输入冻结点与同版本重放合同.md"),
                Path("docs/研发中心/任务/任务-000099.md"),
            ]
            for relative in paths:
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            source_relative = SOURCE.relative_to(ROOT)
            shutil.copytree(SOURCE, fixture / source_relative)
            output_root = fixture / "artifacts" / "审计" / "阶段1事前冻结决策重放"
            output_root.parent.mkdir(parents=True, exist_ok=True)
            common = [
                sys.executable,
                str(fixture / SCRIPT.relative_to(ROOT)),
                "--config",
                str(fixture / CONFIG.relative_to(ROOT)),
                "--repo-root",
                str(fixture),
                "--output-root",
                str(output_root),
                "--batch-id",
                batch,
            ]
            commands = [
                [*common, "--mode", "prepare"],
                [*common, "--mode", "decide"],
                [*common, "--mode", "replay", "--slot", "1"],
                [*common, "--mode", "replay", "--slot", "2"],
            ]
            for command in commands:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

            root = output_root / batch
            intent = MODULE.load_json_strict(root / "intent" / "intent.json")
            decision = MODULE.load_json_strict(root / "decision" / "decision.json")
            first = MODULE.load_json_strict(root / "replay-1" / "replay.json")
            second = MODULE.load_json_strict(root / "replay-2" / "replay.json")
            self.assertEqual(4, len({intent["process_id"], decision["process_id"], first["process_id"], second["process_id"]}))
            self.assertLess(
                MODULE.parse_utc(MODULE.load_json_strict(root / "intent-published.json")["published_at"]),
                MODULE.parse_utc(decision["process_started_at"]),
            )
            self.assertLess(
                MODULE.parse_utc(MODULE.load_json_strict(root / "decision-published.json")["published_at"]),
                MODULE.parse_utc(first["process_started_at"]),
            )
            self.assertLess(
                MODULE.parse_utc(MODULE.load_json_strict(root / "replay-1-published.json")["published_at"]),
                MODULE.parse_utc(second["process_started_at"]),
            )

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

    def test_正式批次存在时四阶段身份与资源通过(self):
        if not FINAL_ROOT.exists():
            self.skipTest("真实批次在专项实现完成后生成")
        batches = sorted(path for path in FINAL_ROOT.iterdir() if path.is_dir())
        self.assertGreaterEqual(len(batches), 1)
        batch = batches[-1]
        intent = MODULE.load_json_strict(batch / "intent" / "intent.json")
        decision = MODULE.load_json_strict(batch / "decision" / "decision.json")
        first = MODULE.load_json_strict(batch / "replay-1" / "replay.json")
        second = MODULE.load_json_strict(batch / "replay-2" / "replay.json")
        self.assertLess(MODULE.parse_utc(intent["data_cutoff_at"]), MODULE.parse_utc(decision["decision_at"]))
        self.assertEqual(decision["result_sha256"], first["result_sha256"])
        self.assertEqual(first["result_sha256"], second["result_sha256"])
        self.assertEqual(4, len({intent["process_id"], decision["process_id"], first["process_id"], second["process_id"]}))
        self.assertEqual(4, len({intent["process_run_id"], decision["process_run_id"], first["process_run_id"], second["process_run_id"]}))
        self.assertEqual(MODULE.sha256_file(SCRIPT), intent["executor_sha256"])
        self.assertEqual(MODULE.sha256_file(CONFIG), intent["config_file_sha256"])
        self.assertEqual(MODULE.task_contract_sha256(ROOT / "docs" / "研发中心" / "任务" / "任务-000099.md"), intent["task_contract_sha256"])
        intent_published = MODULE.load_json_strict(batch / "intent-published.json")
        decision_published = MODULE.load_json_strict(batch / "decision-published.json")
        first_published = MODULE.load_json_strict(batch / "replay-1-published.json")
        self.assertLess(MODULE.parse_utc(intent_published["published_at"]), MODULE.parse_utc(decision["process_started_at"]))
        self.assertLess(MODULE.parse_utc(decision_published["published_at"]), MODULE.parse_utc(first["process_started_at"]))
        self.assertLess(MODULE.parse_utc(first_published["published_at"]), MODULE.parse_utc(second["process_started_at"]))
        for phase in ("intent", "decision", "replay-1", "replay-2"):
            receipt = MODULE.load_json_strict(batch / phase / "resource.json")
            self.assertTrue(receipt["final_resource_gate_enforced_after_receipt_readback"])
            completion = MODULE.load_json_strict(batch / phase / "completion.json")
            self.assertTrue(completion["completion_marker_required"])
            self.assertEqual(
                sum(path.stat().st_size for path in (batch / phase).iterdir()),
                completion["published_bytes"],
            )
            self.assertTrue(completion["final_gate_rechecked_after_completion_readback"])
            self.assertLessEqual(completion["final_precommit_resource_facts"]["process_max_rss_bytes"], 512 * 1024 * 1024)

    @staticmethod
    def member():
        return {
            "collected_at": "2026-08-12T10:19:32.400000Z",
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
