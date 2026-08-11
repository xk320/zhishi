import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "审计" / "重算阶段1新候选集门禁.py"
CONFIG = ROOT / "config" / "审计" / "任务-000093阶段1新候选集重算.json"
SOURCE_BATCH = ROOT / "artifacts" / "数据" / "Binance历史归档来源身份" / "binance-archive-provenance-20260811T063739Z-7a6da0087493"
BATCH = ROOT / "artifacts" / "审计" / "阶段1新候选集重算" / "stage1-candidate-recompute-20260811T131000Z-c88fa0502d54"
SPEC = importlib.util.spec_from_file_location("stage1_candidate_recompute", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Stage1CandidateRecomputeTests(unittest.TestCase):
    def test_执行器入口存在(self):
        self.assertTrue(SCRIPT.is_file(), "任务-000093执行器尚未实现")

    def test_只采纳已证明成员并保留原分母(self):
        records = [
            self.member("BTCUSDT-trades", "BTCUSDT-trades-2024-01-01.zip", "已证明", "a" * 64),
            self.member("BTCUSDT-trades", "BTCUSDT-trades-2024-01-02.zip", "拒绝", "b" * 64),
            self.member("ETHUSDT-trades", "ETHUSDT-trades-2024-01-01.zip", "已证明", "c" * 64),
        ]
        accepted, summary = MODULE.select_formal_members(records, self.groups())
        self.assertEqual(2, len(accepted))
        self.assertEqual(["BTCUSDT-trades-2024-01-01.zip", "ETHUSDT-trades-2024-01-01.zip"], [item["relative_name"] for item in accepted])
        self.assertEqual({"candidate_total": 3, "已证明": 2, "拒绝": 1, "无法判定": 0, "失败": 0, "未成熟": 0, "失效": 0}, summary["totals"])

    def test_重复成员和未知组失败安全(self):
        member = self.member("BTCUSDT-trades", "BTCUSDT-trades-2024-01-01.zip", "已证明", "a" * 64)
        with self.assertRaisesRegex(ValueError, "DUPLICATE_MEMBER"):
            MODULE.select_formal_members([member, dict(member)], self.groups())
        with self.assertRaisesRegex(ValueError, "UNKNOWN_GROUP"):
            MODULE.select_formal_members([self.member("SOLUSDT-trades", "SOLUSDT-trades-2024-01-01.zip", "已证明", "d" * 64)], self.groups())

    def test_单成员ZIP全流观察首末事件时间(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = Path("trades/BTCUSDT/BTCUSDT-trades-2024-01-01.zip")
            path = root / relative
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "BTCUSDT-trades-2024-01-01.csv",
                    "1,42000,0.1,4200,1704067200000,false\n"
                    "2,42100,0.2,8420,1704153599999,true\n",
                )
            sha = MODULE.sha256_file(path)
            member = self.member("BTCUSDT-trades", path.name, "已证明", sha)
            member["size_bytes"] = path.stat().st_size
            fact = MODULE.inspect_formal_member(root, self.groups()["BTCUSDT-trades"], member, 1024)
            self.assertEqual("已观察", fact["status"])
            self.assertEqual(1704067200000, fact["first_event_time_ms"])
            self.assertEqual(1704153599999, fact["last_event_time_ms"])
            self.assertEqual(2, fact["row_count"])
            self.assertNotIn("price", json.dumps(fact))
            self.assertNotIn("42000", json.dumps(fact))

    def test_微秒事件时间规范化为毫秒(self):
        self.assertEqual(1735689600123, MODULE.normalize_event_time_ms("1735689600123456"))
        self.assertEqual(1735689600123, MODULE.normalize_event_time_ms("1735689600123"))

    def test_带表头归档跳过表头后观察事件时间(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = Path("aggTrades/BTCUSDT/BTCUSDT-aggTrades-2024-01-01.zip")
            path = root / relative
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "BTCUSDT-aggTrades-2024-01-01.csv",
                    "agg_trade_id,price,quantity,first_trade_id,last_trade_id,transact_time,is_buyer_maker\n"
                    "1,42000,0.1,1,1,1704067200000,false\n",
                )
            member = self.member("BTCUSDT-aggTrades", path.name, "已证明", MODULE.sha256_file(path))
            member["size_bytes"] = path.stat().st_size
            member["schema"]["header_present"] = True
            fact = MODULE.inspect_formal_member(root, self.agg_group(), member, 1024)
            self.assertEqual(1, fact["row_count"])
            self.assertEqual(1704067200000, fact["first_event_time_ms"])

    def test_路径越界和内容漂移被拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            member = self.member("BTCUSDT-trades", "../outside.zip", "已证明", "a" * 64)
            with self.assertRaisesRegex(ValueError, "PATH_REJECTED"):
                MODULE.resolve_member_path(root, self.groups()["BTCUSDT-trades"], member)
            path = root / "trades/BTCUSDT/BTCUSDT-trades-2024-01-01.zip"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"drift")
            member = self.member("BTCUSDT-trades", path.name, "已证明", "a" * 64)
            member["size_bytes"] = path.stat().st_size
            with self.assertRaisesRegex(ValueError, "CONTENT_SHA_DRIFT"):
                MODULE.verify_file_identity(root, self.groups()["BTCUSDT-trades"], member)

    def test_固定数据根和相对路径任一级符号链接均被拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            path = target / "trades/BTCUSDT/BTCUSDT-trades-2024-01-01.zip"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"data")
            member = self.member("BTCUSDT-trades", path.name, "已证明", MODULE.sha256_file(path))
            member["size_bytes"] = path.stat().st_size
            linked_root = base / "linked-root"
            linked_root.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "SOURCE_PATH_SYMLINK_REJECTED"):
                MODULE.resolve_member_path(linked_root, self.groups()["BTCUSDT-trades"], member)

            ordinary_root = base / "ordinary-root"
            ordinary_root.mkdir()
            (ordinary_root / "trades").symlink_to(target / "trades", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "SOURCE_PATH_SYMLINK_REJECTED"):
                MODULE.resolve_member_path(ordinary_root, self.groups()["BTCUSDT-trades"], member)

    def test_配置完整冻结且任何字段漂移失败安全(self):
        valid = MODULE.load_config(CONFIG)
        self.assertEqual("000093", valid["task_id"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            changed = dict(valid)
            changed["local_root"] = "/tmp/unapproved-root"
            path.write_text(json.dumps(changed, ensure_ascii=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CONFIG_FINGERPRINT_INVALID"):
                MODULE.load_config(path)

    def test_来源批次完整文件集合必须在读取前匹配固定指纹(self):
        config = MODULE.load_config(CONFIG)
        files = MODULE.verify_source_batch_files(
            SOURCE_BATCH,
            expected_fingerprint=config["source_batch_files_fingerprint"],
            max_files=config["limits"]["source_member_count"],
            max_file_bytes=config["limits"]["single_source_file_bytes"],
        )
        self.assertIn("summary.json", files)
        with tempfile.TemporaryDirectory() as directory:
            batch = Path(directory)
            (batch / "summary.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SOURCE_BATCH_FILES_FINGERPRINT_DRIFT"):
                MODULE.verify_source_batch_files(
                    batch,
                    expected_fingerprint="0" * 64,
                    max_files=10,
                    max_file_bytes=1024,
                )

    def test_资源探针失败与硬门超限均失败安全(self):
        with mock.patch.object(MODULE.subprocess, "run", side_effect=OSError), mock.patch.object(
            MODULE.Path, "read_text", side_effect=OSError
        ):
            self.assertEqual(0.0, MODULE._memory_available_percent())
        limits = {
            "min_available_memory_percent": 20,
            "min_free_disk_bytes": 5 * 1024**3,
            "memory_bytes": 256 * 1024**2,
        }
        snapshot = {
            "memory_available_percent": 100.0,
            "output_disk_free_bytes": 10 * 1024**3,
            "process_max_rss_bytes": 100 * 1024**2,
        }
        MODULE.assert_resource_limits(snapshot, limits)
        for field, value, reason in (
            ("memory_available_percent", 0.0, "MEMORY_HEADROOM_INSUFFICIENT"),
            ("output_disk_free_bytes", 0, "DISK_HEADROOM_INSUFFICIENT"),
            ("process_max_rss_bytes", 300 * 1024**2, "PROCESS_MEMORY_LIMIT_EXCEEDED"),
        ):
            changed = dict(snapshot)
            changed[field] = value
            with self.assertRaisesRegex(ValueError, reason):
                MODULE.assert_resource_limits(changed, limits)
        with self.assertRaisesRegex(TimeoutError, "TOTAL_TIME_LIMIT_EXCEEDED"):
            MODULE.assert_time_limit(MODULE.time.monotonic() - 2, {"total_seconds": 1})

    def test_单源文件超过固定上限时在哈希前拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "trades/BTCUSDT/BTCUSDT-trades-2024-01-01.zip"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"oversized")
            member = self.member("BTCUSDT-trades", path.name, "已证明", MODULE.sha256_file(path))
            member["size_bytes"] = path.stat().st_size
            with self.assertRaisesRegex(ValueError, "SOURCE_FILE_SIZE_LIMIT_EXCEEDED"):
                MODULE.verify_file_identity(
                    root,
                    self.groups()["BTCUSDT-trades"],
                    member,
                    max_file_bytes=path.stat().st_size - 1,
                )

    def test_八叶子完整且未知硬门阻塞(self):
        leaves = MODULE.build_gate_leaves(
            accepted_counts={"BTC": 10, "ETH": 8},
            observations={"BTC": {"observed": 10}, "ETH": {"observed": 8}},
        )
        self.assertEqual(8, len(leaves))
        self.assertEqual({("BTC", 4), ("BTC", 8), ("BTC", 24), ("BTC", 48), ("ETH", 4), ("ETH", 8), ("ETH", 24), ("ETH", 48)}, {(item["underlying"], item["horizon_hours"]) for item in leaves})
        for leaf in leaves:
            self.assertEqual("通过", leaf["gates"]["来源身份"]["status"])
            self.assertEqual("无法判定", leaf["gates"]["三类时间"]["status"])
            self.assertEqual("阻塞", leaf["decision"])
            for gate in leaf["gates"].values():
                self.assertTrue(gate["evidence_refs"])
                self.assertTrue(gate["release_conditions"])

    def test_追加式发布禁止覆盖(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = MODULE.atomic_publish(root, "batch-1", {"summary.json": "{}\n"}, max_file_bytes=1024, max_total_bytes=2048)
            self.assertTrue((target / "summary.json").is_file())
            with self.assertRaises(FileExistsError):
                MODULE.atomic_publish(root, "batch-1", {"summary.json": "{}\n"}, max_file_bytes=1024, max_total_bytes=2048)

    def test_JSON分片按增量字节生成且保持规范序列化(self):
        records = [{"id": index, "value": "x" * 20} for index in range(5)]
        shards = MODULE._json_shards(records, "items", 90)
        rebuilt = []
        for name, content in sorted(shards.items()):
            self.assertLessEqual(len(content.encode("utf-8")), 90, name)
            rebuilt.extend(json.loads(content))
        self.assertEqual(records, rebuilt)

    def test_真实批次分母指纹资源与八叶子闭合(self):
        summary = json.loads((BATCH / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(5387, summary["denominator"]["totals"]["candidate_total"])
        self.assertEqual(5180, summary["formal_member_count"])
        self.assertEqual(207, summary["denominator"]["totals"]["拒绝"])
        self.assertEqual(5180, summary["observed_member_count"])
        self.assertEqual(0, summary["inspection_failure_count"])
        self.assertFalse(summary["stage1_complete"])
        self.assertFalse(summary["stage2_released"])
        self.assertFalse(summary["legacy_task_000084_current_gate"])
        self.assertEqual(summary["source_inventory_before_sha256"], summary["source_inventory_after_sha256"])
        self.assertLessEqual(summary["resource_facts"]["completed"]["process_max_rss_bytes"], 256 * 1024 * 1024)
        leaves = json.loads((BATCH / "leaves.json").read_text(encoding="utf-8"))
        self.assertEqual(8, len(leaves))
        self.assertTrue(all(item["decision"] == "阻塞" for item in leaves))

    def test_真实批次正式成员唯一有序且不保存业务值字段(self):
        formal = []
        observations = []
        for path in sorted(BATCH.glob("formal-input-*.json")):
            formal.extend(json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(BATCH.glob("member-observations-*.json")):
            observations.extend(json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(5180, len(formal))
        self.assertEqual(5180, len({item["member_id"] for item in formal}))
        self.assertEqual(5180, len(observations))
        self.assertEqual([], json.loads((BATCH / "inspection-failures.json").read_text(encoding="utf-8")))
        forbidden = {"price", "quantity", "qty", "trade_id", "agg_trade_id"}
        self.assertFalse(forbidden.intersection({key for item in observations for key in item}))
        self.assertLess(sum(path.stat().st_size for path in BATCH.iterdir() if path.is_file()), 25 * 1024 * 1024)
        self.assertTrue(all(path.stat().st_size < 5 * 1024 * 1024 for path in BATCH.iterdir() if path.is_file()))

    def test_真实覆盖按组保留缺日(self):
        coverage = json.loads((BATCH / "coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(0, coverage["BTCUSDT-aggTrades"]["missing_date_count"])
        self.assertEqual(8, coverage["BTCUSDT-trades"]["missing_date_count"])
        self.assertEqual(199, coverage["ETHUSDT-trades"]["missing_date_count"])

    @staticmethod
    def groups():
        return {
            "BTCUSDT-trades": {"id": "BTCUSDT-trades", "underlying": "BTC", "contract": "BTCUSDT", "dataset": "trades", "relative_dir": "trades/BTCUSDT"},
            "ETHUSDT-trades": {"id": "ETHUSDT-trades", "underlying": "ETH", "contract": "ETHUSDT", "dataset": "trades", "relative_dir": "trades/ETHUSDT"},
        }

    @staticmethod
    def agg_group():
        return {"id": "BTCUSDT-aggTrades", "underlying": "BTC", "contract": "BTCUSDT", "dataset": "aggTrades", "relative_dir": "aggTrades/BTCUSDT"}

    @staticmethod
    def member(group, relative_name, status, content_sha):
        contract, dataset = group.split("-", 1)
        return {
            "group": group,
            "underlying": "BTC" if contract.startswith("BTC") else "ETH",
            "contract": contract,
            "dataset": dataset,
            "relative_name": relative_name,
            "member_id": f"{contract}:{dataset}:{relative_name}",
            "status": status,
            "content_sha256": content_sha,
            "size_bytes": 1,
            "schema": {"schema_version": "sha256:" + "e" * 64},
        }


if __name__ == "__main__":
    unittest.main()
