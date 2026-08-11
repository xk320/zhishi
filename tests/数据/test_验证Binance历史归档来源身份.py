import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "数据" / "验证Binance历史归档来源身份.py"
SPEC = importlib.util.spec_from_file_location("binance_archive_provenance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class BinanceArchiveProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_pair(self, name="BTCUSDT-trades-2024-01-01.zip", rows=None):
        rows = rows or b"1,100.0,0.1,10.0,1704067200000,true\n"
        path = self.root / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(name.removesuffix(".zip") + ".csv", rows)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksum = path.with_name(path.name + ".CHECKSUM")
        checksum.write_text(f"{digest}  {path.name}\n", encoding="ascii")
        return path, checksum, digest

    def test_parse_checksum_requires_exact_lowercase_hash_and_filename(self):
        archive, checksum, digest = self.make_pair()
        self.assertEqual(digest, MODULE.parse_checksum(checksum, archive.name))
        checksum.write_text(f"{digest.upper()}  {archive.name}\n", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "CHECKSUM_FORMAT_INVALID"):
            MODULE.parse_checksum(checksum, archive.name)

    def test_streaming_hash_matches_content(self):
        archive, _, digest = self.make_pair()
        self.assertEqual(digest, MODULE.sha256_file(archive, chunk_size=17))

    def test_discovery_rejects_hidden_resource_forks_and_orphans(self):
        archive, checksum, _ = self.make_pair()
        (self.root / f"._{archive.name}").write_bytes(b"resource fork")
        (self.root / "BTCUSDT-trades-2024-01-02.zip").write_bytes(b"orphan")
        result = MODULE.discover_group(
            self.root, "BTCUSDT", "trades", max_entries=20
        )
        self.assertEqual(((archive, checksum),), result.members)
        self.assertEqual(
            ["HIDDEN_FILE_REJECTED", "PAIR_MISSING"],
            sorted(item.code for item in result.exclusions),
        )

    def test_discovery_stops_before_unbounded_directory_aggregation(self):
        for index in range(4):
            (self.root / f"unknown-{index}").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "DIRECTORY_ENTRY_LIMIT_EXCEEDED"):
            MODULE.discover_group(
                self.root, "BTCUSDT", "trades", max_entries=3
            )

    def test_inventory_stops_before_unbounded_row_aggregation(self):
        source = self.root / "source"
        source.mkdir()
        for index in range(4):
            (source / f"item-{index}").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "INVENTORY_ENTRY_LIMIT_EXCEEDED"):
            MODULE.inventory_fingerprint(
                [source], self.root, max_entries=4
            )

    def test_zip_inspection_rejects_traversal_and_returns_schema(self):
        archive, _, _ = self.make_pair()
        schema = MODULE.inspect_zip(
            archive, "BTCUSDT-trades-2024-01-01.csv", max_sample_bytes=1024
        )
        self.assertEqual(6, schema["column_count"])
        self.assertFalse(schema["header_present"])
        bad = self.root / "BTCUSDT-trades-2024-01-02.zip"
        with zipfile.ZipFile(bad, "w") as item:
            item.writestr("../escape.csv", b"x")
        with self.assertRaisesRegex(ValueError, "ZIP_MEMBER_INVALID"):
            MODULE.inspect_zip(
                bad, "BTCUSDT-trades-2024-01-02.csv", max_sample_bytes=1024
            )

    def test_zip_schema_sample_does_not_require_small_csv(self):
        rows = b"1,100.0,0.1,10.0,1704067200000,true\n" * 60000
        archive, _, _ = self.make_pair(rows=rows)
        schema = MODULE.inspect_zip(
            archive, "BTCUSDT-trades-2024-01-01.csv", max_sample_bytes=1024
        )
        self.assertEqual(6, schema["column_count"])
        self.assertGreater(schema["uncompressed_size"], 1024)

    def test_s3_page_is_prefix_bounded_and_deterministic(self):
        xml = b"""<?xml version='1.0' encoding='UTF-8'?>
<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>
<IsTruncated>true</IsTruncated>
<Contents><Key>data/futures/um/daily/trades/BTCUSDT/a.zip</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>\"abc\"</ETag><Size>12</Size></Contents>
</ListBucketResult>"""
        page = MODULE.parse_s3_page(
            xml, "data/futures/um/daily/trades/BTCUSDT/"
        )
        self.assertTrue(page.truncated)
        self.assertEqual("data/futures/um/daily/trades/BTCUSDT/a.zip", page.next_marker)
        self.assertEqual(12, page.objects[0].size)

    def test_member_requires_size_checksum_etag_and_schema(self):
        archive, checksum, digest = self.make_pair()
        prefix = "data/futures/um/daily/trades/BTCUSDT/"
        objects = {
            prefix + archive.name: MODULE.RemoteObject(
                prefix + archive.name, archive.stat().st_size, "multipart-etag", "t"
            ),
            prefix + checksum.name: MODULE.RemoteObject(
                prefix + checksum.name,
                checksum.stat().st_size,
                hashlib.md5(checksum.read_bytes(), usedforsecurity=False).hexdigest(),
                "t",
            ),
        }
        record = MODULE.validate_member(
            archive,
            checksum,
            expected_contract="BTCUSDT",
            dataset="trades",
            remote_prefix=prefix,
            remote_objects=objects,
            max_sample_bytes=1024,
            max_archive_bytes=1024 * 1024,
        )
        self.assertEqual("已证明", record["status"])
        self.assertEqual(digest, record["content_sha256"])
        self.assertEqual("BTC", record["source_identity"]["underlying"])
        self.assertEqual(archive.stat().st_size, record["remote_evidence"]["zip_size_bytes"])
        self.assertEqual(
            hashlib.md5(checksum.read_bytes(), usedforsecurity=False).hexdigest(),
            record["remote_evidence"]["checksum_etag"],
        )
        self.assertEqual(
            hashlib.sha256(checksum.read_bytes()).hexdigest(),
            record["local_evidence"]["checksum_file_sha256"],
        )
        objects[prefix + checksum.name] = MODULE.RemoteObject(
            prefix + checksum.name, checksum.stat().st_size, "wrong", "t"
        )
        rejected = MODULE.validate_member(
            archive,
            checksum,
            expected_contract="BTCUSDT",
            dataset="trades",
            remote_prefix=prefix,
            remote_objects=objects,
            max_sample_bytes=1024,
            max_archive_bytes=1024 * 1024,
        )
        self.assertEqual("拒绝", rejected["status"])
        self.assertIn("REMOTE_CHECKSUM_ETAG_MISMATCH", rejected["reason_codes"])

    def test_member_io_error_is_a_structured_failure(self):
        archive, checksum, _ = self.make_pair()
        with mock.patch.object(MODULE, "sha256_file", side_effect=OSError("denied")):
            record = MODULE.validate_member(
                archive,
                checksum,
                expected_contract="BTCUSDT",
                dataset="trades",
                remote_prefix="data/futures/um/daily/trades/BTCUSDT/",
                remote_objects={},
                max_sample_bytes=1024,
                max_archive_bytes=1024 * 1024,
            )
        self.assertEqual("失败", record["status"])
        self.assertIn("MEMBER_IO_FAILED", record["reason_codes"])

    def test_member_stat_race_is_a_structured_failure(self):
        archive, checksum, _ = self.make_pair()
        with mock.patch.object(Path, "stat", side_effect=OSError("gone")):
            record = MODULE.validate_member(
                archive,
                checksum,
                expected_contract="BTCUSDT",
                dataset="trades",
                remote_prefix="data/futures/um/daily/trades/BTCUSDT/",
                remote_objects={},
                max_sample_bytes=1024,
                max_archive_bytes=1024 * 1024,
            )
        self.assertEqual("失败", record["status"])
        self.assertIn("MEMBER_IO_FAILED", record["reason_codes"])

    def test_member_size_limit_is_inside_structured_validation(self):
        archive, checksum, _ = self.make_pair()
        record = MODULE.validate_member(
            archive,
            checksum,
            expected_contract="BTCUSDT",
            dataset="trades",
            remote_prefix="data/futures/um/daily/trades/BTCUSDT/",
            remote_objects={},
            max_sample_bytes=1024,
            max_archive_bytes=1,
        )
        self.assertEqual("拒绝", record["status"])
        self.assertIn("SOURCE_FILE_TOO_LARGE", record["reason_codes"])

    def test_curl_arguments_are_fixed_and_do_not_follow_redirects(self):
        args = MODULE.build_s3_curl_args(
            "/usr/bin/curl",
            "https://s3-ap-northeast-1.amazonaws.com/data.binance.vision",
            "data/futures/um/daily/trades/BTCUSDT/",
            marker="key one",
        )
        self.assertNotIn("--location", args)
        self.assertNotIn("--insecure", args)
        self.assertIn("prefix=data/futures/um/daily/trades/BTCUSDT/", args)
        self.assertIn("marker=key one", args)

    def test_curl_reader_stops_while_response_exceeds_limit(self):
        payload = self.root / "large-response.bin"
        payload.write_bytes(b"x" * 2048)
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=AssertionError("响应读取不得使用事后无界缓冲"),
        ):
            with self.assertRaisesRegex(ValueError, "REMOTE_RESPONSE_TOO_LARGE"):
                MODULE._run_curl(
                    ["/usr/bin/curl", "--silent", payload.as_uri()],
                    limit=1024,
                    timeout=2,
                )

    def test_atomic_publish_refuses_overwrite(self):
        target = MODULE.atomic_publish(
            self.root, "batch-1", {"summary.json": json.dumps({"ok": True})}
        )
        self.assertTrue((target / "summary.json").is_file())
        with self.assertRaisesRegex(FileExistsError, "batch-1"):
            MODULE.atomic_publish(
                self.root, "batch-1", {"summary.json": json.dumps({"ok": True})}
            )

    def test_member_shards_are_standard_json_files(self):
        files = MODULE._json_shards([{"id": 1}, {"id": 2}], "group", 1024)
        self.assertEqual(["members/group-001.json"], list(files))
        self.assertEqual([{"id": 1}, {"id": 2}], json.loads(next(iter(files.values()))))

    def test_output_size_field_can_reach_exact_fixed_point(self):
        summary = {"planned_output_bytes": 0}
        files = {"members/items.json": "[]\n"}
        for _ in range(8):
            files["summary.json"] = json.dumps(summary, indent=2) + "\n"
            total = sum(len(value.encode()) for value in files.values())
            if summary["planned_output_bytes"] == total:
                break
            summary["planned_output_bytes"] = total
        self.assertEqual(total, summary["planned_output_bytes"])

    def test_resource_headroom_rejects_low_memory_and_low_disk(self):
        healthy = {
            "system_memory_available_percent": 61.0,
            "disk_free_bytes": 10 * 1024**3,
        }
        MODULE._assert_resource_headroom(
            healthy,
            min_memory_percent=20,
            min_disk_free_bytes=5 * 1024**3,
            planned_output_bytes=1024,
        )
        with self.assertRaisesRegex(ValueError, "SYSTEM_MEMORY_HEADROOM_LOW"):
            MODULE._assert_resource_headroom(
                {**healthy, "system_memory_available_percent": 19.9},
                min_memory_percent=20,
                min_disk_free_bytes=5 * 1024**3,
                planned_output_bytes=0,
            )
        with self.assertRaisesRegex(ValueError, "DISK_HEADROOM_LOW"):
            MODULE._assert_resource_headroom(
                {**healthy, "disk_free_bytes": 5 * 1024**3},
                min_memory_percent=20,
                min_disk_free_bytes=5 * 1024**3,
                planned_output_bytes=1,
            )

    def test_config_contract_rejects_local_executable_and_limit_drift(self):
        source = ROOT / "config" / "数据" / "任务-000092Binance历史归档来源身份.json"
        original = json.loads(source.read_text(encoding="utf-8"))
        mutations = (
            ("curl_path", "/tmp/not-curl"),
            ("local_root", "/tmp/other-data"),
            ("limits", {**original["limits"], "memory_bytes": 999999999}),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                config = {**original, key: value}
                path = self.root / f"{key}.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "CONFIG_CONTRACT_INVALID"):
                    MODULE._load_config(path)

    def test_execution_paths_must_stay_in_repository_contract(self):
        config = ROOT / "config/数据/任务-000092Binance历史归档来源身份.json"
        output = ROOT / "artifacts/数据/Binance历史归档来源身份"
        MODULE._validate_execution_paths(config, output, ROOT)
        with self.assertRaisesRegex(ValueError, "EXECUTION_PATH_REJECTED"):
            MODULE._validate_execution_paths(config, self.root / "outside", ROOT)


if __name__ == "__main__":
    unittest.main()
