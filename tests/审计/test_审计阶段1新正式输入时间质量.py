import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "审计" / "审计阶段1新正式输入时间质量.py"
CONFIG = ROOT / "config" / "审计" / "任务-000094逐行时间质量审计.json"
FORMAL_BATCH = ROOT / "artifacts" / "审计" / "阶段1新候选集重算" / "stage1-candidate-recompute-20260811T145500Z-22191bf6b82a"
SCANNER_MODULE = ROOT / "scripts" / "审计" / "阶段1时间质量扫描器.py"
FINAL_BATCH = ROOT / "artifacts" / "审计" / "阶段1逐行时间质量" / "stage1-time-quality-20260812T021000Z-d1bc5118ee09"


def load_auditor():
    if not SCRIPT.is_file():
        raise AssertionError(f"执行器尚未实现：{SCRIPT}")
    spec = importlib.util.spec_from_file_location("stage1_time_quality", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("无法加载执行器")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExecutorEntryTests(unittest.TestCase):
    def test_执行器入口存在(self):
        self.assertTrue(SCRIPT.is_file(), f"执行器尚未实现：{SCRIPT}")


class Stage1TimeQualityAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auditor = load_auditor()
        cls.tools = {"unzip": "/usr/bin/unzip", "awk": "/usr/bin/awk"}
        cls.limits = {
            "single_source_file_bytes": 1024 * 1024,
            "scanner_stdout_bytes": 4096,
            "scanner_stderr_bytes": 65536,
            "member_seconds": 30,
        }

    def make_zip(self, directory: Path, name: str, rows: list[str]) -> Path:
        path = directory / f"{name}.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{name}.csv", "\n".join(rows) + "\n")
        return path

    def member(self, name: str, header_present: bool = False) -> dict:
        return {
            "member_id": f"BTCUSDT:trades:{name}.zip",
            "relative_name": f"{name}.zip",
            "content_sha256": "a" * 64,
            "schema": {"header_present": header_present},
            "remote_evidence": {
                "zip_last_modified": "2025-01-02T01:02:03.000Z",
                "checksum_last_modified": "2025-01-02T01:02:04.000Z",
            },
        }

    def trades_group(self) -> dict:
        return {
            "id": "BTCUSDT-trades",
            "underlying": "BTC",
            "contract": "BTCUSDT",
            "dataset": "trades",
            "column_count": 6,
            "header": ["id", "price", "qty", "quote_qty", "time", "is_buyer_maker"],
            "business_key_index": 1,
            "event_time_index": 5,
        }

    def test_配置完整冻结(self):
        config = self.auditor.load_config(CONFIG)
        self.assertEqual("000094", config["task_id"])
        self.assertEqual(5180, config["expected_counts"]["formal_members"])
        self.assertEqual([4, 8, 24, 48], config["main_horizons_hours"])
        self.assertEqual("/usr/bin/awk", config["tools"]["awk"])

    def test_毫秒与微秒事件时间规范化(self):
        self.assertEqual(1735689600000, self.auditor.normalize_epoch_ms("1735689600000"))
        self.assertEqual(1735689600000, self.auditor.normalize_epoch_ms("1735689600000000"))
        for value in ("", "-1", "1.5", "17356896000000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.auditor.normalize_epoch_ms(value)

    def test_有限十进制边界(self):
        self.assertTrue(self.auditor.normalize_decimal("0", positive=False))
        self.assertTrue(self.auditor.normalize_decimal("0.010", positive=True))
        self.assertFalse(self.auditor.normalize_decimal("0", positive=True))
        for value in ("-1", "+1", "1e3", "NaN", "", ".1", "1."):
            self.assertFalse(self.auditor.normalize_decimal(value, positive=False))

    def test_官方较晚对象时间是归档可见边界(self):
        self.assertEqual(
            "2025-01-02T01:02:04Z",
            self.auditor.source_visible_at(self.member("BTCUSDT-trades-2025-01-01")),
        )
        broken = self.member("BTCUSDT-trades-2025-01-01")
        broken["remote_evidence"]["zip_last_modified"] = "not-time"
        with self.assertRaises(ValueError):
            self.auditor.source_visible_at(broken)

    def test_逐行扫描通过且不公开业务键(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "BTCUSDT-trades-2025-01-01"
            path = self.make_zip(
                root,
                name,
                [
                    "1,100.0,2.0,200.0,1735689600000,true",
                    "2,100.1,1.0,100.1,1735689600001000,false",
                ],
            )
            result = self.auditor.scan_member(
                path, self.member(name), self.trades_group(), self.tools, self.limits
            )
            self.assertEqual("已证明", result["status"])
            self.assertEqual(2, result["row_count"])
            self.assertEqual(1735689600000, result["first_event_time_ms"])
            compact = self.auditor.compact_member_result(result)
            self.assertNotIn("_first_key", compact)
            self.assertNotIn("_last_key", compact)
            self.assertNotIn("price", json.dumps(compact))

    def test_表头必须精确匹配(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "BTCUSDT-trades-2025-01-01"
            rows = [
                "id,price,qty,quote_qty,time,is_buyer_maker",
                "1,100,2,200,1735689600000,true",
            ]
            path = self.make_zip(root, name, rows)
            result = self.auditor.scan_member(
                path, self.member(name, header_present=True), self.trades_group(), self.tools, self.limits
            )
            self.assertEqual("已证明", result["status"])
            rows[0] = "id,price,qty,quote_qty,bad,is_buyer_maker"
            path.unlink()
            path = self.make_zip(root, name, rows)
            result = self.auditor.scan_member(
                path, self.member(name, header_present=True), self.trades_group(), self.tools, self.limits
            )
            self.assertEqual("拒绝", result["status"])
            self.assertIn("HEADER_INVALID", result["reason_codes"])

    def test_重复键回退时间回退日期越界和字段异常均拒绝(self):
        cases = {
            "DUPLICATE_OR_REVERSED_KEY": [
                "2,100,1,100,1735689600000,true",
                "2,100,1,100,1735689600001,true",
            ],
            "EVENT_TIME_REVERSED": [
                "1,100,1,100,1735689600100,true",
                "2,100,1,100,1735689600000,true",
            ],
            "EVENT_DATE_MISMATCH": ["1,100,1,100,1735776000000,true"],
            "DECIMAL_INVALID": ["1,-100,1,100,1735689600000,true"],
            "BOOLEAN_INVALID": ["1,100,1,100,1735689600000,TRUE"],
            "COLUMN_COUNT_INVALID": ["1,100,1,100,1735689600000"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for reason, rows in cases.items():
                with self.subTest(reason=reason):
                    name = "BTCUSDT-trades-2025-01-01"
                    path = root / f"{name}.zip"
                    if path.exists():
                        path.unlink()
                    path = self.make_zip(root, name, rows)
                    result = self.auditor.scan_member(
                        path, self.member(name), self.trades_group(), self.tools, self.limits
                    )
                    self.assertEqual("拒绝", result["status"])
                    self.assertIn(reason, result["reason_codes"])

    def test_聚合成交首末编号关系被验证(self):
        group = {
            "id": "BTCUSDT-aggTrades",
            "underlying": "BTC",
            "contract": "BTCUSDT",
            "dataset": "aggTrades",
            "column_count": 7,
            "header": [
                "agg_trade_id", "price", "quantity", "first_trade_id",
                "last_trade_id", "transact_time", "is_buyer_maker",
            ],
            "business_key_index": 1,
            "event_time_index": 6,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "BTCUSDT-aggTrades-2025-01-01"
            path = self.make_zip(root, name, ["1,100,2,9,8,1735689600000,true"])
            member = self.member(name)
            member["member_id"] = f"BTCUSDT:aggTrades:{name}.zip"
            result = self.auditor.scan_member(path, member, group, self.tools, self.limits)
            self.assertEqual("拒绝", result["status"])
            self.assertIn("AGG_TRADE_RANGE_INVALID", result["reason_codes"])

    def test_连续段按标的对象隔离并由缺日切断(self):
        rows = [
            {"underlying": "BTC", "contract": "BTCUSDT", "dataset": "trades", "event_date": "2025-01-01", "status": "已证明"},
            {"underlying": "BTC", "contract": "BTCUSDT", "dataset": "trades", "event_date": "2025-01-02", "status": "已证明"},
            {"underlying": "BTC", "contract": "BTCUSDT", "dataset": "trades", "event_date": "2025-01-04", "status": "已证明"},
            {"underlying": "ETH", "contract": "ETHUSDT", "dataset": "trades", "event_date": "2025-01-01", "status": "已证明"},
            {"underlying": "BTC", "contract": "BTCUSDT", "dataset": "aggTrades", "event_date": "2025-01-01", "status": "已证明"},
        ]
        segments = self.auditor.build_segments(rows)
        btc_trades = [row for row in segments if row["group"] == "BTCUSDT-trades"]
        self.assertEqual([2, 1], [row["day_count"] for row in btc_trades])
        self.assertEqual(4, len(segments))

    def test_追加式发布禁止覆盖和超限(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self.auditor.atomic_publish(root, "batch-a", {"summary.json": "{}\n"}, 1024)
            self.assertTrue((target / "summary.json").is_file())
            with self.assertRaises(FileExistsError):
                self.auditor.atomic_publish(root, "batch-a", {"summary.json": "{}\n"}, 1024)
            with self.assertRaises(ValueError):
                self.auditor.atomic_publish(root, "batch-b", {"summary.json": "x" * 1025}, 1024)

    def test_列式正式输入可逆解码且固定指纹匹配(self):
        records = self.auditor.load_record_table_shards(FORMAL_BATCH, "formal-input", 6000)
        self.assertEqual(5180, len(records))
        self.assertEqual(
            "a1c69d6e2446c364578edb08e6b6fa30912f2e5577d7e51377ef8ab4c648952d",
            self.auditor.sha256_bytes(self.auditor.canonical_json(records).encode("utf-8")),
        )
        self.assertEqual(
            {"BTCUSDT-trades", "ETHUSDT-trades", "BTCUSDT-aggTrades"},
            {row["group"] for row in records},
        )

    def test_正式输入必须与来源身份逐项全等(self):
        formal = [{
            "member_id": "m1", "group": "BTCUSDT-trades", "underlying": "BTC",
            "contract": "BTCUSDT", "dataset": "trades", "relative_name": "BTCUSDT-trades-2025-01-01.zip",
            "content_sha256": "a" * 64, "size_bytes": 10, "schema_version": "s1",
        }]
        source = [{
            **formal[0], "status": "已证明", "schema": {"schema_version": "s1"},
            "remote_evidence": {"zip_last_modified": "2025-01-02T00:00:00Z", "checksum_last_modified": "2025-01-02T00:00:01Z"},
        }]
        joined, rejected = self.auditor.reconcile_formal_members(formal, source)
        self.assertEqual(1, len(joined))
        self.assertEqual([], rejected)
        drift = [dict(formal[0], content_sha256="b" * 64)]
        with self.assertRaisesRegex(ValueError, "FORMAL_SOURCE_IDENTITY_DRIFT"):
            self.auditor.reconcile_formal_members(drift, source)

    def test_跨成员相邻边界继续校验且缺日切断(self):
        rows = [
            {"group": "BTCUSDT-trades", "event_date": "2025-01-01", "status": "已证明", "_first_key": "1", "_last_key": "10", "first_event_time_ms": 1735689600000, "last_event_time_ms": 1735775999000},
            {"group": "BTCUSDT-trades", "event_date": "2025-01-02", "status": "已证明", "_first_key": "10", "_last_key": "20", "first_event_time_ms": 1735776000000, "last_event_time_ms": 1735862399000},
            {"group": "BTCUSDT-trades", "event_date": "2025-01-04", "status": "已证明", "_first_key": "1", "_last_key": "2", "first_event_time_ms": 1735948800000, "last_event_time_ms": 1736035199000},
        ]
        self.auditor.validate_cross_member_boundaries(rows)
        self.assertEqual("拒绝", rows[1]["status"])
        self.assertIn("CROSS_MEMBER_KEY_NOT_INCREASING", rows[1]["reason_codes"])
        self.assertEqual("已证明", rows[2]["status"], "缺日后不跨缺口比较业务键")

    def test_只更新三类时间和质量门并保留其他门(self):
        old = [{
            "underlying": "BTC", "horizon_hours": 4, "decision": "阻塞",
            "gates": {
                "来源身份": {"status": "通过", "reason_code": "SOURCE", "evidence_refs": ["a"], "release_conditions": ["a"]},
                "三类时间": {"status": "无法判定", "reason_code": "OLD_TIME", "evidence_refs": ["b"], "release_conditions": ["b"]},
                "质量": {"status": "无法判定", "reason_code": "OLD_QUALITY", "evidence_refs": ["c"], "release_conditions": ["c"]},
                "历史重放": {"status": "无法判定", "reason_code": "REPLAY", "evidence_refs": ["d"], "release_conditions": ["d"]},
            },
        }]
        updated = self.auditor.update_gate_leaves(old, {"BTC": 10}, {"BTC": 10}, {"BTC": 2})
        self.assertEqual("通过", updated[0]["gates"]["三类时间"]["status"])
        self.assertEqual("通过", updated[0]["gates"]["质量"]["status"])
        self.assertEqual(old[0]["gates"]["历史重放"], updated[0]["gates"]["历史重放"])
        self.assertEqual("阻塞", updated[0]["decision"])

    def test_列式结果分片可逆且确定(self):
        records = [
            {"member": f"m{index}", "status": "已证明", "rows": index}
            for index in range(5)
        ]
        shards = list(self.auditor.json_table_shards(records, "members", 420))
        self.assertEqual(shards, list(self.auditor.json_table_shards(records, "members", 420)))
        rebuilt = []
        for _, content in shards:
            rebuilt.extend(self.auditor.decode_record_table(json.loads(content)))
        self.assertEqual(records, rebuilt)

    def test_编译扫描器与Python合同输出一致(self):
        self.assertTrue(SCANNER_MODULE.is_file(), "扫描器源码载体尚未实现")
        source = self.auditor.embedded_scanner_source(SCANNER_MODULE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = self.auditor.compile_scanner(source, root, "/usr/bin/clang")
            name = "BTCUSDT-trades-2025-01-01"
            path = self.make_zip(root, name, [
                "1,100.0,2.0,200.0,1735689600000,true",
                "2,100.1,1.0,100.1,1735689600001000,false",
            ])
            tools = {"unzip": "/usr/bin/unzip", "scanner": str(scanner)}
            result = self.auditor.scan_member(path, self.member(name), self.trades_group(), tools, self.limits)
            self.assertEqual("已证明", result["status"])
            self.assertEqual(2, result["row_count"])
            path.unlink()
            path = self.make_zip(root, name, [
                "2,100.0,2.0,200.0,1735689600100,true",
                "2,-1,1.0,100.0,1735689600000,TRUE",
            ])
            rejected = self.auditor.scan_member(path, self.member(name), self.trades_group(), tools, self.limits)
            self.assertEqual("拒绝", rejected["status"])
            self.assertEqual(
                {"DUPLICATE_OR_REVERSED_KEY", "EVENT_TIME_REVERSED", "DECIMAL_INVALID", "BOOLEAN_INVALID"},
                set(rejected["reason_codes"]),
            )

    def test_扫描器源文件必须匹配冻结指纹(self):
        config = self.auditor.load_config(CONFIG)
        source = self.auditor.embedded_scanner_source(SCANNER_MODULE)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SCANNER_SOURCE_FINGERPRINT_DRIFT"):
                self.auditor.compile_scanner(
                    source + b"\n", Path(directory) / "bin", "/usr/bin/clang",
                    config["tools"]["scanner_source_sha256"],
                )

    def test_最终真实批次计数指纹与门禁守恒(self):
        summary = json.loads((FINAL_BATCH / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(5180, summary["audited_member_count"])
        self.assertEqual(
            {"已证明": 4789, "拒绝": 391, "无法判定": 0, "失败": 0, "未成熟": 0, "失效": 0},
            summary["status_counts"],
        )
        self.assertEqual(16121999478, summary["scanned_row_count"])
        self.assertEqual(summary["source_inventory_before_sha256"], summary["source_inventory_after_sha256"])
        self.assertFalse(summary["legacy_task_000084_current_gate"])
        self.assertEqual(
            self.auditor.sha256_bytes(self.auditor.embedded_scanner_source(SCANNER_MODULE)),
            summary["scanner"]["source_sha256"],
        )
        actual = {
            name: self.auditor.sha256_file(FINAL_BATCH / name)
            for name in summary["output_payload_files"]
        }
        self.assertEqual(summary["output_payload_files"], actual)
        self.assertEqual(
            summary["output_payload_fingerprint"],
            self.auditor.sha256_bytes(self.auditor.canonical_json(actual).encode("utf-8")),
        )
        leaves = json.loads((FINAL_BATCH / "leaves.json").read_text(encoding="utf-8"))
        self.assertEqual(8, len(leaves))
        for leaf in leaves:
            self.assertEqual("通过", leaf["gates"]["三类时间"]["status"])
            self.assertEqual("通过", leaf["gates"]["质量"]["status"])
            self.assertEqual("阻塞", leaf["decision"])


if __name__ == "__main__":
    unittest.main()
