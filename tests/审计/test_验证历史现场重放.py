from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "审计" / "验证历史现场重放.py"
INVENTORY_COLUMNS = [
    "发现批次", "资产编号", "资产类型", "逻辑主机", "服务或项目", "资源名称", "位置", "格式",
    "标的范围", "时间范围", "字节数", "最后修改时间", "访问状态", "发现证据", "限制", "后续任务",
]
QUALITY_COLUMNS = [
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "资产类型", "服务或项目", "位置",
    "格式", "候选标的范围", "扫描状态", "扫描完整性", "记录数", "字段数", "结构缺失数", "结构缺失率",
    "重复状态", "精确重复数", "事件时间状态", "事件时间候选字段", "到达时间状态", "到达时间候选字段",
    "采集时间状态", "采集时间候选字段", "延迟状态", "乱序状态", "实际覆盖范围", "可用性结论", "依据", "限制",
    "解除条件", "证据指纹",
]
GAP_COLUMNS = [
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "候选标的范围", "断档状态",
    "预期频率", "事件时间字段", "断档数", "断档范围", "原因", "解除条件",
]
ANOMALY_COLUMNS = [
    "审计批次", "规则版本", "规则指纹", "清单指纹", "资产编号", "候选标的范围", "规则编号",
    "异常类型", "异常数量", "异常比例", "严重度", "规则状态", "证据", "处置",
]


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("historical_replay", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_csv(path: Path, columns: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def make_inputs(root: Path, count: int = 3) -> tuple[Path, Path]:
    inventory = root / "数据源清单.csv"
    quality = root / "数据质量结果.csv"
    gap = root / "数据断档结果.csv"
    anomaly = root / "数据异常结果.csv"
    inventory_rows = []
    quality_rows = []
    gap_rows = []
    anomaly_rows = []
    scopes = ["BTC", "ETH", "未限定"]
    for index in range(count):
        asset_id = f"DS-{index + 1:06d}"
        location = f"/opt/crypto-radar/data/{asset_id}.csv"
        inventory_rows.append({
            "发现批次": "discovery-fixed", "资产编号": asset_id,
            "资产类型": "候选数据文件", "逻辑主机": "ubuntu", "服务或项目": "crypto-radar",
            "资源名称": f"{asset_id}.csv", "位置": location, "格式": "CSV",
            "标的范围": scopes[index], "时间范围": "未知", "字节数": "42",
            "最后修改时间": "2026-07-28T08:00:00+08:00", "访问状态": "元数据可访问",
            "发现证据": "只读元数据", "限制": "未审计内容", "后续任务": "任务-000004",
        })
        quality_rows.append({
            "审计批次": "audit-fixed", "规则版本": "dq-rules-1.0", "规则指纹": "a" * 64,
            "清单指纹": "PENDING", "资产编号": asset_id, "资产类型": "候选数据文件",
            "服务或项目": "crypto-radar", "位置": location, "格式": "CSV", "候选标的范围": scopes[index],
            "扫描状态": "已完成", "扫描完整性": "完整" if index == 0 else "仅元数据",
            "记录数": "2" if index == 0 else "无法判定", "字段数": "3" if index == 0 else "无法判定",
            "结构缺失数": "0" if index == 0 else "无法判定", "结构缺失率": "0" if index == 0 else "无法判定",
            "重复状态": "无法判定", "精确重复数": "无法判定", "事件时间状态": "无法判定",
            "事件时间候选字段": "event_time", "到达时间状态": "无法判定",
            "到达时间候选字段": "arrival_time", "采集时间状态": "无法判定",
            "采集时间候选字段": "collected_at", "延迟状态": "无法判定", "乱序状态": "无法判定",
            "实际覆盖范围": "无法判定", "可用性结论": "无法判定", "依据": "候选字段不是语义合同",
            "限制": "缺少三类时间合同", "解除条件": "冻结决策时点与到达时间合同", "证据指纹": "b" * 64,
        })
        gap_rows.append({
            "审计批次": "audit-fixed", "规则版本": "dq-rules-1.0", "规则指纹": "a" * 64,
            "清单指纹": "PENDING", "资产编号": asset_id, "候选标的范围": scopes[index],
            "断档状态": "无法判定", "预期频率": "未提供正式频率合同", "事件时间字段": "event_time",
            "断档数": "无法判定", "断档范围": "无法判定", "原因": "缺少合同", "解除条件": "冻结合同",
        })
        anomaly_rows.append({
            "审计批次": "audit-fixed", "规则版本": "dq-rules-1.0", "规则指纹": "a" * 64,
            "清单指纹": "PENDING", "资产编号": asset_id, "候选标的范围": scopes[index],
            "规则编号": "DQ-STRUCT-001", "异常类型": "结构解析异常汇总", "异常数量": "无法判定",
            "异常比例": "无法判定", "严重度": "无法判定", "规则状态": "未执行", "证据": "b" * 64,
            "处置": "仅记录，不修改原始数据",
        })

    write_csv(inventory, INVENTORY_COLUMNS, inventory_rows)
    inventory_fingerprint = hashlib.sha256(inventory.read_bytes()).hexdigest()
    for rows in (quality_rows, gap_rows, anomaly_rows):
        for row in rows:
            row["清单指纹"] = inventory_fingerprint
    write_csv(quality, QUALITY_COLUMNS, quality_rows)
    write_csv(gap, GAP_COLUMNS, gap_rows)
    write_csv(anomaly, ANOMALY_COLUMNS, anomaly_rows)
    return inventory, quality


def make_snapshot_evidence(replay: ModuleType) -> dict[str, object]:
    records = [
        {"id": "visible", "event": "2026-07-28T07:00:00+08:00",
         "arrival": "2026-07-28T08:00:00+08:00",
         "collection": "2026-07-28T07:30:00+08:00", "fixture": "smoke-only"},
        {"id": "future", "event": "2026-07-28T07:00:00+08:00",
         "arrival": "2026-07-28T08:00:01+08:00",
         "collection": "2026-07-28T07:30:00+08:00", "fixture": "smoke-only"},
    ]
    return {
        "证据类型": "smoke-only",
        "合同版本": "fixture-v1",
        "来源证据": "smoke-only fixed fixture",
        "决策记录编号": "DEC-SMOKE-001",
        "快照逻辑标识": "ZS-数据快照-SMOKE-001",
        "历史时间": "2026-07-28T08:00:00+08:00",
        "决策时间": "2026-07-28T08:00:00+08:00",
        "输入数据版本": "smoke-data-v1",
        "输入数据哈希": replay.calculate_data_sha256(records, ["id"]),
        "输入资产集合": ["DS-000001"],
        "事件时间字段": "event",
        "到达时间字段": "arrival",
        "采集时间字段": "collection",
        "字段冻结状态": {
            "event": "已冻结", "arrival": "已冻结", "collection": "已冻结",
        },
        "三类时间合同状态": "已证明",
        "业务键": ["id"],
        "记录": records,
    }


@unittest.skipUnless(MODULE_PATH.exists(), "等待历史重放实现")
class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.replay = load_module()

    def test_四份输入冻结且不同批次失败(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            self.assertEqual(3, len(frozen["质量记录"]))
            self.assertEqual(hashlib.sha256(inventory.read_bytes()).hexdigest(), frozen["清单指纹"])

            gap = Path(directory) / "数据断档结果.csv"
            with gap.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["审计批次"] = "audit-other"
            write_csv(gap, GAP_COLUMNS, rows)
            with self.assertRaisesRegex(ValueError, "批次"):
                self.replay.load_and_freeze_inputs(inventory, quality)

    def test_质量报告必须与CSV批次和指纹一致(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, quality = make_inputs(root)
            fingerprint = hashlib.sha256(inventory.read_bytes()).hexdigest()
            report = root / "数据质量审计报告.md"
            report.write_text(
                "\n".join([
                    "# 审计报告",
                    "",
                    "- 审计批次：`audit-fixed`",
                    f"- 资产清单SHA-256：`{fingerprint}`",
                    "- 规则版本：`dq-rules-1.0`",
                    f"- 规则SHA-256：`{'a' * 64}`",
                    "",
                ]),
                encoding="utf-8",
            )
            frozen = self.replay.load_and_freeze_inputs(inventory, quality, report)
            self.assertEqual("audit-fixed", frozen["质量审计批次"])

            report.write_text(report.read_text(encoding="utf-8").replace("audit-fixed", "audit-other"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "报告"):
                self.replay.load_and_freeze_inputs(inventory, quality, report)

    def test_缺少资产覆盖或清单指纹漂移失败(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            anomaly = Path(directory) / "数据异常结果.csv"
            with anomaly.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            write_csv(anomaly, ANOMALY_COLUMNS, rows[:-1])
            with self.assertRaisesRegex(ValueError, "覆盖"):
                self.replay.load_and_freeze_inputs(inventory, quality)

            _, quality = make_inputs(Path(directory))
            with quality.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["清单指纹"] = "f" * 64
            write_csv(quality, QUALITY_COLUMNS, rows)
            with self.assertRaisesRegex(ValueError, "指纹"):
                self.replay.load_and_freeze_inputs(inventory, quality)

    def test_ssh仅允许逻辑别名ubuntu并且远端失败不回显(self):
        self.assertEqual("ubuntu", self.replay.validate_ssh_target("ubuntu"))
        blocked_ip = ".".join(("192", "168", "31", "201"))
        for invalid in ("root@ubuntu", blocked_ip, "prod", "ubuntu;id", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.replay.validate_ssh_target(invalid)

        password_key = "pass" + "word"
        completed = subprocess.CompletedProcess(
            args=[], returncode=255, stdout="", stderr=f"{password_key}=do-not-leak"
        )
        with mock.patch.object(self.replay.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(RuntimeError, "remote_preflight_failed") as raised:
                self.replay.run_remote_preflight("ubuntu", 7)
        self.assertNotIn("do-not-leak", str(raised.exception))
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list)
        self.assertEqual("ubuntu", args[0][-3])
        self.assertEqual(["python3", "-"], args[0][-2:])
        self.assertEqual(self.replay.REMOTE_PREFLIGHT_PROGRAM, kwargs["input"])
        self.assertEqual(7, kwargs["timeout"])


@unittest.skipUnless(MODULE_PATH.exists(), "等待历史重放实现")
class SnapshotContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.replay = load_module()

    def test_快照合同缺版本哈希资产集合或字段状态失败(self):
        evidence = make_snapshot_evidence(self.replay)
        cases = (
            ("输入数据版本", "", "data_version_missing"),
            ("输入数据版本", "latest", "data_version_missing"),
            ("输入数据哈希", "", "data_hash_missing"),
            ("输入资产集合", [], "input_asset_set_missing"),
            ("字段冻结状态", {"event": "已冻结"}, "available_fields_unproven"),
        )
        for field, value, code in cases:
            candidate = dict(evidence)
            candidate[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, code):
                self.replay.freeze_replay_snapshot(candidate)

    def test_数据哈希必须与完整输入规范JSON一致(self):
        evidence = make_snapshot_evidence(self.replay)
        evidence["输入数据哈希"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "data_hash_mismatch"):
            self.replay.freeze_replay_snapshot(evidence)

    def test_输入顺序不影响内容寻址版本(self):
        first = make_snapshot_evidence(self.replay)
        second = make_snapshot_evidence(self.replay)
        second["记录"] = list(reversed(second["记录"]))
        second["输入数据哈希"] = self.replay.calculate_data_sha256(
            second["记录"], second["业务键"]
        )
        frozen_first = self.replay.freeze_replay_snapshot(first)
        frozen_second = self.replay.freeze_replay_snapshot(second)
        self.assertEqual(frozen_first["输入数据哈希"], frozen_second["输入数据哈希"])
        self.assertEqual(frozen_first["快照版本标识"], frozen_second["快照版本标识"])

    def test_冻结后原始对象突变不影响快照(self):
        evidence = make_snapshot_evidence(self.replay)
        frozen = self.replay.freeze_replay_snapshot(evidence)
        version = frozen["快照版本标识"]
        frozen_value = frozen["输入记录"][0]["id"]
        evidence["记录"][0]["id"] = "mutated"
        evidence["输入资产集合"].append("ETH")
        evidence["字段冻结状态"]["event"] = "未冻结"
        self.assertEqual(version, frozen["快照版本标识"])
        self.assertEqual(frozen_value, frozen["输入记录"][0]["id"])
        with self.assertRaises(TypeError):
            frozen["快照逻辑标识"] = "changed"
        with self.assertRaises(TypeError):
            frozen["输入记录"][0]["id"] = "changed"

    def test_快照显式绑定双时点三时间字段和业务键(self):
        frozen = self.replay.freeze_replay_snapshot(make_snapshot_evidence(self.replay))
        self.assertEqual("replay-snapshot-contract-1.0", frozen["快照合同版本"])
        self.assertEqual("2026-07-28T08:00:00+08:00", frozen["历史时间"])
        self.assertEqual("2026-07-28T08:00:00+08:00", frozen["决策时间"])
        self.assertEqual(("id",), frozen["业务键"])
        self.assertEqual(
            {"event": "已冻结", "arrival": "已冻结", "collection": "已冻结"},
            dict(frozen["字段冻结状态"]),
        )

    def test_原因码和中文修复建议覆盖固定合同(self):
        required = {
            "input_identity_drift", "input_scan_incomplete", "decision_record_missing",
            "snapshot_contract_incomplete", "data_version_missing", "data_hash_missing",
            "data_hash_mismatch", "input_asset_set_missing", "available_fields_unproven",
            "output_hash_mismatch", "source_provenance_unverified", "numeric_precision_unproven",
        }
        self.assertTrue(required.issubset(self.replay.UNREPLAYABLE_REMEDIATIONS))
        self.assertTrue(all(
            self.replay.UNREPLAYABLE_REMEDIATIONS[code].startswith("修复建议：")
            for code in required
        ))

    def test_重放前篡改任一快照身份必须失败安全(self):
        frozen = self.replay.freeze_replay_snapshot(make_snapshot_evidence(self.replay))

        def set_nested_field(snapshot: dict[str, object]) -> None:
            snapshot["字段冻结状态"]["event"] = "未冻结"

        cases = (
            ("快照逻辑标识", lambda item: item.__setitem__("快照逻辑标识", "ZS-数据快照-OTHER")),
            ("历史时间", lambda item: item.__setitem__("历史时间", "2026-07-28T07:59:59+08:00")),
            ("决策时间", lambda item: item.__setitem__("决策时间", "2026-07-28T07:59:59+08:00")),
            ("输入数据版本", lambda item: item.__setitem__("输入数据版本", "smoke-data-v2")),
            ("输入资产集合", lambda item: item.__setitem__("输入资产集合", ["DS-000002"])),
            ("字段冻结状态", set_nested_field),
            ("业务键", lambda item: item.__setitem__("业务键", ["arrival"])),
            ("事件时间字段", lambda item: item.__setitem__("事件时间字段", "arrival")),
            ("到达时间字段", lambda item: item.__setitem__("到达时间字段", "event")),
            ("采集时间字段", lambda item: item.__setitem__("采集时间字段", "arrival")),
            ("输入数据哈希", lambda item: item.__setitem__("输入数据哈希", "f" * 64)),
            ("快照合同版本", lambda item: item.__setitem__("快照合同版本", "replay-snapshot-contract-2.0")),
            ("规范JSON版本", lambda item: item.__setitem__("规范JSON版本", "canonical-json-v2")),
            ("快照版本标识", lambda item: item.__setitem__("快照版本标识", "sha256:" + "f" * 64)),
            ("快照记录编号", lambda item: item.__setitem__("快照记录编号", "ZS-历史重放-" + "f" * 64)),
            ("输入资产集合指纹", lambda item: item.__setitem__("输入资产集合指纹", "f" * 64)),
        )
        for field, mutate in cases:
            candidate = self.replay._deep_thaw(frozen)
            mutate(candidate)
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError,
                "data_hash_mismatch|snapshot_contract_incomplete|available_fields_unproven",
            ):
                self.replay.execute_snapshot_replay(candidate)

    def test_逻辑标识与数据版本禁止猜测身份(self):
        invalid_values = (
            "", "latest", " Current ", "LATEST", "2026-07-28T08:00:00+08:00",
            "1722134400", "1722134400000", "contains space",
        )
        for field in ("快照逻辑标识", "输入数据版本"):
            for value in invalid_values:
                evidence = make_snapshot_evidence(self.replay)
                evidence[field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ValueError, "snapshot_contract_incomplete|data_version_missing"
                ):
                    self.replay.freeze_replay_snapshot(evidence)

        valid = make_snapshot_evidence(self.replay)
        valid["快照逻辑标识"] = "ZS-数据快照-知势_01"
        valid["输入数据版本"] = "数据版本-v1.0"
        frozen = self.replay.freeze_replay_snapshot(valid)
        self.assertEqual("ZS-数据快照-知势_01", frozen["快照逻辑标识"])
        self.assertEqual("数据版本-v1.0", frozen["输入数据版本"])

    def test_带命名空间的浮动版本和时间令牌仍必须拒绝(self):
        invalid_values = (
            "dataset/current", "dataset:latest", "x-latest", "dataset/LATEST",
            "data-2026-07-28", "data:2026-07-28T08:00:00Z",
            "data-1722134400", "data:1722134400000",
        )
        for field in ("快照逻辑标识", "输入数据版本"):
            for value in invalid_values:
                evidence = make_snapshot_evidence(self.replay)
                evidence[field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ValueError, "snapshot_contract_incomplete|data_version_missing"
                ):
                    self.replay.freeze_replay_snapshot(evidence)

        for valid_value in ("smoke-data-v1", "DS-000001", "知势-数据_v1.0"):
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入数据版本"] = valid_value
            self.assertEqual(
                valid_value,
                self.replay.freeze_replay_snapshot(evidence)["输入数据版本"],
            )

    def test_紧邻字母的扩展或基本时间身份仍必须拒绝(self):
        invalid_values = (
            "v2026-07-28", "dataset2026-07-28", "v1722134400",
            "data:20260728T080000Z", "prefix20260728", "x1722134400000",
        )
        for field in ("快照逻辑标识", "输入数据版本"):
            for value in invalid_values:
                evidence = make_snapshot_evidence(self.replay)
                evidence[field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ValueError, "snapshot_contract_incomplete|data_version_missing"
                ):
                    self.replay.freeze_replay_snapshot(evidence)

        for valid_value in ("smoke-data-v1", "DS-000001", "current2"):
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入数据版本"] = valid_value
            self.assertEqual(
                valid_value,
                self.replay.freeze_replay_snapshot(evidence)["输入数据版本"],
            )

    def test_快照版本标识不接受调用方注入(self):
        evidence = make_snapshot_evidence(self.replay)
        evidence["快照版本标识"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "snapshot_contract_incomplete"):
            self.replay.freeze_replay_snapshot(evidence)

    def test_资产集合指纹绑定数据版本和数据哈希(self):
        first = make_snapshot_evidence(self.replay)
        second = make_snapshot_evidence(self.replay)
        second["输入数据版本"] = "smoke-data-v2"
        third = make_snapshot_evidence(self.replay)
        third["记录"][0]["fixture"] = "smoke-only-v2"
        third["输入数据哈希"] = self.replay.calculate_data_sha256(
            third["记录"], third["业务键"]
        )
        fingerprints = {
            self.replay.freeze_replay_snapshot(item)["输入资产集合指纹"]
            for item in (first, second, third)
        }
        self.assertEqual(3, len(fingerprints))

    def test_规范JSON拒绝非整数浮点NaN和Infinity(self):
        for value in (1.25, -0.5, float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)), self.assertRaisesRegex(
                ValueError, "numeric_precision_unproven"
            ):
                self.replay.calculate_data_sha256(
                    [{"id": "1", "arrival": "2026-07-28T08:00:00+08:00", "value": value}],
                    ["id"],
                )

    def test_规范JSON版本与固定字节哈希向量(self):
        records = [
            {"id": "2", "active": True, "n": 2},
            {"id": "1", "n": 1.0, "中文": "值"},
        ]
        expected = '[{"id":"1","n":1,"中文":"值"},{"active":true,"id":"2","n":2}]'
        normalized = self.replay._canonical_records(records, ["id"])
        self.assertEqual(expected.encode("utf-8"), self.replay._canonical_json(normalized).encode("utf-8"))
        self.assertEqual(
            hashlib.sha256(expected.encode("utf-8")).hexdigest(),
            self.replay.calculate_data_sha256(records, ["id"]),
        )
        frozen = self.replay.freeze_replay_snapshot(make_snapshot_evidence(self.replay))
        self.assertEqual("canonical-json-v1", self.replay.CANONICAL_JSON_VERSION)
        self.assertEqual("canonical-json-v1", frozen["规范JSON版本"])

        injected = make_snapshot_evidence(self.replay)
        injected["规范JSON版本"] = "canonical-json-v1"
        with self.assertRaisesRegex(ValueError, "snapshot_contract_incomplete"):
            self.replay.freeze_replay_snapshot(injected)

    def test_整数浮点只允许IEEE754安全整数范围(self):
        safe_value = float(2**53 - 1)
        safe_records = [{"id": "1", "value": safe_value}]
        expected = '[{"id":"1","value":9007199254740991}]'
        normalized = self.replay._canonical_records(safe_records, ["id"])
        self.assertEqual(expected, self.replay._canonical_json(normalized))
        self.assertEqual(
            hashlib.sha256(expected.encode("utf-8")).hexdigest(),
            self.replay.calculate_data_sha256(safe_records, ["id"]),
        )

        unsafe_values = (float(2**53), 1e23, 9007199254740993.0)
        for value in unsafe_values:
            with self.subTest(value=repr(value)), self.assertRaisesRegex(
                ValueError, "numeric_precision_unproven"
            ):
                self.replay.calculate_data_sha256([{"id": "1", "value": value}], ["id"])


@unittest.skipUnless(MODULE_PATH.exists(), "等待历史重放实现")
class ReplayEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.replay = load_module()

    def test_无时区决策或到达时间失败(self):
        records = [{"id": "1", "arrival": "2026-07-28T08:00:00+08:00"}]
        with self.assertRaisesRegex(ValueError, "timezone_required"):
            self.replay.replay_visible_records(records, "2026-07-28T08:00:00", "arrival", ["id"])
        records[0]["arrival"] = "2026-07-28T08:00:00"
        with self.assertRaisesRegex(ValueError, "timezone_required"):
            self.replay.replay_visible_records(records, "2026-07-28T08:00:00+08:00", "arrival", ["id"])

    def test_边界包含并拒绝未来到达记录(self):
        records = [
            {"id": "at", "arrival": "2026-07-28T08:00:00+08:00", "value": 1, "fixture": "smoke-only"},
            {"id": "future", "arrival": "2026-07-28T08:00:00.000001+08:00", "value": 2, "fixture": "smoke-only"},
        ]
        result = self.replay.replay_visible_records(
            records, "2026-07-28T08:00:00+08:00", "arrival", ["id"]
        )
        self.assertEqual(1, result["visible_count"])
        self.assertEqual(1, result["rejected_count"])
        self.assertEqual("future_arrival_rejected", result["future_rejection_code"])
        self.assertNotIn("future", result["snapshot_json"])

    def test_稳定排序并生成确定性指纹(self):
        records = [
            {"id": "2", "arrival": "2026-07-28T07:00:00Z", "value": 2},
            {"id": "1", "arrival": "2026-07-28T07:00:00Z", "value": 1},
        ]
        first = self.replay.replay_visible_records(
            records, "2026-07-28T08:00:00Z", "arrival", ["id"]
        )
        second = self.replay.replay_visible_records(
            list(reversed(records)), "2026-07-28T08:00:00Z", "arrival", ["id"]
        )
        self.assertEqual(first["snapshot_fingerprint"], second["snapshot_fingerprint"])
        self.assertEqual(64, len(first["snapshot_fingerprint"]))

    def test_缺少业务键不得猜测(self):
        with self.assertRaisesRegex(ValueError, "business_key_required"):
            self.replay.replay_visible_records(
                [{"arrival": "2026-07-28T07:00:00Z"}],
                "2026-07-28T08:00:00Z", "arrival", []
            )
        with self.assertRaisesRegex(ValueError, "business_key_missing"):
            self.replay.replay_visible_records(
                [{"arrival": "2026-07-28T07:00:00Z"}],
                "2026-07-28T08:00:00Z", "arrival", ["id"]
            )

    def test_第二门编排连续重放两次并拒绝未来到达(self):
        records = [
            {"id": "visible", "arrival": "2026-07-28T08:00:00+08:00", "fixture": "smoke-only"},
            {"id": "future", "arrival": "2026-07-28T08:00:01+08:00", "fixture": "smoke-only"},
        ]
        with mock.patch.object(
            self.replay,
            "replay_visible_records",
            wraps=self.replay.replay_visible_records,
        ) as replay_call:
            result = self.replay.execute_second_gate(
                records, "2026-07-28T08:00:00+08:00", "arrival", ["id"]
            )

        self.assertEqual(2, replay_call.call_count)
        self.assertEqual("通过", result["确定性状态"])
        self.assertEqual("通过（future_arrival_rejected）", result["未来数据拒绝状态"])
        self.assertEqual("通过", result["重放结论"])
        self.assertEqual(result["首次快照指纹"], result["再次快照指纹"])

    def test_第二门连续重放指纹不同时必须拒绝(self):
        first = {
            "visible_count": 1, "rejected_count": 1,
            "future_rejection_code": "future_arrival_rejected",
            "snapshot_json": "[]", "snapshot_fingerprint": "a" * 64,
            "output_fingerprint": "c" * 64,
        }
        second = {**first, "snapshot_fingerprint": "b" * 64, "output_fingerprint": "d" * 64}
        with mock.patch.object(
            self.replay, "replay_visible_records", side_effect=[first, second]
        ):
            result = self.replay.execute_second_gate(
                [], "2026-07-28T08:00:00+08:00", "arrival", ["id"]
            )
        self.assertEqual("拒绝（连续重放快照不一致）", result["确定性状态"])
        self.assertEqual("拒绝", result["重放结论"])
        self.assertEqual("output_hash_mismatch", result["不可重放原因代码"])
        self.assertIn("修复", result["修复建议"])

    def test_冻结快照连续重放两次生成独立结果哈希(self):
        frozen = self.replay.freeze_replay_snapshot(make_snapshot_evidence(self.replay))
        with mock.patch.object(
            self.replay,
            "replay_visible_records",
            wraps=self.replay.replay_visible_records,
        ) as replay_call:
            result = self.replay.execute_snapshot_replay(frozen)
        self.assertEqual(2, replay_call.call_count)
        self.assertEqual("通过", result["重放结论"])
        self.assertEqual(64, len(result["重放结果哈希"]))
        self.assertEqual("无", result["不可重放原因代码"])
        self.assertEqual(frozen["快照版本标识"], result["快照版本标识"])


@unittest.skipUnless(MODULE_PATH.exists(), "等待历史重放实现")
class OutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.replay = load_module()

    def test_正式覆盖不读正文且证据不足均无法判定(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            rows = self.replay.build_formal_coverage(frozen, "replay-fixed")

        self.assertEqual(3, len(rows))
        self.assertEqual(["DS-000001", "DS-000002", "DS-000003"], [r["资产编号"] for r in rows])
        self.assertTrue(all(r["重放结论"] == "无法判定" for r in rows))
        self.assertTrue(all(r["决策时间"] == "无法判定" for r in rows))
        self.assertTrue(all(r["可见记录数"] == "无法判定" for r in rows))
        self.assertTrue(all(r["首次快照指纹"] == "无法判定" for r in rows))
        self.assertIn("完整扫描不等于可见性合同", rows[0]["依据"])
        self.assertIn("仅元数据", rows[1]["依据"])

    def test_v1正式构建器批次级拒绝任何调用方重放证据(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, quality = make_inputs(root)
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            cases = {}

            exact_smoke = make_snapshot_evidence(self.replay)
            cases["精确smoke"] = exact_smoke

            hash_drift = make_snapshot_evidence(self.replay)
            hash_drift["输入数据哈希"] = "f" * 64
            cases["哈希漂移"] = hash_drift

            contract_missing = make_snapshot_evidence(self.replay)
            del contract_missing["三类时间合同状态"]
            cases["合同缺失"] = contract_missing

            formal = make_snapshot_evidence(self.replay)
            formal["证据类型"] = "formal invented"
            cases["伪正式"] = formal

            csv_path = root / "result.csv"
            report_path = root / "report.md"
            csv_path.write_text("old-csv", encoding="utf-8")
            report_path.write_text("old-report", encoding="utf-8")
            for label, evidence in cases.items():
                with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError, "source_provenance_unverified"
                ):
                    rows = self.replay.build_formal_coverage(
                        frozen, "replay-fixed", replay_evidence={"DS-000001": evidence}
                    )
                    self.replay.publish_outputs(csv_path, report_path, rows, "new-report")
                self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
                self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

            rows = self.replay.build_formal_coverage(frozen, "replay-fixed", replay_evidence={})
            self.assertEqual(3, len(rows))
            self.assertTrue(all(row["重放结论"] == "无法判定" for row in rows))

    def test_v1正式证据参数只允许None或内建空字典(self):
        class FalsyDict(dict):
            def __bool__(self) -> bool:
                return False

        class EmptyDictSubclass(dict):
            pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, quality = make_inputs(root)
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            csv_path = root / "result.csv"
            report_path = root / "report.md"
            csv_path.write_text("old-csv", encoding="utf-8")
            report_path.write_text("old-report", encoding="utf-8")

            invalid_values = {
                "含证据但伪值的字典子类": FalsyDict(
                    {"DS-000001": make_snapshot_evidence(self.replay)}
                ),
                "空列表": [],
                "空字典子类": EmptyDictSubclass(),
            }
            for label, replay_evidence in invalid_values.items():
                with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError, "source_provenance_unverified"
                ):
                    rows = self.replay.build_formal_coverage(
                        frozen, "replay-fixed", replay_evidence=replay_evidence
                    )
                    self.replay.publish_outputs(csv_path, report_path, rows, "new-report")
                self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
                self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

            for replay_evidence in (None, {}):
                with self.subTest(valid=repr(replay_evidence)):
                    rows = self.replay.build_formal_coverage(
                        frozen, "replay-fixed", replay_evidence=replay_evidence
                    )
                    self.assertEqual(3, len(rows))
                    self.assertTrue(
                        all(row["重放结论"] == "无法判定" for row in rows)
                    )

    def test_任务000004已确认的输入漂移必须拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            frozen["质量记录"]["DS-000001"]["扫描状态"] = "输入漂移"
            frozen["质量记录"]["DS-000001"]["扫描完整性"] = "未执行"
            rows = self.replay.build_formal_coverage(frozen, "replay-fixed")

        drift = rows[0]
        self.assertEqual("拒绝（任务-000004已确认输入漂移）", drift["输入身份状态"])
        self.assertEqual("拒绝（输入身份漂移）", drift["第一门状态"])
        self.assertEqual("拒绝", drift["重放结论"])
        self.assertIn("输入漂移", drift["依据"])
        self.assertEqual("无法判定", drift["可见记录数"])
        self.assertIn("重新冻结", drift["解除条件"])
        self.assertIn("身份一致", drift["解除条件"])
        self.assertEqual("拒绝与无法判定", self.replay.summarize_formal_conclusion(rows))

        report = self.replay.render_report(
            rows,
            {"验证批次": "replay-fixed", "清单指纹": "a" * 64,
             "质量审计批次": "audit-fixed", "远端预检": "通过"},
        )
        self.assertIn("输入或重放拒绝：1 个", report)
        self.assertIn("证据不足无法判定：2 个", report)

    def test_受控smoke算法路径可进入第二门(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            qualified = self.replay._evaluate_qualified_evidence(
                frozen["质量记录"]["DS-000001"],
                make_snapshot_evidence(self.replay),
                "DS-000001",
            )

        self.assertEqual("通过", qualified["第一门状态"])
        self.assertEqual(1, qualified["可见记录数"])
        self.assertEqual("通过", qualified["确定性状态"])
        self.assertEqual("通过（future_arrival_rejected）", qualified["未来数据拒绝状态"])
        self.assertEqual("通过", qualified["重放结论"])
        self.assertEqual("replay-snapshot-contract-1.0", qualified["快照合同版本"])
        self.assertRegex(qualified["快照记录编号"], r"^ZS-历史重放-[0-9a-f]{64}$")
        self.assertRegex(qualified["重放结果哈希"], r"^[0-9a-f]{64}$")
        self.assertEqual("无", qualified["不可重放原因代码"])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "smoke_only_formal_output_rejected"):
                self.replay.publish_outputs(
                    Path(directory) / "result.csv",
                    Path(directory) / "report.md",
                    [qualified],
                    "safe report",
                )

    def test_报告独立统计BTC_ETH且不外推(self):
        rows = [
            {"资产编号": "DS-000001", "候选标的范围": "BTC", "重放结论": "无法判定"},
            {"资产编号": "DS-000002", "候选标的范围": "BTC、ETH", "重放结论": "无法判定"},
            {"资产编号": "DS-000003", "候选标的范围": "未限定", "重放结论": "无法判定"},
        ]
        report = self.replay.render_report(
            rows, {"验证批次": "replay-fixed", "清单指纹": "a" * 64,
                   "质量审计批次": "audit-fixed", "远端预检": "通过"}
        )
        self.assertIn("| BTC | 2 |", report)
        self.assertIn("| ETH | 1 |", report)
        self.assertNotIn("| SOL |", report)
        self.assertIn("不得外推", report)
        self.assertIn("smoke-only", report)
        self.assertIn("None或精确内建空字典", report)
        self.assertIn("<!-- markdownlint-disable MD013 -->", report)

    def test_报告正确呈现通过拒绝与无法判定分支(self):
        rows = [
            {"资产编号": "DS-000001", "候选标的范围": "BTC", "重放结论": "通过"},
            {"资产编号": "DS-000002", "候选标的范围": "ETH", "重放结论": "无法判定"},
            {"资产编号": "DS-000003", "候选标的范围": "SOL", "重放结论": "拒绝"},
        ]
        report = self.replay.render_report(
            rows,
            {"验证批次": "replay-fixed", "清单指纹": "a" * 64,
             "质量审计批次": "audit-fixed", "远端预检": "通过"},
        )
        self.assertIn("第二门通过：1 个", report)
        self.assertIn("输入或重放拒绝：1 个", report)
        self.assertIn("证据不足无法判定：1 个", report)
        self.assertIn("| BTC | 1 | 通过（全部候选验证单元通过双门重放） |", report)
        self.assertIn("| ETH | 1 | 无法判定", report)
        self.assertNotIn("| SOL |", report)

    def test_正式原因分类和扩展列完整(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            frozen["质量记录"]["DS-000001"]["扫描状态"] = "输入漂移"
            frozen["质量记录"]["DS-000001"]["扫描完整性"] = "未执行"
            frozen["质量记录"]["DS-000003"]["扫描完整性"] = "完整"
            rows = self.replay.build_formal_coverage(frozen, "replay-fixed")

        self.assertEqual(
            ["input_identity_drift", "input_scan_incomplete", "decision_record_missing"],
            [row["不可重放原因代码"] for row in rows],
        )
        self.assertTrue(all(row["快照合同版本"] == "replay-snapshot-contract-1.0" for row in rows))
        self.assertTrue(all(row["修复建议"].startswith("修复建议：") for row in rows))
        self.assertTrue(all(set(row) == set(self.replay.RESULT_COLUMNS) for row in rows))
        self.assertEqual(tuple(self.replay.LEGACY_RESULT_COLUMNS), tuple(self.replay.RESULT_COLUMNS[:22]))
        self.assertEqual(
            ("快照记录编号", "快照合同版本", "快照逻辑标识", "快照版本标识",
             "输入数据版本", "输入数据哈希", "输入资产集合指纹", "重放结果哈希",
             "不可重放原因代码", "修复建议"),
            tuple(self.replay.RESULT_COLUMNS[22:]),
        )
        self.assertFalse(any(value in ("", "0") for row in rows for value in row.values()))

        report = self.replay.render_report(
            rows,
            {"验证批次": "replay-fixed", "清单指纹": "a" * 64,
             "质量审计批次": "audit-fixed", "远端预检": "通过"},
        )
        self.assertIn("replay-snapshot-contract-1.0", report)
        self.assertIn("规范JSON", report)
        self.assertIn("SHA-256", report)
        self.assertIn("`input_identity_drift`：1", report)
        self.assertIn("`input_scan_incomplete`：1", report)
        self.assertIn("`decision_record_missing`：1", report)
        self.assertIn("逻辑标识", report)
        self.assertIn("不可变版本", report)

    def test_smoke算法入口在证据合同不完整时失败安全(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            evidence = make_snapshot_evidence(self.replay)
            del evidence["三类时间合同状态"]
            with self.assertRaisesRegex(ValueError, "snapshot_contract_incomplete"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                )

    def test_smoke算法入口在数据哈希漂移时拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入数据哈希"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "data_hash_mismatch"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                )

    def test_不完整扫描不得被表面完整快照证据覆盖(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            with self.assertRaisesRegex(ValueError, "input_scan_incomplete"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000002"],
                    make_snapshot_evidence(self.replay),
                    "DS-000002",
                )

    def test_快照输入资产集合必须绑定当前资产编号(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入资产集合"] = ["DS-999999"]
            with self.assertRaisesRegex(ValueError, "input_asset_set_missing"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                )

    def test_逐资产快照不得混入额外未知资产(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入资产集合"] = ["DS-000001", "DS-999999"]
            with self.assertRaisesRegex(ValueError, "input_asset_set_missing"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                )

    def test_逐资产快照不得混入已知但扫描不完整资产(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            evidence = make_snapshot_evidence(self.replay)
            evidence["输入资产集合"] = ["DS-000001", "DS-000002"]
            with self.assertRaisesRegex(ValueError, "input_asset_set_missing"):
                self.replay._evaluate_qualified_evidence(
                    frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                )

    def test_自报正式或伪合成来源不得进入第二门(self):
        untrusted_types = ("formal", "mock", "SMOKE-ONLY", "smoke_only", "smoke-only-v2", "任意自报")
        with tempfile.TemporaryDirectory() as directory:
            inventory, quality = make_inputs(Path(directory))
            frozen = self.replay.load_and_freeze_inputs(inventory, quality)
            for evidence_type in untrusted_types:
                evidence = make_snapshot_evidence(self.replay)
                evidence["证据类型"] = evidence_type
                with self.subTest(evidence_type=evidence_type), mock.patch.object(
                    self.replay, "execute_snapshot_replay", wraps=self.replay.execute_snapshot_replay
                ) as replay_call:
                    with self.assertRaisesRegex(ValueError, "source_provenance_unverified"):
                        self.replay._evaluate_qualified_evidence(
                            frozen["质量记录"]["DS-000001"], evidence, "DS-000001"
                        )
                    self.assertEqual(0, replay_call.call_count)

    def test_正式发布拒绝自报通过行和合成标记变体(self):
        base = {column: "无法判定" for column in self.replay.RESULT_COLUMNS}
        base.update({"资产编号": "DS-000001", "决策记录编号": "DEC-001"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for marker in ("mock", "SMOKE-ONLY", "smoke_only", "smoke-only-v2"):
                row = dict(base)
                row["依据"] = marker
                with self.subTest(marker=marker), self.assertRaisesRegex(
                    ValueError, "smoke_only_formal_output_rejected"
                ):
                    self.replay.publish_outputs(
                        root / "result.csv", root / "report.md", [row], "safe report"
                    )

            invented = dict(base)
            invented["重放结论"] = "通过"
            invented["依据"] = "formal invented text"
            with self.assertRaisesRegex(ValueError, "source_provenance_unverified"):
                self.replay.publish_outputs(
                    root / "result.csv", root / "report.md", [invented], "safe report"
                )

    def test_固定列公式防护与敏感发布失败保留旧版(self):
        password_key = "pass" + "word"
        row = {column: "无法判定" for column in self.replay.RESULT_COLUMNS}
        row.update({"资产编号": "DS-000001", "候选标的范围": "=cmd", "决策记录编号": "无法判定"})
        output = io.StringIO()
        self.replay.write_csv_stream(output, [row])
        self.assertNotIn("\r\n", output.getvalue())
        output.seek(0)
        parsed = list(csv.DictReader(output))
        self.assertEqual(list(self.replay.RESULT_COLUMNS), list(parsed[0]))
        self.assertEqual("'=cmd", parsed[0]["候选标的范围"])

        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "result.csv"
            report_path = Path(directory) / "report.md"
            csv_path.write_text("old-csv", encoding="utf-8")
            report_path.write_text("old-report", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sensitive_content_detected"):
                self.replay.publish_outputs(
                    csv_path, report_path, [row], f"{password_key}=do-not-write"
                )
            self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
            self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

            token_key = "to" + "ken"
            row["依据"] = f"{token_key}=do-not-redact-and-publish"
            with self.assertRaisesRegex(ValueError, "sensitive_content_detected"):
                self.replay.publish_outputs(csv_path, report_path, [row], "safe report")
            self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
            self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

    def test_第二份产物替换失败时回滚两份旧版(self):
        row = {column: "无法判定" for column in self.replay.RESULT_COLUMNS}
        row.update({"资产编号": "DS-000001", "决策记录编号": "无法判定"})
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "result.csv"
            report_path = Path(directory) / "report.md"
            csv_path.write_text("old-csv", encoding="utf-8")
            report_path.write_text("old-report", encoding="utf-8")
            real_replace = self.replay.os.replace

            def fail_second_publish(source: object, target: object) -> None:
                if Path(target) == report_path and Path(source).suffix == ".tmp":
                    raise OSError("simulated second publish failure")
                real_replace(source, target)

            with mock.patch.object(self.replay.os, "replace", side_effect=fail_second_publish):
                with self.assertRaises(OSError):
                    self.replay.publish_outputs(csv_path, report_path, [row], "safe report")
            self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
            self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

    def test_输出路径不得覆盖任务000003或000004输入(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = [
                root / "数据源清单.csv",
                root / "数据质量结果.csv",
                root / "数据断档结果.csv",
                root / "数据异常结果.csv",
                root / "数据质量审计报告.md",
            ]
            for path in protected:
                path.write_text("protected", encoding="utf-8")

            for target in protected:
                with self.subTest(target=target), self.assertRaisesRegex(
                    ValueError, "protected_input_path"
                ):
                    self.replay.validate_output_separation(
                        target if target.suffix == ".csv" else root / "result.csv",
                        target if target.suffix == ".md" else root / "report.md",
                        protected,
                    )

    def test_cli只读生成同一批次两份产物(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, quality = make_inputs(root)
            csv_path = root / "result.csv"
            report_path = root / "report.md"
            audit_report = root / "audit-report.md"
            audit_report.write_text(
                "\n".join([
                    "# 审计报告", "",
                    "- 审计批次：`audit-fixed`",
                    f"- 资产清单SHA-256：`{hashlib.sha256(inventory.read_bytes()).hexdigest()}`",
                    "- 规则版本：`dq-rules-1.0`",
                    f"- 规则SHA-256：`{'a' * 64}`", "",
                ]),
                encoding="utf-8",
            )
            with mock.patch.object(
                self.replay,
                "run_remote_preflight",
                return_value={
                    "status": "ok",
                    "python": "3.12.0",
                    "runtime": "python3-stdin-read-only-preflight",
                },
            ):
                status = self.replay.main([
                    "--inventory", str(inventory), "--quality", str(quality),
                    "--audit-report", str(audit_report),
                    "--ssh-target", "ubuntu", "--output", str(csv_path),
                    "--report", str(report_path), "--batch", "replay-fixed",
                ])
            self.assertEqual(0, status)
            with csv_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(3, len(rows))
            self.assertTrue(all(row["验证批次"] == "replay-fixed" for row in rows))
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("replay-fixed", report)
            self.assertNotIn("smoke-only 记录数", report)


if __name__ == "__main__":
    unittest.main()
