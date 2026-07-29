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

    def test_ssh仅允许逻辑别名ubunut并且远端失败不回显(self):
        self.assertEqual("ubuntu", self.replay.validate_ssh_target("ubuntu"))
        for invalid in ("root@ubuntu", "192.168.31.201", "prod", "ubuntu;id", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.replay.validate_ssh_target(invalid)

        completed = subprocess.CompletedProcess(
            args=[], returncode=255, stdout="", stderr="password=do-not-leak"
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

    def test_报告独立统计BTC_ETH_SOL且不外推(self):
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
        self.assertIn("| SOL | 0 |", report)
        self.assertIn("不得外推", report)
        self.assertIn("smoke-only", report)

    def test_固定列公式防护与敏感发布失败保留旧版(self):
        row = {column: "无法判定" for column in self.replay.RESULT_COLUMNS}
        row.update({"资产编号": "DS-000001", "候选标的范围": "=cmd", "决策记录编号": "无法判定"})
        output = io.StringIO()
        self.replay.write_csv_stream(output, [row])
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
                    csv_path, report_path, [row], "password=do-not-write"
                )
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

            row["依据"] = "token=do-not-redact-and-publish"
            with self.assertRaisesRegex(ValueError, "sensitive_content_detected"):
                self.replay.publish_outputs(csv_path, report_path, [row], "safe report")
            self.assertEqual("old-csv", csv_path.read_text(encoding="utf-8"))
            self.assertEqual("old-report", report_path.read_text(encoding="utf-8"))

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
