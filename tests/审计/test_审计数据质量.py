from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "审计" / "审计数据质量.py"
INVENTORY_COLUMNS = [
    "发现批次",
    "资产编号",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
]


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


def load_audit_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("data_quality_audit", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inventory_rows() -> list[dict[str, str]]:
    base = {
        "发现批次": "discovery-fixed",
        "逻辑主机": "ubuntu",
        "服务或项目": "crypto-radar",
        "资源名称": "btc.csv",
        "标的范围": "BTC",
        "时间范围": "未知",
        "字节数": "42",
        "最后修改时间": "2026-07-28T08:00:00+08:00",
        "访问状态": "元数据可访问",
        "发现证据": "只读元数据",
        "限制": "未审计内容",
        "后续任务": "任务-000004",
    }
    return [
        {
            **base,
            "资产编号": "DS-000001",
            "资产类型": "候选数据文件",
            "位置": "/opt/crypto-radar/data/btc.csv",
            "格式": "CSV",
        },
        {
            **base,
            "资产编号": "DS-000002",
            "资产类型": "数据库元数据",
            "服务或项目": "crypto_radar",
            "资源名称": "signals",
            "位置": "MySQL/crypto_radar/signals",
            "格式": "InnoDB",
            "标的范围": "未限定",
            "字节数": "未知",
            "最后修改时间": "未知",
            "访问状态": "可访问",
        },
    ]


def write_inventory(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=INVENTORY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


@unittest.skipUnless(MODULE_PATH.exists(), "等待数据质量审计实现")
class InventoryAndRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit_module()

    def test_清单校验并只选择验证单元(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.csv"
            rows = inventory_rows() + [
                {
                    **inventory_rows()[0],
                    "资产编号": "DS-000003",
                    "资产类型": "运行环境",
                    "位置": "ubuntu",
                    "格式": "Linux",
                }
            ]
            write_inventory(path, rows)

            loaded = self.audit.load_inventory(path)
            units = self.audit.build_validation_units(loaded)

        self.assertEqual(["DS-000001", "DS-000002"], [u["资产编号"] for u in units])

    def test_清单拒绝多批次重复编号和越界路径(self):
        mutations = []
        multiple_batches = inventory_rows()
        multiple_batches[1]["发现批次"] = "discovery-other"
        mutations.append((multiple_batches, "发现批次"))
        duplicate_ids = inventory_rows()
        duplicate_ids[1]["资产编号"] = "DS-000001"
        mutations.append((duplicate_ids, "资产编号"))
        outside = inventory_rows()
        outside[0]["位置"] = "/tmp/btc.csv"
        mutations.append((outside, "白名单"))

        for rows, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "inventory.csv"
                write_inventory(path, rows)
                if message == "白名单":
                    loaded = self.audit.load_inventory(path)
                    with self.assertRaisesRegex(ValueError, message):
                        self.audit.build_validation_units(loaded)
                else:
                    with self.assertRaisesRegex(ValueError, message):
                        self.audit.load_inventory(path)

    def test_mysql系统日志保留覆盖但禁止读取内容(self):
        row = {
            **inventory_rows()[0],
            "资产编号": "DS-000003",
            "服务或项目": "mysql",
            "资源名称": "general_log.CSV",
            "位置": "/var/lib/mysql/mysql/general_log.CSV",
        }

        units = self.audit.build_validation_units([row])
        remote_units = self.audit._remote_units(units)

        self.assertEqual(1, len(units))
        self.assertIn("敏感", units[0]["审计排除原因"])
        self.assertIn("敏感", remote_units[0]["excluded_reason"])

    def test_ssh目标别名必须安全(self):
        self.assertEqual("ubuntu", self.audit.validate_ssh_target("ubuntu"))
        for invalid in ("root@ubuntu", "ubuntu;id", "../ubuntu", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.audit.validate_ssh_target(invalid)

    def test_字段名只能形成时间候选不能证明时间语义(self):
        schema = {
            "audit_version": "1.0",
            "phase": "schema",
            "objects": [
                {
                    "asset_id": "DS-000001",
                    "status": "已发现结构",
                    "fields": ["event_time", "arrival_time", "collected_at"],
                    "types": {},
                    "primary_key": [],
                    "identity": {"size": 42, "mtime_ns": 1},
                },
                {
                    "asset_id": "DS-000002",
                    "status": "已发现结构",
                    "fields": ["id", "created_at"],
                    "types": {},
                    "primary_key": ["id"],
                    "identity": {},
                },
            ],
        }

        rules, fingerprint = self.audit.freeze_rules(schema)
        first = rules["objects"][0]

        self.assertEqual("无法判定", first["event_time_status"])
        self.assertEqual("无法判定", first["arrival_time_status"])
        self.assertEqual("无法判定", first["collection_time_status"])
        self.assertEqual("无法判定", first["gap_status"])
        self.assertIn("event_time", first["event_time_candidates"])
        self.assertEqual(64, len(fingerprint))

    def test_远端结果必须覆盖全部验证单元且不得重复(self):
        units = self.audit.build_validation_units(inventory_rows())
        payload = {
            "audit_version": "1.0",
            "phase": "schema",
            "objects": [
                {"asset_id": "DS-000001", "status": "已发现结构"},
                {"asset_id": "DS-000002", "status": "已发现结构"},
            ],
        }

        validated = self.audit.validate_remote_payload(payload, "schema", units)
        self.assertEqual(2, len(validated["objects"]))

        payload["objects"] = [payload["objects"][0]]
        with self.assertRaisesRegex(ValueError, "覆盖"):
            self.audit.validate_remote_payload(payload, "schema", units)

    def test_远端程序只包含允许的只读能力(self):
        probe = self.audit.REMOTE_AUDIT_PROGRAM

        for required in (
            "mode=ro",
            "query_only",
            "--no-defaults",
            "information_schema",
        ):
            self.assertIn(required, probe)
        for forbidden in (
            "sudo ",
            "os.environ",
            "getenv(",
            "systemctl ",
            "VACUUM",
            "ATTACH ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "CREATE TABLE",
            "write_text(",
            "open(path, \"w",
        ):
            self.assertNotIn(forbidden, probe)


@unittest.skipUnless(MODULE_PATH.exists(), "等待数据质量审计实现")
class LocalStatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit_module()

    def test_csv统计缺失重复和列宽异常(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.csv"
            path.write_text(
                "event_time,price\n1,10\n1,10\n2,\n3,12,extra\n",
                encoding="utf-8",
            )
            result = self.audit.audit_csv_file(path, duplicate_limit=100)

        self.assertEqual(4, result["record_count"])
        self.assertEqual(1, result["missing_count"])
        self.assertEqual(1, result["exact_duplicate_count"])
        self.assertEqual(1, result["row_width_error_count"])
        self.assertEqual("完整", result["scan_completeness"])

    def test_远端程序可执行且空清单返回合法结果(self):
        request = {
            "audit_version": "1.0",
            "phase": "schema",
            "objects": [],
            "rules": None,
            "duplicate_limit": 100,
            "object_timeout": 5,
        }
        completed = subprocess.run(
            [sys.executable, "-c", self.audit.REMOTE_AUDIT_PROGRAM],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual("schema", payload["phase"])
        self.assertEqual([], payload["objects"])

    def test_远端失败只返回异常类别不返回输入正文(self):
        request = {
            "audit_version": "1.0",
            "phase": "schema",
            "objects": "secret=should-not-leak",
        }
        completed = subprocess.run(
            [sys.executable, "-c", self.audit.REMOTE_AUDIT_PROGRAM],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(2, completed.returncode)
        self.assertIn("remote_audit_failed:ValueError", completed.stderr)
        self.assertNotIn("should-not-leak", completed.stderr)

    def test_ssh调用使用参数数组且不回显远端错误(self):
        units = self.audit.build_validation_units(inventory_rows())
        response = {
            "audit_version": "1.0",
            "phase": "schema",
            "objects": [
                {"asset_id": unit["资产编号"], "status": "无法判定"}
                for unit in units
            ],
        }
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(response), stderr="敏感远端错误"
        )
        with mock.patch.object(self.audit.subprocess, "run", return_value=completed) as runner:
            payload = self.audit.run_remote_phase(
                "ubuntu", "schema", units, None, "ssh", 30
            )

        command = runner.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertIn("BatchMode=yes", command)
        self.assertEqual("python3", command[-2])
        self.assertEqual("-", command[-1])
        self.assertNotIn(self.audit.REMOTE_AUDIT_PROGRAM, command)
        self.assertIn("REMOTE_REQUEST_JSON", runner.call_args.kwargs["input"])
        self.assertEqual(2, len(payload["objects"]))

        failure = subprocess.CompletedProcess(
            args=[], returncode=255, stdout="", stderr="server=192.168.31.201"
        )
        with mock.patch.object(self.audit.subprocess, "run", return_value=failure):
            with self.assertRaisesRegex(RuntimeError, "SSH远端审计失败") as caught:
                self.audit.run_remote_phase("ubuntu", "schema", units, None, "ssh", 30)
        self.assertNotIn("192.168.31.201", str(caught.exception))

    def test_jsonl统计结构异常和规范重复(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.jsonl"
            path.write_text(
                '{"event_time":1,"price":10}\n'
                '{"price":10,"event_time":1}\n'
                "\n"
                "not-json\n"
                "[]\n"
                '{"event_time":2}\n',
                encoding="utf-8",
            )
            result = self.audit.audit_jsonl_file(path, duplicate_limit=100)

        self.assertEqual(3, result["record_count"])
        self.assertEqual(1, result["exact_duplicate_count"])
        self.assertEqual(1, result["empty_line_count"])
        self.assertEqual(1, result["invalid_json_count"])
        self.assertEqual(1, result["non_object_count"])
        self.assertEqual(1, result["missing_count"])

    def test_sqlite以只读方式统计空值和主键(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                "CREATE TABLE bars(id INTEGER PRIMARY KEY, price REAL, note TEXT);"
                "INSERT INTO bars VALUES (1, 10.0, 'ok');"
                "INSERT INTO bars VALUES (2, NULL, '');"
            )
            connection.commit()
            connection.close()

            result = self.audit.audit_sqlite_file(path)

        self.assertEqual(2, result["record_count"])
        self.assertEqual(2, result["missing_count"])
        self.assertEqual(["bars.id"], result["primary_key"])
        self.assertEqual("完整", result["scan_completeness"])


@unittest.skipUnless(MODULE_PATH.exists(), "等待数据质量审计实现")
class OutputContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.audit = load_audit_module()

    def test_csv防公式注入且三类输出共享批次(self):
        units = inventory_rows()
        units[0]["服务或项目"] = "=WEBSERVICE(1)"
        schema = {
            "objects": [
                {"asset_id": row["资产编号"], "status": "已发现结构", "fields": []}
                for row in units
            ]
        }
        quality_payload = {
            "objects": [
                {
                    "asset_id": row["资产编号"],
                    "status": "完成",
                    "scan_completeness": "完整",
                    "record_count": 0,
                }
                for row in units
            ]
        }
        rules = {
            "objects": [
                {
                    "asset_id": row["资产编号"],
                    "event_time_status": "无法判定",
                    "arrival_time_status": "无法判定",
                    "collection_time_status": "无法判定",
                    "gap_status": "无法判定",
                }
                for row in units
            ]
        }
        metadata = {
            "audit_batch": "audit-fixed",
            "inventory_fingerprint": "a" * 64,
            "rules_fingerprint": "b" * 64,
            "cutoff_time": "2026-07-28T10:00:00+08:00",
        }

        quality, gaps, anomalies = self.audit.build_output_rows(
            units, schema, quality_payload, rules, metadata
        )
        quality_csv = self.audit.render_csv(self.audit.QUALITY_COLUMNS, quality)

        self.assertEqual(len(units), len(quality))
        self.assertEqual(len(units), len(gaps))
        self.assertEqual({"DS-000001", "DS-000002"}, {row["资产编号"] for row in anomalies})
        self.assertIn("'=WEBSERVICE(1)", quality_csv)
        self.assertTrue(all(row["审计批次"] == "audit-fixed" for row in quality + gaps + anomalies))

    def test_报告分别保留三个标的无法判定结论(self):
        report = self.audit.render_report(
            [],
            [],
            [],
            {
                "audit_batch": "audit-fixed",
                "inventory_fingerprint": "a" * 64,
                "rules_fingerprint": "b" * 64,
                "cutoff_time": "2026-07-28T10:00:00+08:00",
                "unit_count": 0,
            },
        )

        for symbol in ("BTC", "ETH", "SOL"):
            self.assertIn(f"| {symbol} | 无法判定 |", report)
        self.assertIn("## 技术摘要", report)
        self.assertIn("## 全部验证单元均未达到可用性证据门槛", report)
        self.assertIn("## BTC、ETH、SOL均无法判定", report)
        self.assertIn("## 作用域与指标定义", report)
        self.assertIn("## 方法与稳健性检查", report)
        self.assertIn("## 推荐的解除路径", report)
        self.assertIn("## 仍需回答的问题", report)

    def test_报告汇总完整扫描缺失重复与时间候选但不提升语义(self):
        quality_rows = [
            {
                "资产类型": "候选数据文件",
                "扫描完整性": "完整",
                "扫描状态": "完成",
                "记录数": "3",
                "结构缺失数": "2",
                "重复状态": "已量化（规范记录完全一致）",
                "精确重复数": "1",
                "事件时间候选字段": "event_time",
                "到达时间候选字段": "无",
                "采集时间候选字段": "created_at",
                "可用性结论": "无法判定",
            },
            {
                "资产类型": "数据库元数据",
                "扫描完整性": "元数据范围",
                "扫描状态": "仅元数据",
                "记录数": "10",
                "结构缺失数": "无法判定",
                "重复状态": "无法判定（未读取业务记录）",
                "精确重复数": "无法判定",
                "事件时间候选字段": "无",
                "到达时间候选字段": "无",
                "采集时间候选字段": "无",
                "可用性结论": "无法判定",
            },
        ]
        report = self.audit.render_report(
            quality_rows,
            [],
            [],
            {
                "audit_batch": "audit-fixed",
                "inventory_fingerprint": "a" * 64,
                "rules_fingerprint": "b" * 64,
                "cutoff_time": "2026-07-28T10:00:00+08:00",
                "unit_count": 2,
            },
        )

        self.assertIn("完整扫描文件记录：3条", report)
        self.assertIn("结构空值或空文本：2项", report)
        self.assertIn("已量化的规范记录重复：1条", report)
        self.assertIn("事件时间候选字段：1个验证单元", report)
        self.assertIn("候选不构成时间语义证明", report)

    def test_脱敏覆盖地址私钥令牌和明文凭据(self):
        raw = (
            "server=192.168.31.201 password=hunter2 "
            "ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "-----BEGIN PRIVATE KEY-----"
        )
        redacted = self.audit.redact(raw)

        self.assertNotIn("192.168.31.201", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("ghp_", redacted)
        self.assertNotIn("BEGIN PRIVATE KEY", redacted)

    def test_发布前置失败不覆盖既有产物且拒绝符号链接(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "quality.csv"
            existing.write_text("old", encoding="utf-8")
            target = root / "linked.md"
            real_target = root / "real.md"
            real_target.write_text("real", encoding="utf-8")
            os.symlink(real_target, target)

            with self.assertRaisesRegex(ValueError, "符号链接"):
                self.audit.publish_outputs({existing: "new", target: "report"})

            self.assertEqual("old", existing.read_text(encoding="utf-8"))
            self.assertEqual("real", real_target.read_text(encoding="utf-8"))

    def test_完整命令行流程生成同一批次的四个产物(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.csv"
            output_dir = root / "artifacts"
            output_dir.mkdir()
            report = root / "report.md"
            write_inventory(inventory, inventory_rows())
            schema = {
                "audit_version": "1.0",
                "phase": "schema",
                "objects": [
                    {
                        "asset_id": "DS-000001",
                        "status": "已发现结构",
                        "fields": ["event_time", "price"],
                        "types": {},
                        "primary_key": [],
                        "identity": {"size": 42, "mtime_ns": 1},
                    },
                    {
                        "asset_id": "DS-000002",
                        "status": "已发现结构",
                        "fields": ["id"],
                        "types": {},
                        "primary_key": ["id"],
                        "identity": {},
                    },
                ],
            }
            quality = {
                "audit_version": "1.0",
                "phase": "quality",
                "objects": [
                    {
                        "asset_id": "DS-000001",
                        "status": "完成",
                        "scan_completeness": "完整",
                        "record_count": 2,
                        "field_count": 2,
                        "missing_count": 0,
                        "exact_duplicate_count": 0,
                    },
                    {
                        "asset_id": "DS-000002",
                        "status": "仅元数据",
                        "scan_completeness": "元数据范围",
                        "record_count": "无法判定",
                        "field_count": 1,
                        "missing_count": "无法判定",
                    },
                ],
            }

            with mock.patch.object(
                self.audit, "run_remote_phase", side_effect=[schema, quality]
            ) as runner:
                exit_code = self.audit.main(
                    [
                        "--inventory",
                        str(inventory),
                        "--ssh-target",
                        "ubuntu",
                        "--output-dir",
                        str(output_dir),
                        "--report",
                        str(report),
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual(2, runner.call_count)
            outputs = [
                output_dir / "数据质量结果.csv",
                output_dir / "数据断档结果.csv",
                output_dir / "数据异常结果.csv",
                report,
            ]
            self.assertTrue(all(path.is_file() for path in outputs))
            batches = set()
            for path in outputs[:3]:
                with path.open(encoding="utf-8") as handle:
                    rows = list(csv.DictReader(handle))
                self.assertTrue(rows)
                batches.update(row["审计批次"] for row in rows)
            self.assertEqual(1, len(batches))
            self.assertIn(next(iter(batches)), report.read_text(encoding="utf-8"))

    def test_远端失败时不覆盖既有正式产物(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.csv"
            output_dir = root / "artifacts"
            output_dir.mkdir()
            quality_path = output_dir / "数据质量结果.csv"
            quality_path.write_text("old", encoding="utf-8")
            report = root / "report.md"
            report.write_text("old-report", encoding="utf-8")
            write_inventory(inventory, inventory_rows())

            with mock.patch.object(
                self.audit,
                "run_remote_phase",
                side_effect=RuntimeError("SSH远端审计失败"),
            ):
                exit_code = self.audit.main(
                    [
                        "--inventory",
                        str(inventory),
                        "--ssh-target",
                        "ubuntu",
                        "--output-dir",
                        str(output_dir),
                        "--report",
                        str(report),
                    ]
                )

            self.assertEqual(1, exit_code)
            self.assertEqual("old", quality_path.read_text(encoding="utf-8"))
            self.assertEqual("old-report", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
