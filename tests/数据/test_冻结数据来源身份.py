from __future__ import annotations

import csv
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "数据" / "冻结数据来源身份.py"
CONFIG_PATH = REPO_ROOT / "config" / "数据" / "数据来源与资产身份.json"
CONTRACT_PATH = REPO_ROOT / "docs" / "数据" / "数据来源与资产身份合同.md"
MAIN_BASELINE = "c7763a411ba6c239ddecb923bf04ebbbec5eebf3"
TASK_28_MERGE = "e138bd589a5bde38c81f48d38b7c449f6f13df37"
TASK_38_MERGE = "b49cf2fabfbbb2968dc18efba80121de0d7601e8"
TASK_29_BASELINE_SHA = "025f6498fa29edc5fc6c1cdb8214a1215b3e0fe7869bdb543a9ceb440e56d560"
EVIDENCE_VERSION = "source-identity-evidence-1.0"

INVENTORY_COLUMNS = (
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
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_module() -> ModuleType:
    if not MODULE_PATH.exists():
        raise AssertionError(f"实现文件尚不存在：{MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("freeze_source_identity", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_inventory(path: Path, *, reverse: bool = False) -> None:
    rows = [
        {
            "发现批次": "discovery-test",
            "资产编号": "DS-000002",
            "资产类型": "候选数据文件",
            "逻辑主机": "ubuntu",
            "服务或项目": "测试项目",
            "资源名称": "BTCUSDT_seconds.csv",
            "位置": "/opt/binance-event/data/BTCUSDT_seconds.csv",
            "格式": "CSV",
            "标的范围": "BTC",
            "时间范围": "未知",
            "字节数": "42",
            "最后修改时间": "2026-08-03T00:00:00+08:00",
            "访问状态": "元数据可访问",
            "发现证据": "测试元数据",
            "限制": "仅测试",
            "后续任务": "任务-000029",
        },
        {
            "发现批次": "discovery-test",
            "资产编号": "DS-000001",
            "资产类型": "数据库元数据",
            "逻辑主机": "ubuntu",
            "服务或项目": "market_data",
            "资源名称": "ticks",
            "位置": "MySQL/market_data/ticks",
            "格式": "InnoDB",
            "标的范围": "未限定",
            "时间范围": "未知",
            "字节数": "未知",
            "最后修改时间": "未知",
            "访问状态": "可访问",
            "发现证据": "information_schema元数据",
            "限制": "未读取业务记录",
            "后续任务": "任务-000029",
        },
        {
            "发现批次": "discovery-test",
            "资产编号": "DS-000003",
            "资产类型": "运行服务",
            "逻辑主机": "ubuntu",
            "服务或项目": "测试项目",
            "资源名称": "irrelevant.service",
            "位置": "systemd",
            "格式": "不适用",
            "标的范围": "未限定",
            "时间范围": "未知",
            "字节数": "未知",
            "最后修改时间": "未知",
            "访问状态": "运行中",
            "发现证据": "测试",
            "限制": "不属于候选数据对象",
            "后续任务": "任务-000029",
        },
    ]
    if reverse:
        rows.reverse()
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=INVENTORY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def valid_contract(root: Path, inventory: Path) -> dict[str, object]:
    current_task = root / "docs" / "研发中心" / "任务" / "任务-000029.md"
    current_task.parent.mkdir(parents=True, exist_ok=True)
    current_task.write_text("# smoke-only执行任务\n", encoding="utf-8")
    evidence_files = []
    for name in ("数据源说明.md", "既有审计报告.md", "缺口清单.md", "发现器.py"):
        path = root / name
        path.write_text(f"{name} smoke-only\n", encoding="utf-8")
        evidence_files.append(
            {
                "用途": name,
                "路径": name,
                "SHA-256": sha256(path),
            }
        )
    return {
        "合同版本": "source-identity-1.0",
        "任务编号": "任务-000029",
        "治理基线": governance_baseline(),
        "输入文件": [
            {
                "用途": "资产清单",
                "路径": inventory.name,
                "SHA-256": sha256(inventory),
            },
            *evidence_files,
        ],
        "候选资产类型": ["候选数据文件", "数据库元数据"],
        "标的": ["BTC", "ETH"],
        "身份字段": [
            "来源提供者",
            "交易场所",
            "市场类型",
            "标的身份",
            "精确合约",
            "数据对象",
            "Schema确切版本",
            "授权边界",
            "字段中文映射",
        ],
        "允许状态": ["已证明", "拒绝", "无法判定"],
        "允许SSH目标": ["ubuntu"],
        "允许文件根目录": [
            "/opt/binance-event",
            "/opt/celueqing",
            "/opt/crypto-radar",
            "/opt/event-prob-lab",
            "/opt/orderbook-intelligence-service",
            "/var/lib/mysql",
        ],
        "数据库元数据范围": [
            "information_schema.TABLES",
            "information_schema.COLUMNS",
        ],
        "资源上限": {
            "批次总超时秒": 600,
            "逐成员超时秒": 5,
            "最大成员数": 1000,
            "最大输出字节数": 8 * 1024 * 1024,
            "最大日志字节数": 32 * 1024,
        },
        "安全边界": {
            "远端写入": False,
            "远端临时文件": False,
            "数据库业务记录读取": False,
            "读取环境变量或凭据": False,
            "原始业务记录落盘": False,
            "修改原始数据": False,
        },
        "身份声明": [],
    }


def write_contract(path: Path, contract: dict[str, object]) -> None:
    path.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def governance_baseline() -> dict[str, str]:
    return {
        "main基线提交": MAIN_BASELINE,
        "任务-000028合并提交": TASK_28_MERGE,
        "任务-000038合并提交": TASK_38_MERGE,
        "任务-000029基线路径": "docs/研发中心/任务/任务-000029.md",
        "任务-000029基线SHA-256": TASK_29_BASELINE_SHA,
    }


def add_identity_evidence(
    contract: dict[str, object],
    root: Path,
    input_member_hash: str,
    *,
    asset_id: str = "DS-000001",
    target: str = "BTC",
) -> tuple[str, str, Path, dict[str, object]]:
    evidence_path = root / "身份合同证据.json"
    purpose = "身份合同证据:测试来源合同"
    field_values: dict[str, object] = {
        "来源提供者": "已核验提供者",
        "交易场所": "已核验场所",
        "市场类型": "现货",
        "标的身份": "BTC",
        "精确合约": "BTC/法币现货合同V1",
        "数据对象": "逐笔成交",
        "Schema确切版本": "sha256:" + "3" * 64,
        "授权边界": "仅获批元数据复核",
        "字段中文映射": [
            {
                "原始字段": "event_id",
                "中文名称": "事件编号",
                "类型": "字符串",
                "单位": "不适用",
                "精度": "不适用",
                "空值语义": "禁止为空",
            }
        ],
    }
    evidence = {
        "证据版本": EVIDENCE_VERSION,
        "记录": [
            {
                "证据记录编号": f"EVI-000001-{index:02d}",
                "资产编号": asset_id,
                "标的": target,
                "输入成员SHA-256": input_member_hash,
                "证明字段": field,
                "声明值": value,
            }
            for index, (field, value) in enumerate(field_values.items(), start=1)
        ],
    }
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    contract["输入文件"].append(
        {
            "用途": purpose,
            "路径": evidence_path.name,
            "SHA-256": sha256(evidence_path),
        }
    )
    return purpose, sha256(evidence_path), evidence_path, evidence


def rewrite_identity_evidence(
    contract: dict[str, object],
    purpose: str,
    evidence_path: Path,
    evidence: dict[str, object],
) -> str:
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    fingerprint = sha256(evidence_path)
    item = next(item for item in contract["输入文件"] if item["用途"] == purpose)
    item["SHA-256"] = fingerprint
    return fingerprint


def proven_claim(
    input_member_hash: str,
    evidence_purpose: str,
    evidence_hash: str,
) -> dict[str, object]:
    identity_fields = [
        "来源提供者",
        "交易场所",
        "市场类型",
        "标的身份",
        "精确合约",
        "数据对象",
        "Schema确切版本",
        "授权边界",
        "字段中文映射",
    ]
    return {
        "资产编号": "DS-000001",
        "标的": "BTC",
        "状态": "已证明",
        "输入成员SHA-256": input_member_hash,
        "远端元数据SHA-256": "1" * 64,
        "来源提供者": "已核验提供者",
        "交易场所": "已核验场所",
        "市场类型": "现货",
        "标的身份": "BTC",
        "精确合约": "BTC/法币现货合同V1",
        "数据对象": "逐笔成交",
        "Schema确切版本": "sha256:" + "3" * 64,
        "授权边界": "仅获批元数据复核",
        "字段中文映射": [
            {
                "原始字段": "event_id",
                "中文名称": "事件编号",
                "类型": "字符串",
                "单位": "不适用",
                "精度": "不适用",
                "空值语义": "禁止为空",
            }
        ],
        "证据": [
            {
                "证据用途": evidence_purpose,
                "证据定位": f"EVI-000001-{index:02d}",
                "SHA-256": evidence_hash,
                "证明字段": [field],
            }
            for index, field in enumerate(identity_fields, start=1)
        ],
        "限制": "只证明登记范围",
        "解除条件": "不适用",
    }


def observed_probe() -> dict[str, object]:
    return {
        "探针版本": "source-identity-probe-1.0",
        "远端写入": False,
        "数据库业务记录读取": False,
        "结果": [
            {
                "资产编号": "DS-000002",
                "复核状态": "已观察",
                "元数据SHA-256": "2" * 64,
                "SchemaSHA-256": "",
                "证据": "白名单普通文件stat元数据与冻结输入一致",
                "限制": "未读取文件正文",
            },
            {
                "资产编号": "DS-000001",
                "复核状态": "已观察",
                "元数据SHA-256": "1" * 64,
                "SchemaSHA-256": "3" * 64,
                "证据": "获批information_schema元数据与冻结输入一致",
                "限制": "未读取数据库业务记录",
            },
        ],
    }


def encoded_text(value: str | None) -> str:
    if value is None:
        return "N"
    return "H" + value.encode("utf-8").hex().upper()


def encoded_number(value: int | None) -> str:
    return "N" if value is None else f"V{value}"


def schema_row(**changes: str) -> list[str]:
    fields = [
        encoded_text("market_data"),
        encoded_text("ticks"),
        encoded_text("InnoDB"),
        encoded_text("utf8mb4_0900_ai_ci"),
        encoded_text("Dynamic"),
        encoded_text(""),
        encoded_number(1),
        encoded_text("id"),
        encoded_text("bigint unsigned"),
        encoded_text("NO"),
        encoded_text(None),
        encoded_text(None),
        encoded_text(None),
        encoded_text("PRI"),
        encoded_number(20),
        encoded_number(0),
        encoded_number(None),
        encoded_text(""),
        encoded_text(""),
        encoded_text("identifier"),
    ]
    indexes = {
        "default": 10,
        "column_collation": 12,
        "column_key": 13,
        "generation": 18,
    }
    for name, value in changes.items():
        fields[indexes[name]] = value
    return fields


def run_fake_mysql_probe(
    module: ModuleType,
    root: Path,
    rows: list[list[str]],
    *,
    row_limit: int | None = None,
) -> dict[str, object]:
    mysql = root / "mysql"
    if rows:
        commands = "\n".join(
            "printf '%s\\n' '" + "\t".join(row) + "'" for row in rows
        )
    else:
        commands = "exit 0"
    mysql.write_text("#!/bin/sh\n" + commands + "\n", encoding="utf-8")
    mysql.chmod(0o755)
    unused = root / "unused.csv"
    unused.write_text("smoke\n", encoding="utf-8")
    contract = valid_contract(root, unused)
    assets = [
        {
            "资产编号": "DS-000001",
            "资产类型": "数据库元数据",
            "位置": "MySQL/market_data/ticks",
            "格式": "InnoDB",
            "字节数": "未知",
            "最后修改时间": "未知",
            "数据库Schema": "market_data",
            "数据库表": "ticks",
        }
    ]
    script = module.build_probe_script(assets, contract)
    script = script.replace(
        '"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
        f'"PATH": {str(root)!r}',
    )
    if row_limit is not None:
        script = script.replace("DB_ROW_LIMIT = 200000", f"DB_ROW_LIMIT = {row_limit}")
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)["结果"][0]


class DeliveryPresenceTests(unittest.TestCase):
    def test_四类固定交付物存在(self):
        for path in (MODULE_PATH, CONFIG_PATH, CONTRACT_PATH, Path(__file__)):
            self.assertTrue(path.exists(), f"固定交付物尚不存在：{path}")


@unittest.skipUnless(MODULE_PATH.exists(), "等待冻结来源身份实现")
class FreezeSourceIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def assert_api(self, name: str):
        self.assertTrue(hasattr(self.module, name), f"缺少接口：{name}")
        return getattr(self.module, name)

    def assert_contract_loads(self, load_contract, config: Path, root: Path):
        try:
            return load_contract(config, root)
        except ValueError as error:
            self.fail(f"符合新合同的配置应可加载：{error}")

    def invoke_main(self, config: Path, batch_root: Path) -> tuple[int, str, str]:
        return self.invoke_main_args(
            [
                "--contract",
                str(config),
                "--ssh-target",
                "ubuntu",
                "--batch-root",
                str(batch_root),
                "--timeout",
                "60",
            ]
        )

    def invoke_main_args(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                returncode = self.module.main(arguments)
            except SystemExit as error:
                returncode = int(error.code)
        return returncode, stdout.getvalue(), stderr.getvalue()

    def make_inputs(self, root: Path, *, reverse: bool = False):
        inventory = root / "inventory.csv"
        config = root / "contract.json"
        write_inventory(inventory, reverse=reverse)
        write_contract(config, valid_contract(root, inventory))
        return inventory, config

    def test_合同精确冻结输入与安全边界(self):
        load_contract = self.assert_api("load_contract")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = self.assert_contract_loads(load_contract, config, root)
            self.assertEqual(["ubuntu"], contract["允许SSH目标"])

            invalid = valid_contract(root, inventory)
            invalid["未知字段"] = True
            write_contract(config, invalid)
            with self.assertRaisesRegex(ValueError, "未知字段"):
                load_contract(config, root)

            invalid = valid_contract(root, inventory)
            invalid["输入文件"][0]["SHA-256"] = "0" * 64
            write_contract(config, invalid)
            with self.assertRaisesRegex(ValueError, "指纹"):
                load_contract(config, root)

    def test_成员覆盖BTC和ETH且不从路径字段猜身份(self):
        load_contract = self.assert_api("load_contract")
        build_members = self.assert_api("build_members")
        with tempfile.TemporaryDirectory() as first_directory, tempfile.TemporaryDirectory() as second_directory:
            first = Path(first_directory)
            second = Path(second_directory)
            first_inventory, first_config = self.make_inputs(first)
            second_inventory, second_config = self.make_inputs(second, reverse=True)
            forward = build_members(first_inventory, load_contract(first_config, first))
            reverse = build_members(second_inventory, load_contract(second_config, second))

        self.assertEqual(forward, reverse)
        self.assertEqual(4, len(forward))
        self.assertEqual(4, len({row["成员编号"] for row in forward}))
        self.assertEqual(
            [("DS-000001", "BTC"), ("DS-000001", "ETH"), ("DS-000002", "BTC"), ("DS-000002", "ETH")],
            [(row["资产编号"], row["标的"]) for row in forward],
        )
        file_btc = next(
            row for row in forward if row["资产编号"] == "DS-000002" and row["标的"] == "BTC"
        )
        for field in (
            "来源提供者",
            "交易场所",
            "市场类型",
            "标的身份",
            "精确合约",
            "数据对象",
            "Schema确切版本",
            "授权边界",
        ):
            self.assertEqual("未知", file_btc[field])

    def test_只有完整证据声明可成为已证明且BTC_ETH独立(self):
        load_contract = self.assert_api("load_contract")
        build_members = self.assert_api("build_members")
        evaluate_identities = self.assert_api("evaluate_identities")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            raw = valid_contract(root, inventory)
            initial_contract = load_contract(config, root)
            input_member_hash = next(
                row["输入成员SHA-256"]
                for row in build_members(inventory, initial_contract)
                if row["资产编号"] == "DS-000001"
            )
            purpose, evidence_hash, _evidence_path, _evidence = add_identity_evidence(
                raw, root, input_member_hash
            )
            raw["身份声明"] = [
                proven_claim(input_member_hash, purpose, evidence_hash)
            ]
            write_contract(config, raw)
            contract = self.assert_contract_loads(load_contract, config, root)
            members = build_members(inventory, contract)
            rows, summary = evaluate_identities(members, observed_probe(), contract)

        btc = next(row for row in rows if row["资产编号"] == "DS-000001" and row["标的"] == "BTC")
        eth = next(row for row in rows if row["资产编号"] == "DS-000001" and row["标的"] == "ETH")
        self.assertEqual("已证明", btc["状态"])
        self.assertEqual("无法判定", eth["状态"])
        self.assertEqual(4, summary["身份成员总体"])
        self.assertEqual(4, sum(summary["三态计数"].values()))
        for target in ("BTC", "ETH"):
            self.assertEqual(2, sum(summary["分标的三态计数"][target].values()))

    def test_缺失漂移和超时使用三态失败安全(self):
        load_contract = self.assert_api("load_contract")
        build_members = self.assert_api("build_members")
        evaluate_identities = self.assert_api("evaluate_identities")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = self.assert_contract_loads(load_contract, config, root)
            members = build_members(inventory, contract)
            probe = observed_probe()
            probe["结果"][0]["复核状态"] = "拒绝"
            probe["结果"][0]["证据"] = "冻结元数据漂移"
            probe["结果"][1]["复核状态"] = "无法判定"
            probe["结果"][1]["证据"] = "逐成员元数据复核超时"
            rows, summary = evaluate_identities(members, probe, contract)

        states_by_asset = {
            asset_id: {row["状态"] for row in rows if row["资产编号"] == asset_id}
            for asset_id in ("DS-000001", "DS-000002")
        }
        self.assertEqual({"无法判定"}, states_by_asset["DS-000001"])
        self.assertEqual({"拒绝"}, states_by_asset["DS-000002"])
        self.assertEqual(2, summary["三态计数"]["拒绝"])
        self.assertEqual(2, summary["三态计数"]["无法判定"])

    def test_有效拒绝声明在探针无法判定时仍优先执行(self):
        load_contract = self.assert_api("load_contract")
        build_members = self.assert_api("build_members")
        evaluate_identities = self.assert_api("evaluate_identities")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            raw = valid_contract(root, inventory)
            initial_contract = load_contract(config, root)
            input_member_hash = next(
                row["输入成员SHA-256"]
                for row in build_members(inventory, initial_contract)
                if row["资产编号"] == "DS-000001"
            )
            purpose, evidence_hash, evidence_path, evidence = add_identity_evidence(
                raw, root, input_member_hash
            )
            evidence["记录"] = [
                {
                    "证据记录编号": "EVI-REJECT-000001",
                    "资产编号": "DS-000001",
                    "标的": "BTC",
                    "输入成员SHA-256": input_member_hash,
                    "证明字段": "拒绝结论",
                    "声明值": "拒绝",
                }
            ]
            evidence_hash = rewrite_identity_evidence(
                raw, purpose, evidence_path, evidence
            )
            raw["身份声明"] = [
                {
                    "资产编号": "DS-000001",
                    "标的": "BTC",
                    "状态": "拒绝",
                    "输入成员SHA-256": input_member_hash,
                    "远端元数据SHA-256": "1" * 64,
                    "来源提供者": "未知",
                    "交易场所": "未知",
                    "市场类型": "未知",
                    "标的身份": "未知",
                    "精确合约": "未知",
                    "数据对象": "未知",
                    "Schema确切版本": "未知",
                    "授权边界": "未知",
                    "字段中文映射": [],
                    "证据": [
                        {
                            "证据用途": purpose,
                            "证据定位": "EVI-REJECT-000001",
                            "SHA-256": evidence_hash,
                            "证明字段": ["拒绝结论"],
                        }
                    ],
                    "限制": "冻结证据明确拒绝",
                    "解除条件": "提供新的专用身份合同证据",
                }
            ]
            write_contract(config, raw)
            contract = self.assert_contract_loads(load_contract, config, root)
            members = build_members(inventory, contract)
            probe = observed_probe()
            probe["结果"][1].update(
                {
                    "复核状态": "无法判定",
                    "元数据SHA-256": "",
                    "SchemaSHA-256": "",
                    "证据": "逐成员元数据复核超时",
                }
            )
            rows, _summary = evaluate_identities(members, probe, contract)

        rejected = next(
            row
            for row in rows
            if row["资产编号"] == "DS-000001" and row["标的"] == "BTC"
        )
        self.assertEqual("拒绝", rejected["状态"])
        self.assertIn("身份合同证据", rejected["证据"])

    def test_声明拒绝陈旧成员指纹非结构化证据和缺字段证明(self):
        load_contract = self.assert_api("load_contract")
        build_members = self.assert_api("build_members")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            initial = load_contract(config, root)
            input_member_hash = next(
                row["输入成员SHA-256"]
                for row in build_members(inventory, initial)
                if row["资产编号"] == "DS-000001"
            )
            raw = valid_contract(root, inventory)
            purpose, evidence_hash, evidence_path, evidence = add_identity_evidence(
                raw, root, input_member_hash
            )
            claim = proven_claim(input_member_hash, purpose, evidence_hash)
            raw["身份声明"] = [claim]
            write_contract(config, raw)
            loaded = self.assert_contract_loads(load_contract, config, root)
            self.assertEqual(input_member_hash, loaded["身份声明"][0]["输入成员SHA-256"])

            missing_locator = deepcopy(raw)
            missing_locator["身份声明"][0]["证据"][0]["证据定位"] = "EVI-NOT-FOUND"
            write_contract(config, missing_locator)
            with self.assertRaisesRegex(ValueError, "证据定位"):
                load_contract(config, root)

            wrong_value = deepcopy(raw)
            wrong_value["身份声明"][0]["来源提供者"] = "与证据不一致的提供者"
            write_contract(config, wrong_value)
            with self.assertRaisesRegex(ValueError, "声明值"):
                load_contract(config, root)

            for field, wrong in (
                ("资产编号", "DS-999999"),
                ("标的", "ETH"),
                ("输入成员SHA-256", "9" * 64),
            ):
                with self.subTest(证据绑定字段=field):
                    mismatch = deepcopy(raw)
                    mismatch_evidence = deepcopy(evidence)
                    mismatch_evidence["记录"][0][field] = wrong
                    mismatch_hash = rewrite_identity_evidence(
                        mismatch, purpose, evidence_path, mismatch_evidence
                    )
                    for item in mismatch["身份声明"][0]["证据"]:
                        item["SHA-256"] = mismatch_hash
                    write_contract(config, mismatch)
                    with self.assertRaisesRegex(ValueError, "证据记录绑定"):
                        load_contract(config, root)

            original_hash = rewrite_identity_evidence(raw, purpose, evidence_path, evidence)
            for item in raw["身份声明"][0]["证据"]:
                item["SHA-256"] = original_hash

            stale = deepcopy(raw)
            stale["身份声明"][0]["输入成员SHA-256"] = "0" * 64
            write_contract(config, stale)
            with self.assertRaisesRegex(ValueError, "输入成员指纹"):
                load_contract(config, root)

            ordinary = deepcopy(raw)
            ordinary["身份声明"][0]["证据"][0]["证据用途"] = "既有审计报告.md"
            ordinary["身份声明"][0]["证据"][0]["SHA-256"] = sha256(
                root / "既有审计报告.md"
            )
            write_contract(config, ordinary)
            with self.assertRaisesRegex(ValueError, "专用身份合同证据"):
                load_contract(config, root)

            markdown = deepcopy(raw)
            markdown_path = root / "伪身份合同证据.md"
            markdown_path.write_text(
                "# 身份合同证据\n\n自述已证明全部字段。\n",
                encoding="utf-8",
            )
            markdown_purpose = "身份合同证据:普通Markdown"
            markdown["输入文件"].append(
                {
                    "用途": markdown_purpose,
                    "路径": markdown_path.name,
                    "SHA-256": sha256(markdown_path),
                }
            )
            for item in markdown["身份声明"][0]["证据"]:
                item["证据用途"] = markdown_purpose
                item["SHA-256"] = sha256(markdown_path)
            write_contract(config, markdown)
            with self.assertRaisesRegex(ValueError, "结构化身份合同证据"):
                load_contract(config, root)

            smoke = deepcopy(raw)
            smoke_evidence = deepcopy(evidence)
            smoke_evidence["证据版本"] = "smoke-only-self-asserted"
            smoke_hash = rewrite_identity_evidence(
                smoke, purpose, evidence_path, smoke_evidence
            )
            for item in smoke["身份声明"][0]["证据"]:
                item["SHA-256"] = smoke_hash
            write_contract(config, smoke)
            with self.assertRaisesRegex(ValueError, "证据版本"):
                load_contract(config, root)

            original_hash = rewrite_identity_evidence(raw, purpose, evidence_path, evidence)
            for item in raw["身份声明"][0]["证据"]:
                item["SHA-256"] = original_hash

            missing_field = deepcopy(raw)
            missing_field["身份声明"][0]["证据"].pop()
            write_contract(config, missing_field)
            with self.assertRaisesRegex(ValueError, "覆盖全部身份字段"):
                load_contract(config, root)

            empty_locator = deepcopy(raw)
            empty_locator["身份声明"][0]["证据"][0]["证据定位"] = ""
            write_contract(config, empty_locator)
            with self.assertRaisesRegex(ValueError, "证据定位"):
                load_contract(config, root)

    def test_治理基线冻结且可复核基线任务内容(self):
        load_contract = self.assert_api("load_contract")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            raw = valid_contract(root, inventory)
            raw["治理基线"] = governance_baseline()
            write_contract(config, raw)
            loaded = self.assert_contract_loads(load_contract, config, root)
            self.assertEqual(MAIN_BASELINE, loaded["治理基线"]["main基线提交"])

        formal = self.assert_contract_loads(load_contract, CONFIG_PATH, REPO_ROOT)
        self.assertEqual(governance_baseline(), formal["治理基线"])

        with tempfile.TemporaryDirectory() as directory:
            wrong_path = Path(directory) / "wrong-baseline.json"
            wrong = deepcopy(formal)
            wrong["治理基线"]["任务-000029基线SHA-256"] = "0" * 64
            write_contract(wrong_path, wrong)
            with self.assertRaisesRegex(ValueError, "基线任务内容"):
                load_contract(wrong_path, REPO_ROOT)

    def test_已观察探针指纹必须与资产类型一致(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        validate_probe = self.assert_api("validate_probe_result")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            assets = build_assets(inventory, contract)

            missing_database_schema = observed_probe()
            missing_database_schema["结果"][1]["SchemaSHA-256"] = ""
            with self.assertRaisesRegex(ValueError, "数据库.*Schema"):
                validate_probe(missing_database_schema, assets)

            forged_file_schema = observed_probe()
            forged_file_schema["结果"][0]["SchemaSHA-256"] = "4" * 64
            with self.assertRaisesRegex(ValueError, "文件.*Schema"):
                validate_probe(forged_file_schema, assets)

    def test_远端未知字段错误不回显攻击者字段名(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        validate_probe = self.assert_api("validate_probe_result")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            assets = build_assets(inventory, contract)
            payload = observed_probe()
            leaked_name = "/secret/BTCUSDT/10.1.2.3/root-user"
            payload["结果"][0][leaked_name] = "攻击者值"
            with self.assertRaises(ValueError) as caught:
                validate_probe(payload, assets)

        self.assertNotIn(leaked_name, str(caught.exception))
        self.assertEqual("远端探针结果结构不符合固定合同", str(caught.exception))

    def test_探针必须完整覆盖冻结资产且只用获批元数据(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        build_probe_script = self.assert_api("build_probe_script")
        validate_probe = self.assert_api("validate_probe_result")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            assets = build_assets(inventory, contract)
            script = build_probe_script(assets, contract)

            incomplete = observed_probe()
            incomplete["结果"].pop()
            with self.assertRaisesRegex(ValueError, "完整覆盖"):
                validate_probe(incomplete, assets)

        self.assertIn("information_schema.TABLES", script)
        self.assertIn("information_schema.COLUMNS", script)
        self.assertIn(
            "(t.TABLE_SCHEMA='market_data' AND t.TABLE_NAME='ticks')",
            script,
        )
        self.assertNotIn("TABLE_SCHEMA NOT IN", script)
        self.assertIn("os.lstat", script)
        self.assertNotIn("SELECT *", script.upper())
        for forbidden in ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER "):
            self.assertNotIn(forbidden, script.upper())

    def test_文件探针拒绝伪装成同尺寸同mtime的目录(self):
        build_probe_script = self.assert_api("build_probe_script")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disguised = root / "looks-like-file.csv"
            disguised.mkdir()
            metadata = disguised.stat()
            unused = root / "unused.csv"
            unused.write_text("smoke-only\n", encoding="utf-8")
            contract = valid_contract(root, unused)
            contract["允许文件根目录"] = [str(root.resolve())]
            contract["资源上限"]["逐成员超时秒"] = 2
            assets = [
                {
                    "资产编号": "DS-000001",
                    "资产类型": "候选数据文件",
                    "位置": str(disguised.resolve()),
                    "格式": "CSV",
                    "字节数": str(metadata.st_size),
                    "最后修改时间": dt.datetime.fromtimestamp(
                        metadata.st_mtime
                    ).astimezone().isoformat(),
                    "数据库Schema": "",
                    "数据库表": "",
                }
            ]
            script = build_probe_script(assets, contract)
            completed = subprocess.run(
                [sys.executable, "-B", "-c", script],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout)["结果"][0]

        self.assertEqual("拒绝", result["复核状态"])
        self.assertIn("普通文件", result["证据"])
        self.assertIn("stat.S_ISREG", script)
        self.assertIn('"文件类型"', script)
        self.assertIn('"模式"', script)

    def test_有界流式读取超限或超时立即终止且不泄漏正文(self):
        run_bounded = self.assert_api("run_bounded_process")
        processes = []

        def popen_factory(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            processes.append(process)
            return process

        with self.assertRaisesRegex(RuntimeError, "输出超过冻结上限") as oversized:
            run_bounded(
                [sys.executable, "-B", "-c", "import sys;sys.stdout.write('secret-path-'*1000)"],
                input_text="",
                timeout=5,
                maximum_stdout=128,
                maximum_stderr=128,
                popen_factory=popen_factory,
            )
        self.assertNotIn("secret-path", str(oversized.exception))
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

        with self.assertRaisesRegex(RuntimeError, "批次超时"):
            run_bounded(
                [sys.executable, "-B", "-c", "import time;time.sleep(5)"],
                input_text="",
                timeout=0.1,
                maximum_stdout=128,
                maximum_stderr=128,
            )

    def test_有界子进程遇到BaseException仍终止并回收(self):
        run_bounded = self.assert_api("run_bounded_process")
        real_selector = self.module.selectors.DefaultSelector
        processes = []

        class InterruptingSelector:
            def __init__(self):
                self.delegate = real_selector()

            def register(self, *args, **kwargs):
                return self.delegate.register(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                return self.delegate.unregister(*args, **kwargs)

            def get_map(self):
                return self.delegate.get_map()

            def select(self, _timeout):
                raise KeyboardInterrupt("定向测试中断")

            def close(self):
                self.delegate.close()

        def popen_factory(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            processes.append(process)
            return process

        observed_poll = None
        try:
            with mock.patch.object(
                self.module.selectors,
                "DefaultSelector",
                InterruptingSelector,
            ), self.assertRaises(KeyboardInterrupt):
                run_bounded(
                    [sys.executable, "-B", "-c", "import time;time.sleep(30)"],
                    input_text="",
                    timeout=10,
                    maximum_stdout=128,
                    maximum_stderr=128,
                    popen_factory=popen_factory,
                )
            observed_poll = processes[0].poll()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()

        self.assertIsNotNone(observed_poll)

    def test_有界子进程在selector构造失败时仍终止回收并关闭管道(self):
        run_bounded = self.assert_api("run_bounded_process")
        processes = []

        def interrupting_selector():
            raise KeyboardInterrupt("定向测试构造中断")

        def popen_factory(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            processes.append(process)
            return process

        observed_poll = None
        observed_stdout_closed = False
        observed_stderr_closed = False
        try:
            with mock.patch.object(
                self.module.selectors,
                "DefaultSelector",
                interrupting_selector,
            ), self.assertRaises(KeyboardInterrupt):
                run_bounded(
                    [sys.executable, "-B", "-c", "import time;time.sleep(30)"],
                    input_text="",
                    timeout=10,
                    maximum_stdout=128,
                    maximum_stderr=128,
                    popen_factory=popen_factory,
                )
            process = processes[0]
            observed_poll = process.poll()
            observed_stdout_closed = process.stdout.closed
            observed_stderr_closed = process.stderr.closed
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()
                if process.stderr is not None and not process.stderr.closed:
                    process.stderr.close()

        self.assertIsNotNone(observed_poll)
        self.assertTrue(observed_stdout_closed)
        self.assertTrue(observed_stderr_closed)

    def test_远端有界子进程finally无条件终止并回收(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        build_probe_script = self.assert_api("build_probe_script")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            script = build_probe_script(build_assets(inventory, contract), contract)

        finally_block = script.split("finally:", 1)[1].split("def mysql_lines", 1)[0]
        self.assertIn("process.poll()", finally_block)
        self.assertIn("process.kill()", finally_block)
        self.assertIn("process.wait()", finally_block)

    def test_远端有界子进程在selector构造失败时仍终止回收并关闭管道(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        build_probe_script = self.assert_api("build_probe_script")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            script = build_probe_script(build_assets(inventory, contract), contract)

        real_popen = subprocess.Popen
        processes = []

        def interrupting_selector():
            raise KeyboardInterrupt("定向测试远端构造中断")

        def popen_factory(_arguments, **kwargs):
            process = real_popen(
                [sys.executable, "-B", "-c", "import time;time.sleep(30)"],
                stdin=kwargs.get("stdin"),
                stdout=kwargs.get("stdout"),
                stderr=kwargs.get("stderr"),
                env=kwargs.get("env"),
            )
            processes.append(process)
            return process

        previous_alarm_handler = signal.getsignal(signal.SIGALRM)
        observed_poll = None
        observed_stdout_closed = False
        observed_stderr_closed = False
        try:
            with mock.patch.object(
                self.module.selectors,
                "DefaultSelector",
                interrupting_selector,
            ), mock.patch.object(
                subprocess,
                "Popen",
                popen_factory,
            ), self.assertRaises(KeyboardInterrupt):
                exec(compile(script, "<远端只读探针>", "exec"), {"__name__": "__main__"})
            process = processes[0]
            observed_poll = process.poll()
            observed_stdout_closed = process.stdout.closed
            observed_stderr_closed = process.stderr.closed
        finally:
            signal.signal(signal.SIGALRM, previous_alarm_handler)
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()
                if process.stderr is not None and not process.stderr.closed:
                    process.stderr.close()

        self.assertIsNotNone(observed_poll)
        self.assertTrue(observed_stdout_closed)
        self.assertTrue(observed_stderr_closed)

    def test_远端mysql同样使用有界流式读取(self):
        load_contract = self.assert_api("load_contract")
        build_assets = self.assert_api("build_probe_assets")
        build_probe_script = self.assert_api("build_probe_script")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = load_contract(config, root)
            script = build_probe_script(build_assets(inventory, contract), contract)

        self.assertIn("selectors.DefaultSelector", script)
        self.assertIn("subprocess.Popen", script)
        self.assertIn("process.kill()", script)
        self.assertNotIn("capture_output=True", script)
        self.assertNotIn("subprocess.run(", script)
        self.assertIn('"PYTHONDONTWRITEBYTECODE": "1"', script)

    def test_DB_Schema单次查询且关键字段变化改变指纹(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = run_fake_mysql_probe(self.module, root, [schema_row()])
            variants = [
                run_fake_mysql_probe(
                    self.module,
                    root,
                    [schema_row(default=encoded_text("0"))],
                ),
                run_fake_mysql_probe(
                    self.module,
                    root,
                    [schema_row(column_collation=encoded_text("utf8mb4_bin"))],
                ),
                run_fake_mysql_probe(
                    self.module,
                    root,
                    [schema_row(column_key=encoded_text("UNI"))],
                ),
                run_fake_mysql_probe(
                    self.module,
                    root,
                    [schema_row(generation=encoded_text("id + 1"))],
                ),
            ]
            probe_inventory = root / "probe.csv"
            probe_inventory.write_text("smoke\n", encoding="utf-8")
            probe_contract = valid_contract(root, probe_inventory)

        self.assertEqual("已观察", baseline["复核状态"])
        hashes = {baseline["SchemaSHA-256"]}
        for result in variants:
            self.assertEqual("已观察", result["复核状态"])
            hashes.add(result["SchemaSHA-256"])
        self.assertEqual(5, len(hashes))

        script = self.module.build_probe_script(
            [
                {
                    "资产编号": "DS-000001",
                    "资产类型": "数据库元数据",
                    "位置": "MySQL/market_data/ticks",
                    "格式": "InnoDB",
                    "字节数": "未知",
                    "最后修改时间": "未知",
                    "数据库Schema": "market_data",
                    "数据库表": "ticks",
                }
            ],
            probe_contract,
        )
        self.assertEqual(2, script.count("mysql_lines("))
        self.assertIn("JOIN information_schema.COLUMNS", script)
        for field in (
            "TABLE_COLLATION",
            "ROW_FORMAT",
            "CREATE_OPTIONS",
            "COLUMN_DEFAULT",
            "CHARACTER_SET_NAME",
            "COLLATION_NAME",
            "COLUMN_KEY",
            "NUMERIC_PRECISION",
            "NUMERIC_SCALE",
            "DATETIME_PRECISION",
            "GENERATION_EXPRESSION",
            "COLUMN_COMMENT",
        ):
            self.assertIn(field, script)

    def test_DB_Schema畸形空列重复和达到LIMIT均无法判定(self):
        malformed = schema_row()
        malformed[7] = "HZZ"
        duplicate = [schema_row(), schema_row()]
        second = schema_row()
        second[6] = encoded_number(2)
        second[7] = encoded_text("value")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "畸形HEX": run_fake_mysql_probe(self.module, root, [malformed]),
                "空列集": run_fake_mysql_probe(self.module, root, []),
                "重复列序": run_fake_mysql_probe(self.module, root, duplicate),
                "达到LIMIT": run_fake_mysql_probe(
                    self.module, root, [schema_row(), second], row_limit=1
                ),
            }

        for name, result in cases.items():
            with self.subTest(name=name):
                self.assertEqual("无法判定", result["复核状态"])
                self.assertEqual("", result["SchemaSHA-256"])

    def test_SSH远端命令使用固定清洁隔离环境(self):
        build_command = self.assert_api("build_ssh_command")
        expected_suffix = [
            "ubuntu",
            "env",
            "-i",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/nonexistent",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            "-I",
            "-B",
            "-",
        ]
        with mock.patch.dict(
            os.environ,
            {"PYTHONPATH": "/tmp/attacker", "PYTHONSTARTUP": "/tmp/attacker.py"},
        ):
            command = build_command("ssh", "ubuntu", 60)

        self.assertEqual(expected_suffix, command[-len(expected_suffix) :])
        self.assertNotIn("PYTHONPATH", "\n".join(command))
        self.assertNotIn("PYTHONSTARTUP", "\n".join(command))
        self.assertNotIn("shell", command)

    def test_批次内容寻址确定排序且历史不可覆盖(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            batch_root = root / "batches"
            frozen = dt.datetime(2026, 8, 3, 1, 2, 3, tzinfo=dt.timezone(dt.timedelta(hours=8)))
            frozen_contract = json.loads(config.read_text(encoding="utf-8"))
            expected_inputs = {
                item["路径"]: item["SHA-256"]
                for item in frozen_contract["输入文件"]
            }
            expected_rule_hash = sha256(config)
            expected_executor_hash = sha256(MODULE_PATH)
            expected_task_hash = sha256(
                root / "docs" / "研发中心" / "任务" / "任务-000029.md"
            )

            def runner(command, **kwargs):
                self.assertIsInstance(command, list)
                self.assertNotIn("shell", kwargs)
                self.assertEqual("ubuntu", command[-12])
                self.assertEqual("env", command[-11])
                self.assertEqual("-i", command[-10])
                self.assertEqual("python3", command[-4])
                self.assertEqual("-I", command[-3])
                self.assertEqual("-B", command[-2])
                self.assertEqual("-", command[-1])
                self.assertIn("DS-000001", kwargs["input"])
                self.assertEqual(600, kwargs["timeout"])
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(observed_probe(), ensure_ascii=False),
                    stderr="",
                )

            batch = execute_batch(
                config,
                "ubuntu",
                batch_root,
                600,
                repo_root=root,
                runner=runner,
                now=frozen,
            )
            csv_path = batch / "来源身份清单.csv"
            json_path = batch / "身份清单.json"
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            with csv_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(4, len(rows))
            self.assertIn("批次载荷", payload)
            self.assertIn("批次载荷SHA-256", payload)
            self.assertEqual(
                sorted(
                    rows,
                    key=lambda row: (
                        row["来源提供者"],
                        row["交易场所"],
                        row["市场类型"],
                        row["标的"],
                        row["精确合约"],
                        row["数据对象"],
                        row["Schema确切版本"],
                        row["资产编号"],
                    ),
                ),
                rows,
            )
            self.assertEqual(sha256(csv_path), payload["输出SHA-256"]["来源身份清单.csv"])
            for field in ("输入SHA-256", "规则SHA-256", "成员SHA-256", "清单内容SHA-256"):
                self.assertIn(field, payload)
            self.assertEqual(
                self.module.object_fingerprint(payload["批次载荷"]),
                payload["批次载荷SHA-256"],
            )
            self.assertIn("治理基线", payload["批次载荷"])
            self.assertIn("当前执行任务文件SHA-256", payload)
            self.assertEqual(expected_inputs, payload["输入SHA-256"])
            self.assertEqual(expected_rule_hash, payload["规则SHA-256"])
            self.assertEqual(expected_executor_hash, payload["执行器SHA-256"])
            self.assertEqual(
                expected_task_hash,
                payload["当前执行任务文件SHA-256"],
            )
            self.assertIn("非递归", payload["批次载荷定义"])
            self.assertTrue(batch.name.endswith(payload["批次载荷SHA-256"][:12]))

            before = {path.name: sha256(path) for path in batch.iterdir()}
            with self.assertRaisesRegex(FileExistsError, "已存在"):
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    600,
                    repo_root=root,
                    runner=runner,
                    now=frozen,
                )
            self.assertEqual(before, {path.name: sha256(path) for path in batch.iterdir()})

    def test_暂存目录位于批次根目录内以保证同文件系统原子发布(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _inventory, config = self.make_inputs(root)
            batch_root = root / "batches"

            def runner(command, **_kwargs):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(observed_probe(), ensure_ascii=False),
                    stderr="",
                )

            real_atomic = self.module.atomic_publish_directory_no_replace

            def checked_atomic(source, target):
                source_path = Path(source)
                self.assertEqual(batch_root, source_path.parent.parent)
                return real_atomic(source, target)

            with mock.patch.object(
                self.module,
                "atomic_publish_directory_no_replace",
                side_effect=checked_atomic,
            ):
                batch = execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=runner,
                    now=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
                )
            self.assertTrue(batch.is_dir())

    def test_原子no_clobber拒绝竞争窗口中新建空目标目录(self):
        atomic_publish = self.assert_api("atomic_publish_directory_no_replace")
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            target = root / "target"
            source.mkdir()
            (source / "payload").write_text("new", encoding="utf-8")
            target.mkdir()
            target_inode = target.stat().st_ino

            with self.assertRaises(FileExistsError):
                atomic_publish(source, target)
            self.assertEqual(target_inode, target.stat().st_ino)
            self.assertTrue(source.is_dir())

            _inventory, config = self.make_inputs(root)
            batch_root = root / "batches"
            raced_inode = None
            original_atomic = atomic_publish

            def racing_atomic(staging, destination):
                nonlocal raced_inode
                destination.mkdir()
                raced_inode = destination.stat().st_ino
                return original_atomic(staging, destination)

            def runner(command, **_kwargs):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(observed_probe(), ensure_ascii=False),
                    stderr="",
                )

            with mock.patch.object(
                self.module,
                "atomic_publish_directory_no_replace",
                side_effect=racing_atomic,
            ), self.assertRaises(FileExistsError):
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=runner,
                    now=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
                )

            raced_target = next(batch_root.glob("source-identity-*"))
            self.assertEqual(raced_inode, raced_target.stat().st_ino)
            self.assertEqual([], list(raced_target.iterdir()))

    def test_执行前后指纹夹持拒绝配置执行器任务和清单漂移(self):
        execute_batch = self.assert_api("execute_batch")
        executor_original = MODULE_PATH.read_bytes()

        def mutate_file(path: Path):
            path.write_bytes(path.read_bytes() + b"\n")

        for target_name in ("配置", "执行器", "当前任务", "资产清单"):
            with self.subTest(漂移对象=target_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inventory, config = self.make_inputs(root)
                batch_root = root / "batches"
                current_task = root / "docs" / "研发中心" / "任务" / "任务-000029.md"
                targets = {
                    "配置": config,
                    "执行器": MODULE_PATH,
                    "当前任务": current_task,
                    "资产清单": inventory,
                }

                def runner(command, **_kwargs):
                    mutate_file(targets[target_name])
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=json.dumps(observed_probe(), ensure_ascii=False),
                        stderr="",
                    )

                try:
                    with self.assertRaisesRegex(ValueError, "执行快照指纹漂移"):
                        execute_batch(
                            config,
                            "ubuntu",
                            batch_root,
                            60,
                            repo_root=root,
                            runner=runner,
                            now=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
                        )
                finally:
                    if target_name == "执行器":
                        MODULE_PATH.write_bytes(executor_original)
                self.assertEqual([], list(batch_root.glob("source-identity-*")))

    def test_加载和成员构建被启动SSH前指纹复核夹持(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            batch_root = root / "batches"
            original_builder = self.module.build_probe_script
            runner_called = False

            def drifting_builder(assets, contract):
                script = original_builder(assets, contract)
                inventory.write_bytes(inventory.read_bytes() + b"\n")
                return script

            def runner(command, **_kwargs):
                nonlocal runner_called
                runner_called = True
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(observed_probe(), ensure_ascii=False),
                    stderr="",
                )

            with mock.patch.object(
                self.module, "build_probe_script", side_effect=drifting_builder
            ), self.assertRaisesRegex(ValueError, "执行快照指纹漂移"):
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=runner,
                )

            self.assertFalse(runner_called)
            self.assertEqual([], list(batch_root.glob("source-identity-*")))

    def test_批次只消费快照字节且不受合同A_B_A瞬时替换影响(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _inventory, config = self.make_inputs(root)
            batch_root = root / "batches"
            contract_a = config.read_bytes()
            contract_b = json.loads(contract_a.decode("utf-8"))
            contract_b["资源上限"]["批次总超时秒"] = 10
            contract_b_bytes = (
                json.dumps(contract_b, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            original_load = self.module.load_contract
            reread_called = False

            def aba_load(path, repo_root):
                nonlocal reread_called
                reread_called = True
                path.write_bytes(contract_b_bytes)
                try:
                    return original_load(path, repo_root)
                finally:
                    path.write_bytes(contract_a)

            def runner(command, **_kwargs):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps(observed_probe(), ensure_ascii=False),
                    stderr="",
                )

            with mock.patch.object(self.module, "load_contract", side_effect=aba_load):
                try:
                    batch = execute_batch(
                        config,
                        "ubuntu",
                        batch_root,
                        60,
                        repo_root=root,
                        runner=runner,
                        now=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
                    )
                except ValueError as error:
                    self.fail(f"批次不得读取瞬时B合同：{error}")

            self.assertFalse(reread_called)
            self.assertTrue(batch.is_dir())
            self.assertEqual(contract_a, config.read_bytes())

    def test_失败日志脱敏且超时不发布半批次(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _inventory, config = self.make_inputs(root)
            batch_root = root / "batches"

            def failed_runner(command, **kwargs):
                return subprocess.CompletedProcess(
                    command,
                    1,
                    stdout="",
                    stderr="10.1.2.3 " + "password" + "=must-not-leak root@server",
                )

            with self.assertRaisesRegex(RuntimeError, "只读元数据复核失败") as caught:
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=failed_runner,
                )
            self.assertNotIn("must-not-leak", str(caught.exception))
            self.assertNotIn("10.1.2.3", str(caught.exception))
            self.assertEqual([], list(batch_root.glob("source-identity-*")))

            def timeout_runner(command, **kwargs):
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])

            with self.assertRaisesRegex(RuntimeError, "批次超时"):
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=timeout_runner,
                )
            self.assertEqual([], list(batch_root.glob("source-identity-*")))

    def test_非法JSON与SSH系统错误使用固定脱敏错误(self):
        execute_batch = self.assert_api("execute_batch")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _inventory, config = self.make_inputs(root)
            batch_root = root / "batches"
            leaked = "10.1.2.3 " + "password" + "=must-not-leak root@server"

            def invalid_json_runner(command, **_kwargs):
                return subprocess.CompletedProcess(command, 0, stdout=leaked, stderr="")

            with self.assertRaisesRegex(RuntimeError, "远端响应不是合法JSON") as invalid:
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=invalid_json_runner,
                )
            self.assertNotIn(leaked, str(invalid.exception))

            def os_error_runner(_command, **_kwargs):
                raise OSError(leaked)

            with self.assertRaisesRegex(RuntimeError, "SSH客户端不可用") as unavailable:
                execute_batch(
                    config,
                    "ubuntu",
                    batch_root,
                    60,
                    repo_root=root,
                    runner=os_error_runner,
                )
            self.assertNotIn(leaked, str(unavailable.exception))
            self.assertEqual([], list(batch_root.glob("source-identity-*")))

    def test_CLI对不可信合同错误只输出固定公开错误码(self):
        expected = "冻结来源身份失败：[ZI-SI-1001] 输入或冻结合同无效\n"
        leaked = "10.1.2.3/root/private/username/" + "password" + "=must-not-leak"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, config = self.make_inputs(root)
            contract = valid_contract(root, inventory)
            contract[leaked] = True
            write_contract(config, contract)
            returncode, stdout, stderr = self.invoke_main(config, root / "batches")
            self.assertEqual((1, "", expected), (returncode, stdout, stderr))
            self.assertNotIn(leaked, stderr)

            config.write_text(leaked, encoding="utf-8")
            returncode, stdout, stderr = self.invoke_main(config, root / "batches")
            self.assertEqual((1, "", expected), (returncode, stdout, stderr))
            self.assertNotIn(leaked, stderr)

    def test_CLI对文件系统与未知运行时错误只输出固定类别(self):
        leaked = "10.1.2.3/root/private/username/" + "password" + "=must-not-leak"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _inventory, config = self.make_inputs(root)
            for error, expected in (
                (
                    PermissionError(leaked),
                    "冻结来源身份失败：[ZI-SI-1002] 本地文件系统操作失败\n",
                ),
                (
                    OSError(leaked),
                    "冻结来源身份失败：[ZI-SI-1002] 本地文件系统操作失败\n",
                ),
                (
                    RuntimeError(leaked),
                    "冻结来源身份失败：[ZI-SI-2999] 只读元数据复核失败\n",
                ),
            ):
                with self.subTest(error=type(error).__name__), mock.patch.object(
                    self.module, "execute_batch", side_effect=error
                ):
                    returncode, stdout, stderr = self.invoke_main(
                        config, root / leaked / "batches"
                    )
                    self.assertEqual((1, "", expected), (returncode, stdout, stderr))
                    self.assertNotIn(leaked, stderr)

    def test_CLI非法整数不回显敏感值或usage(self):
        leaked = "10.1.2.3/root/private/" + "password" + "=must-not-leak"
        result = self.invoke_main_args(
            ["--ssh-target", "ubuntu", "--timeout", leaked]
        )
        self.assertEqual(
            (1, "", "冻结来源身份失败：[ZI-SI-1000] 命令行参数无效\n"),
            result,
        )

    def test_CLI未知参数不回显原始参数或usage(self):
        leaked = "--private-10.1.2.3/root/" + "password" + "=must-not-leak"
        result = self.invoke_main_args(
            ["--ssh-target", "ubuntu", "--timeout", "60", leaked]
        )
        self.assertEqual(
            (1, "", "冻结来源身份失败：[ZI-SI-1000] 命令行参数无效\n"),
            result,
        )

    def test_CLI缺少必填参数不输出usage或参数名(self):
        result = self.invoke_main_args([])
        self.assertEqual(
            (1, "", "冻结来源身份失败：[ZI-SI-1000] 命令行参数无效\n"),
            result,
        )

    def test_仓库冻结配置与合同文档可复核(self):
        load_contract = self.assert_api("load_contract")
        contract = load_contract(CONFIG_PATH, REPO_ROOT)
        self.assertEqual(["BTC", "ETH"], contract["标的"])
        self.assertEqual(["已证明", "拒绝", "无法判定"], contract["允许状态"])
        text = CONTRACT_PATH.read_text(encoding="utf-8")
        for phrase in (
            "不得从路径、文件名、字段或常识猜测身份",
            "候选资产总体",
            "三态计数守恒",
            "历史批次不可覆盖",
            "数据库业务记录",
            "交易许可",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
