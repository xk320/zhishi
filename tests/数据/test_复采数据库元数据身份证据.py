from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/数据/复采数据库元数据身份证据.py"


def load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("database_metadata_identity", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("无法加载任务-000077入口")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DatabaseMetadataIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.config = cls.module.load_config()

    def test_配置和输入成员精确覆盖(self):
        members = self.module.load_members(self.config)
        self.assertEqual(184, len(members))
        self.assertEqual(92, len({row["资产编号"] for row in members}))
        self.assertEqual({"BTC", "ETH"}, {row["标的"] for row in members})
        self.assertEqual(members, sorted(members, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"])))

    def test_探针只接收数据库资产并包含固定元数据范围(self):
        assets = self.module.load_database_assets(self.config)
        script = self.module.build_probe_script(assets, self.config)
        self.assertIn("information_schema.TABLES", script)
        self.assertIn("information_schema.COLUMNS", script)
        self.assertNotIn("SELECT * FROM", script)
        self.assertNotIn("information_schema.TABLE_PRIVILEGES", script)

    def test_结构观察不会升级为身份已证明(self):
        members = [{
            "来源身份批次": "source-identity-field-evidence-test",
            "成员编号": "ZI-test-member-0001",
            "资产编号": "DS-000225",
            "资产类型": "数据库元数据",
            "标的": "BTC",
            "输入成员SHA-256": "a" * 64,
        }, {
            "来源身份批次": "source-identity-field-evidence-test",
            "成员编号": "ZI-test-member-0002",
            "资产编号": "DS-000225",
            "资产类型": "数据库元数据",
            "标的": "ETH",
            "输入成员SHA-256": "b" * 64,
        }]
        assets = [{
            "资产编号": "DS-000225",
            "资产类型": "数据库元数据",
            "位置": "MySQL/celueqing/orders",
            "格式": "InnoDB",
            "字节数": "未知",
            "最后修改时间": "未知",
            "数据库Schema": "celueqing",
            "数据库表": "orders",
        }]
        payload = {
            "探针版本": self.module.PROBE_VERSION,
            "远端写入": False,
            "数据库业务记录读取": False,
            "结果": [{
                "资产编号": "DS-000225",
                "复核状态": "已观察",
                "元数据SHA-256": "b" * 64,
                "SchemaSHA-256": "c" * 64,
                "证据": "固定information_schema元数据与冻结引擎声明一致",
                "限制": "未读取数据库业务记录",
            }],
        }
        rows, summary = self.module.build_rows(members, assets, payload, "batch-test", self.config)
        self.assertEqual("已观察", rows[0]["元数据状态"])
        self.assertEqual("无法判定", rows[0]["状态"])
        self.assertEqual(2, summary["已观察"])
        self.assertEqual(0, summary["拒绝"])

    def test_越权探针结果失败关闭(self):
        members = [{
            "来源身份批次": "source-identity-field-evidence-test",
            "成员编号": "ZI-test-member-0001",
            "资产编号": "DS-000225",
            "资产类型": "数据库元数据",
            "标的": "BTC",
            "输入成员SHA-256": "a" * 64,
        }]
        assets = [{
            "资产编号": "DS-000225", "资产类型": "数据库元数据", "数据库Schema": "celueqing", "数据库表": "orders",
        }]
        payload = {"探针版本": self.module.PROBE_VERSION, "远端写入": True, "数据库业务记录读取": False, "结果": []}
        with self.assertRaises(ValueError):
            self.module.build_rows(members, assets, payload, "batch-test", self.config)


if __name__ == "__main__":
    unittest.main()
