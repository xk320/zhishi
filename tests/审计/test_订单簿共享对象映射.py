from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/审计/验证订单簿共享对象映射.py"
ENTRY_PATH = ROOT / "scripts/审计/远程共享表元数据固定入口.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载{name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OrderBookMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load(VALIDATOR_PATH, "orderbook_mapping_validator")
        cls.entry = load(ENTRY_PATH, "orderbook_schema_entry")

    def test_固定16个对象和未登记候选不漂移(self):
        validator = self.validator
        self.assertEqual(len(validator.TARGETS), 16)
        self.assertEqual(validator.target_manifest_fingerprint(), validator.TARGET_MANIFEST_FINGERPRINT)
        self.assertEqual(set(validator.SCHEMA_EXPECTATIONS), {item["表"] for item in validator.TARGETS})
        self.assertIn("order_book_derived_state_revisions", validator.SOURCE_ONLY_CANDIDATES)

    def test_源代码结构指纹可复算(self):
        parsed = self.validator.source_contract(self.validator.SOURCE_DEFAULT)
        expected = self.validator.SCHEMA_EXPECTATIONS
        self.assertEqual({key: parsed["表"][key]["摘要"] for key in expected}, expected)
        self.assertEqual(parsed["未登记候选"], self.validator.SOURCE_ONLY_CANDIDATES)

    def test_状态守恒且顺序固定(self):
        validator = self.validator
        rows = [
            {"资产编号": item["资产编号"], "表": item["表"], "表身份指纹": validator.object_identity_fingerprint(item["数据库"], item["表"]), "采集状态": "已采集", **validator.SCHEMA_EXPECTATIONS[item["表"]]}
            for item in validator.TARGETS
        ]
        self.assertEqual(validator.validate_states(rows), {"匹配": 16, "漂移": 0, "未发现": 0, "无法判定": 0, "失败": 0})
        rows[1]["列数"] += 1
        self.assertEqual(validator.validate_states(rows)["漂移"], 1)
        rows.reverse()
        with self.assertRaises(validator.ContractError):
            validator.validate_states(rows)

    def test_远端文档拒绝业务正文和写入标记(self):
        validator = self.validator
        rows = [
            {"资产编号": item["资产编号"], "表": item["表"], "表身份指纹": validator.object_identity_fingerprint(item["数据库"], item["表"]), "采集状态": "已采集", **validator.SCHEMA_EXPECTATIONS[item["表"]]}
            for item in validator.TARGETS
        ]
        document = {
            "protocol": validator.PROTOCOL,
            "operation": "schema-audit",
            "status": "通过",
            "wrapper_version": validator.REMOTE_WRAPPER_VERSION,
            "wrapper_sha256": validator.sha256_bytes(ENTRY_PATH.read_bytes()),
            "合同版本": validator.CONTRACT_VERSION,
            "覆盖矩阵指纹": validator.MATRIX_FINGERPRINT,
            "对象清单指纹": validator.TARGET_MANIFEST_FINGERPRINT,
            "资源合同": validator.RESOURCE_CONTRACT,
            "规则脚本指纹": validator.sha256_bytes(VALIDATOR_PATH.read_bytes()),
            "授权会话指纹": validator.EXPECTED_SESSION_FINGERPRINT,
            "授权权限快照指纹": validator.EXPECTED_GRANTS_FINGERPRINT,
            "远端临时写入": False,
            "对象结果": rows,
        }
        self.assertEqual(validator.validate_remote_document(document)["匹配"], 16)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["远端临时写入"] = True
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["wrapper_sha256"] = "0" * 64
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["规则脚本指纹"] = "0" * 64
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["授权权限快照指纹"] = "0" * 64
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["对象结果"][0]["表身份指纹"] = bad["对象结果"][1]["表身份指纹"]
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)
        bad = json.loads(json.dumps(document, ensure_ascii=False))
        bad["对象结果"][0]["原因码"] = "SELECT payload_json"
        with self.assertRaises(validator.ContractError):
            validator.validate_remote_document(bad)

    def test_固定入口协议绑定且只允许元数据查询(self):
        entry = self.entry
        valid = {
            "protocol": entry.PROTOCOL,
            "operation": "schema-audit",
            "payload": {
                "合同版本": entry.CONTRACT_VERSION,
                "覆盖矩阵指纹": entry.MATRIX_FINGERPRINT,
                "对象清单指纹": entry.TARGETS_FINGERPRINT,
                "资源合同指纹": entry.RESOURCE_CONTRACT_FINGERPRINT,
                "数据截止": entry.FROZEN_DATA_CUTOFF,
                "规则脚本指纹": "a" * 64,
            },
        }
        self.assertEqual(entry._parse_request(json.dumps(valid, ensure_ascii=False)), valid)
        invalid = json.loads(json.dumps(valid, ensure_ascii=False))
        invalid["payload"]["对象清单指纹"] = "0" * 64
        with self.assertRaises(entry.ProtocolError):
            entry._parse_request(json.dumps(invalid, ensure_ascii=False))
        with self.assertRaises(RuntimeError):
            entry._mysql("SELECT * FROM orderbook.order_book_signals", 9999999999)
        self.assertNotIn("payload_json", entry._one.__code__.co_names)
        source = ENTRY_PATH.read_text(encoding="utf-8")
        self.assertIn("information_schema.COLUMNS", source)
        self.assertIn("information_schema.STATISTICS", source)
        self.assertIn("SSH_ORIGINAL_COMMAND", source)
        self.assertIn("NON_UNIQUE", source)
        self.assertNotIn("/Users/", source)

    def test_源合同保留列内键与索引唯一性(self):
        parsed = self.validator.source_contract(self.validator.SOURCE_DEFAULT)
        first = parsed["表"]["historical_backfill_files"]
        self.assertEqual(first["列"][0]["键"], "pri")
        self.assertTrue(all("非唯一" in index and "索引类型" in index for index in first["索引"]))

    def test_批次目录可复验(self):
        path = ROOT / "artifacts/审计/订单簿共享对象映射/批次-20260806T143417Z-v2"
        if path.exists():
            self.assertEqual(self.validator.validate_artifact_directory(path)["匹配"], 5)


if __name__ == "__main__":
    unittest.main()
