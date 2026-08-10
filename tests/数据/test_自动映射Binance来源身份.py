from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/数据/自动映射Binance来源身份.py"
SPEC = importlib.util.spec_from_file_location("auto_mapping", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class AutoMappingTests(unittest.TestCase):
    def test_config_matches_fixed_contract(self):
        config = json.loads(MODULE.CONFIG_PATH.read_text(encoding="utf-8"))
        MODULE.validate_config(config)
        self.assertEqual(config["本地只读根目录"], "/Volumes/data/data/binance/futures/um")
        self.assertEqual(config["输出绑定"]["绑定字段"][-2:], ["证据定位", "字段中文映射指纹"])

    def test_member_status_never_infers_from_binance_api(self):
        member = {"成员编号": "m1", "资产编号": "DS-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}
        row = MODULE.member_status(member, manifest_stats={"固定根目录内路径数": 1}, api_summaries=[{"状态": "成功", "市场类型": "USDⓈ-M合约"}])
        self.assertEqual(row["状态"], "无法判定")
        self.assertEqual(row["原因代码"], "PUBLIC_API_METADATA_UNAVAILABLE")
        self.assertEqual(row["匹配符号"], "")

    def test_member_status_requires_exact_symbol_and_field_checks(self):
        member = {"成员编号": "m1", "资产编号": "DS-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}
        candidate = {
            "资产编号": "DS-1", "symbol": "BTCUSDT", "path": "/Volumes/data/data/binance/futures/um/BTCUSDT.csv",
            "来源端点": "https://fapi.binance.com/fapi/v1/exchangeInfo", "市场类型": "USDⓈ-M合约",
            "输入成员SHA-256": "a" * 64, "Schema确切版本指纹": "sha256:schema", "授权边界指纹": "sha256:auth",
            "字段中文映射指纹": "sha256:fields", "证据定位": "manifest#DS-1", "声明内容SHA-256": "b" * 64,
            "来源提供者": "Binance", "交易场所": "Binance", "标的身份": "BTC", "精确合约": "BTCUSDT",
            "数据对象": "1d_klines", "Schema确切版本": "binance-exchangeInfo-1.0", "授权边界": "Binance公开无认证GET", "字段中文映射": "fields-v1",
        }
        uri = "https://fapi.binance.com/fapi/v1/exchangeInfo"
        api = [{"端点": uri, "状态": "成功", "市场类型": "USDⓈ-M合约", "Schema确切版本指纹": "sha256:schema", "_合约索引": [{"symbol": "BTCUSDT", "baseAsset": "BTC"}]}]
        row = MODULE.member_status(member, manifest_stats={}, api_summaries=api, manifest_entries=[candidate], inventory_rows={"DS-1": {"资产编号": "DS-1"}}, field_mapping_sha="sha256:fields", auth_fingerprints={uri: "sha256:auth"})
        self.assertEqual(row["状态"], "已证明")
        self.assertTrue(all(row["匹配检查"].values()))
        evidence, binding = MODULE.build_identity_records(member, candidate, "sha256:fields")
        self.assertEqual(len(evidence), 9)
        self.assertEqual(len(binding), 9)
        self.assertEqual({item["证据记录编号"] for item in evidence}, {item["证据记录编号"] for item in binding})

        candidate["授权边界指纹"] = "sha256:wrong"
        rejected = MODULE.member_status(member, manifest_stats={}, api_summaries=api, manifest_entries=[candidate], inventory_rows={"DS-1": {"资产编号": "DS-1"}}, field_mapping_sha="sha256:fields", auth_fingerprints={uri: "sha256:auth"})
        self.assertEqual(rejected["状态"], "无法判定")

    def test_schema_fingerprint_does_not_store_payload(self):
        payload = {"timezone": "UTC", "symbols": [{"symbol": "BTCUSDT", "baseAsset": "BTC"}]}
        fingerprint = MODULE.schema_fingerprint(payload)
        self.assertTrue(fingerprint.startswith("sha256:"))
        self.assertNotIn("BTCUSDT", fingerprint)

    def test_batch_is_append_only_and_counts_are_conservative(self):
        fake = lambda url, started: {"端点": url, "市场类型": MODULE.API_ENDPOINTS[url], "状态": "失败", "失败原因代码": "TEST_API_UNAVAILABLE", "失败原因指纹": "x"}
        with tempfile.TemporaryDirectory() as tmp:
            batch, manifest = MODULE.build_batch(batch_root=Path(tmp), now=MODULE.datetime(2026, 8, 11, tzinfo=MODULE.timezone.utc), fetcher=fake)
            self.assertTrue(batch.is_dir())
            self.assertEqual(manifest["结果摘要"]["总计"]["候选总体"], 630)
            self.assertEqual(manifest["结果摘要"]["总计"]["无法判定"], 630)
            self.assertEqual(manifest["结果摘要"]["总计"]["计数守恒"], True)
            evidence = json.loads((batch / "source-identity-evidence-1.0.json").read_text(encoding="utf-8"))
            self.assertEqual(evidence, {"证据版本": "source-identity-evidence-1.0", "记录": []})
            with self.assertRaises(FileExistsError):
                MODULE.build_batch(batch_root=Path(tmp), now=MODULE.datetime(2026, 8, 11, tzinfo=MODULE.timezone.utc), fetcher=fake)


if __name__ == "__main__":
    unittest.main()
