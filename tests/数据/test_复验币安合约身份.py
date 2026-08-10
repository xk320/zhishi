import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.数据 import 复验币安合约身份 as module


class TestBinanceContractIdentity(unittest.TestCase):
    def test_config_contract(self):
        config = module.load_config()
        self.assertEqual(config["任务编号"], "任务-000085")
        self.assertEqual(config["允许SSH目标"], ["ubuntu"])
        self.assertEqual(config["标的"], ["BTC", "ETH"])
        self.assertEqual(config["资源上限"]["批次总超时秒"], 900)
        self.assertTrue(config["远端扫描规则"]["不跟随符号链接"])
        self.assertFalse(any(config["安全边界"].values()))

    def test_remote_probe_source_is_fixed_and_safe(self):
        source = module._remote_probe_source(module.load_config(), 10)
        compile(source, "<remote-probe>", "exec")
        self.assertIn("followlinks=False", source)
        self.assertIn("远端追加", source)
        self.assertIn("/proc", source)
        self.assertNotIn("scp ", source)
        self.assertNotIn("DROP TABLE", source)

    def test_api_snapshot_filters_only_btc_eth(self):
        payload = {
            "timezone": "UTC",
            "serverTime": 1700000000000,
            "symbols": [
                {
                    "symbol": "BTCUSDT",
                    "pair": "BTCUSDT",
                    "contractType": "PERPETUAL",
                    "status": "TRADING",
                    "baseAsset": "BTC",
                    "quoteAsset": "USDT",
                    "marginAsset": "USDT",
                    "foo": "x",
                },
                {"symbol": "SOLUSDT", "baseAsset": "SOL"},
            ],
        }
        class Response:
            returncode = 0
            stdout = json.dumps(payload).encode()

        api_spec = {"市场类型": "USDⓈ-M合约", "端点": "https://fapi.binance.com/fapi/v1/exchangeInfo"}
        with patch.object(module.subprocess, "run", return_value=Response()):
            snapshot = module.fetch_exchange_info(api_spec, {"最大API响应字节": 16 * 1024 * 1024}, dt.datetime.now(dt.timezone.utc))
        self.assertEqual(snapshot["状态"], "通过")
        self.assertEqual([row["symbol"] for row in snapshot["合约"]], ["BTCUSDT"])
        self.assertEqual(snapshot["HTTP状态"], 200)
        self.assertRegex(snapshot["响应SHA-256"], r"^[0-9a-f]{64}$")

    def test_evidence_requires_exact_member_and_contract(self):
        members = [{"资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}]
        candidate = {"字段": {
            "资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64, "标的身份": "BTC",
            "来源提供者": "Binance", "交易场所": "Binance", "市场类型": "USDⓈ-M合约",
            "精确合约": "BTCUSDT", "数据对象": "exchangeInfo.symbols[BTCUSDT]",
            "Schema确切版本": "sha256:" + "b" * 64, "授权边界": "Binance公开无认证GET",
            "字段中文映射": module.EXPECTED_FIELD_MAPPING,
        }}
        contracts = {"BTC": [{"symbol": "BTCUSDT", "baseAsset": "BTC", "市场类型": "USDⓈ-M合约", "响应Schema指纹": "b" * 64}], "ETH": []}
        evidence, verified = module.build_evidence(members, [candidate], contracts)
        self.assertEqual(len(evidence["记录"]), 9)
        self.assertEqual(len(verified), 1)
        self.assertEqual({item["证明字段"] for item in evidence["记录"]}, set(module.IDENTITY_FIELDS))

    def test_evidence_rejects_wrong_contract_mapping(self):
        members = [{"资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}]
        candidate = {"字段": {
            "资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64,
            "来源提供者": "Binance", "交易场所": "Binance", "市场类型": "WRONG",
            "标的身份": "BTC", "精确合约": "BTCUSDT", "数据对象": "WRONG",
            "Schema确切版本": "WRONG", "授权边界": "WRONG", "字段中文映射": {},
        }}
        contracts = {"BTC": [{"symbol": "BTCUSDT", "baseAsset": "BTC", "市场类型": "USDⓈ-M合约", "响应Schema指纹": "b" * 64}], "ETH": []}
        evidence, verified = module.build_evidence(members, [candidate], contracts)
        self.assertEqual(evidence["记录"], [])
        self.assertEqual(verified, [])

    def test_summary_preserves_btc_eth_denominators(self):
        members = [
            {"资产编号": f"DS-{index:06d}", "标的": "BTC" if index < 315 else "ETH"}
            for index in range(630)
        ]
        summary = module.summarize(members, [], {"候选文件数": 2, "扫描UID": 1001, "扫描是否专用只读": True}, [{"状态": "通过"}])
        self.assertTrue(summary["计数守恒"])
        self.assertEqual(summary["分标的"]["BTC"]["候选总体"], 315)
        self.assertEqual(summary["分标的"]["ETH"]["无法判定"], 315)
        self.assertEqual(summary["已证明"], 0)

    def test_incomplete_scan_discards_partial_candidates(self):
        members = module.load_members()
        candidate = {
            "字段": {
                "资产编号": members[0]["资产编号"], "成员编号": members[0]["成员编号"],
                "标的": members[0]["标的"], "输入成员SHA-256": members[0]["输入成员SHA-256"],
                "标的身份": "BTC", "来源提供者": "Binance", "交易场所": "Binance",
                "市场类型": "USDⓈ-M合约", "精确合约": "BTCUSDT",
                "数据对象": "exchangeInfo.symbols[BTCUSDT]", "Schema确切版本": "sha256:" + "b" * 64,
                "授权边界": "Binance公开无认证GET", "字段中文映射": module.EXPECTED_FIELD_MAPPING,
            }
        }
        remote = {
            "扫描完整": False, "失败安全": True, "失败原因代码": "ROOT_OR_WALK_ACCESS_FAILED",
            "失败原因指纹": module.fingerprint("ROOT_OR_WALK_ACCESS_FAILED"),
            "候选": [candidate], "扫描UID": 1001, "扫描是否专用只读": True,
            "候选文件数": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            target = module.render_batch(
                module.load_config(), members, [], remote,
                dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc), Path(directory),
                batch_id_override="test-incomplete-scan-fails-safe",
            )
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            summary = manifest["结果摘要"]
            self.assertEqual(manifest["证据记录数"], 0)
            self.assertEqual(summary["已观察"], 0)
            self.assertEqual(summary["已证明"], 0)
            self.assertEqual(summary["无法判定"], 630)


if __name__ == "__main__":
    unittest.main()
