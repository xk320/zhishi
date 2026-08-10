import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.数据 import 复验币安合约身份root兼容 as module


class _Completed:
    def __init__(self, payload, returncode=0):
        self.stdout = json.dumps(payload, ensure_ascii=False).encode()
        self.stderr = b""
        self.returncode = returncode


class TestRootCompatibleContractIdentity(unittest.TestCase):
    def test_config_requires_explicit_root_mode(self):
        config = module.load_config()
        self.assertEqual(config["任务编号"], "任务-000088")
        self.assertEqual(config["访问模式"], "root兼容只读")
        self.assertEqual(config["实际UID"], 0)
        self.assertEqual(config["专用只读UID"], 1001)

    def test_probe_source_is_fixed_and_not_dedicated(self):
        source = module._root_probe_source(module.load_config(), 10)
        compile(source, "<root-probe>", "exec")
        self.assertIn('"访问模式":"root兼容只读"', source)
        self.assertIn('"扫描是否专用只读":False', source)
        self.assertIn("EXPECTED_UID=0", source)
        self.assertIn("followlinks=False", source)
        self.assertNotIn("scp ", source)
        self.assertNotIn("DROP TABLE", source)

    def test_probe_accepts_uid_zero_only_and_records_mode(self):
        roots = [
            {"根目录": Path(path).name, "路径指纹": module.legacy.fingerprint(path), "模式": "0o700", "属主UID": 0, "属组GID": 0, "可读": True, "可写": False}
            for path in module.load_config()["远端候选根目录"]
        ]
        payload = {
            "协议": "zhishi-binance-contract-probe/1", "访问模式": "root兼容只读", "扫描UID": 0, "扫描GID": 0,
            "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "失败原因代码": "", "失败原因指纹": "",
            "扫描文件数": 1, "候选文件数": 0, "候选": [], "存储根目录": roots, "远端追加": False,
            "远端临时文件": False, "数据库写入": False, "订单簿读取": False,
        }
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertEqual(result["扫描UID"], 0)
        self.assertEqual(result["访问模式"], "root兼容只读")
        self.assertFalse(result["扫描是否专用只读"])
        self.assertEqual(result["退出码"], 0)
        self.assertGreater(result["资源事实"]["标准输出字节"], 0)

    def test_probe_rejects_uid_one_thousand_one(self):
        payload = {
            "协议": "zhishi-binance-contract-probe/1", "访问模式": "root兼容只读", "扫描UID": 1001, "扫描GID": 1001,
            "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "失败原因代码": "", "失败原因指纹": "",
            "扫描文件数": 0, "候选文件数": 0, "候选": [], "存储根目录": [], "远端追加": False,
            "远端临时文件": False, "数据库写入": False, "订单簿读取": False,
        }
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "ROOT_IDENTITY_FACT_INVALID")
        self.assertEqual(result["候选"], [])

    def test_probe_rejects_unallowlisted_candidate_payload(self):
        payload = {
            "协议": "zhishi-binance-contract-probe/1", "访问模式": "root兼容只读", "扫描UID": 0, "扫描GID": 0,
            "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "失败原因代码": "", "失败原因指纹": "",
            "扫描文件数": 1, "候选文件数": 1,
            "候选": [{"路径指纹": "a" * 64, "文件名": "evil.csv", "上级目录名": "data", "候选根目录指纹": module.legacy.fingerprint("/opt/binance-event"), "大小": 1, "修改时间_ns": 1, "模式": "0o600", "属主UID": 0, "属组GID": 0, "可读": True, "父目录可写": False, "内容摘要": {"格式": "csv", "字段映射": {}, "行": [], "Schema指纹": "b" * 64}}],
            "存储根目录": [{"根目录": "binance-event", "路径指纹": module.legacy.fingerprint("/opt/binance-event"), "模式": "0o700", "属主UID": 0, "属组GID": 0, "可读": True, "可写": False}],
            "远端追加": False, "远端临时文件": False, "数据库写入": False, "订单簿读取": False,
        }
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_CANDIDATE_NAME_INVALID")
        self.assertEqual(result["候选"], [])

    def test_probe_rejects_malformed_content_and_types_failure_safe(self):
        roots = [
            {"根目录": Path(path).name, "路径指纹": module.legacy.fingerprint(path), "模式": "0o700", "属主UID": 0, "属组GID": 0, "可读": True, "可写": False}
            for path in module.load_config()["远端候选根目录"]
        ]
        candidate = {
            "路径指纹": "a" * 64, "文件名": "contracts.csv", "上级目录名": "data",
            "候选根目录指纹": module.legacy.fingerprint("/opt/binance-event"), "大小": 1,
            "修改时间_ns": 1, "模式": "0o600", "属主UID": 0, "属组GID": 0,
            "可读": True, "父目录可写": False, "内容摘要": {"行": []},
        }
        payload = {
            "协议": "zhishi-binance-contract-probe/1", "访问模式": "root兼容只读", "扫描UID": 0, "扫描GID": 0,
            "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "失败原因代码": "", "失败原因指纹": "",
            "扫描文件数": 1, "候选文件数": 1, "候选": [candidate], "存储根目录": roots,
            "远端追加": False, "远端临时文件": False, "数据库写入": False, "订单簿读取": False,
        }
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_CONTENT_SUMMARY_INVALID")
        self.assertEqual(result["候选"], [])

        payload["候选"][0]["文件名"] = []
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_CANDIDATE_METADATA_INVALID")

        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(None)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_PAYLOAD_INVALID")

    def test_probe_rejects_scan_limit_claimed_complete(self):
        payload = {
            "协议": "zhishi-binance-contract-probe/1", "访问模式": "root兼容只读", "扫描UID": 0, "扫描GID": 0,
            "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "失败原因代码": "", "失败原因指纹": "",
            "扫描文件数": 4096, "候选文件数": 0, "候选": [], "存储根目录": [], "远端追加": False,
            "远端临时文件": False, "数据库写入": False, "订单簿读取": False,
        }
        with patch.object(module.legacy.engine, "run_bounded_process", return_value=_Completed(payload)):
            result = module.run_root_remote_probe(module.load_config())
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_SCAN_COUNT_LIMIT")

    def test_partial_evidence_is_not_published(self):
        members = module.legacy.load_members()
        remote = {"访问模式": "root兼容只读", "扫描UID": 0, "扫描是否专用只读": False, "扫描完整": True, "失败安全": False, "候选": []}
        with tempfile.TemporaryDirectory() as directory:
            target = module.render_root_batch(
                module.load_config(), members, [], remote,
                dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc), Path(directory),
                batch_id_override="test-root-partial-safe",
            )
            self.assertFalse((target / "任务-000084来源身份声明证据.json").exists())
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["证据记录数"], 0)
            self.assertEqual(manifest["结果摘要"]["分标的"]["BTC"]["候选总体"], 315)
            self.assertEqual(manifest["结果摘要"]["分标的"]["ETH"]["无法判定"], 315)

    def test_evidence_identifiers_are_task_specific(self):
        members = [{"资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}]
        candidate = {"字段": {
            "资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64,
            "标的身份": "BTC", "来源提供者": "Binance", "交易场所": "Binance", "市场类型": "USDⓈ-M合约",
            "精确合约": "BTCUSDT", "数据对象": "exchangeInfo.symbols[BTCUSDT]", "Schema确切版本": "sha256:" + "b" * 64,
            "授权边界": "Binance公开无认证GET", "字段中文映射": module.legacy.EXPECTED_FIELD_MAPPING,
        }}
        contracts = {"BTC": [{"symbol": "BTCUSDT", "baseAsset": "BTC", "市场类型": "USDⓈ-M合约", "响应Schema指纹": "b" * 64}], "ETH": []}
        evidence, _ = module.build_evidence(members, [candidate], contracts)
        self.assertTrue(evidence["记录"])
        self.assertTrue(all(item["证据记录编号"].startswith("E-000088-") for item in evidence["记录"]))

    def test_duplicate_binding_is_failure_safe(self):
        members = [{"资产编号": "DS-000001", "成员编号": "ZI-1", "标的": "BTC", "输入成员SHA-256": "a" * 64}]
        candidate = {"字段": {"标的": "BTC", "资产编号": "DS-000001", "成员编号": "ZI-1", "输入成员SHA-256": "a" * 64}}
        evidence, verified = module.build_evidence(members, [candidate, candidate], {"BTC": [], "ETH": []})
        self.assertEqual(evidence["记录"], [])
        self.assertEqual(verified, [])


if __name__ == "__main__":
    unittest.main()
