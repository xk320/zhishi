from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
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
        self.assertEqual(config["可信HTTPS传输"]["可执行文件"], "/usr/bin/curl")
        self.assertEqual(config["可信HTTPS传输"]["禁止参数"], ["--insecure", "-k", "--location", "-L"])

    def test_trusted_curl_uses_fixed_tls_verified_command(self):
        uri = "https://fapi.binance.com/fapi/v1/exchangeInfo"
        captured: list[tuple[list[str], dict[str, object]]] = []
        payload = json.dumps(
            {"timezone": "UTC", "symbols": [{"symbol": "BTCUSDT", "baseAsset": "BTC"}]}
        ).encode("utf-8")

        def fake_runner(command, **kwargs):
            captured.append((command, kwargs))
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, b"curl 8.7.1 test\n", b"")
            return subprocess.CompletedProcess(
                command, 0, payload + b"\n__ZHISHI_HTTP_STATUS__:200", b""
            )

        summary = MODULE.fetch_exchange_info(
            uri,
            started=0.0,
            runner=fake_runner,
            curl_path=MODULE.CURL_PATH,
        )

        self.assertEqual(summary["状态"], "成功")
        command, kwargs = captured[-1]
        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertEqual(command[1], "--disable")
        self.assertEqual(command[-1], uri)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("-k", command)
        self.assertNotIn("--location", command)
        self.assertNotIn("-L", command)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(summary["传输器"]["TLS校验"], "系统默认证书与主机名校验")

    def test_trusted_curl_rejects_non_allowlisted_endpoint(self):
        with self.assertRaisesRegex(ValueError, "公开端点不在白名单"):
            MODULE.fetch_exchange_info(
                "https://example.com/exchangeInfo",
                started=0.0,
                runner=lambda *_args, **_kwargs: None,
                curl_path=MODULE.CURL_PATH,
            )

    def test_trusted_curl_maps_timeout_without_response_body(self):
        def fake_runner(command, **_kwargs):
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, b"curl 8.7.1 test\n", b"")
            raise subprocess.TimeoutExpired(command, 60)

        summary = MODULE.fetch_exchange_info(
            "https://fapi.binance.com/fapi/v1/exchangeInfo",
            started=0.0,
            runner=fake_runner,
            curl_path=MODULE.CURL_PATH,
        )
        self.assertEqual(summary["状态"], "失败")
        self.assertEqual(summary["失败原因代码"], "CURL_TIMEOUT")
        self.assertNotIn("响应正文", summary)

    def test_trusted_curl_rejects_oversize_and_non_json(self):
        uri = "https://fapi.binance.com/fapi/v1/exchangeInfo"

        def fake_oversize(command, **_kwargs):
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, b"curl 8.7.1 test\n", b"")
            return subprocess.CompletedProcess(
                command, 0, b"x" * 33 + b"\n__ZHISHI_HTTP_STATUS__:200", b""
            )

        with patch.object(MODULE, "MAX_RESPONSE_BYTES", 32):
            oversize = MODULE.fetch_exchange_info(
                uri, started=0.0, runner=fake_oversize, curl_path=MODULE.CURL_PATH
            )
        self.assertEqual(oversize["失败原因代码"], "API_RESPONSE_TOO_LARGE")

        def fake_non_json(command, **_kwargs):
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, b"curl 8.7.1 test\n", b"")
            return subprocess.CompletedProcess(
                command, 0, b"not-json\n__ZHISHI_HTTP_STATUS__:200", b""
            )

        invalid = MODULE.fetch_exchange_info(
            uri, started=0.0, runner=fake_non_json, curl_path=MODULE.CURL_PATH
        )
        self.assertEqual(invalid["失败原因代码"], "API_JSON_INVALID")

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

    def test_rules_fingerprint_binds_trusted_transport_contract(self):
        config = json.loads(MODULE.CONFIG_PATH.read_text(encoding="utf-8"))
        baseline = MODULE.rules_fingerprint(config)
        changed = copy.deepcopy(config)
        changed["可信HTTPS传输"]["单端点总超时秒"] = 61
        self.assertNotEqual(baseline, MODULE.rules_fingerprint(changed))

    def test_batch_persists_transport_facts_without_internal_response_fields(self):
        transport = {
            "可执行文件": "/usr/bin/curl",
            "版本": "curl 8.7.1 test",
            "二进制SHA-256": "a" * 64,
            "TLS校验": "系统默认证书与主机名校验",
            "环境边界SHA-256": "b" * 64,
            "参数SHA-256": "c" * 64,
        }

        def fake(url, _started):
            return {
                "端点": url,
                "市场类型": MODULE.API_ENDPOINTS[url],
                "方法": "GET",
                "授权边界": "Binance公开无认证GET",
                "HTTP状态": 200,
                "响应字节数": 2,
                "响应SHA-256": "d" * 64,
                "Schema确切版本指纹": "sha256:" + "e" * 64,
                "合约条目数": 0,
                "传输器": transport,
                "状态": "成功",
                "_合约索引": [],
                "_完整响应": "禁止落盘",
            }

        with tempfile.TemporaryDirectory() as tmp:
            _batch, manifest = MODULE.build_batch(
                batch_root=Path(tmp),
                now=MODULE.datetime(2026, 8, 11, 1, tzinfo=MODULE.timezone.utc),
                fetcher=fake,
            )
        self.assertEqual(manifest["修复任务编号"], "任务-000091")
        self.assertIn("任务-000091", manifest["输入"]["依赖SHA-256"])
        self.assertEqual(manifest["API"][0]["传输器"], transport)
        self.assertFalse(any(key.startswith("_") for item in manifest["API"] for key in item))

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
