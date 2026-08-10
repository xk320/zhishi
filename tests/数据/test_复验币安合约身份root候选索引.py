#!/usr/bin/env python3
"""任务-000089候选索引入口的固定合同与失败安全测试。"""

from __future__ import annotations

import ast
import json
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts.数据 import 复验币安合约身份 as legacy
from scripts.数据 import 复验币安合约身份root候选索引 as target


class RootCandidateIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = target.load_config()

    def test_config_has_fixed_index_limits(self) -> None:
        self.assertEqual(
            self.config["资源上限"]["最大索引目录数"],
            16384,
        )
        self.assertEqual(
            self.config["资源上限"]["最大索引条目数"],
            262144,
        )
        self.assertEqual(
            self.config["资源上限"]["最大候选摘要聚合字节"],
            33554432,
        )

    def test_probe_source_is_fixed_and_compiles(self) -> None:
        source = target._probe_source(self.config, 900)
        compile(source, "<root-candidate-probe>", "exec")
        self.assertIn("MAX_DIRS=16384", source)
        self.assertIn("MAX_ENTRIES=262144", source)
        self.assertIn("MAX_QUEUE=16384", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("subprocess", source)

    def test_probe_source_sanitizes_addresses_and_orders_walk(self) -> None:
        source = target._probe_source(self.config, 900)
        self.assertIn("25[0-5]", source)
        self.assertIn("entries=sorted(os.scandir(current), key=lambda item: item.name)", source)

    def test_generated_probe_matches_ipv4_sensitive_value(self) -> None:
        source = target._probe_source(self.config, 900)
        tree = ast.parse(source)
        safe_assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target_node, ast.Name) and target_node.id == "SAFE" for target_node in node.targets)
        )
        pattern = ast.literal_eval(safe_assignment.value.args[0])
        self.assertIsNotNone(re.search(pattern, "candidate address 192.0.2.1"))

    def test_failure_payload_is_root_compatible_and_empty(self) -> None:
        result = target._failure("INDEX_ENTRY_LIMIT")
        self.assertEqual(result["访问模式"], "root兼容只读")
        self.assertFalse(result["扫描是否专用只读"])
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["候选"], [])
        self.assertEqual(result["候选文件数"], 0)

    def test_remote_failure_clears_candidates(self) -> None:
        payload = {
            "协议": "zhishi-binance-contract-probe/1",
            "访问模式": "root兼容只读",
            "扫描UID": 0,
            "扫描GID": 0,
            "扫描是否专用只读": False,
            "扫描完整": False,
            "失败安全": True,
            "失败原因代码": "INDEX_ENTRY_LIMIT",
            "失败原因指纹": legacy.fingerprint("INDEX_ENTRY_LIMIT"),
            "扫描文件数": 123,
            "候选文件数": 0,
            "候选": [],
            "存储根目录": [],
            "索引目录数": 16384,
            "索引条目数": 262144,
            "待处理目录数": 1,
            "索引候选摘要字节": 0,
            "远端追加": False,
            "远端临时文件": False,
            "数据库写入": False,
            "订单簿读取": False,
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload, ensure_ascii=False),
            stderr="",
        )
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["候选"], [])
        self.assertEqual(result["候选文件数"], 0)
        self.assertEqual(result["退出码"], 0)

    def test_complete_empty_index_is_valid_but_not_identity_proof(self) -> None:
        roots = []
        for index, path in enumerate(target.EXPECTED_ROOTS, 1):
            roots.append(
                {
                    "路径指纹": legacy.fingerprint(path),
                    "模式": "0o755",
                    "属主UID": 0,
                    "属组GID": 0,
                    "可读": True,
                    "可写": False,
                }
            )
        payload = {
            "协议": "zhishi-binance-contract-probe/1",
            "访问模式": "root兼容只读",
            "扫描UID": 0,
            "扫描GID": 0,
            "扫描是否专用只读": False,
            "扫描完整": True,
            "失败安全": False,
            "失败原因代码": "",
            "失败原因指纹": "",
            "扫描文件数": 0,
            "候选文件数": 0,
            "候选": [],
            "存储根目录": roots,
            "索引目录数": 6,
            "索引条目数": 0,
            "待处理目录数": 0,
            "索引候选摘要字节": 0,
            "远端追加": False,
            "远端临时文件": False,
            "数据库写入": False,
            "订单簿读取": False,
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload, ensure_ascii=False),
            stderr="",
        )
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["扫描完整"])
        self.assertFalse(result["失败安全"])
        self.assertEqual(result["候选文件数"], 0)
        self.assertEqual(result["访问模式"], "root兼容只读")

    def test_probe_rejects_duplicate_root_set(self) -> None:
        roots = []
        root = {
            "路径指纹": legacy.fingerprint(target.EXPECTED_ROOTS[0]),
            "模式": "0o755",
            "属主UID": 0,
            "属组GID": 0,
            "可读": True,
            "可写": False,
        }
        roots.extend([root.copy() for _ in target.EXPECTED_ROOTS])
        payload = self._base_payload(扫描完整=True, 失败安全=False, 存储根目录=roots)
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_ROOT_PATH_INVALID")
        self.assertEqual(result["候选"], [])

    def test_probe_rejects_malformed_root_without_throwing(self) -> None:
        roots = self._valid_roots()
        roots[0]["路径指纹"] = [roots[0]["路径指纹"]]
        payload = self._base_payload(扫描完整=False, 失败安全=True, 存储根目录=roots)
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_ROOT_PATH_INVALID")

    def test_probe_rejects_malformed_candidate_without_throwing(self) -> None:
        roots = self._valid_roots()
        candidate = {
            "路径指纹": legacy.fingerprint("/opt/binance-event/contracts.csv"),
            "文件名": None,
            "上级目录指纹": legacy.fingerprint("/opt/binance-event"),
            "候选根目录指纹": legacy.fingerprint(target.EXPECTED_ROOTS[0]),
            "大小": 1,
            "修改时间_ns": 1,
            "模式": "0o644",
            "属主UID": 0,
            "属组GID": 0,
            "可读": True,
            "父目录可写": False,
            "内容摘要": {"格式": "csv", "字段映射": {}, "行": [], "原因代码": "INCOMPLETE_IDENTITY_SCHEMA"},
        }
        payload = self._base_payload(扫描完整=True, 失败安全=False, 存储根目录=roots, 候选=[candidate], 候选文件数=1)
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_CANDIDATE_METADATA_INVALID")
        self.assertEqual(result["候选"], [])

    def test_probe_rejects_unhashable_candidate_fingerprint_without_throwing(self) -> None:
        roots = self._valid_roots()
        candidate = {
            "路径指纹": ["not-a-fingerprint"],
            "文件名": "contracts.csv",
            "上级目录指纹": legacy.fingerprint("/opt/binance-event"),
            "候选根目录指纹": legacy.fingerprint(target.EXPECTED_ROOTS[0]),
            "大小": 1,
            "修改时间_ns": 1,
            "模式": "0o644",
            "属主UID": 0,
            "属组GID": 0,
            "可读": True,
            "父目录可写": False,
            "内容摘要": {"格式": "csv", "字段映射": {}, "行": [], "原因代码": "INCOMPLETE_IDENTITY_SCHEMA"},
        }
        payload = self._base_payload(扫描完整=True, 失败安全=False, 存储根目录=roots, 候选=[candidate], 候选文件数=1)
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch.object(target.legacy.engine, "run_bounded_process", return_value=completed):
            result = target.run_remote_probe(self.config)
        self.assertTrue(result["失败安全"])
        self.assertEqual(result["失败原因代码"], "PROBE_CANDIDATE_SCHEMA_INVALID")

    def test_incomplete_summary_reason_is_not_a_valid_candidate(self) -> None:
        summary = {
            "格式": "csv",
            "字段映射": {"标的": "target"},
            "行": [],
            "原因代码": "INCOMPLETE_IDENTITY_SCHEMA",
        }
        self.assertFalse(target._validate_summary(summary, self.config["资源上限"]))

    def test_incomplete_evidence_is_never_published(self) -> None:
        with patch.object(
            target,
            "_ROOT_BUILD_EVIDENCE",
            return_value=(
                {"证据版本": "source-identity-evidence-1.0", "记录": [{"证据记录编号": "E-1"}]},
                [{"资产编号": "BTCUSDT", "标的": "BTC"}],
            ),
        ):
            evidence, verified = target._build_evidence(
                [{"资产编号": "BTCUSDT", "标的": "BTC"}], [], {}
            )
        self.assertEqual(evidence, {"证据版本": "source-identity-evidence-1.0", "记录": []})
        self.assertEqual(verified, [])

    def test_legacy_parent_name_fallback_is_hashed(self) -> None:
        payload = {
            "候选": [
                {
                    "路径指纹": "a" * 64,
                    "文件名": "contracts.csv",
                    "上级目录名": "secret-parent",
                    "大小": 1,
                    "修改时间_ns": 1,
                    "模式": "0o644",
                    "属主UID": 0,
                    "属组GID": 0,
                    "内容摘要": {
                        "格式": "csv",
                        "字段映射": {},
                        "行": [{field: "value" for field in legacy.CANDIDATE_FIELDS}],
                        "Schema指纹": "b" * 64,
                    },
                }
            ]
        }
        result = legacy.flatten_candidates(payload)
        self.assertEqual(result[0]["文件"]["上级目录指纹"], legacy.fingerprint("secret-parent"))
        self.assertNotIn("上级目录名", result[0]["文件"])

    def test_summary_rejects_missing_identity_field_values(self) -> None:
        row = {field: "value" for field in legacy.CANDIDATE_FIELDS}
        row["精确合约"] = None
        summary = {
            "格式": "csv",
            "字段映射": {field: field for field in legacy.CANDIDATE_FIELDS},
            "行": [row],
            "Schema指纹": "b" * 64,
        }
        self.assertFalse(target._validate_summary(summary, self.config["资源上限"]))

    def test_summary_rejects_unbound_sqlite_schema(self) -> None:
        summary = {
            "格式": "sqlite",
            "表": [{
                "表名指纹": "not-a-fingerprint",
                "字段指纹": "b" * 64,
                "字段映射": {"标的": "symbol"},
            }],
            "行": [],
        }
        self.assertFalse(target._validate_summary(summary, self.config["资源上限"]))

    def test_summary_rejects_unbound_csv_mapping(self) -> None:
        summary = {
            "格式": "csv",
            "字段映射": {field: field for field in legacy.CANDIDATE_FIELDS},
            "行": [],
            "Schema指纹": "b" * 64,
        }
        summary["字段映射"]["标的"] = "unbound-column"
        self.assertFalse(target._validate_summary(summary, self.config["资源上限"]))

    def _valid_roots(self):
        return [
            {
                "路径指纹": legacy.fingerprint(path),
                "模式": "0o755",
                "属主UID": 0,
                "属组GID": 0,
                "可读": True,
                "可写": False,
            }
            for index, path in enumerate(target.EXPECTED_ROOTS, 1)
        ]

    def _base_payload(self, **overrides):
        payload = {
            "协议": "zhishi-binance-contract-probe/1",
            "访问模式": "root兼容只读",
            "扫描UID": 0,
            "扫描GID": 0,
            "扫描是否专用只读": False,
            "扫描完整": False,
            "失败安全": True,
            "失败原因代码": "INDEX_ENTRY_LIMIT",
            "失败原因指纹": legacy.fingerprint("INDEX_ENTRY_LIMIT"),
            "扫描文件数": 0,
            "候选文件数": 0,
            "候选": [],
            "存储根目录": [],
            "索引目录数": 0,
            "索引条目数": 0,
            "待处理目录数": 0,
            "索引候选摘要字节": 0,
            "远端追加": False,
            "远端临时文件": False,
            "数据库写入": False,
            "订单簿读取": False,
        }
        payload.update(overrides)
        return payload


if __name__ == "__main__":
    unittest.main()
