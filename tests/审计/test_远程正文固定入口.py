from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/审计/执行未完整扫描对象正文.py"
FIXED_ENTRY = ROOT / "scripts/审计/远程正文固定入口.py"


def load_module():
    spec = importlib.util.spec_from_file_location("body_audit_runner", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("无法加载正文复采执行器")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_fixed_entry():
    spec = importlib.util.spec_from_file_location("fixed_body_entry", FIXED_ENTRY)
    if spec is None or spec.loader is None:
        raise AssertionError("无法加载远程固定入口")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixedBodyEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_固定入口是版本化协议且不接受远程命令(self):
        text = FIXED_ENTRY.read_text(encoding="utf-8")
        self.assertIn('PROTOCOL = "zhishi-ro/2"', text)
        self.assertIn('if os.environ.get("SSH_ORIGINAL_COMMAND")', text)
        self.assertIn('raise ProtocolError("request-operation")', text)
        self.assertIn('len(objects) != 92', text)
        self.assertNotIn("/Users/", text)
        self.assertIn('raise RuntimeError("resource-limit-failed")', text)

    def test_请求绑定对象资源指纹和冻结截止(self):
        entry = load_fixed_entry()
        valid = {
            "protocol": "zhishi-ro/2",
            "operation": "body-audit",
            "payload": {
                "合同版本": "task-000070",
                "覆盖矩阵指纹": entry.MATRIX_FINGERPRINT,
                "对象清单指纹": entry.TARGETS_FINGERPRINT,
                "资源合同指纹": entry.RESOURCE_CONTRACT_FINGERPRINT,
                "数据截止": entry.FROZEN_DATA_CUTOFF,
                "规则脚本指纹": "a" * 64,
            },
        }
        self.assertEqual(valid, entry._parse_request(json.dumps(valid, ensure_ascii=False)))
        for key, value in (("对象清单指纹", "0" * 64), ("资源合同指纹", "0" * 64)):
            invalid = json.loads(json.dumps(valid, ensure_ascii=False))
            invalid["payload"][key] = value
            with self.assertRaises(entry.ProtocolError):
                entry._parse_request(json.dumps(invalid, ensure_ascii=False))
        invalid = json.loads(json.dumps(valid, ensure_ascii=False))
        invalid["payload"]["数据截止"] = "2020-01-01T00:00:00+08:00"
        with self.assertRaises(entry.ProtocolError):
            entry._parse_request(json.dumps(invalid, ensure_ascii=False))

    def test_数据库调用只发送stdin请求而没有远程命令(self):
        module = self.module
        original_fingerprint = module._key_fingerprint
        original_run = module.subprocess.run
        calls = []

        class FakeCompleted:
            returncode = 0
            stdout = json.dumps({"拒绝": True})
            stderr = ""

        def fake_fingerprint(_path):
            return module.EXPECTED_BODY_KEY_FP

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return FakeCompleted()

        module._key_fingerprint = fake_fingerprint
        module.subprocess.run = fake_run
        try:
            with self.assertRaises(RuntimeError):
                module.run_remote_database(
                    [{"资产编号": "DS-000001", "数据库": "db", "表": "table"}] * 92,
                    "2026-08-06T12:00:00+08:00",
                    "a" * 64,
                    Path("/tmp/body-key"),
                )
        finally:
            module._key_fingerprint = original_fingerprint
            module.subprocess.run = original_run
        self.assertEqual(1, len(calls))
        command, kwargs = calls[0]
        self.assertIn("-i", command)
        self.assertIn("User=zhishi_ro", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertEqual("ubuntu", command[-1])
        self.assertEqual([], command[command.index("ubuntu") + 1 :])
        request = json.loads(kwargs["input"])
        self.assertEqual("zhishi-ro/2", request["protocol"])
        self.assertEqual("body-audit", request["operation"])
        self.assertEqual("task-000070", request["payload"]["合同版本"])


if __name__ == "__main__":
    unittest.main()
