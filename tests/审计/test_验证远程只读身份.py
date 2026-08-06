from __future__ import annotations

import importlib.util
import json
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "scripts/审计/远程只读身份探针.py"
VALIDATOR = ROOT / "scripts/审计/验证远程只读身份.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RemoteReadonlyIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load(PROBE, "zhishi_ro_probe_test")
        cls.validator = load(VALIDATOR, "zhishi_ro_validator_test")

    def run_probe(self, text: str, command: str = ""):
        env = os.environ.copy()
        if command:
            env["SSH_ORIGINAL_COMMAND"] = command
        else:
            env.pop("SSH_ORIGINAL_COMMAND", None)
        completed = subprocess.run(
            [sys.executable, str(PROBE)],
            input=text,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        return completed, json.loads(completed.stdout)

    def test_固定请求可生成(self):
        self.assertEqual(
            self.probe.canonical_request(),
            '{"operation":"identity","payload":{},"protocol":"zhishi-ro/1"}',
        )

    def test_固定请求通过且不读取业务数据(self):
        completed, response = self.run_probe(self.probe.canonical_request())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(response["status"], "通过")
        self.assertFalse(response["database_business_read_performed"])
        self.assertFalse(response["market_data_read_performed"])
        # 本机测试进程可能有用户附加组；验证器的硬门针对远端专用账户，
        # 用不含附加组的固定响应副本验证合同，不把本机身份冒充远端证据。
        validated_response = deepcopy(response)
        validated_response.update(
            {
                "uid": 1001,
                "gid": 1001,
                "uid_nonzero": True,
                "supplementary_group_count": 0,
                "root_home_readable": False,
                "root_home_writable": False,
                "protected_system_path_writable": False,
                "original_command_present": False,
            }
        )
        errors = self.validator.validate_identity_response(
            validated_response, wrapper_sha256=self.validator.sha256_file(PROBE)
        )
        self.assertEqual(errors, ())

    def test_任意原始命令被拒绝(self):
        completed, response = self.run_probe(self.probe.canonical_request(), "id")
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(response["status"], "拒绝")
        self.assertEqual(response["reason_code"], "original-command")

    def test_未知字段和非空载荷被拒绝(self):
        unknown = '{"operation":"identity","payload":{},"protocol":"zhishi-ro/1","x":1}'
        completed, response = self.run_probe(unknown)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(response["reason_code"], "request-fields")
        nonempty = '{"operation":"identity","payload":{"x":1},"protocol":"zhishi-ro/1"}'
        completed, response = self.run_probe(nonempty)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(response["reason_code"], "request-payload")

    def test_重复字段被拒绝(self):
        duplicate = '{"operation":"identity","payload":{},"protocol":"zhishi-ro/1","protocol":"zhishi-ro/1"}'
        completed, response = self.run_probe(duplicate)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(response["reason_code"], "invalid-json")


if __name__ == "__main__":
    unittest.main()
