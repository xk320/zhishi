from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import time
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
                "admin_group_membership": False,
                "sudo_noninteractive_allowed": False,
                "supplementary_group_count": 0,
                "root_home_readable": False,
                "root_home_openable": False,
                "root_home_writable": False,
                "protected_system_path_writable": False,
                "original_command_present": False,
            }
        )
        errors = self.validator.validate_identity_response(
            validated_response, wrapper_sha256=self.validator.sha256_file(PROBE)
        )
        self.assertEqual(errors, ())

    def test_批次构建重新验证响应和权限事实(self):
        _, response = self.run_probe(self.probe.canonical_request())
        with tempfile.TemporaryDirectory() as directory:
            fixture_uid = os.getuid() or 1001
            fixture_gid = os.getgid() or 1001
            response.update(
                {
                "uid": fixture_uid,
                "gid": fixture_gid,
                "uid_nonzero": True,
                "admin_group_membership": False,
                "sudo_noninteractive_allowed": False,
                "supplementary_group_count": 0,
                "root_home_readable": False,
                "root_home_openable": False,
                "root_home_writable": False,
                "protected_system_path_writable": False,
                "original_command_present": False,
                }
            )
            public_key = Path(directory) / "sample.pub"
            public_key.write_text("ssh-ed25519 AAECAwQ= sample\n", encoding="utf-8")
            authorized_keys = Path(directory) / "authorized_keys"
            options = 'restrict,command="/usr/local/libexec/zhishi_ro_identity_probe.py"'
            authorized_keys.write_text(
                f"{options} ssh-ed25519 AAECAwQ= sample\n", encoding="utf-8"
            )
            authorized_keys.chmod(0o600)
            wrapper_stat = Path(directory) / "wrapper-stat.json"
            wrapper_stat.write_text(
                json.dumps(
                    {
                        "owner_uid": 0,
                        "owner_gid": 0,
                        "mode": "0755",
                        "regular_file": True,
                        "content_sha256": self.validator.sha256_file(PROBE),
                    }
                ),
                encoding="utf-8",
            )
            permission_facts = Path(directory) / "permission-facts.json"
            permission_facts.write_text(
                json.dumps(
                    {
                        "snapshot_version": "zhishi-ro-permissions/1",
                        "source": "root-management-readonly",
                        "account": {
                            "uid": fixture_uid,
                            "gid": fixture_gid,
                            "supplementary_group_count": 0,
                            "admin_group_membership": False,
                            "password_locked": True,
                            "sudo_noninteractive_allowed": False,
                        },
                        "wrapper": {
                            "owner_uid": 0,
                            "owner_gid": 0,
                            "mode": "0755",
                            "regular_file": True,
                            "content_sha256": self.validator.sha256_file(PROBE),
                        },
                        "authorized_keys": {
                            "owner_uid": fixture_uid,
                            "owner_gid": fixture_gid,
                            "mode": "0600",
                            "regular_file": True,
                            "content_sha256": self.validator.sha256_file(authorized_keys),
                            "key_count": 1,
                            "key_fingerprint": "SHA256:CLteXW6qwQSe3giT0w7QIrGk2bW0jbQUhx9Rycs1KD0",
                            "options_fingerprint": hashlib.sha256(options.encode()).hexdigest(),
                            "restrict": True,
                            "fixed_command": True,
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                self.validator.compute_public_key_fingerprint(public_key),
                "SHA256:CLteXW6qwQSe3giT0w7QIrGk2bW0jbQUhx9Rycs1KD0",
            )
            kwargs = {
                "wrapper_path": PROBE,
                "public_key_path": public_key,
                "authorized_keys_path": authorized_keys,
                "wrapper_stat_path": wrapper_stat,
                "permission_facts_path": permission_facts,
                "batch_id": "remote-ro-identity-20260806T081014Z-v1",
                "frozen_at": "2026-08-06T08:10:14Z",
                "ssh_options": options,
                "authorized_key_count": 1,
                "password_locked": True,
                "admin_groups": False,
                "supplementary_group_count": 0,
                "probe_exit_code": 0,
                "memory_available_percent": 72,
                "disk_available_gib": 159.4,
            }
            metadata = self.validator.build_batch_metadata(response, **kwargs)
            self.assertEqual(metadata["状态"], "通过")
            fake = dict(response)
            fake["uid"] = 0
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(fake, **kwargs)
            fake_admin = dict(response)
            fake_admin["admin_group_membership"] = True
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(fake_admin, **kwargs)
            fake_sudo = dict(response)
            fake_sudo["sudo_noninteractive_allowed"] = True
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(fake_sudo, **kwargs)
            bad_options = dict(kwargs)
            bad_options["ssh_options"] = 'restrict,command="/tmp/other-wrapper.py"'
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **bad_options)
            bad_owner = dict(kwargs)
            bad_owner["wrapper_stat_path"] = Path(directory) / "bad-wrapper-stat.json"
            bad_owner["wrapper_stat_path"].write_text(
                json.dumps(
                    {
                        "owner_uid": 501,
                        "owner_gid": 20,
                        "mode": "0644",
                        "regular_file": True,
                        "content_sha256": self.validator.sha256_file(PROBE),
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **bad_owner)
            bad_content = dict(kwargs)
            bad_content["permission_facts_path"] = Path(directory) / "bad-content.json"
            bad_snapshot = json.loads(permission_facts.read_text(encoding="utf-8"))
            bad_snapshot["authorized_keys"]["content_sha256"] = "a" * 64
            bad_content["permission_facts_path"].write_text(
                json.dumps(bad_snapshot), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **bad_content)
            bad_key_owner = dict(kwargs)
            bad_key_owner["permission_facts_path"] = Path(directory) / "bad-key-owner.json"
            bad_owner_snapshot = json.loads(permission_facts.read_text(encoding="utf-8"))
            bad_owner_snapshot["authorized_keys"]["owner_uid"] = 1001
            bad_owner_snapshot["authorized_keys"]["owner_gid"] = 1001
            bad_key_owner["permission_facts_path"].write_text(
                json.dumps(bad_owner_snapshot), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **bad_key_owner)
            authorized_keys.write_text(
                f"{options} ssh-ed25519 AAECAwQ= tampered\n", encoding="utf-8"
            )
            authorized_keys.chmod(0o600)
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **kwargs)
            authorized_keys.chmod(0o644)
            with self.assertRaises(ValueError):
                self.validator.build_batch_metadata(response, **kwargs)

    def test_批次目录拒绝覆盖(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "batch"
            wrapper_evidence = Path(directory) / "wrapper-stat.json"
            account_evidence = Path(directory) / "账户授权事实.json"
            wrapper_evidence.write_text("{}\n", encoding="utf-8")
            account_evidence.write_text("{}\n", encoding="utf-8")
            payload = {
                "证据文件": {
                    "wrapper统计快照": {
                        "文件名": "wrapper-stat.json",
                        "SHA256": self.validator.sha256_file(wrapper_evidence),
                    },
                    "账户与授权事实快照": {
                        "文件名": "账户授权事实.json",
                        "SHA256": self.validator.sha256_file(account_evidence),
                    },
                }
            }
            self.validator.write_batch_append_only(
                out,
                metadata=payload,
                response=payload,
                boundary_summary=payload,
                evidence_files={
                    "wrapper-stat.json": wrapper_evidence,
                    "账户授权事实.json": account_evidence,
                },
                started_monotonic=time.monotonic(),
            )
            with self.assertRaises(TypeError):
                self.validator.write_batch_append_only(
                    Path(directory) / "missing-start",
                    metadata=payload,
                    response=payload,
                    boundary_summary=payload,
                    evidence_files={
                        "wrapper-stat.json": wrapper_evidence,
                        "账户授权事实.json": account_evidence,
                    },
                )
            with self.assertRaises(FileExistsError):
                self.validator.write_batch_append_only(
                    out,
                    metadata=payload,
                    response=payload,
                    boundary_summary=payload,
                    evidence_files={
                        "wrapper-stat.json": wrapper_evidence,
                        "账户授权事实.json": account_evidence,
                    },
                    started_monotonic=time.monotonic(),
                )
            with self.assertRaises(TimeoutError):
                self.validator.write_batch_append_only(
                    Path(directory) / "expired",
                    metadata=payload,
                    response=payload,
                    boundary_summary=payload,
                    evidence_files={
                        "wrapper-stat.json": wrapper_evidence,
                        "账户授权事实.json": account_evidence,
                    },
                    started_monotonic=time.monotonic() - 601,
                )

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
