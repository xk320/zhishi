from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "审计" / "发现数据资产.py"


def load_discovery_module() -> ModuleType:
    if not MODULE_PATH.exists():
        raise AssertionError(f"实现文件尚不存在：{MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("data_asset_discovery", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sample_probe_result() -> dict[str, object]:
    return {
        "probe_version": "1.0",
        "collected_at": "2026-07-28T09:00:00+08:00",
        "host": {
            "os": "Ubuntu 22.04",
            "kernel": "Linux 5.15",
            "timezone": "Asia/Shanghai",
        },
        "mounts": [
            {"target": "/", "fstype": "ext4", "mode": "rw"},
        ],
        "services": [
            {
                "name": "mysql.service",
                "state": "active",
                "user": "mysql",
                "workdir": "/",
            },
        ],
        "listeners": [
            {"protocol": "tcp", "port": 3306, "process": "mysqld"},
        ],
        "containers": [],
        "roots": [
            {"path": "/opt/crypto-radar", "status": "可访问"},
        ],
        "files": [
            {
                "path": "/opt/crypto-radar/data/btc.csv",
                "format": "CSV",
                "size": 42,
                "modified_at": "2026-07-28T08:00:00+08:00",
                "project": "crypto-radar",
            },
            {
                "path": "/opt/crypto-radar/data/btc.csv",
                "format": "CSV",
                "size": 42,
                "modified_at": "2026-07-28T08:00:00+08:00",
                "project": "crypto-radar",
            },
        ],
        "database": {"status": "无法访问", "objects": []},
        "errors": [{"category": "database", "status": "无法访问"}],
    }


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


@unittest.skipUnless(MODULE_PATH.exists(), "等待数据资产发现实现")
class DataAssetDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.discovery = load_discovery_module()

    def test_探针结果必须包含固定版本和结构(self):
        validated = self.discovery.validate_probe_result(sample_probe_result())

        self.assertEqual("1.0", validated["probe_version"])
        for field in (
            "host",
            "mounts",
            "services",
            "listeners",
            "containers",
            "roots",
            "files",
            "database",
            "errors",
        ):
            self.assertIn(field, validated)

    def test_非法版本和非法集合被拒绝(self):
        wrong_version = sample_probe_result()
        wrong_version["probe_version"] = "9.9"
        with self.assertRaisesRegex(ValueError, "探针版本"):
            self.discovery.validate_probe_result(wrong_version)

        wrong_files = sample_probe_result()
        wrong_files["files"] = "不是列表"
        with self.assertRaisesRegex(ValueError, "files"):
            self.discovery.validate_probe_result(wrong_files)

    def test_资产归一化去重排序且不猜测时间范围(self):
        assets = self.discovery.build_assets(sample_probe_result(), "ubuntu")

        ids = [asset["资产编号"] for asset in assets]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, [f"DS-{index:06d}" for index in range(1, len(ids) + 1)])
        file_assets = [asset for asset in assets if asset["资产类型"] == "候选数据文件"]
        self.assertEqual(1, len(file_assets))
        self.assertEqual("BTC", file_assets[0]["标的范围"])
        self.assertEqual("未知", file_assets[0]["时间范围"])
        self.assertTrue(
            any(
                asset["资产类型"] == "数据库元数据"
                and asset["访问状态"] == "无法访问"
                for asset in assets
            )
        )

    def test_csv和markdown共享批次且声明不可推导结论(self):
        payload = sample_probe_result()
        assets = self.discovery.build_assets(payload, "ubuntu")
        csv_text = self.discovery.render_csv(assets, "discovery-fixed")
        markdown = self.discovery.render_markdown(
            assets,
            payload,
            "discovery-fixed",
            "ubuntu",
        )

        self.assertIn("发现批次,资产编号", csv_text)
        self.assertIn("discovery-fixed", csv_text)
        self.assertIn("发现批次：`discovery-fixed`", markdown)
        self.assertIn("不证明数据完整、可重放或可用于研究", markdown)
        self.assertIn("BTC", markdown)
        self.assertIn("ETH", markdown)
        self.assertIn("SOL", markdown)

    def test_固定探针只有白名单且不包含危险能力(self):
        probe = self.discovery.REMOTE_PROBE

        for root in self.discovery.ALLOWED_ROOTS:
            self.assertIn(root, probe)
        self.assertIn("--no-defaults", probe)
        self.assertIn("information_schema", probe)
        self.assertIn("os.path.islink(root)", probe)
        for forbidden in (
            "sudo ",
            "systemctl restart",
            "systemctl stop",
            "systemctl start",
            "os.environ",
            "getenv(",
            "read_text(",
            "write_text(",
            "chmod(",
            "chown(",
            "unlink(",
            "rmtree(",
        ):
            self.assertNotIn(forbidden, probe)

    def test_ssh命令无shell且目标别名必须安全(self):
        command = self.discovery.build_ssh_command("ssh", "ubuntu", 10)

        self.assertEqual("ssh", command[0])
        self.assertIn("BatchMode=yes", command)
        self.assertIn("ConnectTimeout=10", command)
        self.assertEqual(["ubuntu", "python3", "-"], command[-3:])
        with self.assertRaisesRegex(ValueError, "SSH目标"):
            self.discovery.build_ssh_command("ssh", "ubuntu;touch /tmp/x", 10)

    def test_脱敏覆盖ip私钥令牌和明文凭据(self):
        value = (
            "host=203.0.113.7 password=hunter2 "
            "token=ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "-----BEGIN PRIVATE KEY-----"
        )

        redacted = self.discovery.redact(value)

        self.assertNotIn("203.0.113.7", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("ghp_", redacted)
        self.assertNotIn("PRIVATE KEY", redacted)

    def _write_fake_ssh(self, directory: Path, output: str, exit_code: int) -> Path:
        fake_ssh = directory / "fake-ssh"
        fake_ssh.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.read()\n"
            f"sys.stdout.write({output!r})\n"
            f"raise SystemExit({exit_code})\n",
            encoding="utf-8",
        )
        fake_ssh.chmod(fake_ssh.stat().st_mode | stat.S_IXUSR)
        return fake_ssh

    def test_完整命令行流程写出同一批次的两个产物(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            fake_ssh = self._write_fake_ssh(
                directory,
                json.dumps(sample_probe_result(), ensure_ascii=False),
                0,
            )
            csv_output = directory / "assets.csv"
            markdown_output = directory / "assets.md"

            batch_id, asset_count = self.discovery.run_discovery(
                target="ubuntu",
                ssh_bin=str(fake_ssh),
                timeout=10,
                csv_output=csv_output,
                markdown_output=markdown_output,
            )

            self.assertGreater(asset_count, 0)
            self.assertIn(batch_id, csv_output.read_text(encoding="utf-8"))
            self.assertIn(batch_id, markdown_output.read_text(encoding="utf-8"))

    def test_ssh失败和非法json不覆盖既有产物(self):
        for output, exit_code in (("连接失败", 255), ("not-json", 0)):
            with self.subTest(output=output, exit_code=exit_code):
                with tempfile.TemporaryDirectory() as raw_directory:
                    directory = Path(raw_directory)
                    fake_ssh = self._write_fake_ssh(directory, output, exit_code)
                    csv_output = directory / "assets.csv"
                    markdown_output = directory / "assets.md"
                    csv_output.write_text("旧CSV", encoding="utf-8")
                    markdown_output.write_text("旧Markdown", encoding="utf-8")

                    with self.assertRaises(self.discovery.DiscoveryError):
                        self.discovery.run_discovery(
                            target="ubuntu",
                            ssh_bin=str(fake_ssh),
                            timeout=10,
                            csv_output=csv_output,
                            markdown_output=markdown_output,
                        )

                    self.assertEqual("旧CSV", csv_output.read_text(encoding="utf-8"))
                    self.assertEqual(
                        "旧Markdown",
                        markdown_output.read_text(encoding="utf-8"),
                    )


if __name__ == "__main__":
    unittest.main()
