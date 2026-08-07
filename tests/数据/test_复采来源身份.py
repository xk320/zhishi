from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.数据 import 复采来源身份 as module


ROOT = Path(__file__).resolve().parents[2]


class RecaptureSourceIdentityTests(unittest.TestCase):
    def test_contract_and_baseline_are_frozen(self) -> None:
        contract = module.load_contract()
        self.assertEqual(contract["任务编号"], "任务-000072")
        self.assertEqual(contract["合同版本"], "source-identity-recapture-1.0")
        self.assertEqual(contract["身份声明"], [])
        self.assertEqual(len(contract["输入文件"]), 6)

    def test_members_are_deterministic_and_separate_by_asset(self) -> None:
        contract = module.load_contract()
        inventory = next(item for item in contract["输入文件"] if item["用途"] == "资产清单")
        inventory_bytes = (ROOT / inventory["路径"]).read_bytes()
        first = module.engine.build_members_from_inventory_bytes(inventory_bytes, contract)
        second = module.engine.build_members_from_inventory_bytes(inventory_bytes, contract)
        self.assertEqual(first, second)
        self.assertEqual(len(first) % 2, 0)
        self.assertEqual({row["标的"] for row in first}, {"BTC", "ETH"})
        self.assertEqual(len({row["成员编号"] for row in first}), len(first))

    def test_real_batch_path_uses_fake_only_probe_and_is_immutable(self) -> None:
        contract = module.load_contract()
        inventory = next(item for item in contract["输入文件"] if item["用途"] == "资产清单")
        assets = module.engine.build_probe_assets_from_inventory_bytes(
            (ROOT / inventory["路径"]).read_bytes(), contract
        )
        payload = {
            "探针版本": module.PROBE_VERSION,
            "远端写入": False,
            "数据库业务记录读取": False,
            "结果": [
                {
                    "资产编号": asset["资产编号"],
                    "复核状态": "无法判定",
                    "元数据SHA-256": "",
                    "SchemaSHA-256": "",
                    "证据": "测试探针未提供来源身份元数据",
                    "限制": "测试不访问远端",
                }
                for asset in assets
            ],
        }

        def fake_runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload, ensure_ascii=False), stderr="")

        with tempfile.TemporaryDirectory() as directory:
            target = module.execute_batch(
                module.DEFAULT_CONTRACT,
                "ubuntu",
                Path(directory),
                60,
                runner=fake_runner,
            )
            self.assertTrue(target.is_dir())
            self.assertTrue((target / "来源身份清单.csv").is_file())
            self.assertTrue((target / "身份清单.json").is_file())
            manifest = json.loads((target / "身份清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["任务编号"], "任务-000072")
            self.assertTrue(manifest["来源身份批次"].startswith("source-identity-recapture-"))
            self.assertEqual(manifest["结果摘要"]["三态计数"]["无法判定"], len(assets) * 2)

    def test_non_whitelisted_target_is_rejected_before_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                module.execute_batch(module.DEFAULT_CONTRACT, "192.168.31.201", Path(directory), 60)


if __name__ == "__main__":
    unittest.main()
