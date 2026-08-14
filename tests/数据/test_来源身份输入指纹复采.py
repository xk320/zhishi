from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.数据 import 复采来源身份 as source_module
from scripts.数据 import 复采来源身份输入指纹 as module


ROOT = Path(__file__).resolve().parents[2]


class SourceIdentityInputDriftTests(unittest.TestCase):
    def test_drift_classifier_is_conservative(self) -> None:
        self.assertEqual(module.classify_drift(b"same", b"same"), "未漂移")
        self.assertEqual(module.classify_drift(b"a\r\nb", b"a\nb"), "仅换行规范化差异")
        self.assertEqual(module.classify_drift(b"new", b"old"), "内容变化")
        self.assertEqual(module.classify_drift(None, b"old"), "输入缺失")

    def test_current_and_historical_inputs_are_reproducible(self) -> None:
        config = module._load_config()
        rows = module._drift_snapshot(config, ROOT)
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(row["漂移分类"] == "内容变化" for row in rows), 3)
        self.assertEqual(sum(row["漂移分类"] == "未漂移" for row in rows), 3)
        self.assertEqual({row["路径"] for row in rows}, {
            "artifacts/审计/数据源清单.csv",
            "config/数据/数据来源与资产身份.json",
            "docs/数据/数据来源与资产身份合同.md",
            "docs/审计/阶段1最终审计报告.md",
            "docs/审计/数据缺口与补采清单.md",
            "docs/研发中心/任务/任务-000071.md",
        })

    def test_fake_probe_batch_is_append_only_and_binds_drift(self) -> None:
        config = source_module.load_contract(repo_root=ROOT)
        inventory = next(item for item in config["输入文件"] if item["用途"] == "资产清单")
        assets = source_module.engine.build_probe_assets_from_inventory_bytes(
            (ROOT / inventory["路径"]).read_bytes(), config
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
            target = module.execute_batch(batch_root=Path(directory), timeout=60, runner=fake_runner)
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["任务编号"], "任务-000075")
            self.assertTrue(manifest["来源身份输入指纹批次"].startswith("source-identity-input-drift-"))
            self.assertEqual(manifest["漂移快照"]["漂移计数"]["内容变化"], 3)
            self.assertEqual(manifest["结果摘要"]["三态计数"]["无法判定"], len(assets) * 2)
            self.assertTrue((target / "来源身份清单.csv").is_file())

    def test_non_whitelisted_target_is_rejected_before_probe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                module.execute_batch(batch_root=Path(directory), ssh_target="not-ubuntu", timeout=60)


if __name__ == "__main__":
    unittest.main()
