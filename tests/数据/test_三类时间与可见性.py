from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.数据 import 复采三类时间 as module


ROOT = Path(__file__).resolve().parents[2]


class TimeVisibilityRecaptureTests(unittest.TestCase):
    def test_contract_freezes_scope_and_safety(self) -> None:
        contract = module.load_contract()
        self.assertEqual(contract["任务编号"], "任务-000073")
        self.assertEqual(contract["合同版本"], "time-visibility-recapture-1.0")
        self.assertEqual(contract["标的"], ["BTC", "ETH"])
        self.assertEqual(contract["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(contract["事后结果观察窗口"], ["15分钟", "1小时"])
        self.assertTrue(all(value is False for value in contract["安全边界"].values()))

    def test_identity_members_are_complete_and_rows_are_deterministic(self) -> None:
        contract = module.load_contract()
        identity = module._load_identity(contract, ROOT)
        self.assertEqual(len(identity["成员顺序"]), 630)
        self.assertEqual({row["标的"] for row in identity["成员顺序"]}, {"BTC", "ETH"})
        rows_a = [module._build_row(member, "pending", identity["来源身份批次"]) for member in identity["成员顺序"]]
        rows_b = [module._build_row(member, "pending", identity["来源身份批次"]) for member in identity["成员顺序"]]
        self.assertEqual(rows_a, rows_b)
        self.assertEqual(len(rows_a), 630)
        self.assertTrue(all(row["主研究尺度"] == list(module.SCALES) for row in rows_a))
        self.assertEqual({row["结果观察窗口"][0] for row in rows_a}, {"15分钟"})
        self.assertEqual({row["结果观察窗口"][1] for row in rows_a}, {"1小时"})
        self.assertTrue(all(row["三类时间"]["事件时间"]["状态"] in {"失败", "无法判定"} for row in rows_a))

    def test_counts_keep_btc_eth_and_all_failure_safe_states(self) -> None:
        contract = module.load_contract()
        identity = module._load_identity(contract, ROOT)
        rows = [module._build_row(member, "pending", identity["来源身份批次"]) for member in identity["成员顺序"]]
        summary = module._counts(rows)
        self.assertEqual(summary["候选总体"], 630)
        self.assertEqual(summary["分母"], 630)
        self.assertEqual(summary["已观察"], 630)
        self.assertEqual(summary["拒绝"], 12)
        self.assertEqual(summary["失败"], 12)
        self.assertEqual(summary["无法判定"], 618)
        self.assertEqual(summary["未成熟"], 0)
        self.assertEqual(summary["失效"], 0)
        self.assertEqual(module._counts(rows, target="BTC"), module._counts(rows, target="ETH"))

    def test_fake_probe_publishes_immutable_batch_without_business_rows(self) -> None:
        def fake_probe(_target: str, _timeout: int, _ssh_bin: str) -> dict[str, object]:
            return {
                "探针版本": module.PROBE_VERSION,
                "状态": "可执行",
                "读取业务正文": False,
                "读取数据库业务记录": False,
                "远端写入": False,
            }

        contract = module.load_contract()
        full_identity = module._load_identity(contract, ROOT)
        small_identity = dict(full_identity)
        small_identity["成员顺序"] = full_identity["成员顺序"][:2]
        original_loader = module._load_identity
        module._load_identity = lambda _contract, _repo_root: small_identity  # type: ignore[assignment]
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = module.execute_batch(
                    module.DEFAULT_CONTRACT,
                    batch_root=Path(directory),
                    probe_runner=fake_probe,
                )
                manifest = json.loads((target / "三类时间与可见性清单.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["任务编号"], "任务-000073")
                self.assertEqual(manifest["成员总数"], 2)
                self.assertEqual(manifest["分组成员数"], 2)
                self.assertTrue(manifest["安全声明"]["未读取业务正文"])
                self.assertTrue((target / "三类时间与可见性清单.csv").is_file())
                tampered = json.loads(json.dumps(manifest, ensure_ascii=False))
                tampered["按标的状态计数"]["BTC"]["候选总体"] += 1
                (target / "三类时间与可见性清单.json").write_text(
                    json.dumps(tampered, ensure_ascii=False), encoding="utf-8"
                )
                with self.assertRaises(ValueError):
                    module.validate_manifest(target / "三类时间与可见性清单.json")
                with self.assertRaises(FileExistsError):
                    module.execute_batch(
                        module.DEFAULT_CONTRACT,
                        batch_root=Path(directory),
                        probe_runner=fake_probe,
                        now=__import__("datetime").datetime.fromisoformat(manifest["冻结时间"]),
                    )
        finally:
            module._load_identity = original_loader  # type: ignore[assignment]

    def test_short_scale_cannot_become_research_scale(self) -> None:
        self.assertNotIn("15分钟", module.SCALES)
        self.assertNotIn("1小时", module.SCALES)
        self.assertEqual(module.OBSERVATION_WINDOWS, ("15分钟", "1小时"))

    def test_probe_rejects_output_over_bound(self) -> None:
        def oversized_runner(_command: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "x" * 4097, "")

        with self.assertRaises(RuntimeError):
            module._probe("ubuntu", 10, runner=oversized_runner)


if __name__ == "__main__":
    unittest.main()
