import csv
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/审计/执行阶段1最终审计重算.py"
SPEC = importlib.util.spec_from_file_location("stage1_final_audit_recompute", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Stage1FinalAuditRecomputeTests(unittest.TestCase):
    def setUp(self):
        self.batch = ROOT / "artifacts/审计/阶段1最终审计/final-recompute-20260808T042000Z-v3"

    def test_新证据提交与状态计数可复算(self):
        evidence = MODULE.verify_new_upstream()
        self.assertEqual(evidence["任务-000075至任务-000077"]["任务-000075"]["状态计数"]["拒绝"], 12)
        self.assertEqual(evidence["任务-000075至任务-000077"]["任务-000076"]["状态计数"]["无法判定"], 618)
        self.assertEqual(evidence["任务-000075至任务-000077"]["任务-000077"]["状态计数"]["无法判定"], 184)
        self.assertEqual(len(evidence["身份状态"]), 630)
        self.assertEqual(len(evidence["元数据最终身份状态"]), 184)
        self.assertEqual(len(evidence["元数据观察状态"]), 184)

    def test_八个叶子与尺度边界及状态守恒(self):
        with (self.batch / "叶子裁决.csv").open(encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 8)
        self.assertEqual({(row["标的"], row["主研究尺度"]) for row in rows}, {(a, s) for a in MODULE.ASSETS for s in MODULE.SCALES})
        self.assertEqual(sum(int(row["候选总体"]) for row in rows), 2520)
        self.assertEqual(sum(int(row["拒绝"]) for row in rows), 56)
        self.assertEqual(sum(int(row["无法判定"]) for row in rows), 2464)
        self.assertTrue(all(row["最终裁决"] == "阻塞" for row in rows))
        self.assertTrue(all("15分钟" not in row["主研究尺度"] and "1小时" not in row["主研究尺度"] for row in rows))

    def test_清单保留最新上游分母和安全边界(self):
        manifest = json.loads((self.batch / "验证清单.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["任务编号"], "任务-000078")
        self.assertEqual(manifest["最终叶子数"], 8)
        self.assertEqual(len(manifest["任务链"]), 49)
        self.assertRegex(manifest["最新main提交SHA"], r"^[0-9a-f]{40}$")
        self.assertEqual(manifest["阶段1结论"], "阻塞")
        self.assertEqual(manifest["阶段2结论"], "阻塞")
        self.assertEqual(manifest["输入范围"]["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(manifest["输入范围"]["事后结果观察窗口"], ["15分钟", "1小时"])
        self.assertFalse(manifest["安全边界"]["访问服务器"])
        self.assertFalse(manifest["安全边界"]["访问数据库业务正文"])
        self.assertFalse(manifest["安全边界"]["读取真实市场数据"])
        self.assertEqual(manifest["资源事实"], {"测试进程数": 1, "Node堆上限MiB": 256, "额外工作树": 0, "远端访问": False, "数据库业务正文读取": False})

    def test_历史最终审计批次未被覆盖(self):
        self.assertTrue((ROOT / MODULE.LEGACY_FINAL_MANIFEST).is_file())
        self.assertTrue((self.batch / "任务-000078执行合同快照.md").is_file())
        self.assertTrue((self.batch / "缺口清单.csv").is_file())


if __name__ == "__main__":
    unittest.main()
