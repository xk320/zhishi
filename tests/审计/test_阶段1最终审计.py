import csv
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/审计/执行阶段1最终审计.py"
SPEC = importlib.util.spec_from_file_location("stage1_final_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Stage1FinalAuditTests(unittest.TestCase):
    def setUp(self):
        self.batch = ROOT / "artifacts/审计/阶段1最终审计/final-20260805T061500Z-v1"

    def test_上游完成态和合并提交指纹一致(self):
        evidence = MODULE.verify_upstream()
        self.assertEqual(evidence["合并提交"], MODULE.MERGE_COMMITS)
        self.assertEqual(len(evidence["批次"]), 8)
        self.assertTrue(all(item["文件SHA-256"] for item in evidence["批次"].values()))

    def test_最终叶子覆盖双标的四尺度且不含短窗口主尺度(self):
        rows = MODULE.read_loop_rows(ROOT / MODULE.LOOP_CSV)
        leaves, aggregate = MODULE.build_leaves(rows)
        self.assertEqual(len(leaves), 8)
        self.assertEqual({(row["标的"], row["主研究尺度"]) for row in leaves}, {(a, s) for a in MODULE.ASSETS for s in MODULE.SCALES})
        self.assertNotIn("15分钟", {row["主研究尺度"] for row in leaves})
        self.assertNotIn("1小时", {row["主研究尺度"] for row in leaves})
        self.assertEqual(aggregate["候选总体"], 2520)
        self.assertEqual(aggregate["拒绝"], 56)
        self.assertEqual(aggregate["无法判定"], 2464)
        self.assertTrue(aggregate["候选总体"] == sum(aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")))

    def test_每个叶子八类硬门和保守裁决完整(self):
        with (self.batch / "叶子裁决.csv").open(encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        gates = ("身份门", "三类时间门", "质量门", "重放门", "成本门", "血缘门", "容量门", "恢复门")
        self.assertEqual(len(rows), 8)
        for row in rows:
            self.assertEqual(row["最终裁决"], "阻塞")
            self.assertEqual(row["交易场所"], "未知")
            self.assertEqual(row["市场类型"], "未知")
            self.assertEqual(row["精确合约"], "未知")
            self.assertEqual(row["数据对象"], "未知")
            self.assertEqual(row["时间范围"], "无法判定")
            self.assertTrue(all(row[gate] in {"通过", "拒绝", "无法判定"} for gate in gates))

    def test_最终批次不可变清单保留安全边界和空允许范围(self):
        manifest = json.loads((self.batch / "验证清单.json").read_text(encoding="utf-8"))
        summary = json.loads((self.batch / "统计摘要.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["任务编号"], "任务-000037")
        self.assertEqual(manifest["阶段2结论"], "阻塞")
        self.assertEqual(manifest["允许研究范围"], [])
        self.assertEqual(manifest["输入范围"]["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(manifest["输入范围"]["事后结果观察窗口"], ["15分钟", "1小时"])
        self.assertTrue(manifest["计数守恒"])
        self.assertTrue(summary["计数守恒"])
        self.assertFalse(manifest["安全边界"]["访问服务器"])
        self.assertFalse(manifest["安全边界"]["读取真实市场数据"])

    def test_历史输入未被最终批次覆盖(self):
        self.assertTrue((self.batch / "叶子裁决.csv").is_file())
        self.assertTrue((self.batch / "缺口清单.csv").is_file())
        self.assertTrue((self.batch / "验证清单.json").is_file())
        self.assertEqual(len(list((ROOT / "artifacts/审计/阶段1最终审计").glob("final-*/"))), 1)


if __name__ == "__main__":
    unittest.main()
