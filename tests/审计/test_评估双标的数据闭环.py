import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


根目录 = Path(__file__).resolve().parents[2]
脚本 = 根目录 / "scripts/审计/评估双标的数据闭环.py"
配置 = 根目录 / "config/审计/双标的数据闭环.json"


class 双标数据闭环测试(unittest.TestCase):
    def 运行(self, 临时目录: Path, 配置路径: Path = 配置, 批次: str = "loop-test"):
        return subprocess.run(
            [
                sys.executable,
                str(脚本),
                "--repo-root",
                str(根目录),
                "--config",
                str(配置路径),
                "--batch-root",
                str(临时目录 / "批次"),
                "--report",
                str(临时目录 / "报告.md"),
                "--batch-id",
                批次,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_BTC与ETH独立成员和状态守恒(self):
        with tempfile.TemporaryDirectory() as 目录:
            结果 = self.运行(Path(目录))
            self.assertEqual(结果.returncode, 0, 结果.stdout)
            摘要 = json.loads(结果.stdout)
            self.assertEqual(摘要["候选总体"], 315)
            self.assertEqual(摘要["每标的逐尺度叶子数"], 1260)
            self.assertEqual(摘要["总成员数"], 2520)
            self.assertEqual(摘要["最终状态计数"]["BTC"]["不可用"], 28)
            self.assertEqual(摘要["最终状态计数"]["ETH"]["不可用"], 28)
            成员路径 = Path(目录) / "批次" / "loop-test" / "闭环成员.csv"
            with 成员路径.open(encoding="utf-8", newline="") as 文件:
                行 = list(csv.DictReader(文件))
            self.assertEqual([行[0]["标的"], 行[1259]["标的"], 行[1260]["标的"]], ["BTC", "BTC", "ETH"])
            self.assertEqual(sum(记录["标的"] == "BTC" for 记录 in 行), 1260)
            self.assertEqual(sum(记录["标的"] == "ETH" for 记录 in 行), 1260)
            self.assertEqual({记录["主研究尺度"] for 记录 in 行}, {"4小时", "8小时", "24小时", "48小时"})
            self.assertEqual({记录["交易场所"] for 记录 in 行}, {"未知"})
            self.assertEqual({记录["市场类型"] for 记录 in 行}, {"未知"})
            self.assertEqual({记录["精确合约"] for 记录 in 行}, {"未知"})
            self.assertEqual({记录["数据对象"] for 记录 in 行}, {"未知"})
            self.assertTrue(all(记录["门6血缘"] == "通过" for 记录 in 行))
            self.assertTrue(all(记录["最终状态"] in {"可用", "有限可用", "不可用", "无法判定"} for 记录 in 行))

    def test_输入指纹漂移时失败且不发布批次(self):
        with tempfile.TemporaryDirectory() as 目录:
            临时目录 = Path(目录)
            临时配置 = 临时目录 / "配置.json"
            内容 = json.loads(配置.read_text(encoding="utf-8"))
            内容["输入"]["来源身份"]["SHA-256"] = "0" * 64
            临时配置.write_text(json.dumps(内容, ensure_ascii=False), encoding="utf-8")
            结果 = self.运行(临时目录, 临时配置, "loop-drift")
            self.assertEqual(结果.returncode, 2)
            self.assertFalse((临时目录 / "批次" / "loop-drift").exists())
            self.assertIn("输入指纹不一致", 结果.stdout)

    def test_同一批次禁止覆盖(self):
        with tempfile.TemporaryDirectory() as 目录:
            临时目录 = Path(目录)
            第一次 = self.运行(临时目录, 批次="loop-immutable")
            self.assertEqual(第一次.returncode, 0, 第一次.stdout)
            第二次 = self.运行(临时目录, 批次="loop-immutable")
            self.assertEqual(第二次.returncode, 2)
            self.assertIn("报告路径已存在", 第二次.stdout)

    def test_血缘索引覆盖七份输入和全部成员(self):
        with tempfile.TemporaryDirectory() as 目录:
            临时目录 = Path(目录)
            结果 = self.运行(临时目录, 批次="loop-lineage")
            self.assertEqual(结果.returncode, 0, 结果.stdout)
            路径 = 临时目录 / "批次" / "loop-lineage" / "血缘索引.csv"
            with 路径.open(encoding="utf-8", newline="") as 文件:
                行 = list(csv.DictReader(文件))
            self.assertEqual(len(行), 2520 * 7)
            self.assertEqual({记录["输入名称"] for 记录 in 行}, {"来源身份", "时间质量", "质量结果", "断档结果", "异常结果", "重放结果", "成本结果"})
            self.assertEqual({记录["标的"] for 记录 in 行}, {"BTC", "ETH"})


if __name__ == "__main__":
    unittest.main()
