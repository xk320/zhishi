from __future__ import annotations

import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


脚本路径 = Path(__file__).parents[2] / "scripts/数据/构建最小闭环试点.py"
查询路径 = Path(__file__).parents[2] / "scripts/数据/查询最小闭环试点.py"
构建规范 = importlib.util.spec_from_file_location("pilot_builder", 脚本路径)
assert 构建规范 and 构建规范.loader
构建 = importlib.util.module_from_spec(构建规范)
sys.modules[构建规范.name] = 构建
构建规范.loader.exec_module(构建)
查询规范 = importlib.util.spec_from_file_location("pilot_query", 查询路径)
assert 查询规范 and 查询规范.loader
查询模块 = importlib.util.module_from_spec(查询规范)
sys.modules[查询规范.name] = 查询模块
查询规范.loader.exec_module(查询模块)


class 最小闭环试点测试(unittest.TestCase):
    def 写入输入(self, 根: Path, *, 最终状态: str = "不可用") -> tuple[Path, Path]:
        来源 = 根 / "artifacts/审计/双标的数据闭环/loop-v4/闭环成员.csv"
        来源.parent.mkdir(parents=True)
        列 = sorted(构建.必需列)
        行 = {
            列名: ""
            for 列名 in 列
        }
        行.update(
            {
                "批次": "loop-v4",
                "资产编号": "DS-000001",
                "标的": "BTC",
                "交易场所": "demo-venue",
                "市场类型": "spot",
                "精确合约": "BTC-USD",
                "数据对象": "bars",
                "主研究尺度": "4小时",
                "尺度证据状态": "通过",
                "事后结果观察窗口": '["15分钟","1小时"]',
                "时间范围": "2024-01-01/2024-02-01",
                "最终状态": 最终状态,
                "门1来源身份": "通过",
                "门2时间与质量合同": "通过",
                "门3质量审计": "通过",
                "门4历史重放": "通过",
                "门5成本与执行": "通过",
                "门6血缘": "通过",
                "成员指纹": "a" * 64,
                "来源成员编号": "ZI-1",
            }
        )
        with 来源.open("w", encoding="utf-8", newline="") as 文件:
            写入器 = csv.DictWriter(文件, fieldnames=列, lineterminator="\n")
            写入器.writeheader()
            写入器.writerow(行)
        配置路径 = 根 / "config/数据/最小闭环试点.json"
        配置路径.parent.mkdir(parents=True)
        配置 = {
            "配置版本": "test",
            "来源批次": "loop-v4",
            "来源成员路径": "artifacts/审计/双标的数据闭环/loop-v4/闭环成员.csv",
            "来源成员SHA256": 构建.文件指纹(来源),
            "最大成员数": 1,
            "最大评估行数": 10,
            "最大输出字节数": 1024 * 1024,
            "限制": "test",
        }
        配置路径.write_text(json.dumps(配置, ensure_ascii=False), encoding="utf-8")
        return 配置路径, 来源

    def test_零成员拒绝保留逐行证据并可查询空集(self) -> None:
        with tempfile.TemporaryDirectory() as 临时:
            根 = Path(临时)
            配置, _ = self.写入输入(根)
            报告 = 构建.构建批次(配置, 根 / "artifacts/数据/最小闭环试点", "pilot-zero")
            self.assertEqual(报告["状态"], "零成员拒绝")
            批次 = 根 / "artifacts/数据/最小闭环试点/pilot-zero"
            with (批次 / "成员.csv").open(encoding="utf-8-sig", newline="") as 文件:
                self.assertEqual(list(csv.DictReader(文件)), [])
            with (批次 / "候选评估.csv").open(encoding="utf-8-sig", newline="") as 文件:
                评估 = list(csv.DictReader(文件))
            self.assertEqual(len(评估), 1)
            self.assertEqual(评估[0]["是否合格"], "否")
            self.assertIn("最终状态=不可用不允许", 评估[0]["拒绝原因"])
            查询结果 = 查询模块.查询(批次, 标的="BTC", 主尺度="4小时")
            self.assertEqual(查询结果["状态"], "空集")
            self.assertEqual(查询结果["成员数"], 0)

    def test_满足全部门时只选择首个成员(self) -> None:
        with tempfile.TemporaryDirectory() as 临时:
            根 = Path(临时)
            配置, 来源 = self.写入输入(根, 最终状态="可用")
            报告 = 构建.构建批次(配置, 根 / "artifacts/数据/最小闭环试点", "pilot-one")
            self.assertEqual(报告["统计"]["合格成员数"], 1)
            with (根 / "artifacts/数据/最小闭环试点/pilot-one/成员.csv").open(encoding="utf-8-sig", newline="") as 文件:
                成员 = list(csv.DictReader(文件))
            self.assertEqual(len(成员), 1)
            self.assertEqual(成员[0]["主研究尺度"], "4小时")
            self.assertEqual(成员[0]["来源批次"], "loop-v4")
            self.assertEqual(构建.文件指纹(来源), json.loads(配置.read_text(encoding="utf-8"))["来源成员SHA256"])

    def test_批次拒绝覆盖且来源漂移失败(self) -> None:
        with tempfile.TemporaryDirectory() as 临时:
            根 = Path(临时)
            配置, 来源 = self.写入输入(根)
            输出根 = 根 / "artifacts/数据/最小闭环试点"
            构建.构建批次(配置, 输出根, "pilot-zero")
            with self.assertRaises(构建.合同错误):
                构建.构建批次(配置, 输出根, "pilot-zero")
            来源.write_text(来源.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaises(构建.合同错误):
                构建.构建批次(配置, 输出根, "pilot-drift")

    def test_查询拒绝越界尺度(self) -> None:
        with tempfile.TemporaryDirectory() as 临时:
            根 = Path(临时)
            配置, _ = self.写入输入(根)
            构建.构建批次(配置, 根 / "artifacts/数据/最小闭环试点", "pilot-zero")
            with self.assertRaises(ValueError):
                查询模块.查询(根 / "artifacts/数据/最小闭环试点/pilot-zero", 主尺度="1小时")


if __name__ == "__main__":
    unittest.main()
