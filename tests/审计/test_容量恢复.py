import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


根 = Path(__file__).resolve().parents[2]
模块路径 = 根 / "scripts/审计/执行容量恢复演练.py"
规格 = importlib.util.spec_from_file_location("执行容量恢复演练", 模块路径)
模块 = importlib.util.module_from_spec(规格)
assert 规格.loader is not None
规格.loader.exec_module(模块)


class 容量恢复合同测试(unittest.TestCase):
    def setUp(self):
        self.试点 = 根 / "artifacts/数据/最小闭环试点/pilot-20260805T045300+0800-zero-v2"
        self.配置 = 根 / "config/审计/双标的容量恢复.json"

    def test_零成员试点与双标配置可计算(self):
        输入, 文件 = 模块.校验试点(self.试点)
        self.assertEqual(输入["报告"]["统计"]["合格成员数"], 0)
        self.assertEqual(len(文件), 5)
        配置 = 模块.读取json(self.配置)
        行 = 模块.计算容量(配置)
        self.assertEqual({项["标的"] for 项 in 行}, {"BTC", "ETH"})
        self.assertEqual({项["期限月数"] for 项 in 行}, {3, 6, 12})
        self.assertTrue(all("规划假设" in 项["状态"] for 项 in 行))

    def test_隔离演练生成恢复指纹(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-capacity-test-") as 临时:
            输出 = 模块.执行(self.试点, self.配置, Path(临时), 最小可用字节数=1, 测试模式=True)
            报告 = json.loads((输出 / "验证报告.json").read_text(encoding="utf-8"))
            self.assertEqual(报告["隔离元数据恢复"], "通过")
            self.assertFalse(报告["恢复指纹全部匹配"] is False)
            self.assertEqual(报告["市场记录恢复"], "无法判定（零成员）")

    def test_低磁盘安全门(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-capacity-test-") as 临时:
            with self.assertRaises(模块.合同错误):
                模块.执行(self.试点, self.配置, Path(临时), 最小可用字节数=10**30, 测试模式=True)

    def test_输入路径越界被拒绝(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-capacity-test-") as 临时:
            with self.assertRaises(模块.合同错误):
                模块.执行(Path(临时), self.配置, Path(临时), 测试模式=True)

    def test_中断安全门(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-capacity-test-") as 临时:
            with self.assertRaises(模块.合同错误):
                模块.检查资源(Path(临时), 1, 截止时间=0)

    def test_生产资源上限不可被调用方降低(self):
        with self.assertRaises(模块.合同错误):
            模块.执行(self.试点, self.配置, 根 / "artifacts/审计/容量恢复", 最小可用字节数=1)

    def test_输出超限清理失败产物(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-capacity-test-") as 临时:
            原上限 = 模块.最大输出字节数
            模块.最大输出字节数 = 1
            try:
                with self.assertRaises(模块.合同错误):
                    模块.执行(self.试点, self.配置, Path(临时), 最小可用字节数=1, 测试模式=True)
                self.assertEqual(list(Path(临时).iterdir()), [])
            finally:
                模块.最大输出字节数 = 原上限


if __name__ == "__main__":
    unittest.main()
