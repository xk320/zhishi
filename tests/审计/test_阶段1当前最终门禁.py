import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


根 = Path(__file__).resolve().parents[2]
模块路径 = 根 / "scripts/审计/重算阶段1当前最终门禁.py"
模块 = None
if 模块路径.exists():
    规格 = importlib.util.spec_from_file_location("重算阶段1当前最终门禁", 模块路径)
    模块 = importlib.util.module_from_spec(规格)
    assert 规格.loader is not None
    规格.loader.exec_module(模块)


class 阶段1当前最终门禁测试(unittest.TestCase):
    def test_执行器存在(self):
        self.assertTrue(模块路径.exists(), "阶段1当前最终门禁执行器尚未实现")

    @unittest.skipIf(模块 is None, "等待执行器实现")
    def test_五个冻结输入可验证且不读取仓库外路径(self):
        配置 = 模块.读取配置(根 / "config/审计/任务-000105阶段1最终审计.json")
        事实 = 模块.验证正式输入(根, 配置)
        self.assertEqual(set(事实), {"000094", "000099", "000100", "000103", "000104"})
        self.assertEqual({事实[任务]["验证器状态"] for 任务 in 事实}, {"通过"})
        self.assertEqual(事实["000099"]["正式成员数"], 5180)
        self.assertEqual(事实["000103"]["模拟成员数"], 512)
        越界 = json.loads(json.dumps(配置))
        越界["正式输入"]["000104"]["目录"] = "/tmp"
        with self.assertRaisesRegex(模块.合同错误, "INPUT_PATH_INVALID"):
            模块.验证正式输入(根, 越界)

    @unittest.skipIf(模块 is None, "等待执行器实现")
    def test_生成八个叶子与九道门且分母隔离(self):
        配置 = 模块.读取配置(根 / "config/审计/任务-000105阶段1最终审计.json")
        事实 = 模块.验证正式输入(根, 配置)
        结果 = 模块.生成裁决(事实)
        self.assertEqual(len(结果["leaves"]), 8)
        self.assertEqual(
            [(项["underlying"], 项["horizon_hours"]) for 项 in 结果["leaves"]],
            [(标的, 尺度) for 标的 in ("BTC", "ETH") for 尺度 in (4, 8, 24, 48)],
        )
        self.assertEqual({len(项["gates"]) for 项 in 结果["leaves"]}, {9})
        self.assertEqual({项["formal_member_count"] for 项 in 结果["leaves"][:4]}, {2937})
        self.assertEqual({项["formal_member_count"] for 项 in 结果["leaves"][4:]}, {2243})
        self.assertEqual({项["simulated_member_count"] for 项 in 结果["leaves"]}, {256})
        self.assertEqual({tuple(项["post_event_observation_minutes"]) for 项 in 结果["leaves"]}, {(15, 60)})

    @unittest.skipIf(模块 is None, "等待执行器实现")
    def test_未知成本执行使阶段失败关闭并收敛唯一缺口(self):
        配置 = 模块.读取配置(根 / "config/审计/任务-000105阶段1最终审计.json")
        结果 = 模块.生成裁决(模块.验证正式输入(根, 配置))
        self.assertFalse(结果["stage1_complete"])
        self.assertFalse(结果["stage2_released"])
        self.assertEqual(结果["allowed_research_leaf_count"], 0)
        self.assertEqual(len(结果["remaining_gaps"]), 1)
        self.assertEqual(结果["remaining_gaps"][0]["reason_code"], "COST_EXECUTION_COVERAGE_INCOMPLETE")
        self.assertEqual(结果["successor_recommendation"]["count"], 1)
        for 叶子 in 结果["leaves"]:
            self.assertEqual(叶子["gates"]["成本与执行"]["status"], "无法判定")
            self.assertEqual(叶子["gates"]["容量"]["status"], "通过")
            self.assertEqual(叶子["gates"]["恢复"]["status"], "通过")
            self.assertEqual(叶子["decision"], "阻塞")

    @unittest.skipIf(模块 is None, "等待执行器实现")
    def test_正式批次两次重放全等且输入漂移失败(self):
        配置路径 = 根 / "config/审计/任务-000105阶段1最终审计.json"
        with tempfile.TemporaryDirectory(prefix="zhishi-task105-test-") as 临时:
            输出根 = Path(临时) / "输出"
            输出根.mkdir()
            批次 = "stage1-current-final-gate-20260812T220000Z-a1b2c3d4e5f6"
            目标 = 模块.执行正式批次(根, 配置路径, 输出根, 批次, 测试模式=True)
            摘要 = 模块.验证已发布批次(根, 配置路径, 目标)
            self.assertTrue(摘要["replays_equal"])
            self.assertEqual(摘要["leaf_count"], 8)
            self.assertEqual(摘要["remaining_gap_count"], 1)
            with (目标 / "decision.json").open("ab") as 文件:
                文件.write(b"drift")
            with self.assertRaisesRegex(模块.合同错误, "PUBLISHED_FILE_DRIFT"):
                模块.验证已发布批次(根, 配置路径, 目标)


if __name__ == "__main__":
    unittest.main()
