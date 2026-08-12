import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


根 = Path(__file__).resolve().parents[2]
模块路径 = 根 / "scripts/审计/验证阶段1模拟负载容量恢复.py"
规格 = importlib.util.spec_from_file_location("验证阶段1模拟负载容量恢复", 模块路径)
模块 = importlib.util.module_from_spec(规格)
assert 规格.loader is not None
规格.loader.exec_module(模块)


class 阶段1模拟负载容量恢复测试(unittest.TestCase):
    def setUp(self):
        self.配置路径 = 根 / "config/审计/任务-000104容量恢复.json"
        self.配置 = 模块.读取JSON(self.配置路径)
        self.来源 = 根 / self.配置["来源相对目录"]

    def test_正式来源逐文件与语义一致(self):
        事实 = 模块.验证来源批次(self.来源, self.配置)
        self.assertEqual(事实["内容文件数"], 10)
        self.assertEqual(事实["总文件数"], 11)
        self.assertEqual(事实["成员数"], 512)
        self.assertEqual(事实["生命周期事件数"], 6144)
        self.assertEqual(事实["分组数"], 1056)
        self.assertEqual(事实["按标的成员"], {"BTCUSDT": 256, "ETHUSDT": 256})

    def test_串行负载不扩充正式分母(self):
        测量 = 模块.测量负载(self.来源, self.配置, [1, 2])
        self.assertEqual([项["倍数"] for 项 in 测量], [1, 2])
        self.assertEqual({项["正式成员分母"] for 项 in 测量}, {512})
        self.assertEqual(测量[1]["处理成员次数"], 1024)
        self.assertEqual(测量[0]["结果指纹"], 测量[1]["结果指纹"])
        self.assertTrue(all(项["耗时秒"] > 0 for 项 in 测量))
        self.assertTrue(all(项["峰值RSS字节"] > 0 for 项 in 测量))

    def test_单文件漂移被拒绝且源不变(self):
        源SHA = 模块.文件SHA256(self.来源 / "summary.json")
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            副本 = Path(临时) / "副本"
            shutil.copytree(self.来源, 副本)
            with (副本 / "summary.json").open("ab") as 文件:
                文件.write(b"x")
            with self.assertRaisesRegex(模块.合同错误, "FILE_DRIFT"):
                模块.验证来源批次(副本, self.配置, 限制正式路径=False)
        self.assertEqual(模块.文件SHA256(self.来源 / "summary.json"), 源SHA)

    def test_符号链接与路径逃逸被拒绝(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            副本 = Path(临时) / "副本"
            shutil.copytree(self.来源, 副本)
            (副本 / "summary.json").unlink()
            (副本 / "summary.json").symlink_to(self.来源 / "summary.json")
            with self.assertRaisesRegex(模块.合同错误, "NON_REGULAR_FILE"):
                模块.验证来源批次(副本, self.配置, 限制正式路径=False)
        with self.assertRaisesRegex(模块.合同错误, "SOURCE_PATH_INVALID"):
            模块.验证来源批次(Path("/tmp"), self.配置)

    def test_故障检测与隔离恢复逐字节一致(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            结果 = 模块.隔离恢复演练(self.来源, self.配置, Path(临时))
            self.assertTrue(结果["故障已检测"])
            self.assertTrue(结果["恢复逐文件一致"])
            self.assertEqual(结果["恢复总文件数"], 11)
            self.assertEqual(结果["恢复语义"]["成员数"], 512)

    def test_清理失败禁止正式发布(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            输出根 = Path(临时) / "输出"
            输出根.mkdir()
            with mock.patch.object(模块, "安全清理", side_effect=模块.合同错误("CLEANUP_FAILED")):
                with self.assertRaisesRegex(模块.合同错误, "CLEANUP_FAILED"):
                    模块.执行正式批次(
                        根,
                        self.配置路径,
                        输出根,
                        "stage1-simulated-load-recovery-20260812T210000Z-a1b2c3d4e5f6",
                        测试模式=True,
                    )
            self.assertEqual(list(输出根.iterdir()), [])

    def test_配置漂移与不安全倍数被拒绝(self):
        漂移 = json.loads(json.dumps(self.配置))
        漂移["负载倍数"] = [1, 4, 2]
        with self.assertRaisesRegex(模块.合同错误, "CONFIG_INVALID"):
            模块.验证配置(漂移)

    def test_已发布批次可独立回读且漂移失败(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            输出根 = Path(临时) / "输出"
            输出根.mkdir()
            批次 = "stage1-simulated-load-recovery-20260812T210000Z-b1c2d3e4f5a6"
            目标 = 模块.执行正式批次(根, self.配置路径, 输出根, 批次, 测试模式=True)
            结果 = 模块.验证已发布批次(目标, self.配置, repo_root=根, config_path=self.配置路径)
            self.assertEqual(结果["批次"], 批次)
            self.assertEqual(结果["正式成员分母"], 512)
            self.assertTrue(结果["清理早于发布"])
            with (目标 / "measurements.json").open("ab") as 文件:
                文件.write(b"drift")
            with self.assertRaisesRegex(模块.合同错误, "PUBLISHED_FILE_DRIFT"):
                模块.验证已发布批次(目标, self.配置)

    def test_已发布批次绑定当前合同配置与执行器(self):
        with tempfile.TemporaryDirectory(prefix="zhishi-task104-test-") as 临时:
            输出根 = Path(临时) / "输出"
            输出根.mkdir()
            目标 = 模块.执行正式批次(
                根,
                self.配置路径,
                输出根,
                "stage1-simulated-load-recovery-20260812T210000Z-c1d2e3f4a5b6",
                测试模式=True,
            )
            意图路径 = 目标 / "intent.json"
            意图 = json.loads(意图路径.read_text(encoding="utf-8"))
            意图["executor_sha256"] = "0" * 64
            意图路径.write_text(json.dumps(意图, ensure_ascii=False) + "\n", encoding="utf-8")
            模块.重建发布清单仅供测试(目标)
            with self.assertRaisesRegex(模块.合同错误, "DELIVERY_BINDING_DRIFT"):
                模块.验证已发布批次(目标, self.配置, repo_root=根, config_path=self.配置路径)


if __name__ == "__main__":
    unittest.main()
