import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.数据 import 复采来源身份声明 as module


class 来源身份声明测试(unittest.TestCase):
    def test_配置固定研究边界且当前声明为空(self):
        config = module.load_config()
        self.assertEqual(config["任务编号"], "任务-000079")
        self.assertEqual(config["身份字段"], list(module.FIELDS))
        self.assertEqual(config["身份声明"], [])
        self.assertEqual(config["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(config["事后结果观察窗口"], ["15分钟", "1小时"])

    def test_探针脚本只做白名单stat且不读取正文(self):
        script = module.build_probe_script(
            [{"资产编号": "DS-000001", "资产类型": "候选数据文件", "位置": "/opt/binance-event/data/a.csv", "字节数": "1", "最后修改时间": "2026-01-01T00:00:00+08:00"}],
            ["/opt/binance-event"],
        )
        self.assertIn("os.lstat", script)
        self.assertIn("数据库业务记录读取", script)
        self.assertNotIn("open(asset", script)
        self.assertNotIn("SELECT *", script)
        self.assertNotIn("price", script.lower())

    def test_探针越过安全边界被拒绝(self):
        payload = {
            "探针版本": module.PROBE_VERSION,
            "远端写入": False,
            "远端临时文件": False,
            "数据库业务记录读取": True,
            "读取环境变量或凭据": False,
            "读取价格成交订单簿": False,
            "结果": [],
        }
        def runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with self.assertRaises(ValueError):
            module.run_probe("", module.load_config(), runner)

    def test_声明缺失时只能无法判定并保留历史拒绝(self):
        members = [
            {"成员编号": "m1", "资产编号": "DS-000001", "资产类型": "候选数据文件", "标的": "BTC", "状态": "拒绝", "输入成员SHA-256": "a" * 64},
            {"成员编号": "m2", "资产编号": "DS-000002", "资产类型": "候选数据文件", "标的": "ETH", "状态": "无法判定", "输入成员SHA-256": "b" * 64},
        ]
        inventory = [
            {"资产编号": "DS-000001", "资产类型": "候选数据文件"},
            {"资产编号": "DS-000002", "资产类型": "候选数据文件"},
        ]
        probe = {"结果": [
            {"资产编号": "DS-000001", "状态": "无法判定", "原因代码": "IDENTITY_DECLARATION_MISSING", "元数据SHA-256": "未知"},
            {"资产编号": "DS-000002", "状态": "无法判定", "原因代码": "IDENTITY_DECLARATION_MISSING", "元数据SHA-256": "未知"},
        ]}
        config = {"身份声明": [], "主研究尺度": ["4小时", "8小时", "24小时", "48小时"], "事后结果观察窗口": ["15分钟", "1小时"]}
        rows, summary = module.build_rows(members, inventory, probe, config, "batch", config_hash="c" * 64, rules_hash="d" * 64, executor_hash="e" * 64)
        self.assertEqual([row["状态"] for row in rows], ["拒绝", "无法判定"])
        self.assertEqual(summary["已证明"], 0)
        self.assertEqual(summary["拒绝"], 1)
        self.assertEqual(summary["无法判定"], 1)
        self.assertTrue(all(row["来源提供者"] == "未知" for row in rows))

    def test_输出字段顺序固定(self):
        row = {column: "" for column in module.OUTPUT_COLUMNS}
        text = module._render([row])
        self.assertEqual(text.splitlines()[0].split(","), list(module.OUTPUT_COLUMNS))


if __name__ == "__main__":
    unittest.main()
