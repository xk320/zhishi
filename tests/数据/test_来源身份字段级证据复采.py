import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.数据 import 复采来源身份字段级证据 as module


class 来源身份字段级证据测试(unittest.TestCase):
    def test_配置冻结并绑定任务(self):
        config = module.load_config()
        self.assertEqual(config["任务编号"], "任务-000076")
        self.assertEqual(config["字段白名单"], list(module.FIELD_NAMES))
        self.assertEqual(config["标的"], ["BTC", "ETH"])

    def test_探针脚本固定只读范围(self):
        script = module.build_probe_script(
            [{"资产编号": "DS-000001", "资产类型": "候选数据文件", "位置": "/opt/binance-event/data/a.csv", "字节数": "1", "最后修改时间": "2026-01-01T00:00:00+08:00"}],
            ["/opt/binance-event"],
            {"逐成员超时秒": 5},
        )
        self.assertIn("information_schema.TABLE_PRIVILEGES", script)
        self.assertIn("数据库业务记录读取", script)
        self.assertNotIn("SELECT *", script)
        self.assertNotIn("price", script.lower())

    def test_探针响应越界被拒绝(self):
        payload = {
            "探针版本": module.PROBE_VERSION,
            "远端写入": False,
            "数据库业务记录读取": True,
            "读取价格成交订单簿": False,
            "数据库元数据范围": list(module.load_config()["数据库元数据范围"]),
            "结果": [],
        }
        def runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with self.assertRaises(ValueError):
            module._ssh_probe(["ssh"], "", 10, 10000, 10000, runner)

    def test_状态构建保留拒绝并拒绝伪造通过(self):
        members = [
            {"来源身份批次": "old", "成员编号": "m1", "资产编号": "DS-000001", "资产类型": "候选数据文件", "标的": "BTC", "来源提供者": "未知", "交易场所": "未知", "市场类型": "未知", "标的身份": "未知", "精确合约": "未知", "数据对象": "未知", "Schema确切版本": "未知", "授权边界": "未知", "字段中文映射": "未知", "状态": "拒绝", "证据": "历史拒绝", "限制": "只读", "解除条件": "重新证明", "输入成员SHA-256": "a" * 64, "远端元数据SHA-256": "未知", "身份记录SHA-256": "x"},
            {"来源身份批次": "old", "成员编号": "m2", "资产编号": "DS-000001", "资产类型": "候选数据文件", "标的": "ETH", "来源提供者": "未知", "交易场所": "未知", "市场类型": "未知", "标的身份": "未知", "精确合约": "未知", "数据对象": "未知", "Schema确切版本": "未知", "授权边界": "未知", "字段中文映射": "未知", "状态": "无法判定", "证据": "未知", "限制": "只读", "解除条件": "重新证明", "输入成员SHA-256": "b" * 64, "远端元数据SHA-256": "未知", "身份记录SHA-256": "x"},
        ]
        probe = {"结果": [{"资产编号": "DS-000001", "复核状态": "已观察", "元数据SHA-256": "c" * 64, "授权快照SHA-256": "未知", "字段级证据SHA-256": "未知", "证据": "stat", "限制": "未读取正文"}]}
        rows, summary = module._build_rows(members, probe, "batch")
        self.assertEqual([row["状态"] for row in rows], ["拒绝", "无法判定"])
        self.assertEqual(summary["已证明"], 0)
        self.assertEqual(summary["拒绝"], 1)
        self.assertEqual(summary["无法判定"], 1)

    def test_CSV字段顺序确定(self):
        row = {column: "" for column in module.OUTPUT_COLUMNS}
        row.update({"来源身份批次": "batch", "成员编号": "m", "资产编号": "DS-000001", "标的": "BTC"})
        text = module._render_csv([row], "batch")
        self.assertEqual(text.splitlines()[0].split(","), list(module.OUTPUT_COLUMNS))
        self.assertIn("batch", text)


if __name__ == "__main__":
    unittest.main()
