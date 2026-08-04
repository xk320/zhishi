from __future__ import annotations

import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "审计" / "可信历史现场重放.py"


def load_module():
    spec = importlib.util.spec_from_file_location("trusted_replay", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TrustedReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.config = json.loads((ROOT / "config/审计/可信重放来源.json").read_text(encoding="utf-8"))

    def test_输入合同与成员覆盖固定(self):
        source, quality, members = self.mod.load_inputs(ROOT, self.config)
        self.assertEqual(len(members), 630)
        self.assertEqual(len(quality), 315)
        self.assertEqual({m["标的"] for m in members}, {"BTC", "ETH"})
        self.assertEqual(source["合同版本"], "source-identity-1.0")

    def test_结果确定性且不产生通过(self):
        source, quality, members = self.mod.load_inputs(ROOT, self.config)
        first = self.mod.build_rows("replay-20260805T012500+0800-000000000000", source, quality, members, "a" * 64)
        second = self.mod.build_rows("replay-20260805T012500+0800-000000000000", source, quality, members, "a" * 64)
        self.assertEqual(first, second)
        self.assertEqual({row["重放结论"] for row in first}, {"拒绝", "无法判定"})
        self.assertNotIn("通过", {row["重放结论"] for row in first})
        self.assertEqual(len({row["来源成员编号"] for row in first}), 630)

    def test_禁止调用方伪造来源(self):
        source, quality, members = self.mod.load_inputs(ROOT, self.config)
        rows = self.mod.build_rows("replay-20260805T012500+0800-000000000000", source, quality, members, "a" * 64)
        self.assertTrue(all(row["决策记录编号"] == "未登记" for row in rows))
        self.assertTrue(all(row["重放结论"] != "通过" for row in rows))

    def test_到达时间闭区间过滤(self):
        decision = dt.datetime.fromisoformat("2026-08-05T01:00:00+08:00")
        records = [{"id": "at", "到达时间": "2026-08-05T01:00:00+08:00"}, {"id": "future", "到达时间": "2026-08-05T01:00:01+08:00"}]
        visible = self.mod.visible_records(records, decision)
        self.assertEqual([record["id"] for record in visible], ["at"])

    def test_远端预检记录实际日志字节(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": '{"python":"3.10.12","runtime":"trusted-replay-read-only-preflight","status":"ok"}', "stderr": "xy"})()
        with mock.patch.object(self.mod.subprocess, "run", return_value=completed):
            result = self.mod.run_remote_preflight("ubuntu")
        self.assertEqual(result["日志字节数"], 2)

    def test_源清单指纹漂移失败(self):
        broken = json.loads(json.dumps(self.config))
        broken["输入"]["来源身份清单"]["SHA-256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.mod.load_inputs(ROOT, broken)

    def test_批准输入路径和身份不可替换(self):
        broken = json.loads(json.dumps(self.config))
        broken["输入"]["质量验证清单"]["质量结果"] = "artifacts/伪造.csv"
        with self.assertRaises(ValueError):
            self.mod.load_inputs(ROOT, broken)

    def test_批次目录不可覆盖(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "replay-20260805T012500+0800-000000000000"
            destination.mkdir()
            with self.assertRaises(ValueError):
                self.mod.publish_batch(root, destination.name, [], "", {}, {"验证批次": destination.name}, max_output_bytes=1024)


if __name__ == "__main__":
    unittest.main()
