from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATHS = {
    "discovery": ROOT / "scripts/审计/发现数据资产.py",
    "quality": ROOT / "scripts/审计/审计数据质量.py",
    "continuous": ROOT / "scripts/审计/持续验证数据质量.py",
    "replay": ROOT / "scripts/审计/验证历史现场重放.py",
}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ForwardAuditScopeTests(unittest.TestCase):
    def test_当前入口统一为BTC和ETH(self):
        for name, path in SCRIPT_PATHS.items():
            with self.subTest(script=name):
                module = load(path, f"forward_scope_{name}")
                self.assertEqual(("BTC", "ETH"), tuple(module.CURRENT_TARGETS))

    def test_当前配置统一为BTC和ETH(self):
        for relative in (
            "config/审计/数据质量持续验证.json",
            "config/审计/最小数据闭环容量.json",
        ):
            with self.subTest(config=relative):
                data = json.loads((ROOT / relative).read_text(encoding="utf-8"))
                self.assertEqual(["BTC", "ETH"], data["作用域"]["标的"] if "作用域" in data else data["标的"])

    def test_当前入口不把SOL生成前向报告(self):
        quality = load(SCRIPT_PATHS["quality"], "forward_scope_quality_report")
        replay = load(SCRIPT_PATHS["replay"], "forward_scope_replay_report")
        metadata = {
            "audit_batch": "audit-forward-scope",
            "inventory_fingerprint": "a" * 64,
            "rules_fingerprint": "b" * 64,
            "cutoff_time": "2026-08-04T00:00:00+08:00",
            "unit_count": 1,
        }
        quality_report = quality.render_report([], [], [], metadata)
        replay_report = replay.render_report(
            [{"资产编号": "DS-000001", "候选标的范围": "SOL", "重放结论": "拒绝"}],
            {"验证批次": "replay-forward-scope", "清单指纹": "a" * 64,
             "质量审计批次": "audit-forward-scope", "远端预检": "通过"},
        )
        self.assertNotIn("| SOL |", quality_report)
        self.assertNotIn("| SOL |", replay_report)


if __name__ == "__main__":
    unittest.main()
