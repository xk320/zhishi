from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "数据" / "验证时间与质量合同.py"
CONFIG_PATH = ROOT / "config" / "数据" / "时间与质量规则.json"


def load_module():
    spec = importlib.util.spec_from_file_location("time_quality_contract", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("无法加载时间质量合同校验器")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TimeQualityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_module()
        cls.config = cls.policy.validate_rules(
            cls.policy.load_json(CONFIG_PATH)
        )

    def member(self, member_id: str, asset_id: str, target: str, state: str = "无法判定"):
        return {
            "成员编号": member_id,
            "资产编号": asset_id,
            "资产类型": "候选数据文件",
            "标的": target,
            "状态": state,
            "输入成员SHA-256": member_id.ljust(64, "0")[:64],
        }

    def identity(self, members):
        return {
            "任务编号": "任务-000029",
            "合同版本": "source-identity-1.0",
            "来源身份批次": "source-identity-test",
            "成员顺序": members,
            "成员SHA-256": "a" * 64,
        }

    def manifest(self, members):
        records = [self.policy.build_member_contract(item) for item in members]
        return self.policy.build_manifest(
            self.config,
            self.identity(members),
            sorted(members, key=lambda item: (item["标的"], item["资产编号"], item["成员编号"])),
            config_sha="b" * 64,
            identity_sha="c" * 64,
            task_sha="d" * 64,
            batch_name="time-quality-test-000000+0000-aaaaaaaaaaaa",
        )

    def test_规则冻结主尺度和观察窗口(self):
        self.assertEqual(self.config["标的"], ["BTC", "ETH"])
        self.assertEqual(self.config["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(self.config["事后结果观察窗口"], ["15分钟", "1小时"])

    def test_短窗口不能替代主研究尺度(self):
        broken = copy.deepcopy(self.config)
        broken["主研究尺度"] = ["15分钟", "1小时", "4小时", "8小时"]
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_rules(broken)

    def test_未知字段和安全放宽失败关闭(self):
        broken = copy.deepcopy(self.config)
        broken["额外字段"] = True
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_rules(broken)
        broken = copy.deepcopy(self.config)
        broken["安全边界"]["允许远端写入"] = True
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_rules(broken)

    def test_三类时间和质量未知只能无法判定(self):
        record = self.policy.build_member_contract(self.member("m1", "DS-000001", "BTC"))
        self.assertEqual(record["质量状态"], "无法判定")
        self.assertEqual(
            {item["状态"] for item in record["三类时间"].values()}, {"无法判定"}
        )
        self.assertEqual(
            {item["状态"] for item in record["质量规则"].values()}, {"无法判定"}
        )

    def test_身份拒绝不能被质量合同补偿(self):
        record = self.policy.build_member_contract(
            self.member("m1", "DS-000001", "BTC", state="拒绝")
        )
        self.assertEqual(record["质量状态"], "失败")
        self.assertNotEqual(record["质量状态"], "已证明")

    def test_BTC和ETH独立计数不互相补偿(self):
        manifest = self.manifest(
            [
                self.member("m2", "DS-000002", "ETH"),
                self.member("m1", "DS-000001", "BTC"),
            ]
        )
        self.assertEqual(manifest["BTC状态计数"]["无法判定"], 1)
        self.assertEqual(manifest["ETH状态计数"]["无法判定"], 1)
        self.policy.validate_manifest(manifest)

    def test_成员顺序确定且重复成员失败(self):
        members = [
            self.member("m2", "DS-000002", "BTC"),
            self.member("m1", "DS-000001", "BTC"),
        ]
        manifest = self.manifest(list(reversed(members)))
        ordered = manifest["成员顺序"]
        self.assertEqual([item["资产编号"] for item in ordered], ["DS-000001", "DS-000002"])
        broken = copy.deepcopy(manifest)
        broken["成员顺序"].append(copy.deepcopy(broken["成员顺序"][0]))
        broken["成员总数"] += 1
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_manifest(broken)

    def test_成员内容指纹或短尺度越权失败(self):
        manifest = self.manifest([self.member("m1", "DS-000001", "BTC")])
        broken = copy.deepcopy(manifest)
        broken["成员顺序"][0]["内容指纹"] = "0" * 64
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_manifest(broken)
        broken = self.manifest([self.member("m1", "DS-000001", "BTC")])
        broken["成员顺序"][0]["主研究尺度"] = ["15分钟"]
        with self.assertRaises(self.policy.ContractError):
            self.policy.validate_manifest(broken)

    def test_历史批次拒绝覆盖(self):
        manifest = self.manifest([self.member("m1", "DS-000001", "BTC")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.policy.write_batch(manifest, root)
            self.assertTrue((first / "合同清单.json").exists())
            with self.assertRaises(self.policy.ContractError):
                self.policy.write_batch(manifest, root)

    def test_JSON重复字段失败(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"合同版本":"time-quality-1.0","合同版本":"x"}', encoding="utf-8")
            with self.assertRaises(self.policy.ContractError):
                self.policy.load_json(path)


if __name__ == "__main__":
    unittest.main()
