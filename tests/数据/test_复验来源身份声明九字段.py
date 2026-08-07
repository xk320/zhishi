from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/数据/复验来源身份声明九字段.py"
SPEC = importlib.util.spec_from_file_location("review_source_identity_nine_fields", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReviewSourceIdentityNineFieldsTests(unittest.TestCase):
    def test_empty_entries_are_not_proof(self) -> None:
        entries, _fingerprints = MODULE.entry_engine.load_declaration_entries()
        _manifest, rows = MODULE.load_frozen_members()
        result = MODULE._evaluate_member(rows[0], entries)
        self.assertEqual(result["入口状态"], "未登记")
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_MISSING")

    def test_input_members_are_btc_eth_630_and_separate(self) -> None:
        _manifest, rows = MODULE.load_frozen_members()
        self.assertEqual(len(rows), 630)
        self.assertEqual(sum(row["标的"] == "BTC" for row in rows), 315)
        self.assertEqual(sum(row["标的"] == "ETH" for row in rows), 315)

    def test_complete_entry_requires_current_member_match(self) -> None:
        _manifest, rows = MODULE.load_frozen_members()
        row = rows[0]
        entry = {"配置": "test", "资产编号": row["资产编号"], "标的": row["标的"]}
        for field in MODULE.IDENTITY_FIELDS:
            entry[field] = "声明值"
        for field in MODULE.EVIDENCE_FIELDS:
            entry[field] = "未撤销" if field == "撤销事实" else "fingerprint"
        result = MODULE._evaluate_member(row, [entry])
        self.assertEqual(result["入口状态"], "已登记")
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_MISMATCH")

    def test_batch_is_append_only_and_counts_630(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = MODULE.execute("source-identity-nine-fields-20260808T070126+0800-test", Path(directory))
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["任务编号"], "任务-000081")
            self.assertEqual(manifest["输入"]["声明入口条数"], 0)
            self.assertEqual(manifest["结果摘要"]["候选成员总体"], 630)
            self.assertEqual(manifest["结果摘要"]["已证明"], 0)
            with self.assertRaises(ValueError):
                MODULE.execute("source-identity-nine-fields-20260808T070126+0800-test", Path(directory))

    def test_dangling_symlink_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            target = output_root / "source-identity-nine-fields-20260808T070127+0800-link"
            os.symlink(output_root / "missing", target)
            with self.assertRaises(ValueError):
                MODULE.execute(target.name, output_root)


if __name__ == "__main__":
    unittest.main()
