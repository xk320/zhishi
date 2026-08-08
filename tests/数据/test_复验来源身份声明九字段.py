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
        row = {**row, **{field: "declared" for field in MODULE.IDENTITY_FIELDS}}
        entry = {"配置": "test", "资产编号": row["资产编号"], "标的": row["标的"]}
        for field in MODULE.IDENTITY_FIELDS:
            entry[field] = "声明值"
        for field in MODULE.EVIDENCE_FIELDS:
            entry[field] = "未撤销" if field == "撤销事实" else "fingerprint"
        result = MODULE._evaluate_member(row, [entry])
        self.assertEqual(result["入口状态"], "已登记")
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_MISMATCH")

    def test_conflicting_complete_entries_fail_safe(self) -> None:
        _manifest, rows = MODULE.load_frozen_members()
        row = rows[0]
        row = {**row, **{field: "declared" for field in MODULE.IDENTITY_FIELDS}}
        entry = {"配置": "test", "资产编号": row["资产编号"], "标的": row["标的"]}
        for field in MODULE.IDENTITY_FIELDS:
            entry[field] = row[field]
        entry.update(
            {
                "证据定位": "snapshot#entry",
                "证据文件SHA-256": "a" * 64,
                "输入成员SHA-256": row["输入成员SHA-256"],
                "Schema指纹": "b" * 64,
                "授权快照SHA-256": "c" * 64,
                "撤销事实": "未撤销",
                "声明内容SHA-256": "d" * 64,
            }
        )
        conflicting = {**entry, "来源提供者": "CONFLICT"}
        result = MODULE._evaluate_member(row, [entry, conflicting])
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_CONFLICT")

    def test_incomplete_entry_cannot_be_ignored_by_complete_entry(self) -> None:
        _manifest, rows = MODULE.load_frozen_members()
        row = {**rows[0], **{field: "declared" for field in MODULE.IDENTITY_FIELDS}}
        complete = {"配置": "test", "资产编号": row["资产编号"], "标的": row["标的"]}
        for field in MODULE.IDENTITY_FIELDS:
            complete[field] = row[field]
        complete.update(
            {
                "证据定位": "snapshot#entry",
                "证据文件SHA-256": "a" * 64,
                "输入成员SHA-256": row["输入成员SHA-256"],
                "Schema指纹": "b" * 64,
                "授权快照SHA-256": "c" * 64,
                "撤销事实": "未撤销",
                "声明内容SHA-256": "d" * 64,
            }
        )
        incomplete = {**complete, "Schema确切版本": "未知"}
        result = MODULE._evaluate_member(row, [complete, incomplete])
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_INCOMPLETE")

    def test_snapshot_rejects_non_object_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = json.loads(MODULE.INPUT_SNAPSHOT.read_text(encoding="utf-8"))
            payload["来源文件"][0]["身份声明"] = ["not-an-object"]
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_declaration_snapshot(path)

    def test_snapshot_injects_source_identity_for_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = json.loads(MODULE.INPUT_SNAPSHOT.read_text(encoding="utf-8"))
            payload["来源文件"][0]["身份声明"] = [{"资产编号": "*", "标的": "BTC"}]
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            entries, _snapshot = MODULE.load_declaration_snapshot(path)
            self.assertEqual(entries[0]["配置"], payload["来源文件"][0]["路径"])

    def test_batch_is_append_only_and_counts_630(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = MODULE.execute("source-identity-nine-fields-20260808T070126+0800-test", Path(directory))
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["任务编号"], "任务-000081")
            self.assertEqual(manifest["输入"]["声明入口输入快照"]["入口条数"], 0)
            self.assertEqual(manifest["结果摘要"]["候选成员总体"], 630)
            self.assertEqual(manifest["结果摘要"]["已证明"], 0)
            for symbol in ("BTC", "ETH"):
                counts = manifest["结果摘要"]["分标的完整计数"][symbol]
                self.assertEqual(counts["候选总体"], 315)
                self.assertEqual(counts["入口状态计数"], {"未登记": 315, "入口不完整": 0, "已登记": 0})
                self.assertEqual(counts["可定位计数"], {"已定位": 0, "不可定位": 315})
                self.assertEqual(counts["九字段状态计数"]["无法判定"], 315)
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
