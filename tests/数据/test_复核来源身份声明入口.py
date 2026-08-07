from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/数据/复核来源身份声明入口.py"
SPEC = importlib.util.spec_from_file_location("review_source_identity_entry", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReviewSourceIdentityEntryTests(unittest.TestCase):
    def test_declaration_entries_are_explicitly_empty(self) -> None:
        entries, fingerprints = MODULE.load_declaration_entries()
        self.assertEqual(entries, [])
        self.assertEqual(set(fingerprints), {str(path.relative_to(ROOT)) for path in MODULE.DECLARATION_CONFIGS})

    def test_final_members_are_separate_and_conserved(self) -> None:
        _manifest, rows = MODULE.load_final_members()
        self.assertEqual(len(rows), 630)
        self.assertEqual({row["标的"] for row in rows}, {"BTC", "ETH"})
        self.assertEqual(sum(row["标的"] == "BTC" for row in rows), 315)
        self.assertEqual(sum(row["标的"] == "ETH" for row in rows), 315)

    def test_empty_entry_is_not_proof_and_batch_is_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = MODULE.execute(
                "source-identity-entry-review-20260808T055500+0800-test",
                Path(directory),
            )
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["输入"]["声明入口条数"], 0)
            self.assertEqual(manifest["结果摘要"]["已证明"], 0)
            self.assertEqual(manifest["结果摘要"]["分标的入口状态"]["BTC"]["未登记"], 315)
            self.assertEqual(manifest["结果摘要"]["分标的入口状态"]["ETH"]["未登记"], 315)
            with self.assertRaises(ValueError):
                MODULE.execute(
                    "source-identity-entry-review-20260808T055500+0800-test",
                    Path(directory),
                )

    def test_dangling_symlink_is_not_a_publish_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            target = output_root / "source-identity-entry-review-20260808T055501+0800-link"
            os.symlink(output_root / "missing-target", target)
            with self.assertRaises(ValueError):
                MODULE.execute(target.name, output_root)


if __name__ == "__main__":
    unittest.main()
