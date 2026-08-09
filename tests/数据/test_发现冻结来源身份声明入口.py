from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/数据/发现冻结来源身份声明入口.py"
SPEC = importlib.util.spec_from_file_location("discover_source_identity_entry", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def empty_probe() -> dict[str, object]:
    results = [
        {
            "资产编号": row["资产编号"],
            "文件入口数": 0,
            "数据库入口数": 0,
            "元数据SHA-256": "未知",
            "状态": "无法判定",
            "原因代码": "READONLY_METADATA_UNAVAILABLE",
        }
        for row in MODULE.load_inventory()
    ]
    return {
        "探针版本": MODULE.PROBE_VERSION,
        **{key: False for key in MODULE.SAFETY_KEYS},
        "结果": results,
        "候选": [],
    }


class DiscoverSourceIdentityEntryTests(unittest.TestCase):
    def test_config_and_inputs_are_frozen(self) -> None:
        config = MODULE.load_config()
        self.assertEqual(config["允许SSH目标"], ["ubuntu"])
        self.assertEqual(config["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(config["事后结果观察窗口"], ["15分钟", "1小时"])

    def test_probe_script_is_metadata_only_and_compiles(self) -> None:
        config = MODULE.load_config()
        script = MODULE.build_probe_script(MODULE.load_inventory(), config)
        compile(script, "<remote-probe>", "exec")
        self.assertIn("information_schema.TABLES", script)
        self.assertIn("information_schema.COLUMNS", script)
        self.assertNotIn("SELECT *", script)
        self.assertNotIn("INSERT ", script.upper())
        self.assertNotIn("UPDATE ", script.upper())
        self.assertNotIn("DELETE ", script.upper())

    def test_run_probe_rejects_safety_drift(self) -> None:
        config = MODULE.load_config()
        payload = empty_probe()
        payload["远端写入"] = True
        fake = SimpleNamespace(returncode=0, stdout=json.dumps(payload, ensure_ascii=False), stderr="")
        with self.assertRaises(ValueError):
            MODULE.run_probe("print(1)", config, runner=lambda *args, **kwargs: fake)

    def test_missing_entry_is_failure_safe(self) -> None:
        _manifest, members = MODULE.load_members()
        result = MODULE.evaluate_member(members[0], [])
        self.assertEqual(result["入口状态"], "未登记")
        self.assertEqual(result["九字段状态"], "无法判定")
        self.assertEqual(result["原因代码"], "IDENTITY_DECLARATION_MISSING")

    def test_incomplete_entry_cannot_prove_member(self) -> None:
        _manifest, members = MODULE.load_members()
        row = members[0]
        candidate = {"来源类型": "测试", "证据定位": "repo#entry", "入口内容SHA-256": "a" * 64, "声明": {"资产编号": row["资产编号"], "标的": row["标的"], "成员编号": row["成员编号"]}}
        result = MODULE.evaluate_member(row, [candidate])
        self.assertEqual(result["入口状态"], "入口不完整")
        self.assertEqual(result["最终身份状态"], "拒绝")

    def test_complete_requires_strict_binding_fields(self) -> None:
        _manifest, members = MODULE.load_members()
        row = members[0]
        declaration = {field: "value" for field in MODULE.DECLARATION_FIELDS}
        declaration.update({
            "标的": row["标的"],
            "资产编号": row["资产编号"],
            "成员编号": row["成员编号"],
            "输入成员SHA-256": row["输入成员SHA-256"],
            "任务合同版本": MODULE.CONTRACT_VERSION,
            "采集时间": "2020-01-01T00:00:00+00:00",
            "证据定位": "repo#entry",
            "撤销事实": "有效",
            "Schema指纹": "b" * 64,
            "授权快照SHA-256": "c" * 64,
        })
        declaration["声明内容SHA-256"] = MODULE.fp({key: value for key, value in declaration.items() if key != "声明内容SHA-256"})
        candidate = {"来源类型": "测试", "证据定位": "repo#entry", "入口内容SHA-256": "a" * 64, "声明": declaration}
        ok, missing = MODULE.complete(candidate, row)
        self.assertTrue(ok, missing)
        declaration["未登记字段"] = "不应被接受"
        ok, missing = MODULE.complete(candidate, row)
        self.assertFalse(ok)
        self.assertIn("声明字段越界:未登记字段", missing)

    def test_execute_empty_probe_is_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = MODULE.execute_batch(batch_root=Path(directory), runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(empty_probe(), ensure_ascii=False), stderr=""))
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["结果摘要"]["候选成员总体"], 630)
            self.assertEqual(manifest["结果摘要"]["已证明"], 0)
            self.assertEqual(manifest["结果摘要"]["分标的"]["BTC"]["最终状态计数"]["拒绝"], 6)
            with self.assertRaises(FileExistsError):
                MODULE.execute_batch(batch_root=Path(directory), runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(empty_probe(), ensure_ascii=False), stderr=""))

    def test_sensitive_candidate_is_rejected(self) -> None:
        _manifest, members = MODULE.load_members()
        candidate = {"来源类型": "测试", "证据定位": "repo#entry", "入口内容SHA-256": "a" * 64, "声明": {"资产编号": members[0]["资产编号"], "标的": members[0]["标的"], "来源提供者": "pass" + "word=bad"}}
        self.assertTrue(MODULE.sensitive(candidate))

if __name__ == "__main__":
    unittest.main()
