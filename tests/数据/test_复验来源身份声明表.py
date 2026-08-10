from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/数据/复验来源身份声明表.py"
SPEC = importlib.util.spec_from_file_location("verify_source_identity_table", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def empty_probe() -> dict[str, object]:
    return {
        "探针版本": MODULE.PROBE_VERSION,
        **{key: False for key in MODULE.SAFETY_KEYS},
        "结果": [
            {"资产编号": row["资产编号"], "表": row["位置"], "状态": "元数据未复验", "候选": False}
            for row in MODULE.load_inventory()
        ],
        "候选表": [],
        "候选行": [],
    }


class VerifySourceIdentityTableTests(unittest.TestCase):
    def test_config_freezes_twenty_fields_and_boundaries(self) -> None:
        config = MODULE.load_config()
        self.assertEqual(config["允许SSH目标"], ["ubuntu"])
        self.assertEqual(config["允许对象类型"], ["BASE TABLE"])
        self.assertEqual(len(config["逻辑字段顺序"]), 20)
        self.assertEqual(config["主研究尺度"], ["4小时", "8小时", "24小时", "48小时"])
        self.assertEqual(config["事后结果观察窗口"], ["15分钟", "1小时"])

    def test_probe_is_metadata_and_fixed_column_only(self) -> None:
        config = MODULE.load_config()
        script = MODULE.build_probe_script(MODULE.load_members(), MODULE.load_inventory(), config)
        compile(script, "<remote-probe>", "exec")
        self.assertIn("information_schema.TABLES", script)
        self.assertIn("TABLE_TYPE", script)
        self.assertNotIn("SELECT *", script.upper())
        self.assertNotIn("INSERT ", script.upper())
        self.assertNotIn("UPDATE ", script.upper())
        self.assertNotIn("DELETE ", script.upper())
        self.assertIn("ORDER BY", script)
        self.assertIn("LIMIT 631", script)
        self.assertIn("元数据探针返回失败", script)
        self.assertIn("候选声明列探针返回失败", script)

    def test_empty_probe_is_failure_safe_and_append_only(self) -> None:
        config = MODULE.load_config()
        payload = empty_probe()
        fake = SimpleNamespace(returncode=0, stdout=json.dumps(payload, ensure_ascii=False), stderr="")
        with tempfile.TemporaryDirectory() as directory:
            frozen = MODULE.dt.datetime(2026, 8, 10, 10, 0, tzinfo=MODULE.dt.timezone.utc)
            target = MODULE.execute_batch(config_path=MODULE.CONFIG_PATH, batch_root=Path(directory), now=frozen, runner=lambda *args, **kwargs: fake)
            manifest = json.loads((target / "批次清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["结果摘要"]["候选成员总体"], 630)
            self.assertEqual(manifest["结果摘要"]["分母"], 630)
            self.assertEqual(manifest["结果摘要"]["已观察"], 0)
            self.assertEqual(manifest["结果摘要"]["已证明"], 0)
            self.assertEqual(manifest["结果摘要"]["分标的"]["BTC"]["分母"], 315)
            self.assertEqual(manifest["结果摘要"]["分标的"]["BTC"]["已观察"], 0)
            self.assertEqual(manifest["结果摘要"]["分标的"]["BTC"]["最终状态计数"]["拒绝"], 6)
            with self.assertRaises(FileExistsError):
                MODULE.execute_batch(config_path=MODULE.CONFIG_PATH, batch_root=Path(directory), now=frozen, runner=lambda *args, **kwargs: fake)

    def test_probe_failure_is_not_reclassified_as_empty_candidate_set(self) -> None:
        config = MODULE.load_config()
        failed = SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
        with self.assertRaises(RuntimeError):
            MODULE.run_probe("print(1)", config, runner=lambda *args, **kwargs: failed)

    def test_complete_requires_schema_and_binding_fields(self) -> None:
        row = MODULE.load_members()[0]
        location = "MySQL/schema/table#成员编号=" + row["成员编号"]
        declaration = {field: "value" for field in MODULE.IDENTITY_FIELDS}
        declaration.update({
            "成员编号": row["成员编号"],
            "资产编号": row["资产编号"],
            "标的": row["标的"],
            "任务合同版本": MODULE.CONTRACT_VERSION,
            "采集时间": "2026-08-09T00:00:00+00:00",
            "声明版本或生效版本": "v1",
            "Schema指纹": "a" * 64,
            "成员输入指纹": row["输入成员SHA-256"],
            "授权指纹": "b" * 64,
            "可撤销事实或撤销时间": "有效",
        })
        declaration["声明内容指纹"] = MODULE.fp(declaration)
        declaration["证据定位"] = location
        candidate = {
            "来源类型": "测试",
            "证据定位": location,
            "入口内容SHA-256": "c" * 64,
            "候选Schema指纹": "a" * 64,
            "声明": declaration,
        }
        ok, missing = MODULE.complete(candidate, row, MODULE.dt.datetime(2026, 8, 10, tzinfo=MODULE.dt.timezone.utc))
        self.assertTrue(ok, missing)
        candidate["候选Schema指纹"] = "d" * 64
        ok, missing = MODULE.complete(candidate, row, MODULE.dt.datetime(2026, 8, 10, tzinfo=MODULE.dt.timezone.utc))
        self.assertFalse(ok)
        self.assertIn("Schema指纹绑定", missing)

    def test_probe_accepts_a_complete_candidate_with_logical_field_names(self) -> None:
        config = MODULE.load_config()
        row = MODULE.load_members()[0]
        declaration = {
            field: "value"
            for field in MODULE.LOGICAL_FIELDS
            if field not in {"成员编号", "资产编号", "标的", "任务合同版本", "采集时间", "声明内容指纹", "成员输入指纹", "Schema指纹", "授权指纹"}
        }
        declaration.update({
            "成员编号": row["成员编号"],
            "资产编号": row["资产编号"],
            "标的": row["标的"],
            "任务合同版本": MODULE.CONTRACT_VERSION,
            "采集时间": "2026-08-09T00:00:00+00:00",
            "成员输入指纹": row["输入成员SHA-256"],
            "Schema指纹": "a" * 64,
            "授权指纹": "b" * 64,
            "声明版本或生效版本": "v1",
            "可撤销事实或撤销时间": "有效",
        })
        declaration["声明内容指纹"] = MODULE.fp(declaration)
        table_path = MODULE.load_inventory()[0]["位置"]
        location = table_path + "#成员编号=" + row["成员编号"]
        payload = empty_probe()
        payload["候选表"] = [{
            "表": table_path,
            "对象类型": "BASE TABLE",
            "字段映射": {field: MODULE.FIELD_ALIASES[field][0] for field in MODULE.LOGICAL_FIELDS},
            "Schema指纹": "a" * 64,
            "候选行数": 1,
        }]
        payload["候选行"] = [{
            "来源类型": "数据库候选BASE TABLE",
            "证据定位": location,
            "入口内容SHA-256": MODULE.fp({"表": table_path, "Schema指纹": "a" * 64}),
            "候选Schema指纹": "a" * 64,
            "声明": {**declaration, "证据定位": location},
        }]
        fake = SimpleNamespace(returncode=0, stdout=json.dumps(payload, ensure_ascii=False), stderr="")
        accepted = MODULE.run_probe("print(1)", config, runner=lambda *args, **kwargs: fake)
        self.assertEqual(len(accepted["候选行"]), 1)
        ok, missing = MODULE.complete(accepted["候选行"][0], row, MODULE.dt.datetime(2026, 8, 10, tzinfo=MODULE.dt.timezone.utc))
        self.assertTrue(ok, missing)

    def test_complete_treats_mysql_null_as_missing(self) -> None:
        row = MODULE.load_members()[0]
        location = "MySQL/schema/table#成员编号=" + row["成员编号"]
        declaration = {field: "value" for field in MODULE.LOGICAL_FIELDS}
        declaration.update({
            "成员编号": row["成员编号"],
            "资产编号": row["资产编号"],
            "标的": row["标的"],
            "任务合同版本": MODULE.CONTRACT_VERSION,
            "采集时间": "2026-08-09T00:00:00+00:00",
            "成员输入指纹": row["输入成员SHA-256"],
            "Schema指纹": "a" * 64,
            "授权指纹": "b" * 64,
            "可撤销事实或撤销时间": "有效",
            "声明版本或生效版本": "v1",
        })
        declaration["声明内容指纹"] = MODULE.fp(declaration)
        candidate = {
            "来源类型": "测试",
            "证据定位": location,
            "入口内容SHA-256": "c" * 64,
            "候选Schema指纹": "a" * 64,
            "声明": {**declaration, "证据定位": location, "来源提供者": "\\N"},
        }
        ok, missing = MODULE.complete(candidate, row, MODULE.dt.datetime(2026, 8, 10, tzinfo=MODULE.dt.timezone.utc))
        self.assertFalse(ok)
        self.assertIn("来源提供者", missing)

    def test_unknown_candidate_columns_are_rejected(self) -> None:
        payload = empty_probe()
        payload["候选表"] = [{
            "表": "MySQL/schema/table",
            "对象类型": "BASE TABLE",
            "字段映射": {field: "column_" + str(index) for index, field in enumerate(MODULE.LOGICAL_FIELDS) if field != "声明版本或生效版本"},
            "Schema指纹": "a" * 64,
            "候选行数": 0,
        }]
        fake = SimpleNamespace(returncode=0, stdout=json.dumps(payload, ensure_ascii=False), stderr="")
        with self.assertRaises(ValueError):
            MODULE.run_probe("print(1)", MODULE.load_config(), runner=lambda *args, **kwargs: fake)


if __name__ == "__main__":
    unittest.main()
