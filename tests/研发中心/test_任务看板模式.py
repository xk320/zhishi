import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "scripts" / "研发中心" / "验证自动合并资格.py"
MANIFEST_PATH = ROOT / "docs" / "研发中心" / "任务看板模式.md"
BOARD_PATH = ROOT / "docs" / "研发中心" / "看板.md"


def load_policy():
    spec = importlib.util.spec_from_file_location("board_mode_policy", POLICY_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载可信校验器：{POLICY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BoardModeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy()
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.board = BOARD_PATH.read_text(encoding="utf-8")

    def test_机器合同版本指纹与可信校验器一致(self):
        self.assertEqual(
            {"schema_version", "content_sha256", "sections"},
            set(self.manifest),
        )
        self.assertEqual("zhishi-task-board/v1", self.manifest["schema_version"])
        self.assertEqual(
            set(self.policy.REQUIRED_BOARD_SECTIONS),
            set(self.manifest["sections"]),
        )
        self.assertEqual(
            self.manifest["content_sha256"],
            self.policy._board_schema_digest(
                self.manifest["schema_version"], self.manifest["sections"]
            ),
        )
        self.assertEqual(
            {
                section: tuple(lines)
                for section, lines in self.manifest["sections"].items()
            },
            self.policy.BOARD_TABLE_SCHEMA,
        )

    def test_当前看板符合单一模式合同(self):
        self.assertTrue(self.policy._board_schema_is_valid(self.board))
        self.assertNotIn("Pull Request", self.board)

    def test_旧表头别名失败关闭(self):
        legacy = self.board.replace(
            "| 优先级 | 任务 | 名称 | 分支 | PR |",
            "| 优先级 | 任务 | 名称 | 分支 | Pull Request |",
            1,
        )
        self.assertIn("Pull Request", legacy)
        self.assertFalse(self.policy._board_schema_is_valid(legacy))

    def test_重复表头失败关闭(self):
        duplicate = self.board.replace(
            "| --- | --- | --- | --- | --- |",
            "| --- | --- | --- | --- | --- |\n| --- | --- | --- | --- | --- |",
            1,
        )
        self.assertFalse(self.policy._board_schema_is_valid(duplicate))

    def test_缺少标准状态分区失败关闭(self):
        for section in ("需修复", "已取消"):
            with self.subTest(section=section):
                missing = self.board.replace(f"## {section}\n", "", 1)
                self.assertFalse(self.policy._board_schema_is_valid(missing))

    def test_无关任务重复映射失败关闭(self):
        row = next(
            line
            for line in self.board.splitlines()
            if line.startswith("|") and "| 任务-" in line
        )
        duplicate = self.board.replace(row, row + "\n" + row, 1)
        self.assertFalse(self.policy._board_schema_is_valid(duplicate))

    def test_机器合同缺失时失败关闭(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with mock.patch.object(self.policy, "BOARD_SCHEMA_PATH", missing):
                self.assertEqual(self.policy._load_board_table_schema(), {})

    def test_机器合同指纹损坏时失败关闭(self):
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.json"
            document = dict(self.manifest)
            document["content_sha256"] = "0" * 64
            broken.write_text(
                json.dumps(document, ensure_ascii=False), encoding="utf-8"
            )
            with mock.patch.object(self.policy, "BOARD_SCHEMA_PATH", broken):
                self.assertEqual(self.policy._load_board_table_schema(), {})

    def test_机器合同重复JSON键失败关闭(self):
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"zhishi-task-board/v1",'
                '"schema_version":"zhishi-task-board/v1",'
                '"content_sha256":"0", "sections":{}}',
                encoding="utf-8",
            )
            with mock.patch.object(self.policy, "BOARD_SCHEMA_PATH", duplicate):
                self.assertEqual(self.policy._load_board_table_schema(), {})


if __name__ == "__main__":
    unittest.main()
