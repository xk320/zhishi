from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import re


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts/研发中心/验证外部状态一致性.py"
SPEC = importlib.util.spec_from_file_location("external_state_contract", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
CANONICAL_CURRENT_STATE_PREFIXES = (
    "当前外部事实以任务-000031最新脱敏执行",
    "当前外部状态以任务-000031最新脱敏执行",
)
FORBIDDEN_CURRENT_CLAIMS = {
    "README.md": ("服务器连接已经恢复", "服务器当前可访问"),
    "AGENTS.md": ("服务器当前可访问",),
    "docs/研发中心/总体计划.md": ("服务器连接已经恢复",),
    "docs/研发中心/Codex自动执行提示词.md": ("服务器连接已经恢复",),
    "docs/研究/数据验证阶段执行规范.md": ("服务器连接已恢复", "数据服务器连接已经恢复"),
}
BOARD_SCHEMA_PATH = ROOT / "docs/研发中心/任务看板模式.md"


def _insert_board_row(board: str, section: str, row: str) -> str:
    """按唯一机器看板模式在内存夹具中插入任务行，兼容空分区。"""

    schema = json.loads(BOARD_SCHEMA_PATH.read_text(encoding="utf-8"))
    header, separator = schema["sections"][section]
    table = f"## {section}\n\n{header}\n{separator}"
    if table in board:
        return board.replace(table, f"{table}\n{row}", 1)
    empty = f"## {section}\n\n无。"
    if empty in board:
        return board.replace(empty, f"{table}\n{row}", 1)
    raise AssertionError(f"看板缺少可插入的{section}分区")


class ExternalStateConsistencyTests(unittest.TestCase):
    def test_现行入口引用任务031证据(self):
        for relative_path in FORBIDDEN_CURRENT_CLAIMS:
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertTrue(
                any(prefix in text for prefix in CANONICAL_CURRENT_STATE_PREFIXES),
                relative_path,
            )

    def test_现行入口不保留无证据恢复声明(self):
        for relative_path, forbidden_claims in FORBIDDEN_CURRENT_CLAIMS.items():
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            for claim in forbidden_claims:
                self.assertNotIn(claim, text, f"{relative_path}仍包含现行冲突声明：{claim}")

    def test_任务031阻塞事实与看板一致(self):
        task = (ROOT / "docs/研发中心/任务/任务-000031.md").read_text(encoding="utf-8")
        board = (ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        self.assertIn("- 状态：阻塞", task)
        self.assertIn("获批只读目标`ubuntu`当前不可达", task)
        self.assertIn(
            "| 任务-000031 | 完成不可变输入与全量只读质量审计 | 000030 | 获批只读目标`ubuntu`当前不可达",
            board,
        )

    def _assert_task043_state_mapping(self, task: str, board: str) -> None:
        status_lines = [
            line[len("- 状态：") :].strip()
            for line in task.splitlines()
            if line.startswith("- 状态：")
        ]
        self.assertEqual(len(status_lines), 1)
        status = status_lines[0]
        self.assertIn(status, {"待评审", "已完成"})

        current_section = ""
        task_rows = []
        for line in board.splitlines():
            if line.startswith("## "):
                current_section = line[3:].strip()
                continue
            if re.match(r"^\|\s*(?:P[0-3]\s*\|\s*)?任务-000043\s*\|", line):
                task_rows.append((current_section, line))
        self.assertEqual(len(task_rows), 1)
        section, row = task_rows[0]
        if status == "待评审":
            self.assertEqual(section, "待评审")
            self.assertEqual(
                row,
                "| P0 | 任务-000043 | 统一外部环境事实与阶段状态声明 | "
                "`codex/000043-external-state-consistency-v1` | "
                "[#62](https://github.com/xk320/zhishi/pull/62) |",
            )
        else:
            self.assertEqual(section, "已完成")
            self.assertEqual(
                row,
                "| 任务-000043 | 统一外部环境事实与阶段状态声明 | "
                "PR #62；合并提交 `abe66037161332d350b9782492beedd8898a4f8a` |",
            )
            self.assertIn("[#62](https://github.com/xk320/zhishi/pull/62)", task)
            self.assertIn("abe66037161332d350b9782492beedd8898a4f8a", task)

    def test_任务043交付态与完成态元数据和看板一致(self):
        task = (ROOT / "docs/研发中心/任务/任务-000043.md").read_text(encoding="utf-8")
        board = (ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        self._assert_task043_state_mapping(task, board)

        pending_row = (
            "| P0 | 任务-000043 | 统一外部环境事实与阶段状态声明 | `codex/000043-external-state-consistency-v1` | "
            "[#62](https://github.com/xk320/zhishi/pull/62) |"
        )
        completed_row = (
            "| 任务-000043 | 统一外部环境事实与阶段状态声明 | "
            "PR #62；合并提交 `abe66037161332d350b9782492beedd8898a4f8a` |"
        )
        if "- 状态：待评审" in task:
            completed_task = task.replace("- 状态：待评审", "- 状态：已完成")
            completed_task += "\n- 合并提交SHA：`abe66037161332d350b9782492beedd8898a4f8a`\n"
            completed_board = board.replace(pending_row, "")
            completed_board = _insert_board_row(completed_board, "已完成", completed_row)
            self._assert_task043_state_mapping(completed_task, completed_board)
        else:
            pending_task = task.replace("- 状态：已完成", "- 状态：待评审")
            pending_board = board.replace(completed_row, "")
            pending_board = _insert_board_row(pending_board, "待评审", pending_row)
            self._assert_task043_state_mapping(pending_task, pending_board)

        current_row = pending_row if "- 状态：待评审" in task else completed_row
        wrong_section_row = pending_row if "- 状态：待评审" in task else completed_row
        wrong_section_board = board.replace(current_row, "")
        if "- 状态：待评审" in task:
            wrong_section_board = _insert_board_row(wrong_section_board, "已完成", wrong_section_row)
        else:
            wrong_section_board = _insert_board_row(wrong_section_board, "待评审", wrong_section_row)
        with self.assertRaises(AssertionError):
            self._assert_task043_state_mapping(task, wrong_section_board)

        with self.assertRaises(AssertionError):
            self._assert_task043_state_mapping(task, board.replace(current_row, ""))

    def test_任务043拒绝未知缺失和重复状态(self):
        task = (ROOT / "docs/研发中心/任务/任务-000043.md").read_text(encoding="utf-8")
        board = (ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        current_status = "已完成" if "- 状态：已完成" in task else "待评审"
        status_prefix = f"- 状态：{current_status}"
        for malformed in (
            task.replace(status_prefix, "- 状态：执行中"),
            task.replace(status_prefix, f"{status_prefix}\n- 状态：{current_status}"),
            task.replace(status_prefix + "\n", ""),
        ):
            with self.assertRaises(AssertionError):
                self._assert_task043_state_mapping(malformed, board)

    def test_历史任务记录仍保留(self):
        historical = (ROOT / "docs/研发中心/任务/任务-000028.md").read_text(encoding="utf-8")
        def assert_historical_record(text: str) -> None:
            self.assertIn("任务-000028：统一阶段状态与BTC、ETH研究范围", text)
            self.assertIn("执行记录", text)

        assert_historical_record(historical)
        with self.assertRaises(AssertionError):
            assert_historical_record(historical.replace("执行记录", ""))

    def test_四个现行外部状态词汇已冻结(self):
        design = (ROOT / "docs/superpowers/specs/2026-08-04-external-state-consistency-design.md").read_text(encoding="utf-8")
        self.assertEqual(
            CONTRACT.STATE_VOCABULARY,
            ("未验证", "可达（仅连接）", "不可达", "可达但审计未完成"),
        )
        for state in CONTRACT.STATE_VOCABULARY:
            self.assertIn(f"`{state}`", design)

    def test_证据新鲜度拒绝缺时区未来和过期(self):
        observed = datetime(2026, 8, 4, 4, 0, tzinfo=timezone.utc)
        self.assertTrue(
            CONTRACT.evidence_is_fresh(
                observed - timedelta(minutes=30), observed
            )
        )
        self.assertFalse(
            CONTRACT.evidence_is_fresh(
                observed - timedelta(minutes=61), observed
            )
        )
        self.assertFalse(
            CONTRACT.evidence_is_fresh(
                observed + timedelta(minutes=1), observed
            )
        )
        self.assertFalse(
            CONTRACT.evidence_is_fresh(
                datetime(2026, 8, 4, 3, 30), observed
            )
        )

    def test_恢复只能走阻塞到待执行或需修复(self):
        common = {
            "current_state": "阻塞",
            "probe_reachable": True,
            "audit_evidence": True,
            "evidence_fresh": True,
        }
        self.assertTrue(
            CONTRACT.recovery_is_permitted(transition="阻塞→待执行", **common)
        )
        self.assertTrue(
            CONTRACT.recovery_is_permitted(transition="阻塞→需修复", **common)
        )
        for transition in ("待执行→执行中", "阻塞→已完成", "执行中→待执行"):
            self.assertFalse(
                CONTRACT.recovery_is_permitted(transition=transition, **common)
            )
        self.assertFalse(
            CONTRACT.recovery_is_permitted(
                transition="阻塞→待执行", **{**common, "audit_evidence": False}
            )
        )


if __name__ == "__main__":
    unittest.main()
