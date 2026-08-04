from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
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

    def test_任务043待评审元数据与看板一致(self):
        task = (ROOT / "docs/研发中心/任务/任务-000043.md").read_text(encoding="utf-8")
        board = (ROOT / "docs/研发中心/看板.md").read_text(encoding="utf-8")
        self.assertIn("- 状态：待评审", task)
        self.assertIn("- 执行分支：`codex/000043-external-state-consistency-v1`", task)
        self.assertIn(
            "| P0 | 任务-000043 | 统一外部环境事实与阶段状态声明 | `codex/000043-external-state-consistency-v1` | [#62](https://github.com/xk320/zhishi/pull/62) |",
            board,
        )

    def test_历史任务记录仍保留(self):
        historical = (ROOT / "docs/研发中心/任务/任务-000028.md").read_text(encoding="utf-8")
        self.assertIn("任务-000028：统一阶段状态与BTC、ETH研究范围", historical)
        self.assertIn("执行记录", historical)


if __name__ == "__main__":
    unittest.main()
