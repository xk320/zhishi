import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TASK_DIR = ROOT / "docs" / "研发中心" / "任务"
BOARD_PATH = ROOT / "docs" / "研发中心" / "看板.md"

STANDARD_STATUSES = {
    "待执行",
    "执行中",
    "阻塞",
    "待评审",
    "需修复",
    "已完成",
    "已取消",
}


def task_documents():
    documents = {}
    for path in sorted(TASK_DIR.glob("任务-[0-9][0-9][0-9][0-9][0-9][0-9].md")):
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^# (任务-\d{6})：(.+)$", text, re.MULTILINE)
        if not match:
            raise AssertionError(f"任务文件标题不合规：{path}")
        documents[match.group(1)] = (path, match.group(2).strip(), text)
    return documents


def metadata(text, field):
    match = re.search(rf"^- {re.escape(field)}：(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


def board_sections(text):
    sections = {}
    matches = list(re.finditer(r"^## (待执行|执行中|阻塞|待评审|需修复|已完成|已取消)$", text, re.MULTILINE))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1)] = text[match.end():end]
    return sections


class TaskCenterMappingTests(unittest.TestCase):
    def test_每个任务在看板中恰好出现一次(self):
        tasks = task_documents()
        board = BOARD_PATH.read_text(encoding="utf-8")
        board_ids = []
        for line in board.splitlines():
            if not line.startswith("|"):
                continue
            for cell in (part.strip() for part in line.strip("|").split("|")):
                if re.fullmatch(r"任务-\d{6}", cell):
                    board_ids.append(cell)

        for task_id in tasks:
            self.assertEqual(
                board_ids.count(task_id),
                1,
                f"{task_id}在看板中必须恰好出现一次",
            )

        self.assertEqual(set(board_ids), set(tasks), "看板不得包含无任务文件的编号")

    def test_任务状态与看板分区一致(self):
        tasks = task_documents()
        board = BOARD_PATH.read_text(encoding="utf-8")
        sections = board_sections(board)

        for task_id, (_, _, text) in tasks.items():
            status = metadata(text, "状态")
            self.assertIn(status, STANDARD_STATUSES, f"{task_id}状态不合法")
            self.assertIn(status, sections, f"看板缺少{status}分区")
            self.assertEqual(
                len(re.findall(rf"\b{re.escape(task_id)}\b", sections[status])),
                1,
                f"{task_id}未位于看板的{status}分区",
            )


class TaskContractTests(unittest.TestCase):
    def test_待执行或需修复任务必须有已批准唯一方案(self):
        for task_id, (_, _, text) in task_documents().items():
            status = metadata(text, "状态")
            if status not in {"待执行", "需修复"}:
                continue
            self.assertIsNotNone(metadata(text, "执行方案"), f"{task_id}缺少执行方案")
            self.assertEqual(
                metadata(text, "方案状态"),
                "已批准执行",
                f"{task_id}方案尚未批准，不能处于{status}",
            )
            self.assertIsNotNone(metadata(text, "执行授权"), f"{task_id}缺少执行授权")

    def test_任务000028具有完整治理合同(self):
        _, title, text = task_documents()["任务-000028"]
        self.assertEqual(title, "统一阶段状态与BTC、ETH研究范围")
        self.assertIn(metadata(text, "状态"), {"执行中", "待评审", "已完成"})
        self.assertEqual(metadata(text, "方案状态"), "已批准执行")
        self.assertEqual(metadata(text, "阶段"), "阶段1 数据闭环修复与范围治理")

        required_metadata = (
            "类型",
            "优先级",
            "执行方案",
            "方案状态",
            "执行授权",
            "并行规则",
        )
        for field in required_metadata:
            self.assertIsNotNone(metadata(text, field), f"任务-000028缺少{field}")

        if metadata(text, "状态") == "执行中":
            self.assertIsNotNone(metadata(text, "执行分支"), "执行中任务缺少执行分支")
            self.assertIsNotNone(metadata(text, "开始时间"), "执行中任务缺少开始时间")

        required_headings = (
            "依赖与阻塞条件",
            "背景",
            "任务目标",
            "固定执行方案",
            "默认工程决策",
            "允许停止条件",
            "输入合同",
            "输出合同",
            "工作范围",
            "不在范围",
            "安全边界",
            "验收标准",
            "验证命令",
            "完成定义",
        )
        for heading in required_headings:
            self.assertIn(f"## {heading}", text, f"任务-000028缺少{heading}")

    def test_看板当前阶段反映阶段1证据修复(self):
        board = BOARD_PATH.read_text(encoding="utf-8")
        self.assertIn("阶段1数据闭环证据修复", board)
        self.assertNotIn("进入研究数据闭环真实化阶段", board)


if __name__ == "__main__":
    unittest.main()
