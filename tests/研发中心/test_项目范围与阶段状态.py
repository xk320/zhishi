import hashlib
import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TASK_DIR = ROOT / "docs" / "研发中心" / "任务"
BOARD_PATH = ROOT / "docs" / "研发中心" / "看板.md"
BOARD_POLICY_PATH = ROOT / "scripts" / "研发中心" / "验证自动合并资格.py"

STANDARD_STATUSES = {
    "待执行",
    "执行中",
    "阻塞",
    "待评审",
    "需修复",
    "已完成",
    "已取消",
}

FORWARD_SCOPE_FILES = (
    "AGENTS.md",
    "README.md",
    "《知势宣言》.md",
    "docs/白皮书/知势白皮书.md",
    "docs/决策/AI决策推理规范.md",
    "docs/决策/交易许可协议.md",
    "docs/决策/决策卡模板.md",
    "docs/决策/知势决策委员会.md",
    "docs/决策/知势决策标准.md",
    "docs/方法论/知势词典.md",
    "docs/架构/历史事件回放与结果统计体系.md",
    "docs/架构/最小数据闭环.md",
    "docs/架构/市场事件层架构.md",
    "docs/架构/市场状态架构.md",
    "docs/架构/知势知识图谱.md",
    "docs/架构/知识图谱运行时设计.md",
    "docs/架构/系统蓝图.md",
    "docs/研究/决策复盘规范.md",
    "docs/研究/市场状态—事件关联分析合同.md",
    "docs/研究/数据验证阶段执行规范.md",
    "docs/研究/研究准入规范.md",
    "docs/研究/研究数据合同与实验记录规范.md",
    "docs/研究/研究模板.md",
    "docs/审计/数据缺口与补采清单.md",
    "docs/治理/任务与验收规范.md",
    "docs/路线图/第一阶段路线图.md",
    "docs/风控/风险预算规范.md",
)

CURRENT_STATE_FILES = FORWARD_SCOPE_FILES + (
    "docs/研发中心/README.md",
    "docs/研发中心/总体计划.md",
    "docs/研发中心/Codex自动执行提示词.md",
)

AUTOMATION_GOVERNANCE_FILES = (
    "AGENTS.md",
    "README.md",
    "docs/研发中心/README.md",
    "docs/研发中心/任务规范.md",
    "docs/研发中心/Codex自动执行提示词.md",
    "docs/治理/PR自动合并策略.md",
)

AUTOMATION_GOVERNANCE_PHRASES = (
    "任务登记",
    "数据治理",
    "数据审计",
    "数据工程",
    "基础设施验证",
    "策略研究",
    "研究工程",
    "模拟交易",
    "测试",
    "工具",
    "真实资金",
    "生产写入",
    "精确头SHA",
)

HISTORICAL_EVIDENCE_HASHES = {
    "docs/审计/数据资产审计报告.md": "6468e1537ddb4170c4527df008a8235abe37d8d8cc384d361dd318952a33c8aa",
    "docs/审计/数据源清单.md": "e15ce622af0d8f1efdb68a36e9f8c39f3740d63fb9a340d52a1c34b17e6a4bd0",
    "artifacts/审计/数据源清单.csv": "019010d64fe47d89c81bfaedafd458f1d886025bb34292c0c32eafcfa4392657",
    "docs/审计/数据质量审计报告.md": "5954106f25920937b1bece689ac0afe07fc24a43bbe5b0039048b74b3df1bcb8",
    "artifacts/审计/数据质量结果.csv": "30358415ff997a759f784dd509af75e944b80231d61d5f9841ed7437218f6bb4",
    "docs/审计/历史现场重放验证.md": "3c62e7dea4e11e65e4834b39cf289abe783a13cd2acd00ce3002dce165ac4a16",
    "artifacts/审计/历史重放结果.csv": "56a4c928a39911bd6da5dc97e1d8fcdfa7211784f2c9decb8aeedcd91f431895",
    "artifacts/审计/数据质量持续验证/dqv-20260803T035557+0800-87273a8d253a/验证清单.json": "8cc36b5243fc6cc8bf1e5372035600e3df2375297c7f15f398603c950857cac9",
}
HISTORICAL_INDEX_PREFIX_HASH = "aafc925f412925e2affe86dbe5621655414d5e0a242e398e5d2309590d481c1d"


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


def board_policy():
    spec = importlib.util.spec_from_file_location(
        "project_scope_board_policy", BOARD_POLICY_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载可信看板校验器：{BOARD_POLICY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TaskCenterMappingTests(unittest.TestCase):
    def test_任务文件名与标题编号一致(self):
        for task_id, (path, _, _) in task_documents().items():
            self.assertEqual(path.stem, task_id, f"任务文件名与标题不一致：{path}")

    def test_任务编号唯一且只保留历史缺号(self):
        tasks = task_documents()
        numbers = sorted(
            int(task_id.removeprefix("任务-")) for task_id in tasks
        )
        self.assertEqual(len(numbers), len(set(numbers)))
        self.assertEqual(
            [
                number
                for number in range(1, max(numbers) + 1)
                if number not in numbers
            ],
            [26],
        )
        self.assertGreaterEqual(numbers[-1], 39)
        task_28 = tasks["任务-000028"][2]
        self.assertIn("PR #38合并时36个任务文件", task_28)
        self.assertNotIn("37个任务文件", task_28)

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

    def test_任务映射使用同一机器看板合同(self):
        board = BOARD_PATH.read_text(encoding="utf-8")
        self.assertTrue(board_policy()._board_schema_is_valid(board))


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
        self.assertEqual(metadata(text, "状态"), "已完成")
        self.assertEqual(
            metadata(text, "合并提交SHA"),
            "`e138bd589a5bde38c81f48d38b7c449f6f13df37`",
        )
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

    def test_任务000038具有完整自动评审合同(self):
        tasks = task_documents()
        _, title, text = tasks["任务-000038"]
        task_28 = tasks["任务-000028"][2]
        self.assertEqual(title, "建立子智能体评审、自动修复与自动合并治理")
        self.assertEqual(metadata(task_28, "状态"), "已完成")
        self.assertEqual(
            metadata(task_28, "合并提交SHA"),
            "`e138bd589a5bde38c81f48d38b7c449f6f13df37`",
        )
        self.assertEqual(metadata(task_28, "合并时间"), "2026-08-03 07:30:24 +0800")
        task_38_status = metadata(text, "状态")
        self.assertIn(task_38_status, {"待评审", "已完成"})
        self.assertEqual(
            metadata(text, "执行分支"),
            "`codex/000038-agent-review-auto-merge-implementation-v1`",
        )
        self.assertEqual(metadata(text, "开始时间"), "2026-08-03 07:42:38 +0800")
        self.assertEqual(
            metadata(text, "Pull Request"),
            "[#40](https://github.com/xk320/zhishi/pull/40)",
        )
        if task_38_status == "已完成":
            self.assertRegex(
                metadata(text, "合并提交SHA") or "",
                r"^`[0-9a-f]{40}`$",
            )
            self.assertRegex(
                metadata(text, "合并时间") or "",
                r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$",
            )
        self.assertEqual(metadata(text, "类型"), "治理")
        self.assertEqual(metadata(text, "方案状态"), "已批准执行")
        self.assertIn("唯一前序依赖：任务-000028已", text)
        self.assertIn("当前依赖已满足", text)
        self.assertIn("最多同时运行两个只读子智能体", text)
        self.assertIn("最多自动修复三轮", text)
        self.assertIn("精确头SHA", text)
        self.assertIn("不再等待人工批准", text)
        self.assertIn("Node最大堆256 MiB", text)
        self.assertIn("所有规则和可执行脚本必须来自受信任的`main`", text)
        self.assertIn("PR头提交、PR正文", text)
        self.assertIn("基线SHA或头SHA变化", text)
        self.assertIn("来源仓库必须为`xk320/zhishi`", text)
        self.assertIn("目标分支必须为`main`", text)
        self.assertIn("PR必须非草稿", text)
        self.assertIn("未解决评审线程", text)
        self.assertIn("CHANGES_REQUESTED", text)
        self.assertIn("测试单进程", text)
        self.assertIn("不创建额外工作树", text)
        self.assertIn("可用内存低于20%", text)
        self.assertIn("可用磁盘", text)
        self.assertIn("低于5 GiB", text)
        self.assertIn("合并后状态闭环", text)

        plan = (ROOT / "docs/研发中心/总体计划.md").read_text(encoding="utf-8")
        roadmap = (ROOT / "docs/路线图/第一阶段路线图.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("固定依赖链为：任务-000038", plan)
        self.assertIn("任务-000029至任务-000037", plan)
        self.assertNotIn("当前按任务-000028至任务-000037", plan)
        self.assertIn("任务-000038建立自动评审", roadmap)
        self.assertIn("任务-000029至任务-000037", roadmap)

        task_29 = tasks["任务-000029"][2]
        self.assertIn("任务-000038合并后的自动评审治理版本", task_29)

        for heading in (
            "依赖与阻塞条件",
            "背景",
            "任务目标",
            "输入合同",
            "输出合同",
            "固定执行方案",
            "默认工程决策",
            "允许停止条件",
            "工作范围",
            "不在范围",
            "安全边界",
            "验收标准",
            "验证命令",
            "完成定义",
        ):
            self.assertIn(f"## {heading}", text, f"任务-000038缺少{heading}")

    def test_阶段1修复任务链具有完整批准合同(self):
        expected = {
            "任务-000029": ("冻结数据来源与资产身份合同", "任务-000038"),
            "任务-000030": ("建立三类时间与数据质量合同", "任务-000029"),
            "任务-000031": ("完成不可变输入与全量只读质量审计", "任务-000030"),
            "任务-000032": ("建立可信重放来源与历史决策现场", "任务-000031"),
            "任务-000033": ("建立成本、流动性与执行数据闭环", "任务-000032"),
            "任务-000034": ("建立BTC与ETH独立数据闭环", "任务-000033"),
            "任务-000035": ("实施最小数据闭环试点", "任务-000034"),
            "任务-000036": ("完成容量试采与隔离恢复演练", "任务-000035"),
            "任务-000037": ("完成阶段1最终审计与阶段2门禁裁决", "任务-000036"),
        }
        tasks = task_documents()
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

        for task_id, (expected_title, dependency) in expected.items():
            self.assertIn(task_id, tasks, f"缺少{task_id}任务文件")
            _, title, text = tasks[task_id]
            self.assertEqual(title, expected_title)
            dependency_status = metadata(tasks[dependency][2], "状态")
            actual_status = metadata(text, "状态")
            if dependency_status != "已完成":
                self.assertEqual(actual_status, "阻塞")
            else:
                self.assertIn(actual_status, STANDARD_STATUSES)
            self.assertEqual(metadata(text, "方案状态"), "已批准执行")
            self.assertEqual(
                metadata(text, "执行授权"),
                "Codex直接执行，不得再次要求用户选择方案",
            )
            self.assertEqual(metadata(text, "并行规则"), "禁止并行；只在前序任务合并后认领")
            self.assertIn(dependency, text, f"{task_id}未引用唯一前序依赖{dependency}")
            self.assertIn("BTC", text)
            self.assertIn("ETH", text)
            self.assertNotIn("SOL", text)
            for heading in required_headings:
                self.assertIn(f"## {heading}", text, f"{task_id}缺少{heading}")

    def test_看板当前阶段反映阶段1证据修复(self):
        board = BOARD_PATH.read_text(encoding="utf-8")
        self.assertIn("阶段1数据闭环证据修复", board)
        self.assertNotIn("进入研究数据闭环真实化阶段", board)


class ProjectScopeAndStageTests(unittest.TestCase):
    def test_受控研发自动合并治理入口一致(self):
        for relative_path in AUTOMATION_GOVERNANCE_FILES:
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            for phrase in AUTOMATION_GOVERNANCE_PHRASES:
                self.assertIn(
                    phrase,
                    text,
                    f"{relative_path}缺少受控自动合并治理术语：{phrase}",
                )
            self.assertNotIn(
                "其他PR人工合并",
                text,
                f"{relative_path}仍保留失效的人工合并分流",
            )

    def test_前向规范只允许BTC和ETH(self):
        for relative_path in FORWARD_SCOPE_FILES:
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn("SOL", text, f"{relative_path}仍包含SOL前向范围")

    def test_现行文档不保留失效状态(self):
        forbidden = (
            "等待服务器恢复",
            "服务器恢复前",
            "服务器恢复后",
            "任务-000003至任务-000006尚未完成",
            "数据资产审计尚未完成",
        )
        for relative_path in CURRENT_STATE_FILES:
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            for phrase in forbidden:
                self.assertNotIn(phrase, text, f"{relative_path}仍包含失效状态：{phrase}")

    def test_三个阶段入口使用同一当前结论(self):
        expected = (
            "阶段0：已完成",
            "阶段0.5：核心理论合同已完成",
            "阶段1：数据闭环证据修复",
            "阶段2：被阶段1证据门阻塞",
            "阶段3至阶段7：仅完成部分理论合同，运行能力未解锁",
        )
        for relative_path in (
            "README.md",
            "docs/研发中心/总体计划.md",
            "docs/路线图/第一阶段路线图.md",
        ):
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            for line in expected:
                self.assertIn(line, text, f"{relative_path}缺少统一阶段结论：{line}")

    def test_旧市场状态设计明确标记为历史草案(self):
        path = ROOT / "docs" / "架构设计" / "市场状态层（Market Regime）顶层架构设计.md"
        text = path.read_text(encoding="utf-8")
        self.assertIn("历史草案", text)
        self.assertIn("../架构/市场状态架构.md", text)
        self.assertNotIn("当前交易系统已经具备", text)

    def test_历史审计证据指纹保持不变(self):
        for relative_path, expected_hash in HISTORICAL_EVIDENCE_HASHES.items():
            digest = hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
            self.assertEqual(digest, expected_hash, f"历史证据被改写：{relative_path}")

    def test_追加式批次索引只保护既有历史前缀(self):
        path = ROOT / "artifacts/审计/数据质量持续验证/批次索引.csv"
        lines = path.read_bytes().splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 2)
        digest = hashlib.sha256(b"".join(lines[:2])).hexdigest()
        self.assertEqual(digest, HISTORICAL_INDEX_PREFIX_HASH)

    def test_现行阶段2只由任务000037裁决(self):
        plan = (ROOT / "docs/研发中心/总体计划.md").read_text(encoding="utf-8")
        validation = (ROOT / "docs/研究/数据验证阶段执行规范.md").read_text(
            encoding="utf-8"
        )
        task_34 = (ROOT / "docs/研发中心/任务/任务-000034.md").read_text(
            encoding="utf-8"
        )
        combined = "\n".join((plan, validation))
        self.assertNotIn("在任务-000006完成前", combined)
        self.assertNotIn("任务-000006明确允许进入基准阶段", combined)
        self.assertNotIn("由任务-000006决定是否进入基准模型阶段", combined)
        self.assertIn("只有任务-000037", combined)
        self.assertIn("任务-000034无权解锁阶段2", task_34)
        self.assertNotIn("除非两个标的允许范围由证据精确限定", task_34)

    def test_持续验证合同现行章节不含旧标的范围(self):
        text = (ROOT / "docs/研究/数据质量持续验证合同.md").read_text(
            encoding="utf-8"
        )
        current_contract = text.split("## 十、初始真实批次", maxsplit=1)[0]
        self.assertNotIn("SOL", current_contract)


if __name__ == "__main__":
    unittest.main()
