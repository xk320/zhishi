import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/研发中心/验证跨载体冲突.py"
SPEC = importlib.util.spec_from_file_location("cross_carrier_conflict", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONFLICT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONFLICT
SPEC.loader.exec_module(CONFLICT)


class CrossCarrierConflictTests(unittest.TestCase):
    def test_main基线无跨载体冲突(self):
        report = CONFLICT.check_refs(ROOT, "main", "main")
        self.assertTrue(report.ok, report.reasons)
        payload = report.as_dict()
        self.assertEqual("zhishi-conflict-resolution/v1", payload["protocol_version"])
        self.assertEqual([], payload["conflicts"])
        self.assertEqual(64, len(payload["rule_fingerprint"]))

    def test无效提交身份失败关闭(self):
        report = CONFLICT.check_refs(ROOT, "not-a-ref", "main")
        self.assertFalse(report.ok)
        self.assertIn("PR_BASELINE_DRIFT", report.reasons[0])

    def test依赖环失败关闭(self):
        records = {
            "000001": ("a", "A", "待执行", "P0", ("000002",)),
            "000002": ("b", "B", "待执行", "P0", ("000001",)),
        }
        conflicts = []
        CONFLICT._check_dependencies(records, conflicts)
        self.assertTrue(any(item.code == "DEPENDENCY_CYCLE" for item in conflicts))

    def test资源不足安全停机(self):
        self.assertTrue(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="normal",
                memory_available_percent=66,
                disk_available_gib=134,
            )
        )
        self.assertFalse(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="warning",
                memory_available_percent=19,
                disk_available_gib=134,
            )
        )
        self.assertFalse(
            CONFLICT.resource_policy_is_safe(
                memory_pressure="normal",
                memory_available_percent=66,
                disk_available_gib=4.9,
            )
        )

    def test评审证据提交变化即失效(self):
        self.assertTrue(
            CONFLICT.review_evidence_is_current(
                base_sha="a",
                head_sha="b",
                reviewed_base_sha="a",
                reviewed_head_sha="b",
            )
        )
        self.assertFalse(
            CONFLICT.review_evidence_is_current(
                base_sha="a",
                head_sha="c",
                reviewed_base_sha="a",
                reviewed_head_sha="b",
            )
        )

    def test修复计划只重建派生看板(self):
        schema = CONFLICT._schema_at_ref(ROOT, "main")
        board = CONFLICT._read_at_ref(ROOT, "main", CONFLICT.BOARD_PATH)
        self.assertIsNotNone(schema)
        self.assertIsNotNone(board)
        records = {
            "000049": (
                "docs/研发中心/任务/任务-000049.md",
                "研发中心跨载体冲突裁决与安全闭环",
                "待执行",
                "P0",
                ("000048",),
            )
        }
        repaired = CONFLICT.repair_board_text(board, records, schema)
        self.assertIn("任务-000049", repaired)
        self.assertIn("## 待执行", repaired)
        self.assertIn("## 状态维护要求", repaired)
        self.assertIn("000049", repaired)
        self.assertNotIn("任务文件记录", repaired)

    def test元数据资源与评审证据均绑定当前提交(self):
        base_sha = CONFLICT._resolve_ref(ROOT, "main")
        self.assertIsNotNone(base_sha)
        metadata = {
            "base_ref": "main",
            "base_sha": base_sha,
            "head_ref": "codex/000049-conflict-resolution-v1",
            "head_sha": base_sha,
            "pr_number": 83,
            "repository": "xk320/zhishi",
            "head_repository": "xk320/zhishi",
        }
        evidence = {
            "base_sha": base_sha,
            "head_sha": base_sha,
            "reviews": [
                {"reviewed_base_sha": base_sha, "reviewed_head_sha": base_sha},
                {"reviewed_base_sha": base_sha, "reviewed_head_sha": base_sha},
            ],
        }
        report = CONFLICT.check_refs(
            ROOT,
            "main",
            "main",
            metadata=metadata,
            review_evidence=evidence,
            resource_policy={
                "memory_pressure": "normal",
                "memory_available_percent": 66,
                "disk_available_gib": 134,
            },
        )
        self.assertTrue(report.ok, report.reasons)

    def test元数据漂移失败关闭(self):
        report = CONFLICT.check_refs(
            ROOT,
            "main",
            "main",
            metadata={"base_ref": "develop", "repository": "xk320/zhishi"},
        )
        self.assertFalse(report.ok)
        self.assertTrue(any("PR_BASELINE_DRIFT" in reason for reason in report.reasons))

    def test任务分支和PR编号必须精确绑定(self):
        base_sha = CONFLICT._resolve_ref(ROOT, "main")
        head_sha = CONFLICT._resolve_ref(ROOT, "HEAD")
        report = CONFLICT.check_refs(
            ROOT,
            base_sha,
            head_sha,
            task_id="000049",
            metadata={
                "base_ref": "main",
                "base_sha": base_sha,
                "head_ref": "codex/wrong-branch",
                "head_sha": head_sha,
                "pr_number": 999,
                "repository": "xk320/zhishi",
                "head_repository": "xk320/zhishi",
            },
        )
        self.assertFalse(report.ok)
        self.assertGreaterEqual(
            sum("PR_BASELINE_DRIFT" in reason for reason in report.reasons), 2
        )

    def test状态闭环保留原交付证据而不绑定新分支(self):
        base_sha = CONFLICT._resolve_ref(ROOT, "main")
        head_sha = CONFLICT._resolve_ref(ROOT, "HEAD")
        conflicts = []
        CONFLICT._check_task_execution_metadata(
            ROOT,
            head_sha,
            "000049",
            {
                "body": "## 变更类型\n- 合并后状态闭环\n",
                "head_ref": "codex/closure-000049",
                "pr_number": 84,
            },
            conflicts,
        )
        self.assertEqual([], conflicts)

    def test阻塞合同修复执行任务缺少开始时间失败(self):
        task_text = (
            "# 任务-000056：修复治理任务测试路径授权冲突\n\n"
            "- 状态：待评审\n"
            "- 执行分支：`codex/task-000056-repair`\n"
        )
        conflicts = []
        with mock.patch.object(
            CONFLICT,
            "_read_at_ref",
            return_value=task_text,
        ):
            CONFLICT._check_task_execution_metadata(
                ROOT,
                "codex/task-000056-repair",
                "000056",
                {
                    "body": (
                        "## 关联任务\n- 任务-000056\n\n"
                        "## 变更类型\n- 阻塞任务合同修复\n"
                    ),
                    "head_ref": "codex/task-000056-repair",
                    "pr_number": 124,
                },
                conflicts,
            )
        self.assertTrue(
            any("缺少开始时间" in item.repair_mode for item in conflicts),
            conflicts,
        )

    def test_root合同修复不把已完成源任务绑定到新PR分支(self):
        task_text = (
            "# 任务-000086：建立Ubuntu root只读兼容模式合同修复通道\n\n"
            "- 状态：已完成\n"
            "- 执行分支：`codex/task-000086-root-readonly-contract-governance-v1`\n"
            "- 开始时间：`2026-08-10T20:50:25+08:00`\n"
            "- Pull Request：[#227](https://github.com/xk320/zhishi/pull/227)\n"
        )
        conflicts = []
        with mock.patch.object(
            CONFLICT,
            "_read_at_ref",
            return_value=task_text,
        ):
            CONFLICT._check_task_execution_metadata(
                ROOT,
                "codex/task-000084-root-readonly-contract-repair-v1",
                "000086",
                {
                    "body": (
                        "## 关联任务\n- 任务-000086\n\n"
                        "## 变更类型\n- 阻塞任务合同修复\n"
                    ),
                    "head_ref": "codex/task-000084-root-readonly-contract-repair-v1",
                    "pr_number": 228,
                },
                conflicts,
            )
        self.assertEqual([], conflicts)

    def test空评审证据失败关闭(self):
        conflicts = []
        CONFLICT._check_review_evidence(
            {"base_sha": "a", "head_sha": "b", "reviews": []},
            base_sha="a",
            head_sha="b",
            conflicts=conflicts,
        )
        self.assertTrue(any(item.code == "REVIEW_EVIDENCE_STALE" for item in conflicts))

    def test合同正文漂移失败关闭(self):
        path = "docs/研发中心/任务/任务-000049.md"
        base_text = "# 任务-000049：示例\n\n## 任务目标\n\n保持安全边界。\n"
        head_text = base_text.replace("保持安全边界", "扩大范围并降低门槛")

        def paths(_repo, _ref):
            return (path,)

        def read(_repo, ref, requested):
            self.assertEqual(path, requested)
            return base_text if ref == "base" else head_text

        conflicts = []
        with mock.patch.object(CONFLICT, "_list_task_paths", side_effect=paths), mock.patch.object(
            CONFLICT, "_read_at_ref", side_effect=read
        ):
            CONFLICT._check_task_contract_drift(ROOT, "base", "head", conflicts)
        self.assertTrue(any(item.code == "TASK_CONTRACT_CONFLICT" for item in conflicts))

    def test任务合同冲突修复目标允许进入专用字段校验(self):
        path = "docs/研发中心/任务/任务-000066.md"
        base_text = (ROOT / path).read_text(encoding="utf-8")
        head_text = base_text.replace(
            "- 实现提交SHA：`eb632a33d3d0c08893dfe4bcee1f4dc549e03f4e`\n",
            "- 实现提交SHA：`eb632a33d3d0c08893dfe4bcee1f4dc549e03f4e`\n"
            "- 交付提交SHA：`c5a5f838f3c09b352150508388d15c3d7935818c`\n",
            1,
        ).replace(
            "本登记PR合并后任务保持`阻塞`，不标记已完成。只有解除条件有证据并经独立状态闭环PR恢复为待执行后，\n"
            "才能认领执行；正文审计交付须另行PR、双只读评审、main可信复验和合并后状态闭环。",
            "正文审计交付PR已合并并完成双只读评审、主执行器验证和main可信复验；随后通过独立状态闭环PR标记本任务为`已完成`。\n"
            "审计结果中的无法判定、失败和未成熟必须继续保留，不代表阶段1数据门槛或阶段2放行。",
            1,
        )

        def paths(_repo, _ref):
            return (path,)

        def read(_repo, ref, requested):
            self.assertEqual(path, requested)
            return base_text if ref == "base" else head_text

        conflicts = []
        with mock.patch.object(CONFLICT, "_list_task_paths", side_effect=paths), mock.patch.object(
            CONFLICT, "_read_at_ref", side_effect=read
        ):
            CONFLICT._check_task_contract_drift(
                ROOT,
                "base",
                "head",
                conflicts,
                contract_conflict_repair_target="000066",
            )
        self.assertEqual([], conflicts)

    def testroot只读兼容合同修复目标允许追加固定段落(self):
        path = "docs/研发中心/任务/任务-000084.md"
        base_text = (ROOT / path).read_text(encoding="utf-8")
        # 测试夹具固定为合同修复前基线，避免当前工作树中的待验证段落
        # 被重复追加后触发“基线已存在”冲突。
        root_section = CONFLICT.ROOT_READONLY_COMPAT_SECTION.strip()
        if root_section in base_text:
            base_text = base_text.split(root_section, 1)[0].rstrip("\n") + "\n"
        head_text = base_text.rstrip("\n") + "\n\n" + CONFLICT.ROOT_READONLY_COMPAT_SECTION.strip() + "\n"

        def paths(_repo, _ref):
            return (path,)

        def read(_repo, ref, requested):
            self.assertEqual(path, requested)
            return base_text if ref == "base" else head_text

        conflicts = []
        with mock.patch.object(CONFLICT, "_list_task_paths", side_effect=paths), mock.patch.object(
            CONFLICT, "_read_at_ref", side_effect=read
        ):
            CONFLICT._check_task_contract_drift(
                ROOT,
                "base",
                "head",
                conflicts,
                root_readonly_contract_repair_target="000084",
            )
        self.assertEqual([], conflicts)

    def test阻塞原因在依赖区段允许状态闭环(self):
        base_text = (
            "# 任务-000049：示例\n\n- 状态：阻塞\n\n"
            "## 依赖与阻塞条件\n\n- 当前阻塞原因：旧原因。\n"
            "- 解除条件：旧条件。\n\n## 任务目标\n\n保持目标。\n"
        )
        head_text = base_text.replace("旧原因", "新原因").replace("旧条件", "新条件")
        self.assertNotEqual(
            CONFLICT._immutable_task_contract(base_text),
            CONFLICT._immutable_task_contract(head_text),
        )
        self.assertEqual(
            CONFLICT._immutable_task_contract(
                base_text, allow_dependency_mutation=True
            ),
            CONFLICT._immutable_task_contract(
                head_text, allow_dependency_mutation=True
            ),
        )

    def test取消证据只在状态闭环允许变化(self):
        base_text = (
            "# 任务-000050：示例\n\n- 状态：阻塞\n"
            "- 唯一前序依赖：任务-000049完成后执行\n\n"
            "## 任务目标\n\n保持目标。\n"
        )
        cancellation_fields = (
            "- 取消时间：2026-08-04 11:20:00 +0800\n"
            "- 取消原因：原路径已被替代任务取代。\n"
            "- 取消依据任务：任务-000051\n"
            "- 取消依据PR：[#89](https://github.com/xk320/zhishi/pull/89)\n"
            "- 取消依据合并时间：2026-08-04 03:00:00 +0000\n"
            "- 取消依据合并提交SHA：`0123456789abcdef0123456789abcdef01234567`\n"
        )
        head_text = base_text.replace("- 状态：阻塞", "- 状态：已取消", 1).replace(
            "## 任务目标", cancellation_fields + "## 任务目标", 1
        )
        self.assertNotEqual(
            CONFLICT._immutable_task_contract(base_text),
            CONFLICT._immutable_task_contract(head_text),
        )
        self.assertEqual(
            CONFLICT._immutable_task_contract(
                base_text, allow_cancellation_mutation=True
            ),
            CONFLICT._immutable_task_contract(
                head_text, allow_cancellation_mutation=True
            ),
        )

    def test有损看板修复被拒绝(self):
        schema = CONFLICT._schema_at_ref(ROOT, "main")
        board = CONFLICT._read_at_ref(ROOT, "main", CONFLICT.BOARD_PATH)
        conflicts = []
        records = CONFLICT._task_records(ROOT, "main", conflicts)
        self.assertIsNotNone(schema)
        self.assertIsNotNone(board)
        with self.assertRaises(ValueError):
            CONFLICT.repair_board_text(board, records, schema)

    def test已取消看板修复使用替代任务证据(self):
        schema = CONFLICT._schema_at_ref(ROOT, "main")
        board = CONFLICT._read_at_ref(ROOT, "main", CONFLICT.BOARD_PATH)
        self.assertIsNotNone(schema)
        self.assertIsNotNone(board)
        records = {
            "000050": (
                "docs/研发中心/任务/任务-000050.md",
                "重复任务裁决",
                "已取消",
                "P1",
                (),
                "",
                "",
                "",
                "[#89](https://github.com/xk320/zhishi/pull/89)",
                "998294a823ccbd526c1a33fb4764bc1f968fa4df",
                "000051",
                "原路径已被替代任务取代。",
            )
        }
        repaired = CONFLICT.repair_board_text(board, records, schema)
        self.assertIn("替代任务-000051", repaired)
        self.assertIn("取消原因：原路径已被替代任务取代。", repaired)

    def test研究尺度越界失败关闭(self):
        original = CONFLICT._read_at_ref

        def altered(repo_root, ref, path):
            text = original(repo_root, ref, path)
            if path == CONFLICT.SCALE_SCOPE_DOCS[0] and text is not None:
                return text.replace("15分钟", "")
            return text

        with mock.patch.object(CONFLICT, "_read_at_ref", side_effect=altered):
            conflicts = []
            CONFLICT._check_scope(ROOT, "main", conflicts)
        self.assertTrue(any(item.code == "SCOPE_BOUNDARY_DRIFT" for item in conflicts))

    def test前向文档出现未标注SOL失败关闭(self):
        original = CONFLICT._read_at_ref

        def altered(repo_root, ref, path):
            if path == "AGENTS.md":
                return "当前范围：BTC、ETH、SOL\n"
            return original(repo_root, ref, path)

        with mock.patch.object(CONFLICT, "_read_at_ref", side_effect=altered):
            conflicts = []
            CONFLICT._check_scope(ROOT, "main", conflicts)
        self.assertTrue(any(item.code == "SCOPE_BOUNDARY_DRIFT" for item in conflicts))

    def test历史证据变更失败关闭(self):
        original = CONFLICT._read_at_ref
        # 使用合成引用，避免测试在main与HEAD相同或不同的拓扑下出现分支依赖。
        main_sha = "base-ref"
        head_sha = "head-ref"
        path = next(
            path
            for path in CONFLICT.HISTORICAL_IMMUTABLE_PATHS
            if original(ROOT, "main", path) is not None
        )

        def altered(repo_root, ref, requested):
            value = original(repo_root, "main", requested)
            if requested == path and ref == head_sha:
                return (value or "") + "\n未经授权变更"
            return value

        conflicts = []
        with mock.patch.object(CONFLICT, "_read_at_ref", side_effect=altered):
            CONFLICT._check_historical_immutability(ROOT, main_sha, head_sha, conflicts)
        self.assertTrue(any(item.code == "SCOPE_BOUNDARY_DRIFT" for item in conflicts))


if __name__ == "__main__":
    unittest.main()
