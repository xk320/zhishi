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

    def test有损看板修复被拒绝(self):
        schema = CONFLICT._schema_at_ref(ROOT, "main")
        board = CONFLICT._read_at_ref(ROOT, "main", CONFLICT.BOARD_PATH)
        conflicts = []
        records = CONFLICT._task_records(ROOT, "main", conflicts)
        self.assertIsNotNone(schema)
        self.assertIsNotNone(board)
        with self.assertRaises(ValueError):
            CONFLICT.repair_board_text(board, records, schema)

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
