from __future__ import annotations

import csv
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "审计" / "持续验证数据质量.py"
AUDITOR_PATH = REPO_ROOT / "scripts" / "审计" / "审计数据质量.py"
INVENTORY_COLUMNS = [
    "发现批次",
    "资产编号",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
]


class ImplementationPresenceTest(unittest.TestCase):
    def test_实现文件存在(self):
        self.assertTrue(MODULE_PATH.exists(), f"实现文件尚不存在：{MODULE_PATH}")


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"无法加载实现文件：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_rows() -> list[dict[str, str]]:
    base = {
        "发现批次": "discovery-fixed",
        "逻辑主机": "ubuntu",
        "服务或项目": "crypto-radar",
        "资源名称": "btc.csv",
        "标的范围": "BTC",
        "时间范围": "未知",
        "字节数": "42",
        "最后修改时间": "2026-08-03T00:00:00+08:00",
        "访问状态": "元数据可访问",
        "发现证据": "只读元数据",
        "限制": "未证明精确作用域",
        "后续任务": "任务-000027",
    }
    return [
        {
            **base,
            "资产编号": "DS-000002",
            "资产类型": "数据库元数据",
            "服务或项目": "crypto_radar",
            "资源名称": "signals",
            "位置": "MySQL/crypto_radar/signals",
            "格式": "InnoDB",
            "标的范围": "未限定",
            "字节数": "未知",
            "最后修改时间": "未知",
        },
        {
            **base,
            "资产编号": "DS-000001",
            "资产类型": "候选数据文件",
            "位置": "/opt/crypto-radar/data/btc.csv",
            "格式": "CSV",
        },
    ]


def write_inventory(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=INVENTORY_COLUMNS)
        writer.writeheader()
        writer.writerows(inventory_rows())


def valid_plan(inventory: Path) -> dict[str, object]:
    return {
        "方案版本": "dq-continuous-plan-1.0",
        "底层审计规则版本": "dq-rules-1.0",
        "资产清单指纹": sha256(inventory),
        "允许SSH目标": ["ubuntu"],
        "检查项": [
            "身份与Schema",
            "事件时间、到达时间、采集时间",
            "完整性、连续性与断档",
            "重复、乱序、晚到与异常",
            "规则、清单与作用域漂移",
        ],
        "状态映射": {
            "可用": "通过",
            "有限可用": "拒绝",
            "不可用": "拒绝",
            "无法判定": "无法判定",
        },
        "作用域": {
            "标的": ["BTC", "ETH", "SOL"],
            "主研究尺度": ["4小时", "8小时", "24小时", "48小时"],
            "结果观察窗口": ["15分钟", "1小时"],
            "分组维度": [
                "标的",
                "交易场所",
                "市场类型",
                "精确合约",
                "数据资产",
                "Schema确切版本",
            ],
        },
        "资源上限": {
            "批次总超时秒": 3600,
            "最大成员数": 500,
            "最大输出字节数": 10 * 1024 * 1024,
            "最大日志字节数": 4096,
        },
        "安全边界": {
            "远端写入": False,
            "远端临时文件": False,
            "数据库业务正文": False,
            "自动数据修复": False,
            "自动研究或交易放行": False,
        },
    }


def write_plan(path: Path, plan: dict[str, object]) -> None:
    path.write_text(
        json.dumps(plan, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_csv(path: Path, columns: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def output_rows(auditor: ModuleType, inventory_fingerprint: str):
    batch = "audit-fixed"
    rules = "a" * 64
    quality_rows = []
    gap_rows = []
    anomaly_rows = []
    for asset_id, scan_status, completeness, conclusion in (
        ("DS-000001", "完成", "完整", "可用"),
        ("DS-000002", "未执行", "未执行", "无法判定"),
    ):
        quality = {column: "" for column in auditor.QUALITY_COLUMNS}
        quality.update({
            "审计批次": batch,
            "规则版本": auditor.RULE_VERSION,
            "规则指纹": rules,
            "清单指纹": inventory_fingerprint,
            "资产编号": asset_id,
            "资产类型": "候选数据文件",
            "服务或项目": "crypto-radar",
            "位置": "/opt/crypto-radar/data/example.csv",
            "格式": "CSV",
            "候选标的范围": "BTC" if asset_id.endswith("1") else "未限定",
            "扫描状态": scan_status,
            "扫描完整性": completeness,
            "记录数": "10" if completeness == "完整" else "无法判定",
            "字段数": "2" if completeness == "完整" else "无法判定",
            "结构缺失数": "1" if completeness == "完整" else "无法判定",
            "精确重复数": "0" if completeness == "完整" else "无法判定",
            "事件时间状态": "无法判定",
            "到达时间状态": "无法判定",
            "采集时间状态": "无法判定",
            "延迟状态": "无法判定",
            "乱序状态": "无法判定",
            "可用性结论": conclusion,
            "证据指纹": ("b" if asset_id.endswith("1") else "c") * 64,
        })
        quality_rows.append(quality)

        gap = {column: "" for column in auditor.GAP_COLUMNS}
        gap.update({
            "审计批次": batch,
            "规则版本": auditor.RULE_VERSION,
            "规则指纹": rules,
            "清单指纹": inventory_fingerprint,
            "资产编号": asset_id,
            "候选标的范围": quality["候选标的范围"],
            "断档状态": "无法判定",
            "断档数": "无法判定",
        })
        gap_rows.append(gap)

        anomaly = {column: "" for column in auditor.ANOMALY_COLUMNS}
        anomaly.update({
            "审计批次": batch,
            "规则版本": auditor.RULE_VERSION,
            "规则指纹": rules,
            "清单指纹": inventory_fingerprint,
            "资产编号": asset_id,
            "候选标的范围": quality["候选标的范围"],
            "规则编号": "DQ-STRUCT-001",
            "异常类型": "结构解析异常汇总",
            "异常数量": "0" if completeness == "完整" else "无法判定",
            "规则状态": "已执行" if completeness == "完整" else "未执行",
        })
        anomaly_rows.append(anomaly)
    return quality_rows, gap_rows, anomaly_rows


@unittest.skipUnless(MODULE_PATH.exists(), "等待持续验证实现")
class ContinuousValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module(MODULE_PATH, "continuous_quality_validation")
        cls.auditor = load_module(AUDITOR_PATH, "continuous_test_auditor")

    def make_inputs(self, root: Path):
        inventory = root / "inventory.csv"
        plan_path = root / "plan.json"
        write_inventory(inventory)
        write_plan(plan_path, valid_plan(inventory))
        return inventory, plan_path

    def fake_runner(self, inventory_fingerprint: str):
        auditor = self.auditor

        def run(command, **kwargs):
            self.assertIsInstance(command, list)
            self.assertNotIn("shell", kwargs)
            self.assertNotIn("capture_output", kwargs)
            self.assertEqual(sys.executable, command[0])
            self.assertEqual(str(AUDITOR_PATH), command[1])
            self.assertEqual("ubuntu", command[command.index("--ssh-target") + 1])
            output_dir = Path(command[command.index("--output-dir") + 1])
            report = Path(command[command.index("--report") + 1])
            quality, gaps, anomalies = output_rows(auditor, inventory_fingerprint)
            write_csv(output_dir / "数据质量结果.csv", auditor.QUALITY_COLUMNS, quality)
            write_csv(output_dir / "数据断档结果.csv", auditor.GAP_COLUMNS, gaps)
            write_csv(output_dir / "数据异常结果.csv", auditor.ANOMALY_COLUMNS, anomalies)
            report.write_text(
                "# 测试审计报告\n\n"
                "- 审计批次：`audit-fixed`\n"
                "- 数据截止时间：`2026-08-03T00:00:00+08:00`\n"
                f"- 资产清单SHA-256：`{inventory_fingerprint}`\n"
                f"- 规则版本：`{auditor.RULE_VERSION}`\n"
                f"- 规则SHA-256：`{'a' * 64}`\n"
                f"- 结构SHA-256：`{'d' * 64}`\n"
                "- 规则冻结时间：`2026-08-03T00:00:01+08:00`\n",
                encoding="utf-8",
            )
            kwargs["stdout"].write("审计批次=audit-fixed\n")
            kwargs["stderr"].write("只读测试\n")
            return subprocess.CompletedProcess(command, 0)

        return run

    def test_方案必须精确冻结且拒绝未知字段和目标漂移(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            plan = self.module.load_plan(plan_path, inventory, AUDITOR_PATH)
            self.assertEqual(["ubuntu"], plan["允许SSH目标"])

            invalid = deepcopy(valid_plan(inventory))
            invalid["额外字段"] = True
            write_plan(plan_path, invalid)
            with self.assertRaisesRegex(ValueError, "未知字段"):
                self.module.load_plan(plan_path, inventory, AUDITOR_PATH)

            invalid = valid_plan(inventory)
            invalid["允许SSH目标"] = ["root@ubuntu"]
            write_plan(plan_path, invalid)
            with self.assertRaisesRegex(ValueError, "SSH"):
                self.module.load_plan(plan_path, inventory, AUDITOR_PATH)

    def test_清单指纹和资源上限漂移时拒绝执行(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            plan = valid_plan(inventory)
            plan["资产清单指纹"] = "0" * 64
            write_plan(plan_path, plan)
            with self.assertRaisesRegex(ValueError, "清单指纹"):
                self.module.load_plan(plan_path, inventory, AUDITOR_PATH)

            plan = valid_plan(inventory)
            plan["资源上限"]["最大成员数"] = 1
            write_plan(plan_path, plan)
            loaded = self.module.load_plan(plan_path, inventory, AUDITOR_PATH)
            with self.assertRaisesRegex(ValueError, "成员数"):
                self.module.build_member_manifest(inventory, loaded, self.auditor)

    def test_底层审计器符号链接被拒绝(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            auditor_link = root / "auditor.py"
            auditor_link.symlink_to(AUDITOR_PATH)

            with self.assertRaisesRegex(ValueError, "普通文件"):
                self.module.load_plan(plan_path, inventory, auditor_link)

    def test_成员清单顺序确定且不猜测精确作用域(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            plan = self.module.load_plan(plan_path, inventory, AUDITOR_PATH)
            members = self.module.build_member_manifest(inventory, plan, self.auditor)

        self.assertEqual(["DS-000001", "DS-000002"], [row["资产编号"] for row in members])
        self.assertTrue(all(row["精确作用域状态"] == "无法判定" for row in members))
        self.assertNotIn("主机地址", members[0])

    def test_状态守恒且输入漂移优先判为拒绝(self):
        quality, gaps, anomalies = output_rows(self.auditor, "e" * 64)
        quality[0]["扫描状态"] = "输入漂移"
        quality[0]["可用性结论"] = "无法判定"
        summary = self.module.build_summary(quality, gaps, anomalies, valid_plan_for_summary())

        states = summary["主状态计数"]
        self.assertEqual(2, summary["候选总体"])
        self.assertEqual(1, states["拒绝"])
        self.assertEqual(1, states["无法判定"])
        self.assertEqual(2, sum(states.values()))

    def test_超时不能映射为通过且未知数值不补零(self):
        quality, gaps, anomalies = output_rows(self.auditor, "e" * 64)
        quality[0]["扫描状态"] = "超时"
        quality[0]["可用性结论"] = "可用"
        summary = self.module.build_summary(quality, gaps, anomalies, valid_plan_for_summary())

        self.assertEqual(1, summary["主状态计数"]["失败"])
        self.assertEqual(1, summary["质量指标"]["记录数"]["无法判定成员数"])
        self.assertEqual(10, summary["质量指标"]["记录数"]["已知合计"])

    def test_真实编排生成不可变批次和追加索引(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            batch_root = root / "batches"
            frozen = dt.datetime(2026, 8, 3, 1, 2, 3, tzinfo=dt.timezone(dt.timedelta(hours=8)))
            runner = self.fake_runner(sha256(inventory))

            batch = self.module.execute_batch(
                inventory,
                plan_path,
                "ubuntu",
                batch_root,
                3600,
                auditor_path=AUDITOR_PATH,
                runner=runner,
                now=frozen,
            )
            manifest = json.loads((batch / "验证清单.json").read_text(encoding="utf-8"))
            with (batch_root / "批次索引.csv").open(encoding="utf-8", newline="") as handle:
                index_rows = list(csv.DictReader(handle))

            self.assertEqual("audit-fixed", manifest["底层审计批次"])
            self.assertEqual(sha256(inventory), manifest["资产清单指纹"])
            self.assertEqual("a" * 64, manifest["规则指纹"])
            self.assertEqual(2, manifest["结果摘要"]["候选总体"])
            self.assertEqual(2, sum(manifest["结果摘要"]["主状态计数"].values()))
            self.assertEqual(1, len(index_rows))
            self.assertEqual(batch.name, index_rows[0]["验证批次"])
            self.assertEqual(
                {"验证清单.json", "数据质量结果.csv", "数据断档结果.csv", "数据异常结果.csv", "验证报告.md"},
                {path.name for path in batch.iterdir()},
            )

            before = {path.name: sha256(path) for path in batch.iterdir()}
            with self.assertRaisesRegex(FileExistsError, "已存在"):
                self.module.execute_batch(
                    inventory,
                    plan_path,
                    "ubuntu",
                    batch_root,
                    3600,
                    auditor_path=AUDITOR_PATH,
                    runner=runner,
                    now=frozen,
                )
            self.assertEqual(before, {path.name: sha256(path) for path in batch.iterdir()})

    def test_同身份批次可比较而方案漂移不可比较(self):
        previous = {
            "验证批次": "dqv-previous",
            "方案指纹": "1" * 64,
            "规则指纹": "2" * 64,
            "资产清单指纹": "3" * 64,
            "Schema指纹": "4" * 64,
            "作用域指纹": "5" * 64,
            "结果摘要": {"对比指标": {"记录数已知合计": 10, "拒绝数": 1}},
        }
        current = {key: value for key, value in previous.items() if key != "结果摘要"}
        current["结果摘要"] = {"对比指标": {"记录数已知合计": 12, "拒绝数": 1}}
        result = self.module.compare_with_previous(previous, current)
        self.assertEqual("可比较", result["比较状态"])
        self.assertEqual(2, result["指标变化"]["记录数已知合计"])

        current["作用域指纹"] = "9" * 64
        result = self.module.compare_with_previous(previous, current)
        self.assertEqual("不可比较", result["比较状态"])
        self.assertIn("作用域指纹", result["原因"])

    def test_失败日志脱敏且不发布半批次(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            batch_root = root / "batches"

            def failed_runner(command, **kwargs):
                kwargs["stderr"].write("remote-internal-detail-must-not-leak\n")
                return subprocess.CompletedProcess(command, 1)

            with self.assertRaisesRegex(RuntimeError, "底层只读审计失败") as caught:
                self.module.execute_batch(
                    inventory,
                    plan_path,
                    "ubuntu",
                    batch_root,
                    30,
                    auditor_path=AUDITOR_PATH,
                    runner=failed_runner,
                )

            self.assertNotIn("remote-internal-detail-must-not-leak", str(caught.exception))
            self.assertFalse((batch_root / "批次索引.csv").exists())
            self.assertEqual([], [path for path in batch_root.glob("dqv-*")])

    def test_批次超时和输出超限均不发布(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, plan_path = self.make_inputs(root)
            batch_root = root / "batches"

            def timeout_runner(command, **kwargs):
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])

            with self.assertRaisesRegex(RuntimeError, "批次超时"):
                self.module.execute_batch(
                    inventory,
                    plan_path,
                    "ubuntu",
                    batch_root,
                    30,
                    auditor_path=AUDITOR_PATH,
                    runner=timeout_runner,
                )
            self.assertFalse((batch_root / "批次索引.csv").exists())

            plan = valid_plan(inventory)
            plan["资源上限"]["最大输出字节数"] = 1024
            write_plan(plan_path, plan)
            with self.assertRaisesRegex(ValueError, "大小上限"):
                self.module.execute_batch(
                    inventory,
                    plan_path,
                    "ubuntu",
                    batch_root,
                    30,
                    auditor_path=AUDITOR_PATH,
                    runner=self.fake_runner(sha256(inventory)),
                )
            self.assertFalse((batch_root / "批次索引.csv").exists())


def valid_plan_for_summary() -> dict[str, object]:
    return {
        "状态映射": {
            "可用": "通过",
            "有限可用": "拒绝",
            "不可用": "拒绝",
            "无法判定": "无法判定",
        }
    }


if __name__ == "__main__":
    unittest.main()
