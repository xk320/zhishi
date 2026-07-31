import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


仓库根目录 = Path(__file__).resolve().parents[2]
评估器 = 仓库根目录 / "scripts/审计/评估最小数据闭环.py"
配置 = 仓库根目录 / "config/审计/最小数据闭环容量.json"
审计目录 = 仓库根目录 / "artifacts/审计"


class 最小数据闭环评估测试(unittest.TestCase):
    def 运行评估(
        self,
        输出: Path,
        quality: Path | None = None,
        config: Path | None = None,
    ):
        return subprocess.run(
            [
                sys.executable,
                str(评估器),
                "--inventory",
                str(审计目录 / "数据源清单.csv"),
                "--quality",
                str(quality or 审计目录 / "数据质量结果.csv"),
                "--gaps",
                str(审计目录 / "数据断档结果.csv"),
                "--anomalies",
                str(审计目录 / "数据异常结果.csv"),
                "--replay",
                str(审计目录 / "历史重放结果.csv"),
                "--config",
                str(config or 配置),
                "--capacity-output",
                str(输出),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_冻结证据生成可重算容量并禁止基准模型阶段(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            输出 = Path(临时目录) / "容量.csv"
            结果 = self.运行评估(输出)

            self.assertEqual(结果.returncode, 0, 结果.stderr)
            摘要 = json.loads(结果.stdout)
            self.assertEqual(摘要["验证单元数"], 315)
            self.assertEqual(摘要["重放拒绝数"], 4)
            self.assertEqual(摘要["重放无法判定数"], 311)
            self.assertEqual(摘要["基准模型阶段"], "禁止")

            with 输出.open(encoding="utf-8", newline="") as 文件:
                行 = list(csv.DictReader(文件))
            self.assertEqual(len(行), 15)
            self.assertEqual(
                [记录["期限月数"] for 记录 in 行 if 记录["数据族"] == "总计"],
                ["3", "6", "12"],
            )
            for 月数 in ("3", "6", "12"):
                明细 = [
                    记录
                    for 记录 in 行
                    if 记录["期限月数"] == 月数 and 记录["数据族"] != "总计"
                ]
                总计 = next(
                    记录
                    for 记录 in 行
                    if 记录["期限月数"] == 月数 and 记录["数据族"] == "总计"
                )
                for 字段 in (
                    "基础字节数",
                    "质量血缘字节数",
                    "副本后字节数",
                    "安全余量后字节数",
                ):
                    self.assertEqual(
                        int(总计[字段]),
                        sum(int(记录[字段]) for 记录 in 明细),
                    )

    def test_质量结论漂移时拒绝发布并保留旧产物(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            临时路径 = Path(临时目录)
            质量副本 = 临时路径 / "质量.csv"
            shutil.copy2(审计目录 / "数据质量结果.csv", 质量副本)
            with 质量副本.open(encoding="utf-8", newline="") as 文件:
                读取器 = csv.DictReader(文件)
                表头 = list(读取器.fieldnames or [])
                行 = list(读取器)
            行[0]["可用性结论"] = "可用"
            with 质量副本.open("w", encoding="utf-8", newline="") as 文件:
                写入器 = csv.DictWriter(文件, fieldnames=表头, lineterminator="\n")
                写入器.writeheader()
                写入器.writerows(行)
            临时配置 = 临时路径 / "配置.json"
            配置内容 = json.loads(配置.read_text(encoding="utf-8"))
            配置内容["证据合同"]["输入文件指纹"]["质量结果"] = hashlib.sha256(
                质量副本.read_bytes()
            ).hexdigest()
            临时配置.write_text(
                json.dumps(配置内容, ensure_ascii=False),
                encoding="utf-8",
            )

            输出 = 临时路径 / "容量.csv"
            输出.write_text("旧产物\n", encoding="utf-8")
            结果 = self.运行评估(
                输出,
                quality=质量副本,
                config=临时配置,
            )

            self.assertEqual(结果.returncode, 2)
            self.assertIn("质量结论分布", 结果.stderr)
            self.assertEqual(输出.read_text(encoding="utf-8"), "旧产物\n")

    def test_冻结证据正文漂移时拒绝发布(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            临时路径 = Path(临时目录)
            质量副本 = 临时路径 / "质量.csv"
            shutil.copy2(审计目录 / "数据质量结果.csv", 质量副本)
            with 质量副本.open(encoding="utf-8", newline="") as 文件:
                读取器 = csv.DictReader(文件)
                表头 = list(读取器.fieldnames or [])
                行 = list(读取器)
            行[0]["依据"] = f"{行[0]['依据']}；未登记变化"
            with 质量副本.open("w", encoding="utf-8", newline="") as 文件:
                写入器 = csv.DictWriter(文件, fieldnames=表头, lineterminator="\n")
                写入器.writeheader()
                写入器.writerows(行)

            输出 = 临时路径 / "容量.csv"
            结果 = self.运行评估(输出, quality=质量副本)

            self.assertEqual(结果.returncode, 2)
            self.assertIn("文件指纹", 结果.stderr)
            self.assertFalse(输出.exists())

    def test_相同冻结输入重复运行产生完全相同结果(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            临时路径 = Path(临时目录)
            第一次输出 = 临时路径 / "第一次.csv"
            第二次输出 = 临时路径 / "第二次.csv"

            第一次 = self.运行评估(第一次输出)
            第二次 = self.运行评估(第二次输出)

            self.assertEqual(第一次.returncode, 0, 第一次.stderr)
            self.assertEqual(第二次.returncode, 0, 第二次.stderr)
            self.assertEqual(第一次.stdout, 第二次.stdout)
            self.assertEqual(第一次输出.read_bytes(), 第二次输出.read_bytes())

    def test_容量配置不接受浮点预算(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            临时路径 = Path(临时目录)
            临时配置 = 临时路径 / "配置.json"
            配置内容 = json.loads(配置.read_text(encoding="utf-8"))
            配置内容["数据族"][0]["单记录预算字节数"] = 256.5
            临时配置.write_text(
                json.dumps(配置内容, ensure_ascii=False),
                encoding="utf-8",
            )

            输出 = 临时路径 / "容量.csv"
            结果 = self.运行评估(输出, config=临时配置)

            self.assertEqual(结果.returncode, 2)
            self.assertIn("正整数", 结果.stderr)
            self.assertFalse(输出.exists())

    def test_容量配置拒绝表格公式前缀(self):
        with tempfile.TemporaryDirectory() as 临时目录:
            临时路径 = Path(临时目录)
            临时配置 = 临时路径 / "配置.json"
            配置内容 = json.loads(配置.read_text(encoding="utf-8"))
            配置内容["数据族"][0]["名称"] = "=1+1"
            临时配置.write_text(
                json.dumps(配置内容, ensure_ascii=False),
                encoding="utf-8",
            )

            输出 = 临时路径 / "容量.csv"
            结果 = self.运行评估(输出, config=临时配置)

            self.assertEqual(结果.returncode, 2)
            self.assertIn("表格公式", 结果.stderr)
            self.assertFalse(输出.exists())


if __name__ == "__main__":
    unittest.main()
