from __future__ import annotations
import importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/"scripts/数据/验证成本执行闭环.py"
def load():
 spec=importlib.util.spec_from_file_location("cost_exec",PATH); assert spec and spec.loader; m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
class CostExecutionTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls): cls.m=load(); cls.config=json.loads((ROOT/"config/数据/成本执行来源.json").read_text(encoding="utf-8"))
 def test_固定输入成员(self):
  rows,manifest=self.m.load_members(ROOT,self.config); self.assertEqual(len(rows),630); self.assertEqual(manifest["状态计数"]["通过"],0)
 def test_缺少来源不生成通过(self):
  rows,manifest=self.m.load_members(ROOT,self.config); out=self.m.build_rows("cost-20260805T014500+0800-000000000000",rows,"a"*64); self.assertNotIn("通过",{r["结论"] for r in out}); self.assertEqual(len(out),630)
 def test_配置输入不可替换(self):
  bad=json.loads(json.dumps(self.config)); bad["输入"]["可信重放清单"]["SHA-256"]="0"*64
  with self.assertRaises(ValueError): self.m.config_ok(bad)
 def test_只允许四个主尺度(self): self.assertEqual(tuple(self.config["主研究尺度"]),("4小时","8小时","24小时","48小时"))
if __name__=="__main__": unittest.main()
