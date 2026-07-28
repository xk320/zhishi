# 任务-000004数据质量审计实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** 以任务-000003资产清单为冻结白名单，通过两阶段只读探针量化可证明的数据
质量事实，生成三份CSV、BTC/ETH/SOL独立结论报告、可复现脚本和测试。

**Architecture:** 本地Python工具校验清单后，通过SSH标准输入执行固定远端Python
探针。第一阶段只发现结构并冻结规则指纹；第二阶段流式审计CSV/JSONL，以只读连接
审计SQLite，并只读取MySQL元数据。所有对象都产生结果或明确未执行原因，本地统一
脱敏、排序和原子发布三份CSV与Markdown报告。

**Tech Stack:** Python 3标准库、OpenSSH、CSV、JSON、SQLite、MySQL CLI元数据查询、
`unittest`、Markdown。

---

## Task 1: 固定执行合同与设计

**Files:**

- Modify: `docs/研发中心/任务/任务-000004.md`
- Modify: `docs/研发中心/看板.md`
- Create: `docs/superpowers/specs/2026-07-28-data-quality-audit-design.md`
- Create: `docs/superpowers/plans/2026-07-28-data-quality-audit.md`

- [x] **Step 1: 确认无重复执行**

检查远程分支和未关闭PR，不存在任务-000004的在途执行。

- [x] **Step 2: 创建分支并同步执行中状态**

创建`codex/000004-data-quality-audit-v1`，记录开始时间、输入合同、输出合同、范围、
安全边界、验收标准和完成定义；看板从待执行移动到执行中。

- [x] **Step 3: 固化方案A设计**

设计明确两阶段规则冻结、逐资产覆盖、MySQL仅元数据、文件和SQLite只读内容统计、
保守可用性判定、资源上限、失败安全和测试策略。

- [x] **Step 4: 验证并提交规划**

Run:

```bash
npx --yes markdownlint-cli2 \
  docs/研发中心/任务/任务-000004.md \
  docs/研发中心/看板.md \
  docs/superpowers/specs/2026-07-28-data-quality-audit-design.md \
  docs/superpowers/plans/2026-07-28-data-quality-audit.md
git diff --check
git commit -m 'docs: 规划任务000004数据质量审计'
```

Expected: Markdown为0 issues，空白检查通过，规划形成独立提交。

## Task 2: 用失败测试定义审计输入与安全合同

**Files:**

- Create: `tests/审计/test_审计数据质量.py`
- Test: `tests/审计/test_审计数据质量.py`

- [x] **Step 1: 写实现存在性与模块加载测试**

测试先断言`scripts/审计/审计数据质量.py`存在，再使用`importlib`加载。实现缺失时必须
因“实现文件尚不存在”失败，不能因夹具、编码或导入错误失败。

- [x] **Step 2: 写清单校验测试**

用临时CSV覆盖以下行为：

```python
assets = audit.load_inventory(path)
self.assertEqual(["DS-000001", "DS-000002"], [a["资产编号"] for a in assets])
```

断言缺列、多个发现批次、重复编号、不支持格式、非白名单路径、相对路径、路径逃逸、
符号链接语义和非法SSH别名被拒绝；仅`候选数据文件`与`数据库元数据`进入验证单元。

- [x] **Step 3: 写固定探针安全测试**

断言`REMOTE_AUDIT_PROGRAM`包含`mode=ro`、`query_only`、`--no-defaults`和
`information_schema`，且不包含`sudo`、写文件、环境变量读取、凭据搜索、服务控制、
数据库写语句、`ATTACH`或`VACUUM`。SSH命令必须为参数数组并使用`BatchMode=yes`。

- [x] **Step 4: 运行测试并确认正确失败**

Run:

```bash
python3 -m unittest tests/审计/test_审计数据质量.py -v
```

Expected: 因实现文件不存在失败；失败信息精确指向缺失实现。

## Task 3: 实现清单校验、结构规则与安全远程调用

**Files:**

- Create: `scripts/审计/审计数据质量.py`
- Modify: `tests/审计/test_审计数据质量.py`

- [x] **Step 1: 实现固定合同常量与清单校验**

实现`load_inventory(Path)`、`validate_ssh_target(str)`、
`inventory_fingerprint(Path)`和`build_validation_units(rows)`四个公开接口，并通过
以下调用合同：

```python
AUDIT_VERSION = "1.0"
RULE_VERSION = "dq-rules-1.0"
rows = load_inventory(Path("artifacts/审计/数据源清单.csv"))
target = validate_ssh_target("ubuntu")
fingerprint = inventory_fingerprint(Path("artifacts/审计/数据源清单.csv"))
units = build_validation_units(rows)
```

`load_inventory`验证任务-000003固定列和单一发现批次；`build_validation_units`只接收
CSV、JSONL、NDJSON、SQLite和InnoDB元数据，并验证路径位于固定白名单内。

- [x] **Step 2: 实现结构结果校验与规则冻结**

实现`validate_schema_payload(payload, units)`和`freeze_rules(schema_payload)`，满足：

```python
validated_schema = validate_schema_payload(schema_payload, units)
rules, rules_sha256 = freeze_rules(validated_schema)
assert len(rules_sha256) == 64
```

冻结结果包含验证单元身份、字段、类型、SQLite主键、时间候选和每项规则状态。列名只
形成候选，不自动映射三类时间；无正式频率时断档规则固定为`无法判定`。指纹使用排序
JSON的SHA-256。

- [x] **Step 3: 实现SSH调用与失败安全**

实现`run_remote_phase(target, phase, units, rules, ssh_bin, timeout)`并满足：

```python
schema_payload = run_remote_phase(
    "ubuntu", "schema", units, None, "ssh", 900
)
quality_payload = run_remote_phase(
    "ubuntu", "quality", units, rules, "ssh", 3600
)
```

命令使用参数数组`ssh -o BatchMode=yes -o ConnectTimeout=10`并追加固定存活检测参数、
`ubuntu python3 -`，把版本、
阶段、已校验资产和规则嵌入固定程序输入；不调用shell。非零退出、超时、非法JSON、
版本不匹配和对象集合漂移均抛出中文错误，不回显远端标准错误正文。

- [x] **Step 4: 运行输入与安全合同测试**

Run:

```bash
python3 -m unittest tests/审计/test_审计数据质量.py -v
```

Expected: 清单、规则冻结、安全探针和SSH失败测试全部通过。

## Task 4: 用失败测试定义质量统计与输出合同

**Files:**

- Modify: `tests/审计/test_审计数据质量.py`
- Test: `tests/审计/test_审计数据质量.py`

- [x] **Step 1: 写远端统计夹具测试**

通过模块提供的本地探针测试入口，在临时目录建立：

- CSV：两条规范重复、一个空字段、一条列宽错误；
- JSONL：两个规范重复对象、一个空行、一个非法JSON、一个非对象JSON；
- SQLite：一张带主键表，包含空值。

断言记录数、字段数、缺失数、精确重复数、解析异常数和扫描完整状态准确。测试入口与
SSH运行使用同一审计函数，不另写测试专用实现。

- [x] **Step 2: 写时间与断档保守判定测试**

夹具字段包含`event_time`、`arrival_time`和`collected_at`，断言它们只出现在候选
字段中，三类时间合同、延迟、乱序和断档仍为`无法判定`；没有规则时不得执行统计。

- [x] **Step 3: 写CSV、报告与脱敏测试**

断言：

```python
quality, gaps, anomalies = audit.build_output_rows(
    units, schema_payload, quality_payload, frozen_rules, run_metadata
)
self.assertEqual(len(units), len(quality))
self.assertEqual(len(units), len(gaps))
self.assertTrue(all(a["资产编号"] for a in anomalies))
```

三份CSV共享批次和规则指纹、列固定、按资产编号排序、防公式注入；报告包含事实、判定、
建议及BTC、ETH、SOL独立结论。IPv4、私钥头、令牌和明文凭据不得进入任一产物。

- [x] **Step 4: 运行新增测试并确认缺失行为导致失败**

Run:

```bash
python3 -m unittest tests/审计/test_审计数据质量.py -v
```

Expected: 新测试因统计与输出函数尚未实现而失败，不是夹具错误。

## Task 5: 实现远端统计、产物生成与CLI

**Files:**

- Modify: `scripts/审计/审计数据质量.py`
- Modify: `tests/审计/test_审计数据质量.py`

- [x] **Step 1: 实现CSV和JSONL流式统计**

CSV以`newline=""`和UTF-8替换模式读取；JSONL逐行解析。实现记录数、结构空值、列宽、
空行、非法JSON、非对象、字段并集和规范记录SHA-256重复。重复集合上限固定并在超限
时把重复状态改为`无法判定`，不得将部分重复数写成全量。

- [x] **Step 2: 实现SQLite与MySQL元数据审计**

SQLite使用`file:<path>?mode=ro`和`PRAGMA query_only=ON`，逐表统计行数与NULL/空文本，
主键仅来自`PRAGMA table_info`。MySQL只使用`information_schema.COLUMNS`、
`STATISTICS`和`TABLES`元数据，记录行数估计与结构，不查询业务表内容。

- [x] **Step 3: 实现输出归一化与报告**

实现`build_output_rows`、`render_csv`、`render_report`和`publish_outputs`，调用合同为：

```python
quality, gaps, anomalies = build_output_rows(
    units, schema_payload, quality_payload, frozen_rules, run_metadata
)
quality_csv = render_csv(QUALITY_COLUMNS, quality)
report = render_report(quality, gaps, anomalies, run_metadata)
publish_outputs({quality_path: quality_csv, report_path: report})
```

每个验证单元必须有质量、断档和至少一条异常汇总记录。报告按事实、判定、建议分节；
BTC、ETH、SOL在缺少标的身份、三类时间、重放或闭环证据时为`无法判定`，并列出解除
条件。四个产物先在内存生成并通过敏感扫描，再以本地临时文件替换；失败不覆盖旧文件。

- [x] **Step 4: 实现CLI和本地探针测试入口**

CLI参数固定为`--inventory`、`--ssh-target`、`--ssh-bin`、`--timeout`、
`--output-dir`和`--report`。成功输出审计批次、规则指纹、验证单元数和三份CSV路径；
失败只输出中文错误类别并返回非零。

- [x] **Step 5: 运行测试并提交实现**

Run:

```bash
python3 -m unittest tests/审计/test_审计数据质量.py -v
git add scripts/审计/审计数据质量.py tests/审计/test_审计数据质量.py
git commit -m 'feat: 建立只读数据质量审计器'
```

Expected: 任务-000004单元测试全部通过，形成实现提交。

## Task 6: 在目标环境执行只读审计

**Files:**

- Create: `artifacts/审计/数据质量结果.csv`
- Create: `artifacts/审计/数据断档结果.csv`
- Create: `artifacts/审计/数据异常结果.csv`
- Create: `docs/审计/数据质量审计报告.md`

- [x] **Step 1: 运行真实两阶段审计**

Run:

```bash
python3 scripts/审计/审计数据质量.py \
  --inventory artifacts/审计/数据源清单.csv \
  --ssh-target ubuntu \
  --output-dir artifacts/审计 \
  --report docs/审计/数据质量审计报告.md
```

Expected: 远端无落盘；每个验证单元有覆盖或失败原因；四个产物共享审计批次、清单指纹
和规则指纹。运行较长时通过进度输出确认当前对象，不制造虚假完成。

- [x] **Step 2: 核对覆盖与敏感信息**

用只读Python核对质量和断档CSV行数等于验证单元数、异常CSV覆盖全部资产编号、批次与
指纹一致。扫描IPv4、私钥头、GitHub/云令牌和明文凭据；任何命中先停止发布并修复。

- [x] **Step 3: 核对BTC、ETH、SOL独立结论**

确认报告没有把候选文件名当作标的身份，没有借用其他标的证据，没有在任务-000005
和任务-000006完成前给出`可用`，每项`无法判定`都含解除条件。

- [x] **Step 4: 提交真实审计产物**

Run:

```bash
git add artifacts/审计/数据质量结果.csv \
  artifacts/审计/数据断档结果.csv \
  artifacts/审计/数据异常结果.csv \
  docs/审计/数据质量审计报告.md
git commit -m 'docs: 记录数据质量只读审计结果'
```

## Task 7: 完整验收并创建Pull Request

**Files:**

- Modify: `docs/研发中心/任务/任务-000004.md`
- Modify: `docs/研发中心/看板.md`
- Modify: `docs/superpowers/plans/2026-07-28-data-quality-audit.md`

- [x] **Step 1: 运行完整验证**

Run:

```bash
python3 -m unittest tests/审计/test_审计数据质量.py -v
python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
python3 -m unittest discover -s tests/审计 -p 'test_*.py' -v
npx --yes markdownlint-cli2 \
  docs/superpowers/specs/2026-07-28-data-quality-audit-design.md \
  docs/superpowers/plans/2026-07-28-data-quality-audit.md \
  docs/审计/数据质量审计报告.md \
  docs/研发中心/任务/任务-000004.md \
  docs/研发中心/看板.md
git diff --check origin/main...HEAD
```

Expected: 全部测试通过、Markdown为0 issues、无空白错误。

- [x] **Step 2: 自审安全和任务合同**

确认没有服务器或数据库写入、没有原始记录或凭据进入仓库、没有未来数据使用、没有
训练/回测/交易代码、没有虚构统计，且任务全部交付物和验收项都有证据。

- [x] **Step 3: 推送实现并创建PR**

PR正文引用任务-000004，列出修改内容、交付物、验收结果、实际验证命令、已知限制、
数据与安全影响和回滚方式。任务类型为数据审计且包含脚本、测试和CSV，只能人工合并。

- [x] **Step 4: 更新任务和看板为待评审**

任务记录分支、实现提交SHA、PR编号、交付物、验证结果、已知限制、数据与安全影响、
人工决策和下一任务。看板同步从执行中移动到待评审，状态更新提交到同一PR。

- [x] **Step 5: 推送最终状态并复核PR**

Run:

```bash
git push origin codex/000004-data-quality-audit-v1
env -u GITHUB_TOKEN gh pr view --repo xk320/zhishi --json number,url,state,headRefName,baseRefName
```

Expected: PR为OPEN、目标`main`、来源分支正确；任务和看板均为`待评审`，不自行合并。
