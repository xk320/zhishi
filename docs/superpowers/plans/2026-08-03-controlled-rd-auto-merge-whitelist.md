# 《知势》受控研发自动合并白名单扩展实施计划

<!-- markdownlint-disable MD013 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不开放真实资金、生产写入、凭据和原始数据破坏权限的前提下，让任务登记、数据研发、策略研究与模拟交易研发可以通过现有可信工作流自动评审、修复、合并和闭环。

**Architecture:** 保留`main`为唯一可信控制面，在现有资格检查器中加入三层组合门：基线任务类型或治理范围、严格PR变更类型、Git路径与对象事实。所有事实从基线和头提交的Git对象读取，不执行PR头代码；最终仍由双子智能体证据、当前头检查和精确SHA合并控制。

**Tech Stack:** Python 3标准库、`unittest`、Git对象命令、GitHub Actions、Markdown。

---

## 文件结构

- 修改：`tests/研发中心/test_项目范围与阶段状态.py`
  - 当前登记自举时同步任务数量；策略实现后改为稳定的编号唯一、历史缺口与单调新增检查。
- 修改：`tests/研发中心/test_验证自动合并资格.py`
  - 覆盖新任务类型、任务登记、路径、对象模式、体积、敏感信息及PR #44回归。
- 修改：`scripts/研发中心/验证自动合并资格.py`
  - 扩展任务类型、增加任务登记、采集Git对象事实、执行受控研发组合门。
- 修改：`.github/workflows/pr-auto-merge-eligibility.yml`
  - 保持从基线执行可信检查器；只在测试证明需要时增加有界输入或输出，不执行PR头代码。
- 修改：`.github/workflows/pr-auto-merge.yml`
  - 保持实时检查、证据与精确SHA合并；只同步新变更类型说明，不降低任何实时硬门。
- 修改：`AGENTS.md`
- 修改：`README.md`
- 修改：`docs/研发中心/README.md`
- 修改：`docs/研发中心/任务规范.md`
- 修改：`docs/研发中心/Codex自动执行提示词.md`
- 修改：`docs/治理/PR自动合并策略.md`
  - 统一受控研发自动化规则、模拟交易边界和自举限制。
- 修改：`docs/研发中心/任务/任务-000039.md`
- 修改：`docs/研发中心/看板.md`
  - 记录认领、交付、评审和合并状态。

## Task 1：完成任务-000039登记自举

**Files:**

- Modify: `tests/研发中心/test_项目范围与阶段状态.py:98-109`
- Existing: `docs/研发中心/任务/任务-000039.md`
- Existing: `docs/研发中心/看板.md`
- Existing: `docs/superpowers/specs/2026-08-03-controlled-rd-auto-merge-whitelist-design.md`
- Existing: `docs/superpowers/plans/2026-08-03-controlled-rd-auto-merge-whitelist.md`

- [ ] **Step 1: 复现任务登记的失败测试**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest \
  tests.研发中心.test_项目范围与阶段状态.TaskCenterMappingTests.test_当前任务数量和缺号事实准确 -v
```

Expected: FAIL，显示实际任务数38而旧断言为37。

- [ ] **Step 2: 只同步登记基线，不提前实现新策略**

将断言改为：

```python
tasks = task_documents()
self.assertEqual(len(tasks), 38)
self.assertNotIn("任务-000026", tasks)
self.assertIn("任务-000039", tasks)
```

保留任务-000028历史文字断言，避免登记任务时改写历史证据。

- [ ] **Step 3: 验证登记合同、看板和Markdown**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
NODE_OPTIONS=--max-old-space-size=256 \
  npx --yes --offline markdownlint-cli2 \
  'docs/superpowers/specs/2026-08-03-controlled-rd-auto-merge-whitelist-design.md' \
  'docs/superpowers/plans/2026-08-03-controlled-rd-auto-merge-whitelist.md' \
  'docs/研发中心/任务/任务-000039.md' \
  'docs/研发中心/看板.md'
git diff --check origin/main...HEAD
```

Expected: 研发中心全部测试通过，Markdown 0问题，差异检查通过。

- [ ] **Step 4: 提交并创建一次性登记PR**

```bash
git add \
  docs/superpowers/specs/2026-08-03-controlled-rd-auto-merge-whitelist-design.md \
  docs/superpowers/plans/2026-08-03-controlled-rd-auto-merge-whitelist.md \
  docs/研发中心/任务/任务-000039.md \
  docs/研发中心/看板.md \
  tests/研发中心/test_项目范围与阶段状态.py
git commit -m "test: 同步任务-000039登记基线"
git push origin codex/000039-open-controlled-auto-merge-whitelist-v1
```

PR正文使用：

```markdown
## 关联任务

- 任务-000039（仅登记合同，不执行）

## 变更类型

- 任务登记
```

现行`main`尚不认识`任务登记`，资格检查预期失败。记录失败证据，由仓库所有者人工合并
这一次自举PR；不得直接写入`main`或伪造资格成功。

## Task 2：从最新main认领任务-000039

**Files:**

- Modify: `docs/研发中心/任务/任务-000039.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 确认登记合并和无重复执行**

```bash
git fetch origin main
git show origin/main:docs/研发中心/任务/任务-000039.md
gh pr list --repo xk320/zhishi \
  --search 'head:codex/000039- status:open' \
  --json number,headRefName,state,url
git ls-remote --heads origin 'codex/000039-*'
```

Expected: `origin/main`存在状态为`待执行`的任务-000039；除登记分支外没有执行分支或开放
执行PR。

- [ ] **Step 2: 创建执行分支并更新为执行中**

```bash
git switch main
git pull --ff-only origin main
git switch -c codex/000039-controlled-rd-auto-merge-implementation-v1
```

任务头更新为：

```markdown
- 状态：执行中
- 执行分支：`codex/000039-controlled-rd-auto-merge-implementation-v1`
- 开始时间：执行器运行`TZ=Asia/Shanghai date +%Y-%m-%dT%H:%M:%S%z`后写入返回的完整值
```

看板把任务-000039从`待执行`移动到`执行中`，任务-000029保持其远程PR中的在途状态，
不得改写其实现或真实批次。

- [ ] **Step 3: 验证并提交认领**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v
git diff --check
git add docs/研发中心/任务/任务-000039.md docs/研发中心/看板.md
git commit -m "chore: 认领任务-000039"
git push -u origin codex/000039-controlled-rd-auto-merge-implementation-v1
```

Expected: 状态与看板一致，提交和推送成功。

## Task 3：用失败测试定义受控研发任务与路径

**Files:**

- Modify: `tests/研发中心/test_验证自动合并资格.py`
- Modify: `scripts/研发中心/验证自动合并资格.py`

- [ ] **Step 1: 扩展测试夹具表达Git对象事实**

在测试文件增加：

```python
def regular_fact(path: str, *, size: int = 128, text: str = ""):
    return {
        "path": path,
        "status": "A",
        "mode": "100644",
        "object_type": "blob",
        "size": size,
        "text": text,
    }
```

`evaluate()`默认把每条`changed_paths`转换为普通、小型、无敏感信息的事实，并允许测试通过
`path_facts`覆盖边界。

- [ ] **Step 2: 写允许类型和PR #44路径的失败测试**

增加表驱动测试：

```python
def test_受控研发类型允许自动合并(self):
    for task_type in (
        "数据治理", "数据审计", "数据工程", "基础设施验证",
        "策略研究", "研究工程", "模拟交易", "测试", "工具",
    ):
        with self.subTest(task_type=task_type):
            result = self.evaluate(
                changed_paths=[
                    "config/数据/规则.json",
                    "scripts/数据/验证.py",
                    "tests/数据/test_验证.py",
                    "artifacts/数据/批次/清单.csv",
                    "docs/研发中心/任务/任务-000013.md",
                ],
                base_tasks={"000013": task_text(status="待执行", task_type=task_type)},
                head_tasks={"000013": task_text(status="待评审", task_type=task_type)},
            )
            self.assertTrue(result.eligible, result.reasons)
```

另加`test_pr44数据治理路径通过受控研发白名单`，使用PR #44的九条精确路径，断言资格通过。

- [ ] **Step 3: 写高风险类型和路径的失败测试**

```python
def test_高风险和未知类型继续拒绝(self):
    for task_type in ("真实交易", "资金管理", "生产运维", "凭据管理", "未知"):
        result = self.evaluate(
            base_tasks={"000013": task_text(status="待执行", task_type=task_type)},
            head_tasks={"000013": task_text(status="待评审", task_type=task_type)},
        )
        self.assertFalse(result.eligible)
```

对`.github/workflows/部署.yml`、`deploy/production.sh`、`secrets/account.env`、数据库文件、
模型权重、压缩包和媒体文件分别断言`不允许自动合并`。

- [ ] **Step 4: 运行测试确认RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_受控研发类型允许自动合并 \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_pr44数据治理路径通过受控研发白名单 \
  -v
```

Expected: FAIL，原因分别为任务类型和受控研发路径尚未允许。

- [ ] **Step 5: 实现最小类型和路径白名单**

在资格检查器定义：

```python
ALLOWED_TASK_TYPES = frozenset({
    "文档", "治理", "研究规范", "数据治理", "数据审计", "数据工程",
    "基础设施验证", "策略研究", "研究工程", "模拟交易", "测试", "工具",
})
CONTROLLED_RD_TASK_TYPES = ALLOWED_TASK_TYPES - {"文档", "治理", "研究规范"}
CONTROLLED_ROOT_SUFFIXES = {
    "config": frozenset({".json", ".yaml", ".yml", ".toml"}),
    "src": frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".json"}),
    "scripts": frozenset({".py", ".sh"}),
    "tests": frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".json"}),
    "artifacts": frozenset({".json", ".csv", ".md"}),
}

def _is_controlled_rd_path(path: str) -> bool:
    if _is_low_risk_path(path):
        return True
    pure = PurePosixPath(path)
    if len(pure.parts) < 2 or pure.parts[0] not in CONTROLLED_ROOT_SUFFIXES:
        return False
    if pure.parts[0] == "scripts" and pure.parts[1] in {"交易", "部署", "生产"}:
        return False
    return pure.suffix.lower() in CONTROLLED_ROOT_SUFFIXES[pure.parts[0]]
```

`_validate_delivery_tasks`返回路径配置枚举，而非单一布尔值：普通低风险、治理自动化或
受控研发。工作流文件始终只由治理自动化配置允许。

- [ ] **Step 6: 运行GREEN与原有拒绝回归**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
```

Expected: 新允许测试通过，原有外部仓库、状态、工作流越权和控制面重放拒绝测试仍通过。

- [ ] **Step 7: 提交**

```bash
git add scripts/研发中心/验证自动合并资格.py \
  tests/研发中心/test_验证自动合并资格.py
git commit -m "feat: 允许受控数据与模拟研发自动合并"
```

## Task 4：实现Git对象、资源和敏感信息硬门

**Files:**

- Modify: `tests/研发中心/test_验证自动合并资格.py`
- Modify: `scripts/研发中心/验证自动合并资格.py`

- [ ] **Step 1: 写对象模式和资源边界失败测试**

增加测试并确认每项单独失败：

```python
def test_受控研发拒绝非普通文件和资源越界(self):
    cases = (
        (regular_fact("scripts/数据/link.py") | {"mode": "120000"}, "符号链接"),
        (regular_fact("src/module.py") | {"mode": "100755"}, "可执行文件"),
        (regular_fact("artifacts/数据/model.bin") | {"size": 1}, "扩展名"),
        (regular_fact("artifacts/数据/large.json", size=5 * 1024 * 1024 + 1), "单文件"),
    )
    for fact, reason in cases:
        with self.subTest(reason=reason):
            result = self.evaluate_for_fact(fact)
            self.assertFalse(result.eligible)
```

另外创建501个小文件事实和26 MiB合计事实，分别断言文件数和总量拒绝。

- [ ] **Step 2: 写敏感信息失败测试**

使用测试专用假值，不使用真实凭据：

```python
def test_配置与产物中的敏感信息失败关闭且不回显(self):
    samples = (
        "-----BEGIN PRIVATE KEY-----",
        "password=smoke-only-secret",
        "token=smoke-only-token-value",
        "AKIA" + "A" * 16,
    )
    for sample in samples:
        fact = regular_fact("config/数据/规则.json", text=sample)
        result = self.evaluate_for_fact(fact)
        self.assertFalse(result.eligible)
        self.assertNotIn(sample, "；".join(result.reasons))
```

- [ ] **Step 3: 运行测试确认RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_受控研发拒绝非普通文件和资源越界 \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_配置与产物中的敏感信息失败关闭且不回显 \
  -v
```

Expected: FAIL，旧资格函数没有对象事实和资源门。

- [ ] **Step 4: 实现不可变对象事实与验证函数**

在资格检查器增加：

```python
MAX_CHANGED_FILES = 500
MAX_BLOB_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 25 * 1024 * 1024
SENSITIVE_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"(?i:\b(?:password|passwd|secret|token)\s*[:=]\s*[^\s,;]+)"
)

@dataclass(frozen=True)
class PathFact:
    path: str
    status: str
    mode: str
    object_type: str
    size: int
    text: str | None
```

实现`_validate_path_facts(path_facts, controlled_paths, reasons)`：

- 精确比较事实路径与`changed_paths`；
- 只接受`A`或`M`、`100644`、`blob`；
- 先验证非负大小、数量、单文件和总量，再扫描文本；
- 敏感命中只记录`变更文件“路径”命中敏感信息门`，不记录正文；
- 不允许缺失事实、重复路径或额外事实。

- [ ] **Step 5: 从Git安全提取事实**

增加`_load_path_facts(repo_root, base_ref, head_ref)`：

1. 使用`git diff --name-status -z --no-renames`读取状态与UTF-8路径；
2. 使用`git ls-tree -z head_ref -- path`读取模式、类型和对象ID；
3. 使用`git cat-file -s object_id`读取blob大小；
4. 只有扩展名属于文本白名单且大小不超限时，才用`git cat-file blob object_id`读取内容；
5. 解码失败记录`text=None`并由受控文本门拒绝，不忽略；
6. 所有Git子进程`check=True`、捕获输出且不把内容写入异常信息。

`main()`把事实传给`evaluate_eligibility`，输出JSON只包含路径、资格和原因，不包含文件正文。

- [ ] **Step 6: 运行GREEN和CLI集成测试**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
```

Expected: 对象与资源测试通过；现有中文NUL路径、控制面和状态闭环测试无回归。

- [ ] **Step 7: 提交**

```bash
git add scripts/研发中心/验证自动合并资格.py \
  tests/研发中心/test_验证自动合并资格.py
git commit -m "feat: 增加自动合并Git对象与资源硬门"
```

## Task 5：实现新任务登记自动资格

**Files:**

- Modify: `tests/研发中心/test_验证自动合并资格.py`
- Modify: `scripts/研发中心/验证自动合并资格.py`
- Modify: `tests/研发中心/test_项目范围与阶段状态.py`

- [ ] **Step 1: 写合法任务登记失败测试**

测试正文：

```markdown
## 关联任务

- 任务-000040

## 变更类型

- 任务登记
```

输入满足：基线无任务-000040，头新增完整合同，状态`待执行`，看板新增唯一对应行，变更只
包含任务文件、看板和`docs/superpowers/specs/`设计文档。断言`eligible=True`。

- [ ] **Step 2: 写任务登记夹带和合同缺失失败测试**

分别删除每个必需字段或章节，并测试：

- 同时登记两个任务；
- 修改既有任务；
- 状态为`执行中`、`待评审`或`已完成`；
- 夹带`scripts/`、`config/`、`artifacts/`或非设计文档；
- 看板缺行、重复行、分区错误、名称或优先级不一致；
- 任务编号不是当前最大编号加一，或复用历史缺号000026。

每项必须得到稳定原因代码，不能因解析异常放行。

- [ ] **Step 3: 运行测试确认RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_完整单任务登记允许 \
  tests.研发中心.test_验证自动合并资格.AutoMergeEligibilityTests.test_任务登记拒绝夹带和不完整合同 \
  -v
```

Expected: FAIL，旧解析器不识别`任务登记`。

- [ ] **Step 4: 实现完整合同与单调编号检查**

增加：

```python
CHANGE_TYPES = frozenset({"任务登记", "任务交付", "合并后状态闭环"})
REGISTRATION_STATUSES = frozenset({"待执行", "阻塞"})
REQUIRED_TASK_FIELDS = (
    "状态", "类型", "阶段", "优先级", "执行方案", "方案状态", "执行授权",
    "并行规则",
)
REQUIRED_TASK_HEADINGS = (
    "依赖与阻塞条件", "背景", "任务目标", "固定执行方案", "默认工程决策",
    "允许停止条件", "输入合同", "输出合同", "工作范围", "不在范围", "安全边界",
    "验收标准", "验证命令", "完成定义",
)
```

实现`_validate_task_registration`：只接受一个任务；基线任务必须不存在；头任务必须存在且
字段、标题各出现一次；方案状态必须为`已批准执行`；编号必须大于基线全部任务编号且等于
最大编号加一；禁止复用历史缺号；看板新增行可由任务标题、状态、优先级和依赖复算；除
任务、看板及同任务设计文档外无其他路径。

CLI加载基线全部任务编号，但仍只加载关联任务正文，避免把整个仓库内容传入评估器。

- [ ] **Step 5: 把固定任务总数测试改为稳定规则**

将`test_当前任务数量和缺号事实准确`改名为`test_任务编号唯一且只保留历史缺号`：

```python
tasks = task_documents()
numbers = sorted(int(task_id.removeprefix("任务-")) for task_id in tasks)
self.assertEqual(len(numbers), len(set(numbers)))
self.assertEqual([number for number in range(1, max(numbers) + 1) if number not in numbers], [26])
self.assertEqual(numbers[-1], 39)
```

其中`numbers[-1]`只作为本次登记基线，任务登记资格测试负责保证以后只能按最大编号加一，
不再要求每个后续登记PR修改固定任务总数。

- [ ] **Step 6: 运行GREEN**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v
```

Expected: 新任务登记成功与拒绝测试、任务映射测试全部通过。

- [ ] **Step 7: 提交**

```bash
git add scripts/研发中心/验证自动合并资格.py \
  tests/研发中心/test_验证自动合并资格.py \
  tests/研发中心/test_项目范围与阶段状态.py
git commit -m "feat: 支持完整任务合同自动登记"
```

## Task 6：同步治理合同和工作流边界

**Files:**

- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `docs/研发中心/README.md`
- Modify: `docs/研发中心/任务规范.md`
- Modify: `docs/研发中心/Codex自动执行提示词.md`
- Modify: `docs/治理/PR自动合并策略.md`
- Modify if tests require: `.github/workflows/pr-auto-merge-eligibility.yml`
- Modify if tests require: `.github/workflows/pr-auto-merge.yml`

- [ ] **Step 1: 写文档一致性失败测试**

在现有研发中心治理测试中加入精确断言：

```python
required_phrases = (
    "任务登记", "数据治理", "数据审计", "数据工程", "基础设施验证",
    "策略研究", "模拟交易", "真实资金", "生产写入", "精确头SHA",
)
```

对上述六份现行治理入口逐项检查，不允许README继续声称“其他PR人工合并”。工作流检查
继续断言`pull_request_target`不存在、Action固定SHA、PR头代码不执行。

- [ ] **Step 2: 运行测试确认RED**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
```

Expected: FAIL，现行文档仍是低风险白名单表述。

- [ ] **Step 3: 更新六份治理入口**

统一表达：

- 系统只进行策略研究和实时数据模拟交易，不连接真实资金；
- 合格任务默认走任务登记、交付、评审、修复、验证、合并和状态闭环自动化；
- 允许类型、路径、Git对象、文件数量和体积使用精确白名单；
- 真实资金、生产写入、凭据、原始数据破坏和不可逆操作仍停止请求人工授权；
- GitHub Free轻量可信工作流继续使用，阶段2平台增强不作为当前阻塞。

不得删除“任务文件唯一事实来源”、BTC/ETH独立证据、未来数据禁令和七道质量门。

- [ ] **Step 4: 保持工作流最小变更**

资格工作流当前已经从PR基线检出可信脚本并传入base/head，不需要执行PR头代码。只有当
CLI新增输出或Git历史深度测试证明现有工作流不足时才修改；否则保持不变。

合并工作流继续要求：当前资格检查成功、无未解决线程、无`CHANGES_REQUESTED`、全部
检查完成、`mergeable_state=clean`和精确头SHA。不得把failure改成neutral或skipped。

- [ ] **Step 5: 运行GREEN并提交**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
NODE_OPTIONS=--max-old-space-size=256 \
  npx --yes --offline markdownlint-cli2 AGENTS.md README.md 'docs/**/*.md'
git diff --check
git add AGENTS.md README.md docs/研发中心 docs/治理/PR自动合并策略.md \
  tests/研发中心
git commit -m "docs: 开放受控研发自动合并规则"
```

Expected: 研发中心测试通过，Markdown 0问题。

## Task 7：完成PR #44精确回归与全量验证

**Files:**

- Modify: `tests/研发中心/test_验证自动合并资格.py`
- Modify: `docs/研发中心/任务/任务-000039.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 固定PR #44离线回归事实**

测试必须使用：

```python
base_sha = "c7763a411ba6c239ddecb923bf04ebbbec5eebf3"
head_sha = "5f6da4da7d878f5973c31d9787215c2ff1f3dccb"
task_type = "数据治理"
expected_paths = (
    "artifacts/数据/来源身份/source-identity-20260803T131620+0800-e7bc65038f21/来源身份清单.csv",
    "artifacts/数据/来源身份/source-identity-20260803T131620+0800-e7bc65038f21/身份清单.json",
    "config/数据/数据来源与资产身份.json",
    "docs/数据/数据来源与资产身份合同.md",
    "docs/研发中心/任务/任务-000029.md",
    "docs/研发中心/看板.md",
    "scripts/数据/冻结数据来源身份.py",
    "tests/数据/test_冻结数据来源身份.py",
    "tests/研发中心/test_项目范围与阶段状态.py",
)
```

断言该事实集合在新规则下允许；如果远端PR头已变化，测试继续保留历史回归，实时合并流程
必须对新头重新生成评审和验证证据。

- [ ] **Step 2: 串行运行全部验证**

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest tests/研发中心/test_验证自动评审证据.py -v
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests/审计 -p 'test_*.py' -v
NODE_OPTIONS=--max-old-space-size=256 \
  npx --yes --offline markdownlint-cli2 AGENTS.md README.md 'docs/**/*.md'
git diff --check origin/main...HEAD
```

Expected: 全部通过；Node内存上限256 MiB；测试单进程。

- [ ] **Step 3: 更新任务为待评审并记录证据**

任务文件记录实现提交、验证数量、类型与路径门、资源边界、PR #44回归、已知限制和回滚。
看板将任务-000039从`执行中`移动到`待评审`。

- [ ] **Step 4: 提交、推送并创建PR**

```bash
git add .github AGENTS.md README.md docs scripts/研发中心 tests/研发中心
git commit -m "chore: 更新任务-000039评审状态"
git push origin codex/000039-controlled-rd-auto-merge-implementation-v1
```

PR正文严格包含：

```markdown
## 关联任务

- 任务-000039

## 变更类型

- 任务交付
```

并写明交付物、验收结果、验证命令、已知限制、数据与安全影响和回滚方式。

## Task 8：双子智能体评审、自动修复和策略合并

**Files:**

- Read-only review of all PR changes
- Modify only files required to close P0/P1 findings

- [ ] **Step 1: 测量资源并冻结评审头SHA**

```bash
git rev-parse origin/main
git rev-parse HEAD
df -h / /Volumes/data
vm_stat
```

Expected: 本机可用磁盘不少于5 GiB、内存非危急；记录基线和头SHA。

- [ ] **Step 2: 并行启动两个只读评审者**

治理/架构评审覆盖任务合同、任务登记、类型、状态、看板、可信控制面和PR #44回归；
范围/安全评审覆盖路径、Git对象、资源、敏感信息、真实资金与生产硬否决。评审者不得修改
文件、使用凭据、访问服务器或运行全量测试。

- [ ] **Step 3: 自动修复P0/P1并重新评审**

每轮先写失败测试复现问题，再最小修复。任何新提交使旧评审和旧验证失效；最多三轮。
P2只在不扩大范围且风险低时修复，否则记录限制。

- [ ] **Step 4: 对最终头运行完整验证并生成证据**

结构化证据使用`zhishi-agent-review/v1`，绑定仓库、PR、任务、基线、头SHA、两个不同角色、
P0/P1计数、验证命令、时间和资源预算。证据不得包含环境转储、凭据或PR正文。
主执行器把通过`验证自动评审证据.py`校验的最终JSON保存到未跟踪路径
`.git/zhishi-agent-review-task39.json`，不得加入提交。

- [ ] **Step 5: 触发可信自动合并工作流**

```bash
task39_pr=$(env -u GITHUB_TOKEN gh pr list --repo xk320/zhishi \
  --head codex/000039-controlled-rd-auto-merge-implementation-v1 \
  --state open --json number --jq '.[0].number')
final_head_sha=$(git rev-parse HEAD)
review_evidence_json=$(jq -c . .git/zhishi-agent-review-task39.json)
env -u GITHUB_TOKEN gh workflow run pr-auto-merge.yml \
  --repo xk320/zhishi --ref main \
  -f pr_number="$task39_pr" \
  -f head_sha="$final_head_sha" \
  -f review_evidence="$review_evidence_json"
```

Expected: `main`可信资格、评审证据、线程、检查、实时基线与头SHA全部通过，工作流产生
真实merge commit。任一失败则保留PR并修复，不直接调用合并API。

## Task 9：重新验证并自动合并PR #44

**Files:**

- No repository edits before live revalidation
- Later state closure modifies only task-000029, task-000030 and board

- [ ] **Step 1: 重新触发PR #44资格检查**

对PR正文执行无语义改变的受控编辑，或使用GitHub允许的重新运行机制，使资格工作流从新
`main`执行。确认当前PR开放、非草稿、目标`main`、同仓库来源和可合并。

- [ ] **Step 2: 对当前头重新完成双评审与完整验证**

旧评审只有在基线和头SHA仍与新证据完全一致时才可引用；由于`main`基线已变化，必须重新
生成两份只读评审和主执行器验证证据。任务-000029真实批次不得重跑或覆盖。
通过`验证自动评审证据.py`校验的新证据保存到未跟踪路径
`.git/zhishi-agent-review-pr44.json`，不得加入提交。

- [ ] **Step 3: 触发PR #44可信自动合并**

```bash
pr44_head_sha=$(env -u GITHUB_TOKEN gh pr view 44 --repo xk320/zhishi \
  --json headRefOid --jq .headRefOid)
review_evidence_json=$(jq -c . .git/zhishi-agent-review-pr44.json)
env -u GITHUB_TOKEN gh workflow run pr-auto-merge.yml \
  --repo xk320/zhishi --ref main \
  -f pr_number='44' \
  -f head_sha="$pr44_head_sha" \
  -f review_evidence="$review_evidence_json"
```

Expected: 当前头资格检查成功、P0=P1=0、全部检查成功且`mergeable_state=clean`后合并；
记录merge commit SHA。

- [ ] **Step 4: 自动创建合并后状态闭环PR**

从最新`main`创建独立分支，只修改：

- `docs/研发中心/任务/任务-000029.md`：`待评审→已完成`并增加真实合并时间和SHA；
- `docs/研发中心/任务/任务-000030.md`：`阻塞→待执行`并登记任务-000029已完成；
- `docs/研发中心/看板.md`：移动任务-000029并解锁任务-000030。

变更类型为`合并后状态闭环`，通过同样双评审、验证与自动合并流程。

- [ ] **Step 5: 继续自动选择任务-000030**

状态闭环进入`main`后，重新扫描任务中心。任务-000030依赖满足且为P0，应成为下一可执行
任务；不得跳过依赖直接执行任务-000031及以后任务。
