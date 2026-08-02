# 子智能体评审与自动合并实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立无需人工批准、由独立子智能体评审和自动修复复验驱动的精确SHA自动合并流程。

**Architecture:** Codex主执行器负责状态机、修复和最终合并；至少两个子智能体对冻结SHA
执行只读评审。GitHub资格工作流保持只读，合并入口改为显式代理评审触发，并始终运行
`main`上的可信检查器。高风险生产操作继续停止，不由本流程授权。

**Tech Stack:** Markdown治理合同、GitHub Actions、Python 3标准库、`unittest`、GitHub CLI。

---

### Task 1: 用失败测试定义新评审与合并协议

**Files:**
- Modify: `tests/研发中心/test_自动合并工作流.py`
- Modify: `tests/研发中心/test_验证自动合并资格.py`
- Modify: `tests/研发中心/test_项目范围与阶段状态.py`

- [ ] **Step 1: 将旧人工批准断言替换为代理评审断言**

测试必须要求`workflow_dispatch`输入`pr_number`、`head_sha`和`review_comment_id`，拒绝
`issue_comment`和`/架构评审通过`，并要求`/子智能体评审通过`绑定40位SHA。

- [ ] **Step 2: 增加治理合同断言**

验证AGENTS、任务规范、自动执行提示词和自动合并策略均包含至少两个独立子智能体、
新提交使旧评审失效、自动修复复验、精确SHA合并和资源上限。

- [ ] **Step 3: 运行测试确认RED**

```bash
python3 -m unittest tests/研发中心/test_自动合并工作流.py -v
python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v
```

预期：旧工作流仍依赖人工评论，因此新断言失败。

### Task 2: 更新任务中心和代理执行规则

**Files:**
- Modify: `AGENTS.md`
- Modify: `docs/研发中心/任务规范.md`
- Modify: `docs/研发中心/Codex自动执行提示词.md`
- Modify: `docs/治理/PR自动合并策略.md`
- Modify: `docs/研发中心/任务/任务-000028.md`

- [ ] **Step 1: 写入统一评审状态机**

明确至少两个只读角色、主执行器统一修复、每次提交重新评审、P0/P1为零后自动合并，
不再等待用户批准。

- [ ] **Step 2: 写入资源和高风险边界**

最多三个并发只读评审，测试与数据任务串行；生产、真实资金、凭据、原始数据写入和
不可逆操作不因评审通过而获得授权。

- [ ] **Step 3: 更新任务-000028授权与交付记录**

记录2026-08-03用户授权、设计和实施计划，并把自动评审规则纳入验收。

### Task 3: 将合并工作流改为代理评审触发

**Files:**
- Modify: `.github/workflows/pr-auto-merge.yml`
- Modify: `.github/workflows/pr-auto-merge-eligibility.yml`
- Modify: `scripts/研发中心/验证自动合并资格.py`

- [ ] **Step 1: 改用workflow_dispatch输入**

合并工作流接受PR编号、精确头SHA和评审评论编号；读取GitHub API验证评论为当前SHA的
`/子智能体评审通过`记录，不接受旧人工命令。

- [ ] **Step 2: 保持main可信复验**

只检出`main`并运行其中检查器；只获取PR提交做Git差异比较，不执行PR分支代码；合并前
再次核对base/head SHA、可合并状态和成功资格检查。

- [ ] **Step 3: 扩展低风险任务类型但保留硬禁止**

允许阶段1数据治理、数据审计、受限数据工程和隔离基础设施验证；交易执行、生产、真实
资金、权限、密钥和破坏性变更保持不符合资格。

### Task 4: GREEN验证与独立复审

**Files:**
- Test: `tests/研发中心/test_自动合并工作流.py`
- Test: `tests/研发中心/test_验证自动合并资格.py`
- Test: `tests/研发中心/test_项目范围与阶段状态.py`

- [ ] **Step 1: 运行研发中心专项测试**

```bash
python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
```

预期：全部通过。

- [ ] **Step 2: 运行审计回归和文档检查**

```bash
python3 -m unittest discover -s tests/审计 -p 'test_*.py' -v
npx --yes markdownlint-cli2 AGENTS.md README.md '《知势宣言》.md' 'docs/**/*.md'
git diff --check origin/main...HEAD
```

- [ ] **Step 3: 对最终头SHA重新组织独立评审**

至少合同与实现审查者、QA验证者返回P0/P1为零；任何问题由主执行器修复后重新执行本步骤。

### Task 5: 更新PR并精确SHA自动合并

**Files:**
- Modify: `docs/研发中心/任务/任务-000028.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 提交并推送最终评审候选**

更新PR #38正文，记录交付、验证、评审、资源和回滚信息。

- [ ] **Step 2: 冻结头SHA并生成评审审计评论**

评论第一行必须为`/子智能体评审通过 <40位SHA>`，并附角色、结论、验证和资源记录。

- [ ] **Step 3: 精确SHA合并**

使用GitHub合并API携带冻结头SHA；若SHA、base、检查或可合并状态变化立即停止并重新复验。

- [ ] **Step 4: 同步main完成记录并启动任务-000029**

合并后拉取最新`main`，将任务-000028标记`已完成`、任务-000029解除为`待执行`，同步
看板，并按其唯一批准方案继续执行。
