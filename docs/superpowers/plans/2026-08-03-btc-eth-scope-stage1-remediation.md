# BTC、ETH范围与阶段1数据闭环修复实施计划

<!-- markdownlint-disable MD001 MD013 MD032 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 统一阶段与研究范围，并按硬门顺序完成BTC、ETH阶段1数据闭环复验。

**Architecture:** 使用任务-000028完成治理收口并登记任务-000029至000037；每个后续任务只处理一个阶段门，通过不可变版本、指纹、白名单只读访问和失败安全状态连接。历史批次保持不变，新事实只通过追加批次发布。

**Tech Stack:** Markdown任务合同、Python 3标准库、CSV/JSON不可变产物、SSH逻辑别名`ubuntu`、`unittest`、markdownlint、Git/GitHub Pull Request。

---

### Task 1: 修复任务-000028合同与研发中心看板

**Files:**
- Modify: `docs/研发中心/任务/任务-000028.md`
- Modify: `docs/研发中心/看板.md`
- Create: `tests/研发中心/test_项目范围与阶段状态.py`

- [ ] **Step 1: 编写失败测试**

测试必须拒绝看板任务范围压缩、任务-000028合同字段缺失、待执行任务方案未批准，以及
规范性阶段入口出现失效状态。

- [ ] **Step 2: 运行测试并确认失败原因**

Run: `python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v`

Expected: FAIL，明确指出任务映射、合同或现状漂移。

- [ ] **Step 3: 补齐任务合同并更新为执行中**

任务-000028固定为阶段1治理任务，记录当前分支、开始时间、唯一方案、输入输出、安全边界、
验收和后续任务依赖链。看板恢复每个任务一行并把任务-000028移入执行中。

- [ ] **Step 4: 运行专项和研发中心测试**

Run: `python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v`

Expected: 所有测试通过。

- [ ] **Step 5: 提交治理合同**

Commit: `chore: 修复任务000028治理合同`

### Task 2: 统一阶段状态与BTC、ETH前向范围

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `《知势宣言》.md`
- Modify: `docs/研发中心/总体计划.md`
- Modify: `docs/路线图/第一阶段路线图.md`
- Modify: `docs/白皮书/知势白皮书.md`
- Modify: `docs/架构/系统蓝图.md`
- Modify: all current normative Markdown files selected by the scope manifest
- Modify: `docs/架构设计/市场状态层（Market Regime）顶层架构设计.md`

- [ ] **Step 1: 扩展失败测试覆盖规范性文档清单**

测试维护显式规范性文件清单，拒绝SOL作为前向标的、旧服务器状态、旧任务完成状态和互相
冲突的阶段状态；历史任务记录、已发布审计报告和不可变产物不在机械改写范围。

- [ ] **Step 2: 运行测试并确认失败**

Run: `python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v`

Expected: FAIL，列出尚未更新的规范性文件和语句。

- [ ] **Step 3: 修改规范性文档**

把当前范围统一为BTC、ETH；把阶段0.5更新为核心合同已完成、阶段1更新为修复中、阶段2
更新为被阶段1证据门阻塞、阶段3至7更新为仅有部分理论合同。旧市场状态草案标记为历史
草案并引用现行架构。

- [ ] **Step 4: 复核运行测试和Markdown格式**

Run: `python3 -m unittest tests/研发中心/test_项目范围与阶段状态.py -v`

Run: `npx --yes markdownlint-cli2 README.md AGENTS.md '《知势宣言》.md' 'docs/**/*.md'`

Expected: 专项测试通过；修改文件0项Markdown问题。

- [ ] **Step 5: 提交范围与状态修复**

Commit: `docs: 统一BTC与ETH研究范围及阶段状态`

### Task 3: 登记阶段1依赖任务链

**Files:**
- Create: `docs/研发中心/任务/任务-000029.md`
- Create: `docs/研发中心/任务/任务-000030.md`
- Create: `docs/研发中心/任务/任务-000031.md`
- Create: `docs/研发中心/任务/任务-000032.md`
- Create: `docs/研发中心/任务/任务-000033.md`
- Create: `docs/研发中心/任务/任务-000034.md`
- Create: `docs/研发中心/任务/任务-000035.md`
- Create: `docs/研发中心/任务/任务-000036.md`
- Create: `docs/研发中心/任务/任务-000037.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 扩展合同完整性测试并确认失败**

每个任务必须具有唯一方案、批准状态、执行授权、严格依赖、输入输出合同、范围、安全边界、
资源限制、验收命令和完成定义。后序任务初始为阻塞，禁止并行。

- [ ] **Step 2: 创建九个完整任务合同**

任务分别覆盖来源身份、三类时间、完整审计、可信重放、成本执行、双标的独立闭环、最小
闭环试点、容量恢复和最终门禁，不合并互相独立的验收结论。

- [ ] **Step 3: 更新看板唯一映射**

每个任务文件在看板恰好出现一次；任务-000029至000037在任务-000028合并完成前保持阻塞。

- [ ] **Step 4: 运行研发中心完整测试**

Run: `python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v`

Expected: 所有任务合同、状态和看板映射通过。

- [ ] **Step 5: 提交任务链**

Commit: `docs: 登记阶段1数据闭环修复任务链`

### Task 4: 完成任务-000028交付和Pull Request

**Files:**
- Modify: `docs/研发中心/任务/任务-000028.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 运行全部适用验证**

Run: `python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v`

Run: `python3 -m unittest discover -s tests/审计 -p 'test_*.py' -v`

Run: `git diff --check origin/main...HEAD`

Expected: 全部通过，历史审计产物无修改。

- [ ] **Step 2: 更新任务-000028为待评审**

记录分支、提交SHA、交付物、验证结果、已知限制、数据与安全影响和人工评审要求，并同步
看板。

- [ ] **Step 3: 提交并创建Pull Request**

Commit: `docs: 提交任务000028阶段治理修复`

Pull Request必须关联任务-000028，说明BTC、ETH范围、历史证据保留、后续依赖任务、验证、
限制、安全影响和回滚方式，不自行合并。

### Task 5: 按任务-000029至000037顺序执行

**Files:**
- Follow each task file after it enters `main`

- [ ] **Step 1: 每次只认领一个已解除阻塞的任务**

从最新`main`创建独立分支，先更新任务与看板为执行中；不得并行执行后序任务。

- [ ] **Step 2: 每项代码能力使用TDD**

先写失败测试并确认失败，再实现最小能力；所有远端数据访问保持白名单只读和资源有界。

- [ ] **Step 3: 每项任务分别验证、提交、推送和创建PR**

每个PR等待所有者对当前头提交评审。代码、配置、数据和生产相关变更不得自动合并。

- [ ] **Step 4: 合并后更新任务完成状态并解除下一任务**

只有合并证据进入`main`后，才把当前任务标记已完成并将下一任务从阻塞改为待执行。

- [ ] **Step 5: 任务-000037形成最终阶段门结论**

最终报告必须分别给出BTC与ETH六道门、允许研究范围和阶段2门禁。任何门失败或无法判定，
结论保持禁止并列出下一解除条件；不得为了完成目标虚构放行。
