# 任务-000098 阶段1同版本历史重放实施计划

<!-- markdownlint-disable MD013 MD032 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用任务-000094的不可变脱敏批次连续两次重建同一数据资格决策，并在不重扫854GB原始数据的前提下关闭8个叶子的历史重放门。

**Architecture:** 一个标准库Python执行器严格校验固定七文件、解码列式成员表、重建可见集与门禁叶子，再以两次独立加载产生逐字节一致的规范JSON。发布采用同一输出根下临时目录、源证据发布前复验和原子更名；任务-000094批次及原始数据始终只读。

**Tech Stack:** Python 3标准库、JSON/SHA-256、unittest/pytest、Markdown。

---

## 实施任务

### Task 1: 冻结合同与输入配置

**Files:**
- Create: `docs/数据/阶段1同版本历史重放合同.md`
- Create: `config/审计/任务-000098阶段1同版本历史重放.json`

- [ ] **Step 1: 写入决策身份、时间可见性、守恒、双重放、原子发布及三项剩余门的合同。**
- [ ] **Step 2: 写入任务-000094合并提交、批次路径、七个文件SHA、完整批次指纹、固定计数、允许对象和资源上限。**
- [ ] **Step 3: 规范化配置并确认无路径、版本或计数占位符。**

Run: `python3 -m json.tool config/审计/任务-000098阶段1同版本历史重放.json >/dev/null`

Expected: exit 0。

### Task 2: 测试驱动实现重放执行器

**Files:**
- Create: `tests/审计/test_重放阶段1同版本数据资格决策.py`
- Create: `scripts/审计/重放阶段1同版本数据资格决策.py`

- [ ] **Step 1: 先写配置漂移、重复成员、未来可见、分组漂移、门禁边界和两次字节一致测试并确认缺少执行器时失败。**
- [ ] **Step 2: 实现无重复键JSON、普通文件与符号链接边界、七文件指纹和配置/合同/执行器指纹验证。**
- [ ] **Step 3: 实现列式成员解码、5180/207/391/175/8守恒、UTC可见集和BTC/ETH独立分组。**
- [ ] **Step 4: 实现两次独立加载、规范输出比较、发布前第三次源复验、文件回读和原子追加式发布。**
- [ ] **Step 5: 运行专项测试直到全部通过。**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/审计/test_重放阶段1同版本数据资格决策.py`

Expected: all passed。

### Task 3: 生成真实不可变重放批次

**Files:**
- Create: `artifacts/审计/阶段1同版本历史重放/<批次>/decision.json`
- Create: `artifacts/审计/阶段1同版本历史重放/<批次>/replay-first.json`
- Create: `artifacts/审计/阶段1同版本历史重放/<批次>/replay-second.json`
- Create: `artifacts/审计/阶段1同版本历史重放/<批次>/leaves.json`
- Create: `artifacts/审计/阶段1同版本历史重放/<批次>/summary.json`

- [ ] **Step 1: 固定执行器指纹后运行单进程真实重放。**
- [ ] **Step 2: 校验两份重放字节SHA相等、8叶子仅历史重放门通过、其他三门仍无法判定。**
- [ ] **Step 3: 校验任务-000094七个源文件SHA在发布前后不变，批次输出小于25MiB且RSS小于512MiB。**

Run: `PYTHONHASHSEED=0 python3 scripts/审计/重放阶段1同版本数据资格决策.py --config config/审计/任务-000098阶段1同版本历史重放.json --repo-root . --output-root artifacts/审计/阶段1同版本历史重放 --batch-id <固定批次>`

Expected: JSON输出`status=已证明`且`replays_byte_identical=true`。

### Task 4: 同步派生文档与任务状态

**Files:**
- Modify: `docs/审计/阶段1最终审计报告.md`
- Modify: `docs/审计/数据缺口与补采清单.md`
- Modify: `README.md`
- Modify: `docs/研发中心/总体计划.md`
- Modify: `docs/研发中心/任务/任务-000098.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: 写入批次身份、证据计数、重放指纹、资源事实和不扫描原始数据事实。**
- [ ] **Step 2: 仅移除同版本历史重放阻塞，保留成本与执行、容量、恢复三个阻塞。**
- [ ] **Step 3: 将任务和看板更新为待评审并记录分支、提交占位前的交付物和验证结果。**

### Task 5: 全量验证、双评审、交付与闭环

**Files:**
- Test: `tests/审计/`
- Test: `tests/数据/`
- Test: `tests/研发中心/`

- [ ] **Step 1: 单进程运行专项、审计、数据、研发中心测试和Python编译。**
- [ ] **Step 2: 运行变更Markdown检查、敏感信息扫描与`git diff --check`。**
- [ ] **Step 3: 提交并创建PR，组织治理/架构与范围/安全两个只读评审者；自动修复P0/P1并复验。**
- [ ] **Step 4: 可信自动合并交付PR，再用独立状态闭环PR将任务标记已完成。**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/审计 && PYTHONHASHSEED=0 python3 -m pytest -q tests/数据 && PYTHONHASHSEED=0 python3 -m pytest -q tests/研发中心`

Expected: all passed；两个评审均APPROVE；可信工作流合并成功。

## 自审

- 合同全部要求分别落在任务1至任务4，没有重扫原始数据或访问Ubuntu的步骤。
- 执行器只允许历史重放门变为通过，不会放行阶段1/阶段2。
- 计划无TBD、TODO或未定义的实现占位；批次名在执行时以固定UTC时间和配置指纹生成。
