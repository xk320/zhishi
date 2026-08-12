# Task 000103 Simulated Order Lifecycle Implementation Plan

<!-- markdownlint-disable MD001 MD013 MD032 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用最多BTC/ETH各256个有界只读订单簿快照，生成不下单、可重放、时间语义保守的阶段1模拟委托生命周期证据。

**Architecture:** 新执行器复用任务-000100的SSH隔离、元数据指纹、资源硬门和原子发布原语，按`prepare → probe → plan → collect → simulate → replay-1 → replay-2 → validate`八阶段运行。原始订单簿只存在于单进程内存，Git仅保存快照身份哈希、四类时间裁决、布尔可成交事实、生命周期事件、分母和指纹；来源时间语义不完整时对应门保持未知。

**Tech Stack:** Python 3标准库、pytest、MySQL只读客户端、SSH逻辑别名`ubuntu`、JSON/CSV、SHA-256、MarkdownLint。

---

### Task 1: 冻结配置与安全原语

**Files:**
- Create: `config/模拟交易/任务-000103阶段1委托生命周期.json`
- Create: `scripts/模拟交易/验证阶段1委托生命周期.py`
- Test: `tests/模拟交易/test_阶段1委托生命周期.py`

- [x] **Step 1: Write the failing configuration and SQL boundary tests**

```python
def test_config_fixes_bounded_scope(module, config):
    module.validate_config(config)
    assert config["资源上限"]["每标的快照"] == 256
    assert config["资源上限"]["RSS字节"] == 268435456


def test_sql_rejects_write_or_unbounded_query(module, config):
    with pytest.raises(ValueError, match="SQL_NOT_READ_ONLY"):
        module.validate_business_sql("DELETE FROM order_book_raw_snapshots", config)
```

- [x] **Step 2: Run the tests and confirm they fail before the module exists**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py`

Expected: FAIL because the new module/config is absent.

- [x] **Step 3: Implement the fixed configuration and reusable safety surface**

```python
SCRIPT_VERSION = "stage1-simulated-order-lifecycle-1.0"
CONFIG_RELATIVE_PATH = Path("config/模拟交易/任务-000103阶段1委托生命周期.json")
TASK_RELATIVE_PATH = Path("docs/研发中心/任务/任务-000103.md")
ALLOWED_STATES = {
    "created": {"sent"},
    "sent": {"acknowledged"},
    "acknowledged": {"evaluated"},
    "evaluated": {"filled", "canceled", "unknown"},
}
```

Implement canonical JSON, exclusive writes, no-replace directory publication, sensitive-text rejection, config validation, SQL token validation and RSS/time/byte limits by reusing the proven task-000100 behavior without modifying its frozen script.

- [x] **Step 4: Run the focused tests**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py`

Expected: configuration and SQL boundary tests PASS.

### Task 2: Freeze intent, metadata and deterministic query plan

**Files:**
- Modify: `scripts/模拟交易/验证阶段1委托生命周期.py`
- Modify: `tests/模拟交易/test_阶段1委托生命周期.py`

- [x] **Step 1: Write failing tests for intent-before-read, metadata drift and total ordering**

```python
def test_query_is_totally_ordered(module, frozen_metadata, intent, config):
    plan = module.build_query_plan(frozen_metadata, intent, config)
    assert all("capture_ts_ms` DESC,`snapshot_id` DESC" in q["SQL"] for q in plan["queries"])
    assert all("LIMIT 256" in q["SQL"] for q in plan["queries"])


def test_duplicate_member_identity_fails_closed(module):
    with pytest.raises(ValueError, match="MEMBER_IDENTITY_DUPLICATE"):
        module.validate_member_order([{"capture_ts_ms": 1, "snapshot_id": "x"}] * 2)
```

- [x] **Step 2: Verify the new tests fail**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'query or duplicate or metadata'`

Expected: FAIL on missing planning functions.

- [x] **Step 3: Implement `prepare`, `probe` and `plan`**

```python
def build_query_plan(metadata, intent, config):
    return {
        "schema_version": "zhishi-simulated-order-query-plan/v1",
        "queries": [build_symbol_query(symbol, intent["data_cutoff_ms"], config) for symbol in config["标的"]],
    }
```

Freeze task-000100 manifest/summary SHA, task/config/executor SHA, exact cutoff, scenario set and resources before any business read. Probe only the approved `information_schema` views and require UID=0, table-level SELECT, exact 13-column schema, PRIMARY(`snapshot_id`) and `idx_raw_snapshot_symbol_capture(symbol,capture_ts_ms)`. Use one constant query per symbol, a lower/upper time bound, `ORDER BY capture_ts_ms DESC,snapshot_id DESC LIMIT 256`, then `EXPLAIN FORMAT=JSON`; reject `ALL/index`, wrong index or total estimate over10000.

- [x] **Step 4: Run planning tests**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'query or duplicate or metadata'`

Expected: PASS.

### Task 3: Normalize snapshots and enforce four independent time classes

**Files:**
- Modify: `scripts/模拟交易/验证阶段1委托生命周期.py`
- Modify: `tests/模拟交易/test_阶段1委托生命周期.py`

- [x] **Step 1: Write failing payload and time-boundary tests**

```python
def test_capture_time_never_becomes_market_event_time(module, payload):
    row = module.normalize_snapshot(["id", "BTCUSDT", "1000", "1001", json.dumps(payload)])
    assert row["market_event_time_ms"] == payload["E"]
    assert row["earliest_visible_time_ms"] == 1000


def test_missing_event_time_keeps_time_gate_unknown(module, payload):
    payload.pop("E")
    row = module.normalize_snapshot(["id", "BTCUSDT", "1000", "1001", json.dumps(payload)])
    assert row["time_gate"] == "unknown"
```

- [x] **Step 2: Verify the time tests fail**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'time or payload or future'`

Expected: FAIL on missing normalization.

- [x] **Step 3: Implement bounded collection and redaction**

```python
def time_decision(payload, capture_ts_ms, created_at_ms, provenance_proved):
    event = unique_market_event_time(payload)
    visible = capture_ts_ms if provenance_proved else None
    return {
        "market_event_time_ms": event,
        "earliest_visible_time_ms": visible,
        "batch_collected_at": utc_now(),
        "time_gate": "pass" if event is not None and visible is not None else "unknown",
    }
```

Read no more than512 rows/64MiB in one process, validate symbol, unique identity, payload object, bids/asks numeric ordering and nonnegative quantities. Persist only identity SHA, event/capture/created time decisions, payload SHA and booleans needed for symmetric simulation; never persist price, quantity, depth arrays or payload text. Reject future-visible input and mark absent/ambiguous event or arrival semantics unknown rather than substituting another clock.

- [x] **Step 4: Run collection boundary tests**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'time or payload or future or sensitive'`

Expected: PASS.

### Task 4: Implement deterministic lifecycle and two independent replays

**Files:**
- Modify: `scripts/模拟交易/验证阶段1委托生命周期.py`
- Modify: `tests/模拟交易/test_阶段1委托生命周期.py`

- [x] **Step 1: Write failing state-machine and replay tests**

```python
def test_invalid_transition_fails_closed(module):
    with pytest.raises(ValueError, match="STATE_TRANSITION_INVALID"):
        module.transition("created", "filled")


def test_passive_order_never_fakes_queue_fill(module, frozen_member):
    result = module.simulate_member(frozen_member, "passive_limit", "buy", "baseline")
    assert result["terminal_state"] in {"canceled", "unknown"}


def test_replays_are_identical(module, frozen_input):
    assert module.simulate(frozen_input) == module.simulate(frozen_input)
```

- [x] **Step 2: Verify lifecycle tests fail**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'transition or passive or replay'`

Expected: FAIL on missing simulator.

- [x] **Step 3: Implement the lifecycle state machine and replay commands**

```python
def transition(current, target):
    if target not in ALLOWED_STATES.get(current, set()):
        raise ValueError("STATE_TRANSITION_INVALID")
    return target
```

Generate buy/sell × aggressive-market/aggressive-limit/passive-limit-cancel × baseline/stress scenarios with deterministic relative milliseconds. Aggressive scenarios may be `filled` only from the frozen top-book validity facts; passive scenarios end `canceled` with `QUEUE_IDENTITY_UNAVAILABLE`. `replay-1` and `replay-2` must run as separate invocations consuming only `frozen-input.json`; each writes a canonical result SHA, and `validate` requires both equal the initial simulation SHA.

- [x] **Step 4: Run lifecycle tests**

Run: `PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py -k 'transition or passive or replay or denominator'`

Expected: PASS.

### Task 5: Publish one real batch and document the conservative decision

**Files:**
- Create: `docs/数据/模拟委托生命周期数据合同.md`
- Create: `docs/审计/阶段1模拟执行生命周期证据报告.md`
- Modify: `docs/数据/成本流动性与执行数据合同.md`
- Modify: `README.md`
- Modify: `docs/研发中心/总体计划.md`
- Modify: `docs/研发中心/任务/任务-000103.md`
- Modify: `docs/研发中心/看板.md`
- Create: `artifacts/模拟交易/阶段1委托生命周期/stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8/`

- [x] **Step 1: Run the frozen eight-stage batch serially**

Run each command with the same frozen batch ID:

```bash
python3 scripts/模拟交易/验证阶段1委托生命周期.py prepare --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py probe --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py plan --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py collect --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py simulate --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py replay-1 --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py replay-2 --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
python3 scripts/模拟交易/验证阶段1委托生命周期.py validate --batch stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
```

Expected: one append-only batch, exact replay hashes, zero remote/database/network orders and resource usage below contract limits.

- [x] **Step 2: Write evidence-backed docs**

Record exact batch/manifest/summary SHA, BTC and ETH denominators, time-gate counts, lifecycle terminal counts, replay hashes, SQL count/estimate/bytes, elapsed/RSS and limitations. State that the simulator is runnable/replayable but does not prove exchange latency, multi-year costs, predictive edge or trading permission.

- [x] **Step 3: Run the complete serial verification set**

```bash
PYTHONHASHSEED=0 python3 -m pytest -q tests/模拟交易/test_阶段1委托生命周期.py
PYTHONHASHSEED=0 python3 -m pytest -q tests/数据 tests/审计 tests/模拟交易
PYTHONHASHSEED=0 python3 -m pytest -q tests/研发中心
python3 -m py_compile scripts/模拟交易/验证阶段1委托生命周期.py
NODE_OPTIONS=--max-old-space-size=256 npx --yes --offline markdownlint-cli2 README.md docs/数据/模拟委托生命周期数据合同.md docs/数据/成本流动性与执行数据合同.md docs/审计/阶段1模拟执行生命周期证据报告.md docs/研发中心/总体计划.md docs/研发中心/任务/任务-000103.md docs/研发中心/看板.md docs/superpowers/plans/2026-08-13-task-000103-simulated-order-lifecycle.md
git diff --check
```

Expected: all commands exit0, one test process at a time, Node heap capped at256MiB.

- [x] **Step 4: Commit, push, create PR and enter read-only review**

```bash
git add README.md config/模拟交易/任务-000103阶段1委托生命周期.json scripts/数据/验证阶段1成本执行.py scripts/模拟交易/验证阶段1委托生命周期.py tests/模拟交易/test_阶段1委托生命周期.py docs/数据/模拟委托生命周期数据合同.md docs/数据/成本流动性与执行数据合同.md docs/审计/阶段1模拟执行生命周期证据报告.md docs/研发中心/总体计划.md docs/研发中心/任务/任务-000103.md docs/研发中心/看板.md docs/superpowers/plans/2026-08-13-task-000103-simulated-order-lifecycle.md artifacts/模拟交易/阶段1委托生命周期/stage1-simulated-lifecycle-20260812T195103Z-f0f4ff04c8e8
git commit -m "feat: 建立阶段1模拟委托生命周期证据"
git push -u origin codex/task-000103-simulated-order-lifecycle-v1
```

The PR must bind Task000103, exact deliverables, validation, limitations, data/safety impact and rollback. Then update the task/board to `待评审`, bind the delivery SHA/PR, revalidate, obtain two independent read-only approvals and merge only the exact reviewed head.
