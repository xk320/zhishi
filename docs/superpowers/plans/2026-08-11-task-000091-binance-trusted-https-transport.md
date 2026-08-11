# 任务-000091 Binance 可信 HTTPS 传输修复 Implementation Plan

<!-- markdownlint-disable MD013 MD001 MD032 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用固定系统`/usr/bin/curl`替换任务-000090执行器失败的Python证书链请求，同时保持TLS校验、630成员证据门和历史批次不变。

**Architecture:** 在现有单文件执行器中新增一个小型传输适配器，负责固定端点、固定参数、无shell进程调用、响应上限和传输指纹；JSON解析后继续进入原有证据流水线。配置只增加传输合同，批次只追加传输器脱敏事实，不保存完整响应。

**Tech Stack:** Python 3标准库、`/usr/bin/curl`、`unittest`、JSON、GitHub Actions可信资格检查。

---

### Task 1: 固定执行状态与传输合同

**Files:**
- Modify: `docs/研发中心/任务/任务-000091.md`
- Modify: `docs/研发中心/看板.md`
- Modify: `config/数据/任务-000090Binance来源身份自动映射.json`
- Create: `docs/superpowers/plans/2026-08-11-task-000091-binance-trusted-https-transport.md`

- [x] **Step 1: 将任务与看板迁移为执行中**

写入执行分支`codex/task-000091-binance-trusted-https-exec-v1`和带时区开始时间；看板保持唯一映射。

- [x] **Step 2: 在配置中增加固定传输合同**

新增顶层`可信HTTPS传输`对象，固定以下字段：

```json
{
  "可执行文件": "/usr/bin/curl",
  "HTTP方法": "GET",
  "允许协议": "https",
  "跟随重定向": false,
  "连接超时秒": 15,
  "单端点总超时秒": 60,
  "最大响应字节": 16777216,
  "禁止参数": ["--insecure", "-k", "--location", "-L"]
}
```

- [x] **Step 3: 更新配置校验测试并确认先失败**

Run: `python3 -m unittest tests/数据/test_自动映射Binance来源身份.py -q`

Expected: FAIL，提示配置尚未包含`可信HTTPS传输`或实现尚未验证传输合同。

### Task 2: 测试先行定义固定 curl 适配器

**Files:**
- Modify: `tests/数据/test_自动映射Binance来源身份.py`
- Modify: `scripts/数据/自动映射Binance来源身份.py`

- [x] **Step 1: 新增成功与参数安全测试**

用可注入`runner`捕获命令数组，断言：

```python
summary = MODULE.fetch_exchange_info(
    uri,
    started=0.0,
    runner=fake_runner,
    curl_path=Path("/usr/bin/curl"),
)
self.assertEqual(summary["状态"], "成功")
self.assertNotIn("--insecure", captured_command)
self.assertNotIn("-k", captured_command)
self.assertNotIn("--location", captured_command)
self.assertEqual(captured_command[-1], uri)
```

- [x] **Step 2: 新增白名单、超时、超限和非JSON失败测试**

分别验证非白名单URI抛出`ValueError`，进程超时映射为`CURL_TIMEOUT`，响应超过16MiB映射为`API_RESPONSE_TOO_LARGE`，非JSON映射为`API_JSON_INVALID`，且全部不回显响应正文。

- [x] **Step 3: 运行测试确认RED**

Run: `python3 -m unittest tests/数据/test_自动映射Binance来源身份.py -q`

Expected: FAIL，因为现有函数仍使用`urllib`且不接受`runner`与`curl_path`。

- [x] **Step 4: 实现最小传输适配器**

实现以下接口并保持无shell调用：

```python
def run_curl(uri: str, *, runner=subprocess.run, curl_path: Path = CURL_PATH) -> tuple[bytes, dict[str, Any]]:
    validate_endpoint(uri)
    command = build_curl_command(uri, curl_path=curl_path)
    completed = runner(command, check=False, capture_output=True, timeout=HTTP_TIMEOUT_SECONDS)
    if completed.returncode != 0:
        raise CurlTransportError(map_curl_error(completed.returncode), completed.stderr)
    if len(completed.stdout) > MAX_RESPONSE_BYTES:
        raise CurlTransportError("API_RESPONSE_TOO_LARGE", b"")
    return completed.stdout, transport_facts(curl_path, command)
```

- [x] **Step 5: 运行专项测试确认GREEN**

Run: `python3 -m unittest tests/数据/test_自动映射Binance来源身份.py -q`

Expected: PASS，所有传输和既有证据测试通过。

### Task 3: 批次绑定与历史不变回归

**Files:**
- Modify: `scripts/数据/自动映射Binance来源身份.py`
- Modify: `tests/数据/test_自动映射Binance来源身份.py`

- [x] **Step 1: 新增批次传输事实失败测试**

断言`批次清单.json`包含传输器路径、版本、二进制SHA、参数指纹和每个响应SHA，但不包含`_合约索引`或完整API响应。

- [x] **Step 2: 运行测试确认RED**

Run: `python3 -m unittest tests/数据/test_自动映射Binance来源身份.py -q`

Expected: FAIL，现有批次未记录传输器指纹。

- [x] **Step 3: 实现批次绑定并确认GREEN**

把传输事实加入规则指纹和`资源事实`，继续过滤所有以下划线开头的内存字段；不改变成员排序、身份门和计数函数。

Run: `python3 -m unittest tests/数据/test_自动映射Binance来源身份.py -q`

Expected: PASS。

- [x] **Step 4: 验证历史批次树不变**

Run: `git diff --exit-code origin/main -- 'artifacts/数据/Binance来源身份自动映射/binance-source-identity-auto-mapping-20260810T200235Z-30cadf61bf69'`

Expected: exit 0。

### Task 4: 真实复采、全量验证与PR交付

**Files:**
- Create: `artifacts/数据/Binance来源身份自动映射/<新批次>/批次清单.json`
- Create: `artifacts/数据/Binance来源身份自动映射/<新批次>/成员状态.json`
- Create: `artifacts/数据/Binance来源身份自动映射/<新批次>/source-identity-evidence-1.0.json`
- Create: `artifacts/数据/Binance来源身份自动映射/<新批次>/来源身份绑定清单-1.0.json`
- Modify: `docs/研发中心/任务/任务-000091.md`
- Modify: `docs/研发中心/看板.md`

- [x] **Step 1: 执行一次真实串行复采**

Run: `python3 scripts/数据/自动映射Binance来源身份.py`

Expected: 两个固定端点使用默认TLS校验完成或以明确失败码失败；无完整响应落盘；生成唯一追加批次。

- [x] **Step 2: 验证批次计数与边界**

确认BTC与ETH各315、总计630、计数守恒；如九字段仍不完整，所有未证明成员保持`无法判定`，任务-000084保持阻塞。

- [x] **Step 3: 运行合同要求的全部验证**

Run: 任务-000091“验证命令”章节中的专项、数据、审计、研发中心、Python编译、MarkdownLint、敏感扫描和`git diff --check`命令。

Expected: 与本任务相关检查通过；任何main基线失败以同命令对照记录，不伪称通过。

- [x] **Step 4: 更新待评审元数据并提交PR**

任务文件和看板迁移到`待评审`，写入执行分支、实现提交SHA、PR编号、批次、验证结果、限制和安全影响。推送同一分支并创建关联任务-000091的`任务交付`PR。
