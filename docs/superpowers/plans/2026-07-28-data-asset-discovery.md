# 任务-000003数据资产发现实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过固定只读SSH探针发现目标环境、服务、接口、数据库候选与
BTC、ETH、SOL相关文件元数据，生成可复现的CSV和Markdown清单。

**Architecture:** 本地Python命令行工具把版本固定的Python探针经标准输入发送给
SSH别名`ubuntu`；远端探针只运行固定只读命令和白名单目录元数据扫描，返回JSON。
本地校验、脱敏、归一化、去重、排序后，以同一批次编号写入CSV和Markdown，并在
可捕获的发布失败中回滚两个旧产物。

**Tech Stack:** Python 3标准库、OpenSSH、`unittest`、CSV、JSON、Markdown。

---

## Task 1: 解除阻塞并固定执行合同

**Files:**

- Modify: `docs/研发中心/任务/任务-000003.md`
- Modify: `docs/研发中心/看板.md`

- [x] **Step 1: 用无交互SSH验证解除条件**

Run:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 ubuntu \
  'printf "SSH_OK\\n"; uname -srm; date +%z'
```

Expected: 返回`SSH_OK`、Linux系统信息和`+0800`，且不修改远端状态。

- [x] **Step 2: 同步任务和看板为执行中**

记录分支`codex/000003-access-blocker-20260727`、开始时间、解除阻塞证据和只读边界，
并从看板阻塞区移动到执行中区。

- [x] **Step 3: 检查并提交认领状态**

Run:

```bash
npx --yes markdownlint-cli2 \
  docs/研发中心/任务/任务-000003.md docs/研发中心/看板.md
git diff --check
git commit -m 'docs: 解除任务000003访问阻塞'
```

Expected: Markdown为0 issues，空白检查通过并形成独立认领提交。

## Task 2: 用失败测试定义发现器合同

**Files:**

- Create: `tests/审计/test_发现数据资产.py`
- Test: `tests/审计/test_发现数据资产.py`

- [x] **Step 1: 写实现存在性和模块加载测试**

测试必须先断言`scripts/审计/发现数据资产.py`存在；实现文件缺失时测试明确失败。
模块存在后通过`importlib.util.spec_from_file_location`加载，不依赖包名或第三方库。

- [x] **Step 2: 写纯函数合同测试**

使用固定探针JSON覆盖：

```python
def sample_probe_result() -> dict[str, object]:
    return {
        "probe_version": "1.0",
        "collected_at": "2026-07-28T09:00:00+08:00",
        "host": {
            "os": "Ubuntu 22.04",
            "kernel": "Linux",
            "timezone": "Asia/Shanghai",
        },
        "mounts": [{"target": "/", "fstype": "ext4", "mode": "rw"}],
        "services": [{
            "name": "mysql.service",
            "state": "active",
            "user": "mysql",
            "workdir": "/",
        }],
        "listeners": [{"protocol": "tcp", "port": 3306, "process": "mysqld"}],
        "containers": [],
        "roots": [{"path": "/opt/crypto-radar", "status": "可访问"}],
        "files": [{
            "path": "/opt/crypto-radar/data/btc.csv",
            "format": "CSV",
            "size": 42,
            "modified_at": "2026-07-28T08:00:00+08:00",
            "project": "crypto-radar",
        }],
        "database": {"status": "无法访问", "objects": []},
        "errors": [{"category": "database", "status": "无法访问"}],
    }
```

断言：资产编号稳定、BTC范围正确、未知时间范围不被猜测、数据库失败被明确记录、
相同资源去重、排序稳定、CSV和Markdown批次编号相同。

- [x] **Step 3: 写安全与失败合同测试**

断言固定探针：

- 只包含白名单根目录和候选扩展名；
- SSH参数使用`BatchMode=yes`且目标经严格别名校验；
- 不包含文件内容读取、环境变量、凭据搜索、服务启停、写入或提权行为；
- MySQL命令带`--no-defaults`，只查询`information_schema`元数据；
- SSH失败、非法JSON或非法结构返回非零，且不覆盖既有产物；
- 输出中不出现IPv4、私钥头、令牌或密码值。

- [x] **Step 4: 运行测试并确认正确失败**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: 因实现文件不存在而失败，不是语法、夹具或导入错误。

## Task 3: 实现固定只读探针和本地生成器

**Files:**

- Create: `scripts/审计/发现数据资产.py`
- Modify: `tests/审计/test_发现数据资产.py`

- [x] **Step 1: 实现远端固定探针**

模块常量必须包含`PROBE_VERSION`、`ALLOWED_ROOTS`、`CANDIDATE_SUFFIXES`和
`REMOTE_PROBE`。远端代码只用标准库和固定参数的`subprocess.run`：

```python
ALLOWED_ROOTS = (
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
    "/var/lib/mysql",
)
CANDIDATE_SUFFIXES = {
    ".csv": "CSV", ".jsonl": "JSONL", ".ndjson": "NDJSON",
    ".parquet": "Parquet", ".sqlite": "SQLite", ".sqlite3": "SQLite",
    ".db": "SQLite", ".arrow": "Arrow", ".feather": "Feather",
}
```

探针收集逻辑身份无关的OS、内核、时区、挂载、任务相关服务、监听端口进程名、容器
名称与镜像、白名单根目录和候选文件`stat`元数据。目录遍历不得跟随符号链接，忽略
`.git`、虚拟环境、缓存、备份、部署副本、测试夹具、明确样例文件和隐藏目录；每个
根目录设置明确上限并记录截断。MySQL只运行`mysql --no-defaults`的
`information_schema`元数据查询，失败仅输出`无法访问`，不保留原始错误文本。

- [x] **Step 2: 实现结构校验与安全归一化**

提供：

```python
def validate_probe_result(payload: object) -> dict[str, object]: ...
def build_assets(
    payload: dict[str, object],
    logical_host: str,
) -> list[dict[str, str]]: ...
def infer_symbols(text: str) -> str: ...
def redact(value: object) -> str: ...
```

校验顶层字段和集合类型；拒绝探针版本不匹配。所有文本进入产物前统一过滤IPv4、私钥
头、疑似令牌和`password/secret/token=值`。无法从文件元数据证明的时间范围写`未知`，
不可把资源存在解释为数据质量或研究可用性。

- [x] **Step 3: 实现CLI与双产物失败回滚**

CLI参数：`--target`、`--ssh-bin`、`--timeout`、`--csv-output`、
`--markdown-output`。SSH使用参数数组，不调用shell：

```python
command = [
    ssh_bin,
    "-o", "BatchMode=yes",
    "-o", f"ConnectTimeout={timeout}",
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=1",
    target,
    "python3", "-",
]
```

先完整校验JSON和生成两个内存文本，再拒绝目录、符号链接或扩展名错误的输出目标，
随后在本地输出目录创建临时文件并`os.replace`。任一前置失败不创建、不截断、不覆盖
既有产物；发布失败时尝试同时回滚，回滚失败则保留备份。成功输出批次编号和资产数量，
失败只给中文错误类别及退出码，不回显SSH标准错误中的主机、地址或凭据片段。

- [x] **Step 4: 运行测试直到全部通过**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: 所有发现器合同测试通过，0 failures、0 errors。

- [x] **Step 5: 提交实现与测试**

Run:

```bash
git add scripts/审计/发现数据资产.py tests/审计/test_发现数据资产.py
git commit -m 'feat: 建立只读数据资产发现器'
```

## Task 4: 执行真实只读发现并核验产物

**Files:**

- Create: `artifacts/审计/数据源清单.csv`
- Create: `docs/审计/数据源清单.md`

- [x] **Step 1: 在目标环境执行一次真实只读发现**

Run:

```bash
python3 scripts/审计/发现数据资产.py --target ubuntu \
  --csv-output artifacts/审计/数据源清单.csv \
  --markdown-output docs/审计/数据源清单.md
```

Expected: 命令退出0，两个产物使用同一批次编号；数据库无凭据时记录`无法访问`而不
寻找密码或扩大权限。

- [x] **Step 2: 执行产物合同和敏感信息检查**

用只读Python检查CSV列、编号唯一、排序稳定、BTC/ETH/SOL映射、批次一致与Markdown
必要章节。使用显式模式扫描IPv4、私钥头、GitHub/云令牌和明文凭据；任何命中必须先
确认并删除敏感值，不得提交。

- [x] **Step 3: 提交真实发现产物**

Run:

```bash
git add artifacts/审计/数据源清单.csv docs/审计/数据源清单.md
git commit -m 'docs: 记录数据资产只读发现结果'
```

## Task 5: 完整验收并更新待评审状态

**Files:**

- Modify: `docs/研发中心/任务/任务-000003.md`
- Modify: `docs/研发中心/看板.md`
- Modify: `docs/superpowers/plans/2026-07-28-data-asset-discovery.md`

- [x] **Step 1: 运行完整验证**

Run:

```bash
python3 -m unittest discover -s tests/研发中心 -p 'test_*.py' -v
python3 -m unittest discover -s tests/审计 -p 'test_*.py' -v
npx --yes markdownlint-cli2 \
  docs/superpowers/specs/2026-07-28-data-asset-discovery-design.md \
  docs/superpowers/plans/2026-07-28-data-asset-discovery.md \
  docs/审计/数据源清单.md \
  docs/研发中心/任务/任务-000003.md \
  docs/研发中心/看板.md
git diff --check origin/main...HEAD
```

Expected: 全部测试通过、Markdown为0 issues、无空白错误。

- [x] **Step 2: 逐项核验任务交付与安全边界**

确认四个交付物存在；真实产物只包含允许的元数据；未读取候选文件内容或数据库业务
记录；未修改服务器、数据库、服务、权限、防火墙或原始数据；未产生胜率、收益、
质量、可重放或交易许可结论。

- [x] **Step 3: 更新任务和看板为待评审**

任务文件记录实现提交、PR #23、交付物、实际验证结果、已知限制、数据与安全影响、
需要人工决策和自动合并资格。看板同步移动到待评审区。

- [x] **Step 4: 提交并推送最终状态，更新PR正文并转为可评审**

Run:

```bash
git commit -m 'docs: 更新任务000003待评审状态'
git push
env -u GITHUB_TOKEN gh pr ready 23 --repo xk320/zhishi
```

PR正文必须包含任务、交付物、验收结果、验证命令、已知限制、数据与安全影响和回滚
方式。任务缺少基线类型，且PR包含脚本、测试和CSV，因此自动合并资格为“不符合并转
人工”，不得自行合并。
