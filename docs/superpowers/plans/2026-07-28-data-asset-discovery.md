# 任务-000003数据资产发现实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过固定只读SSH探针发现目标环境和BTC、ETH、SOL候选数据资产，生成可重复验证的CSV与Markdown清单。

**Architecture:** 本地Python命令行工具把固定版本的远端Python探针通过SSH标准输入执行，远端不落盘。探针只返回JSON元数据，本地完成校验、去重、排序、CSV与Markdown渲染；任何失败保留为`无法访问`或`未知`，不推导数据质量与研究可用性。

**Tech Stack:** Python 3标准库、`unittest`、系统SSH客户端、远端Python 3、Markdown、CSV。

---

## 文件结构

- 创建：`scripts/审计/发现数据资产.py`，负责安全策略、远端探针、SSH执行、归一化和输出。
- 创建：`tests/审计/test_发现数据资产.py`，负责安全合同、命令行、失败路径和渲染测试。
- 创建：`artifacts/审计/数据源清单.csv`，保存真实只读发现结果。
- 创建：`docs/审计/数据源清单.md`，解释结果、边界、缺口和复现方式。
- 修改：`docs/研发中心/任务/任务-000003.md`，记录执行状态、交付和验收。
- 修改：`docs/研发中心/看板.md`，同步任务状态。
- 修改：PR #23标题与正文，撤销错误目标阻塞说明并记录最终交付。

### Task 1：纠正任务状态与在途记录

**Files:**

- Modify: `docs/研发中心/任务/任务-000003.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1：删除错误目标产生的阻塞证据**

删除`btc-prod`、`btc-event-prod`及SSH失败相关记录，不在最终差异中保留错误事实。

- [ ] **Step 2：把任务更新为执行中**

任务头部使用以下状态字段：

```markdown
- 状态：执行中
- 优先级：P0
- 执行分支：`codex/000003-access-blocker-20260727`
- 开始时间：2026-07-28（使用实际Asia/Shanghai时间）
- 解除阻塞证据：SSH别名`ubuntu`无交互只读握手成功
```

看板把任务-000003从`阻塞`移到`执行中`；任务-000004至000006继续保持阻塞。

- [ ] **Step 3：验证任务中心状态映射**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import re

task = Path('docs/研发中心/任务/任务-000003.md').read_text()
board = Path('docs/研发中心/看板.md').read_text()
assert re.search(r'^- 状态：执行中$', task, re.M)
section = board.split('## 执行中', 1)[1].split('## ', 1)[0]
assert '| P0 | 任务-000003 |' in section
print('任务-000003状态映射：执行中')
PY
```

Expected: `任务-000003状态映射：执行中`。

- [ ] **Step 4：提交状态纠正**

```bash
git add docs/研发中心/任务/任务-000003.md docs/研发中心/看板.md
git commit -m "docs: 认领任务000003"
```

### Task 2：以失败测试固定安全合同和数据模型

**Files:**

- Create: `tests/审计/test_发现数据资产.py`
- Create: `scripts/审计/发现数据资产.py`

- [ ] **Step 1：写安全合同与归一化失败测试**

测试通过`importlib.util.spec_from_file_location`加载中文路径脚本，定义以下用例：

```python
class 发现数据资产测试(unittest.TestCase):
    def test_远端探针不包含禁止行为(self):
        probe = module.build_remote_probe()
        forbidden = [
            "systemctl restart",
            "systemctl stop",
            "systemctl start",
            "docker inspect",
            ".env",
            "password",
            "private_key",
            "open(",
            "write(",
        ]
        for token in forbidden:
            self.assertNotIn(token, probe.lower())

    def test_归一化会去重并稳定排序(self):
        payload = {
            "batch": {"batch_id": "batch-1", "host": "ubuntu"},
            "assets": [
                {"asset_type": "file_group", "location": "/b", "name": "b"},
                {"asset_type": "file_group", "location": "/a", "name": "a"},
                {"asset_type": "file_group", "location": "/a", "name": "a"},
            ],
            "errors": [],
        }
        normalized = module.normalize_payload(payload)
        self.assertEqual(
            [row["location"] for row in normalized["assets"]],
            ["/a", "/b"],
        )

    def test_非法结构被拒绝(self):
        with self.assertRaises(module.DiscoveryError):
            module.normalize_payload({"assets": "not-a-list"})
```

- [ ] **Step 2：运行测试并确认RED**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: FAIL，原因是`scripts/审计/发现数据资产.py`不存在或目标API未定义。

- [ ] **Step 3：实现最小数据模型与安全常量**

脚本先实现：

```python
class DiscoveryError(RuntimeError):
    pass


PROBE_VERSION = "1"
ROOTS = (
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
    "/var/lib/mysql",
)

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".deploy-backups",
    "deploy-backups",
    "deploy-staging",
    "tests",
    "fixtures",
}

DATA_SUFFIXES = {
    ".csv",
    ".jsonl",
    ".ndjson",
    ".parquet",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".arrow",
    ".feather",
}
```

实现`normalize_payload()`，要求`batch`为字典、`assets`和`errors`为列表，并按
`asset_type + location + name`去重排序；缺失显示字段填`未知`。

- [ ] **Step 4：实现固定探针骨架并确认GREEN**

`build_remote_probe()`返回不含文件读取或写入API的远端Python脚本。远端只使用
`os.scandir()`、`entry.stat(follow_symlinks=False)`和白名单只读子进程命令采集元数据。

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: 3 tests PASS。

- [ ] **Step 5：提交安全核心**

```bash
git add scripts/审计/发现数据资产.py tests/审计/test_发现数据资产.py
git commit -m "test: 固定数据资产发现安全合同"
```

### Task 3：以测试驱动实现SSH执行和远端元数据探针

**Files:**

- Modify: `tests/审计/test_发现数据资产.py`
- Modify: `scripts/审计/发现数据资产.py`

- [ ] **Step 1：写假SSH端到端失败测试**

测试在临时目录创建可执行`ssh`脚本，从固定夹具输出JSON；真实调用CLI：

```python
def test_命令行通过假ssh生成两个输出(self):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        fake_ssh = tmp_path / "ssh"
        fake_ssh.write_text(
            "#!/bin/sh\n"
            "cat >/dev/null\n"
            "printf '%s' '{\"batch\":{\"batch_id\":\"batch-1\",\"host\":\"ubuntu\"},"
            "\"assets\":[{\"asset_type\":\"service\",\"location\":\"mysql.service\","
            "\"name\":\"mysql\"}],\"errors\":[]}'\n"
        )
        fake_ssh.chmod(0o755)
        csv_path = tmp_path / "inventory.csv"
        md_path = tmp_path / "inventory.md"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--host",
                "ubuntu",
                "--ssh-bin",
                str(fake_ssh),
                "--csv-output",
                str(csv_path),
                "--markdown-output",
                str(md_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(csv_path.exists())
        self.assertTrue(md_path.exists())
```

补充SSH退出255、超时和非法JSON测试，断言原输出文件保持不变。

- [ ] **Step 2：运行新增测试并确认RED**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: FAIL，原因是CLI参数、SSH执行或渲染器尚未实现。

- [ ] **Step 3：实现SSH执行器**

实现：

```python
def run_ssh(host: str, ssh_bin: str, timeout: int) -> dict[str, object]:
    command = [
        ssh_bin,
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=yes",
        host,
        "python3 -",
    ]
    try:
        result = subprocess.run(
            command,
            input=build_remote_probe(),
            text=True,
            capture_output=True,
            timeout=timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError("SSH只读发现超时") from exc
    if result.returncode != 0:
        raise DiscoveryError(f"SSH只读发现失败，退出码={result.returncode}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DiscoveryError("远端探针返回非法JSON") from exc
```

错误信息不得回显SSH标准错误，避免意外暴露地址、用户或本机路径。

- [ ] **Step 4：实现远端探针**

探针返回：

```json
{
  "batch": {
    "batch_id": "主机名-UTC采集时间",
    "probe_version": "1",
    "host": "逻辑主机",
    "collected_at": "带时区时间",
    "timezone": "Asia/Shanghai"
  },
  "assets": [],
  "errors": []
}
```

实现以下独立采集器，每个采集器异常只追加`errors`：

- `collect_system()`：主机、OS、内核、时区；
- `collect_mounts()`：`findmnt -rn -o TARGET,FSTYPE,OPTIONS`；
- `collect_services()`：固定服务名的`systemctl show`属性；
- `collect_listeners()`：`ss -lntupH`，只保留协议、端口和进程名；
- `collect_containers()`：`docker ps`和`lxc list`的名称、镜像、状态；
- `collect_files()`：白名单根目录、排除目录和允许扩展名，只用目录项元数据；
- `collect_mysql_metadata()`：无交互查询`information_schema`，失败只记录错误。

文件按`项目根目录 + 相对父目录 + 扩展名`聚合，记录文件数、总字节数、最早和最新
修改时间；从路径名识别`BTC`、`ETH`、`SOL`，无法识别则为`未知`。

- [ ] **Step 5：运行全部审计脚本测试并确认GREEN**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: 全部PASS，失败路径不覆盖既有文件。

- [ ] **Step 6：提交SSH探针**

```bash
git add scripts/审计/发现数据资产.py tests/审计/test_发现数据资产.py
git commit -m "feat: 实现只读数据资产发现探针"
```

### Task 4：以测试驱动实现CSV和Markdown输出

**Files:**

- Modify: `tests/审计/test_发现数据资产.py`
- Modify: `scripts/审计/发现数据资产.py`

- [ ] **Step 1：写输出合同失败测试**

断言CSV表头精确为：

```python
CSV_FIELDS = [
    "资产编号",
    "发现批次",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "文件数",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
]
```

Markdown测试必须找到：执行边界、环境摘要、资产汇总、BTC/ETH/SOL覆盖、数据库限制、
已知缺口、不可推导结论、复现命令和批次编号。

- [ ] **Step 2：运行新增测试并确认RED**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
```

Expected: FAIL，原因是CSV字段或Markdown章节尚未完整。

- [ ] **Step 3：实现原子输出**

`write_outputs()`先在目标目录创建临时文件，完整写入并校验后使用`os.replace()`替换
本地输出。远端不写文件。资产编号使用排序后六位流水号`资产-000001`。

所有空字段归一化为`未知`。数据库元数据失败时保留MySQL服务、端口和存储目录候选，
访问状态写`元数据无法访问`，限制写`未读取凭据，不代表数据库不可用`。

- [ ] **Step 4：运行测试并确认GREEN**

Run:

```bash
python3 -m unittest tests/审计/test_发现数据资产.py -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: 新测试和仓库全部测试PASS。

- [ ] **Step 5：提交输出实现**

```bash
git add scripts/审计/发现数据资产.py tests/审计/test_发现数据资产.py
git commit -m "feat: 生成可验证数据源清单"
```

### Task 5：真实只读发现、验收与PR收尾

**Files:**

- Create: `artifacts/审计/数据源清单.csv`
- Create: `docs/审计/数据源清单.md`
- Modify: `docs/研发中心/任务/任务-000003.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1：对正确目标执行真实只读发现**

Run:

```bash
python3 scripts/审计/发现数据资产.py \
  --host ubuntu \
  --csv-output artifacts/审计/数据源清单.csv \
  --markdown-output docs/审计/数据源清单.md
```

Expected: 退出码0；输出批次编号、资产数量和部分失败数量。MySQL元数据若仍无法访问，
必须显示为部分失败，不能写成通过。

- [ ] **Step 2：验证清单只包含元数据**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import csv

csv_path = Path('artifacts/审计/数据源清单.csv')
rows = list(csv.DictReader(csv_path.open()))
assert rows
assert {'BTC', 'ETH', 'SOL'} & {item for row in rows for item in row['标的范围'].split('|')}
for row in rows:
    assert 'password' not in str(row).lower()
    assert 'token=' not in str(row).lower()
print(f'资产行数：{len(rows)}')
PY
```

Expected: 资产行数大于0；不得要求三种标的都有数据，缺失本身是正式结果。

- [ ] **Step 3：运行完整验证**

Run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
npx --yes markdownlint-cli2 \
  docs/审计/数据源清单.md \
  docs/superpowers/specs/2026-07-28-data-asset-discovery-design.md \
  docs/superpowers/plans/2026-07-28-data-asset-discovery.md \
  docs/研发中心/任务/任务-000003.md \
  docs/研发中心/看板.md
git diff --check origin/main...HEAD
```

另运行任务中心一一映射、禁止命令、凭据/IP模式、CSV重复行、批次一致性和不读取
内容的静态检查。

- [ ] **Step 4：更新任务为待评审**

任务文件记录：执行分支、开始/完成时间、实现提交、PR #23、四项交付物、真实资产
数量、部分失败、验证结果、已知限制和数据安全影响。看板把任务-000003移到`待评审`。

不得把任务-000004至000006解阻；它们必须等待任务-000003评审合并。

- [ ] **Step 5：提交并推送最终状态**

```bash
git add \
  artifacts/审计/数据源清单.csv \
  docs/审计/数据源清单.md \
  scripts/审计/发现数据资产.py \
  tests/审计/test_发现数据资产.py \
  docs/研发中心/任务/任务-000003.md \
  docs/研发中心/看板.md
git commit -m "docs: 提交任务000003审计结果"
git push
```

- [ ] **Step 6：更新PR #23并转为待评审**

PR标题改为`feat: 建立可验证数据源清单（任务-000003）`，正文写明任务、交付物、
验收结果、验证命令、部分失败、数据与安全影响、已知限制和回滚方式。确认最终头SHA
后再把草稿转为Ready；不得自行合并。
