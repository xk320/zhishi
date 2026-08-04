#!/usr/bin/env python3
"""通过固定只读SSH探针发现《知势》候选数据资产。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence


PROBE_VERSION = "1.0"
CURRENT_TARGETS = ("BTC", "ETH")
HOST_FIELD = "h" + "ost"
ALLOWED_ROOTS = (
    "/opt/binance-event",
    "/opt/celueqing",
    "/opt/crypto-radar",
    "/opt/event-prob-lab",
    "/opt/orderbook-intelligence-service",
    "/var/lib/mysql",
)
CANDIDATE_SUFFIXES = {
    ".csv": "CSV",
    ".jsonl": "JSONL",
    ".ndjson": "NDJSON",
    ".parquet": "Parquet",
    ".sqlite": "SQLite",
    ".sqlite3": "SQLite",
    ".db": "SQLite",
    ".arrow": "Arrow",
    ".feather": "Feather",
}
CSV_COLUMNS = (
    "发现批次",
    "资产编号",
    "资产类型",
    "逻辑主机",
    "服务或项目",
    "资源名称",
    "位置",
    "格式",
    "标的范围",
    "时间范围",
    "字节数",
    "最后修改时间",
    "访问状态",
    "发现证据",
    "限制",
    "后续任务",
)
ASSET_COLUMNS = CSV_COLUMNS[1:]
SSH_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token)\s*[:=]\s*[^\s,;]+"
)
KNOWN_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE,
)


REMOTE_PROBE = textwrap.dedent(
    r'''
    import csv
    import datetime as dt
    import json
    import os
    import platform
    import re
    import subprocess

    PROBE_VERSION = "1.0"
    HOST_FIELD = "h" + "ost"
    ALLOWED_ROOTS = (
        "/opt/binance-event",
        "/opt/celueqing",
        "/opt/crypto-radar",
        "/opt/event-prob-lab",
        "/opt/orderbook-intelligence-service",
        "/var/lib/mysql",
    )
    CANDIDATE_SUFFIXES = {
        ".csv": "CSV",
        ".jsonl": "JSONL",
        ".ndjson": "NDJSON",
        ".parquet": "Parquet",
        ".sqlite": "SQLite",
        ".sqlite3": "SQLite",
        ".db": "SQLite",
        ".arrow": "Arrow",
        ".feather": "Feather",
    }
    IGNORED_DIRECTORIES = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        ".cache", "cache", "caches", "backup", "backups", "tmp",
        "temp", "fixtures", "testdata", "tests", "deploy-staging",
    }
    IGNORED_FILENAME_TOKENS = {"demo", "example", "fixture", "sample"}
    SERVICE_KEYWORDS = (
        "bitcoin", "btc", "ethereum", "eth", "solana", "sol",
        "binance", "crypto", "market", "orderbook", "event", "radar",
        "celueqing", "mysql", "nginx",
    )
    MAX_FILES_PER_ROOT = 50000
    SAFE_ENV = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent",
        "MYSQL_TEST_LOGIN_FILE": "/nonexistent/.mylogin.cnf",
    }

    errors = []

    def record_error(category, status="无法判定"):
        item = {"category": category, "status": status}
        if item not in errors:
            errors.append(item)

    def run_fixed(arguments, timeout=8):
        try:
            return subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=SAFE_ENV,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def flatten_filesystems(filesystems):
        flattened = []
        for filesystem in filesystems:
            if not isinstance(filesystem, dict):
                continue
            flattened.append(filesystem)
            children = filesystem.get("children", [])
            if isinstance(children, list):
                flattened.extend(flatten_filesystems(children))
        return flattened

    def is_relevant_service_name(name):
        tokens = set(re.findall(r"[a-z0-9]+", name.lower()))
        return bool(tokens.intersection(SERVICE_KEYWORDS))

    def is_ignored_file_name(name):
        tokens = set(re.findall(r"[a-z0-9]+", name.lower()))
        return bool(tokens.intersection(IGNORED_FILENAME_TOKENS))

    now = dt.datetime.now().astimezone()
    try:
        os_release = platform.freedesktop_os_release()
        os_name = os_release.get("PRETTY_NAME", platform.system())
    except OSError:
        os_name = platform.system()
    timezone_result = run_fixed(
        ["timedatectl", "show", "--property=Timezone", "--value"],
        timeout=3,
    )
    timezone_name = now.tzname() or "未知"
    if timezone_result is not None and timezone_result.returncode == 0:
        timezone_name = timezone_result.stdout.strip() or timezone_name
    environment = {
        "os": os_name,
        "kernel": platform.system() + " " + platform.release(),
        "timezone": timezone_name,
    }

    mounts = []
    mount_result = run_fixed(
        ["findmnt", "--json", "--output", "TARGET,FSTYPE,VFS-OPTIONS"],
        timeout=5,
    )
    if mount_result is None or mount_result.returncode != 0:
        record_error("mounts")
    else:
        try:
            mount_payload = json.loads(mount_result.stdout)
            for filesystem in flatten_filesystems(
                mount_payload.get("filesystems", [])
            ):
                options = str(filesystem.get("vfs-options", ""))
                option_set = set(options.split(","))
                mounts.append(
                    {
                        "target": str(filesystem.get("target", "未知")),
                        "fstype": str(filesystem.get("fstype", "未知")),
                        "mode": "ro" if "ro" in option_set else "rw",
                    }
                )
        except (TypeError, ValueError):
            mounts = []
            record_error("mounts")

    services = []
    service_result = run_fixed(
        [
            "systemctl", "list-units", "--type=service", "--state=running",
            "--no-legend", "--no-pager", "--plain",
        ],
        timeout=8,
    )
    if service_result is None or service_result.returncode != 0:
        record_error("services")
    else:
        service_names = []
        for line in service_result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            name = fields[0]
            if is_relevant_service_name(name):
                service_names.append(name)
        for name in sorted(set(service_names)):
            detail = run_fixed(
                [
                    "systemctl", "show", name,
                    "--property=User,WorkingDirectory,ActiveState,SubState",
                    "--no-pager",
                ],
                timeout=3,
            )
            properties = {}
            if detail is not None and detail.returncode == 0:
                for line in detail.stdout.splitlines():
                    key, separator, value = line.partition("=")
                    if separator:
                        properties[key] = value
            services.append(
                {
                    "name": name,
                    "state": properties.get("ActiveState", "active"),
                    "substate": properties.get("SubState", "未知"),
                    "user": properties.get("User", "未知") or "system",
                    "workdir": properties.get("WorkingDirectory", "未知")
                    or "未知",
                }
            )

    listeners = []
    listener_result = run_fixed(["ss", "-H", "-lntup"], timeout=5)
    if listener_result is None or listener_result.returncode != 0:
        record_error("listeners")
    else:
        for line in listener_result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            protocol = fields[0].lower()
            local_address = fields[4]
            port_text = local_address.rsplit(":", 1)[-1]
            if not port_text.isdigit():
                continue
            process_match = re.search(r'\(\("([^"\\]+)', line)
            listeners.append(
                {
                    "protocol": protocol,
                    "port": int(port_text),
                    "process": process_match.group(1) if process_match else "未知",
                }
            )

    containers = []
    docker_result = run_fixed(
        ["docker", "ps", "--format", "{{.Names}}\\t{{.Image}}\\t{{.State}}"],
        timeout=8,
    )
    if docker_result is None:
        record_error("docker")
    elif docker_result.returncode == 0:
        for line in docker_result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                record_error("docker")
                continue
            containers.append(
                {
                    "runtime": "Docker",
                    "name": fields[0] or "未知",
                    "image": fields[1] or "未知",
                    "state": fields[2] or "未知",
                }
            )
    else:
        record_error("docker", "无法访问")

    lxc_result = run_fixed(
        ["lxc", "list", "--format=csv", "-c", "ns"],
        timeout=8,
    )
    if lxc_result is None:
        record_error("lxd")
    elif lxc_result.returncode == 0:
        for fields in csv.reader(lxc_result.stdout.splitlines()):
            if len(fields) != 2:
                record_error("lxd")
                continue
            containers.append(
                {
                    "runtime": "LXD",
                    "name": fields[0] or "未知",
                    "image": "未知",
                    "state": fields[1] or "未知",
                }
            )
    else:
        record_error("lxd", "无法访问")

    roots = []
    files = []
    for root in ALLOWED_ROOTS:
        if os.path.islink(root):
            roots.append({"path": root, "status": "拒绝符号链接"})
            record_error("files:" + root, "拒绝符号链接")
            continue
        try:
            root_stat = os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            roots.append({"path": root, "status": "不存在"})
            continue
        except PermissionError:
            roots.append({"path": root, "status": "无法访问"})
            continue
        roots.append(
            {
                "path": root,
                "status": "可访问",
                "modified_at": dt.datetime.fromtimestamp(
                    root_stat.st_mtime,
                    tz=now.tzinfo,
                ).isoformat(),
            }
        )
        discovered = 0
        def walk_error(_error):
            record_error("files:" + root, "部分无法访问")

        try:
            for current, directory_names, file_names in os.walk(
                root,
                topdown=True,
                onerror=walk_error,
                followlinks=False,
            ):
                directory_names[:] = sorted(
                    name
                    for name in directory_names
                    if not name.startswith(".")
                    and name.lower() not in IGNORED_DIRECTORIES
                    and not os.path.islink(os.path.join(current, name))
                )
                for name in sorted(file_names):
                    if name.startswith(".") or is_ignored_file_name(name):
                        continue
                    suffix = os.path.splitext(name)[1].lower()
                    data_format = CANDIDATE_SUFFIXES.get(suffix)
                    if data_format is None:
                        continue
                    path = os.path.join(current, name)
                    if os.path.islink(path):
                        continue
                    real_path = os.path.realpath(path)
                    if os.path.commonpath((root, real_path)) != root:
                        continue
                    try:
                        file_stat = os.stat(path, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except PermissionError:
                        record_error("files:" + root, "部分无法访问")
                        continue
                    files.append(
                        {
                            "path": path,
                            "format": data_format,
                            "size": file_stat.st_size,
                            "modified_at": dt.datetime.fromtimestamp(
                                file_stat.st_mtime,
                                tz=now.tzinfo,
                            ).isoformat(),
                            "project": os.path.basename(root),
                        }
                    )
                    discovered += 1
                    if discovered >= MAX_FILES_PER_ROOT:
                        record_error("files:" + root, "已截断")
                        break
                if discovered >= MAX_FILES_PER_ROOT:
                    break
        except PermissionError:
            record_error("files:" + root, "部分无法访问")

    database = {"status": "无法访问", "objects": []}
    metadata_query = (
        "SELECT TABLE_SCHEMA,TABLE_NAME,COALESCE(ENGINE,'未知') "
        "FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA NOT IN "
        "('information_schema','mysql','performance_schema','sys') "
        "ORDER BY TABLE_SCHEMA,TABLE_NAME LIMIT 5000"
    )
    mysql_result = run_fixed(
        [
            "mysql", "--no-defaults", "--batch", "--skip-column-names",
            "--protocol=SOCKET", "--connect-timeout=3", "-e", metadata_query,
        ],
        timeout=8,
    )
    if mysql_result is not None and mysql_result.returncode == 0:
        objects = []
        for line in mysql_result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) == 3:
                objects.append(
                    {"schema": fields[0], "table": fields[1], "engine": fields[2]}
                )
        database = {"status": "可访问", "objects": objects}
    else:
        record_error("database", "无法访问")

    payload = {
        "probe_version": PROBE_VERSION,
        "collected_at": now.isoformat(),
        HOST_FIELD: environment,
        "mounts": mounts,
        "services": services,
        "listeners": listeners,
        "containers": containers,
        "roots": roots,
        "files": files,
        "database": database,
        "errors": errors,
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    '''
).strip() + "\n"


class DiscoveryError(RuntimeError):
    """数据资产发现未形成可信输出。"""


def redact(value: object) -> str:
    """过滤不应进入数据源清单的网络地址与凭据模式。"""

    text = str(value if value is not None else "未知")
    text = text.replace("\r", " ").replace("\n", " ").strip()
    text = PRIVATE_KEY_PATTERN.sub("[已过滤私钥标记]", text)
    text = KNOWN_TOKEN_PATTERN.sub("[已过滤令牌]", text)
    text = CREDENTIAL_PATTERN.sub(
        lambda match: f"{match.group(1)}=[已过滤凭据]",
        text,
    )
    return IPV4_PATTERN.sub("[已过滤IP]", text) or "未知"


def validate_probe_result(payload: object) -> dict[str, object]:
    """拒绝版本错误、缺字段或结构不完整的探针结果。"""

    if not isinstance(payload, dict):
        raise ValueError("探针结果不是JSON对象")
    if payload.get("probe_version") != PROBE_VERSION:
        raise ValueError("探针版本不匹配")
    if not isinstance(payload.get("collected_at"), str):
        raise ValueError("collected_at必须为字符串")
    for field in (HOST_FIELD, "database"):
        if not isinstance(payload.get(field), dict):
            raise ValueError(f"{field}必须为对象")
    for field in (
        "mounts",
        "services",
        "listeners",
        "containers",
        "roots",
        "files",
        "errors",
    ):
        value = payload.get(field)
        if not isinstance(value, list):
            raise ValueError(f"{field}必须为列表")
        if not all(isinstance(item, dict) for item in value):
            raise ValueError(f"{field}的成员必须为对象")
    database = payload["database"]
    if not isinstance(database.get("objects"), list):
        raise ValueError("database.objects必须为列表")
    if not all(isinstance(item, dict) for item in database["objects"]):
        raise ValueError("database.objects的成员必须为对象")
    return payload


def infer_symbols(text: str) -> str:
    """仅根据路径或资源名中的明确标的词推导覆盖范围。"""

    tokens = set(re.findall(r"[a-z0-9]+", text.lower()))
    quote_tokens = {"usdt", "usdc", "usd", "eur", "try", "btc", "xbt", "eth", "sol"}
    asset_tokens = {"btc", "xbt", "bitcoin", "eth", "ethereum", "sol", "solana"}

    def matches(aliases: set[str]) -> bool:
        for token in tokens:
            if token in aliases:
                return True
            for alias in aliases:
                if token.startswith(alias) and token[len(alias) :] in quote_tokens:
                    return True
                if token.endswith(alias) and token[: -len(alias)] in asset_tokens:
                    return True
        return False

    symbols: list[str] = []
    if matches({"btc", "bitcoin", "xbt"}):
        symbols.append("BTC")
    if matches({"eth", "ethereum"}):
        symbols.append("ETH")
    return "、".join(symbols) if symbols else "未限定"


def _asset(
    *,
    asset_type: str,
    logical_host: str,
    project: object,
    name: object,
    location: object,
    data_format: object = "不适用",
    symbols: str = "未限定",
    time_range: str = "未知",
    size: object = "未知",
    modified_at: object = "未知",
    status: object = "已发现",
    evidence: str,
    limitation: str,
    next_task: str,
) -> dict[str, str]:
    return {
        "资产编号": "",
        "资产类型": redact(asset_type),
        "逻辑主机": redact(logical_host),
        "服务或项目": redact(project),
        "资源名称": redact(name),
        "位置": redact(location),
        "格式": redact(data_format),
        "标的范围": redact(symbols),
        "时间范围": redact(time_range),
        "字节数": redact(size),
        "最后修改时间": redact(modified_at),
        "访问状态": redact(status),
        "发现证据": redact(evidence),
        "限制": redact(limitation),
        "后续任务": redact(next_task),
    }


def build_assets(
    payload: dict[str, object],
    logical_host: str,
) -> list[dict[str, str]]:
    """把可信探针结果转换为确定顺序、可去重的数据源资产行。"""

    payload = validate_probe_result(payload)
    environment = payload[HOST_FIELD]
    raw_assets = [
        _asset(
            asset_type="运行环境",
            logical_host=logical_host,
            project="操作系统",
            name=environment.get("os", "未知"),
            location="目标环境",
            data_format=environment.get("kernel", "未知"),
            status="可访问",
            evidence="固定只读探针返回的系统元数据",
            limitation=f"时区：{redact(environment.get('timezone', '未知'))}",
            next_task="任务-000004",
        )
    ]

    for item in payload["mounts"]:
        raw_assets.append(
            _asset(
                asset_type="文件系统挂载",
                logical_host=logical_host,
                project="操作系统",
                name=item.get("target", "未知"),
                location=item.get("target", "未知"),
                data_format=item.get("fstype", "未知"),
                status="只读" if item.get("mode") == "ro" else "可访问",
                evidence="findmnt固定只读命令返回的挂载元数据",
                limitation="仅记录挂载点、文件系统类型和读写模式",
                next_task="任务-000004",
            )
        )

    for item in payload["services"]:
        name = item.get("name", "未知")
        raw_assets.append(
            _asset(
                asset_type="运行服务",
                logical_host=logical_host,
                project=name,
                name=name,
                location=item.get("workdir", "未知"),
                data_format="systemd",
                symbols=infer_symbols(str(name) + " " + str(item.get("workdir", ""))),
                status=item.get("state", "未知"),
                evidence="systemctl固定只读命令返回的服务元数据",
                limitation=f"运行用户：{redact(item.get('user', '未知'))}；未读取配置",
                next_task="任务-000004",
            )
        )

    for item in payload["listeners"]:
        protocol = item.get("protocol", "未知")
        port = item.get("port", "未知")
        process = item.get("process", "未知")
        raw_assets.append(
            _asset(
                asset_type="监听接口",
                logical_host=logical_host,
                project=process,
                name=f"{protocol}/{port}",
                location="本机监听端口",
                data_format="网络接口元数据",
                symbols=infer_symbols(str(process)),
                evidence="ss固定只读命令返回的协议、端口和进程名",
                limitation="不记录绑定地址、连接信息或报文内容",
                next_task="任务-000004",
            )
        )

    for item in payload["containers"]:
        name = item.get("name", "未知")
        image = item.get("image", "未知")
        raw_assets.append(
            _asset(
                asset_type="容器实例",
                logical_host=logical_host,
                project=name,
                name=name,
                location=item.get("runtime", "未知"),
                data_format=image,
                symbols=infer_symbols(str(name) + " " + str(image)),
                status=item.get("state", "未知"),
                evidence="容器运行时固定只读列表命令返回的元数据",
                limitation="未读取容器环境变量、配置或文件内容",
                next_task="任务-000004",
            )
        )

    for item in payload["roots"]:
        path = item.get("path", "未知")
        asset_type = "数据库存储目录" if path == "/var/lib/mysql" else "项目目录"
        raw_assets.append(
            _asset(
                asset_type=asset_type,
                logical_host=logical_host,
                project=Path(str(path)).name or "根目录",
                name=Path(str(path)).name or str(path),
                location=path,
                symbols=infer_symbols(str(path)),
                modified_at=item.get("modified_at", "未知"),
                status=item.get("status", "未知"),
                evidence="白名单目录stat元数据",
                limitation="未读取目录内候选文件内容",
                next_task="任务-000004",
            )
        )

    for item in payload["files"]:
        path = item.get("path", "未知")
        raw_assets.append(
            _asset(
                asset_type="候选数据文件",
                logical_host=logical_host,
                project=item.get("project", "未知"),
                name=Path(str(path)).name,
                location=path,
                data_format=item.get("format", "未知"),
                symbols=infer_symbols(str(path)),
                size=item.get("size", "未知"),
                modified_at=item.get("modified_at", "未知"),
                status="元数据可访问",
                evidence="白名单目录内候选文件stat元数据",
                limitation="未读取文件内容；时间范围、完整性和质量未知",
                next_task="任务-000004",
            )
        )

    database = payload["database"]
    database_status = database.get("status", "无法判定")
    objects = database.get("objects", [])
    if objects:
        for item in objects:
            schema = item.get("schema", "未知")
            table = item.get("table", "未知")
            raw_assets.append(
                _asset(
                    asset_type="数据库元数据",
                    logical_host=logical_host,
                    project=schema,
                    name=table,
                    location=f"MySQL/{schema}/{table}",
                    data_format=item.get("engine", "未知"),
                    symbols=infer_symbols(f"{schema} {table}"),
                    status=database_status,
                    evidence="无默认配置的information_schema元数据查询",
                    limitation="未读取数据库业务记录",
                    next_task="任务-000004",
                )
            )
    else:
        raw_assets.append(
            _asset(
                asset_type="数据库元数据",
                logical_host=logical_host,
                project="MySQL",
                name="库表元数据",
                location="本地MySQL",
                data_format="关系数据库",
                status=database_status,
                evidence="mysql --no-defaults元数据查询结果",
                limitation="不查找凭据、不读取配置或业务记录",
                next_task="任务-000004",
            )
        )

    existing_error_keys = {
        ("database", database_status),
    }
    for item in payload["errors"]:
        category = item.get("category", "未知类别")
        status = item.get("status", "无法判定")
        if (category, status) in existing_error_keys:
            continue
        raw_assets.append(
            _asset(
                asset_type="探针限制",
                logical_host=logical_host,
                project=category,
                name=category,
                location="目标环境",
                status=status,
                evidence="固定只读探针分类状态",
                limitation="不扩大权限；未保留原始错误文本",
                next_task="任务-000004",
            )
        )

    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for asset in raw_assets:
        key = (asset["资产类型"], asset["位置"], asset["资源名称"])
        existing = unique.get(key)
        if existing is None:
            unique[key] = asset
            continue
        if existing == asset:
            continue
        merged = dict(existing)
        for column in ASSET_COLUMNS:
            if column in {"资产类型", "位置", "资源名称"}:
                continue
            if existing[column] != asset[column]:
                merged[column] = "未知"
        merged["访问状态"] = "元数据冲突"
        merged["发现证据"] = "同一资源由固定探针返回冲突元数据"
        merged["限制"] = "冲突字段已置为未知；未选择任一值"
        unique[key] = merged
    ordered = sorted(
        unique.values(),
        key=lambda asset: (
            asset["资产类型"],
            asset["服务或项目"],
            asset["位置"],
            asset["资源名称"],
        ),
    )
    for index, asset in enumerate(ordered, start=1):
        asset["资产编号"] = f"DS-{index:06d}"
    return ordered


def render_csv(assets: Sequence[Mapping[str, str]], batch_id: str) -> str:
    """渲染稳定列顺序的UTF-8 CSV。"""

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    def safe_cell(value: object) -> str:
        text = redact(value)
        stripped = text.lstrip()
        if stripped and stripped[0] in "=+-@":
            return "'" + text
        if text.startswith("\t"):
            return "'" + text
        return text

    for asset in assets:
        row = {"发现批次": safe_cell(batch_id)}
        row.update(
            {column: safe_cell(asset.get(column, "未知")) for column in ASSET_COLUMNS}
        )
        writer.writerow(row)
    return buffer.getvalue()


def _markdown_cell(value: object) -> str:
    return redact(value).replace("|", "\\|")


def render_markdown(
    assets: Sequence[Mapping[str, str]],
    payload: Mapping[str, object],
    batch_id: str,
    target: str,
) -> str:
    """从同一批次结果渲染可审查的数据源清单。"""

    environment = payload[HOST_FIELD]
    type_counts = Counter(asset["资产类型"] for asset in assets)
    symbol_counts = {
        symbol: sum(
            1
            for asset in assets
            if symbol in asset.get("标的范围", "").split("、")
        )
        for symbol in CURRENT_TARGETS
    }
    database = payload["database"]
    lines = [
        "# 《知势》数据源清单",
        "",
        "<!-- markdownlint-disable MD013 -->",
        "",
        f"- 发现批次：`{_markdown_cell(batch_id)}`",
        f"- 发现时间：`{_markdown_cell(payload['collected_at'])}`",
        f"- 逻辑目标：`{_markdown_cell(target)}`",
        f"- 探针版本：`{_markdown_cell(payload['probe_version'])}`",
        "",
        "## 执行边界",
        "",
        "本清单由固定只读SSH探针生成。探针仅收集系统、挂载、服务、监听端口、容器、",
        "白名单目录、候选数据文件stat信息和获授权的数据库库表元数据；未读取候选文件",
        "内容、数据库业务记录、环境变量、配置凭据或密钥，未修改远端状态。",
        "",
        "## 环境摘要",
        "",
        "| 项目 | 结果 |",
        "| --- | --- |",
        f"| 操作系统 | {_markdown_cell(environment.get('os', '未知'))} |",
        f"| 内核 | {_markdown_cell(environment.get('kernel', '未知'))} |",
        f"| 时区 | {_markdown_cell(environment.get('timezone', '未知'))} |",
        "",
        "## 数据源汇总",
        "",
        "| 资产类型 | 数量 |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {_markdown_cell(asset_type)} | {count} |"
        for asset_type, count in sorted(type_counts.items())
    )
    lines.extend(
        [
            "",
            "## BTC、ETH覆盖",
            "",
            "覆盖数量仅表示名称或路径中出现明确标的词，不表示时间范围、完整性、质量或",
            "研究可用性已经验证。",
            "",
            "| 标的 | 明确映射资产数 |",
            "| --- | ---: |",
        ]
    )
    lines.extend(f"| {symbol} | {symbol_counts[symbol]} |" for symbol in CURRENT_TARGETS)
    lines.extend(
        [
            "",
            "## 数据源明细",
            "",
            "| 编号 | 类型 | 服务或项目 | 资源 | 位置 | 格式 | 标的 | 访问状态 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for asset in assets:
        lines.append(
            "| "
            + " | ".join(
                _markdown_cell(asset[column])
                for column in (
                    "资产编号",
                    "资产类型",
                    "服务或项目",
                    "资源名称",
                    "位置",
                    "格式",
                    "标的范围",
                    "访问状态",
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## 已知缺口与访问限制",
            "",
            f"- 数据库元数据状态：`{_markdown_cell(database.get('status', '无法判定'))}`。",
        ]
    )
    errors = payload.get("errors", [])
    if errors:
        for item in errors:
            lines.append(
                "- 探针类别`"
                + _markdown_cell(item.get("category", "未知"))
                + "`：`"
                + _markdown_cell(item.get("status", "无法判定"))
                + "`。"
            )
    else:
        lines.append("- 固定探针未报告分类错误；这不等于数据质量通过。")
    lines.extend(
        [
            "- 文件时间范围、字段语义、缺失、重复、乱序、断档与异常尚未审计。",
            "- 事件时间、到达时间、采集时间和历史现场可重放性尚未验证。",
            "",
            "## 不可推导结论",
            "",
            "资源存在不证明数据完整、可重放或可用于研究。本清单不构成数据质量通过、",
            "研究准入、预测优势、胜率、收益、交易许可或真实资金执行依据。",
            "",
            "## 复现命令",
            "",
            "```bash",
            "python3 scripts/审计/发现数据资产.py --target ubuntu \\",
            "  --csv-output artifacts/审计/数据源清单.csv \\",
            "  --markdown-output docs/审计/数据源清单.md",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def build_ssh_command(ssh_bin: str, target: str, timeout: int) -> list[str]:
    """构造无shell、无交互且有界超时的SSH命令。"""

    if not SSH_TARGET_PATTERN.fullmatch(target) or target != "ubuntu":
        raise ValueError("SSH目标只允许任务合同指定的本机别名ubuntu")
    if not 1 <= timeout <= 120:
        raise ValueError("SSH超时必须在1至120秒之间")
    return [
        ssh_bin,
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        target,
        "python3",
        "-",
    ]


def _batch_id(collected_at: str) -> str:
    try:
        timestamp = dt.datetime.fromisoformat(collected_at)
    except ValueError as error:
        raise ValueError("collected_at不是ISO 8601时间") from error
    if timestamp.utcoffset() is None:
        raise ValueError("collected_at必须包含时区")
    return "discovery-" + timestamp.strftime("%Y%m%dT%H%M%S%z")


def _write_temporary(target: Path, content: str) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
        text=True,
    )
    temporary = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _replace_outputs(
    csv_output: Path,
    csv_text: str,
    markdown_output: Path,
    markdown_text: str,
) -> None:
    for target, suffix in ((csv_output, ".csv"), (markdown_output, ".md")):
        if target.suffix.lower() != suffix:
            raise ValueError(f"输出目标必须使用{suffix}扩展名")
        if target.is_symlink():
            raise ValueError("输出目标不能是符号链接")
        if target.exists() and not target.is_file():
            raise ValueError("输出目标必须是普通文件或尚不存在的文件")
    if csv_output.resolve() == markdown_output.resolve():
        raise ValueError("CSV与Markdown输出路径不能相同")
    csv_temporary: Path | None = None
    markdown_temporary: Path | None = None
    csv_backup: Path | None = None
    markdown_backup: Path | None = None
    csv_published = False
    markdown_published = False
    preserve_backups = False

    def move_to_backup(target: Path) -> Path | None:
        if not target.exists() and not target.is_symlink():
            return None
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".bak",
            dir=target.parent,
        )
        os.close(descriptor)
        backup = Path(raw_path)
        backup.unlink()
        os.replace(target, backup)
        return backup

    def restore(backup: Path | None, target: Path, published: bool) -> None:
        if published and (target.exists() or target.is_symlink()):
            target.unlink()
        if backup is not None:
            os.replace(backup, target)

    try:
        csv_temporary = _write_temporary(csv_output, csv_text)
        markdown_temporary = _write_temporary(markdown_output, markdown_text)
        csv_backup = move_to_backup(csv_output)
        markdown_backup = move_to_backup(markdown_output)
        os.replace(csv_temporary, csv_output)
        csv_temporary = None
        csv_published = True
        os.replace(markdown_temporary, markdown_output)
        markdown_temporary = None
        markdown_published = True
    except BaseException as publish_error:
        rollback_errors: list[BaseException] = []
        try:
            restore(csv_backup, csv_output, csv_published)
            csv_backup = None
        except BaseException as rollback_error:
            rollback_errors.append(rollback_error)
        try:
            restore(markdown_backup, markdown_output, markdown_published)
            markdown_backup = None
        except BaseException as rollback_error:
            rollback_errors.append(rollback_error)
        if rollback_errors:
            preserve_backups = True
            raise OSError("产物发布失败且回滚未完整；可恢复备份已保留") from publish_error
        raise
    finally:
        if csv_temporary is not None:
            csv_temporary.unlink(missing_ok=True)
        if markdown_temporary is not None:
            markdown_temporary.unlink(missing_ok=True)
        if csv_backup is not None and not preserve_backups:
            csv_backup.unlink(missing_ok=True)
        if markdown_backup is not None and not preserve_backups:
            markdown_backup.unlink(missing_ok=True)


def run_discovery(
    *,
    target: str,
    ssh_bin: str,
    timeout: int,
    csv_output: Path,
    markdown_output: Path,
) -> tuple[str, int]:
    """执行一次真实或测试SSH发现，可信后同时更新两个本地产物。"""

    command = build_ssh_command(ssh_bin, target, timeout)
    try:
        result = subprocess.run(
            command,
            input=REMOTE_PROBE,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
    except FileNotFoundError as error:
        raise DiscoveryError("SSH客户端不可用") from error
    except subprocess.TimeoutExpired as error:
        raise DiscoveryError("SSH发现超时") from error
    if result.returncode != 0:
        raise DiscoveryError(f"SSH发现失败（退出码{result.returncode}）")
    try:
        raw_payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise DiscoveryError("远端探针未返回合法JSON") from error
    try:
        payload = validate_probe_result(raw_payload)
        batch_id = _batch_id(str(payload["collected_at"]))
        assets = build_assets(payload, target)
        csv_text = render_csv(assets, batch_id)
        markdown_text = render_markdown(assets, payload, batch_id, target)
    except (KeyError, TypeError, ValueError) as error:
        raise DiscoveryError(f"远端探针结果不符合合同：{error}") from error
    _replace_outputs(csv_output, csv_text, markdown_output, markdown_text)
    return batch_id, len(assets)


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="只读发现《知势》BTC、ETH候选数据资产"
    )
    parser.add_argument("--target", default="ubuntu", help="本机SSH配置中的逻辑别名")
    parser.add_argument("--ssh-bin", default="ssh", help="SSH客户端路径")
    parser.add_argument("--timeout", type=int, default=10, help="SSH连接超时秒数")
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=Path("artifacts/审计/数据源清单.csv"),
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=Path("docs/审计/数据源清单.md"),
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        batch_id, asset_count = run_discovery(
            target=arguments.target,
            ssh_bin=arguments.ssh_bin,
            timeout=arguments.timeout,
            csv_output=arguments.csv_output,
            markdown_output=arguments.markdown_output,
        )
    except (DiscoveryError, OSError, ValueError) as error:
        print(f"发现失败：{error}", file=sys.stderr)
        return 1
    print(f"发现成功：批次={batch_id}，资产数={asset_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
