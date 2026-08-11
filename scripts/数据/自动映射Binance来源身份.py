#!/usr/bin/env python3
"""任务-000090：自动化 Binance 来源身份映射与失败安全批次发布。

入口只读取固定的下载清单和两个公开 exchangeInfo 元数据端点。它不读取清单指向的
行情正文，不使用环境变量或凭据，也不把文件名、目录名或聊天说明当作来源证明。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000090"
REPAIR_TASK_ID = "任务-000091"
CONTRACT_VERSION = "binance-source-identity-auto-mapping-1.0"
EVIDENCE_VERSION = "source-identity-evidence-1.0"
BINDING_VERSION = "source-identity-binding-1.0"
SOURCE_ROOT = Path("/Volumes/data/data/binance/futures/um")
MANIFEST_NAMES = ("klines_1d_manifest.json", "full_history_download_summary.json")
MEMBERS_PATH = REPO_ROOT / "artifacts/数据/来源身份声明九字段复验/source-identity-nine-fields-20260808T074100+0800-v4/来源身份声明九字段复验清单.csv"
CONFIG_PATH = REPO_ROOT / "config/数据/任务-000090Binance来源身份自动映射.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts/数据/Binance来源身份自动映射"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
TOTAL_TIMEOUT_SECONDS = 900
HTTP_TIMEOUT_SECONDS = 60
CURL_CONNECT_TIMEOUT_SECONDS = 15
CURL_PATH = Path("/usr/bin/curl")
CURL_SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
HTTP_STATUS_MARKER = b"\n__ZHISHI_HTTP_STATUS__:"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TARGETS = ("BTC", "ETH")
IDENTITY_FIELDS = (
    "来源提供者", "交易场所", "市场类型", "标的身份", "精确合约",
    "数据对象", "Schema确切版本", "授权边界", "字段中文映射",
)
STATUS_VALUES = ("已证明", "已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")
API_ENDPOINTS = {
    "https://fapi.binance.com/fapi/v1/exchangeInfo": "USDⓈ-M合约",
    "https://dapi.binance.com/dapi/v1/exchangeInfo": "币本位合约",
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, *, max_bytes: int | None = None) -> str:
    if path.is_symlink():
        raise ValueError(f"拒绝符号链接：{path}")
    hasher = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"文件超过资源上限：{path}")
            hasher.update(chunk)
    return hasher.hexdigest()


def task_contract_fingerprint(path: Path) -> str:
    """为任务依赖生成不受状态闭环和执行记录影响的合同指纹。"""

    mutable_prefixes = (
        "- 状态：", "- 执行分支：", "- 开始时间：", "- 实现提交SHA：",
        "- Pull Request：", "- 完成实现时间：",
    )
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "## 执行记录":
            break
        if line.startswith(mutable_prefixes):
            continue
        lines.append(line.rstrip())
    while lines and not lines[-1].strip():
        lines.pop()
    return sha256_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def load_json(path: Path, label: str) -> tuple[Any, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"{label}超过16MiB")
    return json.loads(raw.decode("utf-8")), sha256_bytes(raw)


def validate_config(config: Mapping[str, Any]) -> None:
    required = {"合同版本", "任务编号", "本地只读根目录", "固定清单文件", "成员清单", "Binance公开接口", "标的", "主研究尺度", "事后结果观察窗口", "身份字段", "字段中文映射", "资源上限", "可信HTTPS传输", "安全边界", "匹配规则", "输出绑定"}
    if set(config) != required:
        raise ValueError("任务-000090配置字段漂移")
    if config["合同版本"] != CONTRACT_VERSION or config["任务编号"] != TASK_ID:
        raise ValueError("任务-000090配置版本漂移")
    if config["本地只读根目录"] != str(SOURCE_ROOT) or tuple(config["固定清单文件"]) != MANIFEST_NAMES:
        raise ValueError("任务-000090固定清单漂移")
    if config["成员清单"] != str(MEMBERS_PATH.relative_to(REPO_ROOT)):
        raise ValueError("任务-000090成员清单漂移")
    endpoints = [item.get("端点") for item in config["Binance公开接口"]]
    if endpoints != list(API_ENDPOINTS):
        raise ValueError("任务-000090公开端点漂移")
    if tuple(config["身份字段"]) != IDENTITY_FIELDS:
        raise ValueError("任务-000090身份字段漂移")
    limits = config["资源上限"]
    if limits.get("批次总超时秒") != TOTAL_TIMEOUT_SECONDS or limits.get("最大API响应字节") != MAX_RESPONSE_BYTES or limits.get("最大输出字节") != MAX_OUTPUT_BYTES or limits.get("单进程串行") is not True:
        raise ValueError("任务-000090资源上限漂移")
    transport = config["可信HTTPS传输"]
    expected_transport = {
        "可执行文件": str(CURL_PATH),
        "HTTP方法": "GET",
        "允许协议": "https",
        "跟随重定向": False,
        "连接超时秒": CURL_CONNECT_TIMEOUT_SECONDS,
        "单端点总超时秒": HTTP_TIMEOUT_SECONDS,
        "最大响应字节": MAX_RESPONSE_BYTES,
        "禁止参数": ["--insecure", "-k", "--location", "-L"],
    }
    if transport != expected_transport:
        raise ValueError("任务-000090可信HTTPS传输合同漂移")
    if config["输出绑定"].get("严格顶层证据版本") != EVIDENCE_VERSION or config["输出绑定"].get("绑定清单版本") != BINDING_VERSION:
        raise ValueError("任务-000090输出版本漂移")


def rules_fingerprint(config: Mapping[str, Any]) -> str:
    """绑定身份门、公开端点、资源上限和可信传输合同。"""

    return sha256_bytes(
        canonical(
            {
                "合同版本": CONTRACT_VERSION,
                "身份字段": IDENTITY_FIELDS,
                "接口": API_ENDPOINTS,
                "资源": {
                    "总超时": TOTAL_TIMEOUT_SECONDS,
                    "响应上限": MAX_RESPONSE_BYTES,
                },
                "可信HTTPS传输": config["可信HTTPS传输"],
                "匹配": config["匹配规则"],
            }
        )
    )


def load_members(path: Path) -> tuple[list[dict[str, str]], str]:
    raw = path.read_bytes()
    digest = sha256_bytes(raw)
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"成员编号", "资产编号", "标的", "输入成员SHA-256"}
        if not required.issubset(set(reader.fieldnames or ())):
            raise ValueError("成员清单字段不足")
        for row in reader:
            target = str(row.get("标的", ""))
            member_sha = str(row.get("输入成员SHA-256", ""))
            if target not in TARGETS or not HEX64.fullmatch(member_sha):
                raise ValueError("成员清单标的或SHA非法")
            rows.append({key: str(row.get(key, "")) for key in required})
    if len(rows) != 630 or any(sum(row["标的"] == target for row in rows) != 315 for target in TARGETS):
        raise ValueError("成员分母不是BTC/ETH各315")
    if len({(row["成员编号"], row["资产编号"]) for row in rows}) != len(rows):
        raise ValueError("成员编号或资产编号重复")
    return rows, digest


def _manifest_entries(document: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise ValueError(f"{name}不是对象")
    if name == "klines_1d_manifest.json":
        entries = list(document.get("results") or []) + list(document.get("retry_results") or [])
        if not all(isinstance(item, dict) for item in entries):
            raise ValueError("klines清单条目非法")
        return entries
    entries = document.get("tasks") or []
    if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
        raise ValueError("历史下载清单条目非法")
    return entries


def load_manifests() -> tuple[list[dict[str, Any]], dict[str, str], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    hashes: dict[str, str] = {}
    stats: dict[str, Any] = {"清单条目总数": 0, "固定根目录内路径数": 0, "路径越界数": 0, "符号链接数": 0, "BTC线索数": 0, "ETH线索数": 0}
    for name in MANIFEST_NAMES:
        path = SOURCE_ROOT / name
        if path.parent != SOURCE_ROOT or not path.exists() or path.is_symlink():
            raise FileNotFoundError(f"固定清单不可读：{path}")
        document, digest = load_json(path, name)
        hashes[name] = digest
        current = _manifest_entries(document, name)
        source = str(document.get("source", ""))
        entries.extend({"清单": name, "来源端点": source, **item} for item in current)
    stats["清单条目总数"] = len(entries)
    seen: set[tuple[str, str]] = set()
    for item in entries:
        symbol = str(item.get("symbol", ""))
        path_value = str(item.get("path", item.get("output_dir", "")))
        if path_value:
            candidate = Path(path_value)
            try:
                inside = candidate.is_absolute() and candidate.resolve(strict=False).is_relative_to(SOURCE_ROOT.resolve())
            except (OSError, RuntimeError):
                inside = False
            if inside:
                stats["固定根目录内路径数"] += 1
            else:
                stats["路径越界数"] += 1
            if candidate.is_symlink():
                stats["符号链接数"] += 1
        key = (symbol, path_value)
        if key in seen:
            continue
        seen.add(key)
        if symbol.startswith("BTC"):
            stats["BTC线索数"] += 1
        if symbol.startswith("ETH"):
            stats["ETH线索数"] += 1
    return entries, hashes, stats


def schema_fingerprint(payload: Mapping[str, Any]) -> str:
    symbols = payload.get("symbols")
    symbol_keys = sorted({key for row in symbols if isinstance(row, dict) for key in row}) if isinstance(symbols, list) else []
    shape = {"顶层字段": sorted(payload), "symbols字段": symbol_keys}
    return "sha256:" + sha256_bytes(canonical(shape))


class CurlTransportError(Exception):
    """只携带稳定错误码和脱敏细节指纹的传输异常。"""

    def __init__(
        self,
        code: str,
        detail: bytes = b"",
        *,
        detail_fingerprint: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.detail_fingerprint = detail_fingerprint or sha256_bytes(detail[:MAX_LOG_BYTES])


class BoundedProcessResult:
    """子进程的有界输出结果；stderr 哈希覆盖完整字节流。"""

    def __init__(
        self,
        returncode: int,
        stdout: bytes,
        stderr: bytes,
        stderr_sha256: str,
        stderr_truncated: bool,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stderr_sha256 = stderr_sha256
        self.stderr_truncated = stderr_truncated


def run_bounded_process(
    command: list[str],
    *,
    timeout: int,
    stdout_limit: int,
    stderr_limit: int,
) -> BoundedProcessResult:
    """无 shell 执行并在读取期间强制 stdout/stderr 资源边界。"""

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=CURL_SAFE_ENV,
        bufsize=0,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise CurlTransportError("PROCESS_PIPE_UNAVAILABLE")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout = bytearray()
    stderr = bytearray()
    stderr_hasher = hashlib.sha256()
    stderr_total = 0
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise CurlTransportError("PROCESS_TIMEOUT")
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    if len(stdout) + len(chunk) > stdout_limit:
                        process.kill()
                        process.wait()
                        raise CurlTransportError("PROCESS_STDOUT_TOO_LARGE")
                    stdout.extend(chunk)
                else:
                    stderr_hasher.update(chunk)
                    stderr_total += len(chunk)
                    keep = max(0, stderr_limit - len(stderr))
                    if keep:
                        stderr.extend(chunk[:keep])
        returncode = process.wait()
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return BoundedProcessResult(
        returncode,
        bytes(stdout),
        bytes(stderr),
        stderr_hasher.hexdigest(),
        stderr_total > stderr_limit,
    )


def validate_curl_command(command: list[str], uri: str) -> None:
    """拒绝白名单外端点、可执行文件及会削弱TLS边界的参数。"""

    if uri not in API_ENDPOINTS:
        raise ValueError("公开端点不在白名单")
    if not command or command[0] != str(CURL_PATH) or command[-1] != uri:
        raise ValueError("curl命令边界漂移")
    forbidden = {
        "--insecure", "-k", "--location", "-L", "--location-trusted",
        "--proxy", "-x", "--proxy-user", "-U", "--user", "-u",
        "--cacert", "--capath",
    }
    if forbidden.intersection(command):
        raise ValueError("curl命令包含禁止参数")


def build_curl_command(uri: str, *, curl_path: Path = CURL_PATH) -> list[str]:
    """构建固定、无shell、默认TLS校验的公开GET命令。"""

    if uri not in API_ENDPOINTS:
        raise ValueError("公开端点不在白名单")
    if curl_path != CURL_PATH:
        raise ValueError("curl可执行文件不在白名单")
    command = [
        str(curl_path),
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--request",
        "GET",
        "--connect-timeout",
        str(CURL_CONNECT_TIMEOUT_SECONDS),
        "--max-time",
        str(HTTP_TIMEOUT_SECONDS),
        "--max-filesize",
        str(MAX_RESPONSE_BYTES),
        "--header",
        "User-Agent: zhishi-task-000091/1",
        "--output",
        "-",
        "--write-out",
        "\n__ZHISHI_HTTP_STATUS__:%{http_code}",
        uri,
    ]
    validate_curl_command(command, uri)
    return command


def _run_process(
    runner,
    command: list[str],
    *,
    timeout: int,
    stdout_limit: int,
    stderr_limit: int,
) -> BoundedProcessResult:
    if runner is subprocess.run:
        return run_bounded_process(
            command,
            timeout=timeout,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
    completed = runner(
        command,
        check=False,
        capture_output=True,
        timeout=timeout,
        env=CURL_SAFE_ENV,
    )
    stdout = bytes(completed.stdout or b"")
    full_stderr = bytes(completed.stderr or b"")
    if len(stdout) > stdout_limit:
        raise CurlTransportError("PROCESS_STDOUT_TOO_LARGE")
    return BoundedProcessResult(
        completed.returncode,
        stdout,
        full_stderr[:stderr_limit],
        sha256_bytes(full_stderr),
        len(full_stderr) > stderr_limit,
    )


def inspect_curl_transport(*, runner=subprocess.run, curl_path: Path = CURL_PATH) -> dict[str, str]:
    """冻结固定curl二进制、版本和TLS校验边界。"""

    if curl_path != CURL_PATH:
        raise ValueError("curl可执行文件不在白名单")
    if not curl_path.exists() or curl_path.is_symlink() or not os.access(curl_path, os.X_OK):
        raise CurlTransportError("CURL_EXECUTABLE_UNAVAILABLE")
    try:
        completed = _run_process(
            runner,
            [str(curl_path), "--version"],
            timeout=CURL_CONNECT_TIMEOUT_SECONDS,
            stdout_limit=4096,
            stderr_limit=MAX_LOG_BYTES,
        )
    except CurlTransportError as exc:
        if exc.code == "PROCESS_TIMEOUT":
            raise CurlTransportError("CURL_VERSION_TIMEOUT") from exc
        raise
    except subprocess.TimeoutExpired as exc:
        raise CurlTransportError("CURL_VERSION_TIMEOUT") from exc
    except OSError as exc:
        raise CurlTransportError("CURL_EXECUTION_FAILED") from exc
    if completed.returncode != 0:
        raise CurlTransportError(
            "CURL_VERSION_FAILED",
            completed.stderr,
            detail_fingerprint=completed.stderr_sha256,
        )
    version_line = completed.stdout.decode("utf-8", errors="replace").splitlines()
    if not version_line:
        raise CurlTransportError("CURL_VERSION_INVALID")
    return {
        "可执行文件": str(curl_path),
        "版本": version_line[0][:120],
        "二进制SHA-256": sha256_file(curl_path, max_bytes=MAX_EXECUTABLE_BYTES),
        "TLS校验": "系统默认证书与主机名校验",
        "环境边界SHA-256": sha256_bytes(canonical(CURL_SAFE_ENV)),
    }


def run_curl(
    uri: str,
    *,
    runner=subprocess.run,
    curl_path: Path = CURL_PATH,
) -> tuple[bytes, int, dict[str, str]]:
    """执行固定公开GET并返回内存响应、HTTP状态和脱敏传输事实。"""

    command = build_curl_command(uri, curl_path=curl_path)
    transport = inspect_curl_transport(runner=runner, curl_path=curl_path)
    transport["参数SHA-256"] = sha256_bytes(canonical(command[1:-1]))
    try:
        completed = _run_process(
            runner,
            command,
            timeout=HTTP_TIMEOUT_SECONDS,
            stdout_limit=MAX_RESPONSE_BYTES + len(HTTP_STATUS_MARKER) + 3,
            stderr_limit=MAX_LOG_BYTES,
        )
    except CurlTransportError as exc:
        if exc.code == "PROCESS_TIMEOUT":
            raise CurlTransportError("CURL_TIMEOUT") from exc
        if exc.code == "PROCESS_STDOUT_TOO_LARGE":
            raise CurlTransportError("API_RESPONSE_TOO_LARGE") from exc
        raise
    except subprocess.TimeoutExpired as exc:
        raise CurlTransportError("CURL_TIMEOUT") from exc
    except OSError as exc:
        raise CurlTransportError("CURL_EXECUTION_FAILED") from exc
    if completed.returncode != 0:
        code = {
            28: "CURL_TIMEOUT",
            60: "TLS_CERTIFICATE_VERIFY_FAILED",
            63: "API_RESPONSE_TOO_LARGE",
        }.get(completed.returncode, f"CURL_EXIT_{completed.returncode}")
        raise CurlTransportError(
            code,
            completed.stderr,
            detail_fingerprint=completed.stderr_sha256,
        )
    raw, marker, status_raw = completed.stdout.rpartition(HTTP_STATUS_MARKER)
    if marker != HTTP_STATUS_MARKER or not re.fullmatch(rb"\d{3}", status_raw):
        raise CurlTransportError("HTTP_STATUS_MISSING")
    status = int(status_raw)
    if status != 200:
        raise CurlTransportError(f"HTTP_STATUS_{status}")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CurlTransportError("API_RESPONSE_TOO_LARGE")
    return raw, status, transport


def fetch_exchange_info(
    uri: str,
    started: float,
    *,
    runner=subprocess.run,
    curl_path: Path = CURL_PATH,
) -> dict[str, Any]:
    if uri not in API_ENDPOINTS:
        raise ValueError("公开端点不在白名单")
    market = API_ENDPOINTS[uri]
    summary: dict[str, Any] = {
        "端点": uri,
        "市场类型": market,
        "方法": "GET",
        "授权边界": "Binance公开无认证GET",
    }
    try:
        raw, status, transport = run_curl(uri, runner=runner, curl_path=curl_path)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CurlTransportError("API_JSON_INVALID") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("symbols"), list):
            raise CurlTransportError("API_SCHEMA_INVALID")
        index_fields = ("symbol", "baseAsset", "quoteAsset", "contractType", "status")
        symbol_index = [
            {key: row[key] for key in index_fields if key in row and isinstance(row[key], (str, int, float, bool))}
            for row in payload["symbols"]
            if isinstance(row, dict) and isinstance(row.get("symbol"), str)
        ]
        summary.update({"HTTP状态": status, "响应字节数": len(raw), "响应SHA-256": sha256_bytes(raw), "Schema确切版本指纹": schema_fingerprint(payload), "合约条目数": len(payload["symbols"]), "传输器": transport, "状态": "成功", "_合约索引": symbol_index})
        return summary
    except CurlTransportError as exc:
        reason_material = f"{exc.code}|{exc.detail_fingerprint}".encode("utf-8")
        summary.update({"状态": "失败", "失败原因代码": exc.code, "失败原因指纹": sha256_bytes(reason_material), "已观察秒数": round(time.monotonic() - started, 3)})
        return summary


def member_status(member: Mapping[str, str], *, manifest_stats: Mapping[str, Any], api_summaries: list[Mapping[str, Any]], manifest_entries: list[Mapping[str, Any]] | None = None, inventory_rows: Mapping[str, Mapping[str, str]] | None = None, field_mapping_sha: str = "", auth_fingerprints: Mapping[str, str] | None = None) -> dict[str, Any]:
    target = member["标的"]
    inventory = (inventory_rows or {}).get(member["资产编号"])
    candidates = [item for item in (manifest_entries or []) if item.get("资产编号") == member["资产编号"]]
    api_index = {
        (item.get("市场类型"), row.get("symbol")): row
        for item in api_summaries
        if item.get("状态") == "成功"
        for row in item.get("_合约索引", [])
    }
    candidate = candidates[0] if len(candidates) == 1 else {}
    symbol = str(candidate.get("symbol", ""))
    uri = str(candidate.get("来源端点", ""))
    market = API_ENDPOINTS.get(uri, "")
    matching_api = [item for item in api_summaries if item.get("状态") == "成功" and item.get("端点") == uri and item.get("市场类型") == market]
    has_api = bool(matching_api)
    expected_schema = str(matching_api[0].get("Schema确切版本指纹", "")) if matching_api else ""
    expected_auth = str((auth_fingerprints or {}).get(uri, ""))
    checks = {
        "资产编号唯一绑定": inventory is not None and len(candidates) == 1,
        "路径精确且在固定根目录": bool(candidate.get("path", "")) and Path(str(candidate.get("path"))).is_absolute() and Path(str(candidate.get("path"))).resolve(strict=False).is_relative_to(SOURCE_ROOT.resolve()),
        "符号精确匹配": bool(symbol) and (market, symbol) in api_index and str(api_index[(market, symbol)].get("baseAsset", "")) == target,
        "端点与市场类型精确匹配": bool(uri) and uri in API_ENDPOINTS and bool(str(candidate.get("市场类型", "")).strip()) and market == str(candidate.get("市场类型", "")),
        "成员SHA全等": bool(candidate.get("输入成员SHA-256")) and candidate.get("输入成员SHA-256") == member["输入成员SHA-256"],
        "Schema指纹可复算": bool(expected_schema) and candidate.get("Schema确切版本指纹") == expected_schema,
        "授权指纹可复算": bool(expected_auth) and candidate.get("授权边界指纹") == expected_auth,
        "字段映射指纹全等": bool(field_mapping_sha) and candidate.get("字段中文映射指纹") == field_mapping_sha,
        "九项身份字段完整": all(str(candidate.get(field, "")).strip() for field in IDENTITY_FIELDS),
        "证据定位唯一": bool(str(candidate.get("证据定位", "")).strip()),
        "声明内容SHA可复算": bool(HEX64.fullmatch(str(candidate.get("声明内容SHA-256", "")))),
    }
    complete = all(checks.values()) and has_api
    reason = "EXACT_MATCH_INCOMPLETE"
    if not candidates or inventory is None:
        reason = "MEMBER_ASSET_BINDING_MISSING"
    elif not has_api:
        reason = "PUBLIC_API_METADATA_UNAVAILABLE"
    elif complete:
        reason = "EXACT_MATCH_COMPLETE"
    return {
        "成员编号": member["成员编号"], "资产编号": member["资产编号"], "标的": target,
        "输入成员SHA-256": member["输入成员SHA-256"], "状态": "已证明" if complete else "无法判定", "原因代码": reason,
        "匹配候选数": len(candidates), "匹配符号": symbol, "匹配检查": checks, "证据定位": "" if not complete else str(candidate.get("证据定位", "")),
        "限制": "本地清单未提供可复算的逐成员绑定和内容SHA；公开接口不能追溯证明历史文件" if not complete else "仅限固定输入和当前公开元数据",
        "解除条件": "提供当前成员SHA绑定、精确文件/对象定位、Schema/授权指纹和字段中文映射后追加批次",
    }


def build_identity_records(member: Mapping[str, str], candidate: Mapping[str, Any], field_mapping_sha: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """为已完成九项检查的唯一候选构建相互绑定的六字段/八字段记录。"""

    location = str(candidate.get("证据定位", "")).strip()
    values = {field: str(candidate.get(field, "")).strip() for field in IDENTITY_FIELDS}
    if not location or not all(values.values()) or not HEX64.fullmatch(str(candidate.get("声明内容SHA-256", ""))):
        return [], []
    evidence: list[dict[str, str]] = []
    binding: list[dict[str, str]] = []
    for field in IDENTITY_FIELDS:
        record_id = f"{location}#{field}"
        evidence.append({"证据记录编号": record_id, "资产编号": member["资产编号"], "标的": member["标的"], "输入成员SHA-256": member["输入成员SHA-256"], "证明字段": field, "声明值": values[field]})
        binding.append({"证据记录编号": record_id, "资产编号": member["资产编号"], "标的": member["标的"], "输入成员SHA-256": member["输入成员SHA-256"], "证明字段": field, "声明值": values[field], "证据定位": record_id, "字段中文映射指纹": field_mapping_sha})
    return evidence, binding


def build_batch(*, repo_root: Path = REPO_ROOT, batch_root: Path = DEFAULT_BATCH_ROOT, now: datetime | None = None, fetcher=fetch_exchange_info) -> tuple[Path, dict[str, Any]]:
    started = time.monotonic()
    config, config_sha = load_json(CONFIG_PATH, "任务-000090配置")
    validate_config(config)
    members, member_sha = load_members(MEMBERS_PATH)
    manifests, manifest_hashes, manifest_stats = load_manifests()
    api_summaries = [fetcher(uri, started) for uri in API_ENDPOINTS]
    frozen = now or datetime.now(timezone.utc)
    if frozen.tzinfo is None:
        raise ValueError("冻结时间必须带时区")
    executor_sha = sha256_file(Path(__file__))
    task_path = repo_root / "docs/研发中心/任务/任务-000090.md"
    dependency_paths = {
        "任务-000085": repo_root / "docs/研发中心/任务/任务-000085.md",
        "任务-000089": repo_root / "docs/研发中心/任务/任务-000089.md",
        "任务-000090": task_path,
        "任务-000091": repo_root / "docs/研发中心/任务/任务-000091.md",
    }
    dependency_shas = {
        name: (task_contract_fingerprint(path) if name in {"任务-000090", "任务-000091"} else sha256_file(path))
        for name, path in dependency_paths.items()
    }
    rules_sha = rules_fingerprint(config)
    field_mapping_sha = "sha256:" + sha256_bytes(canonical(config["字段中文映射"]))
    auth_fingerprints = {uri: "sha256:" + sha256_bytes(f"Binance公开无认证GET|{uri}|method=GET".encode("utf-8")) for uri in API_ENDPOINTS}
    manifest_inventory = {
        str(item["资产编号"]): item
        for item in manifests
        if str(item.get("资产编号", ""))
    }
    member_records = [member_status(member, manifest_stats=manifest_stats, api_summaries=api_summaries, manifest_entries=manifests, inventory_rows=manifest_inventory, field_mapping_sha=field_mapping_sha, auth_fingerprints=auth_fingerprints) for member in members]
    evidence_records: list[dict[str, str]] = []
    binding_records: list[dict[str, str]] = []
    for member, record in zip(members, member_records):
        if record["状态"] != "已证明":
            continue
        candidates = [item for item in manifests if item.get("资产编号") == member["资产编号"]]
        candidate_evidence, candidate_binding = build_identity_records(member, candidates[0], field_mapping_sha) if len(candidates) == 1 else ([], [])
        if len(candidate_evidence) != len(IDENTITY_FIELDS) or len(candidate_binding) != len(IDENTITY_FIELDS):
            record["状态"] = "无法判定"
            record["原因代码"] = "EVIDENCE_BINDING_INCOMPLETE"
            record["限制"] = "九项身份字段或六字段/八字段绑定记录不完整；失败安全降级"
            continue
        evidence_records.extend(candidate_evidence)
        binding_records.extend(candidate_binding)
    counts = {status: sum(row["状态"] == status for row in member_records) for status in STATUS_VALUES}
    counts.update({"候选总体": len(member_records), "计数守恒": sum(counts.values()) == len(member_records)})
    summary = {"BTC": {key: sum(row["标的"] == "BTC" and (row["状态"] == key if key in STATUS_VALUES else True) for row in member_records) for key in STATUS_VALUES}, "ETH": {key: sum(row["标的"] == "ETH" and (row["状态"] == key if key in STATUS_VALUES else True) for row in member_records) for key in STATUS_VALUES}}
    summary["BTC"]["候选总体"] = sum(row["标的"] == "BTC" for row in member_records)
    summary["ETH"]["候选总体"] = sum(row["标的"] == "ETH" for row in member_records)
    if len({row["证据记录编号"] for row in evidence_records}) != len(evidence_records) or len({row["证据记录编号"] for row in binding_records}) != len(binding_records):
        raise ValueError("证据记录编号重复，失败安全且不发布")
    evidence = {"证据版本": EVIDENCE_VERSION, "记录": evidence_records}
    binding = {"绑定清单版本": BINDING_VERSION, "记录": binding_records}
    input_fingerprint = sha256_bytes(canonical({"成员清单SHA-256": member_sha, "清单SHA-256": manifest_hashes, "配置SHA-256": config_sha, "依赖SHA-256": dependency_shas}))
    base_id = f"binance-source-identity-auto-mapping-{frozen.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{input_fingerprint[:12]}"
    final_dir = batch_root / base_id
    if final_dir.exists():
        raise FileExistsError(f"批次已存在，禁止覆盖：{final_dir}")
    payloads = {
        "批次清单.json": {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "修复任务编号": REPAIR_TASK_ID, "批次": base_id, "冻结时间": frozen.isoformat(), "输入": {"成员清单路径": str(MEMBERS_PATH.relative_to(repo_root)), "成员清单SHA-256": member_sha, "固定清单": manifest_hashes, "配置SHA-256": config_sha, "依赖SHA-256": dependency_shas, "依赖哈希口径": "任务-000090与任务-000091使用去除状态、执行和交付元数据后的合同指纹；任务-000085与任务-000089使用完整文件SHA-256"}, "规则SHA-256": rules_sha, "执行器SHA-256": executor_sha, "字段中文映射指纹": field_mapping_sha, "API": [{key: value for key, value in item.items() if not key.startswith("_")} for item in api_summaries], "Schema确切版本指纹": {item["端点"]: item.get("Schema确切版本指纹", "未知") for item in api_summaries}, "授权边界指纹": auth_fingerprints, "本地清单统计": manifest_stats, "结果摘要": {"总计": counts, "分标的": summary}, "资源事实": {"单进程串行": True, "最大API响应字节": MAX_RESPONSE_BYTES, "批次总超时秒": TOTAL_TIMEOUT_SECONDS, "实际耗时秒": round(time.monotonic() - started, 3)}, "安全声明": {"本地清单只读": True, "公开GET": True, "远端写入": False, "数据库业务记录读取": False, "读取原始业务正文": False, "读取凭据": False, "真实交易": False}, "结论边界": "无法判定不表达来源已证明、数据质量、因果、预测优势、胜率、收益、研究准入或交易许可"},
        "成员状态.json": {"批次": base_id, "成员": member_records},
        "source-identity-evidence-1.0.json": evidence,
        "来源身份绑定清单-1.0.json": binding,
    }
    serialized = {name: json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n" for name, value in payloads.items()}
    total_bytes = sum(len(text.encode("utf-8")) for text in serialized.values())
    if total_bytes > MAX_OUTPUT_BYTES:
        raise ValueError("输出超过32MiB，失败安全且不发布")
    staging = Path(tempfile.mkdtemp(prefix=f".{base_id}.", dir=str(batch_root)))
    try:
        for name, text in serialized.items():
            (staging / name).write_text(text, encoding="utf-8")
        output_hashes = {name: sha256_file(staging / name) for name in serialized if name != "批次清单.json"}
        manifest_path = staging / "批次清单.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["输出SHA-256"] = output_hashes
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(staging, final_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return final_dir, json.loads((final_dir / "批次清单.json").read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="任务-000090 Binance来源身份自动映射")
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    args = parser.parse_args()
    args.batch_root.mkdir(parents=True, exist_ok=True)
    try:
        batch, manifest = build_batch(batch_root=args.batch_root)
    except Exception as exc:
        print(json.dumps({"状态": "失败安全", "任务编号": TASK_ID, "失败原因代码": str(exc)[:120], "失败原因指纹": sha256_bytes(str(exc).encode("utf-8"))}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps({"状态": "成功", "任务编号": TASK_ID, "批次": batch.name, "结果摘要": manifest["结果摘要"]}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
