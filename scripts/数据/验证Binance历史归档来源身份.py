#!/usr/bin/env python3
"""只读验证本地Binance历史归档并发布紧凑来源身份批次。"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
from xml.etree import ElementTree


SCHEMA_VERSION = "zhishi-binance-archive-provenance/v1"
BATCH_VERSION = "binance-archive-provenance-batch/1"
CHUNK_SIZE = 1024 * 1024
CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+\.zip)\n?$")
DATE_PATTERN = r"\d{4}-\d{2}-\d{2}"
ALLOWED_ENDPOINT = "https://s3-ap-northeast-1.amazonaws.com/data.binance.vision"
ALLOWED_PREFIXES = frozenset(
    {
        "data/futures/um/daily/trades/BTCUSDT/",
        "data/futures/um/daily/trades/ETHUSDT/",
        "data/futures/um/daily/aggTrades/BTCUSDT/",
    }
)
PINNED_README_URL = (
    "https://raw.githubusercontent.com/binance/binance-public-data/"
    "5c7f3197591c0d54d85dc43066226bc4c671d47a/README.md"
)
PINNED_README_SHA256 = "085ab91377aa9325d44f4c7ad27cce4ab381e158403e1d7df2bad39d1a66f7c6"

FIELD_MAPPINGS = {
    "trades": {
        "id": "成交编号",
        "price": "成交价格",
        "qty": "成交数量",
        "quote_qty": "计价资产成交额",
        "time": "事件时间（Unix毫秒）",
        "is_buyer_maker": "买方是否挂单方",
    },
    "aggTrades": {
        "agg_trade_id": "聚合成交编号",
        "price": "成交价格",
        "quantity": "成交数量",
        "first_trade_id": "首个成交编号",
        "last_trade_id": "末个成交编号",
        "transact_time": "事件时间（Unix毫秒）",
        "is_buyer_maker": "买方是否挂单方",
    },
}

EXPECTED_CONFIG = {
    "schema_version": SCHEMA_VERSION,
    "task_id": "000092",
    "local_root": "/Volumes/data/data/binance/futures/um",
    "curl_path": "/usr/bin/curl",
    "s3_endpoint": ALLOWED_ENDPOINT,
    "official_readme": {
        "document_uri": PINNED_README_URL,
        "sha256": PINNED_README_SHA256,
    },
    "groups": [
        {
            "id": "BTCUSDT-trades",
            "contract": "BTCUSDT",
            "dataset": "trades",
            "relative_dir": "trades/BTCUSDT",
            "remote_prefix": "data/futures/um/daily/trades/BTCUSDT/",
        },
        {
            "id": "ETHUSDT-trades",
            "contract": "ETHUSDT",
            "dataset": "trades",
            "relative_dir": "trades/ETHUSDT",
            "remote_prefix": "data/futures/um/daily/trades/ETHUSDT/",
        },
        {
            "id": "BTCUSDT-aggTrades",
            "contract": "BTCUSDT",
            "dataset": "aggTrades",
            "relative_dir": "aggTrades/BTCUSDT",
            "remote_prefix": "data/futures/um/daily/aggTrades/BTCUSDT/",
        },
    ],
    "observations": ["klines_1d/BTCUSDT.csv", "klines_1d/ETHUSDT.csv"],
    "manifests": ["klines_1d_manifest.json", "full_history_download_summary.json"],
    "limits": {
        "single_file_bytes": 17179869184,
        "member_count": 8192,
        "directory_entry_count": 16384,
        "inventory_entry_count": 50000,
        "exclusion_count": 8192,
        "zip_sample_bytes": 1048576,
        "remote_total_bytes": 33554432,
        "output_bytes": 26214400,
        "shard_bytes": 4718592,
        "total_seconds": 14400,
        "memory_bytes": 268435456,
        "min_available_memory_percent": 20,
        "min_free_disk_bytes": 5368709120,
    },
}


@dataclass(frozen=True)
class Exclusion:
    path: str
    code: str
    counts_as_candidate: bool = False


@dataclass(frozen=True)
class Discovery:
    members: tuple[tuple[Path, Path], ...]
    exclusions: tuple[Exclusion, ...]


@dataclass(frozen=True)
class RemoteObject:
    key: str
    size: int
    etag: str
    last_modified: str


@dataclass(frozen=True)
class S3Page:
    objects: tuple[RemoteObject, ...]
    truncated: bool
    next_marker: str | None


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, *, chunk_size: int = CHUNK_SIZE) -> str:
    if chunk_size < 1:
        raise ValueError("HASH_CHUNK_INVALID")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("SOURCE_NOT_REGULAR")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def parse_checksum(path: Path, expected_name: str) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 1024:
        raise ValueError("CHECKSUM_FILE_INVALID")
    try:
        content = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ValueError("CHECKSUM_READ_FAILED") from error
    match = CHECKSUM_PATTERN.fullmatch(content)
    if match is None or match.group(2) != expected_name:
        raise ValueError("CHECKSUM_FORMAT_INVALID")
    return match.group(1)


def _member_pattern(contract: str, dataset: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(contract)}-{re.escape(dataset)}-{DATE_PATTERN}\.zip$")


def _bounded_sorted_children(
    root: Path, *, max_entries: int, error_code: str
) -> list[Path]:
    if max_entries < 1:
        raise ValueError(error_code)
    children: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            if len(children) >= max_entries:
                raise ValueError(error_code)
            children.append(Path(entry.path))
    return sorted(children, key=lambda item: item.name.encode("utf-8"))


def discover_group(
    root: Path, contract: str, dataset: str, *, max_entries: int
) -> Discovery:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("GROUP_ROOT_INVALID")
    pattern = _member_pattern(contract, dataset)
    zips: dict[str, Path] = {}
    checksums: dict[str, Path] = {}
    exclusions: list[Exclusion] = []
    for path in _bounded_sorted_children(
        root,
        max_entries=max_entries,
        error_code="DIRECTORY_ENTRY_LIMIT_EXCEEDED",
    ):
        info = path.lstat()
        if path.name.startswith("."):
            exclusions.append(Exclusion(path.name, "HIDDEN_FILE_REJECTED"))
            continue
        if stat.S_ISLNK(info.st_mode):
            exclusions.append(Exclusion(path.name, "SYMLINK_REJECTED"))
            continue
        if not stat.S_ISREG(info.st_mode):
            exclusions.append(Exclusion(path.name, "NON_REGULAR_REJECTED"))
            continue
        if pattern.fullmatch(path.name):
            zips[path.name] = path
            continue
        if path.name.endswith(".CHECKSUM") and pattern.fullmatch(path.name[:-9]):
            checksums[path.name[:-9]] = path
            continue
        exclusions.append(Exclusion(path.name, "UNKNOWN_FILE_REJECTED"))
    members: list[tuple[Path, Path]] = []
    for name in sorted(set(zips) | set(checksums), key=lambda value: value.encode("utf-8")):
        if name not in zips or name not in checksums:
            exclusions.append(Exclusion(name, "PAIR_MISSING", True))
            continue
        members.append((zips[name], checksums[name]))
    return Discovery(tuple(members), tuple(exclusions))


def inspect_zip(path: Path, expected_member: str, *, max_sample_bytes: int) -> dict[str, Any]:
    if max_sample_bytes < 1 or max_sample_bytes > CHUNK_SIZE:
        raise ValueError("ZIP_SAMPLE_LIMIT_INVALID")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) != 1:
                raise ValueError("ZIP_MEMBER_INVALID")
            item = members[0]
            pure = PurePosixPath(item.filename)
            if (
                item.is_dir()
                or item.filename != expected_member
                or pure.is_absolute()
                or ".." in pure.parts
                or len(pure.parts) != 1
            ):
                raise ValueError("ZIP_MEMBER_INVALID")
            with archive.open(item, "r") as stream:
                sample = stream.read(max_sample_bytes)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ValueError("ZIP_READ_FAILED") from error
    if b"\n" not in sample:
        raise ValueError("ZIP_SCHEMA_SAMPLE_INVALID")
    first_line = sample.split(b"\n", 1)[0]
    try:
        row = next(csv.reader(io.StringIO(first_line.decode("utf-8"))))
    except (UnicodeError, csv.Error, StopIteration) as error:
        raise ValueError("ZIP_SCHEMA_SAMPLE_INVALID") from error
    normalized = [value.strip() for value in row]
    header_present = any(not _looks_like_value(value) for value in normalized)
    schema_fact = {
        "column_count": len(normalized),
        "header_present": header_present,
        "header": normalized if header_present else [],
        "uncompressed_size": item.file_size,
    }
    schema_fact["schema_version"] = "sha256:" + sha256_bytes(
        canonical_json(
            {
                "column_count": schema_fact["column_count"],
                "header_present": header_present,
                "header": schema_fact["header"],
            }
        ).encode("utf-8")
    )
    return schema_fact


def _looks_like_value(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return True
    try:
        float(value)
    except ValueError:
        return False
    return True


def parse_s3_page(payload: bytes, expected_prefix: str) -> S3Page:
    if expected_prefix not in ALLOWED_PREFIXES:
        raise ValueError("REMOTE_PREFIX_REJECTED")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise ValueError("REMOTE_XML_INVALID") from error
    namespace = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    objects: list[RemoteObject] = []
    for element in root.findall(f"{namespace}Contents"):
        key = element.findtext(f"{namespace}Key") or ""
        size_text = element.findtext(f"{namespace}Size") or ""
        etag = (element.findtext(f"{namespace}ETag") or "").strip('"')
        modified = element.findtext(f"{namespace}LastModified") or ""
        if not key.startswith(expected_prefix) or not size_text.isdigit() or not etag:
            raise ValueError("REMOTE_OBJECT_INVALID")
        objects.append(RemoteObject(key, int(size_text), etag, modified))
    ordered = sorted(objects, key=lambda item: item.key.encode("utf-8"))
    if objects != ordered or len({item.key for item in objects}) != len(objects):
        raise ValueError("REMOTE_OBJECT_ORDER_INVALID")
    truncated = (root.findtext(f"{namespace}IsTruncated") or "false").lower() == "true"
    next_marker = objects[-1].key if truncated and objects else None
    if truncated and next_marker is None:
        raise ValueError("REMOTE_PAGINATION_INVALID")
    return S3Page(tuple(objects), truncated, next_marker)


def build_s3_curl_args(
    curl_path: str, service_uri: str, prefix: str, *, marker: str | None = None
) -> list[str]:
    if curl_path != "/usr/bin/curl" or service_uri != ALLOWED_ENDPOINT:
        raise ValueError("REMOTE_ENDPOINT_REJECTED")
    if prefix not in ALLOWED_PREFIXES:
        raise ValueError("REMOTE_PREFIX_REJECTED")
    args = [
        curl_path,
        "--disable",
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--noproxy",
        "*",
        "--connect-timeout",
        "15",
        "--max-time",
        "60",
        "--max-filesize",
        str(4 * 1024 * 1024),
        "--get",
        "--data-urlencode",
        f"prefix={prefix}",
        "--data",
        "max-keys=1000",
    ]
    if marker is not None:
        args.extend(["--data-urlencode", f"marker={marker}"])
    args.append(service_uri)
    return args


def _safe_curl_environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/var/empty"}


def _run_curl(args: Sequence[str], *, limit: int, timeout: int = 70) -> bytes:
    if not args or args[0] != "/usr/bin/curl":
        raise ValueError("CURL_EXECUTABLE_REJECTED")
    if limit < 1 or timeout < 1:
        raise ValueError("REMOTE_LIMIT_INVALID")
    process = subprocess.Popen(
        list(args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_safe_curl_environment(),
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", limit))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", 64 * 1024))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("REMOTE_GET_TIMEOUT")
            for key, _ in selector.select(min(0.2, remaining)):
                label, cap = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(buffers[label]) + len(chunk) > cap:
                    if label == "stdout":
                        raise ValueError("REMOTE_RESPONSE_TOO_LARGE")
                    raise ValueError("REMOTE_STDERR_TOO_LARGE")
                buffers[label].extend(chunk)
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    if return_code != 0:
        raise ValueError(f"REMOTE_GET_FAILED_{return_code}")
    return bytes(buffers["stdout"])


def fetch_s3_listing(curl_path: str, service_uri: str, prefix: str, *, total_limit: int) -> tuple[dict[str, RemoteObject], str, int]:
    marker: str | None = None
    objects: dict[str, RemoteObject] = {}
    total = 0
    pages = 0
    while True:
        payload = _run_curl(
            build_s3_curl_args(curl_path, service_uri, prefix, marker=marker),
            limit=min(4 * 1024 * 1024, total_limit - total),
        )
        total += len(payload)
        pages += 1
        if total > total_limit or pages > 32:
            raise ValueError("REMOTE_LISTING_LIMIT_EXCEEDED")
        page = parse_s3_page(payload, prefix)
        for item in page.objects:
            if item.key in objects:
                raise ValueError("REMOTE_OBJECT_DUPLICATE")
            objects[item.key] = item
        if not page.truncated:
            break
        if marker is not None and (page.next_marker or "") <= marker:
            raise ValueError("REMOTE_PAGINATION_INVALID")
        marker = page.next_marker
    canonical = [item.__dict__ for item in sorted(objects.values(), key=lambda value: value.key.encode("utf-8"))]
    return objects, sha256_bytes(canonical_json(canonical).encode("utf-8")), total


def fetch_pinned_readme(curl_path: str, document_uri: str, expected_sha256: str) -> tuple[str, int]:
    if curl_path != "/usr/bin/curl" or document_uri != PINNED_README_URL or expected_sha256 != PINNED_README_SHA256:
        raise ValueError("README_IDENTITY_REJECTED")
    parsed = urlparse(document_uri)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com":
        raise ValueError("README_IDENTITY_REJECTED")
    args = [
        curl_path,
        "--disable",
        "--silent",
        "--show-error",
        "--fail",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--noproxy",
        "*",
        "--connect-timeout",
        "15",
        "--max-time",
        "60",
        "--max-filesize",
        str(1024 * 1024),
        "-H",
        "User-Agent: zhishi-binance-provenance/1",
        document_uri,
    ]
    payload = _run_curl(args, limit=1024 * 1024)
    actual = sha256_bytes(payload)
    if actual != expected_sha256:
        raise ValueError("README_SHA256_MISMATCH")
    return actual, len(payload)


def validate_member(
    archive: Path,
    checksum: Path,
    *,
    expected_contract: str,
    dataset: str,
    remote_prefix: str,
    remote_objects: Mapping[str, RemoteObject],
    max_sample_bytes: int,
    max_archive_bytes: int,
) -> dict[str, Any]:
    base = {
        "member_id": f"{expected_contract}:{dataset}:{archive.name}",
        "relative_name": archive.name,
        "contract": expected_contract,
        "dataset": dataset,
        "status": "拒绝",
        "reason_codes": [],
    }
    reasons: list[str] = []
    expected_sha = ""
    actual_sha = ""
    checksum_content_sha = ""
    checksum_content_md5 = ""
    checksum_size = 0
    schema: dict[str, Any] = {}
    remote_archive: RemoteObject | None = None
    remote_checksum: RemoteObject | None = None
    failed = False
    archive_size: int | None = None
    try:
        archive_size = archive.stat().st_size
        if archive_size > max_archive_bytes:
            raise ValueError("SOURCE_FILE_TOO_LARGE")
        expected_sha = parse_checksum(checksum, archive.name)
        checksum_bytes = checksum.read_bytes()
        checksum_size = len(checksum_bytes)
        checksum_content_sha = sha256_bytes(checksum_bytes)
        checksum_content_md5 = hashlib.md5(
            checksum_bytes, usedforsecurity=False
        ).hexdigest()
        actual_sha = sha256_file(archive)
        if actual_sha != expected_sha:
            reasons.append("LOCAL_CHECKSUM_MISMATCH")
        remote_archive = remote_objects.get(remote_prefix + archive.name)
        remote_checksum = remote_objects.get(remote_prefix + checksum.name)
        if remote_archive is None or remote_checksum is None:
            reasons.append("REMOTE_OBJECT_MISSING")
        else:
            if remote_archive.size != archive_size:
                reasons.append("REMOTE_ZIP_SIZE_MISMATCH")
            if (
                "-" in remote_checksum.etag
                or remote_checksum.etag != checksum_content_md5
            ):
                reasons.append("REMOTE_CHECKSUM_ETAG_MISMATCH")
        schema = inspect_zip(
            archive,
            archive.name.removesuffix(".zip") + ".csv",
            max_sample_bytes=max_sample_bytes,
        )
        expected_columns = list(FIELD_MAPPINGS[dataset])
        if schema["column_count"] != len(expected_columns):
            reasons.append("SCHEMA_COLUMN_COUNT_MISMATCH")
        if schema["header_present"] and schema["header"] != expected_columns:
            reasons.append("SCHEMA_HEADER_MISMATCH")
    except ValueError as error:
        reasons.append(str(error))
    except OSError:
        reasons.append("MEMBER_IO_FAILED")
        failed = True
    base["local_evidence"] = {
        "zip_size_bytes": archive_size,
        "zip_content_sha256": actual_sha,
        "checksum_declared_zip_sha256": expected_sha,
        "checksum_file_size_bytes": checksum_size,
        "checksum_file_sha256": checksum_content_sha,
        "checksum_file_md5": checksum_content_md5,
    }
    base["remote_evidence"] = {
        "zip_key": remote_prefix + archive.name,
        "zip_size_bytes": remote_archive.size if remote_archive else None,
        "zip_etag_observed_not_content_hash": remote_archive.etag if remote_archive else "",
        "zip_last_modified": remote_archive.last_modified if remote_archive else "",
        "checksum_key": remote_prefix + checksum.name,
        "checksum_size_bytes": remote_checksum.size if remote_checksum else None,
        "checksum_etag": remote_checksum.etag if remote_checksum else "",
        "checksum_last_modified": remote_checksum.last_modified if remote_checksum else "",
    }
    if schema:
        base["schema"] = schema
    if not reasons:
        mapping = FIELD_MAPPINGS[dataset]
        base.update(
            {
                "status": "已证明",
                "content_sha256": actual_sha,
                "checksum_sha256": expected_sha,
                "size_bytes": archive_size,
                "schema": schema,
                "source_identity": {
                    "source_provider": "Binance",
                    "venue": "Binance",
                    "market_type": "USDⓈ-M合约",
                    "underlying": "BTC" if expected_contract.startswith("BTC") else "ETH",
                    "contract": expected_contract,
                    "data_object": dataset,
                    "schema_exact_version": schema["schema_version"],
                    "authorization_boundary": "Binance公开无认证历史市场数据读取，仅限本项目研究使用，不推定再分发、商业使用或账户权限",
                    "field_chinese_mapping": mapping,
                },
                "evidence_locator": {
                    "local_relative_name": archive.name,
                    "remote_zip_key": remote_prefix + archive.name,
                    "remote_checksum_key": remote_prefix + checksum.name,
                },
            }
        )
    else:
        base["reason_codes"] = sorted(set(reasons))
        if failed:
            base["status"] = "失败"
        elif reasons == ["REMOTE_OBJECT_MISSING"]:
            base["status"] = "无法判定"
    return base


def inventory_fingerprint(
    paths: Sequence[Path], root: Path, *, max_entries: int
) -> tuple[str, int]:
    rows: list[dict[str, Any]] = []

    def append_row(row: dict[str, Any]) -> None:
        if len(rows) >= max_entries:
            raise ValueError("INVENTORY_ENTRY_LIMIT_EXCEEDED")
        rows.append(row)

    for parent in paths:
        if not parent.exists() and not parent.is_symlink():
            append_row({"path": str(parent), "kind": "missing"})
            continue
        candidates = [parent]
        if parent.is_dir() and not parent.is_symlink():
            remaining = max_entries - len(rows)
            candidates.extend(
                _bounded_sorted_children(
                    parent,
                    max_entries=remaining,
                    error_code="INVENTORY_ENTRY_LIMIT_EXCEEDED",
                )
            )
        for path in candidates:
            info = path.lstat()
            try:
                relative = str(path.relative_to(root))
            except ValueError:
                relative = str(path)
            kind = "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
            append_row(
                {
                    "path": relative,
                    "kind": kind,
                    "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns,
                }
            )
    return sha256_bytes(canonical_json(rows).encode("utf-8")), len(rows)


def atomic_publish(root: Path, batch_id: str, files: Mapping[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    target = root / batch_id
    if target.exists():
        raise FileExistsError(batch_id)
    temporary = Path(tempfile.mkdtemp(prefix=f".{batch_id}.", dir=root))
    try:
        for relative, content in sorted(files.items()):
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target


def _json_shards(records: Sequence[Mapping[str, Any]], prefix: str, max_bytes: int) -> dict[str, str]:
    files: dict[str, str] = {}
    items: list[str] = []
    size = 3
    index = 1
    for record in records:
        item = canonical_json(record)
        encoded = len(item.encode("utf-8")) + (2 if items else 0)
        if items and size + encoded > max_bytes:
            files[f"members/{prefix}-{index:03d}.json"] = "[\n" + ",\n".join(items) + "\n]\n"
            index += 1
            items = []
            size = 3
            encoded = len(item.encode("utf-8"))
        items.append(item)
        size += encoded
    if items:
        files[f"members/{prefix}-{index:03d}.json"] = "[\n" + ",\n".join(items) + "\n]\n"
    return files


def _load_config(path: Path) -> tuple[dict[str, Any], str]:
    payload = path.read_bytes()
    config = json.loads(payload)
    if config != EXPECTED_CONFIG:
        raise ValueError("CONFIG_CONTRACT_INVALID")
    if config.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("CONFIG_VERSION_INVALID")
    if config.get("s3_endpoint") != ALLOWED_ENDPOINT:
        raise ValueError("CONFIG_ENDPOINT_INVALID")
    prefixes = {item.get("remote_prefix") for item in config.get("groups", [])}
    if prefixes != ALLOWED_PREFIXES:
        raise ValueError("CONFIG_PREFIXES_INVALID")
    readme = config.get("official_readme", {})
    if readme.get("document_uri") != PINNED_README_URL or readme.get("sha256") != PINNED_README_SHA256:
        raise ValueError("CONFIG_README_INVALID")
    return config, sha256_bytes(payload)


def _validate_execution_paths(config_path: Path, output_root: Path, repo_root: Path) -> None:
    expected_config = (
        repo_root / "config/数据/任务-000092Binance历史归档来源身份.json"
    ).resolve()
    expected_output = (
        repo_root / "artifacts/数据/Binance历史归档来源身份"
    ).resolve()
    if config_path.resolve() != expected_config or output_root.resolve() != expected_output:
        raise ValueError("EXECUTION_PATH_REJECTED")


def _curl_identity(path: str) -> dict[str, str]:
    binary = Path(path)
    version = subprocess.run(
        [path, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_safe_curl_environment(),
        timeout=10,
        check=True,
    ).stdout.splitlines()[0].decode("utf-8", errors="replace")
    return {"path": path, "version": version, "sha256": sha256_file(binary)}


def _system_memory_facts() -> dict[str, Any]:
    if sys.platform == "darwin":
        result = subprocess.run(
            ["/usr/bin/memory_pressure", "-Q"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=5,
            check=True,
        )
        if len(result.stdout) > 4096 or len(result.stderr) > 4096:
            raise ValueError("SYSTEM_MEMORY_PROBE_INVALID")
        total_match = re.search(rb"The system has (\d+)", result.stdout)
        percent_match = re.search(
            rb"System-wide memory free percentage:\s*(\d+)%", result.stdout
        )
        if total_match is None or percent_match is None:
            raise ValueError("SYSTEM_MEMORY_PROBE_INVALID")
        total = int(total_match.group(1))
        percent = float(percent_match.group(1))
        return {
            "system_memory_total_bytes": total,
            "system_memory_available_bytes": int(total * percent / 100),
            "system_memory_available_percent": percent,
            "system_memory_probe": "macos-memory-pressure-q/1",
        }
    if sys.platform.startswith("linux"):
        path = Path("/proc/meminfo")
        if path.stat().st_size > 65536:
            raise ValueError("SYSTEM_MEMORY_PROBE_INVALID")
        content = path.read_text(encoding="ascii")
        values: dict[str, int] = {}
        for line in content.splitlines():
            match = re.fullmatch(r"(MemTotal|MemAvailable):\s+(\d+) kB", line)
            if match:
                values[match.group(1)] = int(match.group(2)) * 1024
        if set(values) != {"MemTotal", "MemAvailable"} or values["MemTotal"] < 1:
            raise ValueError("SYSTEM_MEMORY_PROBE_INVALID")
        return {
            "system_memory_total_bytes": values["MemTotal"],
            "system_memory_available_bytes": values["MemAvailable"],
            "system_memory_available_percent": round(
                values["MemAvailable"] * 100 / values["MemTotal"], 3
            ),
            "system_memory_probe": "linux-proc-meminfo/1",
        }
    raise ValueError("SYSTEM_MEMORY_PROBE_UNSUPPORTED")


def _resource_snapshot(
    output_root: Path, source_root: Path | None = None
) -> dict[str, Any]:
    disk_path = output_root.parent if output_root.parent.exists() else Path.cwd()
    disk = shutil.disk_usage(disk_path)
    facts = {
        **_system_memory_facts(),
        "measured_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "output_disk_path": str(disk_path.resolve()),
        "disk_free_bytes": disk.free,
    }
    if source_root is not None:
        facts["source_disk_path"] = str(source_root.resolve())
        facts["source_disk_free_bytes"] = shutil.disk_usage(source_root).free
    return facts


def _assert_resource_headroom(
    snapshot: Mapping[str, Any],
    *,
    min_memory_percent: float,
    min_disk_free_bytes: int,
    planned_output_bytes: int,
) -> None:
    if float(snapshot["system_memory_available_percent"]) < min_memory_percent:
        raise ValueError("SYSTEM_MEMORY_HEADROOM_LOW")
    if int(snapshot["disk_free_bytes"]) - planned_output_bytes < min_disk_free_bytes:
        raise ValueError("DISK_HEADROOM_LOW")


def _process_max_rss_bytes() -> int:
    usage = __import__("resource").getrusage(__import__("resource").RUSAGE_SELF)
    max_rss_bytes = int(usage.ru_maxrss) if sys.platform != "darwin" else int(usage.ru_maxrss)
    if sys.platform != "darwin":
        max_rss_bytes *= 1024
    return max_rss_bytes


def _resource_facts(
    started: float,
    start_snapshot: Mapping[str, Any],
    pre_publish_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "process_max_rss_bytes": _process_max_rss_bytes(),
        "start_snapshot": dict(start_snapshot),
        "pre_publish_snapshot": dict(pre_publish_snapshot),
        "system_memory_available_bytes_at_publish": pre_publish_snapshot[
            "system_memory_available_bytes"
        ],
        "system_memory_available_percent_at_publish": pre_publish_snapshot[
            "system_memory_available_percent"
        ],
        "system_memory_probe": pre_publish_snapshot["system_memory_probe"],
        "disk_free_bytes_at_publish": pre_publish_snapshot["disk_free_bytes"],
        "processes": 1,
        "hash_chunk_bytes": CHUNK_SIZE,
    }


def execute(config_path: Path, output_root: Path, repo_root: Path) -> Path:
    started = time.monotonic()
    _validate_execution_paths(config_path, output_root, repo_root)
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    config, config_sha = _load_config(config_path)
    limits = config["limits"]
    local_root = Path(config["local_root"])
    start_snapshot = _resource_snapshot(output_root, local_root)
    _assert_resource_headroom(
        start_snapshot,
        min_memory_percent=limits["min_available_memory_percent"],
        min_disk_free_bytes=limits["min_free_disk_bytes"],
        planned_output_bytes=0,
    )
    groups = config["groups"]
    inventory_paths = [local_root / item["relative_dir"] for item in groups]
    inventory_paths.extend(local_root / value for value in config.get("observations", []))
    inventory_paths.extend(local_root / value for value in config.get("manifests", []))
    before_fingerprint, inventory_count = inventory_fingerprint(
        inventory_paths,
        local_root,
        max_entries=limits["inventory_entry_count"],
    )
    curl = _curl_identity(config["curl_path"])
    readme_sha, readme_bytes = fetch_pinned_readme(
        config["curl_path"],
        config["official_readme"]["document_uri"],
        config["official_readme"]["sha256"],
    )

    listing_facts: dict[str, Any] = {}
    remote_by_prefix: dict[str, dict[str, RemoteObject]] = {}
    total_listing_bytes = 0
    for group in groups:
        remaining = config["limits"]["remote_total_bytes"] - total_listing_bytes
        objects, fingerprint, response_bytes = fetch_s3_listing(
            config["curl_path"],
            config["s3_endpoint"],
            group["remote_prefix"],
            total_limit=remaining,
        )
        remote_by_prefix[group["remote_prefix"]] = objects
        total_listing_bytes += response_bytes
        listing_facts[group["id"]] = {
            "prefix": group["remote_prefix"],
            "object_count": len(objects),
            "response_bytes": response_bytes,
            "fingerprint": fingerprint,
        }

    all_records: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    group_summaries: dict[str, Any] = {}
    discovered_candidate_total = 0
    for group in groups:
        discovery = discover_group(
            local_root / group["relative_dir"],
            group["contract"],
            group["dataset"],
            max_entries=limits["directory_entry_count"],
        )
        group_candidate_total = len(discovery.members) + sum(
            item.counts_as_candidate for item in discovery.exclusions
        )
        discovered_candidate_total += group_candidate_total
        if discovered_candidate_total > limits["member_count"]:
            raise ValueError("MEMBER_COUNT_LIMIT_EXCEEDED")
        if len(exclusions) + len(discovery.exclusions) > limits["exclusion_count"]:
            raise ValueError("EXCLUSION_COUNT_LIMIT_EXCEEDED")
        for item in discovery.exclusions:
            exclusions.append(
                {
                    "group": group["id"],
                    "path": item.path,
                    "code": item.code,
                    "counts_as_candidate": item.counts_as_candidate,
                }
            )
        records: list[dict[str, Any]] = []
        for index, (archive, checksum) in enumerate(discovery.members, start=1):
            record = validate_member(
                archive,
                checksum,
                expected_contract=group["contract"],
                dataset=group["dataset"],
                remote_prefix=group["remote_prefix"],
                remote_objects=remote_by_prefix[group["remote_prefix"]],
                max_sample_bytes=limits["zip_sample_bytes"],
                max_archive_bytes=limits["single_file_bytes"],
            )
            record["group"] = group["id"]
            records.append(record)
            if index % 100 == 0 or index == len(discovery.members):
                print(f"{group['id']}: {index}/{len(discovery.members)}", file=sys.stderr, flush=True)
                progress_snapshot = _resource_snapshot(output_root, local_root)
                _assert_resource_headroom(
                    progress_snapshot,
                    min_memory_percent=limits["min_available_memory_percent"],
                    min_disk_free_bytes=limits["min_free_disk_bytes"],
                    planned_output_bytes=0,
                )
                if _process_max_rss_bytes() > limits["memory_bytes"]:
                    raise ValueError("MEMORY_LIMIT_EXCEEDED")
            if time.monotonic() - started > config["limits"]["total_seconds"]:
                raise TimeoutError("TOTAL_TIME_LIMIT_EXCEEDED")
        counts = {status: sum(record["status"] == status for record in records) for status in ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")}
        candidate_exclusions = sum(item.counts_as_candidate for item in discovery.exclusions)
        candidate_total = len(records) + candidate_exclusions
        if candidate_total != sum(counts.values()) + candidate_exclusions:
            raise ValueError("COUNTER_CONSERVATION_FAILED")
        group_summaries[group["id"]] = {
            "candidate_total": candidate_total,
            "observed": len(records),
            **counts,
            "excluded_candidate": candidate_exclusions,
            "non_candidate_exclusions": len(discovery.exclusions) - candidate_exclusions,
        }
        all_records.extend(records)

    after_fingerprint, after_count = inventory_fingerprint(
        inventory_paths,
        local_root,
        max_entries=limits["inventory_entry_count"],
    )
    if before_fingerprint != after_fingerprint or inventory_count != after_count:
        raise ValueError("SOURCE_INVENTORY_DRIFT")
    total_counts = {status: sum(record["status"] == status for record in all_records) for status in ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")}
    batch_seed = sha256_bytes(
        canonical_json(
            {
                "started_at": started_at,
                "config_sha256": config_sha,
                "inventory": before_fingerprint,
                "listing": listing_facts,
            }
        ).encode("utf-8")
    )
    batch_id = f"binance-archive-provenance-{started_at.replace('-', '').replace(':', '')}-{batch_seed[:12]}"
    task_path = repo_root / "docs/研发中心/任务/任务-000092.md"
    script_path = Path(__file__).resolve()
    authorization_fingerprint = sha256_bytes(
        canonical_json(
            {
                "authorization_boundary": "Binance公开无认证历史市场数据读取，仅限本项目研究使用，不推定再分发、商业使用或账户权限",
                "official_readme_sha256": readme_sha,
            }
        ).encode("utf-8")
    )
    summary = {
        "schema_version": BATCH_VERSION,
        "batch_id": batch_id,
        "task_id": "000092",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_inventory_before_sha256": before_fingerprint,
        "source_inventory_after_sha256": after_fingerprint,
        "source_inventory_entry_count": inventory_count,
        "config_sha256": config_sha,
        "task_contract_sha256_at_execution": sha256_file(task_path),
        "executor_sha256": sha256_file(script_path),
        "official_readme": {"document_uri": PINNED_README_URL, "sha256": readme_sha, "bytes": readme_bytes},
        "curl": curl,
        "remote_listings": listing_facts,
        "remote_listing_total_bytes": total_listing_bytes,
        "group_summaries": group_summaries,
        "totals": {"candidate_total": sum(item["candidate_total"] for item in group_summaries.values()), "observed": len(all_records), **total_counts},
        "observation_items": [
            {"path": value, "status": "无法判定", "reason_code": "OFFICIAL_CHECKSUM_MISSING", "included_in_archive_denominator": False}
            for value in config.get("observations", [])
        ],
        "authorization_fingerprint": authorization_fingerprint,
        "source_data_modified": False,
        "task_000084_status_changed": False,
        "stage_gate_changed": False,
        "resource_facts": {},
    }
    files: dict[str, str] = {
        "summary.json": json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "exclusions.json": json.dumps(sorted(exclusions, key=lambda item: (item["group"], item["path"])), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        "schema-catalog.json": json.dumps({"schema_version": "binance-field-mapping/1", "mappings": FIELD_MAPPINGS, "fingerprint": sha256_bytes(canonical_json(FIELD_MAPPINGS).encode("utf-8"))}, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    }
    for group in groups:
        records = [record for record in all_records if record["group"] == group["id"]]
        files.update(_json_shards(records, group["id"], config["limits"]["shard_bytes"]))
    pre_publish_snapshot = _resource_snapshot(output_root, local_root)
    summary["resource_facts"] = _resource_facts(
        started, start_snapshot, pre_publish_snapshot
    )
    if summary["resource_facts"]["process_max_rss_bytes"] > limits["memory_bytes"]:
        raise ValueError("MEMORY_LIMIT_EXCEEDED")
    summary["planned_output_bytes"] = 0
    for _ in range(8):
        files["summary.json"] = (
            json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        )
        total_output = sum(len(value.encode("utf-8")) for value in files.values())
        if summary["planned_output_bytes"] == total_output:
            break
        summary["planned_output_bytes"] = total_output
    else:
        raise ValueError("OUTPUT_SIZE_FIXPOINT_FAILED")
    if total_output > config["limits"]["output_bytes"]:
        raise ValueError("OUTPUT_LIMIT_EXCEEDED")
    pre_publish_snapshot = _resource_snapshot(output_root, local_root)
    _assert_resource_headroom(
        pre_publish_snapshot,
        min_memory_percent=limits["min_available_memory_percent"],
        min_disk_free_bytes=limits["min_free_disk_bytes"],
        planned_output_bytes=total_output,
    )
    summary["resource_facts"] = _resource_facts(
        started, start_snapshot, pre_publish_snapshot
    )
    if summary["resource_facts"]["process_max_rss_bytes"] > limits["memory_bytes"]:
        raise ValueError("MEMORY_LIMIT_EXCEEDED")
    for _ in range(8):
        files["summary.json"] = (
            json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        )
        total_output = sum(len(value.encode("utf-8")) for value in files.values())
        if summary["planned_output_bytes"] == total_output:
            break
        summary["planned_output_bytes"] = total_output
    else:
        raise ValueError("OUTPUT_SIZE_FIXPOINT_FAILED")
    if total_output > limits["output_bytes"]:
        raise ValueError("OUTPUT_LIMIT_EXCEEDED")
    _assert_resource_headroom(
        pre_publish_snapshot,
        min_memory_percent=limits["min_available_memory_percent"],
        min_disk_free_bytes=limits["min_free_disk_bytes"],
        planned_output_bytes=total_output,
    )
    return atomic_publish(output_root, batch_id, files)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证并冻结本地Binance历史归档来源身份")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        target = execute(args.config.resolve(), args.output_root.resolve(), args.repo_root.resolve())
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(canonical_json({"ok": False, "error": str(error)}))
        return 1
    print(canonical_json({"ok": True, "batch": str(target)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
