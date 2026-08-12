"""任务-000106 阶段1多年成本与执行证据的确定性闭合工具。"""

import argparse
import calendar
import csv
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


ALLOWED_EXTERNAL_ROOT = Path("/Volumes/data/zhishi/阶段1成本执行/任务-000106")


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
    next_token: str | None


@dataclass(frozen=True)
class InventoryListing:
    objects: tuple[RemoteObject, ...]
    response_bytes: int

    def __iter__(self):
        return iter(self.objects)

    def __len__(self):
        return len(self.objects)


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_config(config: Mapping[str, Any]) -> None:
    if config.get("任务编号") != "任务-000106":
        raise ValueError("CONFIG_TASK_INVALID")
    if config.get("S3服务域") != "https://s3-ap-northeast-1.amazonaws.com/data.binance.vision":
        raise ValueError("CONFIG_S3_ORIGIN_INVALID")
    groups = config.get("归档组")
    expected = {(s, k) for s in ("BTCUSDT", "ETHUSDT") for k in ("fundingRate", "bookTicker", "bookDepth")}
    if not isinstance(groups, list) or len(groups) != 6:
        raise ValueError("CONFIG_GROUPS_INVALID")
    if {(row.get("标的"), row.get("对象类型")) for row in groups} != expected:
        raise ValueError("CONFIG_GROUPS_INVALID")
    for row in groups:
        if row.get("组编号") != f'{row["标的"]}-{row["对象类型"]}':
            raise ValueError("CONFIG_GROUP_ID_INVALID")
        prefix = row.get("前缀", "")
        if not prefix.endswith(f'/{row["标的"]}/') or ".." in prefix:
            raise ValueError("CONFIG_PREFIX_INVALID")
        if not isinstance(row.get("Schema"), list) or not row["Schema"]:
            raise ValueError("CONFIG_SCHEMA_INVALID")
        probe = row.get("探针对象", "")
        expected_dates = {"fundingRate": "2020-01", "bookTicker": "2023-05-16", "bookDepth": "2023-01-01"}
        if probe != f'{row["组编号"]}-{expected_dates[row["对象类型"]]}.zip':
            raise ValueError("CONFIG_PROBE_INVALID")
    limits = config.get("资源上限", {})
    if limits.get("网络总字节") != 20 * 1024**3 or limits.get("RSS字节") != 512 * 1024**2:
        raise ValueError("CONFIG_RESOURCE_LIMIT_INVALID")
    if limits.get("ZIP解压字节") != 2 * 1024**3:
        raise ValueError("CONFIG_ZIP_RESOURCE_LIMIT_INVALID")
    if config.get("运行时", {}).get("Demo主机") != "demo-fapi.binance.com":
        raise ValueError("CONFIG_DEMO_HOST_INVALID")
    expected_upstream = {
        "任务-000105": {
            "批次": "stage1-current-final-gate-20260812T213100Z-6c0e4bf5d923",
            "结果SHA-256": "43814e0f70143eb798b7dea71a36dfa4383b95bd9fff865c808f767ac8f1c4b0",
        },
        "任务-000094批次": "stage1-time-quality-20260812T091000Z-6968246516ef",
        "任务-000099批次": "stage1-prior-frozen-replay-20260812T130000Z-ca8ae0a8ecd7",
    }
    if config.get("上游绑定") != expected_upstream:
        raise ValueError("CONFIG_UPSTREAM_INVALID")


def parse_s3_page(xml: bytes, prefix: str, config: Mapping[str, Any]) -> S3Page:
    validate_config(config)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError("S3_XML_INVALID") from exc
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    objects: list[RemoteObject] = []
    for item in root.findall("s3:Contents", ns):
        key = item.findtext("s3:Key", default="", namespaces=ns)
        if not key.startswith(prefix):
            raise ValueError("S3_PREFIX_ESCAPE")
        try:
            size = int(item.findtext("s3:Size", default="", namespaces=ns))
        except ValueError as exc:
            raise ValueError("S3_SIZE_INVALID") from exc
        if size < 0:
            raise ValueError("S3_SIZE_INVALID")
        objects.append(RemoteObject(
            key=key,
            size=size,
            etag=item.findtext("s3:ETag", default="", namespaces=ns).strip('"'),
            last_modified=item.findtext("s3:LastModified", default="", namespaces=ns),
        ))
    truncated = root.findtext("s3:IsTruncated", default="false", namespaces=ns).lower() == "true"
    token = root.findtext("s3:NextContinuationToken", default="", namespaces=ns) or None
    if truncated and not token:
        raise ValueError("S3_CONTINUATION_TOKEN_MISSING")
    return S3Page(tuple(objects), truncated, token)


def build_s3_curl_args(prefix: str, config: Mapping[str, Any], continuation_token: str | None = None) -> list[str]:
    validate_config(config)
    query = [("list-type", "2"), ("prefix", prefix)]
    if continuation_token:
        query.append(("continuation-token", continuation_token))
    url = f'{config["S3服务域"]}/?{urllib.parse.urlencode(query)}'
    return ["curl", "--fail", "--silent", "--show-error", "--proto", "=https", url]


def list_inventory(
    group: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    runner=subprocess.run,
) -> InventoryListing:
    """串行读取一个绑定前缀的 S3 清单；任何异常均失败关闭。"""
    validate_config(config)
    objects: list[RemoteObject] = []
    response_bytes = 0
    token: str | None = None
    seen_tokens: set[str] = set()
    limits = config["资源上限"]
    while True:
        args = build_s3_curl_args(str(group["前缀"]), config, token)
        result = runner(args, check=False, capture_output=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError("S3_LIST_FAILED")
        payload = result.stdout
        if not isinstance(payload, bytes):
            raise ValueError("S3_RESPONSE_INVALID")
        response_bytes += len(payload)
        if response_bytes > limits["清单响应字节"]:
            raise ValueError("INVENTORY_RESPONSE_LIMIT_EXCEEDED")
        page = parse_s3_page(payload, str(group["前缀"]), config)
        objects.extend(page.objects)
        if len(objects) > limits["清单对象数"]:
            raise ValueError("INVENTORY_OBJECT_LIMIT_EXCEEDED")
        _enforce_rss_limit(config)
        if not page.truncated:
            return InventoryListing(tuple(objects), response_bytes)
        if page.next_token in seen_tokens:
            raise ValueError("S3_CONTINUATION_TOKEN_REPEATED")
        token = page.next_token
        if token is None:
            raise ValueError("S3_CONTINUATION_TOKEN_MISSING")
        seen_tokens.add(token)


def _archive_period(name: str, group: Mapping[str, Any]) -> tuple[str, str]:
    stem = re.escape(str(group["组编号"]))
    monthly = re.fullmatch(rf"{stem}-(\d{{4}})-(\d{{2}})\.zip", name)
    if monthly:
        year, month = map(int, monthly.groups())
        try:
            last = calendar.monthrange(year, month)[1]
        except calendar.IllegalMonthError as exc:
            raise ValueError("ARCHIVE_NAME_INVALID") from exc
        return f"{year:04d}-{month:02d}-01", f"{year:04d}-{month:02d}-{last:02d}"
    daily = re.fullmatch(rf"{stem}-(\d{{4}})-(\d{{2}})-(\d{{2}})\.zip", name)
    if daily:
        value = "-".join(daily.groups())
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("ARCHIVE_NAME_INVALID") from exc
        return value, value
    raise ValueError("ARCHIVE_NAME_INVALID")


def normalize_inventory(rows: Iterable[RemoteObject], group: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    validate_config(config)
    prefix = str(group["前缀"])
    by_key: dict[str, RemoteObject] = {}
    for row in rows:
        if not row.key.startswith(prefix) or row.key in by_key:
            raise ValueError("ARCHIVE_INVENTORY_INVALID")
        by_key[row.key] = row
    archives = sorted(key for key in by_key if key.endswith(".zip"))
    checksums = {key.removesuffix(".CHECKSUM") for key in by_key if key.endswith(".zip.CHECKSUM")}
    if not archives or set(archives) != checksums or len(by_key) != len(archives) * 2:
        raise ValueError("ARCHIVE_PAIR_MISSING")
    periods = [_archive_period(Path(key).name, group) for key in archives]
    normalized = [
        {"key": key, "size": by_key[key].size, "checksum_key": key + ".CHECKSUM", "checksum_size": by_key[key + ".CHECKSUM"].size}
        for key in archives
    ]
    return {
        "组编号": group["组编号"],
        "标的": group["标的"],
        "对象类型": group["对象类型"],
        "成员数": len(archives),
        "总字节": sum(by_key[key].size + by_key[key + ".CHECKSUM"].size for key in archives),
        "覆盖起点": min(start for start, _ in periods),
        "覆盖终点": max(end for _, end in periods),
        "配对完整": True,
        "清单SHA-256": canonical_sha256(normalized),
    }


def _safe_zip_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def validate_zip_uncompressed_size(size: int, config: Mapping[str, Any]) -> None:
    if not isinstance(size, int) or size < 0 or size > config["资源上限"]["ZIP解压字节"]:
        raise ValueError("ZIP_RESOURCE_LIMIT_EXCEEDED")


def validate_probe(archive_path: Path, checksum_path: Path, group: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    validate_config(config)
    archive_path, checksum_path = Path(archive_path), Path(checksum_path)
    if archive_path.name + ".CHECKSUM" != checksum_path.name:
        raise ValueError("CHECKSUM_FILE_INVALID")
    match = re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)\r?\n?", checksum_path.read_text(encoding="ascii"))
    if not match or match.group(2).strip() != archive_path.name:
        raise ValueError("CHECKSUM_FORMAT_INVALID")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest.lower() != match.group(1).lower():
        raise ValueError("CHECKSUM_MISMATCH")
    limits = config["资源上限"]
    if archive_path.stat().st_size > limits["单对象字节"]:
        raise ValueError("OBJECT_DOWNLOAD_LIMIT_EXCEEDED")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) != 1 or len(members) > limits["ZIP成员数"]:
                raise ValueError("ZIP_MEMBER_INVALID")
            member = members[0]
            expected_csv = archive_path.name.removesuffix(".zip") + ".csv"
            if not _safe_zip_member(member.filename) or member.filename != expected_csv or member.is_dir():
                raise ValueError("ZIP_MEMBER_INVALID")
            validate_zip_uncompressed_size(member.file_size, config)
            with archive.open(member) as stream:
                header_bytes = stream.readline(65537)
            if len(header_bytes) > 65536 or not header_bytes.endswith(b"\n"):
                raise ValueError("SCHEMA_INVALID")
    except zipfile.BadZipFile as exc:
        raise ValueError("ZIP_INVALID") from exc
    try:
        header = next(csv.reader([header_bytes.decode("utf-8-sig").rstrip("\r\n")]))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("SCHEMA_INVALID") from exc
    if header != group["Schema"]:
        raise ValueError("SCHEMA_MISMATCH")
    return {"状态": "通过", "Schema": header, "SHA-256": digest}


def decide_acquire(inventory: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    if not inventory.get("配对完整"):
        reasons.append("ARCHIVE_PAIR_MISSING")
    if not isinstance(inventory.get("总字节"), int) or inventory.get("总字节", -1) < 0:
        reasons.append("INVENTORY_SIZE_INVALID")
    elif inventory["总字节"] > config["资源上限"]["网络总字节"]:
        reasons.append("OBJECT_DOWNLOAD_LIMIT_EXCEEDED")
    window = config["正式窗口"].get(inventory.get("标的"), {})
    if set(window) != {"起点", "终点"}:
        reasons.append("FORMAL_WINDOW_INVALID")
    if inventory.get("覆盖起点", "9999") > window["起点"] or inventory.get("覆盖终点", "") < window["终点"]:
        reasons.append("FORMAL_WINDOW_NOT_COVERED")
    return {"状态": "拒绝" if reasons else "允许", "原因代码": reasons}


def demo_credentials_status(environ: Mapping[str, str], config: Mapping[str, Any]) -> dict[str, Any]:
    key = bool(environ.get("ZHISHI_BINANCE_DEMO_API_KEY"))
    secret = bool(environ.get("ZHISHI_BINANCE_DEMO_API_SECRET"))
    return {"状态": "凭据存在（尚未执行）" if key and secret else "未执行", "API_Key存在": key, "API_Secret存在": secret}


def validate_mainnet_execution_evidence(evidence: Mapping[str, Any] | None, config: Mapping[str, Any]) -> dict[str, Any]:
    if evidence is None:
        return {"状态": "无法判定", "原因代码": ["MAINNET_EXECUTION_EVIDENCE_MISSING"]}
    reasons: list[str] = []
    if evidence.get("schema_version") != "zhishi-mainnet-execution-history/v1":
        reasons.append("EVIDENCE_SCHEMA_INVALID")
    try:
        created = datetime.fromisoformat(str(evidence.get("created_at")))
        cutoff = datetime.fromisoformat(config["运行时"]["主网证据事前截止"])
        if created.tzinfo is None or created >= cutoff:
            reasons.append("EVIDENCE_NOT_PREEXISTING")
    except (TypeError, ValueError):
        reasons.append("EVIDENCE_NOT_PREEXISTING")
    records = evidence.get("records")
    if not isinstance(records, list) or not records or evidence.get("candidate_total") != len(records):
        reasons.append("EVIDENCE_DENOMINATOR_INCOMPLETE")
    required_times = {"信号时点", "下单时点", "成交时点", "确认时点"}
    if isinstance(records, list) and any(not required_times.issubset(row) for row in records if isinstance(row, dict)):
        reasons.append("EVIDENCE_FOUR_TIMESTAMPS_INCOMPLETE")
    if not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("content_sha256", ""))):
        reasons.append("EVIDENCE_CONTENT_ADDRESS_INVALID")
    else:
        addressed = {key: value for key, value in evidence.items() if key != "content_sha256"}
        if canonical_sha256(addressed) != evidence["content_sha256"]:
            reasons.append("EVIDENCE_CONTENT_ADDRESS_MISMATCH")
    return {"状态": "拒绝" if reasons else "通过", "原因代码": reasons}


def build_leaf_decisions(costs: Mapping[str, Mapping[str, Any]], demo: Mapping[str, Any], mainnet: Mapping[str, Any], config: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for symbol in ("BTCUSDT", "ETHUSDT"):
        group_ids = [f"{symbol}-{kind}" for kind in ("fundingRate", "bookTicker", "bookDepth")]
        archive_ok = all(costs.get(group_id, {}).get("状态") == "通过" for group_id in group_ids)
        mainnet_ok = mainnet.get("状态") == "通过"
        for horizon in ("4小时", "8小时", "24小时", "48小时"):
            rows.append({
                "标的": symbol,
                "主研究尺度": horizon,
                "成本与执行门": "通过" if archive_ok and mainnet_ok else "失败关闭",
                "归档成本证据": "通过" if archive_ok else "不完整",
                "Demo执行代理": demo.get("状态", "未执行"),
                "主网执行证据": mainnet.get("状态", "无法判定"),
            })
    return rows


def replay_decisions(costs: Mapping[str, Mapping[str, Any]], demo: Mapping[str, Any], mainnet: Mapping[str, Any], config: Mapping[str, Any]) -> list[dict[str, Any]]:
    return build_leaf_decisions(costs, demo, mainnet, config)


def publish_external_batch(root: Path, batch_id: str, files: Mapping[str, Any]) -> Path:
    root = Path(root)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", batch_id) or batch_id in {".", ".."}:
        raise ValueError("BATCH_ID_INVALID")
    root.mkdir(parents=True, exist_ok=True)
    target = root / batch_id
    pending = root / f".{batch_id}.pending"
    pending.mkdir(exist_ok=False)
    try:
        for name, value in sorted(files.items()):
            if Path(name).name != name or not name.endswith(".json"):
                raise ValueError("BATCH_FILE_INVALID")
            payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            _write_fsynced(pending / name, payload.encode("utf-8"))
        _fsync_directory(pending)
        if target.exists():
            raise FileExistsError(target)
        os.rename(pending, target)
        _fsync_directory(root)
    except Exception:
        raise
    return target


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_fsynced(path: Path, payload: bytes, *, exclusive: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _prepare_run_paths(root: Path, batch: str, intent_value: Mapping[str, Any]) -> tuple[Path, Path]:
    intents = root / ".intents"
    pending_root = root / ".pending"
    intents.mkdir(exist_ok=True)
    pending_root.mkdir(exist_ok=True)
    _fsync_directory(root)
    intent = intents / f"{batch}.json"
    _write_fsynced(intent, _json_bytes(intent_value), exclusive=True)
    _fsync_directory(intents)
    pending = pending_root / batch
    pending.mkdir(exist_ok=False)
    _fsync_directory(pending_root)
    return intent, pending


def _probe_name(group: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    return str(group["探针对象"])


def _load_evidence(path: str | None) -> Mapping[str, Any] | None:
    if path is None:
        return None
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("EVIDENCE_INVALID")
    return value


def _safe_inventory_result(
    value: Mapping[str, Any], decision: Mapping[str, Any], probe: Mapping[str, Any], response_bytes: int
) -> dict[str, Any]:
    return {
        "组编号": value["组编号"],
        "成员数": value["成员数"],
        "对象标称总字节": value["总字节"],
        "清单响应字节": response_bytes,
        "覆盖起点": value["覆盖起点"],
        "覆盖终点": value["覆盖终点"],
        "清单SHA-256": value["清单SHA-256"],
        "获取状态": decision["状态"],
        "原因代码": list(decision.get("原因代码", [])),
        "探针状态": probe["状态"],
    }


def _rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _enforce_rss_limit(config: Mapping[str, Any]) -> int:
    rss = _rss_bytes()
    if rss > config["资源上限"]["RSS字节"]:
        raise MemoryError("RSS_LIMIT_EXCEEDED")
    return rss


def _build_intent(config_path: Path, config: Mapping[str, Any], batch: str) -> dict[str, Any]:
    script_path = Path(__file__)
    prefixes = [row["前缀"] for row in config["归档组"]]
    upstream = config["上游绑定"]
    return {
        "任务编号": "任务-000106",
        "批次": batch,
        "状态": "已登记",
        "配置SHA-256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "执行器SHA-256": hashlib.sha256(script_path.read_bytes()).hexdigest(),
        "任务-000105": upstream["任务-000105"],
        "任务-000094批次": upstream["任务-000094批次"],
        "任务-000099批次": upstream["任务-000099批次"],
        "正式窗口": config["正式窗口"],
        "六组前缀SHA-256": canonical_sha256(prefixes),
        "资源预算": config["资源上限"],
    }


def _write_batch_files(pending: Path, files: Mapping[str, Any]) -> None:
    digests: dict[str, str] = {}
    for name, value in sorted(files.items()):
        payload = _json_bytes(value)
        _write_fsynced(pending / name, payload, exclusive=True)
        digests[name] = hashlib.sha256(payload).hexdigest()
    _write_fsynced(pending / "manifest.json", _json_bytes({"文件SHA-256": digests}), exclusive=True)
    _fsync_directory(pending)


def run(argv: list[str] | None = None, *, runner=subprocess.run, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--external-root", required=True)
    parser.add_argument("--probe-root", required=True)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--mainnet-evidence")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.batch) or args.batch in {".", ".."}:
        raise ValueError("BATCH_ID_INVALID")
    external = Path(args.external_root).resolve()
    if external != ALLOWED_EXTERNAL_ROOT.resolve():
        raise ValueError("EXTERNAL_ROOT_NOT_ALLOWED")
    if not external.is_dir():
        raise ValueError("EXTERNAL_ROOT_MISSING")
    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    validate_config(config)
    probe_root = Path(args.probe_root)
    intent_value = _build_intent(config_path, config, args.batch)
    _, pending = _prepare_run_paths(external, args.batch, intent_value)
    try:
        inventories: list[dict[str, Any]] = []
        costs: dict[str, dict[str, Any]] = {}
        total_objects = 0
        object_bytes = 0
        response_bytes = 0
        for group in config["归档组"]:
            rows = list_inventory(group, config, runner=runner)
            total_objects += len(rows)
            response_bytes += rows.response_bytes
            inventory = normalize_inventory(rows, group, config)
            object_bytes += inventory["总字节"]
            acquire = decide_acquire(inventory, config)
            probe_name = _probe_name(group, config)
            probe = validate_probe(probe_root / probe_name, probe_root / f"{probe_name}.CHECKSUM", group, config)
            state = "通过" if acquire["状态"] == "允许" and probe["状态"] == "通过" else "失败关闭"
            costs[group["组编号"]] = {"状态": state}
            inventories.append(_safe_inventory_result(inventory, acquire, probe, rows.response_bytes))
        demo = demo_credentials_status(environ if environ is not None else os.environ, config)
        mainnet = validate_mainnet_execution_evidence(_load_evidence(args.mainnet_evidence), config)
        leaves = build_leaf_decisions(costs, demo, mainnet, config)
        replay_one = replay_decisions(costs, demo, mainnet, config)
        replay_two = replay_decisions(costs, demo, mainnet, config)
        replay_hash = canonical_sha256(leaves)
        replay_equal = replay_hash == canonical_sha256(replay_one) == canonical_sha256(replay_two)
        all_pass = replay_equal and mainnet["状态"] == "通过" and all(row["成本与执行门"] == "通过" for row in leaves)
        rss_bytes = _enforce_rss_limit(config)
        files = {
            "inventories.json": inventories,
            "leaves.json": leaves,
            "summary.json": {"状态": "通过" if all_pass else "失败关闭", "两次重放一致": replay_equal, "决策SHA-256": replay_hash},
            "facts.json": {
                "资源事实": {"对象数": total_objects, "对象标称总字节": object_bytes, "清单响应总字节": response_bytes, "RSS峰值字节": rss_bytes, "网络上限字节": config["资源上限"]["网络总字节"], "RSS上限字节": config["资源上限"]["RSS字节"]},
                "安全事实": {"TLS校验": True, "跟随重定向": False, "主网写入": False, "凭据仅布尔检查": True},
            },
            "demo.json": demo,
            "mainnet.json": mainnet,
        }
        _write_batch_files(pending, files)
        target = external / args.batch
        if target.exists():
            raise FileExistsError(target)
        os.rename(pending, target)
        _fsync_directory(external)
        return 0 if all_pass else 2
    except Exception as exc:
        failure = pending / "failure.json"
        if not failure.exists():
            _write_fsynced(failure, _json_bytes({"状态": "异常失败关闭", "原因代码": type(exc).__name__}), exclusive=True)
            _fsync_directory(pending)
        raise


if __name__ == "__main__":
    raise SystemExit(run())
