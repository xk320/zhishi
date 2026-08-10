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
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000090"
CONTRACT_VERSION = "binance-source-identity-auto-mapping-1.0"
EVIDENCE_VERSION = "source-identity-evidence-1.0"
BINDING_VERSION = "source-identity-binding-1.0"
SOURCE_ROOT = Path("/Volumes/data/data/binance/futures/um")
MANIFEST_NAMES = ("klines_1d_manifest.json", "full_history_download_summary.json")
MEMBERS_PATH = REPO_ROOT / "artifacts/数据/来源身份声明九字段复验/source-identity-nine-fields-20260808T074100+0800-v4/来源身份声明九字段复验清单.csv"
CONFIG_PATH = REPO_ROOT / "config/数据/任务-000090Binance来源身份自动映射.json"
DEFAULT_BATCH_ROOT = REPO_ROOT / "artifacts/数据/Binance来源身份自动映射"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
TOTAL_TIMEOUT_SECONDS = 900
HTTP_TIMEOUT_SECONDS = 60
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


def load_json(path: Path, label: str) -> tuple[Any, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"{label}超过16MiB")
    return json.loads(raw.decode("utf-8")), sha256_bytes(raw)


def validate_config(config: Mapping[str, Any]) -> None:
    required = {"合同版本", "任务编号", "本地只读根目录", "固定清单文件", "成员清单", "Binance公开接口", "标的", "主研究尺度", "事后结果观察窗口", "身份字段", "字段中文映射", "资源上限", "安全边界", "匹配规则", "输出绑定"}
    if set(config) != required:
        raise ValueError("任务-000090配置字段漂移")
    if config["合同版本"] != CONTRACT_VERSION or config["任务编号"] != TASK_ID:
        raise ValueError("任务-000090配置版本漂移")
    if config["本地只读根目录"] != str(SOURCE_ROOT) or tuple(config["固定清单文件"]) != MANIFEST_NAMES:
        raise ValueError("任务-000090固定清单漂移")
    endpoints = [item.get("端点") for item in config["Binance公开接口"]]
    if endpoints != list(API_ENDPOINTS):
        raise ValueError("任务-000090公开端点漂移")
    if tuple(config["身份字段"]) != IDENTITY_FIELDS:
        raise ValueError("任务-000090身份字段漂移")
    limits = config["资源上限"]
    if limits.get("批次总超时秒") != TOTAL_TIMEOUT_SECONDS or limits.get("最大API响应字节") != MAX_RESPONSE_BYTES or limits.get("最大输出字节") != MAX_OUTPUT_BYTES or limits.get("单进程串行") is not True:
        raise ValueError("任务-000090资源上限漂移")
    if config["输出绑定"].get("严格顶层证据版本") != EVIDENCE_VERSION or config["输出绑定"].get("绑定清单版本") != BINDING_VERSION:
        raise ValueError("任务-000090输出版本漂移")


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
        entries.extend({"清单": name, **item} for item in current)
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
        entries.append({}) if False else None
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


def fetch_exchange_info(uri: str, started: float) -> dict[str, Any]:
    market = API_ENDPOINTS[uri]
    request = urllib.request.Request(uri, headers={"User-Agent": "zhishi-task-000090/1"}, method="GET")
    summary: dict[str, Any] = {"端点": uri, "市场类型": market, "方法": "GET", "授权边界": "Binance公开无认证GET"}
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status = int(response.getcode() or 0)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("API_RESPONSE_TOO_LARGE")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("symbols"), list):
            raise ValueError("API_SCHEMA_INVALID")
        summary.update({"HTTP状态": status, "响应字节数": len(raw), "响应SHA-256": sha256_bytes(raw), "Schema确切版本指纹": schema_fingerprint(payload), "合约条目数": len(payload["symbols"]), "状态": "成功"})
        return summary
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        code = str(exc)[:120] or exc.__class__.__name__
        summary.update({"状态": "失败", "失败原因代码": code, "失败原因指纹": sha256_bytes(code.encode("utf-8")), "已观察秒数": round(time.monotonic() - started, 3)})
        return summary


def member_status(member: Mapping[str, str], *, manifest_stats: Mapping[str, Any], api_summaries: list[Mapping[str, Any]]) -> dict[str, Any]:
    target = member["标的"]
    has_api = any(item.get("状态") == "成功" and item.get("市场类型") in {"USDⓈ-M合约", "币本位合约"} for item in api_summaries)
    reason = "MEMBER_BINDING_UNAVAILABLE"
    if not has_api:
        reason = "PUBLIC_API_METADATA_UNAVAILABLE"
    elif manifest_stats.get("固定根目录内路径数", 0) == 0:
        reason = "MANIFEST_PATH_OUT_OF_SCOPE"
    return {
        "成员编号": member["成员编号"], "资产编号": member["资产编号"], "标的": target,
        "输入成员SHA-256": member["输入成员SHA-256"], "状态": "无法判定", "原因代码": reason,
        "证据定位": "", "匹配符号": "", "限制": "本地清单未提供可复算的逐成员绑定和内容SHA；公开接口不能追溯证明历史文件",
        "解除条件": "提供当前成员SHA绑定、精确文件/对象定位、Schema/授权指纹和字段中文映射后追加批次",
    }


def build_batch(*, repo_root: Path = REPO_ROOT, batch_root: Path = DEFAULT_BATCH_ROOT, now: datetime | None = None, fetcher=fetch_exchange_info) -> tuple[Path, dict[str, Any]]:
    started = time.monotonic()
    config, config_sha = load_json(CONFIG_PATH, "任务-000090配置")
    validate_config(config)
    members, member_sha = load_members(MEMBERS_PATH)
    manifests, manifest_hashes, manifest_stats = load_manifests()
    del manifests  # 只保留计数和指纹，不把清单条目原文写入批次
    api_summaries = [fetcher(url, started) for url in API_ENDPOINTS]
    frozen = now or datetime.now(timezone.utc)
    if frozen.tzinfo is None:
        raise ValueError("冻结时间必须带时区")
    executor_sha = sha256_file(Path(__file__))
    task_path = repo_root / "docs/研发中心/任务/任务-000090.md"
    task_sha = sha256_file(task_path)
    rules_sha = sha256_bytes(canonical({"合同版本": CONTRACT_VERSION, "身份字段": IDENTITY_FIELDS, "接口": API_ENDPOINTS, "资源": {"总超时": TOTAL_TIMEOUT_SECONDS, "响应上限": MAX_RESPONSE_BYTES}, "匹配": config["匹配规则"]}))
    field_mapping_sha = "sha256:" + sha256_bytes(canonical(config["字段中文映射"]))
    auth_fingerprints = {uri: "sha256:" + sha256_bytes(f"Binance公开无认证GET|{uri}|method=GET".encode("utf-8")) for uri in API_ENDPOINTS}
    member_records = [member_status(member, manifest_stats=manifest_stats, api_summaries=api_summaries) for member in members]
    counts = {status: sum(row["状态"] == status for row in member_records) for status in STATUS_VALUES}
    counts.update({"候选总体": len(member_records), "计数守恒": sum(counts.values()) == len(member_records)})
    summary = {"BTC": {key: sum(row["标的"] == "BTC" and (row["状态"] == key if key in STATUS_VALUES else True) for row in member_records) for key in STATUS_VALUES}, "ETH": {key: sum(row["标的"] == "ETH" and (row["状态"] == key if key in STATUS_VALUES else True) for row in member_records) for key in STATUS_VALUES}}
    summary["BTC"]["候选总体"] = sum(row["标的"] == "BTC" for row in member_records)
    summary["ETH"]["候选总体"] = sum(row["标的"] == "ETH" for row in member_records)
    evidence = {"证据版本": EVIDENCE_VERSION, "记录": []}
    binding = {"绑定清单版本": BINDING_VERSION, "记录": []}
    input_fingerprint = sha256_bytes(canonical({"成员清单SHA-256": member_sha, "清单SHA-256": manifest_hashes, "配置SHA-256": config_sha}))
    base_id = f"binance-source-identity-auto-mapping-{frozen.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{input_fingerprint[:12]}"
    final_dir = batch_root / base_id
    if final_dir.exists():
        raise FileExistsError(f"批次已存在，禁止覆盖：{final_dir}")
    payloads = {
        "批次清单.json": {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "批次": base_id, "冻结时间": frozen.isoformat(), "输入": {"成员清单路径": str(MEMBERS_PATH.relative_to(repo_root)), "成员清单SHA-256": member_sha, "固定清单": manifest_hashes, "配置SHA-256": config_sha}, "规则SHA-256": rules_sha, "执行器SHA-256": executor_sha, "字段中文映射指纹": field_mapping_sha, "API": api_summaries, "Schema确切版本指纹": {item["端点"]: item.get("Schema确切版本指纹", "未知") for item in api_summaries}, "授权边界指纹": auth_fingerprints, "本地清单统计": manifest_stats, "结果摘要": {"总计": counts, "分标的": summary}, "资源事实": {"单进程串行": True, "最大API响应字节": MAX_RESPONSE_BYTES, "批次总超时秒": TOTAL_TIMEOUT_SECONDS, "实际耗时秒": round(time.monotonic() - started, 3)}, "安全声明": {"本地清单只读": True, "公开GET": True, "远端写入": False, "数据库业务记录读取": False, "读取原始业务正文": False, "读取凭据": False, "真实交易": False}, "结论边界": "无法判定不表达来源已证明、数据质量、因果、预测优势、胜率、收益、研究准入或交易许可"},
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
