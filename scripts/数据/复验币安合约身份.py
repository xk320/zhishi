#!/usr/bin/env python3
"""任务-000085：复验Binance合约元数据并检索Ubuntu历史候选。

本入口只保留脱敏元数据、字段指纹和状态计数；不保存完整API响应或远端文件正文。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000085"
CONFIG_PATH = ROOT / "config/数据/任务-000085币安合约身份复验.json"
TASK_PATH = ROOT / "docs/研发中心/任务/任务-000085.md"
MEMBERS_PATH = ROOT / "artifacts/数据/来源身份声明九字段复验/source-identity-nine-fields-20260808T074100+0800-v4/来源身份声明九字段复验清单.csv"
DEFAULT_BATCH_ROOT = ROOT / "artifacts/数据/Binance合约身份复验"
EVIDENCE_PATH = ROOT / "config/数据/任务-000084来源身份声明证据.json"
TARGETS = ("BTC", "ETH")
IDENTITY_FIELDS = (
    "来源提供者", "交易场所", "市场类型", "标的身份", "精确合约",
    "数据对象", "Schema确切版本", "授权边界", "字段中文映射",
)
CANDIDATE_BINDING_FIELDS = ("资产编号", "成员编号", "标的", "输入成员SHA-256")
CANDIDATE_FIELDS = CANDIDATE_BINDING_FIELDS + IDENTITY_FIELDS
FINAL_STATES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TEXT = re.compile(
    r"(?i)(password|passwd|secret|token\s*=|authorization:|gh[pousr]_[A-Za-z0-9]|-----BEGIN|"
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b)"
)
CONTRACT_NAMES = frozenset({
    "contracts.sqlite3", "contracts.db", "contracts.csv", "contracts_hand.csv",
    "contract.csv", "contract_metadata.csv", "exchangeinfo.json", "exchange_info.json",
})
FIELD_ALIASES = {
    "资产编号": ("asset_id", "asset_no", "资产编号"),
    "成员编号": ("member_id", "member_no", "成员编号"),
    "标的": ("target", "asset", "标的"),
    "标的身份": ("symbol", "asset_symbol", "baseAsset", "base_asset", "标的身份"),
    "来源提供者": ("source_provider", "provider", "来源提供者"),
    "交易场所": ("venue", "exchange", "交易场所"),
    "市场类型": ("market_type", "market", "市场类型"),
    "精确合约": ("contract", "instrument", "symbol", "精确合约"),
    "数据对象": ("data_object", "dataset", "数据对象"),
    "Schema确切版本": ("schema_version", "schema_revision", "Schema确切版本"),
    "授权边界": ("authorization_scope", "access_scope", "授权边界"),
    "字段中文映射": ("field_mapping", "column_mapping", "字段中文映射"),
}
FIXED_ENDPOINTS = {
    "https://fapi.binance.com/fapi/v1/exchangeInfo": "USDⓈ-M合约",
    "https://dapi.binance.com/dapi/v1/exchangeInfo": "币本位合约",
}
EXPECTED_FIELD_MAPPING = {
    "symbol": "精确合约",
    "baseAsset": "标的身份",
    "contractType": "合约类型",
    "status": "合约状态",
    "quoteAsset": "报价资产",
    "marginAsset": "保证金资产",
    "onboardDate": "上线时间",
    "deliveryDate": "交割时间",
}
EXPECTED_AUTHORIZATION_SCOPE = "Binance公开无认证GET"


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


TASK_MUTABLE_PREFIXES = (
    "- 状态：", "- 执行分支：", "- 开始时间：", "- 实现提交SHA：", "- Pull Request：",
    "- 完成实现时间：", "- 架构评审结论：", "- 合并完成时间：",
)


def task_contract_fingerprint(path: Path) -> str:
    """只哈希不可变任务合同正文，排除执行/交付事实元数据。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    record_start = next((i for i, line in enumerate(lines) if line.strip() == "## 执行记录"), len(lines))
    first_section = next((i for i, line in enumerate(lines[:record_start]) if line.startswith("## ")), record_start)
    stable = [
        line for i, line in enumerate(lines[:record_start])
        if not (i < first_section and any(line.startswith(prefix) for prefix in TASK_MUTABLE_PREFIXES))
    ]
    return hashlib.sha256(("\n".join(stable) + "\n").encode("utf-8")).hexdigest()


def sensitive(value: object) -> bool:
    return SAFE_TEXT.search(canonical(value)) is not None


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("配置必须是普通文件")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("配置必须是对象")
    return value


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    value = read_json(path)
    required = {
        "合同版本", "任务编号", "允许SSH目标", "专用只读UID", "远端候选根目录", "Binance公开接口",
        "标的", "主研究尺度", "事后结果观察窗口", "候选文件名", "身份字段",
        "资源上限", "安全边界", "远端扫描规则",
    }
    if set(value) != required or value["合同版本"] != "binance-contract-identity-recheck-1.0" or value["任务编号"] != TASK_ID:
        raise ValueError("任务配置字段或版本漂移")
    if value["允许SSH目标"] != ["ubuntu"] or value["标的"] != list(TARGETS):
        raise ValueError("SSH或标的白名单漂移")
    if value["专用只读UID"] != 1001:
        raise ValueError("专用只读身份UID漂移")
    if value["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or value["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度漂移")
    if set(value["安全边界"]) != {"远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据", "读取价格成交订单簿", "原始业务记录落盘", "修改原始数据", "修改生产系统", "权限或DDL变更"} or any(value["安全边界"].values()):
        raise ValueError("安全边界必须全部为false")
    limits = value["资源上限"]
    if limits.get("批次总超时秒") != 900 or limits.get("最大候选文件数") != 4096 or limits.get("最大API响应字节") != 16777216:
        raise ValueError("资源上限漂移")
    if value["远端扫描规则"] != {
        "不跟随符号链接": True,
        "排除文件系统": ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"],
        "仅读取候选元数据": True,
        "允许读取候选格式": ["csv", "json", "sqlite3", "db"],
    }:
        raise ValueError("远端扫描规则漂移")
    endpoints = value["Binance公开接口"]
    if not isinstance(endpoints, list) or [item.get("端点") for item in endpoints] != list(FIXED_ENDPOINTS):
        raise ValueError("Binance公开接口端点漂移")
    if any(item.get("市场类型") != FIXED_ENDPOINTS.get(item.get("端点")) for item in endpoints):
        raise ValueError("Binance公开接口市场类型漂移")
    return value


def load_members(path: Path = MEMBERS_PATH) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    required = {"成员编号", "资产编号", "标的", "输入成员SHA-256"}
    if len(rows) != 630 or not rows or not required.issubset(rows[0]):
        raise ValueError("任务-000083成员分母或字段漂移")
    ordered = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != ordered or {row["标的"] for row in rows} != set(TARGETS):
        raise ValueError("成员顺序或标的漂移")
    if len({(row["标的"], row["资产编号"]) for row in rows}) != 630:
        raise ValueError("标的与资产编号组合不唯一")
    return rows


def fetch_exchange_info(api_spec: Mapping[str, str], limits: Mapping[str, int], now: dt.datetime) -> dict[str, Any]:
    target_uri = str(api_spec["端点"])
    parsed = urlparse(target_uri)
    if parsed.scheme != "https" or parsed.netloc not in {"fapi.binance.com", "dapi.binance.com"} or parsed.path not in {"/fapi/v1/exchangeInfo", "/dapi/v1/exchangeInfo"} or parsed.query or parsed.fragment or target_uri not in FIXED_ENDPOINTS:
        return {"市场类型": api_spec.get("市场类型"), "端点": target_uri, "状态": "失败", "原因代码": "ENDPOINT_NOT_ALLOWLISTED", "观察时间": now.isoformat(), "HTTP状态": None, "响应SHA-256": None, "响应Schema指纹": None, "合约": []}
    command = ["curl", "--http1.1", "--silent", "--show-error", "--fail", "--connect-timeout", "10", "--max-time", "30", "--user-agent", "zhishi-contract-identity/1.0", target_uri]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=35, check=False, env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"})
        raw = completed.stdout
        status = 200 if completed.returncode == 0 else None
    except (OSError, subprocess.SubprocessError) as error:
        return {"市场类型": api_spec["市场类型"], "端点": target_uri, "状态": "失败", "原因代码": type(error).__name__, "观察时间": now.isoformat(), "HTTP状态": None, "响应SHA-256": None, "响应Schema指纹": None, "合约": []}
    if len(raw) > int(limits["最大API响应字节"]):
        return {"市场类型": api_spec["市场类型"], "端点": target_uri, "状态": "失败", "原因代码": "API_RESPONSE_TOO_LARGE", "观察时间": now.isoformat(), "HTTP状态": status, "响应SHA-256": hashlib.sha256(raw).hexdigest(), "响应Schema指纹": None, "合约": []}
    response_sha = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {"市场类型": api_spec["市场类型"], "端点": target_uri, "状态": "失败", "原因代码": "API_JSON_INVALID", "观察时间": now.isoformat(), "HTTP状态": status, "响应SHA-256": response_sha, "响应Schema指纹": None, "合约": []}
    symbols = payload.get("symbols") if isinstance(payload, dict) else None
    if not isinstance(symbols, list):
        return {"市场类型": api_spec["市场类型"], "端点": target_uri, "状态": "失败", "原因代码": "API_SYMBOLS_MISSING", "观察时间": now.isoformat(), "HTTP状态": status, "响应SHA-256": response_sha, "响应Schema指纹": fingerprint(payload) if isinstance(payload, dict) else None, "合约": []}
    selected: list[dict[str, Any]] = []
    for item in symbols:
        if not isinstance(item, dict) or item.get("baseAsset") not in TARGETS:
            continue
        allowed = {key: item.get(key) for key in ("symbol", "pair", "contractType", "status", "baseAsset", "quoteAsset", "marginAsset", "deliveryDate", "onboardDate") if key in item}
        if not isinstance(allowed.get("symbol"), str) or sensitive(allowed):
            continue
        allowed["字段集合"] = sorted(item)
        allowed["字段集合指纹"] = fingerprint(sorted(item))
        observed_ms = int(now.timestamp() * 1000)
        allowed["未来日期字段"] = [
            key for key in ("onboardDate", "deliveryDate")
            if isinstance(item.get(key), (int, float)) and item[key] > observed_ms
        ]
        selected.append(allowed)
    selected.sort(key=lambda item: (str(item.get("baseAsset")), str(item.get("symbol"))))
    schema_fingerprint = fingerprint({"顶层字段": sorted(payload), "symbol字段集合": sorted({key for item in symbols if isinstance(item, dict) for key in item})})
    return {"市场类型": api_spec["市场类型"], "端点": target_uri, "状态": "通过", "原因代码": "", "观察时间": now.isoformat(), "HTTP状态": status, "响应SHA-256": response_sha, "响应Schema指纹": schema_fingerprint, "合约": selected}


def _remote_probe_source(config: Mapping[str, Any], deadline_seconds: int) -> str:
    roots = json.dumps(config["远端候选根目录"], ensure_ascii=False)
    names = json.dumps(sorted(config["候选文件名"]), ensure_ascii=False)
    excluded = json.dumps(config["远端扫描规则"]["排除文件系统"], ensure_ascii=False)
    max_files = int(config["资源上限"]["最大候选文件数"])
    max_size = int(config["资源上限"]["最大候选文件字节"])
    expected_uid = int(config["专用只读UID"])
    identity_fields = json.dumps(list(IDENTITY_FIELDS), ensure_ascii=False)
    return f'''import csv, hashlib, io, json, os, pathlib, re, sqlite3, stat, time
ROOTS={roots}
NAMES=set({names})
EXCLUDED=tuple({excluded})
IDENTITY_FIELDS=tuple({identity_fields})
CANDIDATE_FIELDS=("资产编号","成员编号","标的","输入成员SHA-256")+IDENTITY_FIELDS
EXPECTED_UID={expected_uid}
MAX_FILES={max_files}
MAX_SIZE={max_size}
DEADLINE=time.monotonic()+{int(deadline_seconds)}
SAFE=re.compile(r"(?i)(password|passwd|secret|token\\s*=|authorization:|gh[pousr]_[A-Za-z0-9]|-----BEGIN)")
def fp(value): return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def skip(path):
    text=str(path)
    return any(text==item or text.startswith(item+"/") for item in EXCLUDED)
def label(path):
    return {{"路径指纹":fp(str(path)),"文件名":path.name,"上级目录名":path.parent.name}}
def fields_from_header(header):
    aliases={{"资产编号":{{"asset_id","asset_no","资产编号"}},"成员编号":{{"member_id","member_no","成员编号"}},"标的":{{"target","asset","标的"}},"输入成员SHA-256":{{"input_member_sha256","input_member_hash","输入成员SHA-256"}},"标的身份":{{"symbol","asset_symbol","baseAsset","base_asset","标的身份"}},"来源提供者":{{"source_provider","provider","来源提供者"}},"交易场所":{{"venue","exchange","交易场所"}},"市场类型":{{"market_type","market","市场类型"}},"精确合约":{{"contract","instrument","symbol","精确合约"}},"数据对象":{{"data_object","dataset","数据对象"}},"Schema确切版本":{{"schema_version","schema_revision","Schema确切版本"}},"授权边界":{{"authorization_scope","access_scope","授权边界"}},"字段中文映射":{{"field_mapping","column_mapping","字段中文映射"}}}}
    mapping={{}}
    for logical, options in aliases.items():
        matches=[item for item in header if item in options]
        if len(matches)==1: mapping[logical]=matches[0]
    return mapping
def failure(reason):
    print(json.dumps({{"协议":"zhishi-binance-contract-probe/1","扫描UID":os.geteuid(),"扫描GID":os.getegid(),"扫描是否专用只读":False,"扫描完整":False,"失败安全":True,"失败原因代码":reason,"扫描文件数":0,"候选文件数":0,"候选":[],"存储根目录":[],"远端追加":False,"远端临时文件":False,"数据库写入":False,"订单簿读取":False}},ensure_ascii=False,sort_keys=True))
    raise SystemExit(0)
if os.geteuid()!=EXPECTED_UID:
    failure("REMOTE_IDENTITY_NOT_DEDICATED")
def read_csv_candidate(path):
    result={{"格式":"csv","字段映射":{{}},"行":[]}}
    try:
        raw=path.read_bytes()[:MAX_SIZE+1]
        if len(raw)>MAX_SIZE: return result|{{"原因代码":"FILE_TOO_LARGE"}}
        text=raw.decode("utf-8-sig")
        reader=csv.DictReader(io.StringIO(text))
        header=[str(item) for item in (reader.fieldnames or [])]
        result["字段映射"]=fields_from_header(header)
        if not set(CANDIDATE_FIELDS).issubset(result["字段映射"]):
            return result|{{"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}}
        for index,row in enumerate(reader):
            if index>=630:
                result["行"]=[]; return result|{{"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}}
            selected={{key:row.get(result["字段映射"][key]) for key in CANDIDATE_FIELDS}}
            if not SAFE.search(json.dumps(selected,ensure_ascii=False,sort_keys=True)):
                result["行"].append(selected)
        result["Schema指纹"]=fp(header)
    except Exception:
        result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
def read_json_candidate(path):
    result={{"格式":"json","字段映射":{{}},"行":[]}}
    try:
        raw=path.read_bytes()[:MAX_SIZE+1]
        if len(raw)>MAX_SIZE: return result|{{"原因代码":"FILE_TOO_LARGE"}}
        payload=json.loads(raw.decode("utf-8"))
        items=payload.get("symbols",payload if isinstance(payload,list) else []) if isinstance(payload,(dict,list)) else []
        if isinstance(items,dict): items=[items]
        if len(items)>630: return result|{{"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}}
        for item in items:
            if not isinstance(item,dict): continue
            mapping=fields_from_header([str(key) for key in item])
            if not set(CANDIDATE_FIELDS).issubset(mapping):
                continue
            selected={{key:item.get(mapping[key]) for key in CANDIDATE_FIELDS}}
            if not SAFE.search(json.dumps(selected,ensure_ascii=False,sort_keys=True)):
                result["行"].append(selected)
        result["Schema指纹"]=fp(sorted(payload) if isinstance(payload,dict) else "list")
    except Exception:
        result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
def read_sqlite_candidate(path):
    result={{"格式":"sqlite","表":[],"行":[]}}
    try:
        connection=sqlite3.connect("file:"+str(path)+"?mode=ro",uri=True)
        try:
            tables=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for table,sql in tables:
                if not isinstance(table,str) or table.startswith("sqlite_"): continue
                columns=[row[1] for row in connection.execute("PRAGMA table_info(\\\""+table.replace("\\\"","\\\"\\\"")+"\\\")")]
                mapping=fields_from_header(columns)
                result["表"].append({{"表名指纹":fp(table),"字段指纹":fp(columns),"字段映射":mapping}})
                if not set(CANDIDATE_FIELDS).issubset(mapping): continue
                query="SELECT "+",".join("\\\""+mapping[key].replace("\\\"","\\\"\\\"")+"\\\"" for key in CANDIDATE_FIELDS)+" FROM \\\""+table.replace("\\\"","\\\"\\\"")+"\\\" LIMIT 631"
                for row in connection.execute(query):
                    if len(result["行"]) >= 630:
                        result["行"]=[]; return result|{{"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}}
                    result["行"].append({{key:row[index] for index,key in enumerate(CANDIDATE_FIELDS)}})
        finally: connection.close()
    except Exception:
        result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
candidates=[]; visited=0; roots_seen=[]; storage=[]; scan_failed=False
for root in ROOTS:
    base=pathlib.Path(root)
    try:
        st=base.stat(); readable=base.is_dir() and os.access(base,os.R_OK)
        roots_seen.append({{"根目录":base.name,"路径指纹":fp(str(base)),"模式":oct(st.st_mode&0o777),"属主UID":st.st_uid,"属组GID":st.st_gid,"可读":readable,"可写":os.access(base,os.W_OK)}})
        if not readable:
            scan_failed=True; continue
    except OSError:
        scan_failed=True; continue
    walk_failed=[False]
    def walk_error(error): walk_failed[0]=True
    for current, dirs, files in os.walk(base,topdown=True,followlinks=False,onerror=walk_error):
        if walk_failed[0]: scan_failed=True
        if time.monotonic()>DEADLINE or visited>=MAX_FILES: break
        dirs[:]=[name for name in dirs if not skip(pathlib.Path(current)/name) and not (pathlib.Path(current)/name).is_symlink()]
        for name in files:
            if time.monotonic()>DEADLINE or visited>=MAX_FILES: break
            visited+=1; path=pathlib.Path(current)/name
            if path.is_symlink() or name.lower() not in NAMES: continue
            try:
                st=path.stat()
                row=label(path)|{{"大小":st.st_size,"修改时间_ns":st.st_mtime_ns,"模式":oct(st.st_mode&0o777),"属主UID":st.st_uid,"属组GID":st.st_gid,"可读":os.access(path,os.R_OK),"父目录可写":os.access(path.parent,os.W_OK)}}
                if st.st_size<=MAX_SIZE and os.access(path,os.R_OK):
                    suffix=path.suffix.lower()
                    if suffix==".csv": row["内容摘要"]=read_csv_candidate(path)
                    elif suffix==".json": row["内容摘要"]=read_json_candidate(path)
                    elif suffix in (".sqlite3",".db"): row["内容摘要"]=read_sqlite_candidate(path)
                if not SAFE.search(json.dumps(row,ensure_ascii=False,sort_keys=True)): candidates.append(row)
            except (OSError,PermissionError): continue
        if time.monotonic()>DEADLINE or visited>=MAX_FILES: break
    if walk_failed[0]: scan_failed=True
    if time.monotonic()>DEADLINE or visited>=MAX_FILES: break
scan_complete=(not scan_failed) and visited<MAX_FILES and time.monotonic()<=DEADLINE
failure_code="" if scan_complete else ("ROOT_OR_WALK_ACCESS_FAILED" if scan_failed else ("MAX_CANDIDATE_FILES_REACHED" if visited>=MAX_FILES else "SCAN_TIMEOUT"))
print(json.dumps({{"协议":"zhishi-binance-contract-probe/1","扫描UID":os.geteuid(),"扫描GID":os.getegid(),"扫描是否专用只读":True,"扫描完整":scan_complete,"失败安全":not scan_complete,"失败原因代码":failure_code,"扫描文件数":visited,"候选文件数":len(candidates),"候选":candidates,"存储根目录":roots_seen,"远端追加":False,"远端临时文件":False,"数据库写入":False,"订单簿读取":False}},ensure_ascii=False,sort_keys=True))
'''


def run_remote_probe(config: Mapping[str, Any]) -> dict[str, Any]:
    connect_timeout = int(config["资源上限"]["SSH连接超时秒"])
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "ubuntu", "python3", "-",
    ]
    script = _remote_probe_source(config, int(config["资源上限"]["批次总超时秒"]))
    completed = engine.run_bounded_process(
        command,
        input_text=script,
        timeout=int(config["资源上限"]["批次总超时秒"]),
        maximum_stdout=int(config["资源上限"]["最大输出字节"]),
        maximum_stderr=int(config["资源上限"]["最大日志字节"]),
    )
    if completed.returncode != 0:
        raise RuntimeError("Ubuntu候选探针失败")
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Ubuntu候选探针响应非法") from error
    required = {"协议", "扫描UID", "扫描GID", "扫描是否专用只读", "扫描完整", "失败安全", "失败原因代码", "扫描文件数", "候选文件数", "候选", "存储根目录", "远端追加", "远端临时文件", "数据库写入", "订单簿读取"}
    if set(payload) != required or payload["协议"] != "zhishi-binance-contract-probe/1":
        raise ValueError("Ubuntu候选探针协议漂移")
    if any(payload[key] is not False for key in ("远端追加", "远端临时文件", "数据库写入", "订单簿读取")):
        raise ValueError("Ubuntu探针越过安全边界")
    if not isinstance(payload["候选"], list) or not isinstance(payload["存储根目录"], list):
        raise ValueError("Ubuntu探针结果类型非法")
    if payload["扫描是否专用只读"] is not True:
        if payload["候选"] or payload["扫描文件数"] != 0:
            raise ValueError("非专用只读身份不得产生候选结果")
    elif payload["扫描UID"] != int(config["专用只读UID"]):
        raise ValueError("专用只读身份UID不匹配")
    if payload["扫描完整"] is not True and payload["失败安全"] is not True:
        raise ValueError("扫描不完整时必须失败安全")
    if sensitive(payload):
        raise ValueError("Ubuntu探针结果包含敏感信息")
    return payload


def flatten_candidates(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for candidate in payload.get("候选", []):
        if not isinstance(candidate, dict):
            continue
        summary = candidate.get("内容摘要", {})
        rows = summary.get("行", []) if isinstance(summary, dict) else []
        for row in rows:
            if isinstance(row, dict) and not sensitive(row):
                result.append({"文件": {key: candidate.get(key) for key in ("路径指纹", "文件名", "上级目录名", "大小", "修改时间_ns", "模式", "属主UID", "属组GID")}, "字段": row, "格式": summary.get("格式") if isinstance(summary, dict) else None, "Schema指纹": summary.get("Schema指纹") if isinstance(summary, dict) else None})
    return result


def api_contracts(api_snapshots: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {target: [] for target in TARGETS}
    for snapshot in api_snapshots:
        if snapshot.get("状态") != "通过":
            continue
        for item in snapshot.get("合约", []):
            if item.get("baseAsset") in result:
                item = dict(item)
                item["市场类型"] = snapshot["市场类型"]
                item["端点"] = snapshot["端点"]
                item["响应SHA-256"] = snapshot["响应SHA-256"]
                item["响应Schema指纹"] = snapshot["响应Schema指纹"]
                item["观察时间"] = snapshot["观察时间"]
                result[item["baseAsset"]].append(item)
    return result


def build_evidence(members: Sequence[Mapping[str, str]], candidates: Sequence[Mapping[str, Any]], contracts: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    by_asset = {(str(row["标的"]), str(row["资产编号"])): row for row in members}
    records: list[dict[str, Any]] = []
    verified_members: set[tuple[str, str]] = set()
    for candidate in candidates:
        fields = candidate.get("字段", {})
        asset_id = str(fields.get("资产编号", ""))
        symbol = str(fields.get("标的", fields.get("标的身份", "")))
        member = by_asset.get((symbol, asset_id))
        exact = str(fields.get("精确合约", fields.get("symbol", "")))
        if member is None or member.get("标的") != symbol or not exact or symbol not in TARGETS:
            continue
        matched = next((item for item in contracts.get(symbol, []) if item.get("symbol") == exact), None)
        if matched is None:
            continue
        if str(fields.get("成员编号", "")) != str(member.get("成员编号", "")):
            continue
        if str(fields.get("输入成员SHA-256", "")) != str(member.get("输入成员SHA-256", "")):
            continue
        required = set(IDENTITY_FIELDS)
        if not required.issubset(fields) or any(fields.get(key) in (None, "", "未知") for key in required):
            continue
        expected = {
            "来源提供者": "Binance",
            "交易场所": "Binance",
            "市场类型": matched.get("市场类型"),
            "标的身份": matched.get("baseAsset"),
            "精确合约": matched.get("symbol"),
            "数据对象": f"exchangeInfo.symbols[{matched.get('symbol')}]",
            "Schema确切版本": f"sha256:{matched.get('响应Schema指纹')}",
            "授权边界": EXPECTED_AUTHORIZATION_SCOPE,
            "字段中文映射": EXPECTED_FIELD_MAPPING,
        }
        if matched.get("未来日期字段") or any(fields.get(key) != value for key, value in expected.items()):
            continue
        verified_members.add((symbol, asset_id))
        values = dict(fields)
        for field in IDENTITY_FIELDS:
            records.append({"证据记录编号": "E-000085-" + fingerprint({"资产编号": asset_id, "字段": field})[:16], "资产编号": asset_id, "标的": symbol, "输入成员SHA-256": member["输入成员SHA-256"], "证明字段": field, "声明值": values[field]})
    records.sort(key=lambda row: (row["标的"], row["资产编号"], row["证明字段"], row["证据记录编号"]))
    evidence = {"证据版本": "source-identity-evidence-1.0", "记录": records}
    return evidence, [{"资产编号": asset_id, "标的": symbol, "成员SHA-256": by_asset[(symbol, asset_id)]["输入成员SHA-256"], "证据记录数": sum(item["资产编号"] == asset_id and item["标的"] == symbol for item in records)} for symbol, asset_id in sorted(verified_members)]


def summarize(members: Sequence[Mapping[str, str]], verified: Sequence[Mapping[str, Any]], remote: Mapping[str, Any], api_snapshots: Sequence[Mapping[str, Any]], candidates: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    verified_ids = {(row["标的"], row["资产编号"]) for row in verified}
    member_ids = {(str(row["标的"]), str(row["资产编号"])) for row in members}
    observed_ids = {(str(item.get("字段", {}).get("标的", item.get("字段", {}).get("标的身份", ""))), str(item.get("字段", {}).get("资产编号", ""))) for item in candidates if isinstance(item.get("字段"), Mapping)} & member_ids
    summary: dict[str, Any] = {"候选总体": len(members), "已观察": len(observed_ids), "已证明": len(verified_ids), "拒绝": 0, "无法判定": len(members) - len(verified_ids), "失败": 0, "未成熟": 0, "失效": 0}
    per_target: dict[str, Any] = {}
    for target in TARGETS:
        rows = [row for row in members if row["标的"] == target]
        count = sum((row["标的"], row["资产编号"]) in verified_ids for row in rows)
        per_target[target] = {"候选总体": len(rows), "已观察": sum(1 for item in observed_ids if item[0] == target), "已证明": count, "拒绝": 0, "无法判定": len(rows) - count, "失败": 0, "未成熟": 0, "失效": 0}
    summary["分标的"] = per_target
    summary["计数守恒"] = sum(summary[state] for state in FINAL_STATES) == len(members) and all(sum(item[state] for state in FINAL_STATES) == 315 for item in per_target.values())
    summary["远端扫描UID"] = remote.get("扫描UID")
    summary["远端专用只读"] = remote.get("扫描是否专用只读")
    summary["扫描完整"] = remote.get("扫描完整")
    summary["失败安全"] = remote.get("失败安全")
    summary["失败原因代码"] = remote.get("失败原因代码")
    summary["公开接口成功数"] = sum(item.get("状态") == "通过" for item in api_snapshots)
    summary["ZS-DATA-GAP-001"] = "继续阻塞；仅有精确九字段证据的成员可进入声明输入" if len(verified_ids) < 630 else "按精确成员范围复算"
    return summary


def render_batch(config: Mapping[str, Any], members: Sequence[Mapping[str, str]], api_snapshots: Sequence[Mapping[str, Any]], remote: Mapping[str, Any], batch_start: dt.datetime, batch_root: Path) -> Path:
    contracts = api_contracts(api_snapshots)
    candidates = flatten_candidates(remote)
    evidence, verified = build_evidence(members, candidates, contracts)
    summary = summarize(members, verified, remote, api_snapshots, candidates=candidates)
    batch_id = "binance-contract-identity-" + batch_start.strftime("%Y%m%dT%H%M%S%z") + "-" + fingerprint({"任务": TASK_ID, "API": api_snapshots, "远端": remote, "成员": sha_path(MEMBERS_PATH)})[:12]
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("批次目录已存在")
    manifest = {
        "合同版本": "binance-contract-identity-recheck-1.0",
        "任务编号": TASK_ID,
        "批次": batch_id,
        "冻结时间": batch_start.isoformat(timespec="microseconds"),
        "成员顺序SHA-256": sha_path(MEMBERS_PATH),
        "任务合同SHA-256": task_contract_fingerprint(TASK_PATH),
        "任务文件SHA-256": sha_path(TASK_PATH),
        "任务合同指纹口径": "固定合同正文；排除执行/交付事实元数据",
        "配置SHA-256": sha_path(CONFIG_PATH),
        "公开接口摘要": api_snapshots,
        "Ubuntu扫描摘要": {key: remote.get(key) for key in ("扫描UID", "扫描GID", "扫描是否专用只读", "扫描完整", "失败安全", "失败原因代码", "扫描文件数", "候选文件数", "存储根目录", "远端追加", "数据库写入", "订单簿读取")},
        "候选文件摘要": remote.get("候选", []),
        "结果摘要": summary,
        "证据记录数": len(evidence["记录"]),
        "安全边界": config["安全边界"],
        "资源上限": config["资源上限"],
        "结论边界": "公开接口和历史候选的描述性差异不能推导因果、预测优势、胜率、收益、研究准入或交易许可",
        "输出文件SHA-256": {},
    }
    output = {
        "批次清单.json": json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "Binance接口摘要.json": json.dumps(api_snapshots, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "Ubuntu候选摘要.json": json.dumps(remote, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "成员状态摘要.json": json.dumps({"结果摘要": summary, "已证明成员": verified}, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    }
    manifest["输出文件SHA-256"] = {
        name: hashlib.sha256(text.encode("utf-8")).hexdigest()
        for name, text in output.items()
        if name != "批次清单.json"
    }
    manifest["输出文件SHA-256"]["批次清单.json"] = "不递归；以发布后的Git对象SHA-256复算"
    output["批次清单.json"] = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if evidence["记录"]:
        output["任务-000084来源身份声明证据.json"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    batch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{batch_id}-", dir=batch_root) as temp:
        staging = Path(temp)
        for name, text in output.items():
            (staging / name).write_text(text, encoding="utf-8")
        for path in staging.iterdir():
            if sensitive(path.read_text(encoding="utf-8")):
                raise ValueError("输出包含敏感信息")
        engine.atomic_publish_directory_no_replace(staging, target)
    return target


def execute(config_path: Path = CONFIG_PATH, batch_root: Path = DEFAULT_BATCH_ROOT, now: dt.datetime | None = None) -> Path:
    config = load_config(config_path)
    members = load_members()
    config_path = config_path.resolve()
    batch_root = batch_root.resolve()
    start = now or dt.datetime.now().astimezone()
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    api_snapshots = [fetch_exchange_info(api_spec, config["资源上限"], start) for api_spec in config["Binance公开接口"]]
    remote = run_remote_probe(config)
    return render_batch(config, members, api_snapshots, remote, start, batch_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="任务-000085 Binance合约元数据身份复验")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    args = parser.parse_args(argv)
    try:
        target = execute(args.config, args.batch_root)
    except Exception as error:
        print(f"任务-000085执行失败：{type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({"状态": "成功", "批次": target.name, "路径": str(target.relative_to(ROOT))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
