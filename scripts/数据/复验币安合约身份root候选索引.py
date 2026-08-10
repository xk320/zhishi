#!/usr/bin/env python3
"""任务-000089：在固定 root 只读范围内建立候选身份索引。

索引只优化候选定位，不扩大任务-000084的根目录、文件名、字段或安全边界。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 复验币安合约身份 as legacy
from scripts.数据 import 复验币安合约身份root兼容 as root_compat

_ROOT_BUILD_EVIDENCE = root_compat.build_evidence

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000089"
CONFIG_PATH = ROOT / "config/数据/任务-000089Root候选身份索引复验.json"
TASK_PATH = ROOT / "docs/研发中心/任务/任务-000089.md"
DEFAULT_BATCH_ROOT = ROOT / "artifacts/数据/Binance合约身份复验"
ROOT_MODE = "root兼容只读"
ROOT_UID = 0
EXPECTED_ROOTS = [
    "/opt/binance-event", "/opt/celueqing", "/opt/crypto-radar",
    "/opt/event-prob-lab", "/opt/orderbook-intelligence-service", "/var/lib/mysql",
]
REQUIRED_CONFIG_KEYS = {
    "合同版本", "任务编号", "访问模式", "允许SSH目标", "实际UID", "专用只读UID",
    "远端候选根目录", "Binance公开接口", "标的", "主研究尺度", "事后结果观察窗口",
    "候选文件名", "身份字段", "资源上限", "安全边界", "远端扫描规则",
}
RESOURCE_KEYS = {
    "批次总超时秒", "SSH连接超时秒", "最大索引目录数", "最大索引条目数",
    "最大索引队列数", "最大索引路径字节", "最大候选摘要聚合字节", "最大候选文件数",
    "最大候选文件字节", "最大API响应字节", "最大输出字节", "最大日志字节",
}


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    value = legacy.read_json(path)
    if set(value) != REQUIRED_CONFIG_KEYS:
        raise ValueError("root候选索引配置字段漂移")
    if value["合同版本"] != "binance-contract-identity-index-recheck-1.0" or value["任务编号"] != TASK_ID:
        raise ValueError("合同版本或任务编号漂移")
    if value["访问模式"] != ROOT_MODE or value["实际UID"] != ROOT_UID or value["专用只读UID"] != 1001:
        raise ValueError("root身份事实漂移")
    if value["允许SSH目标"] != ["ubuntu"] or value["远端候选根目录"] != EXPECTED_ROOTS:
        raise ValueError("目标或根目录白名单漂移")
    if value["标的"] != ["BTC", "ETH"]:
        raise ValueError("标的范围漂移")
    if value["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or value["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度漂移")
    if sorted(value["候选文件名"]) != sorted(legacy.CONTRACT_NAMES) or len(value["候选文件名"]) != len(legacy.CONTRACT_NAMES):
        raise ValueError("候选文件名白名单漂移")
    if value["身份字段"] != list(legacy.IDENTITY_FIELDS):
        raise ValueError("身份字段漂移")
    if set(value["安全边界"]) != {
        "远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据",
        "读取价格成交订单簿", "原始业务记录落盘", "修改原始数据", "修改生产系统", "权限或DDL变更",
    } or any(value["安全边界"].values()):
        raise ValueError("安全边界必须全部为false")
    limits = value["资源上限"]
    if set(limits) != RESOURCE_KEYS:
        raise ValueError("资源上限字段漂移")
    expected_limits = {
        "批次总超时秒": 900, "SSH连接超时秒": 15,
        "最大索引目录数": 16384, "最大索引条目数": 262144, "最大索引队列数": 16384,
        "最大索引路径字节": 4096, "最大候选摘要聚合字节": 33554432,
        "最大候选文件数": 4096, "最大候选文件字节": 16777216,
        "最大API响应字节": 16777216, "最大输出字节": 33554432, "最大日志字节": 65536,
    }
    if limits != expected_limits:
        raise ValueError("资源上限数值漂移")
    if value["远端扫描规则"] != {
        "不跟随符号链接": True,
        "排除文件系统": ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"],
        "仅读取候选元数据": True,
        "允许读取候选格式": ["csv", "json", "sqlite3", "db"],
    }:
        raise ValueError("远端扫描规则漂移")
    endpoints = value["Binance公开接口"]
    if [item.get("端点") for item in endpoints] != list(legacy.FIXED_ENDPOINTS):
        raise ValueError("公开接口漂移")
    if any(item.get("市场类型") != legacy.FIXED_ENDPOINTS.get(item.get("端点")) for item in endpoints):
        raise ValueError("公开接口市场类型漂移")
    return value


def _failure(reason: str, *, exit_code: int | None = None, resource: Mapping[str, Any] | None = None) -> dict[str, Any]:
    safe_reason = reason if re.fullmatch(r"[A-Z0-9_]{1,64}", reason) else "PROBE_FAILED"
    return {
        "协议": "zhishi-binance-contract-probe/1", "访问模式": ROOT_MODE,
        "扫描UID": None, "扫描GID": None, "扫描是否专用只读": False,
        "扫描完整": False, "失败安全": True, "失败原因代码": safe_reason,
        "失败原因指纹": legacy.fingerprint(safe_reason), "扫描文件数": 0,
        "候选文件数": 0, "候选": [], "存储根目录": [], "索引目录数": 0,
        "索引条目数": 0, "待处理目录数": 0, "索引候选摘要字节": 0,
        "远端追加": False, "远端临时文件": False, "数据库写入": False,
        "订单簿读取": False, "退出码": exit_code, "资源事实": dict(resource or {}),
    }


def _probe_source(config: Mapping[str, Any], deadline_seconds: int) -> str:
    """生成固定、无参数拼接的远端探针。"""

    roots = json.dumps(config["远端候选根目录"], ensure_ascii=False)
    names = json.dumps(sorted(config["候选文件名"]), ensure_ascii=False)
    excluded = json.dumps(config["远端扫描规则"]["排除文件系统"], ensure_ascii=False)
    limits = config["资源上限"]
    fields = json.dumps(list(legacy.CANDIDATE_FIELDS), ensure_ascii=False)
    identity = json.dumps(list(legacy.IDENTITY_FIELDS), ensure_ascii=False)
    source = r'''import csv,hashlib,io,json,os,pathlib,re,sqlite3,time
ROOTS=__ROOTS__
NAMES={name.lower() for name in __NAMES__}
EXCLUDED=tuple(__EXCLUDED__)
CANDIDATE_FIELDS=tuple(__FIELDS__)
IDENTITY_FIELDS=tuple(__IDENTITY__)
MAX_DIRS=__MAX_DIRS__
MAX_ENTRIES=__MAX_ENTRIES__
MAX_QUEUE=__MAX_QUEUE__
MAX_PATH_BYTES=__MAX_PATH_BYTES__
MAX_SUMMARY_BYTES=__MAX_SUMMARY_BYTES__
MAX_CANDIDATES=__MAX_CANDIDATES__
MAX_SIZE=__MAX_SIZE__
DEADLINE=time.monotonic()+__DEADLINE__
SAFE=re.compile(r"(?i)(password|passwd|secret|token\s*=|authorization:|gh[pousr]_[A-Za-z0-9]|-----BEGIN|\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b)")
def fp(value): return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def skip(path):
    text=str(path)
    return any(text==item or text.startswith(item+"/") for item in EXCLUDED)
def fields_from_header(header):
    aliases={"资产编号":{"asset_id","asset_no","资产编号"},"成员编号":{"member_id","member_no","成员编号"},"标的":{"target","asset","标的"},"输入成员SHA-256":{"input_member_sha256","input_member_hash","输入成员SHA-256"},"标的身份":{"symbol","asset_symbol","baseAsset","base_asset","标的身份"},"来源提供者":{"source_provider","provider","来源提供者"},"交易场所":{"venue","exchange","交易场所"},"市场类型":{"market_type","market","市场类型"},"精确合约":{"contract","instrument","symbol","精确合约"},"数据对象":{"data_object","dataset","数据对象"},"Schema确切版本":{"schema_version","schema_revision","Schema确切版本"},"授权边界":{"authorization_scope","access_scope","授权边界"},"字段中文映射":{"field_mapping","column_mapping","字段中文映射"}}
    mapping={}
    for logical,options in aliases.items():
        matches=[item for item in header if item in options]
        if len(matches)==1: mapping[logical]=matches[0]
    return mapping
def read_csv_candidate(path):
    result={"格式":"csv","字段映射":{},"行":[]}
    try:
        raw=path.read_bytes()[:MAX_SIZE+1]
        if len(raw)>MAX_SIZE: return result|{"原因代码":"FILE_TOO_LARGE"}
        reader=csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        result["字段映射"]=fields_from_header([str(item) for item in (reader.fieldnames or [])])
        if not set(CANDIDATE_FIELDS).issubset(result["字段映射"]): return result|{"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
        for index,row in enumerate(reader):
            if index>=630: return result|{"行":[],"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}
            selected={key:row.get(result["字段映射"][key]) for key in CANDIDATE_FIELDS}
            if any(not isinstance(value,str) or not value.strip() for value in selected.values()): return result|{"行":[],"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
            if SAFE.search(json.dumps(selected,ensure_ascii=False,sort_keys=True)): return result|{"行":[],"原因代码":"SENSITIVE_CANDIDATE_FIELD"}
            result["行"].append(selected)
        if not result["行"]: return result|{"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
        result["Schema指纹"]=fp([str(item) for item in (reader.fieldnames or [])])
    except Exception: result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
def read_json_candidate(path):
    result={"格式":"json","字段映射":{},"行":[]}
    try:
        raw=path.read_bytes()[:MAX_SIZE+1]
        if len(raw)>MAX_SIZE: return result|{"原因代码":"FILE_TOO_LARGE"}
        payload=json.loads(raw.decode("utf-8"))
        items=payload.get("symbols",[]) if isinstance(payload,dict) else payload if isinstance(payload,list) else []
        if isinstance(items,dict): items=[items]
        if len(items)>630: return result|{"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}
        missing_schema=False; schema_shapes=[]; first_mapping=None
        for item in items:
            if not isinstance(item,dict): missing_schema=True; continue
            mapping=fields_from_header([str(key) for key in item])
            shape=sorted(str(key) for key in item)
            schema_shapes.append(shape)
            if not set(CANDIDATE_FIELDS).issubset(mapping): missing_schema=True; continue
            if set(str(key) for key in item) != set(mapping.values()): missing_schema=True; continue
            if first_mapping is None: first_mapping=mapping
            if mapping != first_mapping: missing_schema=True; continue
            selected={key:item.get(mapping[key]) for key in CANDIDATE_FIELDS}
            if any(not isinstance(value,str) or not value.strip() for value in selected.values()): return result|{"行":[],"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
            if SAFE.search(json.dumps(selected,ensure_ascii=False,sort_keys=True)): return result|{"行":[],"原因代码":"SENSITIVE_CANDIDATE_FIELD"}
            result["行"].append(selected)
        if missing_schema or (items and not result["行"]): return result|{"行":[],"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
        result["字段映射"]=first_mapping or {}
        result["Schema指纹"]=fp({"顶层":sorted(str(key) for key in payload) if isinstance(payload,dict) else "list","对象字段集合":schema_shapes})
    except Exception: result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
def read_sqlite_candidate(path):
    result={"格式":"sqlite","表":[],"行":[]}
    try:
        complete_table=False
        connection=sqlite3.connect("file:"+str(path)+"?mode=ro",uri=True)
        try:
            tables=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for table,sql in tables:
                if not isinstance(table,str) or table.startswith("sqlite_"): continue
                columns=[row[1] for row in connection.execute("PRAGMA table_info(\""+table.replace("\"","\"\"")+"\")")]
                mapping=fields_from_header(columns)
                result["表"].append({"表名指纹":fp(table),"字段指纹":fp(columns),"字段映射":mapping})
                if not set(CANDIDATE_FIELDS).issubset(mapping): continue
                complete_table=True
                selected_columns=",".join("\""+mapping[key].replace("\"","\"\"")+"\"" for key in CANDIDATE_FIELDS)
                order_columns=",".join("\""+mapping[key].replace("\"","\"\"")+"\"" for key in CANDIDATE_FIELDS)
                query="SELECT "+selected_columns+" FROM \""+table.replace("\"","\"\"")+"\" ORDER BY "+order_columns+" LIMIT 631"
                for row in connection.execute(query):
                    if len(result["行"])>=630: return result|{"行":[],"原因代码":"CANDIDATE_ROW_LIMIT_EXCEEDED"}
                    selected={key:row[index] for index,key in enumerate(CANDIDATE_FIELDS)}
                    if any(not isinstance(value,str) or not value.strip() for value in selected.values()): return result|{"行":[],"原因代码":"INCOMPLETE_IDENTITY_SCHEMA"}
                    if SAFE.search(json.dumps(selected,ensure_ascii=False,sort_keys=True)): return result|{"行":[],"原因代码":"SENSITIVE_CANDIDATE_FIELD"}
                    result["行"].append(selected)
        finally: connection.close()
        if not complete_table or not result["行"]: result["原因代码"]="INCOMPLETE_IDENTITY_SCHEMA"
    except Exception: result["原因代码"]="CANDIDATE_READ_FAILED"
    return result
def root_info(base,ordinal):
    st=base.stat()
    return {"路径指纹":fp(str(base)),"模式":oct(st.st_mode&0o777),"属主UID":st.st_uid,"属组GID":st.st_gid,"可读":os.access(base,os.R_OK),"可写":os.access(base,os.W_OK)}
def candidate_info(path,base):
    st=path.stat(); readable=os.access(path,os.R_OK)
    row={"路径指纹":fp(str(path)),"文件名":path.name,"上级目录指纹":fp(str(path.parent)),"候选根目录指纹":fp(str(base)),"大小":st.st_size,"修改时间_ns":st.st_mtime_ns,"模式":oct(st.st_mode&0o777),"属主UID":st.st_uid,"属组GID":st.st_gid,"可读":readable,"父目录可写":os.access(path.parent,os.W_OK)}
    suffix=path.suffix.lower()
    fmt={".csv":"csv",".json":"json",".sqlite3":"sqlite",".db":"sqlite"}.get(suffix,"unknown")
    if not readable or st.st_size>MAX_SIZE: return row|{"内容摘要":{"格式":fmt,"行":[],"原因代码":"FILE_TOO_LARGE" if st.st_size>MAX_SIZE else "CANDIDATE_NOT_READABLE"}}
    summary=read_csv_candidate(path) if suffix==".csv" else read_json_candidate(path) if suffix==".json" else read_sqlite_candidate(path) if suffix in (".sqlite3",".db") else {"格式":"unknown","行":[],"原因代码":"FORMAT_NOT_ALLOWLISTED"}
    return row|{"内容摘要":summary}
def emit(reason,uid=None,gid=None,roots=None,files=0,dirs=0,entries=0,queue=0,summary_bytes=0):
    print(json.dumps({"协议":"zhishi-binance-contract-probe/1","访问模式":"root兼容只读","扫描UID":os.geteuid() if uid is None else uid,"扫描GID":os.getegid() if gid is None else gid,"扫描是否专用只读":False,"扫描完整":False,"失败安全":True,"失败原因代码":reason,"失败原因指纹":fp(reason),"扫描文件数":files,"候选文件数":0,"候选":[],"存储根目录":roots or [],"索引目录数":dirs,"索引条目数":entries,"待处理目录数":queue,"索引候选摘要字节":summary_bytes,"远端追加":False,"远端临时文件":False,"数据库写入":False,"订单簿读取":False},ensure_ascii=False,sort_keys=True))
    raise SystemExit(0)
if os.geteuid()!=0: emit("REMOTE_IDENTITY_NOT_ROOT")
candidates=[]; roots_seen=[]; file_count=0; directory_count=0; entry_count=0; summary_bytes=0; scan_failed=False; failure_code=""
for root_index, root in enumerate(ROOTS,1):
    base=pathlib.Path(root)
    try:
        if base.is_symlink(): emit("ROOT_SYMLINK",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,0,summary_bytes)
        info=root_info(base,root_index); roots_seen.append(info)
        if not base.is_dir() or not info["可读"]: scan_failed=True; continue
    except Exception: scan_failed=True; continue
    queue=[base]
    while queue:
        if time.monotonic()>DEADLINE: emit("INDEX_TIMEOUT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
        if directory_count>=MAX_DIRS: emit("INDEX_DIRECTORY_LIMIT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
        current=queue.pop(0); directory_count+=1
        try: entries=sorted(os.scandir(current), key=lambda item: item.name)
        except Exception: scan_failed=True; continue
        for entry in entries:
            entry_count+=1
            if entry_count>MAX_ENTRIES: emit("INDEX_ENTRY_LIMIT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
            if time.monotonic()>DEADLINE: emit("INDEX_TIMEOUT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
            try:
                path=pathlib.Path(entry.path)
                if entry.is_symlink(): continue
                if entry.is_dir(follow_symlinks=False):
                    if skip(path): continue
                    if len(queue)>=MAX_QUEUE: emit("INDEX_QUEUE_LIMIT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
                    queue.append(path); continue
                if not entry.is_file(follow_symlinks=False): continue
                file_count+=1
                if entry.name.lower() not in NAMES: continue
                if len(str(path).encode("utf-8"))>MAX_PATH_BYTES: emit("INDEX_PATH_LIMIT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
                if len(candidates)>=MAX_CANDIDATES: emit("MAX_CANDIDATE_FILES_REACHED",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
                item=candidate_info(path,base); encoded=json.dumps(item.get("内容摘要",{}),ensure_ascii=False,sort_keys=True,separators=(",",":")).encode("utf-8")
                item_reason=item.get("内容摘要",{}).get("原因代码")
                if item["大小"]>MAX_SIZE or item_reason in {"FILE_TOO_LARGE","CANDIDATE_NOT_READABLE","CANDIDATE_READ_FAILED","SENSITIVE_CANDIDATE_FIELD","CANDIDATE_ROW_LIMIT_EXCEEDED","INCOMPLETE_IDENTITY_SCHEMA"}:
                    scan_failed=True
                    if not failure_code: failure_code="CANDIDATE_FILE_TOO_LARGE" if item["大小"]>MAX_SIZE or item_reason=="FILE_TOO_LARGE" else item_reason
                summary_bytes+=len(encoded)
                if summary_bytes>MAX_SUMMARY_BYTES: emit("INDEX_SUMMARY_BYTES_LIMIT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
                if SAFE.search(json.dumps(item,ensure_ascii=False,sort_keys=True)): emit("SENSITIVE_PROBE_OUTPUT",os.geteuid(),os.getegid(),roots_seen,file_count,directory_count,entry_count,len(queue),summary_bytes)
                candidates.append(item)
            except Exception: scan_failed=True
scan_complete=(not scan_failed and not queue if 'queue' in locals() else not scan_failed)
if not scan_complete: candidates=[]
failure_code="" if scan_complete else (failure_code or "ROOT_OR_WALK_ACCESS_FAILED")
print(json.dumps({"协议":"zhishi-binance-contract-probe/1","访问模式":"root兼容只读","扫描UID":os.geteuid(),"扫描GID":os.getegid(),"扫描是否专用只读":False,"扫描完整":scan_complete,"失败安全":not scan_complete,"失败原因代码":failure_code,"失败原因指纹":fp(failure_code) if failure_code else "","扫描文件数":file_count,"候选文件数":len(candidates),"候选":candidates,"存储根目录":roots_seen,"索引目录数":directory_count,"索引条目数":entry_count,"待处理目录数":0,"索引候选摘要字节":summary_bytes if scan_complete else 0,"远端追加":False,"远端临时文件":False,"数据库写入":False,"订单簿读取":False},ensure_ascii=False,sort_keys=True))
'''
    replacements = {
        "__ROOTS__": roots, "__NAMES__": names, "__EXCLUDED__": excluded,
        "__FIELDS__": fields, "__IDENTITY__": identity,
        "__MAX_DIRS__": str(limits["最大索引目录数"]), "__MAX_ENTRIES__": str(limits["最大索引条目数"]),
        "__MAX_QUEUE__": str(limits["最大索引队列数"]), "__MAX_PATH_BYTES__": str(limits["最大索引路径字节"]),
        "__MAX_SUMMARY_BYTES__": str(limits["最大候选摘要聚合字节"]), "__MAX_CANDIDATES__": str(limits["最大候选文件数"]),
        "__MAX_SIZE__": str(limits["最大候选文件字节"]), "__DEADLINE__": str(int(deadline_seconds)),
    }
    for key, value in replacements.items():
        source = source.replace(key, value)
    return source


def _validate_summary(summary: object, limits: Mapping[str, int]) -> bool:
    if not isinstance(summary, dict) or not isinstance(summary.get("格式"), str) or summary.get("格式") not in {"csv", "json", "sqlite"}:
        return False
    reason = summary.get("原因代码", "")
    if not isinstance(reason, str) or (reason and not re.fullmatch(r"[A-Z0-9_]{1,64}", reason)):
        return False
    if reason:
        return False
    rows = summary.get("行")
    if not isinstance(rows, list) or len(rows) > 630:
        return False
    if summary["格式"] in {"csv", "json"}:
        mapping = summary.get("字段映射")
        if not isinstance(mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in mapping.items()):
            return False
        if not reason and set(mapping) != set(legacy.CANDIDATE_FIELDS):
            return False
        if not reason and (not isinstance(summary.get("Schema指纹"), str) or not re.fullmatch(r"[0-9a-f]{64}", summary["Schema指纹"])):
            return False
    else:
        tables = summary.get("表")
        if not isinstance(tables, list):
            return False
        for table in tables:
            if not isinstance(table, dict) or set(table) != {"表名指纹", "字段指纹", "字段映射"}:
                return False
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(legacy.CANDIDATE_FIELDS) or legacy.sensitive(row):
            return False
        if any(not isinstance(value, str) or not value.strip() for value in row.values()):
            return False
    return True


def run_remote_probe(config: Mapping[str, Any]) -> dict[str, Any]:
    limits = config["资源上限"]
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={limits['SSH连接超时秒']}",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "ubuntu", "python3", "-",
    ]
    resource = {"批次总超时秒": limits["批次总超时秒"], "SSH连接超时秒": limits["SSH连接超时秒"], "最大输出字节": limits["最大输出字节"], "最大日志字节": limits["最大日志字节"]}
    try:
        completed = legacy.engine.run_bounded_process(command, input_text=_probe_source(config, limits["批次总超时秒"]), timeout=limits["批次总超时秒"], maximum_stdout=limits["最大输出字节"], maximum_stderr=limits["最大日志字节"])
        resource.update({"标准输出字节": len(completed.stdout.encode("utf-8")), "标准错误字节": len(completed.stderr.encode("utf-8"))})
    except Exception:
        return _failure("SSH_PROBE_RUNTIME_FAILURE", resource=resource)
    if completed.returncode != 0:
        return _failure("SSH_PROBE_FAILED", exit_code=completed.returncode, resource=resource)
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        return _failure("PROBE_RESPONSE_INVALID", exit_code=completed.returncode, resource=resource)
    required = {"协议", "访问模式", "扫描UID", "扫描GID", "扫描是否专用只读", "扫描完整", "失败安全", "失败原因代码", "失败原因指纹", "扫描文件数", "候选文件数", "候选", "存储根目录", "索引目录数", "索引条目数", "待处理目录数", "索引候选摘要字节", "远端追加", "远端临时文件", "数据库写入", "订单簿读取"}
    if not isinstance(payload, dict) or set(payload) != required or payload.get("协议") != "zhishi-binance-contract-probe/1" or payload.get("访问模式") != ROOT_MODE:
        return _failure("PROBE_PROTOCOL_DRIFT", exit_code=completed.returncode, resource=resource)
    if not isinstance(payload["协议"], str) or not isinstance(payload["访问模式"], str):
        return _failure("PROBE_PAYLOAD_TYPE_INVALID", exit_code=completed.returncode, resource=resource)
    integer_keys = ("扫描UID", "扫描GID", "扫描文件数", "候选文件数", "索引目录数", "索引条目数", "待处理目录数", "索引候选摘要字节")
    if any(isinstance(payload.get(key), bool) or not isinstance(payload.get(key), int) or payload[key] < 0 for key in integer_keys):
        return _failure("PROBE_COUNT_INVALID", exit_code=completed.returncode, resource=resource)
    bool_keys = ("扫描是否专用只读", "扫描完整", "失败安全", "远端追加", "远端临时文件", "数据库写入", "订单簿读取")
    if any(not isinstance(payload[key], bool) for key in bool_keys):
        return _failure("PROBE_PAYLOAD_TYPE_INVALID", exit_code=completed.returncode, resource=resource)
    if not isinstance(payload["失败原因代码"], str) or not isinstance(payload["失败原因指纹"], str):
        return _failure("PROBE_PAYLOAD_TYPE_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描UID"] != ROOT_UID or payload["扫描是否专用只读"] is not False:
        return _failure("ROOT_IDENTITY_FACT_INVALID", exit_code=completed.returncode, resource=resource)
    if any(payload.get(key) is not False for key in ("远端追加", "远端临时文件", "数据库写入", "订单簿读取")):
        return _failure("PROBE_SECURITY_BOUNDARY", exit_code=completed.returncode, resource=resource)
    if any(payload[key] > limits[key_name] for key, key_name in (("索引目录数", "最大索引目录数"), ("索引条目数", "最大索引条目数"), ("待处理目录数", "最大索引队列数"), ("索引候选摘要字节", "最大候选摘要聚合字节"))):
        return _failure("PROBE_INDEX_LIMIT", exit_code=completed.returncode, resource=resource)
    if not isinstance(payload["候选"], list) or payload["候选文件数"] != len(payload["候选"]) or payload["候选文件数"] > limits["最大候选文件数"]:
        return _failure("PROBE_CANDIDATE_COUNT_INVALID", exit_code=completed.returncode, resource=resource)
    if not isinstance(payload["存储根目录"], list) or len(payload["存储根目录"]) > len(EXPECTED_ROOTS):
        return _failure("PROBE_ROOT_SCHEMA_INVALID", exit_code=completed.returncode, resource=resource)
    root_fingerprints = {legacy.fingerprint(path) for path in EXPECTED_ROOTS}
    seen_root_fingerprints = set()
    for root in payload["存储根目录"]:
        if not isinstance(root, dict) or set(root) != {"路径指纹", "模式", "属主UID", "属组GID", "可读", "可写"}:
            return _failure("PROBE_ROOT_SCHEMA_INVALID", exit_code=completed.returncode, resource=resource)
        if (
            not isinstance(root["路径指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", root["路径指纹"])
            or root["路径指纹"] not in root_fingerprints or root["路径指纹"] in seen_root_fingerprints
            or not isinstance(root["模式"], str) or not re.fullmatch(r"0o[0-7]{3,4}", root["模式"])
            or isinstance(root["属主UID"], bool) or not isinstance(root["属主UID"], int) or root["属主UID"] < 0
            or isinstance(root["属组GID"], bool) or not isinstance(root["属组GID"], int) or root["属组GID"] < 0
            or not isinstance(root["可读"], bool) or not isinstance(root["可写"], bool)
        ):
            return _failure("PROBE_ROOT_PATH_INVALID", exit_code=completed.returncode, resource=resource)
        seen_root_fingerprints.add(root["路径指纹"])
    seen = set()
    for candidate in payload["候选"]:
        keys = {"路径指纹", "文件名", "上级目录指纹", "候选根目录指纹", "大小", "修改时间_ns", "模式", "属主UID", "属组GID", "可读", "父目录可写", "内容摘要"}
        if not isinstance(candidate, dict) or set(candidate) != keys:
            return _failure("PROBE_CANDIDATE_SCHEMA_INVALID", exit_code=completed.returncode, resource=resource)
        if not isinstance(candidate["路径指纹"], str) or candidate["路径指纹"] in seen:
            return _failure("PROBE_CANDIDATE_SCHEMA_INVALID", exit_code=completed.returncode, resource=resource)
        seen.add(candidate["路径指纹"])
        if (
            not isinstance(candidate["路径指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["路径指纹"])
            or not isinstance(candidate["候选根目录指纹"], str) or candidate["候选根目录指纹"] not in root_fingerprints
            or not isinstance(candidate["文件名"], str) or not candidate["文件名"]
            or not isinstance(candidate["上级目录指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["上级目录指纹"])
            or candidate["文件名"].lower() not in {name.lower() for name in config["候选文件名"]}
            or isinstance(candidate["大小"], bool) or not isinstance(candidate["大小"], int) or candidate["大小"] < 0 or candidate["大小"] > limits["最大候选文件字节"]
            or isinstance(candidate["修改时间_ns"], bool) or not isinstance(candidate["修改时间_ns"], int) or candidate["修改时间_ns"] < 0
            or not isinstance(candidate["模式"], str) or not re.fullmatch(r"0o[0-7]{3,4}", candidate["模式"])
            or isinstance(candidate["属主UID"], bool) or not isinstance(candidate["属主UID"], int) or candidate["属主UID"] < 0
            or isinstance(candidate["属组GID"], bool) or not isinstance(candidate["属组GID"], int) or candidate["属组GID"] < 0
            or not isinstance(candidate["可读"], bool) or not isinstance(candidate["父目录可写"], bool)
        ):
            return _failure("PROBE_CANDIDATE_METADATA_INVALID", exit_code=completed.returncode, resource=resource)
        if not _validate_summary(candidate["内容摘要"], limits):
            return _failure("PROBE_CONTENT_SUMMARY_INVALID", exit_code=completed.returncode, resource=resource)
        if legacy.sensitive(candidate):
            return _failure("PROBE_SENSITIVE_OUTPUT", exit_code=completed.returncode, resource=resource)
    summary_bytes = sum(len(json.dumps(item["内容摘要"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")) for item in payload["候选"])
    if summary_bytes != payload["索引候选摘要字节"] or summary_bytes > limits["最大候选摘要聚合字节"]:
        return _failure("PROBE_SUMMARY_BYTES_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描完整"] is not True and payload["失败安全"] is not True:
        return _failure("SCAN_FAILURE_SAFETY_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描完整"] is True and payload["失败安全"] is not False:
        return _failure("SCAN_COMPLETION_INVALID", exit_code=completed.returncode, resource=resource)
    reason = payload["失败原因代码"]
    if reason and not re.fullmatch(r"[A-Z0-9_]{1,64}", reason):
        return _failure("PROBE_FAILURE_CODE_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描完整"] is True and reason:
        return _failure("SCAN_COMPLETION_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描完整"] is not True and not reason:
        return _failure("SCAN_FAILURE_REASON_MISSING", exit_code=completed.returncode, resource=resource)
    if reason and payload["失败原因指纹"] != legacy.fingerprint(reason):
        return _failure("PROBE_FAILURE_FINGERPRINT_INVALID", exit_code=completed.returncode, resource=resource)
    if not reason and payload["失败原因指纹"] != "":
        return _failure("PROBE_FAILURE_FINGERPRINT_INVALID", exit_code=completed.returncode, resource=resource)
    if payload["扫描完整"] is not True:
        payload["候选"] = []; payload["候选文件数"] = 0; payload["索引候选摘要字节"] = 0
    elif len(payload["存储根目录"]) != len(EXPECTED_ROOTS) or seen_root_fingerprints != root_fingerprints:
        return _failure("PROBE_ROOT_COUNT_INVALID", exit_code=completed.returncode, resource=resource)
    payload["退出码"] = completed.returncode
    payload["资源事实"] = resource
    return payload


def _build_evidence(members: Sequence[Mapping[str, str]], candidates: Sequence[Mapping[str, Any]], contracts: Mapping[str, Sequence[Mapping[str, Any]]]):
    evidence, verified = _ROOT_BUILD_EVIDENCE(members, candidates, contracts)
    expected_count = len(members) * len(legacy.IDENTITY_FIELDS)
    records = evidence.get("记录") if isinstance(evidence, dict) else None
    record_keys = {"证据记录编号", "资产编号", "标的", "输入成员SHA-256", "证明字段", "声明值"}
    if (
        not isinstance(records, list)
        or len(verified) != len(members)
        or len(records) != expected_count
        or any(not isinstance(record, dict) or set(record) != record_keys for record in records)
        or any(not isinstance(record["证据记录编号"], str) or not record["证据记录编号"] for record in records)
        or len({record["证据记录编号"] for record in records}) != len(records)
        or any(record["证明字段"] not in legacy.IDENTITY_FIELDS for record in records)
    ):
        return {"证据版本": "source-identity-evidence-1.0", "记录": []}, []
    for record in evidence["记录"]:
        record["证据记录编号"] = record["证据记录编号"].replace("E-000088-", "E-000089-", 1)
    return evidence, verified


def execute(config_path: Path = CONFIG_PATH, batch_root: Path = DEFAULT_BATCH_ROOT, now: dt.datetime | None = None, batch_id_override: str | None = None) -> Path:
    config_path = config_path.resolve(); batch_root = batch_root.resolve()
    if config_path != CONFIG_PATH.resolve() or batch_root != DEFAULT_BATCH_ROOT.resolve():
        raise ValueError("执行路径必须固定在仓库配置和批次目录")
    config = load_config(config_path)
    members = legacy.load_members()
    start = now or dt.datetime.now().astimezone()
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    api_snapshots = [legacy.fetch_exchange_info(item, config["资源上限"], start) for item in config["Binance公开接口"]]
    remote = run_remote_probe(config)
    root_compat.TASK_ID = TASK_ID
    root_compat.TASK_PATH = TASK_PATH
    root_compat.CONFIG_PATH = CONFIG_PATH
    root_compat.DEFAULT_BATCH_ROOT = DEFAULT_BATCH_ROOT
    root_compat.build_evidence = _build_evidence
    return root_compat.render_root_batch(config, members, api_snapshots, remote, start, batch_root, batch_id_override=batch_id_override, config_path=config_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="任务-000089 root候选身份索引复验")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--batch-id", default=None)
    args = parser.parse_args(argv)
    try:
        target = execute(args.config, args.batch_root, batch_id_override=args.batch_id)
    except Exception as error:
        print(f"任务-000089执行失败：{type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({"状态": "成功", "批次": target.name, "路径": str(target.relative_to(ROOT))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
