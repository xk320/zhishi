#!/usr/bin/env python3
"""任务-000088：在实际UID=0时复验Binance合约身份候选。

只复用任务-000085的公开接口、成员绑定和不可变批次逻辑；root模式显式记录为
“root兼容只读”，不伪造专用只读身份，不写远端或数据库。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 复验币安合约身份 as legacy

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000088"
CONFIG_PATH = ROOT / "config/数据/任务-000088Root兼容合约身份复验.json"
TASK_PATH = ROOT / "docs/研发中心/任务/任务-000088.md"
MEMBERS_PATH = legacy.MEMBERS_PATH
DEFAULT_BATCH_ROOT = ROOT / "artifacts/数据/Binance合约身份复验"
ROOT_MODE = "root兼容只读"
ROOT_UID = 0
REQUIRED_CONFIG_KEYS = {
    "合同版本", "任务编号", "访问模式", "允许SSH目标", "实际UID", "专用只读UID",
    "远端候选根目录", "Binance公开接口", "标的", "主研究尺度", "事后结果观察窗口",
    "候选文件名", "身份字段", "资源上限", "安全边界", "远端扫描规则",
}


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    value = legacy.read_json(path)
    if set(value) != REQUIRED_CONFIG_KEYS:
        raise ValueError("root兼容配置字段漂移")
    if value["任务编号"] != TASK_ID or value["访问模式"] != ROOT_MODE or value["实际UID"] != ROOT_UID:
        raise ValueError("root兼容身份事实漂移")
    if value["专用只读UID"] != 1001 or value["允许SSH目标"] != ["ubuntu"] or value["标的"] != ["BTC", "ETH"]:
        raise ValueError("身份或标的白名单漂移")
    if value["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or value["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度漂移")
    expected_roots = [
        "/opt/binance-event", "/opt/celueqing", "/opt/crypto-radar",
        "/opt/event-prob-lab", "/opt/orderbook-intelligence-service", "/var/lib/mysql",
    ]
    if value["远端候选根目录"] != expected_roots:
        raise ValueError("远端根目录白名单漂移")
    if sorted(value["候选文件名"]) != sorted(legacy.CONTRACT_NAMES) or len(value["候选文件名"]) != len(legacy.CONTRACT_NAMES):
        raise ValueError("候选文件名白名单漂移")
    if value["身份字段"] != list(legacy.IDENTITY_FIELDS):
        raise ValueError("身份字段漂移")
    if any(value["安全边界"].values()):
        raise ValueError("安全边界必须全部为false")
    if value["远端扫描规则"] != {
        "不跟随符号链接": True,
        "排除文件系统": ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"],
        "仅读取候选元数据": True,
        "允许读取候选格式": ["csv", "json", "sqlite3", "db"],
    }:
        raise ValueError("远端扫描规则漂移")
    if value["资源上限"] != {
        "批次总超时秒": 900,
        "SSH连接超时秒": 15,
        "最大候选文件数": 4096,
        "最大候选文件字节": 16777216,
        "最大API响应字节": 16777216,
        "最大输出字节": 33554432,
        "最大日志字节": 65536,
    }:
        raise ValueError("资源上限漂移")
    endpoints = value["Binance公开接口"]
    if [item.get("端点") for item in endpoints] != list(legacy.FIXED_ENDPOINTS):
        raise ValueError("Binance公开接口漂移")
    if any(item.get("市场类型") != legacy.FIXED_ENDPOINTS.get(item.get("端点")) for item in endpoints):
        raise ValueError("Binance市场类型漂移")
    return value


def _root_failure(reason: str, *, exit_code: int | None = None, resource_facts: Mapping[str, Any] | None = None) -> dict[str, Any]:
    safe_reason = reason if re.fullmatch(r"[A-Z0-9_]{1,64}", reason) else "PROBE_FAILED"
    return {
        "协议": "zhishi-binance-contract-probe/1",
        "访问模式": ROOT_MODE,
        "扫描UID": None,
        "扫描GID": None,
        "扫描是否专用只读": False,
        "扫描完整": False,
        "失败安全": True,
        "失败原因代码": safe_reason,
        "失败原因指纹": legacy.fingerprint(safe_reason),
        "扫描文件数": 0,
        "候选文件数": 0,
        "候选": [],
        "存储根目录": [],
        "远端追加": False,
        "远端临时文件": False,
        "数据库写入": False,
        "订单簿读取": False,
        "退出码": exit_code,
        "资源事实": dict(resource_facts or {}),
    }


def _root_probe_source(config: Mapping[str, Any], deadline_seconds: int) -> str:
    # 任务配置同时保留专用UID=1001作为“不等价”对照；探针期望值必须是实际root UID=0。
    probe_config = dict(config)
    probe_config["专用只读UID"] = ROOT_UID
    source = legacy._remote_probe_source(probe_config, deadline_seconds)
    source = source.replace(
        '"协议":"zhishi-binance-contract-probe/1","扫描UID"',
        '"协议":"zhishi-binance-contract-probe/1","访问模式":"root兼容只读","扫描UID"',
    )
    source = source.replace('"扫描是否专用只读":True', '"扫描是否专用只读":False')
    source = source.replace(
        'return {"路径指纹":fp(str(path)),"文件名":path.name,"上级目录名":path.parent.name}',
        'return {"路径指纹":fp(str(path)),"文件名":path.name,"上级目录名":path.parent.name,"候选根目录指纹":fp(str(base))}',
    )
    return source


def run_root_remote_probe(config: Mapping[str, Any]) -> dict[str, Any]:
    timeout = int(config["资源上限"]["批次总超时秒"])
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "ubuntu", "python3", "-",
    ]
    limits = config["资源上限"]
    resource_facts: dict[str, Any] = {
        "批次总超时秒": int(limits["批次总超时秒"]),
        "SSH连接超时秒": int(limits["SSH连接超时秒"]),
        "最大输出字节": int(limits["最大输出字节"]),
        "最大日志字节": int(limits["最大日志字节"]),
    }

    def byte_length(value: object) -> int:
        if isinstance(value, str):
            return len(value.encode("utf-8"))
        if isinstance(value, (bytes, bytearray)):
            return len(value)
        return 0

    def non_bool_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    try:
        completed = legacy.engine.run_bounded_process(
            command,
            input_text=_root_probe_source(config, timeout),
            timeout=timeout,
            maximum_stdout=int(config["资源上限"]["最大输出字节"]),
            maximum_stderr=int(config["资源上限"]["最大日志字节"]),
        )
        resource_facts.update({
            "标准输出字节": byte_length(completed.stdout),
            "标准错误字节": byte_length(completed.stderr),
        })
    except Exception:
        return _root_failure("SSH_PROBE_RUNTIME_FAILURE", resource_facts=resource_facts)
    if completed.returncode != 0:
        return _root_failure("SSH_PROBE_FAILED", exit_code=completed.returncode, resource_facts=resource_facts)
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        return _root_failure("PROBE_RESPONSE_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if not isinstance(payload, dict):
        return _root_failure("PROBE_PAYLOAD_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    required = {
        "协议", "访问模式", "扫描UID", "扫描GID", "扫描是否专用只读", "扫描完整", "失败安全",
        "失败原因代码", "失败原因指纹", "扫描文件数", "候选文件数", "候选", "存储根目录",
        "远端追加", "远端临时文件", "数据库写入", "订单簿读取",
    }
    if set(payload) != required or payload.get("协议") != "zhishi-binance-contract-probe/1" or payload.get("访问模式") != ROOT_MODE:
        return _root_failure("PROBE_PROTOCOL_DRIFT", exit_code=completed.returncode, resource_facts=resource_facts)
    if not non_bool_int(payload.get("扫描UID")) or payload.get("扫描UID") != ROOT_UID or not non_bool_int(payload.get("扫描GID")) or payload.get("扫描GID") < 0 or payload.get("扫描是否专用只读") is not False:
        return _root_failure("ROOT_IDENTITY_FACT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if any(payload.get(key) is not False for key in ("远端追加", "远端临时文件", "数据库写入", "订单簿读取")):
        return _root_failure("PROBE_SECURITY_BOUNDARY", exit_code=completed.returncode, resource_facts=resource_facts)
    if not isinstance(payload.get("候选"), list) or not isinstance(payload.get("存储根目录"), list):
        return _root_failure("PROBE_PAYLOAD_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if not non_bool_int(payload.get("扫描文件数")) or not non_bool_int(payload.get("候选文件数")):
        return _root_failure("PROBE_COUNT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if (
        not 0 <= payload["扫描文件数"] <= int(limits["最大候选文件数"])
        or (
            payload["扫描文件数"] == int(limits["最大候选文件数"])
            and (payload.get("扫描完整") is not False or payload.get("失败安全") is not True)
        )
    ):
        return _root_failure("PROBE_SCAN_COUNT_LIMIT", exit_code=completed.returncode, resource_facts=resource_facts)
    if not 0 <= payload["候选文件数"] <= int(limits["最大候选文件数"]) or payload["候选文件数"] != len(payload["候选"]):
        return _root_failure("PROBE_CANDIDATE_COUNT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if payload["候选文件数"] > payload["扫描文件数"]:
        return _root_failure("PROBE_COUNT_NOT_CONSERVED", exit_code=completed.returncode, resource_facts=resource_facts)
    try:
        expected_root_fingerprints = {legacy.fingerprint(path) for path in config["远端候选根目录"]}
        expected_root_names = {Path(path).name for path in config["远端候选根目录"]}
        allowed_names = {name.lower() for name in config["候选文件名"]}
        roots = payload["存储根目录"]
        if len({item.get("路径指纹") for item in roots if isinstance(item, dict) and isinstance(item.get("路径指纹"), str)}) != len(roots):
            return _root_failure("PROBE_ROOT_DUPLICATE", exit_code=completed.returncode, resource_facts=resource_facts)
        for item in roots:
            if not isinstance(item, dict) or set(item) != {"根目录", "路径指纹", "模式", "属主UID", "属组GID", "可读", "可写"}:
                return _root_failure("PROBE_ROOT_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if (
                not isinstance(item["根目录"], str)
                or item["根目录"] not in expected_root_names
                or not isinstance(item["路径指纹"], str)
                or item["路径指纹"] not in expected_root_fingerprints
                or not isinstance(item["模式"], str)
                or not re.fullmatch(r"0o[0-7]{3,4}", item["模式"])
                or not non_bool_int(item["属主UID"])
                or item["属主UID"] < 0
                or not non_bool_int(item["属组GID"])
                or item["属组GID"] < 0
                or not isinstance(item["可读"], bool)
                or not isinstance(item["可写"], bool)
            ):
                return _root_failure("PROBE_ROOT_PATH_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
        candidate_keys = {"路径指纹", "文件名", "上级目录名", "候选根目录指纹", "大小", "修改时间_ns", "模式", "属主UID", "属组GID", "可读", "父目录可写", "内容摘要"}
        for candidate in payload["候选"]:
            if not isinstance(candidate, dict) or set(candidate) != candidate_keys:
                return _root_failure("PROBE_CANDIDATE_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if (
                not isinstance(candidate["路径指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["路径指纹"])
                or not isinstance(candidate["候选根目录指纹"], str) or candidate["候选根目录指纹"] not in expected_root_fingerprints
                or not isinstance(candidate["文件名"], str)
                or not isinstance(candidate["上级目录名"], str) or not candidate["上级目录名"]
                or not non_bool_int(candidate["大小"]) or candidate["大小"] < 0 or candidate["大小"] > int(limits["最大候选文件字节"])
                or not non_bool_int(candidate["修改时间_ns"]) or candidate["修改时间_ns"] < 0
                or not isinstance(candidate["模式"], str) or not re.fullmatch(r"0o[0-7]{3,4}", candidate["模式"])
                or not non_bool_int(candidate["属主UID"]) or candidate["属主UID"] < 0
                or not non_bool_int(candidate["属组GID"]) or candidate["属组GID"] < 0
                or not isinstance(candidate["可读"], bool) or not isinstance(candidate["父目录可写"], bool)
                or not isinstance(candidate["内容摘要"], dict)
            ):
                return _root_failure("PROBE_CANDIDATE_METADATA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if candidate["文件名"].lower() not in allowed_names:
                return _root_failure("PROBE_CANDIDATE_NAME_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            summary = candidate["内容摘要"]
            fmt = summary.get("格式")
            if fmt not in {"csv", "json", "sqlite"} or not isinstance(summary.get("行"), list) or len(summary["行"]) > 630:
                return _root_failure("PROBE_CONTENT_SUMMARY_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if not isinstance(summary.get("原因代码", ""), str) or (summary.get("原因代码") and not re.fullmatch(r"[A-Z0-9_]{1,64}", summary["原因代码"])):
                return _root_failure("PROBE_CONTENT_FAILURE_CODE_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if fmt in {"csv", "json"}:
                if set(summary) - {"格式", "字段映射", "行", "Schema指纹", "原因代码"}:
                    return _root_failure("PROBE_CONTENT_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
                mapping = summary.get("字段映射")
                if not isinstance(mapping, dict) or any(not isinstance(key, str) or key not in legacy.CANDIDATE_FIELDS or not isinstance(value, str) for key, value in mapping.items()):
                    return _root_failure("PROBE_FIELD_MAPPING_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
                if not summary.get("原因代码") and set(mapping) != set(legacy.CANDIDATE_FIELDS):
                    return _root_failure("PROBE_FIELD_MAPPING_INCOMPLETE", exit_code=completed.returncode, resource_facts=resource_facts)
            elif not isinstance(summary.get("表"), list):
                return _root_failure("PROBE_SQLITE_TABLES_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            elif set(summary) - {"格式", "表", "行", "原因代码"}:
                return _root_failure("PROBE_CONTENT_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if "原因代码" in summary:
                if set(summary) - {"格式", "字段映射", "行", "Schema指纹", "表", "原因代码"} or summary["行"]:
                    return _root_failure("PROBE_CONTENT_FAILURE_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if "Schema指纹" in summary and (not isinstance(summary["Schema指纹"], str) or not re.fullmatch(r"[0-9a-f]{64}", summary["Schema指纹"])):
                return _root_failure("PROBE_SCHEMA_FINGERPRINT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            if not summary.get("原因代码") and fmt in {"csv", "json"} and "Schema指纹" not in summary:
                return _root_failure("PROBE_SCHEMA_FINGERPRINT_MISSING", exit_code=completed.returncode, resource_facts=resource_facts)
            for row in summary["行"]:
                if not isinstance(row, dict) or set(row) != set(legacy.CANDIDATE_FIELDS):
                    return _root_failure("PROBE_CONTENT_ROW_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
                if legacy.sensitive(row):
                    return _root_failure("PROBE_CONTENT_SENSITIVE", exit_code=completed.returncode, resource_facts=resource_facts)
            if fmt == "sqlite":
                for table in summary.get("表", []):
                    if not isinstance(table, dict) or set(table) != {"表名指纹", "字段指纹", "字段映射"}:
                        return _root_failure("PROBE_SQLITE_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
                    if any(not isinstance(table[key], str) or not re.fullmatch(r"[0-9a-f]{64}", table[key]) for key in ("表名指纹", "字段指纹")):
                        return _root_failure("PROBE_SQLITE_FINGERPRINT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
            elif set(summary) - {"格式", "字段映射", "行", "Schema指纹", "原因代码"}:
                return _root_failure("PROBE_CONTENT_SCHEMA_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    except (AttributeError, TypeError, ValueError):
        return _root_failure("PROBE_PAYLOAD_TYPE_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if payload.get("扫描完整") is not True and payload.get("失败安全") is not True:
        return _root_failure("SCAN_FAILURE_SAFETY_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if payload.get("失败原因代码") and payload.get("失败原因指纹") != legacy.fingerprint(payload["失败原因代码"]):
        return _root_failure("PROBE_FAILURE_FINGERPRINT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if not payload.get("失败原因代码") and payload.get("失败原因指纹") != "":
        return _root_failure("PROBE_FAILURE_FINGERPRINT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    if legacy.sensitive(payload):
        return _root_failure("PROBE_SENSITIVE_OUTPUT", exit_code=completed.returncode, resource_facts=resource_facts)
    if payload.get("扫描完整") is not True or payload.get("失败安全") is not False:
        payload["候选"] = []
        payload["候选文件数"] = 0
    elif len(roots) != len(config["远端候选根目录"]):
        return _root_failure("PROBE_ROOT_COUNT_INVALID", exit_code=completed.returncode, resource_facts=resource_facts)
    payload["退出码"] = completed.returncode
    payload["资源事实"] = resource_facts
    return payload


def build_evidence(members: Sequence[Mapping[str, str]], candidates: Sequence[Mapping[str, Any]], contracts: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    seen_bindings: set[tuple[str, str, str, str]] = set()
    for candidate in candidates:
        fields = candidate.get("字段", {})
        if not isinstance(fields, Mapping):
            continue
        binding = tuple(str(fields.get(key, "")) for key in ("标的", "资产编号", "成员编号", "输入成员SHA-256"))
        if all(binding) and binding in seen_bindings:
            return {"证据版本": "source-identity-evidence-1.0", "记录": []}, []
        if all(binding):
            seen_bindings.add(binding)
    evidence, verified = legacy.build_evidence(members, candidates, contracts)
    for record in evidence["记录"]:
        record["证据记录编号"] = record["证据记录编号"].replace("E-000085-", "E-000088-", 1)
    return evidence, verified


def _task_contract_fingerprint() -> str:
    return legacy.task_contract_fingerprint(TASK_PATH)


def render_root_batch(
    config: Mapping[str, Any],
    members: Sequence[Mapping[str, str]],
    api_snapshots: Sequence[Mapping[str, Any]],
    remote: Mapping[str, Any],
    batch_start: dt.datetime,
    batch_root: Path,
    batch_id_override: str | None = None,
    config_path: Path = CONFIG_PATH,
) -> Path:
    candidates = legacy.flatten_candidates(remote) if remote.get("扫描完整") is True and remote.get("失败安全") is False else []
    contracts = legacy.api_contracts(api_snapshots)
    evidence, verified = build_evidence(members, candidates, contracts)
    complete = len(verified) == len(members) == 630
    if not complete:
        evidence = {"证据版本": "source-identity-evidence-1.0", "记录": []}
        verified = []
    summary = legacy.summarize(members, verified, remote, api_snapshots, candidates=candidates if complete else [])
    summary["访问模式"] = remote.get("访问模式", ROOT_MODE)
    summary["Root身份事实"] = "uid=0；root不等价于专用只读UID=1001"
    generated_id = "binance-contract-identity-" + batch_start.strftime("%Y%m%dT%H%M%S%z") + "-" + legacy.fingerprint({"任务": TASK_ID, "API": api_snapshots, "远端": remote, "成员": legacy.sha_path(MEMBERS_PATH)})[:12]
    batch_id = batch_id_override or generated_id
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}", batch_id):
        raise ValueError("批次身份格式非法")
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("批次目录已存在")
    manifest = {
        "合同版本": "binance-contract-identity-recheck-1.0",
        "任务编号": TASK_ID,
        "访问模式": ROOT_MODE,
        "实际UID": ROOT_UID,
        "批次": batch_id,
        "冻结时间": batch_start.isoformat(timespec="microseconds"),
        "成员顺序SHA-256": legacy.sha_path(MEMBERS_PATH),
        "任务合同SHA-256": _task_contract_fingerprint(),
        "任务文件SHA-256": legacy.sha_path(TASK_PATH),
        "任务合同指纹口径": "固定合同正文；排除执行/交付事实元数据",
        "配置SHA-256": legacy.sha_path(config_path),
        "公开接口摘要": api_snapshots,
        "Ubuntu扫描摘要": {key: remote.get(key) for key in ("访问模式", "扫描UID", "扫描GID", "扫描是否专用只读", "扫描完整", "失败安全", "失败原因代码", "失败原因指纹", "扫描文件数", "候选文件数", "存储根目录", "远端追加", "数据库写入", "订单簿读取", "退出码", "资源事实")},
        "候选文件摘要": remote.get("候选", []),
        "结果摘要": summary,
        "证据记录数": len(evidence["记录"]),
        "安全边界": config["安全边界"],
        "资源上限": config["资源上限"],
        "结论边界": "描述性差异不能推导因果、预测优势、胜率、收益、研究准入或交易许可",
        "输出文件SHA-256": {},
    }
    output = {
        "批次清单.json": json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "Binance接口摘要.json": json.dumps(api_snapshots, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "Ubuntu候选摘要.json": json.dumps(remote, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "成员状态摘要.json": json.dumps({"结果摘要": summary, "已证明成员": verified}, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    }
    manifest["输出文件SHA-256"] = {name: hashlib.sha256(text.encode("utf-8")).hexdigest() for name, text in output.items() if name != "批次清单.json"}
    manifest["输出文件SHA-256"]["批次清单.json"] = "不递归；以发布后的Git对象SHA-256复算"
    output["批次清单.json"] = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if complete:
        output["任务-000084来源身份声明证据.json"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    batch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{batch_id}-", dir=batch_root) as temp:
        staging = Path(temp)
        for name, text in output.items():
            (staging / name).write_text(text, encoding="utf-8")
        if any(legacy.sensitive(path.read_text(encoding="utf-8")) for path in staging.iterdir()):
            raise ValueError("输出包含敏感信息")
        legacy.engine.atomic_publish_directory_no_replace(staging, target)
    return target


def execute(config_path: Path = CONFIG_PATH, batch_root: Path = DEFAULT_BATCH_ROOT, now: dt.datetime | None = None, batch_id_override: str | None = None) -> Path:
    config_path = config_path.resolve()
    batch_root = batch_root.resolve()
    if config_path != CONFIG_PATH.resolve() or batch_root != DEFAULT_BATCH_ROOT.resolve():
        raise ValueError("执行路径必须固定在仓库配置和批次目录")
    config = load_config(config_path)
    members = legacy.load_members()
    start = now or dt.datetime.now().astimezone()
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    api_snapshots = [legacy.fetch_exchange_info(api_spec, config["资源上限"], start) for api_spec in config["Binance公开接口"]]
    remote = run_root_remote_probe(config)
    return render_root_batch(config, members, api_snapshots, remote, start, batch_root, batch_id_override=batch_id_override, config_path=config_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="任务-000088 root兼容只读合约身份复验")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    parser.add_argument("--batch-id", default=None)
    args = parser.parse_args(argv)
    try:
        target = execute(args.config, args.batch_root, batch_id_override=args.batch_id)
    except Exception as error:
        print(f"任务-000088执行失败：{type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({"状态": "成功", "批次": target.name, "路径": str(target.relative_to(ROOT))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
