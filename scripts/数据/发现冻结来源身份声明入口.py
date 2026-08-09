#!/usr/bin/env python3
"""任务-000082：固定白名单内的来源身份声明入口发现与冻结。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000082"
CONTRACT_VERSION = "source-identity-entry-discovery-1.0"
PROBE_VERSION = "source-identity-entry-discovery-probe-1.0"
CONFIG_PATH = ROOT / "config/数据/任务-000082来源身份入口复验.json"
DEFAULT_BATCH_ROOT = ROOT / "artifacts/数据/来源身份声明入口发现"
FINAL_BATCH = ROOT / "artifacts/数据/来源身份声明九字段复验/source-identity-nine-fields-20260808T074100+0800-v4"
FINAL_CSV = FINAL_BATCH / "来源身份声明九字段复验清单.csv"
INVENTORY_PATH = ROOT / "artifacts/审计/数据源清单.csv"
SOURCE_CONFIGS = (ROOT / "config/数据/数据来源与资产身份.json", ROOT / "config/数据/来源身份声明补采.json")
TARGETS = ("BTC", "ETH")
IDENTITY_FIELDS = ("来源提供者", "交易场所", "市场类型", "标的身份", "精确合约", "数据对象", "Schema确切版本", "授权边界", "字段中文映射")
EVIDENCE_FIELDS = ("成员编号", "资产编号", "输入成员SHA-256", "声明版本", "声明内容SHA-256", "Schema指纹", "授权快照SHA-256", "撤销事实", "证据定位")
FINAL_STATES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
ENTRY_STATES = ("未登记", "入口不完整", "已登记")
LOCATABLE_STATES = ("已定位", "不可定位")
SAFETY_KEYS = ("远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据", "原始业务记录落盘", "读取价格成交订单簿", "修改原始数据", "修改生产系统")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
OUTPUT_COLUMNS = ("批次", "成员编号", "资产编号", "标的", "入口状态", "可定位", "候选入口数", "九字段状态", "最终身份状态", *IDENTITY_FIELDS, "声明版本", "声明来源", "证据定位", "声明内容SHA-256", "输入成员SHA-256", "Schema指纹", "授权快照SHA-256", "撤销事实", "原因代码", "缺失字段", "限制", "解除条件", "入口记录SHA-256", "规则SHA-256", "执行器SHA-256", "成员记录SHA-256")


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fp(value: object) -> str:
    return sha_bytes(canonical(value).encode("utf-8"))


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return f"<temporary>/{path.name}"


def sensitive(value: object) -> bool:
    return engine._contains_sensitive(canonical(value))


def load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label}必须是普通文件")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}不是合法JSON") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{label}必须是对象")
    return payload


def resolve_input(path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("输入路径越界")
    candidate = ROOT / path
    resolved = candidate.resolve()
    if candidate.is_symlink() or not candidate.is_file() or ROOT not in resolved.parents:
        raise ValueError("输入文件必须是仓库内普通文件")
    return candidate


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    raw = load_json(path, "任务-000082配置")
    expected = {"合同版本", "任务编号", "允许SSH目标", "允许文件根目录", "声明文件名", "数据库元数据范围", "数据库注释列", "数据库声明前缀", "身份字段", "标的", "主研究尺度", "事后结果观察窗口", "输入文件", "安全边界", "资源上限"}
    if set(raw) != expected or raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("任务配置字段或合同版本漂移")
    if raw["允许SSH目标"] != ["ubuntu"] or raw["标的"] != list(TARGETS):
        raise ValueError("SSH或标的白名单漂移")
    if raw["允许文件根目录"] != ["/opt/binance-event", "/opt/celueqing", "/opt/crypto-radar", "/opt/event-prob-lab", "/opt/orderbook-intelligence-service", "/var/lib/mysql"]:
        raise ValueError("白名单根目录漂移")
    if raw["声明文件名"] != ["来源身份声明.json", "source-identity.json", "data-source-manifest.json", "dataset-identity.json"]:
        raise ValueError("声明文件名白名单漂移")
    if raw["数据库元数据范围"] != ["information_schema.TABLES", "information_schema.COLUMNS"] or raw["数据库声明前缀"] != "知势身份声明:":
        raise ValueError("数据库元数据边界漂移")
    if raw["数据库注释列"] != ["TABLE_SCHEMA", "TABLE_NAME", "TABLE_COMMENT", "COLUMN_NAME", "COLUMN_TYPE", "ORDINAL_POSITION", "COLUMN_COMMENT"]:
        raise ValueError("数据库注释列漂移")
    if raw["身份字段"] != list(IDENTITY_FIELDS) or raw["标的"] != list(TARGETS) or raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度或身份字段漂移")
    if set(raw["安全边界"]) != set(SAFETY_KEYS) or any(raw["安全边界"][key] is not False for key in SAFETY_KEYS):
        raise ValueError("安全边界必须全部为false")
    resource_keys = {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大输出字节数", "最大日志字节数", "单文件最大字节数"}
    if set(raw["资源上限"]) != resource_keys or int(raw["资源上限"]["最大成员数"]) < 630 or int(raw["资源上限"]["单文件最大字节数"]) != 262144:
        raise ValueError("资源上限漂移")
    seen: set[str] = set()
    for item in raw["输入文件"]:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"} or item["路径"] in seen:
            raise ValueError("输入合同字段重复或不完整")
        seen.add(item["路径"])
        if sha_path(resolve_input(str(item["路径"]))) != item["SHA-256"]:
            raise ValueError(f"输入指纹漂移：{item['路径']}")
    return raw


def load_members() -> tuple[dict[str, Any], list[dict[str, str]]]:
    manifest = load_json(FINAL_BATCH / "批次清单.json", "任务-000081最终批次清单")
    if manifest.get("任务编号") != "任务-000081" or manifest.get("输出SHA-256", {}).get(FINAL_CSV.name) != sha_path(FINAL_CSV):
        raise ValueError("任务-000081最终批次指纹漂移")
    with FINAL_CSV.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    required = {"成员编号", "资产编号", "标的", "最终身份状态", "输入成员SHA-256"}
    if len(rows) != 630 or not rows or not required.issubset(rows[0]):
        raise ValueError("任务-000081成员分母或字段漂移")
    ordered = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != ordered or any(row["标的"] not in TARGETS for row in rows) or len({row["成员编号"] for row in rows}) != 630 or len({row["资产编号"] for row in rows}) != 315:
        raise ValueError("成员顺序或唯一性漂移")
    if any(row["最终身份状态"] not in FINAL_STATES for row in rows):
        raise ValueError("历史最终状态非法")
    return manifest, rows


def load_inventory() -> list[dict[str, str]]:
    with INVENTORY_PATH.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    selected = sorted((row for row in rows if row.get("资产类型") in {"候选数据文件", "数据库元数据"}), key=lambda row: row["资产编号"])
    if len(selected) != 315 or len({row["资产编号"] for row in selected}) != 315:
        raise ValueError("资产清单候选总体漂移")
    return selected


def normalize_candidate(raw: object, source: str, location: str, entrance_sha: str, asset_id: str | None = None) -> dict[str, Any] | None:
    if not isinstance(raw, dict) or sensitive(raw) or sensitive(location):
        return None
    declaration = dict(raw)
    if asset_id and not declaration.get("资产编号"):
        declaration["资产编号"] = asset_id
    if "声明内容SHA-256" not in declaration:
        declaration["声明内容SHA-256"] = fp({key: value for key, value in declaration.items() if key != "声明内容SHA-256"})
    return {"来源类型": source, "证据定位": location, "入口内容SHA-256": entrance_sha, "声明": declaration}


def load_local_candidates() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in SOURCE_CONFIGS:
        payload = load_json(path, "仓库来源身份配置")
        declarations = payload.get("身份声明")
        if not isinstance(declarations, list):
            raise ValueError("仓库身份声明入口必须是列表")
        for index, declaration in enumerate(declarations):
            item = normalize_candidate(declaration, "仓库配置", f"{rel(path)}#身份声明[{index}]", sha_path(path))
            if item:
                result.append(item)
    return result


def sql_literal(value: str) -> str:
    if not SAFE_NAME.fullmatch(value):
        raise ValueError("数据库对象名越界")
    return "'" + value.replace("'", "''") + "'"


def build_probe_script(assets: Sequence[Mapping[str, str]], config: Mapping[str, Any]) -> str:
    compact = [{"资产编号": str(a["资产编号"]), "资产类型": str(a["资产类型"]), "位置": str(a["位置"])} for a in assets]
    pairs: list[tuple[str, str]] = []
    for asset in compact:
        if asset["资产类型"] != "数据库元数据":
            continue
        parts = asset["位置"].split("/")
        if len(parts) != 3 or parts[0] != "MySQL" or not SAFE_NAME.fullmatch(parts[1]) or not SAFE_NAME.fullmatch(parts[2]):
            raise ValueError("数据库资产位置越界")
        pairs.append((parts[1], parts[2]))
    where = " OR ".join(f"(t.TABLE_SCHEMA={sql_literal(schema)} AND t.TABLE_NAME={sql_literal(table)})" for schema, table in pairs) or "1=0"
    sql = "SELECT t.TABLE_SCHEMA,t.TABLE_NAME,COALESCE(t.TABLE_COMMENT,''),COALESCE(c.COLUMN_NAME,''),COALESCE(c.COLUMN_TYPE,''),COALESCE(c.ORDINAL_POSITION,''),COALESCE(c.COLUMN_COMMENT,'') FROM information_schema.TABLES t LEFT JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME WHERE " + where + " ORDER BY t.TABLE_SCHEMA,t.TABLE_NAME,c.ORDINAL_POSITION"
    assets_json = json.dumps(compact, ensure_ascii=False, sort_keys=True)
    roots_json = json.dumps(list(config["允许文件根目录"]), ensure_ascii=False)
    names_json = json.dumps(list(config["声明文件名"]), ensure_ascii=False)
    prefix = str(config["数据库声明前缀"])
    return textwrap.dedent(f"""\
        import hashlib, json, os, re, stat, subprocess
        ASSETS = json.loads({assets_json!r})
        ROOTS = json.loads({roots_json!r})
        FILENAMES = set(json.loads({names_json!r}))
        SQL = {sql!r}
        PREFIX = {prefix!r}
        PROBE_VERSION = {PROBE_VERSION!r}
        MAX_FILE = 262144
        SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
        SAFE = re.compile(r"(?i)(?:password|passwd|pwd|secret|token)\\s*[:=]|-----BEGIN|\\b(?:gh[pousr]_\\w{{20,}}|AKIA[A-Z0-9]{{16}})\\b|\\b[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9_.-]+\\b|(?<![\\d.])(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){{3}}(?![\\d.])")
        def fp(value):
            return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        def safe(value):
            if not isinstance(value, dict):
                return None
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if SAFE.search(text):
                return None
            item = dict(value)
            item.setdefault("声明内容SHA-256", fp({{k: v for k, v in item.items() if k != "声明内容SHA-256"}}))
            return item
        candidates = []
        counts = {{asset["资产编号"]: {{\"file\": 0, \"db\": 0}} for asset in ASSETS}}
        metadata = {{asset["资产编号"]: [] for asset in ASSETS if asset["资产类型"] == "数据库元数据"}}
        for root in ROOTS:
            if not os.path.isdir(root) or os.path.islink(root):
                continue
            for current, dirs, files in os.walk(root, topdown=True):
                if os.path.islink(current):
                    dirs[:] = []
                    continue
                depth = os.path.relpath(current, root).count(os.sep) + (0 if os.path.relpath(current, root) == "." else 1)
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {{"secret", "secrets", "runtime", "run"}} and not os.path.islink(os.path.join(current, d))]
                if depth >= 2:
                    dirs[:] = []
                for name in sorted(files):
                    if name not in FILENAMES:
                        continue
                    path = os.path.join(current, name)
                    try:
                        info = os.lstat(path)
                        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > MAX_FILE:
                            continue
                        data = open(path, "rb").read(MAX_FILE + 1)
                        if len(data) > MAX_FILE:
                            continue
                        document = json.loads(data.decode("utf-8"))
                        declarations = document.get("身份声明", []) if isinstance(document, dict) else []
                        if not isinstance(declarations, list):
                            continue
                        entrance_sha = hashlib.sha256(data).hexdigest()
                        for index, declaration in enumerate(declarations):
                            item = safe(declaration)
                            if item is not None:
                                candidates.append({{"来源类型": "ubuntu声明文件", "证据定位": path + "#身份声明[" + str(index) + "]", "入口内容SHA-256": entrance_sha, "声明": item}})
                                for asset in ASSETS:
                                    if item.get("资产编号") in {{asset["资产编号"], "*"}}:
                                        counts[asset["资产编号"]]["file"] += 1
                    except (OSError, UnicodeError, ValueError, TypeError):
                        continue
        env = {{"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}}
        try:
            completed = subprocess.run(["mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names", "--binary-mode", "--protocol=SOCKET", "--connect-timeout=3", "-e", SQL], capture_output=True, text=True, timeout=5, env=env, check=False)
            if completed.returncode == 0 and len(completed.stdout.encode("utf-8", "replace")) <= 8388608 and len(completed.stderr.encode("utf-8", "replace")) <= 32768:
                tables = {{}}
                for line in completed.stdout.splitlines():
                    fields = line.split("\\t")
                    if len(fields) != 7:
                        continue
                    schema, table, table_comment, column, column_type, ordinal, column_comment = fields
                    if not SAFE_NAME.fullmatch(schema) or not SAFE_NAME.fullmatch(table):
                        continue
                    tables.setdefault((schema, table), []).append({{"TABLE_SCHEMA": schema, "TABLE_NAME": table, "TABLE_COMMENT_SHA-256": fp(table_comment), "COLUMN_NAME": column, "COLUMN_TYPE": column_type, "ORDINAL_POSITION": ordinal, "COLUMN_COMMENT_SHA-256": fp(column_comment)}})
                    for comment, marker in ((table_comment, "TABLE_COMMENT"), (column_comment, "COLUMN_COMMENT")):
                        if not comment.startswith(PREFIX):
                            continue
                        try:
                            value = json.loads(comment[len(PREFIX):])
                        except (ValueError, TypeError):
                            continue
                        item = safe(value)
                        if item is None:
                            continue
                        location = "MySQL/" + schema + "/" + table + "#" + marker
                        candidates.append({{"来源类型": "数据库注释", "证据定位": location, "入口内容SHA-256": fp({{"schema": schema, "table": table, "marker": marker}}), "声明": item}})
                        for asset in ASSETS:
                            if asset["位置"] == "MySQL/" + schema + "/" + table:
                                counts[asset["资产编号"]]["db"] += 1
                for asset in ASSETS:
                    if asset["资产类型"] == "数据库元数据":
                        parts = asset["位置"].split("/")
                        rows = tables.get((parts[1], parts[2]), [])
                        metadata[asset["资产编号"]] = rows
            else:
                pass
        except (OSError, subprocess.SubprocessError):
            pass
        results = []
        for asset in ASSETS:
            rows = metadata.get(asset["资产编号"], [])
            results.append({{"资产编号": asset["资产编号"], "文件入口数": counts[asset["资产编号"]]["file"], "数据库入口数": counts[asset["资产编号"]]["db"], "元数据SHA-256": fp(rows) if rows else "未知", "状态": "已读取元数据" if rows else "无法判定", "原因代码": "DATABASE_COMMENT_SUMMARY_READ" if rows else "READONLY_METADATA_UNAVAILABLE"}})
        print(json.dumps({{"探针版本": PROBE_VERSION, "远端写入": False, "远端临时文件": False, "数据库业务记录读取": False, "读取环境变量或凭据": False, "读取价格成交订单簿": False, "原始业务记录落盘": False, "修改原始数据": False, "修改生产系统": False, "结果": results, "候选": candidates}}, ensure_ascii=False, sort_keys=True))
    """)


def run_probe(script: str, config: Mapping[str, Any], runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    resources = config["资源上限"]
    command = engine.build_ssh_command("ssh", "ubuntu", int(resources["批次总超时秒"]))
    completed = runner(command, input=script, capture_output=True, text=True, timeout=int(resources["批次总超时秒"]), check=False) if runner else engine.run_bounded_process(command, input_text=script, timeout=int(resources["批次总超时秒"]), maximum_stdout=int(resources["最大输出字节数"]), maximum_stderr=int(resources["最大日志字节数"]))
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if completed.returncode != 0 or len(stdout.encode()) > int(resources["最大输出字节数"]):
        raise RuntimeError("来源身份入口探针失败或输出超限")
    payload = json.loads(stdout)
    required = {"探针版本", *SAFETY_KEYS, "结果", "候选"}
    if set(payload) != required or payload["探针版本"] != PROBE_VERSION or any(payload[key] is not False for key in SAFETY_KEYS):
        raise ValueError("探针响应越过安全边界")
    if not isinstance(payload["结果"], list) or len(payload["结果"]) != 315 or len({item.get("资产编号") for item in payload["结果"]}) != 315:
        raise ValueError("探针未覆盖315个资产")
    if not isinstance(payload["候选"], list) or len(payload["候选"]) > int(resources["最大成员数"]) or sensitive(payload):
        raise ValueError("探针候选越界")
    for item in payload["候选"]:
        if not isinstance(item, dict) or set(item) != {"来源类型", "证据定位", "入口内容SHA-256", "声明"} or not isinstance(item["声明"], dict):
            raise ValueError("探针候选结构非法")
    return payload

def matching(candidates: Sequence[Mapping[str, Any]], row: Mapping[str, str]) -> list[dict[str, Any]]:
    return sorted(
        [
            dict(item) for item in candidates
            if item.get("声明", {}).get("资产编号") in {row["资产编号"], "*"}
            and item.get("声明", {}).get("标的") in {row["标的"], "*"}
        ],
        key=lambda item: (str(item.get("证据定位", "")), canonical(item.get("声明", {}))),
    )


def complete(candidate: Mapping[str, Any], row: Mapping[str, str]) -> tuple[bool, list[str]]:
    declaration = candidate.get("声明", {})
    missing = [
        field for field in (*IDENTITY_FIELDS, *EVIDENCE_FIELDS)
        if not str(declaration.get(field, "")).strip() or str(declaration.get(field)).strip() == "未知"
    ]
    for field in ("输入成员SHA-256", "声明内容SHA-256", "Schema指纹", "授权快照SHA-256"):
        if not SHA256.fullmatch(str(declaration.get(field, ""))) and field not in missing:
            missing.append(field)
    if declaration.get("资产编号") != row["资产编号"]:
        missing.append("资产编号")
    if declaration.get("标的") != row["标的"]:
        missing.append("标的")
    if declaration.get("成员编号") != row["成员编号"]:
        missing.append("成员编号")
    if declaration.get("输入成员SHA-256") != row["输入成员SHA-256"]:
        missing.append("输入成员SHA-256")
    if declaration.get("撤销事实") not in {"有效", "未撤销"}:
        missing.append("撤销事实")
    content = {key: value for key, value in declaration.items() if key != "声明内容SHA-256"}
    if declaration.get("声明内容SHA-256") != fp(content):
        missing.append("声明内容SHA-256")
    return not missing, sorted(set(missing))


def evaluate_member(row: Mapping[str, str], candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    matches = matching(candidates, row)
    prior = row.get("最终身份状态", "无法判定")
    if not matches:
        return {"入口状态": "未登记", "可定位": "不可定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": 0, "原因代码": "IDENTITY_DECLARATION_MISSING", "缺失字段": ";".join((*IDENTITY_FIELDS, *EVIDENCE_FIELDS)), "声明来源": "未登记", "证据定位": "未登记", "声明": {}}
    complete_items: list[dict[str, Any]] = []
    missing: list[str] = []
    for item in matches:
        ok, fields = complete(item, row)
        if ok:
            complete_items.append(item)
        else:
            missing.extend(fields)
    if len(complete_items) > 1 and len({canonical(item["声明"]) for item in complete_items}) > 1:
        item = complete_items[0]
        return {"入口状态": "已登记", "可定位": "已定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": len(matches), "原因代码": "IDENTITY_DECLARATION_CONFLICT", "缺失字段": "声明冲突", "声明来源": item.get("来源类型", "未知"), "证据定位": item.get("证据定位", "未知"), "声明": item["声明"]}
    if not complete_items:
        item = matches[0]
        return {"入口状态": "入口不完整", "可定位": "已定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": len(matches), "原因代码": "IDENTITY_DECLARATION_INCOMPLETE", "缺失字段": ";".join(sorted(set(missing))), "声明来源": item.get("来源类型", "未知"), "证据定位": item.get("证据定位", "未知"), "声明": item.get("声明", {})}
    item = complete_items[0]
    if prior != "无法判定":
        state, reason = prior, "PRIOR_TERMINAL_STATE_PRESERVED"
    else:
        state, reason = "已证明", "IDENTITY_DECLARATION_MATCHED"
    return {"入口状态": "已登记", "可定位": "已定位", "九字段状态": "已证明", "最终身份状态": state, "候选入口数": len(matches), "原因代码": reason, "缺失字段": "", "声明来源": item.get("来源类型", "未知"), "证据定位": item.get("证据定位", "未知"), "声明": item["声明"]}


def build_rows(members: Sequence[Mapping[str, str]], candidates: Sequence[Mapping[str, Any]], batch_id: str, rules_hash: str, executor_hash: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    rows: list[dict[str, str]] = []
    for member in members:
        result = evaluate_member(member, candidates)
        declaration = result.pop("声明")
        row: dict[str, str] = {
            "批次": batch_id, "成员编号": member["成员编号"], "资产编号": member["资产编号"], "标的": member["标的"],
            "入口状态": str(result["入口状态"]), "可定位": str(result["可定位"]), "候选入口数": str(result["候选入口数"]),
            "九字段状态": str(result["九字段状态"]), "最终身份状态": str(result["最终身份状态"]),
            **{field: str(declaration.get(field, "未知")) for field in IDENTITY_FIELDS},
            "声明版本": str(declaration.get("声明版本", "未知")), "声明来源": str(result["声明来源"]), "证据定位": str(result["证据定位"]),
            "声明内容SHA-256": str(declaration.get("声明内容SHA-256", "未知")), "输入成员SHA-256": str(declaration.get("输入成员SHA-256", member["输入成员SHA-256"])),
            "Schema指纹": str(declaration.get("Schema指纹", "未知")), "授权快照SHA-256": str(declaration.get("授权快照SHA-256", "未知")),
            "撤销事实": str(declaration.get("撤销事实", "未复验")), "原因代码": str(result["原因代码"]), "缺失字段": str(result["缺失字段"]),
            "限制": "只读取固定声明入口和information_schema注释摘要；不读取业务正文、价格、成交、订单簿、账户或凭据",
            "解除条件": "该成员绑定当前版本九字段、唯一定位、成员/Schema/授权指纹和未撤销事实后追加不可变批次",
            "入口记录SHA-256": "", "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash, "成员记录SHA-256": "",
        }
        row["入口记录SHA-256"] = fp({"来源": row["声明来源"], "定位": row["证据定位"], "声明内容SHA-256": row["声明内容SHA-256"]})
        row["成员记录SHA-256"] = fp(row)
        rows.append(row)
    summary: dict[str, Any] = {"候选成员总体": len(rows), "入口候选总体": sum(int(row["候选入口数"]) for row in rows), "已证明": sum(row["最终身份状态"] == "已证明" for row in rows)}
    per_symbol: dict[str, Any] = {}
    for symbol in TARGETS:
        selected = [row for row in rows if row["标的"] == symbol]
        if len(selected) != 315:
            raise ValueError(f"{symbol}成员分母漂移")
        per_symbol[symbol] = {
            "候选总体": 315,
            "入口候选总体": sum(int(row["候选入口数"]) for row in selected),
            "入口状态计数": {state: sum(row["入口状态"] == state for row in selected) for state in ENTRY_STATES},
            "可定位计数": {state: sum(row["可定位"] == state for row in selected) for state in LOCATABLE_STATES},
            "最终状态计数": {state: sum(row["最终身份状态"] == state for row in selected) for state in FINAL_STATES},
        }
        if sum(per_symbol[symbol]["入口状态计数"].values()) != 315 or sum(per_symbol[symbol]["可定位计数"].values()) != 315 or sum(per_symbol[symbol]["最终状态计数"].values()) != 315:
            raise ValueError("状态计数不守恒")
    summary["分标的"] = per_symbol
    summary["ZS-DATA-GAP-001"] = "继续阻塞；未形成每个BTC、ETH成员的完整当前九字段声明" if summary["已证明"] < 630 else "按精确成员范围复算"
    return rows, summary


def render_csv(rows: Sequence[Mapping[str, str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: engine.safe_csv_cell(row.get(key, "")) for key in OUTPUT_COLUMNS})
    return output.getvalue()


def execute_batch(config_path: Path = CONFIG_PATH, batch_root: Path = DEFAULT_BATCH_ROOT, *, runner: Callable[..., Any] | None = None, now: dt.datetime | None = None) -> Path:
    config = load_config(config_path)
    previous_manifest, members = load_members()
    inventory = load_inventory()
    candidates = load_local_candidates()
    probe = run_probe(build_probe_script(inventory, config), config, runner)
    candidates.extend(item for item in probe["候选"] if isinstance(item, dict))
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    config_hash = sha_path(config_path)
    rules_hash = fp({"合同版本": CONTRACT_VERSION, "探针版本": PROBE_VERSION, "身份字段": list(IDENTITY_FIELDS), "状态": list(FINAL_STATES), "入口状态": list(ENTRY_STATES)})
    executor_hash = sha_path(Path(__file__))
    member_hash = fp(members)
    probe_hash = fp(probe)
    batch_id = "source-identity-entry-discovery-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + fp({"配置": config_hash, "成员": member_hash, "探针": probe_hash})[:12]
    rows, summary = build_rows(members, candidates, batch_id, rules_hash, executor_hash)
    csv_text = render_csv(rows)
    candidate_text = json.dumps(candidates, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    task_path = ROOT / "docs/研发中心/任务/任务-000082.md"
    batch_manifest = {
        "合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "批次": batch_id, "冻结时间": frozen.isoformat(timespec="microseconds"),
        "成员顺序SHA-256": member_hash, "探针SHA-256": probe_hash, "配置SHA-256": config_hash, "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash,
        "任务合同执行时SHA-256": sha_path(task_path),
        "输入": {"任务-000081批次": previous_manifest.get("批次"), "任务-000081批次清单SHA-256": sha_path(FINAL_BATCH / "批次清单.json"), "任务-000081成员清单SHA-256": sha_path(FINAL_CSV), "资产清单SHA-256": sha_path(INVENTORY_PATH), "声明入口输入": [{"路径": rel(path), "SHA-256": sha_path(path)} for path in SOURCE_CONFIGS]},
        "入口白名单": {"SSH目标": list(config["允许SSH目标"]), "根目录": list(config["允许文件根目录"]), "声明文件名": list(config["声明文件名"]), "数据库范围": list(config["数据库元数据范围"]), "数据库注释列": list(config["数据库注释列"])},
        "结果摘要": summary, "安全边界": {key: False for key in SAFETY_KEYS}, "资源上限": dict(config["资源上限"]),
        "输出SHA-256": {"来源身份声明入口发现清单.csv": sha_bytes(csv_text.encode()), "入口候选清单.json": sha_bytes(candidate_text.encode())},
        "结论边界": "描述性入口差异不能推导因果、预测优势、胜率、收益、研究准入或交易许可；不足时保持失败安全并阻塞",
    }
    manifest_text = json.dumps(batch_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if len(csv_text.encode()) + len(candidate_text.encode()) + len(manifest_text.encode()) > int(config["资源上限"]["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=f".{batch_id}-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        csv_path = staging / "来源身份声明入口发现清单.csv"
        candidate_path = staging / "入口候选清单.json"
        manifest_path = staging / "批次清单.json"
        csv_path.write_text(csv_text, encoding="utf-8", newline="")
        candidate_path.write_text(candidate_text, encoding="utf-8")
        manifest_path.write_text(manifest_text, encoding="utf-8")
        engine._scan_outputs([csv_path, candidate_path, manifest_path])
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "批次": batch_id, "路径": rel(target), "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


class SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("命令行参数无效")


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeParser(description="任务-000082来源身份声明入口发现")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    try:
        args = parser.parse_args(argv)
        execute_batch(args.config, args.batch_root)
        return 0
    except (FileExistsError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        print("来源身份入口发现失败：未发布批次", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
