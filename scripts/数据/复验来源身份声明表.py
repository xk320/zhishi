#!/usr/bin/env python3
"""任务-000083：候选来源身份声明 BASE TABLE 的固定列只读复验。"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import re
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.数据 import 冻结数据来源身份 as engine

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = "任务-000083"
CONTRACT_VERSION = "source-identity-table-readonly-1.0"
PROBE_VERSION = "source-identity-table-readonly-probe-1.0"
CONFIG_PATH = ROOT / "config/数据/任务-000083来源身份声明表复验.json"
DEFAULT_BATCH_ROOT = ROOT / "artifacts/数据/来源身份声明表复验"
INVENTORY_PATH = ROOT / "artifacts/审计/数据源清单.csv"
FINAL_BATCH = ROOT / "artifacts/数据/来源身份声明九字段复验/source-identity-nine-fields-20260808T074100+0800-v4"
FINAL_CSV = FINAL_BATCH / "来源身份声明九字段复验清单.csv"
TARGETS = ("BTC", "ETH")
IDENTITY_FIELDS = ("来源提供者", "交易场所", "市场类型", "标的身份", "精确合约", "数据对象", "Schema确切版本", "授权边界", "字段中文映射")
LOGICAL_FIELDS = ("成员编号", "资产编号", "标的", "标的身份", "来源提供者", "交易场所", "市场类型", "精确合约", "数据对象", "Schema确切版本", "授权边界", "字段中文映射", "任务合同版本", "采集时间", "声明内容指纹", "成员输入指纹", "Schema指纹", "授权指纹", "可撤销事实或撤销时间", "声明版本或生效版本")
# 探针读取的声明字段必须与配置冻结的20个逻辑字段完全一致；“证据定位”
# 是探针根据表名和成员编号追加的脱敏定位元数据，不属于数据库读取列。
DECLARATION_FIELDS = frozenset((*LOGICAL_FIELDS, "证据定位"))
FINAL_STATES = ("已证明", "拒绝", "无法判定", "失败", "未成熟", "失效")
ENTRY_STATES = ("未登记", "入口不完整", "已登记")
LOCATABLE_STATES = ("已定位", "不可定位")
SAFETY_KEYS = ("远端写入", "远端临时文件", "数据库业务记录读取", "读取环境变量或凭据", "读取价格成交订单簿", "原始业务记录落盘", "修改原始数据", "修改生产系统", "权限或DDL变更")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MISSING_VALUES = frozenset({"", "未知", "NULL", "null", "\\N"})
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
SAFE_COLUMN = re.compile(r"^[A-Za-z0-9_]+$|^[\u4e00-\u9fffA-Za-z0-9_]+$")
FIELD_ALIASES = {
    "成员编号": ("member_id", "member_no", "成员编号", "成员ID"),
    "资产编号": ("asset_id", "asset_no", "资产编号"),
    "标的": ("target", "asset", "symbol_target", "标的"),
    "标的身份": ("symbol", "asset_symbol", "instrument_symbol", "标的身份"),
    "来源提供者": ("source_provider", "provider", "来源提供者"),
    "交易场所": ("venue", "exchange", "交易场所"),
    "市场类型": ("market_type", "market", "市场类型"),
    "精确合约": ("contract", "instrument", "精确合约"),
    "数据对象": ("data_object", "dataset", "数据对象"),
    "Schema确切版本": ("schema_version", "schema_revision", "Schema确切版本"),
    "授权边界": ("authorization_scope", "access_scope", "授权边界"),
    "字段中文映射": ("field_mapping", "column_mapping", "字段中文映射"),
    "任务合同版本": ("contract_version", "task_contract_version", "任务合同版本"),
    "采集时间": ("collected_at", "collection_time", "collected_time", "采集时间"),
    "声明内容指纹": ("declaration_sha256", "content_sha256", "声明内容SHA-256", "声明内容指纹"),
    "成员输入指纹": ("member_sha256", "member_input_sha256", "输入成员SHA-256", "成员输入指纹"),
    "Schema指纹": ("schema_sha256", "schema_fingerprint", "Schema指纹"),
    "授权指纹": ("authorization_sha256", "authorization_fingerprint", "授权快照SHA-256", "授权指纹"),
    "可撤销事实或撤销时间": ("revoked_at", "revocation_fact", "撤销事实", "撤销时间"),
    "声明版本或生效版本": ("declaration_version", "version", "声明版本"),
}
OUTPUT_COLUMNS = ("批次", "成员编号", "资产编号", "标的", "入口状态", "可定位", "候选入口数", "九字段状态", "最终身份状态", *IDENTITY_FIELDS, "任务合同版本", "采集时间", "声明版本", "声明来源", "证据定位", "声明内容SHA-256", "输入成员SHA-256", "Schema指纹", "授权快照SHA-256", "撤销事实", "原因代码", "缺失字段", "限制", "解除条件", "入口记录SHA-256", "规则SHA-256", "执行器SHA-256", "成员记录SHA-256")


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fp(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def sha_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return f"<temporary>/{path.name}"


def sensitive(value: object) -> bool:
    return engine._contains_sensitive(canonical(value))


def is_missing(value: object) -> bool:
    return value is None or str(value).strip() in MISSING_VALUES


def load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label}必须是仓库内普通文件")
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
    raw = load_json(path, "任务-000083配置")
    expected = {"合同版本", "任务编号", "允许SSH目标", "允许对象类型", "数据库元数据范围", "数据库元数据列", "标的", "主研究尺度", "事后结果观察窗口", "逻辑字段顺序", "字段别名", "候选筛选", "输入文件", "安全边界", "资源上限"}
    if set(raw) != expected or raw["合同版本"] != CONTRACT_VERSION or raw["任务编号"] != TASK_ID:
        raise ValueError("任务配置字段或合同版本漂移")
    if raw["允许SSH目标"] != ["ubuntu"] or raw["允许对象类型"] != ["BASE TABLE"] or raw["标的"] != list(TARGETS):
        raise ValueError("SSH、对象类型或标的白名单漂移")
    if raw["数据库元数据范围"] != ["information_schema.TABLES", "information_schema.COLUMNS"] or raw["数据库元数据列"] != ["TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE", "COLUMN_NAME", "COLUMN_TYPE", "ORDINAL_POSITION"]:
        raise ValueError("数据库元数据边界漂移")
    if raw["主研究尺度"] != ["4小时", "8小时", "24小时", "48小时"] or raw["事后结果观察窗口"] != ["15分钟", "1小时"]:
        raise ValueError("研究尺度漂移")
    if raw["逻辑字段顺序"] != list(LOGICAL_FIELDS) or raw["字段别名"] != {key: list(value) for key, value in FIELD_ALIASES.items()}:
        raise ValueError("字段顺序或别名白名单漂移")
    if raw["候选筛选"] != {"对象类型必须精确匹配": True, "每个逻辑字段必须唯一匹配": True, "未知物理列拒绝": True, "别名冲突拒绝": True, "视图定义读取": False, "底层业务列读取": False}:
        raise ValueError("候选筛选规则漂移")
    if set(raw["安全边界"]) != set(SAFETY_KEYS) or any(raw["安全边界"][key] is not False for key in SAFETY_KEYS):
        raise ValueError("安全边界必须全部为false")
    resource_keys = {"批次总超时秒", "逐成员超时秒", "最大成员数", "最大候选行数", "最大输出字节数", "最大日志字节数", "单行最大字节数"}
    if set(raw["资源上限"]) != resource_keys or raw["资源上限"]["最大成员数"] != 630 or raw["资源上限"]["最大候选行数"] != 630 or raw["资源上限"]["单行最大字节数"] != 65536:
        raise ValueError("资源上限漂移")
    seen: set[str] = set()
    for item in raw["输入文件"]:
        if not isinstance(item, dict) or set(item) != {"用途", "路径", "SHA-256"} or item["路径"] in seen:
            raise ValueError("输入文件合同不完整")
        seen.add(item["路径"])
        if sha_path(resolve_input(str(item["路径"]))) != item["SHA-256"]:
            raise ValueError(f"输入指纹漂移：{item['路径']}")
    return raw


def load_members() -> list[dict[str, str]]:
    if not FINAL_CSV.is_file():
        raise ValueError("任务-000081最终成员清单缺失")
    with FINAL_CSV.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    required = {"成员编号", "资产编号", "标的", "最终身份状态", "输入成员SHA-256"}
    if len(rows) != 630 or not rows or not required.issubset(rows[0]):
        raise ValueError("成员分母或字段漂移")
    ordered = sorted(rows, key=lambda row: (row["标的"], row["资产编号"], row["成员编号"]))
    if rows != ordered or len({row["成员编号"] for row in rows}) != 630 or len({row["资产编号"] for row in rows}) != 315 or {row["标的"] for row in rows} != set(TARGETS):
        raise ValueError("成员顺序、唯一性或标的漂移")
    if any(row["最终身份状态"] not in FINAL_STATES for row in rows):
        raise ValueError("历史最终状态非法")
    return rows


def load_inventory() -> list[dict[str, str]]:
    with INVENTORY_PATH.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    selected = sorted((row for row in rows if row.get("资产类型") == "数据库元数据"), key=lambda row: row["资产编号"])
    if len(selected) != 92 or len({row["资产编号"] for row in selected}) != 92:
        raise ValueError("数据库候选资产总体漂移")
    return selected


def sql_literal(value: str) -> str:
    if not SAFE_NAME.fullmatch(value):
        raise ValueError("SQL值越界")
    return "'" + value.replace("'", "''") + "'"


def sql_identifier(value: str) -> str:
    if not SAFE_COLUMN.fullmatch(value):
        raise ValueError("SQL列名越界")
    return "`" + value.replace("`", "``") + "`"


def build_probe_script(members: Sequence[Mapping[str, str]], inventory: Sequence[Mapping[str, str]], config: Mapping[str, Any]) -> str:
    assets = []
    pairs: list[tuple[str, str]] = []
    for asset in inventory:
        parts = str(asset["位置"]).split("/")
        if len(parts) != 3 or parts[0] != "MySQL" or not SAFE_NAME.fullmatch(parts[1]) or not SAFE_NAME.fullmatch(parts[2]):
            raise ValueError("数据库资产位置越界")
        assets.append({"资产编号": str(asset["资产编号"]), "标的": str(next((row["标的"] for row in members if row["资产编号"] == asset["资产编号"]), "未知")), "Schema": parts[1], "Table": parts[2]})
        pairs.append((parts[1], parts[2]))
    where = " OR ".join(f"(t.TABLE_SCHEMA={sql_literal(schema)} AND t.TABLE_NAME={sql_literal(table)})" for schema, table in pairs) or "1=0"
    metadata_sql = "SELECT t.TABLE_SCHEMA,t.TABLE_NAME,t.TABLE_TYPE,c.COLUMN_NAME,c.COLUMN_TYPE,COALESCE(c.ORDINAL_POSITION,'') FROM information_schema.TABLES t JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME WHERE " + where + " ORDER BY t.TABLE_SCHEMA,t.TABLE_NAME,c.ORDINAL_POSITION"
    assets_json = json.dumps(assets, ensure_ascii=False, sort_keys=True)
    members_json = json.dumps([{"成员编号": row["成员编号"], "资产编号": row["资产编号"], "标的": row["标的"], "输入成员SHA-256": row["输入成员SHA-256"]} for row in members], ensure_ascii=False, sort_keys=True)
    aliases_json = json.dumps({key: list(value) for key, value in FIELD_ALIASES.items()}, ensure_ascii=False, sort_keys=True)
    fields_json = json.dumps(list(LOGICAL_FIELDS), ensure_ascii=False)
    return textwrap.dedent(f"""\
        import hashlib, json, re, subprocess
        ASSETS = json.loads({assets_json!r})
        MEMBERS = json.loads({members_json!r})
        ALIASES = json.loads({aliases_json!r})
        FIELDS = json.loads({fields_json!r})
        SQL = {metadata_sql!r}
        PROBE_VERSION = {PROBE_VERSION!r}
        MAX_ROW = 65536
        SAFE = re.compile(r"(?i)(?:password|passwd|pwd|secret|token)\\s*[:=]|-----BEGIN|\\b(?:gh[pousr]_\\w{{20,}}|AKIA[A-Z0-9]{{16}})\\b|\\b[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9_.-]+\\b|(?<![\\d.])(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){{3}}(?![\\d.])")
        def fp(value):
            return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        def identifier(value):
            if not re.fullmatch(r"^[A-Za-z0-9_]+$|^[\\u4e00-\\u9fffA-Za-z0-9_]+$", value):
                raise ValueError("identifier")
            return "`" + value.replace("`", "``") + "`"
        def literal(value):
            if not re.fullmatch(r"^[A-Za-z0-9_.-]+$", value):
                raise ValueError("literal")
            return "'" + value.replace("'", "''") + "'"
        def safe(value):
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            return not SAFE.search(text)
        groups = {{}}
        results = [{{"资产编号": item["资产编号"], "表": "MySQL/" + item["Schema"] + "/" + item["Table"], "状态": "元数据未复验", "候选": False}} for item in ASSETS]
        candidates = []
        env = {{"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}}
        try:
            completed = subprocess.run(["mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names", "--binary-mode", "--protocol=SOCKET", "--connect-timeout=3", "-e", SQL], capture_output=True, text=True, timeout=5, env=env, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("元数据探针执行失败") from error
        if completed.returncode != 0 or len(completed.stdout.encode("utf-8", "replace")) > 8388608 or len(completed.stderr.encode("utf-8", "replace")) > 32768:
            raise RuntimeError("元数据探针返回失败")
        for line in completed.stdout.splitlines():
            fields = line.split("\\t")
            if len(fields) != 6:
                raise RuntimeError("元数据探针行结构非法")
            schema, table, table_type, column, column_type, ordinal = fields
            if not re.fullmatch(r"^[A-Za-z0-9_.-]+$", schema) or not re.fullmatch(r"^[A-Za-z0-9_.-]+$", table):
                raise RuntimeError("元数据探针标识非法")
            groups.setdefault((schema, table), {{"类型": table_type, "列": []}})["列"].append({{"名称": column, "类型": column_type, "顺序": ordinal}})
        member_index = {{row["成员编号"]: row for row in MEMBERS}}
        for (schema, table), info in sorted(groups.items()):
            columns = info["列"]
            names = [item["名称"] for item in columns]
            if info["类型"] != "BASE TABLE" or len(names) != len(set(names)):
                continue
            mapping = {{}}
            invalid = False
            for logical in FIELDS:
                matched = [name for name in names if name in ALIASES[logical]]
                if len(matched) != 1:
                    invalid = True
                    break
                mapping[logical] = matched[0]
            if invalid or len(set(mapping.values())) != len(mapping) or set(names) != set(mapping.values()):
                continue
            ordered_columns = sorted(columns, key=lambda item: int(item["顺序"]) if str(item["顺序"]).isdigit() else 0)
            schema_fp = fp({{"TABLE_SCHEMA": schema, "TABLE_NAME": table, "TABLE_TYPE": info["类型"], "COLUMNS": ordered_columns}})
            candidate_table = {{"表": "MySQL/" + schema + "/" + table, "对象类型": info["类型"], "字段映射": mapping, "Schema指纹": schema_fp}}
            table_entry = {{"表": candidate_table["表"], "对象类型": candidate_table["对象类型"], "字段映射": mapping, "Schema指纹": schema_fp, "候选行数": 0}}
            candidates.append(table_entry)
            ids = ",".join(literal(row["成员编号"]) for row in MEMBERS)
            select_sql = ",".join(identifier(mapping[field]) for field in FIELDS)
            query = "SELECT " + select_sql + " FROM " + identifier(schema) + "." + identifier(table) + " WHERE " + identifier(mapping["成员编号"]) + " IN (" + ids + ") ORDER BY " + identifier(mapping["成员编号"]) + " LIMIT 631"
            try:
                completed = subprocess.run(["mysql", "--no-defaults", "--batch", "--raw", "--skip-column-names", "--binary-mode", "--protocol=SOCKET", "--connect-timeout=3", "-e", query], capture_output=True, text=True, timeout=5, env=env, check=False)
                if completed.returncode != 0 or len(completed.stdout.encode("utf-8", "replace")) > 8388608 or len(completed.stderr.encode("utf-8", "replace")) > 32768:
                    raise RuntimeError("候选声明列探针返回失败")
                observed_rows = 0
                for line in completed.stdout.splitlines():
                    if len(line.encode("utf-8", "replace")) > MAX_ROW:
                        raise RuntimeError("候选声明行超出上限")
                    values = line.split("\\t")
                    if len(values) != len(FIELDS):
                        raise RuntimeError("候选声明行字段数非法")
                    observed_rows += 1
                    if observed_rows > 630:
                        raise RuntimeError("候选声明行超过630条上限")
                    declaration = {{field: values[index] for index, field in enumerate(FIELDS)}}
                    member_id = declaration["成员编号"]
                    if member_id not in member_index or not safe(declaration):
                        continue
                    location = "MySQL/" + schema + "/" + table + "#成员编号=" + member_id
                    declaration["证据定位"] = location
                    if not safe(declaration):
                        continue
                    table_entry["候选行数"] += 1
                    candidates.append({{"来源类型": "数据库候选BASE TABLE", "证据定位": location, "入口内容SHA-256": fp({{"表": candidate_table["表"], "Schema指纹": schema_fp}}), "候选Schema指纹": schema_fp, "声明": declaration}})
            except (OSError, subprocess.SubprocessError) as error:
                raise RuntimeError("候选声明列探针执行失败") from error
        table_rows = [item for item in candidates if "声明" not in item]
        rows = [item for item in candidates if "声明" in item]
        for result in results:
            result["状态"] = "元数据已读取" if any(key == tuple(result["表"].split("/", 2)[1:]) for key in groups) else "元数据未发现"
            result["候选"] = any(item["表"] == result["表"] and "声明" not in item for item in candidates)
        print(json.dumps({{"探针版本": PROBE_VERSION, "远端写入": False, "远端临时文件": False, "数据库业务记录读取": False, "读取环境变量或凭据": False, "读取价格成交订单簿": False, "原始业务记录落盘": False, "修改原始数据": False, "修改生产系统": False, "权限或DDL变更": False, "结果": results, "候选表": table_rows, "候选行": rows}}, ensure_ascii=False, sort_keys=True))
    """)


def run_probe(script: str, config: Mapping[str, Any], runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    command = engine.build_ssh_command("ssh", "ubuntu", int(config["资源上限"]["批次总超时秒"]))
    if runner:
        completed = runner(command, input=script, capture_output=True, text=True, timeout=int(config["资源上限"]["批次总超时秒"]), check=False)
    else:
        completed = engine.run_bounded_process(command, input_text=script, timeout=int(config["资源上限"]["批次总超时秒"]), maximum_stdout=int(config["资源上限"]["最大输出字节数"]), maximum_stderr=int(config["资源上限"]["最大日志字节数"]))
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if completed.returncode != 0 or len(stdout.encode("utf-8", "replace")) > int(config["资源上限"]["最大输出字节数"]):
        raise RuntimeError("来源身份声明表探针失败或输出超限")
    payload = json.loads(stdout)
    required = {"探针版本", *SAFETY_KEYS, "结果", "候选表", "候选行"}
    if set(payload) != required or payload["探针版本"] != PROBE_VERSION or any(payload[key] is not False for key in SAFETY_KEYS):
        raise ValueError("探针响应越过安全边界")
    if not isinstance(payload["结果"], list) or len(payload["结果"]) != 92 or len({item.get("资产编号") for item in payload["结果"]}) != 92:
        raise ValueError("探针未覆盖92个数据库资产")
    for key in ("候选表", "候选行"):
        if not isinstance(payload[key], list) or len(payload[key]) > int(config["资源上限"]["最大候选行数"]):
            raise ValueError("探针候选超过固定上限")
    if sensitive(payload):
        raise ValueError("探针响应包含敏感内容")
    allowed_tables = {
        "MySQL/" + str(asset["位置"])[len("MySQL/") :]
        for asset in load_inventory()
        if str(asset.get("位置", "")).startswith("MySQL/")
    }
    candidate_tables: dict[str, Mapping[str, Any]] = {}
    for item in payload["候选表"]:
        if set(item) != {"表", "对象类型", "字段映射", "Schema指纹", "候选行数"} or item["对象类型"] != "BASE TABLE" or not SHA256.fullmatch(str(item["Schema指纹"])):
            raise ValueError("候选表结构非法")
        if item["表"] not in allowed_tables or not isinstance(item["字段映射"], dict):
            raise ValueError("候选表未在资产清单或字段映射非法")
        if item["字段映射"] != {key: item["字段映射"].get(key) for key in LOGICAL_FIELDS} or len(set(item["字段映射"].values())) != len(LOGICAL_FIELDS):
            raise ValueError("候选字段映射非法")
        for logical, physical in item["字段映射"].items():
            if physical not in FIELD_ALIASES[logical]:
                raise ValueError("候选字段映射越过别名白名单")
        candidate_tables[str(item["表"])] = item
    for item in payload["候选行"]:
        if set(item) != {"来源类型", "证据定位", "入口内容SHA-256", "候选Schema指纹", "声明"} or not isinstance(item["声明"], dict) or set(item["声明"]) != DECLARATION_FIELDS:
            raise ValueError("候选行结构非法")
        location = str(item["证据定位"])
        table_path, separator, _ = location.partition("#成员编号=")
        table = candidate_tables.get(table_path)
        if not separator or table is None or item["候选Schema指纹"] != table["Schema指纹"]:
            raise ValueError("候选行定位或Schema绑定非法")
        expected_entry_hash = fp({"表": table_path, "Schema指纹": table["Schema指纹"]})
        if item["入口内容SHA-256"] != expected_entry_hash:
            raise ValueError("候选行入口指纹绑定非法")
    return payload


def matching(candidates: Sequence[Mapping[str, Any]], row: Mapping[str, str]) -> list[dict[str, Any]]:
    return sorted([dict(item) for item in candidates if item.get("声明", {}).get("成员编号") == row["成员编号"] and item.get("声明", {}).get("资产编号") == row["资产编号"] and item.get("声明", {}).get("标的") == row["标的"]], key=lambda item: str(item.get("证据定位", "")))


def complete(candidate: Mapping[str, Any], row: Mapping[str, str], batch_start: dt.datetime) -> tuple[bool, list[str]]:
    declaration = candidate.get("声明", {})
    missing: list[str] = []
    if set(declaration) != DECLARATION_FIELDS:
        missing.extend(f"声明字段漂移:{field}" for field in sorted(set(declaration) ^ DECLARATION_FIELDS))
    if not SHA256.fullmatch(str(candidate.get("入口内容SHA-256", ""))) or not SHA256.fullmatch(str(candidate.get("候选Schema指纹", ""))):
        missing.append("候选指纹")
    if declaration.get("证据定位") != candidate.get("证据定位"):
        missing.append("证据定位绑定")
    if declaration.get("任务合同版本") != CONTRACT_VERSION:
        missing.append("任务合同版本")
    try:
        collection_time = dt.datetime.fromisoformat(str(declaration.get("采集时间", "")))
        if collection_time.tzinfo is None or collection_time.utcoffset() is None or collection_time > batch_start:
            missing.append("采集时间")
    except (TypeError, ValueError):
        missing.append("采集时间")
    for field in (*LOGICAL_FIELDS, "证据定位"):
        if is_missing(declaration.get(field)):
            missing.append(field)
    for field in ("成员输入指纹", "声明内容指纹", "Schema指纹", "授权指纹"):
        if not SHA256.fullmatch(str(declaration.get(field, ""))):
            missing.append(field)
    if declaration.get("成员编号") != row["成员编号"] or declaration.get("资产编号") != row["资产编号"] or declaration.get("标的") != row["标的"] or declaration.get("成员输入指纹") != row["输入成员SHA-256"]:
        missing.append("成员绑定")
    if is_missing(declaration.get("可撤销事实或撤销时间")):
        missing.append("可撤销事实或撤销时间")
    if declaration.get("Schema指纹") != candidate.get("候选Schema指纹"):
        missing.append("Schema指纹绑定")
    content = {
        key: value
        for key, value in declaration.items()
        if key not in {"声明内容指纹", "证据定位"}
    }
    if declaration.get("声明内容指纹") != fp(content):
        missing.append("声明内容指纹")
    return not missing, sorted(set(missing))


def evaluate_member(row: Mapping[str, str], candidates: Sequence[Mapping[str, Any]], batch_start: dt.datetime) -> dict[str, Any]:
    matches = matching(candidates, row)
    prior = row.get("最终身份状态", "无法判定")
    if not matches:
        return {"入口状态": "未登记", "可定位": "不可定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": 0, "原因代码": "IDENTITY_TABLE_ROW_MISSING", "缺失字段": ";".join((*IDENTITY_FIELDS, "资产编号", "标的", "采集时间")), "声明来源": "未登记", "证据定位": "未登记", "声明": {}}
    complete_items: list[dict[str, Any]] = []
    missing: list[str] = []
    for item in matches:
        ok, fields = complete(item, row, batch_start)
        if ok:
            complete_items.append(item)
        else:
            missing.extend(fields)
    if len(complete_items) > 1:
        item = complete_items[0]
        return {"入口状态": "已登记", "可定位": "已定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": len(matches), "原因代码": "IDENTITY_TABLE_ROW_CONFLICT", "缺失字段": "声明冲突", "声明来源": item["来源类型"], "证据定位": item["证据定位"], "声明": item["声明"]}
    if not complete_items:
        item = matches[0]
        return {"入口状态": "入口不完整", "可定位": "已定位", "九字段状态": "无法判定", "最终身份状态": prior, "候选入口数": len(matches), "原因代码": "IDENTITY_TABLE_ROW_INCOMPLETE", "缺失字段": ";".join(sorted(set(missing))), "声明来源": item["来源类型"], "证据定位": item["证据定位"], "声明": item["声明"]}
    item = complete_items[0]
    state = prior if prior != "无法判定" else "已证明"
    reason = "PRIOR_TERMINAL_STATE_PRESERVED" if prior != "无法判定" else "IDENTITY_TABLE_ROW_MATCHED"
    return {"入口状态": "已登记", "可定位": "已定位", "九字段状态": "已证明", "最终身份状态": state, "候选入口数": len(matches), "原因代码": reason, "缺失字段": "", "声明来源": item["来源类型"], "证据定位": item["证据定位"], "声明": item["声明"]}


def build_rows(members: Sequence[Mapping[str, str]], candidates: Sequence[Mapping[str, Any]], batch_id: str, rules_hash: str, executor_hash: str, batch_start: dt.datetime) -> tuple[list[dict[str, str]], dict[str, Any]]:
    rows: list[dict[str, str]] = []
    for member in members:
        result = evaluate_member(member, candidates, batch_start)
        declaration = result.pop("声明")
        row: dict[str, str] = {"批次": batch_id, "成员编号": member["成员编号"], "资产编号": member["资产编号"], "标的": member["标的"], "入口状态": str(result["入口状态"]), "可定位": str(result["可定位"]), "候选入口数": str(result["候选入口数"]), "九字段状态": str(result["九字段状态"]), "最终身份状态": str(result["最终身份状态"]), **{field: str(declaration.get(field, "未知")) for field in IDENTITY_FIELDS}, "任务合同版本": str(declaration.get("任务合同版本", "未知")), "采集时间": str(declaration.get("采集时间", "未知")), "声明版本": str(declaration.get("声明版本或生效版本", "未知")), "声明来源": str(result["声明来源"]), "证据定位": str(result["证据定位"]), "声明内容SHA-256": str(declaration.get("声明内容指纹", "未知")), "输入成员SHA-256": str(declaration.get("成员输入指纹", member["输入成员SHA-256"])), "Schema指纹": str(declaration.get("Schema指纹", "未知")), "授权快照SHA-256": str(declaration.get("授权指纹", "未知")), "撤销事实": str(declaration.get("可撤销事实或撤销时间", "未复验")), "原因代码": str(result["原因代码"]), "缺失字段": str(result["缺失字段"]), "限制": "只读取information_schema和严格20列声明白名单；不读取业务正文、价格、成交、订单簿、账户或凭据", "解除条件": "该成员绑定当前版本九字段、资产/标的、唯一定位、成员/Schema/授权指纹、带时区采集时间和未撤销事实后追加不可变批次", "入口记录SHA-256": "", "规则SHA-256": rules_hash, "执行器SHA-256": executor_hash, "成员记录SHA-256": ""}
        row["入口记录SHA-256"] = fp({"来源": row["声明来源"], "定位": row["证据定位"], "声明内容SHA-256": row["声明内容SHA-256"]})
        row["成员记录SHA-256"] = fp(row)
        rows.append(row)
    final_counts = {state: sum(row["最终身份状态"] == state for row in rows) for state in FINAL_STATES}
    summary: dict[str, Any] = {
        "候选成员总体": len(rows),
        "候选总体": len(rows),
        "分母": len(rows),
        "已观察": sum(row["可定位"] == "已定位" for row in rows),
        "已观察口径": "存在可定位的严格候选声明行",
        **final_counts,
        "已证明": final_counts["已证明"],
        "入口候选总体": sum(int(row["候选入口数"]) for row in rows),
        "最终状态计数": final_counts,
    }
    per_symbol: dict[str, Any] = {}
    for symbol in TARGETS:
        selected = [row for row in rows if row["标的"] == symbol]
        if len(selected) != 315:
            raise ValueError(f"{symbol}成员分母漂移")
        symbol_final_counts = {state: sum(row["最终身份状态"] == state for row in selected) for state in FINAL_STATES}
        per_symbol[symbol] = {
            "候选总体": len(selected),
            "分母": len(selected),
            "已观察": sum(row["可定位"] == "已定位" for row in selected),
            "已观察口径": "存在可定位的严格候选声明行",
            **symbol_final_counts,
            "入口候选总体": sum(int(row["候选入口数"]) for row in selected),
            "入口状态计数": {state: sum(row["入口状态"] == state for row in selected) for state in ENTRY_STATES},
            "可定位计数": {state: sum(row["可定位"] == state for row in selected) for state in LOCATABLE_STATES},
            "最终状态计数": symbol_final_counts,
        }
        if any(sum(per_symbol[symbol][key].values()) != 315 for key in ("入口状态计数", "可定位计数", "最终状态计数")):
            raise ValueError("状态计数不守恒")
        if per_symbol[symbol]["分母"] != 315 or per_symbol[symbol]["已观察"] > per_symbol[symbol]["分母"] or any(per_symbol[symbol][state] < 0 for state in FINAL_STATES):
            raise ValueError("候选总体、分母或已观察计数非法")
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
    members = load_members()
    inventory = load_inventory()
    task_path = ROOT / "docs/研发中心/任务/任务-000083.md"
    executor_path = Path(__file__)
    frozen_task_hash = sha_path(task_path)
    frozen_executor_hash = sha_path(executor_path)
    frozen = now or dt.datetime.now().astimezone()
    if frozen.tzinfo is None or frozen.utcoffset() is None:
        raise ValueError("冻结时间必须带时区")
    probe = run_probe(build_probe_script(members, inventory, config), config, runner)
    if sha_path(task_path) != frozen_task_hash or sha_path(executor_path) != frozen_executor_hash:
        raise RuntimeError("执行期间任务合同或执行器发生漂移")
    config_hash = sha_path(config_path)
    rules_hash = fp({"合同版本": CONTRACT_VERSION, "探针版本": PROBE_VERSION, "逻辑字段顺序": list(LOGICAL_FIELDS), "字段别名": config["字段别名"], "状态": list(FINAL_STATES)})
    member_hash = fp(members)
    probe_hash = fp(probe)
    batch_id = "source-identity-table-readonly-" + frozen.strftime("%Y%m%dT%H%M%S%z") + "-" + fp({"配置": config_hash, "成员": member_hash, "探针": probe_hash})[:12]
    rows, summary = build_rows(members, probe["候选行"], batch_id, rules_hash, frozen_executor_hash, frozen)
    csv_text = render_csv(rows)
    table_text = json.dumps(probe["候选表"], ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    manifest = {"合同版本": CONTRACT_VERSION, "任务编号": TASK_ID, "批次": batch_id, "冻结时间": frozen.isoformat(timespec="microseconds"), "成员顺序SHA-256": member_hash, "探针SHA-256": probe_hash, "配置SHA-256": config_hash, "规则SHA-256": rules_hash, "执行器SHA-256": frozen_executor_hash, "任务合同执行时SHA-256": frozen_task_hash, "输入": {"任务-000081批次清单SHA-256": sha_path(FINAL_BATCH / "批次清单.json"), "任务-000081成员清单SHA-256": sha_path(FINAL_CSV), "资产清单SHA-256": sha_path(INVENTORY_PATH), "任务-000082配置SHA-256": sha_path(ROOT / "config/数据/任务-000082来源身份入口复验.json")}, "候选表": probe["候选表"], "结果摘要": summary, "安全边界": {key: False for key in SAFETY_KEYS}, "资源上限": dict(config["资源上限"]), "输出SHA-256": {"来源身份声明表复验清单.csv": hashlib.sha256(csv_text.encode("utf-8")).hexdigest(), "候选表清单.json": hashlib.sha256(table_text.encode("utf-8")).hexdigest()}, "结论边界": "本批次只表达来源身份证据状态；描述性差异不能推导因果、预测优势、胜率、收益、研究准入或交易许可。"}
    manifest_text = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if len(csv_text.encode()) + len(table_text.encode()) + len(manifest_text.encode()) > int(config["资源上限"]["最大输出字节数"]):
        raise ValueError("批次输出超过资源上限")
    batch_root.mkdir(parents=True, exist_ok=True)
    target = batch_root / batch_id
    if target.exists() or target.is_symlink():
        raise FileExistsError("不可变批次已存在")
    with tempfile.TemporaryDirectory(prefix=f".{batch_id}-", dir=batch_root) as directory:
        staging = Path(directory) / "batch"
        staging.mkdir()
        (staging / "来源身份声明表复验清单.csv").write_text(csv_text, encoding="utf-8", newline="")
        (staging / "候选表清单.json").write_text(table_text, encoding="utf-8")
        (staging / "批次清单.json").write_text(manifest_text, encoding="utf-8")
        engine._scan_outputs(list(staging.iterdir()))
        engine.atomic_publish_directory_no_replace(staging, target)
    print(json.dumps({"状态": "成功", "批次": batch_id, "路径": rel(target), "结果摘要": summary}, ensure_ascii=False, sort_keys=True))
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="任务-000083来源身份声明表只读复验")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--batch-root", type=Path, default=DEFAULT_BATCH_ROOT)
    args = parser.parse_args(argv)
    try:
        execute_batch(args.config, args.batch_root)
    except Exception as error:
        print(f"任务-000083执行失败：{type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
