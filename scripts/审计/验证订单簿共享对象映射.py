#!/usr/bin/env python3
"""验证任务-000071的订单簿共享表元数据批次。

本验证器只处理结构指纹、计数和状态，不读取或输出列值、业务正文、连接串或凭据。
远端固定入口只负责读取 information_schema；源代码合同在本地冻结并与批次绑定。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
SOURCE_DEFAULT = Path("/Users/luweiming/Documents/Project/code/orderbook-intelligence-service-release-20260731/src/orderbook_service/storage.py")
SOURCE_COMMIT = "030499faca3d6955d75c75cbc59656a4981f6c05"
SOURCE_FILE = "src/orderbook_service/storage.py"
SOURCE_SHA256 = "d4fed7bf0fc89666a9836a17f144ef41d2a6d13d829124437032c9787bf9b05d"
PROTOCOL = "zhishi-ro/schema-audit/1"
CONTRACT_VERSION = "task-000071"
MATRIX_FINGERPRINT = "6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79"
FROZEN_DATA_CUTOFF = "2026-08-06T12:00:00+08:00"
REMOTE_USER = "zhishi_ro"
REMOTE_HOST = "ubuntu"
REMOTE_ENTRY = "/usr/local/libexec/zhishi_ro_schema_audit.py"
RESOURCE_CONTRACT = {
    "单对象字节": 65536,
    "单对象秒": 30,
    "批次秒": 300,
    "批次输出字节": 4194304,
    "最大并发": 1,
    "最大内存字节": 268435456,
    "远端临时写入": False,
}
RESOURCE_CONTRACT_FINGERPRINT = "e1848916ced2bc3343ca0bda53e985add32070630c3ece8af317ac62e631e8b4"
TARGETS = [
    {"资产编号": f"DS-{278 + i:06d}", "数据库": "orderbook", "表": table}
    for i, table in enumerate(
        [
            "historical_backfill_files",
            "order_book_decision_context_snapshots",
            "order_book_feature_buckets",
            "order_book_health_events",
            "order_book_liquidation_events",
            "order_book_liquidation_heatmap_buckets",
            "order_book_market_structure_snapshots",
            "order_book_micro_events",
            "order_book_open_interest",
            "order_book_public_context_snapshots",
            "order_book_raw_snapshots",
            "order_book_risk_states",
            "order_book_signal_delivery_acks",
            "order_book_signals",
            "raw_input_log",
            "symbol_metadata",
        ]
    )
]
TARGET_MANIFEST = {"对象": TARGETS, "覆盖矩阵指纹": MATRIX_FINGERPRINT}
TARGET_MANIFEST_FINGERPRINT = "8ba1b762c7739efd45a53b48f861d848cba21c2dea3f584093a28c071e4cc7e9"
SOURCE_ONLY_CANDIDATES = {
    "order_book_derived_state_revisions": "无任务-000063资产编号，不进入远端查询",
}

# 列指纹为 name:type:ordinal，索引指纹为 index_name:seq_in_index:column。
# 这些指纹由冻结 storage.py 的确定性解析复算；不能用远端名称相似性补齐。
SCHEMA_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "order_book_feature_buckets": {"列数": 8, "列指纹": "4118ff7abbeba3cfb7465ddfd18126ac42db9cd4266f82d6a1446a3414cb4d4d", "索引数": 10, "索引指纹": "981ce7d27c314410c21a713bc8411f7ad711f64dbd5a0915cef961e4fa92f3b9"},
    "order_book_micro_events": {"列数": 7, "列指纹": "b01052fd952a56611e16685334b1c56dfa3509ae4c244f13c026623de2dd5c07", "索引数": 3, "索引指纹": "d9a1eb8b790577e8dc9193af990497d77c2c059c35a78e0331d4fbb8f3741e62"},
    "order_book_signals": {"列数": 9, "列指纹": "c996bafeb419948e766f8d5bdd341cdebcf58c9e6bf9ee3698d154590df6f4fb", "索引数": 6, "索引指纹": "499ec816217406b68fa8d2f1d6fc2cb8614d7dd2fe4a506c790ab29231ee0a69"},
    "raw_input_log": {"列数": 28, "列指纹": "3452feb46eccebe3daf3f27013f60f76d8475682bc708ca5686c5d408efe6d5d", "索引数": 13, "索引指纹": "4e168a875671f15a1dbf70ec56dad67589aa290438be2da13a5d5ae9ac9b3cf9"},
    "symbol_metadata": {"列数": 24, "列指纹": "1bfe505c6709ecf3db5dcdaac8566d5ce1abf815878d2d33a93495e99b9a4f89", "索引数": 3, "索引指纹": "5914a40b8fcac61977d49b12ddd67cc78064cb77fd12f697fe6d6336201d66a8"},
    "order_book_risk_states": {"列数": 8, "列指纹": "56736f58e9a26e1540ffca6aa678ef1d864a9d5585266054cf96805af14c4633", "索引数": 2, "索引指纹": "638dcf2aca57af23cddee60f44a2f4b82f18684f781a384f31d20162babda249"},
    "order_book_health_events": {"列数": 9, "列指纹": "437301f9150eba549f969d1fb87ac830dbc6b6e778178f7e2cfb4db6e68c5d33", "索引数": 2, "索引指纹": "3fd911bb87461c3ed06557e475af14b2c471cf4805c6e4ff4cc001fab03db8ab"},
    "order_book_raw_snapshots": {"列数": 13, "列指纹": "44964af10339eed37f69991213bfec4c957a932ecf3fc3c4b5c91c54694af7f6", "索引数": 2, "索引指纹": "48a2135acee34e54b1e2481e9868c0edd3f762ec0be4e9c991b4fb375921229b"},
    "order_book_signal_delivery_acks": {"列数": 12, "列指纹": "d256e54a13c474739a89255a29c1945427082874c896759f65ecb73dc0868fed", "索引数": 2, "索引指纹": "77e14cca568e9b01c9b6fb8becbb6f14f6b16cb7fa4176c095e91a384afb83f8"},
    "order_book_liquidation_events": {"列数": 18, "列指纹": "7b30eb9ba227a8e7fd33de3fc4baeb17983e067861b867d0f459aa11433fe914", "索引数": 5, "索引指纹": "cf5306bca413f43d984ed74b6f318624d6192bd5f306f07152e7e4e981b4c3bf"},
    "order_book_liquidation_heatmap_buckets": {"列数": 18, "列指纹": "5c08b9110ef4066be95b288717c2e909117e30c80bdebf3db10e975fc781422f", "索引数": 15, "索引指纹": "4a8a245c4873b4a8dc735074eb218d56d30a8bc1f4688e98735c9173ee9a88fe"},
    "order_book_open_interest": {"列数": 10, "列指纹": "6fa64fb60453457f2e14e1d0c6f25564ed2d97af6d2a5eaab9d5111bbd6c5c32", "索引数": 6, "索引指纹": "9c9b3f94779e98d9978c3fc19e9d0c1e12e8925138ae3bbe1412542298da44ba"},
    "order_book_market_structure_snapshots": {"列数": 8, "列指纹": "658b793998b9ff05cac597bcf9f8c760420cf27c947f72b8d59ff1ce65c4b00e", "索引数": 5, "索引指纹": "c3ed06d422de3aa525d13cce6c52e73fa0a64a21245ebf713dee072897eb4825"},
    "order_book_public_context_snapshots": {"列数": 9, "列指纹": "37fcc66bd830042254cccbe83e851ac3ffc3c955f0265aa35361ea7a50fe91be", "索引数": 5, "索引指纹": "3c9b2dd9e07b690e5612bfa7872818e4cbe0f7f594a1cdbd1f15bff3437e1733"},
    "order_book_decision_context_snapshots": {"列数": 12, "列指纹": "5691137bc1f0757518ca6d5268f3cff0f32350d86386a2bf9ba32c3042bf4a66", "索引数": 8, "索引指纹": "b586a7f9bbaa8626217fe0442fcf1f86d4622aaadb11287a2d907369091b93ef"},
    "historical_backfill_files": {"列数": 16, "列指纹": "2e467fe5a718076f0e9eb0abda03b9eb1fc4c2cf175928b2251a2bf33128c896", "索引数": 6, "索引指纹": "407e8622b2c0196b488615dfa53dee266fe8726b35f0de6092095cd47b726d03"},
}


class ContractError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def target_manifest_fingerprint() -> str:
    return sha256_bytes(canonical(TARGET_MANIFEST))


def object_identity_fingerprint(database: str, table: str) -> str:
    return sha256_bytes(f"MySQL/{database}/{table}".encode("utf-8"))


def schema_status(observed: dict[str, Any]) -> tuple[str, str]:
    if observed.get("采集状态") in {"失败", "拒绝"}:
        return "失败", str(observed.get("原因码") or "remote-collection-failed")
    table = observed.get("表")
    expected = SCHEMA_EXPECTATIONS.get(table)
    if expected is None:
        return "无法判定", "unregistered-object"
    if observed.get("采集状态") == "未发现":
        return "未发现", "table-not-found"
    if observed.get("采集状态") != "已采集":
        return "无法判定", "collection-not-proven"
    for key in ("列数", "列指纹", "索引数", "索引指纹"):
        if observed.get(key) != expected[key]:
            return "漂移", f"schema-{key}-mismatch"
    return "匹配", "schema-contract-matched"


def validate_states(results: Iterable[dict[str, Any]], expected_count: int = 16) -> dict[str, int]:
    allowed = {"匹配", "漂移", "未发现", "无法判定", "失败"}
    summary = {key: 0 for key in sorted(allowed)}
    rows = list(results)
    if len(rows) != expected_count:
        raise ContractError("object-count")
    expected_ids = [item["资产编号"] for item in TARGETS]
    actual_ids = [row.get("资产编号") for row in rows]
    if actual_ids != expected_ids:
        raise ContractError("member-order")
    for row in rows:
        status, reason = schema_status(row)
        row["状态"] = status
        row["原因码"] = reason
        summary[status] += 1
    if sum(summary.values()) != expected_count:
        raise ContractError("state-conservation")
    return summary


def validate_remote_document(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("protocol") != PROTOCOL or document.get("合同版本") != CONTRACT_VERSION:
        raise ContractError("protocol-or-contract")
    if document.get("覆盖矩阵指纹") != MATRIX_FINGERPRINT:
        raise ContractError("matrix-fingerprint")
    if document.get("对象清单指纹") != TARGET_MANIFEST_FINGERPRINT:
        raise ContractError("targets-fingerprint")
    if document.get("资源合同") != RESOURCE_CONTRACT:
        raise ContractError("resource-contract")
    if document.get("远端临时写入") is not False:
        raise ContractError("remote-write")
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    forbidden = ("payload_json", "password", "token", "secret", "SELECT ", "mysql://")
    if any(token.lower() in raw.lower() for token in forbidden):
        raise ContractError("sensitive-output")
    summary = validate_states(document.get("对象结果", []))
    return summary


def source_contract(path: Path = SOURCE_DEFAULT) -> dict[str, Any]:
    raw = path.read_bytes()
    if sha256_bytes(raw) != SOURCE_SHA256:
        raise ContractError("source-fingerprint")
    text = raw.decode("utf-8")
    tables: dict[str, dict[str, Any]] = {}
    for table in [item["表"] for item in TARGETS] + list(SOURCE_ONLY_CANDIDATES):
        match = re.search(r"CREATE TABLE IF NOT EXISTS " + re.escape(table) + r"\s*\((.*?)\) ENGINE=", text, re.S)
        if not match:
            raise ContractError("source-table-missing")
        columns: list[tuple[str, str]] = []
        indexes: list[tuple[str, int, str]] = []
        for line in match.group(1).splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            index_match = re.match(r"(PRIMARY KEY|UNIQUE KEY|INDEX|KEY)\s*(?:([A-Za-z_][A-Za-z0-9_]*)\s*)?\(([^)]*)\)", line, re.I)
            if index_match:
                index_name = index_match.group(2) or "PRIMARY"
                for seq, column in enumerate((part.strip().strip("`") for part in index_match.group(3).split(",")), 1):
                    indexes.append((index_name, seq, column))
                continue
            column_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z]+)", line)
            if column_match:
                columns.append((column_match.group(1), column_match.group(2).lower()))
        column_serialized = "|".join(f"{name}:{kind}:{ordinal}" for ordinal, (name, kind) in enumerate(columns, 1))
        index_serialized = "|".join(f"{name}:{seq}:{column}" for name, seq, column in sorted(indexes, key=lambda value: (value[0].lower(), value[1], value[2].lower())))
        tables[table] = {"列数": len(columns), "列指纹": sha256_bytes(column_serialized.encode()), "索引数": len(indexes), "索引指纹": sha256_bytes(index_serialized.encode())}
    return {"提交": SOURCE_COMMIT, "文件": SOURCE_FILE, "文件指纹": SOURCE_SHA256, "表": tables, "未登记候选": SOURCE_ONLY_CANDIDATES}


def build_request(script_fingerprint: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", script_fingerprint):
        raise ContractError("script-fingerprint")
    return {
        "protocol": PROTOCOL,
        "operation": "schema-audit",
        "payload": {
            "合同版本": CONTRACT_VERSION,
            "覆盖矩阵指纹": MATRIX_FINGERPRINT,
            "对象清单指纹": TARGET_MANIFEST_FINGERPRINT,
            "资源合同指纹": RESOURCE_CONTRACT_FINGERPRINT,
            "数据截止": FROZEN_DATA_CUTOFF,
            "规则脚本指纹": script_fingerprint,
        },
    }


def run_remote_schema_audit(key_path: Path, script_fingerprint: str, timeout: int = 360) -> dict[str, Any]:
    if not key_path.is_file():
        raise ContractError("schema-key-missing")
    request = canonical(build_request(script_fingerprint)).decode("utf-8")
    command = [
        "ssh", "-T", "-i", str(key_path), "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "SendEnv=", "-o", "SetEnv=",
        f"User={REMOTE_USER}", REMOTE_HOST,
    ]
    completed = subprocess.run(command, input=request + "\n", text=True, capture_output=True, timeout=timeout, check=False)
    if completed.returncode != 0:
        raise ContractError("remote-invocation-failed")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ContractError("remote-invalid-json") from error
    validate_remote_document(document)
    return document


def self_test() -> None:
    assert len(TARGETS) == 16
    assert target_manifest_fingerprint() == TARGET_MANIFEST_FINGERPRINT
    assert set(SCHEMA_EXPECTATIONS) == {item["表"] for item in TARGETS}
    source_path = SOURCE_DEFAULT
    if source_path.is_file():
        parsed = source_contract(source_path)
        assert parsed["提交"] == SOURCE_COMMIT
        assert {key: parsed["表"][key] for key in SCHEMA_EXPECTATIONS} == SCHEMA_EXPECTATIONS
        assert parsed["未登记候选"] == SOURCE_ONLY_CANDIDATES
    rows = [
        {"资产编号": item["资产编号"], "表": item["表"], "采集状态": "已采集", **SCHEMA_EXPECTATIONS[item["表"]]}
        for item in TARGETS
    ]
    summary = validate_states(rows)
    assert summary == {"匹配": 16, "漂移": 0, "未发现": 0, "无法判定": 0, "失败": 0}
    bad = dict(rows[0]); bad["列数"] += 1
    status, _ = schema_status(bad)
    assert status == "漂移"
    print("订单簿共享对象映射自检通过：16对象、目标指纹、源代码指纹、状态守恒和失败安全")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--schema-key", type=Path)
    parser.add_argument("--script-fingerprint", default=sha256_bytes(Path(__file__).read_bytes()))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.schema_key is None:
        parser.error("需要--schema-key，禁止无凭据猜测或模拟远端结果")
    document = run_remote_schema_audit(args.schema_key, args.script_fingerprint)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical(document) + b"\n")
    print(json.dumps({"状态摘要": validate_remote_document(document), "批次协议": document["protocol"]}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
