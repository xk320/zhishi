#!/usr/bin/env python3
"""验证远程只读身份响应并生成脱敏、追加式批次元数据。"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


PROTOCOL = "zhishi-ro/1"
WRAPPER_VERSION = "zhishi-ro-identity-probe-1.0"
RESPONSE_KEYS = frozenset(
    {
        "protocol",
        "wrapper_version",
        "wrapper_sha256",
        "operation",
        "status",
        "reason_code",
        "uid",
        "gid",
        "uid_nonzero",
        "supplementary_group_count",
        "root_home_readable",
        "root_home_writable",
        "protected_system_path_writable",
        "original_command_present",
        "remote_write_performed",
        "database_business_read_performed",
        "market_data_read_performed",
    }
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|token\s*=|authorization:|gh[pousr]_[A-Za-z0-9]|"
    r"-----BEGIN|\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b)"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("响应必须是JSON对象")
    return value


def validate_identity_response(
    response: Mapping[str, Any], *, wrapper_sha256: str
) -> tuple[str, ...]:
    errors: list[str] = []
    if frozenset(response) != RESPONSE_KEYS:
        errors.append("响应字段集合不匹配")
    if response.get("protocol") != PROTOCOL:
        errors.append("协议版本不匹配")
    if response.get("wrapper_version") != WRAPPER_VERSION:
        errors.append("wrapper版本不匹配")
    if response.get("wrapper_sha256") != wrapper_sha256 or not SHA256.fullmatch(
        str(response.get("wrapper_sha256", ""))
    ):
        errors.append("wrapper内容指纹不匹配")
    if response.get("operation") != "identity" or response.get("status") != "通过":
        errors.append("身份探针未通过")
    if response.get("reason_code") != "":
        errors.append("通过响应包含拒绝原因")
    if not isinstance(response.get("uid"), int) or response.get("uid") == 0:
        errors.append("UID必须为非零整数")
    if not isinstance(response.get("gid"), int) or response.get("gid") == 0:
        errors.append("GID必须为非零整数")
    if response.get("uid_nonzero") is not True:
        errors.append("UID非零断言未通过")
    if response.get("supplementary_group_count") != 0:
        errors.append("存在补充组权限")
    for key in (
        "root_home_readable",
        "root_home_writable",
        "protected_system_path_writable",
        "original_command_present",
        "remote_write_performed",
        "database_business_read_performed",
        "market_data_read_performed",
    ):
        if response.get(key) is not False:
            errors.append(f"安全断言未通过：{key}")
    return tuple(dict.fromkeys(errors))


def validate_rejection(response: Mapping[str, Any], *, reason_code: str) -> tuple[str, ...]:
    errors: list[str] = []
    if frozenset(response) != RESPONSE_KEYS:
        errors.append("拒绝响应字段集合不匹配")
    if response.get("status") != "拒绝" or response.get("reason_code") != reason_code:
        errors.append("拒绝响应原因不匹配")
    if response.get("remote_write_performed") is not False:
        errors.append("拒绝响应声称发生远端写入")
    return tuple(errors)


def build_batch_metadata(
    response: Mapping[str, Any],
    *,
    batch_id: str,
    frozen_at: str,
    public_key_fingerprint: str,
    ssh_options_fingerprint: str,
    probe_exit_code: int,
    memory_available_percent: float,
    disk_available_gib: float,
) -> dict[str, Any]:
    if not re.fullmatch(r"remote-ro-identity-[0-9TZ+:-]+-v[0-9]+", batch_id):
        raise ValueError("批次身份格式非法")
    if not FINGERPRINT.fullmatch(public_key_fingerprint):
        raise ValueError("公钥指纹格式非法")
    if not SHA256.fullmatch(ssh_options_fingerprint):
        raise ValueError("SSH选项指纹格式非法")
    if not isinstance(probe_exit_code, int) or probe_exit_code != 0:
        raise ValueError("探针退出码必须为0")
    if not isinstance(memory_available_percent, (int, float)) or memory_available_percent < 20:
        raise ValueError("可用内存低于硬门")
    if not isinstance(disk_available_gib, (int, float)) or disk_available_gib < 5:
        raise ValueError("可用磁盘低于硬门")
    wrapper_sha256 = str(response.get("wrapper_sha256", ""))
    response_sha256 = hashlib.sha256(
        json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "批次版本": "remote-ro-identity/v1",
        "批次身份": batch_id,
        "冻结时间": frozen_at,
        "身份类型": "专用远程只读",
        "账户UID": response.get("uid"),
        "主组GID": response.get("gid"),
        "补充组数量": response.get("supplementary_group_count"),
        "公钥指纹": public_key_fingerprint,
        "公钥数量": 1,
        "SSH选项指纹": ssh_options_fingerprint,
        "wrapper版本": response.get("wrapper_version"),
        "wrapper内容指纹": wrapper_sha256,
        "响应指纹": response_sha256,
        "探针退出码": probe_exit_code,
        "状态": "通过",
        "敏感信息扫描": "通过",
        "远端写入": False,
        "数据库业务正文读取": False,
        "真实市场数据读取": False,
        "资源": {
            "单探针超时秒": 30,
            "批次总超时秒": 600,
            "内存可用百分比": memory_available_percent,
            "磁盘可用GiB": disk_available_gib,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证远程只读身份")
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--wrapper", type=Path, required=True)
    parser.add_argument("--expected-key-fingerprint")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        response = _load_object(args.response)
        wrapper_sha256 = sha256_file(args.wrapper)
        errors = list(validate_identity_response(response, wrapper_sha256=wrapper_sha256))
        text = json.dumps(response, ensure_ascii=False, sort_keys=True)
        if SENSITIVE.search(text):
            errors.append("响应包含敏感信息")
        if args.expected_key_fingerprint and not FINGERPRINT.fullmatch(
            args.expected_key_fingerprint
        ):
            errors.append("公钥指纹格式非法")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        errors = [str(error)]
    print(json.dumps({"valid": not errors, "reasons": list(dict.fromkeys(errors))}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
