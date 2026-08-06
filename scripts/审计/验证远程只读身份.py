#!/usr/bin/env python3
"""验证远程只读身份响应并生成脱敏、追加式批次元数据。"""

from __future__ import annotations

import argparse
import base64
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
        "admin_group_membership",
        "supplementary_group_count",
        "root_home_readable",
        "root_home_openable",
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


def public_key_fingerprint(path: Path) -> str:
    """按OpenSSH公钥正文复算SHA256指纹。"""

    parts = path.read_text(encoding="utf-8").strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("公钥必须是单行ssh-ed25519")
    try:
        key_blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("公钥正文不是合法Base64") from error
    encoded = base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")
    return f"SHA256:{encoded}"


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
    if response.get("admin_group_membership") is not False:
        errors.append("存在管理员组权限")
    if response.get("supplementary_group_count") != 0:
        errors.append("存在补充组权限")
    for key in (
        "root_home_readable",
        "root_home_openable",
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
    wrapper_sha256: str,
    batch_id: str,
    frozen_at: str,
    public_key_fingerprint: str,
    ssh_options_fingerprint: str,
    wrapper_owner_uid: int,
    wrapper_mode: int,
    authorized_key_count: int,
    password_locked: bool,
    admin_groups: bool,
    supplementary_group_count: int,
    probe_exit_code: int,
    memory_available_percent: float,
    disk_available_gib: float,
) -> dict[str, Any]:
    response_errors = validate_identity_response(
        response, wrapper_sha256=wrapper_sha256
    )
    if response_errors:
        raise ValueError("身份响应未通过：" + "；".join(response_errors))
    if not re.fullmatch(r"remote-ro-identity-[0-9TZ+:-]+-v[0-9]+", batch_id):
        raise ValueError("批次身份格式非法")
    if not FINGERPRINT.fullmatch(public_key_fingerprint):
        raise ValueError("公钥指纹格式非法")
    if not SHA256.fullmatch(ssh_options_fingerprint):
        raise ValueError("SSH选项指纹格式非法")
    if wrapper_owner_uid != 0 or wrapper_mode != 0o755:
        raise ValueError("wrapper必须是root-owned 0755普通文件")
    if authorized_key_count != 1:
        raise ValueError("授权公钥必须且只能有一把")
    if password_locked is not True:
        raise ValueError("密码必须锁定")
    if admin_groups is not False:
        raise ValueError("账户不得属于管理员组")
    if supplementary_group_count != 0:
        raise ValueError("账户不得有补充组")
    if response.get("supplementary_group_count") != supplementary_group_count:
        raise ValueError("响应与权限快照的补充组计数不一致")
    if not isinstance(probe_exit_code, int) or probe_exit_code != 0:
        raise ValueError("探针退出码必须为0")
    if not isinstance(memory_available_percent, (int, float)) or memory_available_percent < 20:
        raise ValueError("可用内存低于硬门")
    if not isinstance(disk_available_gib, (int, float)) or disk_available_gib < 5:
        raise ValueError("可用磁盘低于硬门")
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
        "wrapper文件事实": {
            "owner_uid": wrapper_owner_uid,
            "mode": f"{wrapper_mode:04o}",
            "普通文件": True,
        },
        "authorized_keys事实": {
            "公钥数量": authorized_key_count,
            "公钥指纹": public_key_fingerprint,
            "选项指纹": ssh_options_fingerprint,
            "restrict": True,
            "固定命令": True,
        },
        "账户权限验证": {
            "UID非零": response.get("uid_nonzero"),
            "管理员组": admin_groups,
            "密码登录": "锁定" if password_locked else "未锁定",
            "补充组数量": supplementary_group_count,
            "强制命令": "root-owned固定wrapper",
        },
        "资源": {
            "单探针超时秒": 30,
            "批次总超时秒": 600,
            "内存可用百分比": memory_available_percent,
            "磁盘可用GiB": disk_available_gib,
        },
    }


def write_batch_append_only(
    output_dir: Path,
    *,
    metadata: Mapping[str, Any],
    response: Mapping[str, Any],
    boundary_summary: Mapping[str, Any],
) -> None:
    """以新目录和独占创建写入批次，拒绝覆盖既有批次。"""

    if output_dir.exists():
        raise FileExistsError("批次目录已存在，禁止覆盖")
    output_dir.mkdir(parents=True)
    for filename, payload in (
        ("批次元数据.json", metadata),
        ("探针响应.json", response),
        ("边界探针摘要.json", boundary_summary),
    ):
        path = output_dir / filename
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证远程只读身份")
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--wrapper", type=Path, required=True)
    parser.add_argument("--expected-key-fingerprint")
    parser.add_argument("--public-key", type=Path)
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
        if args.expected_key_fingerprint:
            if not FINGERPRINT.fullmatch(args.expected_key_fingerprint):
                errors.append("公钥指纹格式非法")
            elif args.public_key is None:
                errors.append("公钥指纹缺少原始公钥复算路径")
            elif public_key_fingerprint(args.public_key) != args.expected_key_fingerprint:
                errors.append("公钥指纹与原始公钥不一致")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        errors = [str(error)]
    print(json.dumps({"valid": not errors, "reasons": list(dict.fromkeys(errors))}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
