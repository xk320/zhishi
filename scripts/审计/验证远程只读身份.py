#!/usr/bin/env python3
"""验证远程只读身份响应并生成脱敏、追加式批次元数据。"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import stat
import time
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
        "sudo_noninteractive_allowed",
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
FIXED_AUTHORIZED_OPTIONS = 'restrict,command="/usr/local/libexec/zhishi_ro_identity_probe.py"'
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]+={0,2}$")
PERMISSION_SNAPSHOT_VERSION = "zhishi-ro-permissions/1"
PERMISSION_SNAPSHOT_SOURCE = "root-management-readonly"
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


def compute_public_key_fingerprint(path: Path) -> str:
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


def _fingerprint_from_key_blob(encoded_key: str) -> str:
    try:
        key_blob = base64.b64decode(encoded_key, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("authorized_keys公钥正文不是合法Base64") from error
    encoded = base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")
    return f"SHA256:{encoded}"


def authorized_key_facts(path: Path, *, expected_options: str) -> dict[str, Any]:
    """复算authorized_keys的唯一行、选项和公钥指纹。"""

    if expected_options != FIXED_AUTHORIZED_OPTIONS:
        raise ValueError("强制命令必须绑定固定wrapper")
    if path.is_symlink() or not path.is_file():
        raise ValueError("authorized_keys不得为符号链接")
    file_stat = path.stat()
    if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise ValueError("authorized_keys必须是0600普通文件")
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("authorized_keys必须且只能有一行")
    parts = lines[0].split()
    if len(parts) < 3 or parts[0] != expected_options or parts[1] != "ssh-ed25519":
        raise ValueError("authorized_keys选项或算法不匹配")
    return {
        "公钥数量": 1,
        "公钥指纹": _fingerprint_from_key_blob(parts[2]),
        "选项指纹": hashlib.sha256(parts[0].encode()).hexdigest(),
        "内容指纹": sha256_file(path),
        "文件所有者UID": file_stat.st_uid,
        "文件所有者GID": file_stat.st_gid,
        "文件模式": "0600",
        "普通文件": True,
        "restrict": True,
        "固定命令": True,
    }


def load_wrapper_stat_snapshot(path: Path, *, content_sha256: str) -> dict[str, Any]:
    """读取root采集的脱敏wrapper stat快照并绑定内容指纹。"""

    value = _load_object(path)
    expected = {"owner_uid", "owner_gid", "mode", "regular_file", "content_sha256"}
    if set(value) != expected:
        raise ValueError("wrapper stat快照字段不完整")
    if value["owner_uid"] != 0 or value["owner_gid"] != 0:
        raise ValueError("wrapper stat快照不是root-owned")
    if value["mode"] != "0755" or value["regular_file"] is not True:
        raise ValueError("wrapper stat快照模式或普通文件标志不匹配")
    if value["content_sha256"] != content_sha256:
        raise ValueError("wrapper stat快照与wrapper内容指纹不一致")
    return dict(value)


def load_permission_facts_snapshot(
    path: Path,
    *,
    response: Mapping[str, Any],
    wrapper_stat: Mapping[str, Any],
    authorized_facts: Mapping[str, Any],
    public_key_fingerprint: str,
    password_locked: bool,
    admin_groups: bool,
    supplementary_group_count: int,
) -> dict[str, Any]:
    """校验root管理面生成的脱敏账户/授权事实快照。"""

    if path.is_symlink() or not path.is_file():
        raise ValueError("权限事实快照必须是普通文件")
    value = _load_object(path)
    if set(value) != {"snapshot_version", "source", "account", "wrapper", "authorized_keys"}:
        raise ValueError("权限事实快照字段不完整")
    if value["snapshot_version"] != PERMISSION_SNAPSHOT_VERSION:
        raise ValueError("权限事实快照版本不匹配")
    if value["source"] != PERMISSION_SNAPSHOT_SOURCE:
        raise ValueError("权限事实快照来源不匹配")
    account = value["account"]
    if set(account) != {
        "uid",
        "gid",
        "supplementary_group_count",
        "admin_group_membership",
        "password_locked",
        "sudo_noninteractive_allowed",
    }:
        raise ValueError("账户事实快照字段不完整")
    expected_account = {
        "uid": response.get("uid"),
        "gid": response.get("gid"),
        "supplementary_group_count": supplementary_group_count,
        "admin_group_membership": admin_groups,
        "password_locked": password_locked,
        "sudo_noninteractive_allowed": response.get("sudo_noninteractive_allowed"),
    }
    if account != expected_account:
        raise ValueError("账户事实快照与响应/权限参数不一致")
    if account["password_locked"] is not True:
        raise ValueError("账户密码必须锁定")
    wrapper = value["wrapper"]
    if dict(wrapper) != dict(wrapper_stat):
        raise ValueError("权限快照中的wrapper事实与stat快照不一致")
    authorized = value["authorized_keys"]
    if set(authorized) != {
        "owner_uid",
        "owner_gid",
        "mode",
        "regular_file",
        "content_sha256",
        "key_count",
        "key_fingerprint",
        "options_fingerprint",
        "restrict",
        "fixed_command",
    }:
        raise ValueError("授权文件事实快照字段不完整")
    if authorized["owner_uid"] != response.get("uid") or authorized["owner_gid"] != response.get("gid"):
        raise ValueError("授权文件所有者与专用账户不一致")
    if authorized["mode"] != "0600" or authorized["regular_file"] is not True:
        raise ValueError("授权文件权限或普通文件事实不匹配")
    expected_authorized = {
        "key_count": authorized_facts["公钥数量"],
        "key_fingerprint": public_key_fingerprint,
        "options_fingerprint": authorized_facts["选项指纹"],
        "restrict": True,
        "fixed_command": True,
    }
    if any(authorized[key] != expected for key, expected in expected_authorized.items()):
        raise ValueError("授权文件事实快照与实际授权事实不一致")
    if authorized["content_sha256"] != authorized_facts["内容指纹"]:
        raise ValueError("授权文件内容指纹与实际文件不一致")
    if authorized["mode"] != authorized_facts["文件模式"] or authorized["regular_file"] != authorized_facts["普通文件"]:
        raise ValueError("授权文件模式快照与实际文件不一致")
    if not SHA256.fullmatch(str(authorized["content_sha256"])):
        raise ValueError("授权文件内容指纹格式非法")
    return dict(value)


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
    if response.get("sudo_noninteractive_allowed") is not False:
        errors.append("sudo非交互能力未被拒绝")
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
    wrapper_path: Path,
    public_key_path: Path,
    authorized_keys_path: Path,
    wrapper_stat_path: Path,
    permission_facts_path: Path,
    batch_id: str,
    frozen_at: str,
    ssh_options: str,
    authorized_key_count: int,
    password_locked: bool,
    admin_groups: bool,
    supplementary_group_count: int,
    probe_exit_code: int,
    memory_available_percent: float,
    disk_available_gib: float,
) -> dict[str, Any]:
    wrapper_stat = wrapper_path.stat()
    if not stat.S_ISREG(wrapper_stat.st_mode):
        raise ValueError("本地wrapper副本必须是普通文件")
    wrapper_sha256 = sha256_file(wrapper_path)
    public_key_fingerprint = compute_public_key_fingerprint(public_key_path)
    ssh_options_fingerprint = hashlib.sha256(ssh_options.encode()).hexdigest()
    if not wrapper_path.is_file() or wrapper_path.is_symlink():
        raise ValueError("wrapper必须是普通文件")
    authorized_facts = authorized_key_facts(
        authorized_keys_path, expected_options=ssh_options
    )
    if authorized_facts["公钥指纹"] != public_key_fingerprint:
        raise ValueError("authorized_keys公钥与原始公钥不一致")
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
    wrapper_stat = load_wrapper_stat_snapshot(
        wrapper_stat_path, content_sha256=wrapper_sha256
    )
    permission_facts = load_permission_facts_snapshot(
        permission_facts_path,
        response=response,
        wrapper_stat=wrapper_stat,
        authorized_facts=authorized_facts,
        public_key_fingerprint=public_key_fingerprint,
        password_locked=password_locked,
        admin_groups=admin_groups,
        supplementary_group_count=supplementary_group_count,
    )
    if authorized_key_count != authorized_facts["公钥数量"] or authorized_key_count != 1:
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
            "owner_uid": wrapper_stat["owner_uid"],
            "owner_gid": wrapper_stat["owner_gid"],
            "mode": wrapper_stat["mode"],
            "普通文件": wrapper_stat["regular_file"],
        },
        "证据文件": {
            "wrapper统计快照": {
                "文件名": "wrapper-stat.json",
                "SHA256": sha256_file(wrapper_stat_path),
            },
            "账户与授权事实快照": {
                "文件名": "账户授权事实.json",
                "SHA256": sha256_file(permission_facts_path),
                "版本": permission_facts["snapshot_version"],
            },
        },
        "authorized_keys事实": {
            "公钥数量": authorized_facts["公钥数量"],
            "公钥指纹": public_key_fingerprint,
            "选项指纹": authorized_facts["选项指纹"],
            "restrict": authorized_facts["restrict"],
            "固定命令": authorized_facts["固定命令"],
        },
        "账户权限验证": {
            "UID非零": response.get("uid_nonzero"),
            "管理员组": admin_groups,
            "sudo非交互能力": response.get("sudo_noninteractive_allowed"),
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
    evidence_files: Mapping[str, Path],
    started_monotonic: float,
    max_batch_seconds: int = 600,
) -> None:
    """以新目录和独占创建写入批次，拒绝覆盖既有批次。"""

    if max_batch_seconds < 1 or max_batch_seconds > 600:
        raise ValueError("批次总超时必须为1至600秒")
    if not isinstance(started_monotonic, (int, float)):
        raise ValueError("必须提供批次开始单调时钟")
    if time.monotonic() - started_monotonic > max_batch_seconds:
        raise TimeoutError("批次超过总超时硬门")
    if output_dir.exists():
        raise FileExistsError("批次目录已存在，禁止覆盖")
    output_dir.mkdir(parents=True)
    if set(evidence_files) != {"wrapper-stat.json", "账户授权事实.json"}:
        raise ValueError("必须保存wrapper统计和账户授权事实快照")
    for filename, payload in (
        ("批次元数据.json", metadata),
        ("探针响应.json", response),
        ("边界探针摘要.json", boundary_summary),
    ):
        path = output_dir / filename
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    for filename, source in evidence_files.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError("证据文件必须是普通文件")
        expected = metadata["证据文件"][
            "wrapper统计快照" if filename == "wrapper-stat.json" else "账户与授权事实快照"
        ]
        if expected["文件名"] != filename or expected["SHA256"] != sha256_file(source):
            raise ValueError("证据文件指纹与元数据不一致")
        destination = output_dir / filename
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(source.read_text(encoding="utf-8"))


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
            elif compute_public_key_fingerprint(args.public_key) != args.expected_key_fingerprint:
                errors.append("公钥指纹与原始公钥不一致")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        errors = [str(error)]
    print(json.dumps({"valid": not errors, "reasons": list(dict.fromkeys(errors))}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
