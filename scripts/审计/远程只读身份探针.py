#!/usr/bin/env python3
"""固定的远程只读身份探针与版本化请求协议。

该文件既作为本地请求/响应协议实现，也作为远端root-owned强制命令安装。
远端入口只接受 ``zhishi-ro/1`` 的 ``identity`` 空载荷，不执行原始命令或
任意Python输入；输出只包含脱敏的身份与权限事实。
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import grp
import resource
import signal
import sys
from typing import Any, Mapping


PROTOCOL = "zhishi-ro/1"
WRAPPER_VERSION = "zhishi-ro-identity-probe-1.0"
PROBE_TIMEOUT_SECONDS = 30
PROBE_MEMORY_BYTES = 512 * 1024 * 1024
REQUEST_KEYS = frozenset({"protocol", "operation", "payload"})
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


class ProtocolError(ValueError):
    """请求不是固定协议。"""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate-key")
        result[key] = value
    return result


def canonical_request() -> str:
    """生成唯一身份请求，不包含主机、账户或凭据。"""

    return json.dumps(
        {"protocol": PROTOCOL, "operation": "identity", "payload": {}},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _wrapper_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return ""


def _base_response(
    *, status: str, reason_code: str, operation: str = ""
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "wrapper_version": WRAPPER_VERSION,
        "wrapper_sha256": _wrapper_sha256(),
        "operation": operation,
        "status": status,
        "reason_code": reason_code,
        "uid": None,
        "gid": None,
        "uid_nonzero": False,
        "admin_group_membership": False,
        "supplementary_group_count": None,
        "root_home_readable": None,
        "root_home_openable": None,
        "root_home_writable": None,
        "protected_system_path_writable": None,
        "original_command_present": bool(os.environ.get("SSH_ORIGINAL_COMMAND")),
        "remote_write_performed": False,
        "database_business_read_performed": False,
        "market_data_read_performed": False,
    }


def _reject(reason_code: str, operation: str = "") -> dict[str, Any]:
    return _base_response(status="拒绝", reason_code=reason_code, operation=operation)


def _parse_request(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > 4096:
        raise ProtocolError("request-too-large")
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ProtocolError) as error:
        raise ProtocolError("invalid-json") from error
    if not isinstance(value, dict) or frozenset(value) != REQUEST_KEYS:
        raise ProtocolError("request-fields")
    if value.get("protocol") != PROTOCOL or value.get("operation") != "identity":
        raise ProtocolError("request-operation")
    if value.get("payload") != {}:
        raise ProtocolError("request-payload")
    return value


def probe(raw: str, *, environment: Mapping[str, str] | None = None) -> dict[str, Any]:
    """处理一次请求；任何不符合白名单的输入均失败安全。"""

    if environment is not None:
        original = os.environ.get("SSH_ORIGINAL_COMMAND")
        try:
            if "SSH_ORIGINAL_COMMAND" in environment:
                os.environ["SSH_ORIGINAL_COMMAND"] = environment["SSH_ORIGINAL_COMMAND"]
            else:
                os.environ.pop("SSH_ORIGINAL_COMMAND", None)
            return _probe_with_environment(raw)
        finally:
            if original is None:
                os.environ.pop("SSH_ORIGINAL_COMMAND", None)
            else:
                os.environ["SSH_ORIGINAL_COMMAND"] = original
    return _probe_with_environment(raw)


def _probe_with_environment(raw: str) -> dict[str, Any]:
    if os.environ.get("SSH_ORIGINAL_COMMAND"):
        return _reject("original-command")
    try:
        request = _parse_request(raw)
    except ProtocolError as error:
        reason = str(error)
        return _reject(reason if reason else "invalid-request")

    response = _base_response(
        status="通过", reason_code="", operation=str(request["operation"])
    )
    uid = os.getuid()
    gid = os.getgid()
    group_ids = set(os.getgroups()) | {gid}
    admin_names = {"root", "sudo", "adm", "wheel", "docker"}
    admin_membership = False
    for group_id in group_ids:
        try:
            if grp.getgrgid(group_id).gr_name in admin_names:
                admin_membership = True
        except KeyError:
            continue
    response.update(
        {
            "uid": uid,
            "gid": gid,
            "uid_nonzero": uid != 0,
            "admin_group_membership": admin_membership,
            # 某些发行版会把主组同时放入getgroups()；只计主组之外的附加组。
            "supplementary_group_count": len({group for group in os.getgroups() if group != gid}),
            # 只查询目录权限，不读取目录内容；root目录由root拥有且默认不可读写。
            "root_home_readable": os.access("/root", os.R_OK),
            "root_home_openable": _directory_openable("/root"),
            "root_home_writable": os.access("/root", os.W_OK),
            # /etc是受保护系统路径，用于证明普通身份没有系统写权限。
            "protected_system_path_writable": os.access("/etc", os.W_OK),
        }
    )
    return response


def _directory_openable(path: str) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return False
    os.close(fd)
    return True


def _set_resource_limits() -> None:
    try:
        resource.setrlimit(
            resource.RLIMIT_AS, (PROBE_MEMORY_BYTES, PROBE_MEMORY_BYTES)
        )
    except (OSError, ValueError):
        pass
    try:
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.alarm(PROBE_TIMEOUT_SECONDS)
    except (OSError, ValueError):
        pass


def main() -> int:
    _set_resource_limits()
    if sys.argv[1:] == ["--request"]:
        sys.stdout.write(canonical_request() + "\n")
        return 0
    if sys.argv[1:]:
        response = _reject("arguments-not-allowed")
    else:
        try:
            raw = sys.stdin.read(4097)
        except (OSError, UnicodeError):
            raw = ""
        response = probe(raw)
    sys.stdout.write(
        json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    return 0 if response["status"] == "通过" else 1


if __name__ == "__main__":
    raise SystemExit(main())
