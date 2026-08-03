#!/usr/bin/env python3
"""使用main可信任务合同验证Pull Request自动合并资格。"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Mapping, Sequence


CONTROLLED_RD_TASK_TYPES = frozenset(
    {
        "数据治理",
        "数据审计",
        "数据工程",
        "基础设施验证",
        "策略研究",
        "研究工程",
        "模拟交易",
        "测试",
        "工具",
    }
)
ALLOWED_TASK_TYPES = (
    frozenset({"文档", "治理", "研究规范"}) | CONTROLLED_RD_TASK_TYPES
)
ALLOWED_ROOT_MARKDOWN = frozenset({"AGENTS.md", "README.md", "《知势宣言》.md"})
AUTOMATION_SCOPE = "治理自动化"
AUTOMATION_FILES = frozenset(
    {
        ".github/workflows/pr-auto-merge.yml",
        ".github/workflows/pr-auto-merge-eligibility.yml",
    }
)
TASK_FILE_PATTERN = re.compile(r"^docs/研发中心/任务/任务-(\d{6})\.md$")
TASK_TYPE_PATTERN = re.compile(r"^- 类型：(.+)$", re.MULTILINE)
TASK_STATUS_PATTERN = re.compile(r"^- 状态：(.+)$", re.MULTILINE)
TASK_PRIORITY_PATTERN = re.compile(r"^- 优先级：(.+)$", re.MULTILINE)
TASK_TITLE_PATTERN = re.compile(r"^# 任务-\d{6}：(.+)$", re.MULTILINE)
TASK_TITLE_WITH_ID_PATTERN = re.compile(
    r"^# 任务-(\d{6})：(.+)$", re.MULTILINE
)
BLOCKER_PATTERN = re.compile(r"^- 当前阻塞原因：(.+)$", re.MULTILINE)
BOARD_TASK_ROW_PATTERN = re.compile(
    r"^\|\s*(?:P[0-3]\s*\|\s*)?任务-(\d{6})\s*\|"
)
BOARD_TABLE_SCHEMA = {
    "待执行": (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 |",
        "| --- | --- | --- | --- |",
    ),
    "阻塞": (
        "| 优先级 | 任务 | 名称 | 唯一前序依赖 | 阻塞原因 |",
        "| --- | --- | --- | --- | --- |",
    ),
    "执行中": (
        "| 优先级 | 任务 | 名称 | 执行分支 | 开始时间 |",
        "| --- | --- | --- | --- | --- |",
    ),
    "待评审": (
        "| 优先级 | 任务 | 名称 | 分支 | PR |",
        "| --- | --- | --- | --- | --- |",
    ),
    "已完成": (
        "| 任务 | 名称 | 完成证据 |",
        "| --- | --- | --- |",
    ),
}
AUTOMATION_SCOPE_PATTERN = re.compile(r"^- 自动合并范围：(.+)$", re.MULTILINE)
MERGE_SHA_PATTERN = re.compile(
    r"^- 合并提交SHA：`([0-9a-f]{40})`$", re.MULTILINE
)
MERGE_TIME_PATTERN = re.compile(
    r"^- 合并时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})$",
    re.MULTILINE,
)
PULL_REQUEST_PATTERN = re.compile(
    r"^- Pull Request：\[#(\d+)\]\(https://github\.com/xk320/zhishi/pull/\1\)$",
    re.MULTILINE,
)
DEPENDENCY_PATTERN = re.compile(r"^- 唯一前序依赖：任务-(\d{6})(?:[^\r\n]*)$", re.MULTILINE)
TASK_REFERENCE_LINE = re.compile(
    r"^\s*-\s*任务-(\d{6})(?:\s*[（(][^\r\n]*[）)])?\s*$"
)
CHANGE_TYPES = frozenset({"任务登记", "任务交付", "合并后状态闭环"})
REGISTRATION_STATUSES = frozenset({"待执行", "阻塞"})
REQUIRED_TASK_FIELDS = (
    "状态",
    "类型",
    "阶段",
    "优先级",
    "执行方案",
    "方案状态",
    "执行授权",
    "并行规则",
)
REQUIRED_TASK_HEADINGS = (
    "依赖与阻塞条件",
    "背景",
    "任务目标",
    "固定执行方案",
    "默认工程决策",
    "允许停止条件",
    "输入合同",
    "输出合同",
    "工作范围",
    "不在范围",
    "安全边界",
    "验收标准",
    "验证命令",
    "完成定义",
)
HISTORICAL_MISSING_TASK_IDS = frozenset({"000026"})
REGISTRATION_BOARD_PATH = "docs/研发中心/看板.md"
REGISTRATION_DESIGN_PATTERN = re.compile(
    r"^docs/superpowers/specs/[^/]+-design\.md$"
)
STATE_CLOSURE_TRANSITIONS = frozenset(
    {
        ("待评审", "已完成"),
        ("阻塞", "待执行"),
    }
)
DELIVERY_BASE_STATUSES = frozenset({"待执行", "需修复"})
COMPLETION_MUTABLE_PREFIXES = (
    "- 状态：",
    "- 合并时间：",
    "- 合并提交SHA：",
)
MAX_CHANGED_FILES = 500
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_TOTAL_SIZE = 25 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_LENGTH = 4096
MAX_BASE_TASK_TREE_BYTES = 4 * 1024 * 1024
MAX_BASE_TASK_COUNT = 10000
SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(
        r"(?<![\w])(?:"
        r'"(?:password|passwd|secret|token|client_secret|api_key|access_key)"|'
        r"'(?:password|passwd|secret|token|client_secret|api_key|access_key)'|"
        r"(?:password|passwd|secret|token|client_secret|api_key|access_key)"
        r")\s*[:=]\s*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^\s,}\]\r\n#]+)",
        re.IGNORECASE,
    ),
)
DOUBLE_QUOTED_KEY_PATTERN = re.compile(
    r'"(?P<key>(?:\\.|[^"\\\r\n])*)"(?P<suffix>\s*[:=])'
)


@dataclass(frozen=True)
class EligibilityResult:
    """自动合并资格判定结果。"""

    eligible: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MergeFact:
    """main中已验证的真实合并事实。"""

    sha: str
    merged_at: str
    pr_number: int


@dataclass(frozen=True)
class PathFact:
    """PR头提交中单个变更路径的已验证事实。"""

    path: str
    status: str
    mode: str
    object_type: str
    size: int
    text: str | None


@dataclass(frozen=True)
class _PathObjectMetadata:
    """Git对象正文读取前的有界元数据。"""

    path: str
    status: str
    mode: str
    object_type: str
    oid: str
    size: int


def _task_field(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _markdown_section(text: str, heading: str) -> tuple[str, ...]:
    """读取唯一的CommonMark ATX二级标题区段。"""

    lines = text.splitlines()
    locations: list[int] = []
    for index, line in enumerate(lines):
        parsed = _commonmark_atx_heading(line)
        if parsed == (2, heading):
            locations.append(index)
    if len(locations) != 1:
        return ()
    start = locations[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        parsed = _commonmark_atx_heading(lines[index])
        if parsed is not None and parsed[0] <= 2:
            end = index
            break
    return tuple(lines[start:end])


def _commonmark_atx_heading(line: str) -> tuple[int, str] | None:
    """规范化CommonMark ATX标题的级别和文本。"""

    match = re.fullmatch(
        r" {0,3}(?P<marks>#{1,6})(?:[ \t]+(?P<text>.*)|[ \t]*)",
        line,
    )
    if match is None:
        return None
    text = (match.group("text") or "").rstrip(" \t")
    closing = re.search(r"[ \t]+#+$", text)
    if closing is not None:
        text = text[: closing.start()].rstrip(" \t")
    return len(match.group("marks")), text


def _second_level_heading_count(text: str, heading: str) -> int:
    return sum(
        _commonmark_atx_heading(line) == (2, heading)
        for line in text.splitlines()
    )


def parse_task_references(pr_body: str) -> tuple[str, ...]:
    """只解析PR正文严格的“关联任务”二级标题区段。"""

    task_ids: list[str] = []
    for line in _markdown_section(pr_body, "关联任务"):
        match = TASK_REFERENCE_LINE.fullmatch(line)
        if match is not None and match.group(1) not in task_ids:
            task_ids.append(match.group(1))
    return tuple(sorted(task_ids))


def parse_change_type(pr_body: str) -> str | None:
    """读取严格、唯一的PR变更类型。"""

    values = [
        line.strip()[2:].strip()
        for line in _markdown_section(pr_body, "变更类型")
        if line.strip().startswith("- ")
    ]
    valid = [value for value in values if value in CHANGE_TYPES]
    return valid[0] if len(valid) == 1 and len(values) == 1 else None


def _task_reference_limit(change_type: str | None) -> int:
    return 2 if change_type == "合并后状态闭环" else 1


def _task_reference_limit_reason(change_type: str | None) -> str:
    label = change_type or "未知变更类型"
    return f"{label}最多关联{_task_reference_limit(change_type)}个任务"


def parse_nul_paths(output: bytes) -> tuple[str, ...]:
    """解析Git NUL分隔路径，避免中文路径被quotePath转义。"""

    paths: list[str] = []
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        paths.append(raw_path.decode("utf-8", errors="strict"))
    return tuple(paths)


def _stop_git_process(process: subprocess.Popen[bytes]) -> None:
    """停止Git子进程并回收，不留下管道或僵尸进程。"""

    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _read_nul_field(stream: BinaryIO, max_bytes: int) -> bytes | None:
    value = bytearray()
    while True:
        byte = stream.read(1)
        if byte == b"":
            if value:
                raise ValueError("Git NUL输出不完整")
            return None
        if byte == b"\0":
            return bytes(value)
        value.extend(byte)
        if len(value) > max_bytes:
            raise ValueError("Git NUL字段超出上限")


def _stream_diff_entries(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
) -> tuple[tuple[str, str], ...]:
    process = subprocess.Popen(
        [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            base_ref,
            head_ref,
            "--",
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        _stop_git_process(process)
        raise ValueError("Git变更输出无法读取")
    entries: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    try:
        while True:
            raw_status = _read_nul_field(process.stdout, 16)
            if raw_status is None:
                break
            raw_path = _read_nul_field(process.stdout, MAX_PATH_BYTES)
            if raw_path is None:
                raise ValueError("Git变更路径输出不完整")
            status = raw_status.decode("ascii", errors="strict")
            path = raw_path.decode("utf-8", errors="strict")
            if (
                status not in {"A", "M", "D"}
                or not path
                or len(path) > MAX_PATH_LENGTH
                or path in seen_paths
            ):
                raise ValueError("Git变更路径输出无效")
            seen_paths.add(path)
            entries.append((status, path))
            if len(entries) > MAX_CHANGED_FILES:
                raise ValueError("变更文件数超过500")
        if process.wait() != 0:
            raise ValueError("Git变更命令执行失败")
        return tuple(entries)
    finally:
        _stop_git_process(process)
        process.stdout.close()


def _read_git_output_bounded(
    repo_root: Path,
    arguments: Sequence[str],
    max_bytes: int,
    *,
    literal_paths: bool = False,
) -> bytes:
    environment = None
    if literal_paths:
        environment = os.environ.copy()
        environment["GIT_LITERAL_PATHSPECS"] = "1"
    process = subprocess.Popen(
        ["git", *arguments],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    if process.stdout is None:
        _stop_git_process(process)
        raise ValueError("Git命令输出无法读取")
    try:
        output = process.stdout.read(max_bytes + 1)
        if len(output) > max_bytes:
            raise ValueError("Git命令输出超出上限")
        if process.wait() != 0:
            raise ValueError("Git命令执行失败")
        return output
    finally:
        _stop_git_process(process)
        process.stdout.close()


def _load_object_metadata_batch(
    repo_root: Path,
    head_ref: str,
    entries: Sequence[tuple[str, str]],
) -> tuple[_PathObjectMetadata, ...]:
    present_entries = tuple(
        (status, path) for status, path in entries if status in {"A", "M"}
    )
    if not present_entries:
        return ()
    paths = tuple(path for _, path in present_entries)
    tree_output = _read_git_output_bounded(
        repo_root,
        ["ls-tree", "-z", head_ref, "--", *paths],
        len(paths) * (MAX_PATH_BYTES + 256),
        literal_paths=True,
    )
    records = tuple(record for record in tree_output.split(b"\0") if record)
    if len(records) != len(paths):
        raise ValueError("Git路径对象数量不匹配")

    tree_by_path: dict[str, tuple[str, str, str]] = {}
    expected_paths = set(paths)
    for record in records:
        try:
            raw_metadata, raw_path = record.split(b"\t", 1)
            mode_bytes, type_bytes, oid_bytes = raw_metadata.split(b" ")
            mode = mode_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
            oid = oid_bytes.decode("ascii", errors="strict")
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Git路径对象元数据无效") from error
        if (
            path not in expected_paths
            or path in tree_by_path
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", oid) is None
        ):
            raise ValueError("Git路径对象元数据不匹配")
        tree_by_path[path] = (mode, object_type, oid)
    if set(tree_by_path) != expected_paths:
        raise ValueError("Git路径对象缺失或额外")

    unique_oids = tuple(
        dict.fromkeys(tree_by_path[path][2] for path in paths)
    )
    batch_input = b"".join(oid.encode("ascii") + b"\n" for oid in unique_oids)
    batch_result = subprocess.run(
        [
            "git",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        input=batch_input,
    )
    if batch_result.returncode != 0:
        raise ValueError("Git对象元数据批量读取失败")
    batch_lines = batch_result.stdout.splitlines()
    if len(batch_lines) != len(unique_oids):
        raise ValueError("Git对象元数据数量不匹配")

    object_facts: dict[str, tuple[str, int]] = {}
    for expected_oid, line in zip(unique_oids, batch_lines, strict=True):
        try:
            oid_bytes, type_bytes, size_bytes = line.split(b" ")
            oid = oid_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Git对象元数据无效") from error
        if (
            oid != expected_oid
            or oid in object_facts
            or re.fullmatch(rb"[0-9]+", size_bytes) is None
        ):
            raise ValueError("Git对象元数据不匹配")
        object_facts[oid] = (object_type, int(size_bytes))

    metadata: list[_PathObjectMetadata] = []
    for status, path in present_entries:
        mode, tree_type, oid = tree_by_path[path]
        batch_type, size = object_facts[oid]
        if tree_type != batch_type:
            raise ValueError("Git对象类型不一致")
        metadata.append(
            _PathObjectMetadata(
                path=path,
                status=status,
                mode=mode,
                object_type=tree_type,
                oid=oid,
                size=size,
            )
        )
    return tuple(metadata)


def _read_blob_bounded(repo_root: Path, oid: str, expected_size: int) -> bytes:
    process = subprocess.Popen(
        ["git", "cat-file", "blob", oid],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise ValueError("Git对象正文无法读取")
    with process.stdout:
        content = process.stdout.read(expected_size + 1)
    if len(content) > expected_size:
        process.kill()
        process.wait()
        raise ValueError("Git对象正文超出已验证大小")
    return_code = process.wait()
    if return_code != 0 or len(content) != expected_size:
        raise ValueError("Git对象正文与元数据不一致")
    return content


def _load_path_facts(
    repo_root: Path,
    base_ref: str,
    head_ref: str,
) -> tuple[PathFact, ...]:
    """从Git对象读取路径事实，资源门通过前不读取正文。"""

    entries = _stream_diff_entries(repo_root, base_ref, head_ref)
    metadata = _load_object_metadata_batch(repo_root, head_ref, entries)
    deleted_paths = {path for status, path in entries if status == "D"}

    total_size = sum(item.size for item in metadata)
    resource_limit_exceeded = (
        len(entries) > MAX_CHANGED_FILES
        or any(item.size > MAX_FILE_SIZE for item in metadata)
        or total_size > MAX_TOTAL_SIZE
    )
    metadata_by_path = {item.path: item for item in metadata}
    facts: list[PathFact] = []
    for status, path in entries:
        if path in deleted_paths:
            facts.append(
                PathFact(
                    path=path,
                    status=status,
                    mode="000000",
                    object_type="missing",
                    size=0,
                    text=None,
                )
            )
            continue
        item = metadata_by_path[path]
        text: str | None = None
        if not resource_limit_exceeded and item.object_type == "blob":
            content = _read_blob_bounded(repo_root, item.oid, item.size)
            try:
                text = content.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                text = None
        facts.append(
            PathFact(
                path=path,
                status=item.status,
                mode=item.mode,
                object_type=item.object_type,
                size=item.size,
                text=text,
            )
        )
    return tuple(facts)


def _is_low_risk_path(path: str) -> bool:
    if path in ALLOWED_ROOT_MARKDOWN:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) > 1
        and pure_path.parts[0] == "docs"
        and pure_path.suffix == ".md"
    )


def _is_automation_path(path: str) -> bool:
    if _is_low_risk_path(path) or path in AUTOMATION_FILES:
        return True
    pure_path = PurePosixPath(path)
    return (
        len(pure_path.parts) == 3
        and pure_path.parts[0] in {"scripts", "tests"}
        and pure_path.parts[1] == "研发中心"
        and pure_path.suffix == ".py"
    )


def _is_controlled_rd_path(path: str) -> bool:
    pure_path = PurePosixPath(path)
    if (
        pure_path.is_absolute()
        or any(part in {".", ".."} for part in path.split("/"))
        or len(pure_path.parts) <= 1
    ):
        return False
    root = pure_path.parts[0]
    suffix = pure_path.suffix.lower()
    if root == "docs":
        return suffix == ".md"
    if root == "config":
        return suffix in {".json", ".yaml", ".yml", ".toml"}
    if root == "src":
        return suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}
    if root == "scripts":
        return (
            not any(
                part in {"交易", "部署", "生产"}
                for part in pure_path.parts[1:-1]
            )
            and suffix in {".py", ".sh"}
        )
    if root == "tests":
        return suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".json"}
    if root == "artifacts":
        return suffix in {".json", ".csv", ".md"}
    return False


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _normalize_double_quoted_keys(text: str) -> str | None:
    """仅规范化配置键中严格的Unicode码点转义。"""

    invalid = False

    def replace(match: re.Match[str]) -> str:
        nonlocal invalid
        key = match.group("key")
        normalized: list[str] = []
        index = 0
        while index < len(key):
            character = key[index]
            if character != "\\":
                normalized.append(character)
                index += 1
                continue
            if index + 1 >= len(key):
                invalid = True
                return match.group(0)
            marker = key[index + 1]
            if marker not in {"x", "u", "U"}:
                normalized.extend((character, marker))
                index += 2
                continue
            digit_count = {"x": 2, "u": 4, "U": 8}[marker]
            digits_start = index + 2
            digits_end = digits_start + digit_count
            digits = key[digits_start:digits_end]
            if (
                len(digits) != digit_count
                or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None
            ):
                invalid = True
                return match.group(0)
            codepoint = int(digits, 16)
            if (
                codepoint > 0x10FFFF
                or 0xD800 <= codepoint <= 0xDFFF
            ):
                invalid = True
                return match.group(0)
            decoded = chr(codepoint)
            if not decoded.isprintable():
                invalid = True
                return match.group(0)
            normalized.append(decoded)
            index = digits_end
        normalized_key = "".join(normalized)
        if not all(character.isprintable() for character in normalized_key):
            invalid = True
            return match.group(0)
        return f'"{normalized_key}"{match.group("suffix")}'

    normalized_text = DOUBLE_QUOTED_KEY_PATTERN.sub(replace, text)
    return None if invalid else normalized_text


def _contains_sensitive_text(text: str) -> bool:
    if any(pattern.search(text) for pattern in SENSITIVE_TEXT_PATTERNS):
        return True
    normalized = _normalize_double_quoted_keys(text)
    if normalized is None:
        return True
    return any(pattern.search(normalized) for pattern in SENSITIVE_TEXT_PATTERNS)


def _validate_path_facts(
    changed_paths: Sequence[str],
    path_facts: Sequence[PathFact] | None,
) -> tuple[str, ...]:
    """验证路径事实的完整性、Git对象、资源与敏感内容硬门。"""

    if path_facts is None:
        return ("PR缺少可验证的路径事实",)

    reasons: list[str] = []
    fact_paths = [fact.path for fact in path_facts]
    if (
        len(changed_paths) != len(set(changed_paths))
        or len(fact_paths) != len(set(fact_paths))
        or set(fact_paths) != set(changed_paths)
    ):
        _append_reason(reasons, "路径事实与变更路径不一致")

    if len(path_facts) > MAX_CHANGED_FILES:
        _append_reason(reasons, "变更文件数超过500")

    total_size = 0
    for fact in path_facts:
        valid_size = (
            isinstance(fact.size, int)
            and not isinstance(fact.size, bool)
            and fact.size >= 0
        )
        if (
            fact.status not in {"A", "M"}
            or fact.mode != "100644"
            or fact.object_type != "blob"
            or not valid_size
        ):
            _append_reason(reasons, "路径事实不允许自动合并")
        if valid_size:
            total_size += fact.size
            if fact.size > MAX_FILE_SIZE:
                _append_reason(reasons, "单个文件超过5MiB")
        if not isinstance(fact.text, str):
            _append_reason(reasons, "路径事实缺少可扫描文本")
        elif _contains_sensitive_text(fact.text):
            _append_reason(reasons, "变更文本包含敏感内容")

    if total_size > MAX_TOTAL_SIZE:
        _append_reason(reasons, "变更总量超过25MiB")
    return tuple(reasons)


def _without_mutable_metadata_lines(
    text: str, prefixes: Sequence[str]
) -> tuple[str, ...]:
    """只移除任务头部允许变化的唯一元数据行。"""

    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    return tuple(
        line
        for index, line in enumerate(lines)
        if not (
            index < first_section
            and any(line.startswith(prefix) for prefix in prefixes)
        )
    )


def _has_unique_metadata_fields(
    text: str,
    expected_counts: Mapping[str, int],
) -> bool:
    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )
    for prefix, expected_count in expected_counts.items():
        locations = [
            index for index, line in enumerate(lines) if line.startswith(prefix)
        ]
        if len(locations) != expected_count or any(
            index >= first_section for index in locations
        ):
            return False
    return True


def _successor_mutable_layout(
    text: str,
) -> tuple[str, int, int, int] | None:
    """定位后继字段的固定任务头或依赖章节布局。"""

    lines = text.splitlines()
    first_section = next(
        (index for index, line in enumerate(lines) if line.startswith("## ")),
        len(lines),
    )

    def locations(prefix: str) -> list[int]:
        return [
            index
            for index, line in enumerate(lines)
            if line.startswith(prefix)
        ]

    status_locations = locations("- 状态：")
    if len(status_locations) != 1 or status_locations[0] >= first_section:
        return None
    blocker_locations = locations("- 当前阻塞原因：")
    release_locations = locations("- 解除条件：")
    if len(blocker_locations) != 1 or len(release_locations) != 1:
        return None
    mutable_locations = blocker_locations + release_locations
    if all(index < first_section for index in mutable_locations):
        return "header", first_section, -1, first_section

    section_headings = [
        index
        for index, line in enumerate(lines)
        if line.strip() == "## 依赖与阻塞条件"
    ]
    if len(section_headings) != 1:
        return None
    section_start = section_headings[0]
    section_end = next(
        (
            index
            for index in range(section_start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    if not all(section_start < index < section_end for index in mutable_locations):
        return None
    return "dependency_section", first_section, section_start, section_end


def _without_successor_mutable_lines(text: str) -> tuple[str, ...]:
    """移除已验证位置中的后继状态、阻塞原因与解除条件。"""

    layout = _successor_mutable_layout(text)
    if layout is None:
        return tuple(text.splitlines())
    kind, first_section, section_start, section_end = layout
    return tuple(
        line
        for index, line in enumerate(text.splitlines())
        if not (
            (index < first_section and line.startswith("- 状态："))
            or (
                (
                    index < first_section
                    if kind == "header"
                    else section_start < index < section_end
                )
                and line.startswith(("- 当前阻塞原因：", "- 解除条件："))
            )
        )
    )


def _task_merge_fact(text: str) -> MergeFact | None:
    sha_match = MERGE_SHA_PATTERN.search(text)
    time_match = MERGE_TIME_PATTERN.search(text)
    pr_match = PULL_REQUEST_PATTERN.search(text)
    if sha_match is None or time_match is None or pr_match is None:
        return None
    return MergeFact(
        sha=sha_match.group(1),
        merged_at=time_match.group(1),
        pr_number=int(pr_match.group(1)),
    )


def _board_rows(text: str) -> dict[str, tuple[str, str]]:
    """读取看板中任务所在状态和完整行。"""

    current_section = ""
    rows: dict[str, tuple[str, str]] = {}
    duplicates: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
            continue
        match = BOARD_TASK_ROW_PATTERN.match(line)
        if match is None:
            continue
        task_id = match.group(1)
        if task_id in rows:
            duplicates.add(task_id)
        rows[task_id] = (current_section, line)
    for task_id in duplicates:
        rows[task_id] = ("重复", "")
    return rows


def _board_static_lines(text: str) -> tuple[str, ...]:
    """保留看板非表格、非空态的静态结构。"""

    static: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "无。" or BOARD_TASK_ROW_PATTERN.match(line):
            continue
        known_schema_lines = {
            schema_line
            for schema in BOARD_TABLE_SCHEMA.values()
            for schema_line in schema
        }
        if line in known_schema_lines:
            continue
        static.append(line)
    return tuple(static)


def _board_schema_is_valid(text: str) -> bool:
    current_section = ""
    schema_counts: dict[str, dict[str, int]] = {}
    task_sections: set[str] = set()
    for line in text.splitlines():
        if line.startswith("## "):
            current_section = line[3:].strip()
            continue
        if not line.startswith("|"):
            continue
        if BOARD_TASK_ROW_PATTERN.match(line):
            task_sections.add(current_section)
            continue
        schema = BOARD_TABLE_SCHEMA.get(current_section)
        if schema is None or line not in schema:
            return False
        counts = schema_counts.setdefault(current_section, {})
        counts[line] = counts.get(line, 0) + 1
    for section in task_sections:
        schema = BOARD_TABLE_SCHEMA.get(section)
        counts = schema_counts.get(section, {})
        if schema is None or any(counts.get(line) != 1 for line in schema):
            return False
    return all(count <= 1 for counts in schema_counts.values() for count in counts.values())


def _validate_board_closure(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    merge_facts: Mapping[str, MergeFact],
    reasons: list[str],
) -> None:
    if base_board is None or head_board is None:
        _append_reason(reasons, "合并后状态闭环缺少可复算看板")
        return
    if not _board_schema_is_valid(base_board) or not _board_schema_is_valid(head_board):
        _append_reason(reasons, "合并后状态闭环看板表格结构无效")
    if _board_static_lines(base_board) != _board_static_lines(head_board):
        _append_reason(reasons, "合并后状态闭环夹带看板结构改写")
    base_rows = _board_rows(base_board)
    head_rows = _board_rows(head_board)
    referenced = set(task_ids)
    for task_id, row in base_rows.items():
        if task_id not in referenced and head_rows.get(task_id) != row:
            _append_reason(reasons, f"看板夹带无关任务-{task_id}改写")
    for task_id, row in head_rows.items():
        if task_id not in referenced and base_rows.get(task_id) != row:
            _append_reason(reasons, f"看板夹带无关任务-{task_id}改写")
    for task_id in task_ids:
        task = head_tasks.get(task_id)
        row = head_rows.get(task_id)
        if task is None or row is None or row[0] == "重复":
            _append_reason(reasons, f"任务-{task_id}在看板中不是唯一映射")
            continue
        status = _task_field(TASK_STATUS_PATTERN, task)
        if row[0] != status:
            _append_reason(reasons, f"任务-{task_id}的看板状态与任务文件不一致")
            continue
        title = _task_field(TASK_TITLE_PATTERN, task)
        priority = _task_field(TASK_PRIORITY_PATTERN, task)
        if status == "已完成":
            fact = merge_facts.get(task_id)
            expected = (
                f"| 任务-{task_id} | {title} | PR #{fact.pr_number}；合并提交 `{fact.sha}` |"
                if title is not None and fact is not None
                else ""
            )
        elif status == "待执行":
            dependency = _task_field(DEPENDENCY_PATTERN, task)
            expected = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
                if title is not None and priority is not None and dependency is not None
                else ""
            )
        else:
            expected = ""
        if row[1] != expected:
            _append_reason(reasons, f"任务-{task_id}的看板证据行不可复算")


def _validate_delivery_tasks(
    *,
    task_ids: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    reasons: list[str],
) -> tuple[bool, bool]:
    automation_authorized = bool(task_ids)
    controlled_rd_authorized = bool(task_ids)
    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        if base_task is None:
            _append_reason(reasons, f"任务-{task_id}未在基线main中登记")
            automation_authorized = False
            controlled_rd_authorized = False
            continue
        task_type = _task_field(TASK_TYPE_PATTERN, base_task)
        if task_type is None:
            _append_reason(reasons, f"任务-{task_id}缺少任务类型")
        elif task_type not in ALLOWED_TASK_TYPES:
            _append_reason(
                reasons,
                f"任务-{task_id}类型“{task_type}”不允许自动合并",
            )
        if task_type not in CONTROLLED_RD_TASK_TYPES:
            controlled_rd_authorized = False
        base_status = _task_field(TASK_STATUS_PATTERN, base_task)
        if base_status not in DELIVERY_BASE_STATUSES:
            _append_reason(
                reasons,
                f"任务-{task_id}基线状态“{base_status}”不可进入任务交付",
            )
        if _task_field(AUTOMATION_SCOPE_PATTERN, base_task) != AUTOMATION_SCOPE:
            automation_authorized = False

        head_task = head_tasks.get(task_id)
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
        elif _task_field(TASK_STATUS_PATTERN, head_task) != "待评审":
            _append_reason(reasons, f"任务-{task_id}在PR中的状态不是“待评审”")
    return automation_authorized, controlled_rd_authorized


def _registration_field_value(text: str, field: str) -> str | None:
    """读取任务头部严格唯一且非空的合同字段。"""

    lines = text.splitlines()
    first_section = next(
        (
            index
            for index, line in enumerate(lines)
            if (
                (parsed := _commonmark_atx_heading(line)) is not None
                and parsed[0] == 2
            )
        ),
        len(lines),
    )
    prefix = f"- {field}："
    locations = [
        index for index, line in enumerate(lines) if line.startswith(prefix)
    ]
    if len(locations) != 1 or locations[0] >= first_section:
        return None
    value = lines[locations[0]][len(prefix):].strip()
    return value or None


def _validate_registration_board(
    *,
    task_id: str,
    task: str,
    base_board: str | None,
    head_board: str | None,
    reasons: list[str],
) -> None:
    """验证看板仅新增一条可由任务合同复算的映射。"""

    mapping_reason = f"任务-{task_id}在看板中不是唯一可复算新增映射"
    if base_board is None or head_board is None:
        _append_reason(reasons, mapping_reason)
        return
    if not _board_schema_is_valid(base_board) or not _board_schema_is_valid(
        head_board
    ):
        _append_reason(reasons, mapping_reason)
    base_rows = _board_rows(base_board)
    head_rows = _board_rows(head_board)
    if (
        task_id in base_rows
        or _board_static_lines(base_board) != _board_static_lines(head_board)
        or {
            key: value for key, value in base_rows.items() if key != task_id
        }
        != {
            key: value for key, value in head_rows.items() if key != task_id
        }
    ):
        _append_reason(reasons, mapping_reason)

    title_matches = TASK_TITLE_WITH_ID_PATTERN.findall(task)
    status = _registration_field_value(task, "状态")
    priority = _registration_field_value(task, "优先级")
    dependency = _task_field(DEPENDENCY_PATTERN, task)
    expected_row = ""
    if (
        len(title_matches) == 1
        and title_matches[0][0] == task_id
        and title_matches[0][1].strip()
        and priority is not None
        and dependency is not None
    ):
        title = title_matches[0][1].strip()
        if status == "待执行":
            expected_row = (
                f"| {priority} | 任务-{task_id} | {title} | {dependency} |"
            )
        elif status == "阻塞":
            blocker = _task_field(BLOCKER_PATTERN, task)
            if blocker is not None:
                blocker = blocker.rstrip("；。")
                expected_row = (
                    f"| {priority} | 任务-{task_id} | {title} | "
                    f"{dependency} | {blocker} |"
                )
    row = head_rows.get(task_id)
    if (
        row is None
        or row[0] == "重复"
        or row[0] != status
        or not expected_row
        or row[1] != expected_row
    ):
        _append_reason(reasons, mapping_reason)


def _validate_task_registration(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_task_ids: Sequence[str] | None,
    base_board: str | None,
    head_board: str | None,
    path_facts: Sequence[PathFact] | None,
    reasons: list[str],
) -> None:
    """按基线Git事实验证单个完整新任务合同登记。"""

    if len(task_ids) != 1:
        _append_reason(reasons, "任务登记必须且只能引用一个新任务")
        return
    task_id = task_ids[0]
    task_path = f"docs/研发中心/任务/任务-{task_id}.md"

    raw_base_ids = tuple(base_task_ids) if base_task_ids is not None else tuple(base_tasks)
    valid_base_ids = (
        bool(raw_base_ids)
        and len(raw_base_ids) == len(set(raw_base_ids))
        and all(re.fullmatch(r"\d{6}", item) for item in raw_base_ids)
    )
    if not valid_base_ids:
        _append_reason(reasons, "基线任务编号事实无效")
    else:
        maximum = max(int(item) for item in raw_base_ids)
        expected = maximum + 1
        if task_id in HISTORICAL_MISSING_TASK_IDS:
            _append_reason(reasons, f"任务-{task_id}历史缺号禁止复用")
        if int(task_id) != expected:
            _append_reason(
                reasons,
                f"任务-{task_id}编号必须为基线最大编号"
                f"{maximum:06d}的下一编号{expected:06d}",
            )

    if task_id in base_tasks or task_id in raw_base_ids:
        _append_reason(reasons, f"任务-{task_id}已在基线main中登记")
    task = head_tasks.get(task_id)
    if task is None:
        _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
    else:
        for field in REQUIRED_TASK_FIELDS:
            if _registration_field_value(task, field) is None:
                _append_reason(
                    reasons,
                    f"任务-{task_id}合同字段“{field}”必须且只能出现一次",
                )
        for heading in REQUIRED_TASK_HEADINGS:
            count = _second_level_heading_count(task, heading)
            if count != 1:
                _append_reason(
                    reasons,
                    f"任务-{task_id}合同章节“{heading}”必须且只能出现一次",
                )
        title_matches = TASK_TITLE_WITH_ID_PATTERN.findall(task)
        if (
            len(title_matches) != 1
            or title_matches[0][0] != task_id
            or not title_matches[0][1].strip()
        ):
            _append_reason(reasons, f"任务-{task_id}合同标题与文件编号不一致")
        status = _registration_field_value(task, "状态")
        if status not in REGISTRATION_STATUSES:
            _append_reason(
                reasons,
                f"任务-{task_id}在PR中的状态“{status}”不可登记",
            )
        if _registration_field_value(task, "方案状态") != "已批准执行":
            _append_reason(
                reasons,
                f"任务-{task_id}方案状态不是“已批准执行”",
            )
        dependency_lines = [
            line
            for line in task.splitlines()
            if line.startswith("- 唯一前序依赖：")
        ]
        dependencies = DEPENDENCY_PATTERN.findall(task)
        if len(dependency_lines) != 1 or len(dependencies) != 1:
            _append_reason(
                reasons,
                f"任务-{task_id}唯一前序依赖必须且只能出现一次",
            )
        if status == "阻塞":
            blocker_lines = [
                line
                for line in task.splitlines()
                if line.startswith("- 当前阻塞原因：")
            ]
            blockers = BLOCKER_PATTERN.findall(task)
            if (
                len(blocker_lines) != 1
                or len(blockers) != 1
                or not blockers[0].strip()
            ):
                _append_reason(
                    reasons,
                    f"任务-{task_id}阻塞原因必须且只能出现一次且非空",
                )

    if REGISTRATION_BOARD_PATH not in changed_paths:
        _append_reason(reasons, "任务登记必须同步看板")

    design_paths = tuple(
        path
        for path in changed_paths
        if REGISTRATION_DESIGN_PATTERN.fullmatch(path)
    )
    allowed_paths = {
        task_path,
        REGISTRATION_BOARD_PATH,
        *design_paths,
    }
    for path in changed_paths:
        if path not in allowed_paths:
            _append_reason(reasons, f"任务登记包含不允许路径“{path}”")
    if len(design_paths) != 1:
        _append_reason(reasons, "任务登记必须且只能新增一个对应设计文档")

    facts_by_path = (
        {fact.path: fact for fact in path_facts}
        if path_facts is not None
        else {}
    )
    task_fact = facts_by_path.get(task_path)
    if task_fact is None or task_fact.status != "A":
        _append_reason(reasons, f"任务-{task_id}任务文件必须是新增普通文件")
    for design_path in design_paths:
        design_fact = facts_by_path.get(design_path)
        if design_fact is None or design_fact.status != "A":
            _append_reason(reasons, "任务登记对应设计文档必须是新增普通文件")
        elif re.search(
            rf"(?<!\d)任务-{re.escape(task_id)}(?!\d)",
            design_fact.text or "",
        ) is None:
            _append_reason(reasons, f"任务登记设计文档未对应任务-{task_id}")
    board_fact = facts_by_path.get(REGISTRATION_BOARD_PATH)
    if REGISTRATION_BOARD_PATH in changed_paths and (
        board_fact is None or board_fact.status != "M"
    ):
        _append_reason(reasons, "任务登记看板必须是对基线看板的修改")
    if task is not None:
        _validate_registration_board(
            task_id=task_id,
            task=task,
            base_board=base_board,
            head_board=head_board,
            reasons=reasons,
        )


def _validate_state_closure(
    *,
    task_ids: Sequence[str],
    changed_paths: Sequence[str],
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_board: str | None,
    head_board: str | None,
    merge_facts: Mapping[str, MergeFact],
    reasons: list[str],
) -> None:
    completed = 0
    unlocked = 0
    completed_task_id: str | None = None
    transitions: dict[str, tuple[str | None, str | None]] = {}
    if "docs/研发中心/看板.md" not in changed_paths:
        _append_reason(reasons, "合并后状态闭环必须同步看板")
    for path in changed_paths:
        if path == "docs/研发中心/看板.md" or TASK_FILE_PATTERN.fullmatch(path):
            continue
        _append_reason(reasons, f"合并后状态闭环包含非状态文件“{path}”")

    for task_id in task_ids:
        base_task = base_tasks.get(task_id)
        head_task = head_tasks.get(task_id)
        if base_task is None:
            _append_reason(reasons, f"任务-{task_id}未在基线main中登记")
            continue
        if head_task is None:
            _append_reason(reasons, f"任务-{task_id}未包含在PR头提交中")
            continue
        old_status = _task_field(TASK_STATUS_PATTERN, base_task)
        new_status = _task_field(TASK_STATUS_PATTERN, head_task)
        transitions[task_id] = (old_status, new_status)
        if (old_status, new_status) not in STATE_CLOSURE_TRANSITIONS:
            _append_reason(
                reasons,
                f"任务-{task_id}存在非法状态闭环“{old_status}→{new_status}”",
            )
        if (old_status, new_status) == ("待评审", "已完成"):
            completed += 1
            completed_task_id = task_id
            declared_fact = _task_merge_fact(head_task)
            if declared_fact is None:
                _append_reason(reasons, f"任务-{task_id}缺少真实合并证据")
            if declared_fact != merge_facts.get(task_id):
                _append_reason(
                    reasons,
                    f"任务-{task_id}合并证据与main真实事实不一致",
                )
            fields_valid = _has_unique_metadata_fields(
                base_task,
                {"- 状态：": 1, "- 合并时间：": 0, "- 合并提交SHA：": 0},
            ) and _has_unique_metadata_fields(
                head_task,
                {"- 状态：": 1, "- 合并时间：": 1, "- 合并提交SHA：": 1},
            )
            if not fields_valid or _without_mutable_metadata_lines(
                base_task, COMPLETION_MUTABLE_PREFIXES
            ) != _without_mutable_metadata_lines(
                head_task, COMPLETION_MUTABLE_PREFIXES
            ):
                _append_reason(reasons, f"任务-{task_id}状态闭环夹带合同改写")
        if (old_status, new_status) == ("阻塞", "待执行"):
            unlocked += 1
    if completed != 1:
        _append_reason(reasons, "合并后状态闭环必须且只能完成一个待评审任务")
    if unlocked > 1:
        _append_reason(reasons, "合并后状态闭环最多解除一个唯一后继")
    for task_id, transition in transitions.items():
        if transition != ("阻塞", "待执行"):
            continue
        base_task = base_tasks[task_id]
        head_task = head_tasks[task_id]
        dependency = _task_field(DEPENDENCY_PATTERN, base_task)
        if completed_task_id is None or dependency != completed_task_id:
            _append_reason(
                reasons,
                f"任务-{task_id}不是任务-{completed_task_id or '未知'}的唯一后继",
            )
        base_layout = _successor_mutable_layout(base_task)
        head_layout = _successor_mutable_layout(head_task)
        fields_valid = base_layout is not None and base_layout == head_layout
        if not fields_valid or _without_successor_mutable_lines(
            base_task
        ) != _without_successor_mutable_lines(head_task):
            _append_reason(reasons, f"任务-{task_id}状态闭环夹带合同改写")
        expected_blocker = (
            f"- 当前阻塞原因：无；任务-{completed_task_id}已完成。"
            if completed_task_id is not None
            else ""
        )
        if expected_blocker not in head_task.splitlines() or "- 解除条件：已满足。" not in head_task.splitlines():
            _append_reason(reasons, f"任务-{task_id}未如实登记唯一后继解锁")
    _validate_board_closure(
        task_ids=task_ids,
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_board=base_board,
        head_board=head_board,
        merge_facts=merge_facts,
        reasons=reasons,
    )


def evaluate_eligibility(
    *,
    changed_paths: Sequence[str],
    pr_body: str,
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_task_ids: Sequence[str] | None = None,
    base_branch: str,
    repository: str,
    head_repository: str,
    merge_facts: Mapping[str, MergeFact] | None = None,
    base_board: str | None = None,
    head_board: str | None = None,
    path_facts: Sequence[PathFact] | None = None,
) -> EligibilityResult:
    """按基线任务合同、严格PR合同和变更路径判定资格。"""

    reasons: list[str] = []
    for reason in _validate_path_facts(changed_paths, path_facts):
        _append_reason(reasons, reason)
    if base_branch != "main":
        _append_reason(reasons, "目标分支不是main")
    if repository != "xk320/zhishi" or head_repository != repository:
        _append_reason(reasons, "外部仓库PR不允许自动合并")
    if not changed_paths:
        _append_reason(reasons, "PR没有可验证的变更路径")

    task_ids = parse_task_references(pr_body)
    if not task_ids:
        _append_reason(reasons, "PR正文未引用任务编号")
    change_type = parse_change_type(pr_body)
    if change_type is None:
        _append_reason(reasons, "PR正文缺少有效变更类型")
    if len(task_ids) > _task_reference_limit(change_type):
        _append_reason(reasons, _task_reference_limit_reason(change_type))

    automation_authorized = False
    controlled_rd_authorized = False
    if change_type == "任务登记":
        _validate_task_registration(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_task_ids=base_task_ids,
            base_board=base_board,
            head_board=head_board,
            path_facts=path_facts,
            reasons=reasons,
        )
    elif change_type == "任务交付":
        automation_authorized, controlled_rd_authorized = (
            _validate_delivery_tasks(
                task_ids=task_ids,
                base_tasks=base_tasks,
                head_tasks=head_tasks,
                reasons=reasons,
            )
        )
    elif change_type == "合并后状态闭环":
        _validate_state_closure(
            task_ids=task_ids,
            changed_paths=changed_paths,
            base_tasks=base_tasks,
            head_tasks=head_tasks,
            base_board=base_board,
            head_board=head_board,
            merge_facts=merge_facts or {},
            reasons=reasons,
        )

    referenced_task_ids = set(task_ids)
    changed_task_ids: set[str] = set()
    for path in changed_paths:
        task_file_match = TASK_FILE_PATTERN.fullmatch(path)
        if task_file_match is not None:
            changed_task_ids.add(task_file_match.group(1))
            if task_file_match.group(1) not in referenced_task_ids:
                _append_reason(
                    reasons,
                    f"修改了未在PR正文引用的任务-{task_file_match.group(1)}",
                )

        if change_type == "任务交付":
            allowed = (
                _is_automation_path(path)
                if automation_authorized
                else (
                    _is_controlled_rd_path(path)
                    if controlled_rd_authorized
                    else _is_low_risk_path(path)
                )
            )
            if not allowed:
                _append_reason(reasons, f"变更路径“{path}”不允许自动合并")

    for task_id in task_ids:
        if task_id not in changed_task_ids:
            _append_reason(reasons, f"任务-{task_id}的任务文件未在PR中更新")

    return EligibilityResult(eligible=not reasons, reasons=tuple(reasons))


def _read_task_at_ref(repo_root: Path, ref: str, task_id: str) -> str | None:
    task_path = f"docs/研发中心/任务/任务-{task_id}.md"
    result = subprocess.run(
        ["git", "show", f"{ref}:{task_path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _read_path_at_ref(repo_root: Path, ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def _load_ref_tasks(
    repo_root: Path,
    ref: str,
    task_ids: Sequence[str],
) -> dict[str, str]:
    tasks: dict[str, str] = {}
    for task_id in task_ids:
        content = _read_task_at_ref(repo_root, ref, task_id)
        if content is not None:
            tasks[task_id] = content
    return tasks


def _load_ref_task_ids(repo_root: Path, ref: str) -> tuple[str, ...]:
    """从基线Git树有界加载全部任务编号，不读取合同正文。"""

    output = _read_git_output_bounded(
        repo_root,
        [
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            ref,
            "--",
            "docs/研发中心/任务",
        ],
        MAX_BASE_TASK_TREE_BYTES,
        literal_paths=True,
    )
    paths = parse_nul_paths(output)
    if len(paths) > MAX_BASE_TASK_COUNT:
        raise ValueError("基线任务文件数超出上限")
    task_ids = tuple(
        match.group(1)
        for path in paths
        if (match := TASK_FILE_PATTERN.fullmatch(path)) is not None
    )
    if not task_ids or len(task_ids) != len(set(task_ids)):
        raise ValueError("基线任务编号事实无效")
    return tuple(sorted(task_ids))


def _git_text(repo_root: Path, arguments: Sequence[str]) -> str | None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _derive_merge_facts(
    repo_root: Path,
    base_ref: str,
    head_tasks: Mapping[str, str],
) -> dict[str, MergeFact]:
    """只从已进入main基线的Git提交推导合并事实。"""

    facts: dict[str, MergeFact] = {}
    for task_id, task in head_tasks.items():
        declared = _task_merge_fact(task)
        if declared is None:
            continue
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", declared.sha, base_ref],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        if ancestry.returncode != 0:
            continue
        subject = _git_text(repo_root, ["show", "-s", "--format=%s", declared.sha])
        committed_at = _git_text(
            repo_root, ["show", "-s", "--format=%cI", declared.sha]
        )
        if subject is None or committed_at is None:
            continue
        pr_match = re.fullmatch(r"Merge pull request #(\d+) from .+", subject)
        if pr_match is None:
            continue
        try:
            normalized_time = datetime.fromisoformat(committed_at).strftime(
                "%Y-%m-%d %H:%M:%S %z"
            )
        except ValueError:
            continue
        facts[task_id] = MergeFact(
            sha=declared.sha,
            merged_at=normalized_time,
            pr_number=int(pr_match.group(1)),
        )
    return facts


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="验证《知势》PR自动合并资格")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--metadata", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    repo_root = arguments.repo_root.resolve()
    metadata = json.loads(arguments.metadata.read_text(encoding="utf-8"))
    try:
        path_facts = _load_path_facts(
            repo_root,
            arguments.base_ref,
            arguments.head_ref,
        )
        base_task_ids = _load_ref_task_ids(
            repo_root,
            arguments.base_ref,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        print(
            json.dumps(
                {
                    "eligible": False,
                    "reasons": ["Git路径事实加载失败"],
                    "changed_paths": [],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    changed_paths = tuple(fact.path for fact in path_facts)
    pr_body = str(metadata.get("body", ""))
    change_type = parse_change_type(pr_body)
    task_ids = set(parse_task_references(pr_body))
    for path in changed_paths:
        match = TASK_FILE_PATTERN.fullmatch(path)
        if match is not None:
            task_ids.add(match.group(1))
    if len(task_ids) > _task_reference_limit(change_type):
        print(
            json.dumps(
                {
                    "eligible": False,
                    "reasons": [_task_reference_limit_reason(change_type)],
                    "changed_paths": list(changed_paths),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    ordered_ids = tuple(sorted(task_ids))

    base_tasks = _load_ref_tasks(repo_root, arguments.base_ref, ordered_ids)
    head_tasks = _load_ref_tasks(repo_root, arguments.head_ref, ordered_ids)
    result = evaluate_eligibility(
        changed_paths=changed_paths,
        pr_body=pr_body,
        base_tasks=base_tasks,
        head_tasks=head_tasks,
        base_task_ids=base_task_ids,
        base_branch=str(metadata.get("base_ref", "")),
        repository=str(metadata.get("repository", "")),
        head_repository=str(metadata.get("head_repository", "")),
        merge_facts=_derive_merge_facts(
            repo_root,
            arguments.base_ref,
            head_tasks,
        ),
        base_board=_read_path_at_ref(
            repo_root, arguments.base_ref, "docs/研发中心/看板.md"
        ),
        head_board=_read_path_at_ref(
            repo_root, arguments.head_ref, "docs/研发中心/看板.md"
        ),
        path_facts=path_facts,
    )
    print(
        json.dumps(
            {
                "eligible": result.eligible,
                "reasons": list(result.reasons),
                "changed_paths": list(changed_paths),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.eligible else 1


if __name__ == "__main__":
    raise SystemExit(main())
