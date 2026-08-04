#!/usr/bin/env python3
"""执行阶段1最终审计。

只读取仓库内已经合并的任务合同和不可变聚合证据，不访问服务器、数据库或原始市场数据。
审计结果按 BTC/ETH、主研究尺度和未知作用域逐叶子生成；任何未知或失败门均保持阻塞。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import NamedTemporaryFile


ROOT = Path(__file__).resolve().parents[2]
ASSETS = ("BTC", "ETH")
SCALES = ("4小时", "8小时", "24小时", "48小时")
POST_WINDOWS = ("15分钟", "1小时")
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_ROWS = 10_000

MERGE_COMMITS = {
    "任务-000029": "2e82443d8c309320a28325cc9f5bbdd00ae0cb49",
    "任务-000030": "cde23097fc0aa19d25a95dd70caa31a02c3b3b66",
    "任务-000031": "bf8a00f95cdf5be9d56b963e6fa8f29807dbb918",
    "任务-000032": "5fce9ee989ad222f716fe9648d8ad1ca3763ecdf",
    "任务-000033": "57d7c1e1e8f92a9eb649b6a9c8e44da0e041b629",
    "任务-000034": "6f9a65cd45a089b2d6791bbe2531d4bcf45bc84c",
    "任务-000035": "d1cdfca17c791a347887d20bf4e6be64c30c2234",
    "任务-000036": "fa062eb0fd0c4b9726a345248921f1b314873d1b",
}

MANIFESTS = {
    "任务-000029": "artifacts/数据/来源身份/source-identity-20260803T131620+0800-e7bc65038f21/身份清单.json",
    "任务-000030": "artifacts/数据/时间质量合同/time-quality-20260804T101703+0800-3d3afc62d002/合同清单.json",
    "任务-000031": "artifacts/审计/数据质量/dqv-20260805T005824+0800-95d2dd93a03d/验证清单.json",
    "任务-000032": "artifacts/审计/历史现场重放/replay-20260805T013610+0800-4492706a9320/验证清单.json",
    "任务-000033": "artifacts/数据/成本执行/cost-20260805T020500+0800-c2d7a91e5f40/验证清单.json",
    "任务-000034": "artifacts/审计/双标的数据闭环/loop-20260805T035900+0800-v4/验证清单.json",
    "任务-000035": "artifacts/数据/最小闭环试点/pilot-20260805T045300+0800-zero-v2/清单.json",
    "任务-000036": "artifacts/审计/容量恢复/capacity-20260804T212023Z/清单.json",
}

LOOP_CSV = "artifacts/审计/双标的数据闭环/loop-20260805T035900+0800-v4/闭环成员.csv"
PILOT_MEMBERS = "artifacts/数据/最小闭环试点/pilot-20260805T045300+0800-zero-v2/成员.csv"
CAPACITY_ROOT = "artifacts/审计/容量恢复/capacity-20260804T212023Z"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_with_crlf_normalization(path: Path) -> str:
    """复算旧批次以CRLF生成、被Git规范化为LF后的内容指纹。"""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        pending = b""
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            data = pending + block
            pending = b""
            if data.endswith(b"\r"):
                pending = b"\r"
                data = data[:-1]
            digest.update(data.replace(b"\n", b"\r\n"))
        if pending:
            digest.update(pending)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"输入文件超过32MiB上限：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def task_metadata(task_id: str) -> tuple[str, str]:
    text = (ROOT / "docs/研发中心/任务" / f"{task_id}.md").read_text(encoding="utf-8")
    status = re.search(r"^- 状态：(.+)$", text, re.MULTILINE)
    merge = re.search(r"^- 合并提交SHA：`([0-9a-f]{40})`$", text, re.MULTILINE)
    if not status or not merge:
        raise ValueError(f"{task_id}缺少完成状态或合并提交SHA")
    return status.group(1).strip(), merge.group(1)


def read_loop_rows(path: Path) -> list[dict[str, str]]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"闭环输入超过32MiB上限：{path}")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError(f"闭环成员数量不在有界范围：{len(rows)}")
    required = {
        "标的", "交易场所", "市场类型", "精确合约", "数据对象", "主研究尺度", "时间范围",
        "门1来源身份", "门2时间与质量合同", "门3质量审计", "门4历史重放", "门5成本与执行",
        "门6血缘", "最终状态", "资产编号", "来源成员编号",
    }
    if not required.issubset(rows[0]):
        raise ValueError(f"闭环成员缺少字段：{sorted(required - set(rows[0]))}")
    if len({(row["标的"], row["主研究尺度"], row["资产编号"], row["来源成员编号"]) for row in rows}) != len(rows):
        raise ValueError("闭环成员存在重复确定性键")
    for row in rows:
        if row["标的"] not in ASSETS or row["主研究尺度"] not in SCALES:
            raise ValueError(f"超出固定标的或研究尺度：{row}")
    return rows


def verify_upstream() -> dict:
    commits = {}
    manifests = {}
    for task_id, expected in MERGE_COMMITS.items():
        status, actual = task_metadata(task_id)
        if status != "已完成" or actual != expected:
            raise ValueError(f"{task_id}状态或合并提交不一致：{status} {actual}")
        path = ROOT / MANIFESTS[task_id]
        if not path.is_file():
            raise ValueError(f"缺少不可变输入批次：{path}")
        data = load_json(path)
        manifests[task_id] = {
            "路径": MANIFESTS[task_id],
            "文件SHA-256": sha256(path),
            "批次": data.get("验证批次") or data.get("批次") or data.get("来源身份批次"),
        }
        commits[task_id] = expected

    loop_path = ROOT / LOOP_CSV
    pilot_manifest = load_json(ROOT / MANIFESTS["任务-000035"])
    pilot_members = ROOT / PILOT_MEMBERS
    loop_hash = sha256(loop_path)
    if loop_hash != pilot_manifest["来源成员SHA256"]:
        raise ValueError("双标的数据闭环成员内容指纹不一致")
    if sha256(pilot_members) != pilot_manifest["成员SHA256"]:
        raise ValueError("最小闭环试点成员指纹不一致")
    capacity_manifest = load_json(ROOT / MANIFESTS["任务-000036"])
    if capacity_manifest.get("输入试点批次") != pilot_manifest.get("批次"):
        raise ValueError("容量恢复与最小闭环试点批次不一致")
    capacity_fingerprints = {}
    for name, expected_hash in capacity_manifest.get("输出文件", {}).items():
        output = ROOT / CAPACITY_ROOT / name
        if not output.is_file():
            raise ValueError(f"容量恢复输出指纹不一致：{output}")
        actual_hash = sha256(output)
        normalized_hash = sha256_with_crlf_normalization(output)
        if actual_hash != expected_hash and normalized_hash != expected_hash:
            raise ValueError(f"容量恢复输出指纹不一致：{output}")
        capacity_fingerprints[name] = {
            "期望SHA256": expected_hash,
            "Git检出字节SHA256": actual_hash,
            "CRLF规范化SHA256": normalized_hash,
            "匹配方式": "原始字节" if actual_hash == expected_hash else "CRLF规范化复算",
        }
    return {
        "合并提交": commits,
        "批次": manifests,
        "输入文件": {
            LOOP_CSV: loop_hash,
            PILOT_MEMBERS: sha256(pilot_members),
        },
        "容量输出指纹复算": capacity_fingerprints,
    }


def gate_value(rows: list[dict[str, str]], column: str) -> str:
    values = {row[column] for row in rows}
    if values == {"通过"}:
        return "通过"
    if "拒绝" in values or "失败" in values:
        return "拒绝"
    if "无法判定" in values or "未判定" in values or "未执行" in values:
        return "无法判定"
    return "无法判定"


def build_leaves(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], dict]:
    by_leaf: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_leaf[(row["标的"], row["主研究尺度"])].append(row)
    if set(by_leaf) != {(asset, scale) for asset in ASSETS for scale in SCALES}:
        raise ValueError("最终叶子未覆盖BTC/ETH和四个主研究尺度")

    leaves: list[dict[str, str]] = []
    for asset in ASSETS:
        for scale in SCALES:
            members = by_leaf[(asset, scale)]
            if len(members) != 315:
                raise ValueError(f"{asset}/{scale}候选总体不是315：{len(members)}")
            final = Counter("拒绝" if row["最终状态"] == "不可用" else row["最终状态"] for row in members)
            if set(final) - {"拒绝", "无法判定", "失败", "未成熟", "失效"}:
                raise ValueError(f"存在未登记最终状态：{final}")
            if sum(final.values()) != len(members):
                raise ValueError(f"{asset}/{scale}状态计数不守恒")
            leaves.append({
                "叶子编号": f"{asset}-{scale}", "标的": asset, "交易场所": "未知",
                "市场类型": "未知", "精确合约": "未知", "数据对象": "未知",
                "主研究尺度": scale, "时间范围": "无法判定", "候选总体": str(len(members)),
                "已观察": str(len(members)), "拒绝": str(final.get("拒绝", 0)),
                "无法判定": str(final.get("无法判定", 0)), "失败": str(final.get("失败", 0)),
                "未成熟": str(final.get("未成熟", 0)), "失效": str(final.get("失效", 0)),
                "身份门": gate_value(members, "门1来源身份"),
                "三类时间门": gate_value(members, "门2时间与质量合同"),
                "质量门": gate_value(members, "门3质量审计"),
                "重放门": gate_value(members, "门4历史重放"),
                "成本门": gate_value(members, "门5成本与执行"),
                "血缘门": gate_value(members, "门6血缘"),
                "容量门": "无法判定", "恢复门": "无法判定",
                "最终裁决": "阻塞",
                "证据": "loop-20260805T035900+0800-v4/闭环成员.csv；capacity-20260804T212023Z/清单.json；容量试点为零成员",
                "解除条件": "分别补齐来源身份、三类时间、质量、重放、成本、容量和恢复证据后重新生成不可变批次",
            })

    aggregate = {key: sum(int(leaf[key]) for leaf in leaves) for key in ("候选总体", "已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")}
    if aggregate["候选总体"] != sum(aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")):
        raise ValueError(f"最终状态计数不守恒：{aggregate}")
    return leaves, aggregate


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, delete=False) as temp:
        writer = csv.DictWriter(temp, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        temp_path = Path(temp.name)
    temp_path.replace(path)


def run(batch: str) -> Path:
    if not re.fullmatch(r"final-[0-9]{8}T[0-9]{6}Z-v[0-9]+", batch):
        raise ValueError("批次必须为final-YYYYMMDDTHHMMSSZ-vN")
    evidence = verify_upstream()
    rows = read_loop_rows(ROOT / LOOP_CSV)
    leaves, aggregate = build_leaves(rows)
    out_root = ROOT / "artifacts/审计/阶段1最终审计" / batch
    if out_root.exists():
        raise FileExistsError(f"不可覆盖已有批次：{out_root}")
    out_root.mkdir(parents=True)
    leaf_path = out_root / "叶子裁决.csv"
    gap_path = out_root / "缺口清单.csv"
    summary_path = out_root / "统计摘要.json"
    manifest_path = out_root / "验证清单.json"
    write_csv(leaf_path, leaves)
    gaps = [
        {"缺口编号": "ZS-DATA-GAP-001", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "来源身份拒绝或无法判定；交易场所、市场、合约和对象均未知", "解除条件": "重新冻结来源、场所、市场、标的、合约、对象和Schema版本"},
        {"缺口编号": "ZS-DATA-GAP-002", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "三类时间与时间范围无法判定", "解除条件": "提供事件、到达、采集时间及数据截止合同"},
        {"缺口编号": "ZS-DATA-GAP-003", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "质量、重放和成本门没有完整通过证据", "解除条件": "同一不可变输入链重跑质量、重放和成本门"},
        {"缺口编号": "ZS-DATA-GAP-012", "优先级": "P1", "范围": "BTC、ETH容量", "状态": "阻塞", "证据": "试点候选2520、合格0；市场记录增长和生产容量无法判定", "解除条件": "非零成员试采并单独保留容量、索引、日志和峰值证据"},
        {"缺口编号": "ZS-DATA-GAP-013", "优先级": "P1", "范围": "BTC、ETH恢复", "状态": "阻塞", "证据": "元数据副本可隔离恢复，但市场记录恢复无法判定", "解除条件": "在不改写原始数据的前提下完成真实记录恢复演练"},
    ]
    write_csv(gap_path, gaps)
    write_json(summary_path, {
        "批次": batch, "候选总体": aggregate["候选总体"], "已观察": aggregate["已观察"],
        "状态计数": {key: aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")},
        "计数守恒": aggregate["候选总体"] == sum(aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")),
        "按标的": {asset: {"候选总体": sum(int(x["候选总体"]) for x in leaves if x["标的"] == asset), "拒绝": sum(int(x["拒绝"]) for x in leaves if x["标的"] == asset), "无法判定": sum(int(x["无法判定"]) for x in leaves if x["标的"] == asset)} for asset in ASSETS},
    })
    output_hashes = {p.name: sha256(p) for p in (leaf_path, gap_path, summary_path)}
    write_json(manifest_path, {
        "批次": batch, "任务编号": "任务-000037", "合同版本": "stage1-final-audit-1.0",
        "输入范围": {"标的": list(ASSETS), "主研究尺度": list(SCALES), "事后结果观察窗口": list(POST_WINDOWS), "叶子维度": ["标的", "交易场所", "市场类型", "精确合约", "数据对象", "主研究尺度", "时间范围"]},
        "上游": evidence, "最终叶子数": len(leaves), "成员顺序": "BTC后ETH；各标的内按4小时、8小时、24小时、48小时升序；叶内按上游资产编号和来源成员编号升序",
        "状态计数": {key: aggregate[key] for key in ("候选总体", "已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")},
        "计数守恒": True, "允许研究范围": [], "阶段2结论": "阻塞",
        "八类硬门": ["来源身份", "三类时间与研究尺度", "质量", "历史重放", "成本与执行", "血缘", "容量", "恢复"],
        "门禁规则": "任一关键门失败或无法判定均阻止对应叶子；BTC与ETH不互相补偿；不因服务器可达或局部批次通过而放行",
        "安全边界": {"访问服务器": False, "访问数据库业务正文": False, "读取真实市场数据": False, "修改原始数据": False, "生成模型回测或交易结论": False},
        "输出文件指纹": output_hashes,
    })
    return out_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, help="final-YYYYMMDDTHHMMSSZ-vN")
    args = parser.parse_args(argv)
    try:
        print(run(args.batch))
    except (FileExistsError, OSError, ValueError, KeyError) as error:
        print(f"阶段1最终审计失败安全停止：{error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
