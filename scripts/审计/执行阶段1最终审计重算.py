#!/usr/bin/env python3
"""基于任务-000075至任务-000077证据重算阶段1最终审计。

本入口只读取仓库内已合并的合同、报告、配置和不可变批次，复用现有阶段1
审计器的叶子与门禁语义；不会访问服务器、数据库或真实市场数据。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import NamedTemporaryFile


ROOT = Path(__file__).resolve().parents[2]
LEGACY_PATH = ROOT / "scripts/审计/执行阶段1最终审计.py"
SPEC = importlib.util.spec_from_file_location("stage1_final_audit_legacy", LEGACY_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("无法加载既有阶段1最终审计器")
LEGACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEGACY)

ASSETS = LEGACY.ASSETS
SCALES = LEGACY.SCALES
POST_WINDOWS = LEGACY.POST_WINDOWS
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_ROWS = 10_000

UPSTREAM = {
    "任务-000075": {
        "合并提交SHA": "99f787a0abdf2e0167f1db84fef10815658fbbac",
        "批次清单": "artifacts/数据/来源身份输入指纹复采/source-identity-input-drift-20260807T173144+0800-592622eddd8e/批次清单.json",
        "成员清单": "artifacts/数据/来源身份输入指纹复采/source-identity-input-drift-20260807T173144+0800-592622eddd8e/来源身份清单.csv",
    },
    "任务-000076": {
        "合并提交SHA": "f5451b7695e80e133a974562a6f09a5f975ad857",
        "批次清单": "artifacts/数据/来源身份字段级证据复采/source-identity-field-evidence-20260808T020108+0800-7634991794d9/批次清单.json",
        "成员清单": "artifacts/数据/来源身份字段级证据复采/source-identity-field-evidence-20260808T020108+0800-7634991794d9/来源身份字段级证据清单.csv",
    },
    "任务-000077": {
        "合并提交SHA": "ec5dbcd1f51730f4e3cbb7d7d8ee9cbec2575118",
        "批次清单": "artifacts/数据/数据库元数据身份证据复采/database-metadata-identity-evidence-20260808T030243+0800-c3cb2624d197/批次清单.json",
        "成员清单": "artifacts/数据/数据库元数据身份证据复采/database-metadata-identity-evidence-20260808T030243+0800-c3cb2624d197/数据库元数据身份证据清单.csv",
    },
}

LOOP_CSV = LEGACY.LOOP_CSV
LEGACY_FINAL_MANIFEST = "artifacts/审计/阶段1最终审计/final-20260807T082700Z-v4/验证清单.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"输入文件超过32MiB上限：{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"输入文件超过32MiB上限：{path}")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows or len(rows) > MAX_ROWS:
        raise ValueError(f"CSV行数不在有界范围：{path} {len(rows)}")
    return rows


def task_fact(task_id: str, expected_sha: str) -> dict[str, str]:
    path = ROOT / "docs/研发中心/任务" / f"{task_id}.md"
    text = path.read_text(encoding="utf-8")
    status = re.search(r"^- 状态：(.+)$", text, re.MULTILINE)
    merge = re.search(r"^- 合并提交SHA：`([0-9a-f]{40})`$", text, re.MULTILINE)
    if status is None or merge is None or status.group(1).strip() != "已完成":
        raise ValueError(f"{task_id}不是已完成状态")
    if merge.group(1) != expected_sha:
        raise ValueError(f"{task_id}合并提交SHA漂移")
    return {"任务文件SHA-256": sha256(path), "合并提交SHA": expected_sha}


def _summary_counts(rows: list[dict[str, str]], *, status_key: str = "状态") -> dict[str, int]:
    counts = Counter(row[status_key] for row in rows)
    allowed = {"已观察", "已证明", "通过", "拒绝", "无法判定", "失败", "未成熟", "失效"}
    if set(counts) - allowed:
        raise ValueError(f"出现未登记状态：{set(counts) - allowed}")
    return {key: counts.get(key, 0) for key in ("已观察", "已证明", "通过", "拒绝", "无法判定", "失败", "未成熟", "失效")}


def verify_new_upstream() -> dict:
    """校验新证据的提交、批次、成员指纹和分标的状态守恒。"""

    base = LEGACY.verify_upstream()
    additions: dict[str, dict] = {}
    field_rows: list[dict[str, str]] | None = None
    for task_id, spec in UPSTREAM.items():
        fact = task_fact(task_id, spec["合并提交SHA"])
        manifest_path = ROOT / spec["批次清单"]
        member_path = ROOT / spec["成员清单"]
        manifest = read_json(manifest_path)
        members = read_csv(member_path)
        if manifest.get("任务编号") != task_id:
            raise ValueError(f"{task_id}批次任务编号不一致")
        if manifest.get("输出SHA-256", {}).get(member_path.name) not in {None, sha256(member_path)}:
            raise ValueError(f"{task_id}成员清单输出指纹不一致")
        if task_id == "任务-000075":
            required = {"资产编号", "成员编号", "标的", "状态"}
            if not required.issubset(members[0]):
                raise ValueError("任务-000075成员清单字段不足")
            if len(members) != 630 or len({(r["标的"], r["资产编号"]) for r in members}) != 630:
                raise ValueError("任务-000075候选资产成员不完整")
            counts = _summary_counts(members)
            if counts["拒绝"] != 12 or counts["无法判定"] != 618:
                raise ValueError("任务-000075状态计数漂移")
        elif task_id == "任务-000076":
            required = {"资产编号", "成员编号", "标的", "状态", "字段证据状态"}
            if not required.issubset(members[0]):
                raise ValueError("任务-000076成员清单字段不足")
            if len(members) != 630 or len({(r["标的"], r["资产编号"]) for r in members}) != 630:
                raise ValueError("任务-000076身份成员不完整")
            counts = _summary_counts(members)
            if counts["拒绝"] != 12 or counts["无法判定"] != 618 or counts["已证明"] != 0:
                raise ValueError("任务-000076状态计数漂移")
            field_rows = members
        else:
            required = {"资产编号", "成员编号", "标的", "状态", "元数据状态"}
            if not required.issubset(members[0]):
                raise ValueError("任务-000077成员清单字段不足")
            if len(members) != 184 or len({(r["标的"], r["资产编号"]) for r in members}) != 184:
                raise ValueError("任务-000077元数据成员不完整")
            counts = _summary_counts(members)
            metadata_counts = Counter(row["元数据状态"] for row in members)
            if metadata_counts.get("已观察", 0) != 184 or counts["无法判定"] != 184 or counts["已证明"] != 0:
                raise ValueError("任务-000077状态计数漂移")
        additions[task_id] = {
            **fact,
            "批次清单": spec["批次清单"],
            "成员清单": spec["成员清单"],
            "批次清单SHA-256": sha256(manifest_path),
            "成员清单SHA-256": sha256(member_path),
            "批次": manifest,
            "状态计数": counts,
        }
    assert field_rows is not None
    identity_075 = {
        (row["标的"], row["资产编号"]): row["状态"]
        for row in read_csv(ROOT / UPSTREAM["任务-000075"]["成员清单"])
    }
    identity_076 = {(row["标的"], row["资产编号"]): row["状态"] for row in field_rows}
    if identity_075 != identity_076:
        raise ValueError("任务-000075与任务-000076身份状态不能绑定到同一成员")
    metadata = {
        (row["标的"], row["资产编号"]): row["状态"]
        for row in read_csv(ROOT / UPSTREAM["任务-000077"]["成员清单"])
    }
    if not set(metadata).issubset(identity_076):
        raise ValueError("任务-000077元数据成员不属于任务-000076身份成员")
    return {
        "历史阶段1输入": base,
        "任务-000075至任务-000077": additions,
        "身份状态": identity_076,
        "元数据状态": metadata,
    }


def gate_from_identity(status: str) -> str:
    if status == "已证明":
        return "通过"
    if status == "拒绝":
        return "拒绝"
    return "无法判定"


def build_recomputed_leaves(rows: list[dict[str, str]], evidence: dict) -> tuple[list[dict[str, str]], dict[str, int]]:
    identity = evidence["身份状态"]
    metadata = evidence["元数据状态"]
    by_leaf: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = (row["标的"], row["资产编号"])
        if key not in identity:
            raise ValueError(f"闭环成员缺少最新身份证据：{key}")
        item = dict(row)
        item["门1来源身份"] = gate_from_identity(identity[key])
        item["最新来源身份状态"] = identity[key]
        item["数据库元数据状态"] = metadata.get(key, "未覆盖")
        item["数据库元数据证据范围"] = "任务-000077" if key in metadata else "未覆盖"
        gates = [
            item["门1来源身份"], item["门2时间与质量合同"], item["门3质量审计"],
            item["门4历史重放"], item["门5成本与执行"], item["门6血缘"], "无法判定", "无法判定",
        ]
        if "拒绝" in gates:
            item["重算最终状态"] = "拒绝"
        elif "无法判定" in gates:
            item["重算最终状态"] = "无法判定"
        else:
            item["重算最终状态"] = "通过"
        by_leaf[(item["标的"], item["主研究尺度"])].append(item)

    expected = {(asset, scale) for asset in ASSETS for scale in SCALES}
    if set(by_leaf) != expected:
        raise ValueError("重算叶子未覆盖BTC/ETH四个主研究尺度")

    leaves: list[dict[str, str]] = []
    for asset in ASSETS:
        for scale in SCALES:
            members = sorted(by_leaf[(asset, scale)], key=lambda r: (r["资产编号"], r["来源成员编号"]))
            if len(members) != 315:
                raise ValueError(f"{asset}/{scale}候选总体不是315：{len(members)}")
            final = Counter(row["重算最终状态"] for row in members)
            if set(final) - {"拒绝", "无法判定", "失败", "未成熟", "失效", "通过"}:
                raise ValueError(f"{asset}/{scale}存在未登记状态：{final}")
            if final.get("通过", 0):
                raise ValueError("当前证据出现未经全部硬门证明的通过成员")
            leaves.append({
                "叶子编号": f"{asset}-{scale}", "标的": asset, "交易场所": "未知",
                "市场类型": "未知", "精确合约": "未知", "数据对象": "未知",
                "主研究尺度": scale, "时间范围": "无法判定", "候选总体": str(len(members)),
                "已观察": str(len(members)), "拒绝": str(final.get("拒绝", 0)),
                "无法判定": str(final.get("无法判定", 0)), "失败": str(final.get("失败", 0)),
                "未成熟": str(final.get("未成熟", 0)), "失效": str(final.get("失效", 0)),
                "身份门": LEGACY.gate_value(members, "门1来源身份"),
                "三类时间门": LEGACY.gate_value(members, "门2时间与质量合同"),
                "质量门": LEGACY.gate_value(members, "门3质量审计"),
                "重放门": LEGACY.gate_value(members, "门4历史重放"),
                "成本门": LEGACY.gate_value(members, "门5成本与执行"),
                "血缘门": LEGACY.gate_value(members, "门6血缘"),
                "容量门": "无法判定", "恢复门": "无法判定", "最终裁决": "阻塞",
                "最新来源身份拒绝": str(sum(row["最新来源身份状态"] == "拒绝" for row in members)),
                "最新来源身份无法判定": str(sum(row["最新来源身份状态"] == "无法判定" for row in members)),
                "数据库元数据已观察": str(sum(row["数据库元数据状态"] == "无法判定" for row in members)),
                "证据": "任务-000075/000076来源身份批次；任务-000077数据库元数据批次；历史闭环成员.csv",
                "解除条件": "分别补齐来源身份、三类时间、质量、重放、成本、容量和恢复硬门证据后重新生成不可变批次",
            })
    aggregate = {key: sum(int(leaf[key]) for leaf in leaves) for key in ("候选总体", "已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")}
    if aggregate["候选总体"] != sum(aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")):
        raise ValueError(f"重算状态计数不守恒：{aggregate}")
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
    if not re.fullmatch(r"final-recompute-[0-9]{8}T[0-9]{6}Z-v[0-9]+", batch):
        raise ValueError("批次必须为final-recompute-YYYYMMDDTHHMMSSZ-vN")
    evidence = verify_new_upstream()
    rows = LEGACY.read_loop_rows(ROOT / LOOP_CSV)
    leaves, aggregate = build_recomputed_leaves(rows, evidence)
    out_root = ROOT / "artifacts/审计/阶段1最终审计" / batch
    if out_root.exists():
        raise FileExistsError(f"不可覆盖已有批次：{out_root}")
    out_root.mkdir(parents=True)
    leaf_path = out_root / "叶子裁决.csv"
    gap_path = out_root / "缺口清单.csv"
    summary_path = out_root / "统计摘要.json"
    snapshot_path = out_root / "任务-000078执行合同快照.md"
    manifest_path = out_root / "验证清单.json"
    write_csv(leaf_path, leaves)
    write_csv(gap_path, [
        {"缺口编号": "ZS-DATA-GAP-001", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "任务-000076来源身份已证明0、拒绝12、无法判定618；任务-000077结构元数据已观察184但最终身份已证明0、无法判定184", "解除条件": "分别补齐来源提供者、交易场所、市场类型、精确合约、数据对象、Schema和授权证据"},
        {"缺口编号": "ZS-DATA-GAP-002", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "既有闭环三类时间与时间范围无法判定；本次仅复算，不读取市场正文", "解除条件": "提供事件、到达、采集时间及数据截止合同"},
        {"缺口编号": "ZS-DATA-GAP-003", "优先级": "P0", "范围": "BTC、ETH全部主研究尺度", "状态": "阻塞", "证据": "质量、重放和成本门没有完整通过证据", "解除条件": "同一不可变输入链重跑质量、重放和成本门"},
        {"缺口编号": "ZS-DATA-GAP-012", "优先级": "P1", "范围": "BTC、ETH容量", "状态": "阻塞", "证据": "最小闭环试点候选2520、合格0；容量证据仍无法判定", "解除条件": "非零成员试采并单独保留容量、索引、日志和峰值证据"},
        {"缺口编号": "ZS-DATA-GAP-013", "优先级": "P1", "范围": "BTC、ETH恢复", "状态": "阻塞", "证据": "元数据副本可隔离恢复，但市场记录恢复无法判定", "解除条件": "在不改写原始数据前提下完成真实记录恢复演练"},
    ])
    upstream = evidence["任务-000075至任务-000077"]
    write_json(summary_path, {
        "批次": batch, "候选总体": aggregate["候选总体"], "已观察": aggregate["已观察"],
        "状态计数": {key: aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")},
        "计数守恒": aggregate["候选总体"] == sum(aggregate[key] for key in ("拒绝", "无法判定", "失败", "未成熟", "失效")),
        "按标的": {asset: {"候选总体": sum(int(x["候选总体"]) for x in leaves if x["标的"] == asset), "拒绝": sum(int(x["拒绝"]) for x in leaves if x["标的"] == asset), "无法判定": sum(int(x["无法判定"]) for x in leaves if x["标的"] == asset)} for asset in ASSETS},
        "上游分母": {task: {"候选总体": value["状态计数"].get("已观察", 0) + value["状态计数"].get("已证明", 0) + value["状态计数"].get("拒绝", 0) + value["状态计数"].get("无法判定", 0), "身份成员总体": len(read_csv(ROOT / value["成员清单"]))} for task, value in upstream.items()},
    })
    snapshot_path.write_text((ROOT / "docs/研发中心/任务/任务-000078.md").read_text(encoding="utf-8"), encoding="utf-8")
    output_hashes = {p.name: sha256(p) for p in (leaf_path, gap_path, summary_path, snapshot_path)}
    design_path = ROOT / "docs/superpowers/specs/task-000078-phase1-final-audit-design.md"
    write_json(manifest_path, {
        "批次": batch, "任务编号": "任务-000078", "合同版本": "stage1-final-audit-recompute-1.0",
        "输入范围": {"标的": list(ASSETS), "主研究尺度": list(SCALES), "事后结果观察窗口": list(POST_WINDOWS), "叶子维度": ["标的", "交易场所", "市场类型", "精确合约", "数据对象", "主研究尺度", "时间范围"]},
        "历史最终审计输入": {"路径": LEGACY_FINAL_MANIFEST, "SHA-256": sha256(ROOT / LEGACY_FINAL_MANIFEST)},
        "上游": upstream, "最终叶子数": len(leaves), "成员顺序": "BTC后ETH；各标的内按4小时、8小时、24小时、48小时升序；叶内按资产编号和来源成员编号升序",
        "输入指纹": {"历史阶段1验证清单SHA-256": sha256(ROOT / LEGACY_FINAL_MANIFEST), "任务合同快照SHA-256": sha256(snapshot_path), "规则设计合同SHA-256": sha256(design_path)},
        "规则SHA-256": sha256(design_path), "执行器SHA-256": sha256(Path(__file__)), "任务快照SHA-256": sha256(snapshot_path),
        "资源事实": {"测试进程数": 1, "Node堆上限MiB": 256, "额外工作树": 0, "远端访问": False, "数据库业务正文读取": False},
        "状态计数": {key: aggregate[key] for key in ("候选总体", "已观察", "拒绝", "无法判定", "失败", "未成熟", "失效")},
        "计数守恒": True, "允许研究范围": [], "阶段1结论": "阻塞", "阶段2结论": "阻塞",
        "八类硬门": ["来源身份", "三类时间与研究尺度", "质量", "历史重放", "成本与执行", "血缘", "容量", "恢复"],
        "门禁规则": "任一关键门失败或无法判定均阻止对应叶子；BTC与ETH不互相补偿；不因服务器可达、结构观察或局部批次通过而放行",
        "尺度边界": {"主研究尺度": list(SCALES), "事后结果观察窗口": list(POST_WINDOWS), "短窗口升级为状态或许可尺度": False},
        "安全边界": {"访问服务器": False, "访问数据库业务正文": False, "读取真实市场数据": False, "修改原始数据": False, "生成模型回测或交易结论": False},
        "输出文件指纹": output_hashes,
    })
    return out_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, help="final-recompute-YYYYMMDDTHHMMSSZ-vN")
    args = parser.parse_args(argv)
    try:
        print(run(args.batch))
    except (FileExistsError, OSError, ValueError, KeyError) as error:
        print(f"阶段1最终审计重算失败安全停止：{error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
