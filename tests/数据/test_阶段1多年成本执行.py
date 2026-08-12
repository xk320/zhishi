from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "数据" / "闭合阶段1多年成本执行.py"
CONFIG_PATH = ROOT / "config" / "数据" / "任务-000106阶段1多年成本执行.json"


def load_module():
    spec = importlib.util.spec_from_file_location("stage1_multi_year_cost_execution", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def module():
    return load_module()


@pytest.fixture(scope="module")
def config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def object_row(module, key: str, size: int = 10):
    return module.RemoteObject(key=key, size=size, etag="etag", last_modified="2026-01-01T00:00:00Z")


def test_配置固定六个官方前缀与资源门(module, config):
    module.validate_config(config)
    assert config["任务编号"] == "任务-000106"
    assert config["S3服务域"] == "https://s3-ap-northeast-1.amazonaws.com/data.binance.vision"
    assert len(config["归档组"]) == 6
    assert {(row["标的"], row["对象类型"]) for row in config["归档组"]} == {
        (symbol, kind)
        for symbol in ("BTCUSDT", "ETHUSDT")
        for kind in ("fundingRate", "bookTicker", "bookDepth")
    }
    assert config["资源上限"]["网络总字节"] == 20 * 1024**3
    assert config["资源上限"]["RSS字节"] == 512 * 1024**2
    assert config["运行时"]["Demo主机"] == "demo-fapi.binance.com"


def test_S3_ListObjectsV2分页严格绑定前缀(module, config):
    group = config["归档组"][0]
    xml = f"""<?xml version='1.0' encoding='UTF-8'?>
<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>
<IsTruncated>true</IsTruncated><NextContinuationToken>next-token</NextContinuationToken>
<Contents><Key>{group['前缀']}BTCUSDT-fundingRate-2020-01.zip</Key><LastModified>2020-02-01T00:00:00Z</LastModified><ETag>&quot;a&quot;</ETag><Size>100</Size></Contents>
</ListBucketResult>""".encode()
    page = module.parse_s3_page(xml, group["前缀"], config)
    assert page.truncated is True
    assert page.next_token == "next-token"
    assert page.objects[0].key.startswith(group["前缀"])
    args = module.build_s3_curl_args(group["前缀"], config, continuation_token="next-token")
    joined = " ".join(args)
    assert "list-type=2" in joined and "continuation-token=next-token" in joined
    assert "--location" not in args and "--insecure" not in args


def test_清单规范化顺序无关且必须zip_checksum成对(module, config):
    group = next(row for row in config["归档组"] if row["组编号"] == "BTCUSDT-fundingRate")
    prefix = group["前缀"]
    rows = [
        object_row(module, prefix + "BTCUSDT-fundingRate-2020-02.zip.CHECKSUM", 80),
        object_row(module, prefix + "BTCUSDT-fundingRate-2020-01.zip", 100),
        object_row(module, prefix + "BTCUSDT-fundingRate-2020-02.zip", 110),
        object_row(module, prefix + "BTCUSDT-fundingRate-2020-01.zip.CHECKSUM", 80),
    ]
    first = module.normalize_inventory(rows, group, config)
    second = module.normalize_inventory(list(reversed(rows)), group, config)
    assert first == second
    assert first["成员数"] == 2
    assert first["覆盖起点"] == "2020-01-01" and first["覆盖终点"] == "2020-02-29"
    assert len(first["清单SHA-256"]) == 64
    with pytest.raises(ValueError, match="ARCHIVE_PAIR_MISSING"):
        module.normalize_inventory(rows[:-1], group, config)


def _write_probe(root: Path, name: str, header: str) -> tuple[Path, Path]:
    archive_path = root / name
    csv_name = name.removesuffix(".zip") + ".csv"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(csv_name, header + "\n1,2,3\n")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum = root / f"{name}.CHECKSUM"
    checksum.write_text(f"{digest}  {name}\n", encoding="ascii")
    return archive_path, checksum


@pytest.mark.parametrize(
    ("group_id", "name", "header"),
    [
        ("BTCUSDT-fundingRate", "BTCUSDT-fundingRate-2020-01.zip", "calc_time,funding_interval_hours,last_funding_rate"),
        ("BTCUSDT-bookTicker", "BTCUSDT-bookTicker-2023-05-16.zip", "update_id,best_bid_price,best_bid_qty,best_ask_price,best_ask_qty,transaction_time,event_time"),
        ("BTCUSDT-bookDepth", "BTCUSDT-bookDepth-2023-01-01.zip", "timestamp,percentage,depth,notional"),
    ],
)
def test_探针验证官方SHA_ZIP安全和精确Schema(module, config, tmp_path, group_id, name, header):
    group = next(row for row in config["归档组"] if row["组编号"] == group_id)
    archive, checksum = _write_probe(tmp_path, name, header)
    result = module.validate_probe(archive, checksum, group, config)
    assert result["状态"] == "通过"
    assert result["Schema"] == header.split(",")
    checksum.write_text(f"{'0' * 64}  {name}\n", encoding="ascii")
    with pytest.raises(ValueError, match="CHECKSUM_MISMATCH"):
        module.validate_probe(archive, checksum, group, config)


def test_探针拒绝ZIP路径穿越(module, config, tmp_path):
    group = next(row for row in config["归档组"] if row["组编号"] == "BTCUSDT-bookDepth")
    archive = tmp_path / "BTCUSDT-bookDepth-2023-01-01.zip"
    with zipfile.ZipFile(archive, "w") as item:
        item.writestr("../escape.csv", "timestamp,percentage,depth,notional\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = tmp_path / f"{archive.name}.CHECKSUM"
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    with pytest.raises(ValueError, match="ZIP_MEMBER_INVALID"):
        module.validate_probe(archive, checksum, group, config)


def test_acquire在对象超20GiB或覆盖不到正式窗口时失败关闭(module, config):
    too_large = {
        "标的": "BTCUSDT", "对象类型": "bookTicker", "总字节": 48_968 * 1024**2,
        "覆盖起点": "2023-05-16", "覆盖终点": "2024-03-30", "配对完整": True,
    }
    incomplete = {
        "标的": "BTCUSDT", "对象类型": "bookDepth", "总字节": 600 * 1024**2,
        "覆盖起点": "2023-01-01", "覆盖终点": "2026-08-11", "配对完整": True,
    }
    assert module.decide_acquire(too_large, config)["状态"] == "拒绝"
    assert "OBJECT_DOWNLOAD_LIMIT_EXCEEDED" in module.decide_acquire(too_large, config)["原因代码"]
    assert module.decide_acquire(incomplete, config)["状态"] == "拒绝"
    assert "FORMAL_WINDOW_NOT_COVERED" in module.decide_acquire(incomplete, config)["原因代码"]


def test_Demo只检查两个专用变量且不输出值(module, config):
    missing = module.demo_credentials_status({"BINANCE_API_KEY": "do-not-use"}, config)
    assert missing == {"状态": "未执行", "API_Key存在": False, "API_Secret存在": False}
    present = module.demo_credentials_status(
        {"ZHISHI_BINANCE_DEMO_API_KEY": "key-value", "ZHISHI_BINANCE_DEMO_API_SECRET": "secret-value"}, config
    )
    assert present == {"状态": "凭据存在（尚未执行）", "API_Key存在": True, "API_Secret存在": True}
    assert "key-value" not in json.dumps(present) and "secret-value" not in json.dumps(present)


def test_主网执行证据必须事前存在内容寻址且四时点与分母完整(module, config):
    assert module.validate_mainnet_execution_evidence(None, config)["状态"] == "无法判定"
    bad = {
        "schema_version": "zhishi-mainnet-execution-history/v1", "created_at": "2026-08-13T07:00:00+08:00",
        "content_sha256": "a" * 64, "candidate_total": 1, "records": [],
    }
    result = module.validate_mainnet_execution_evidence(bad, config)
    assert result["状态"] == "拒绝" and "EVIDENCE_NOT_PREEXISTING" in result["原因代码"]


def test_Demo不能使八叶子通过且两次重放规范全等(module, config):
    costs = {group["组编号"]: {"状态": "通过"} for group in config["归档组"]}
    demo = {"状态": "DEMO_EXECUTION_PROXY_OBSERVED", "样本数": 40}
    mainnet = {"状态": "无法判定", "原因代码": ["MAINNET_EXECUTION_EVIDENCE_MISSING"]}
    first = module.build_leaf_decisions(costs, demo, mainnet, config)
    replay_1 = module.replay_decisions(costs, demo, mainnet, config)
    replay_2 = module.replay_decisions(costs, demo, mainnet, config)
    assert len(first) == 8
    assert {(row["标的"], row["主研究尺度"]) for row in first} == {
        (symbol, horizon) for symbol in ("BTCUSDT", "ETHUSDT") for horizon in ("4小时", "8小时", "24小时", "48小时")
    }
    assert all(row["成本与执行门"] == "失败关闭" for row in first)
    assert module.canonical_sha256(first) == module.canonical_sha256(replay_1) == module.canonical_sha256(replay_2)


def test_外部批次只追加不覆盖(module, tmp_path):
    files = {"summary.json": {"状态": "阻塞"}, "leaves.json": [{"标的": "BTCUSDT"}]}
    target = module.publish_external_batch(tmp_path, "batch-1", files)
    assert json.loads((target / "summary.json").read_text(encoding="utf-8"))["状态"] == "阻塞"
    with pytest.raises(FileExistsError):
        module.publish_external_batch(tmp_path, "batch-1", files)


def test_正式窗口按标的固定且acquire按标的判定(module, config):
    assert config["正式窗口"] == {
        "BTCUSDT": {"起点": "2019-09-08", "终点": "2026-07-30"},
        "ETHUSDT": {"起点": "2019-11-27", "终点": "2026-08-03"},
    }
    btc = {"标的": "BTCUSDT", "总字节": 1, "覆盖起点": "2019-09-08", "覆盖终点": "2026-07-30", "配对完整": True}
    eth = {"标的": "ETHUSDT", "总字节": 1, "覆盖起点": "2019-11-28", "覆盖终点": "2026-08-03", "配对完整": True}
    assert module.decide_acquire(btc, config)["状态"] == "允许"
    assert module.decide_acquire(eth, config)["状态"] == "拒绝"


def _s3_xml(prefix: str, names: list[str], truncated: bool = False, token: str | None = None) -> bytes:
    contents = "".join(
        f"<Contents><Key>{prefix}{name}</Key><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>&quot;e&quot;</ETag><Size>10</Size></Contents>"
        for name in names
    )
    continuation = f"<NextContinuationToken>{token}</NextContinuationToken>" if token else ""
    return (
        "<?xml version='1.0'?><ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
        f"<IsTruncated>{str(truncated).lower()}</IsTruncated>{continuation}{contents}</ListBucketResult>"
    ).encode()


def test_list_inventory串行分页并执行累计资源门(module, config):
    group = config["归档组"][0]
    calls = []
    pages = [
        _s3_xml(group["前缀"], ["BTCUSDT-fundingRate-2020-01.zip"], True, "next"),
        _s3_xml(group["前缀"], ["BTCUSDT-fundingRate-2020-01.zip.CHECKSUM"]),
    ]

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": pages.pop(0), "stderr": b""})()

    rows = module.list_inventory(group, config, runner=runner)
    assert len(rows) == 2 and len(calls) == 2
    assert "continuation-token=next" in calls[1][0][-1]
    assert all("--location" not in args and "--insecure" not in args for args, _ in calls)
    assert all(kwargs["check"] is False and kwargs["capture_output"] is True for _, kwargs in calls)

    limited = json.loads(json.dumps(config))
    limited["资源上限"]["清单对象数"] = 1
    with pytest.raises(ValueError, match="INVENTORY_OBJECT_LIMIT_EXCEEDED"):
        module.list_inventory(group, limited, runner=lambda *args, **kwargs: type(
            "Result", (), {"returncode": 0, "stdout": _s3_xml(group["前缀"], [
                "BTCUSDT-fundingRate-2020-01.zip", "BTCUSDT-fundingRate-2020-01.zip.CHECKSUM"
            ]), "stderr": b""})())


def _full_inventory_page(group: dict, config: dict) -> bytes:
    window = config["正式窗口"][group["标的"]]
    if group["对象类型"] == "fundingRate":
        starts = [window["起点"][:7], window["终点"][:7]]
    else:
        starts = [window["起点"], window["终点"]]
    names = []
    for date in starts:
        name = f'{group["组编号"]}-{date}.zip'
        names.extend([name, name + ".CHECKSUM"])
    return _s3_xml(group["前缀"], names)


def _write_all_probes(module, config: dict, root: Path) -> None:
    for group in config["归档组"]:
        _write_probe(root, group["探针对象"], ",".join(group["Schema"]))


def test_run事前留痕失败安全发布脱敏结果与manifest(module, config, tmp_path, monkeypatch):
    external = tmp_path / "allowed"
    probes = tmp_path / "probes"
    external.mkdir()
    probes.mkdir()
    _write_all_probes(module, config, probes)
    monkeypatch.setattr(module, "ALLOWED_EXTERNAL_ROOT", external)
    calls = []
    pages = [_full_inventory_page(group, config) for group in config["归档组"]]

    def runner(args, **kwargs):
        assert (external / ".intents" / "batch-safe.json").exists()
        assert (external / ".pending" / "batch-safe").is_dir()
        calls.append(args)
        return type("Result", (), {"returncode": 0, "stdout": pages.pop(0), "stderr": b""})()

    code = module.run([
        "--config", str(CONFIG_PATH), "--external-root", str(external),
        "--probe-root", str(probes), "--batch", "batch-safe",
    ], runner=runner, environ={})
    assert code == 2 and len(calls) == 6
    target = external / "batch-safe"
    assert target.is_dir() and not (external / ".pending" / "batch-safe").exists()
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    for name, digest in manifest["文件SHA-256"].items():
        assert hashlib.sha256((target / name).read_bytes()).hexdigest() == digest
    rendered = "".join(path.read_text(encoding="utf-8") for path in target.glob("*.json"))
    for forbidden in ("binance.com", "https://", "账户", "key-value", "secret-value", "best_bid_price"):
        assert forbidden not in rendered
    leaves = json.loads((target / "leaves.json").read_text(encoding="utf-8"))
    assert len(leaves) == 8 and all(row["成本与执行门"] == "失败关闭" for row in leaves)
    summary = json.loads((target / "summary.json").read_text(encoding="utf-8"))
    assert summary["两次重放一致"] is True
    assert summary["状态"] == "失败关闭"


def test_run异常不发布部分正式批次并保留失败痕迹(module, tmp_path, monkeypatch):
    external = tmp_path / "allowed"
    probes = tmp_path / "probes"
    external.mkdir()
    probes.mkdir()
    monkeypatch.setattr(module, "ALLOWED_EXTERNAL_ROOT", external)

    def failed_runner(*args, **kwargs):
        return type("Result", (), {"returncode": 22, "stdout": b"", "stderr": b"network detail"})()

    with pytest.raises(RuntimeError, match="S3_LIST_FAILED"):
        module.run([
            "--config", str(CONFIG_PATH), "--external-root", str(external),
            "--probe-root", str(probes), "--batch", "batch-error",
        ], runner=failed_runner, environ=os.environ)
    assert not (external / "batch-error").exists()
    assert (external / ".pending" / "batch-error" / "failure.json").exists()


def test_list_inventory大对象仅由acquire拒绝且网络字节只计XML(module, config):
    group = next(row for row in config["归档组"] if row["组编号"] == "BTCUSDT-bookTicker")
    size = 21 * 1024**3
    xml = (
        "<?xml version='1.0'?><ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
        "<IsTruncated>false</IsTruncated>"
        f'<Contents><Key>{group["前缀"]}BTCUSDT-bookTicker-2023-05-16.zip</Key>'
        f"<LastModified>2026-01-01T00:00:00Z</LastModified><ETag>e</ETag><Size>{size}</Size></Contents>"
        "</ListBucketResult>"
    ).encode()
    result = type("Result", (), {"returncode": 0, "stdout": xml, "stderr": b""})()
    listing = module.list_inventory(group, config, runner=lambda *args, **kwargs: result)
    assert listing.objects[0].size == size
    assert listing.response_bytes == len(xml)
    decision = module.decide_acquire({
        "标的": "BTCUSDT", "总字节": size, "覆盖起点": "2019-09-08",
        "覆盖终点": "2026-07-30", "配对完整": True,
    }, config)
    assert decision["状态"] == "拒绝"
    assert "OBJECT_DOWNLOAD_LIMIT_EXCEEDED" in decision["原因代码"]


def test_每组探针对象固定而非按窗口推导(module, config):
    expected_suffix = {
        "fundingRate": "-2020-01.zip",
        "bookDepth": "-2023-01-01.zip",
        "bookTicker": "-2023-05-16.zip",
    }
    for group in config["归档组"]:
        assert group["探针对象"] == group["组编号"] + expected_suffix[group["对象类型"]]
        assert module._probe_name(group, config) == group["探针对象"]


def test_安全清单输出含拒绝原因且资源事实区分响应与对象字节(module, config):
    inventory = {
        "组编号": "BTCUSDT-bookTicker", "成员数": 2, "总字节": 21 * 1024**3,
        "覆盖起点": "2023-05-16", "覆盖终点": "2026-07-30", "清单SHA-256": "a" * 64,
    }
    decision = {"状态": "拒绝", "原因代码": ["OBJECT_DOWNLOAD_LIMIT_EXCEEDED", "FORMAL_WINDOW_NOT_COVERED"]}
    safe = module._safe_inventory_result(inventory, decision, {"状态": "通过"}, 321)
    assert safe["原因代码"] == decision["原因代码"]
    assert safe["清单响应字节"] == 321
    assert safe["对象标称总字节"] == inventory["总字节"]


def test_intent在网络前绑定完整上游与指纹且不泄露地址(module, config, tmp_path, monkeypatch):
    external = tmp_path / "allowed"
    probes = tmp_path / "probes"
    external.mkdir()
    probes.mkdir()
    _write_all_probes(module, config, probes)
    monkeypatch.setattr(module, "ALLOWED_EXTERNAL_ROOT", external)

    def runner(*args, **kwargs):
        intent = json.loads((external / ".intents" / "batch-intent.json").read_text(encoding="utf-8"))
        assert intent["配置SHA-256"] == hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest()
        assert len(intent["执行器SHA-256"]) == 64
        assert intent["任务-000105"] == config["上游绑定"]["任务-000105"]
        assert intent["任务-000094批次"] == config["上游绑定"]["任务-000094批次"]
        assert intent["任务-000099批次"] == config["上游绑定"]["任务-000099批次"]
        assert intent["正式窗口"] == config["正式窗口"]
        assert intent["资源预算"] == config["资源上限"]
        assert len(intent["六组前缀SHA-256"]) == 64
        rendered = json.dumps(intent, ensure_ascii=False)
        assert "https://" not in rendered and "binance.com" not in rendered
        raise RuntimeError("STOP_AFTER_INTENT")

    with pytest.raises(RuntimeError, match="STOP_AFTER_INTENT"):
        module.run([
            "--config", str(CONFIG_PATH), "--external-root", str(external),
            "--probe-root", str(probes), "--batch", "batch-intent",
        ], runner=runner, environ={})


def test_上游身份绑定精确常量(module, config):
    assert config["上游绑定"] == {
        "任务-000105": {
            "批次": "stage1-current-final-gate-20260812T213100Z-6c0e4bf5d923",
            "结果SHA-256": "43814e0f70143eb798b7dea71a36dfa4383b95bd9fff865c808f767ac8f1c4b0",
        },
        "任务-000094批次": "stage1-time-quality-20260812T091000Z-6968246516ef",
        "任务-000099批次": "stage1-prior-frozen-replay-20260812T130000Z-ca8ae0a8ecd7",
    }
    module.validate_config(config)


def test_ZIP流式成员门覆盖真实bookTicker且拒绝超过2GiB(module, config):
    assert config["资源上限"]["ZIP解压字节"] == 2 * 1024**3
    assert module.validate_zip_uncompressed_size(425_815_842, config) is None
    assert module.validate_zip_uncompressed_size(345_166_570, config) is None
    with pytest.raises(ValueError, match="ZIP_RESOURCE_LIMIT_EXCEEDED"):
        module.validate_zip_uncompressed_size(2 * 1024**3 + 1, config)
