from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "数据" / "验证阶段1成本执行.py"
CONFIG_PATH = ROOT / "config" / "数据" / "任务-000100阶段1成本执行.json"
FORMAL_BATCH = "stage1-cost-execution-20260812T170000Z-81f61b9fae06"
FORMAL_ROOT = ROOT / "artifacts" / "数据" / "阶段1成本执行" / FORMAL_BATCH


def load_module():
    spec = importlib.util.spec_from_file_location("stage1_cost_execution", MODULE_PATH)
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


def test_配置固定任务与研究边界(module, config):
    module.validate_config(config)
    assert config["任务编号"] == "任务-000100"
    assert config["标的"] == ["BTCUSDT", "ETHUSDT"]
    assert config["主研究尺度"] == ["主研究尺度：4小时", "主研究尺度：8小时", "主研究尺度：24小时", "主研究尺度：48小时"]
    assert config["事后观察窗口"] == ["15分钟", "1小时"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM order_book_raw_snapshots",
        "UPDATE order_book_raw_snapshots SET symbol='BTCUSDT'",
        "SELECT symbol FROM order_book_signals",
        "SELECT symbol FROM order_book_raw_snapshots INTO OUTFILE '/tmp/x'",
        "SELECT symbol FROM order_book_raw_snapshots; SELECT 1",
        "SELECT symbol FROM order_book_raw_snapshots -- comment",
    ],
)
def test_SQL白名单拒绝越界(module, config, sql):
    with pytest.raises(ValueError):
        module.validate_business_sql(sql, config)


def test_SQL白名单接受有界索引聚合(module, config):
    sql = (
        "SELECT symbol, MIN(event_time), MAX(event_time), COUNT(id) "
        "FROM order_book_raw_snapshots "
        "WHERE symbol IN ('BTCUSDT','ETHUSDT') "
        "AND event_time >= %s AND event_time < %s GROUP BY symbol LIMIT 8"
    )
    assert module.validate_business_sql(sql, config) == "order_book_raw_snapshots"


def test_EXPLAIN只接受命中索引的有界计划(module):
    allowed = {
        "query_block": {
            "table": {
                "access_type": "range",
                "key": "idx_symbol_event_time",
                "rows_examined_per_scan": 1200,
            }
        }
    }
    assert module.validate_explain(
        allowed, allowed_indexes={"idx_symbol_event_time"}, max_rows=250_000
    ) == 1200


@pytest.mark.parametrize("access_type", ["ALL", "index"])
def test_EXPLAIN拒绝全表与全索引扫描(module, access_type):
    plan = {
        "query_block": {
            "table": {
                "access_type": access_type,
                "key": "idx_symbol_event_time",
                "rows_examined_per_scan": 1,
            }
        }
    }
    with pytest.raises(ValueError):
        module.validate_explain(
            plan, allowed_indexes={"idx_symbol_event_time"}, max_rows=250_000
        )


def test_EXPLAIN拒绝未知索引与估算超限(module):
    unknown_key = {
        "query_block": {
            "table": {
                "access_type": "range",
                "key": "idx_other",
                "rows_examined_per_scan": 1,
            }
        }
    }
    too_many = {
        "query_block": {
            "table": {
                "access_type": "range",
                "key": "idx_symbol_event_time",
                "rows_examined_per_scan": 250_001,
            }
        }
    }
    with pytest.raises(ValueError):
        module.validate_explain(
            unknown_key, allowed_indexes={"idx_symbol_event_time"}, max_rows=250_000
        )
    with pytest.raises(ValueError):
        module.validate_explain(
            too_many, allowed_indexes={"idx_symbol_event_time"}, max_rows=250_000
        )


def test_查询清单拒绝重复和超限(module):
    one = {"查询编号": "q-1", "SQL": "SELECT 1", "表": "symbol_metadata"}
    with pytest.raises(ValueError):
        module.validate_query_manifest([one, one], max_queries=24)
    with pytest.raises(ValueError):
        module.validate_query_manifest(
            [{"查询编号": f"q-{i}", "SQL": f"SELECT {i}", "表": "symbol_metadata"} for i in range(25)],
            max_queries=24,
        )


def test_查询计划篡改在执行前失败关闭(module, config):
    intent = {"batch_id": "batch-1", "data_cutoff_at": "2026-08-12T13:00:00Z"}
    metadata = {
        "metadata": {
            "columns": [
                ["order_book_raw_snapshots", "symbol", "1", "varchar", "NO"],
                ["order_book_raw_snapshots", "capture_ts_ms", "2", "bigint", "NO"],
            ],
            "indexes": [
                ["order_book_raw_snapshots", "idx_symbol_capture", "1", "1", "symbol"],
                ["order_book_raw_snapshots", "idx_symbol_capture", "1", "2", "capture_ts_ms"],
            ],
        }
    }
    plan = module.build_query_plan(metadata, intent, config)
    plan["queries"][0]["SQL"] = "DELETE FROM order_book_raw_snapshots"
    with pytest.raises(ValueError):
        module.validate_query_plan(plan, intent, metadata, config)


def test_查询解释必须绑定当前计划SHA(module):
    with pytest.raises(ValueError):
        module.validate_explain_evidence(
            {"batch_id": "b", "query_plan_sha256": "0" * 64, "results": []},
            plan={"batch_id": "b", "queries": []},
            plan_sha256="1" * 64,
            config={"资源上限": {"单SQL估算扫描行": 1, "批次估算扫描行": 1}},
        )


def test_资源和来源漂移失败关闭(module, config):
    with pytest.raises(ValueError):
        module.validate_resource_facts(
            {"elapsed_seconds": 901, "rss_bytes": 1},
            config["资源上限"],
        )
    pre = {
        "protocol": "zhishi-stage1-cost-metadata/1",
        "uid": 0,
        "identity_sha256": "a" * 64,
        "grant_sha256": "b" * 64,
        "select_capability": True,
        "tables": [["t", "InnoDB", "1"]],
        "columns": [["t", "symbol", "1", "varchar", "NO"]],
        "indexes": [["t", "i", "1", "1", "symbol"]],
        "load1": 0.1,
        "cpu_count": 4,
    }
    post = json.loads(json.dumps(pre))
    post["grant_sha256"] = "c" * 64
    with pytest.raises(ValueError):
        module.assert_metadata_invariants_equal(pre, post)


def test_查询规划识别明确秒与毫秒时间列(module, config):
    intent = {"batch_id": "batch-1", "data_cutoff_at": "2026-08-12T13:00:00Z"}
    metadata = {
        "metadata": {
            "columns": [
                ["order_book_raw_snapshots", "symbol", "1", "varchar", "NO"],
                ["order_book_raw_snapshots", "capture_ts_ms", "2", "bigint", "NO"],
                ["order_book_feature_buckets", "symbol", "1", "varchar", "NO"],
                ["order_book_feature_buckets", "bucket_ts_sec", "2", "bigint", "NO"],
            ],
            "indexes": [
                ["order_book_raw_snapshots", "idx_symbol_capture", "1", "1", "symbol"],
                ["order_book_raw_snapshots", "idx_symbol_capture", "1", "2", "capture_ts_ms"],
                ["order_book_feature_buckets", "idx_symbol_bucket", "1", "1", "symbol"],
                ["order_book_feature_buckets", "idx_symbol_bucket", "1", "2", "bucket_ts_sec"],
            ],
        }
    }
    plan = module.build_query_plan(metadata, intent, config)
    assert plan["query_count"] == 2
    millisecond_sql = next(query["SQL"] for query in plan["queries"] if query["表"] == "order_book_raw_snapshots")
    second_sql = next(query["SQL"] for query in plan["queries"] if query["表"] == "order_book_feature_buckets")
    millisecond_upper = int(millisecond_sql.split("capture_ts_ms`<", 1)[1].split(" ", 1)[0])
    second_upper = int(second_sql.split("bucket_ts_sec`<", 1)[1].split(" ", 1)[0])
    assert millisecond_upper == second_upper * 1000
    assert millisecond_sql.count("SELECT") == 1
    assert "MIN(" in millisecond_sql and "MAX(" in millisecond_sql
    assert "BTCUSDT" in millisecond_sql and "ETHUSDT" in millisecond_sql


def test_元数据探针只使用四个批准视图并隔离登录配置(module):
    program = module.REMOTE_METADATA_PROGRAM
    assert "information_schema.TABLES" in program
    assert "information_schema.COLUMNS" in program
    assert "information_schema.TABLE_PRIVILEGES" in program
    assert "information_schema.STATISTICS" in program
    assert "CURRENT_USER" not in program and "SHOW GRANTS" not in program
    assert '"MYSQL_TEST_LOGIN_FILE":"/dev/null"' in program
    assert "metadata_query_count\":4" in program


def test_Binance只允许公开端点(module, config):
    assert module.validate_public_url(
        "https://fapi.binance.com/fapi/v1/exchangeInfo", config
    )
    for url in (
        "https://api.binance.com/api/v3/account",
        "https://fapi.binance.com/fapi/v2/account",
        "http://fapi.binance.com/fapi/v1/depth",
    ):
        with pytest.raises(ValueError):
            module.validate_public_url(url, config)


def test_Binance远端探针不禁用证书验证(module, config):
    program = module.build_binance_remote_program(config)
    assert "_create_unverified_context" not in program
    assert "CERT_NONE" not in program
    assert "--insecure" not in program
    assert '"-k"' not in program
    assert "/fapi/v2/account" not in program
    assert "fapi.binance.com" in program
    assert "str(response.returncode)" in program
    assert "--no-defaults" in module.REMOTE_METADATA_PROGRAM
    assert "--no-defaults" in module._remote_query_program([], explain_only=False)


def test_资金费率请求绑定冻结截止(module, config):
    cutoff = "2026-08-12T13:00:00Z"
    requests = module._public_requests(config, data_cutoff_at=cutoff)
    funding = [item for item in requests if item["kind"] == "historical_funding"]
    assert len(funding) == 2
    expected = str(int(module.dt.datetime.fromisoformat(cutoff.replace("Z", "+00:00")).timestamp() * 1000))
    assert all(f"endTime={expected}" in item["request_uri"] for item in funding)


def test_行情延迟不得替代执行延迟(module):
    decision = module.build_gate_decision(
        {
            "手续费": "通过",
            "价差": "通过",
            "深度": "通过",
            "冲击": "通过",
            "资金费率": "通过",
            "行情可见性延迟": "通过",
            "可成交量": "通过",
        }
    )
    assert decision["执行延迟"] == "无法判定"
    assert decision["成本与执行总门"] == "无法判定"


def test_当前快照不得回填历史(module):
    with pytest.raises(ValueError):
        module.assert_historical_compatibility(
            source_kind="current_depth", requested_at="2025-01-01T00:00:00Z"
        )


def test_精确生成32个分组且BTC_ETH不互补(module):
    rows = module.build_group_rows(
        batch="batch-1",
        evidence={"资金费率历史窗口已观察": {"BTCUSDT": False, "ETHUSDT": False}},
    )
    assert len(rows) == 32
    assert {row["标的"] for row in rows} == {"BTCUSDT", "ETHUSDT"}
    assert all(row["成本与执行总门"] == "无法判定" for row in rows)
    assert all(row["执行延迟状态"] == "无法判定" for row in rows)
    assert all(row["手续费原因代码"] == "PUBLIC_FEE_VERSION_UNPROVEN" for row in rows)


def test_资金费率按标的独立裁决(module):
    rows = module.build_group_rows(
        batch="batch-1",
        evidence={"资金费率历史窗口已观察": {"BTCUSDT": True, "ETHUSDT": False}},
    )
    btc = [row for row in rows if row["标的"] == "BTCUSDT"]
    eth = [row for row in rows if row["标的"] == "ETHUSDT"]
    assert {row["资金费率状态"] for row in btc} == {"已观察（覆盖不足）"}
    assert {row["资金费率状态"] for row in eth} == {"无法判定"}
    assert {row["资金费率原因代码"] for row in btc} == {"FUNDING_HISTORY_COVERAGE_INSUFFICIENT"}
    assert {row["资金费率原因代码"] for row in eth} == {"BINANCE_FUNDING_EVIDENCE_UNAVAILABLE"}


def test_原子追加拒绝覆盖(module, tmp_path):
    target = tmp_path / "evidence.json"
    module.write_json_exclusive(target, {"a": 1})
    with pytest.raises(FileExistsError):
        module.write_json_exclusive(target, {"a": 2})


def test_目录发布使用原子禁止覆盖(module, tmp_path):
    source = tmp_path / "pending"
    source.mkdir()
    (source / "evidence").write_text("new", encoding="utf-8")
    target = tmp_path / "published"
    target.mkdir()
    (target / "evidence").write_text("existing", encoding="utf-8")
    with pytest.raises(FileExistsError):
        module.publish_directory_no_replace(source, target)
    assert source.is_dir()
    assert (target / "evidence").read_text(encoding="utf-8") == "existing"


def test_远端查询超时失败关闭且不重试(module, monkeypatch):
    calls = 0

    def timeout(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired("ssh", 1)

    monkeypatch.setattr(module.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="REMOTE_PROBE_TIMEOUT"):
        module._run_ssh_python("print('{}')", timeout=1, max_log=1024)
    assert calls == 1


def test_敏感文本失败关闭(module):
    with pytest.raises(ValueError):
        module.assert_safe_text("pass" + "word=forbidden")


def test_正式批次清单与分母可复算(module):
    result = module.validate_batch(ROOT, FORMAL_BATCH)
    assert result["manifest_sha256"] == "a06f20359d7c198c5ecc615671a5a096c855a1ad4afd344bf61eb80127e831b9"
    assert result["summary_sha256"] == "1f8c6e0fc9f93fc8e043c097f3e7c97be84a385d0d47ba69e8b1e2aa0942c15e"
    assert result["candidate_group_count"] == 32
    assert result["cost_execution_gate"] == "无法判定"


def test_正式批次语义篡改即使重签清单也失败(module, tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    for relative in (
        module.CONFIG_RELATIVE_PATH,
        module.TASK_RELATIVE_PATH,
    ):
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    target_batch = repo / "artifacts" / "数据" / "阶段1成本执行" / FORMAL_BATCH
    target_batch.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FORMAL_ROOT, target_batch)
    monkeypatch.setattr(module, "_assert_upstream", lambda *_args: {})
    summary_path = target_batch / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["stage1_complete"] = True
    summary_path.write_bytes(module.canonical_bytes(summary))
    manifest_path = target_batch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["summary.json"] = {
        "sha256": module.sha256_path(summary_path),
        "bytes": summary_path.stat().st_size,
    }
    manifest["total_bytes"] = sum(item["bytes"] for item in manifest["files"].values())
    manifest["manifest_payload_sha256"] = module.sha256_bytes(
        module.canonical_bytes(manifest["files"])
    )
    manifest_path.write_bytes(module.canonical_bytes(manifest))
    with pytest.raises(ValueError):
        module.validate_batch(repo, FORMAL_BATCH)


def test_正式批次数据库查询是索引有界且不重试():
    evidence = json.loads((FORMAL_ROOT / "database-evidence.json").read_text(encoding="utf-8"))
    assert evidence["executed_query_count"] == 4
    assert evidence["estimated_rows"] == 410
    assert evidence["response_bytes"] == 276
    assert evidence["query_retry_count"] == 0
    assert all(item["状态"] == "通过" for item in evidence["query_decisions"])


def test_正式批次凭据隔离SQL预算与逐项原因可复算():
    metadata = json.loads((FORMAL_ROOT / "metadata.json").read_text(encoding="utf-8"))["metadata"]
    assert metadata["option_files_disabled"] is True
    assert metadata["login_path_redirected"] is True
    assert metadata["credential_environment_cleared"] is True
    assert metadata["metadata_query_count"] == 4
    assert {row[0] for row in metadata["table_privileges"] if row[1] == "SELECT"} == {
        row[0] for row in metadata["tables"]
    }
    summary = json.loads((FORMAL_ROOT / "summary.json").read_text(encoding="utf-8"))
    assert summary["resource_facts"]["non_explain_sql_count"] == 12
    assert summary["resource_facts"]["business_query_count"] == 4
    assert summary["funding_window_observed_by_symbol"] == {"BTCUSDT": False, "ETHUSDT": False}
    rows = list(__import__("csv").DictReader((FORMAL_ROOT / "group-results.csv").open(encoding="utf-8")))
    reason_fields = [name for name in rows[0] if name.endswith("原因代码")]
    assert len(reason_fields) == 9
    assert all(all(row[name] for name in reason_fields) for row in rows)


def test_正式批次如实保留Binance公开端点超时():
    evidence = json.loads((FORMAL_ROOT / "binance-evidence.json").read_text(encoding="utf-8"))
    assert evidence["transport"] == "ubuntu-curl-ipv4-verified-https"
    assert len(evidence["requests"]) == 7
    assert {item["reason"] for item in evidence["requests"]} == {"HTTPS_REQUEST_FAILED_28"}
    assert {item["status"] for item in evidence["requests"]} == {"failed"}
