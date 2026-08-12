from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "数据" / "验证阶段1成本执行.py"
CONFIG_PATH = ROOT / "config" / "数据" / "任务-000100阶段1成本执行.json"
FORMAL_BATCH = "stage1-cost-execution-20260812T140402Z-96e21fe4635a"
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
    assert plan["query_count"] == 8
    millisecond_sql = next(query["SQL"] for query in plan["queries"] if query["表"] == "order_book_raw_snapshots")
    second_sql = next(query["SQL"] for query in plan["queries"] if query["表"] == "order_book_feature_buckets")
    millisecond_upper = int(millisecond_sql.split("capture_ts_ms`<", 1)[1].split(" ", 1)[0])
    second_upper = int(second_sql.split("bucket_ts_sec`<", 1)[1].split(" ", 1)[0])
    assert millisecond_upper == second_upper * 1000


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
    rows = module.build_group_rows(batch="batch-1", evidence={})
    assert len(rows) == 32
    assert {row["标的"] for row in rows} == {"BTCUSDT", "ETHUSDT"}
    assert all(row["成本与执行总门"] == "无法判定" for row in rows)
    assert all(row["执行延迟状态"] == "无法判定" for row in rows)


def test_原子追加拒绝覆盖(module, tmp_path):
    target = tmp_path / "evidence.json"
    module.write_json_exclusive(target, {"a": 1})
    with pytest.raises(FileExistsError):
        module.write_json_exclusive(target, {"a": 2})


def test_敏感文本失败关闭(module):
    with pytest.raises(ValueError):
        module.assert_safe_text("pass" + "word=forbidden")


def test_正式批次清单与分母可复算(module):
    result = module.validate_batch(ROOT, FORMAL_BATCH)
    assert result["manifest_sha256"] == "c5ff25d5e4af590a09ea0fe6909423d62a43ba44ed6606dce2b784118a5327b4"
    assert result["summary_sha256"] == "aad650aeb95d212ce761669c723df9e5d61ca1c030ad132043a7778a65dc64e3"
    assert result["candidate_group_count"] == 32
    assert result["cost_execution_gate"] == "无法判定"


def test_正式批次数据库查询是索引有界且不重试():
    evidence = json.loads((FORMAL_ROOT / "database-evidence.json").read_text(encoding="utf-8"))
    assert evidence["executed_query_count"] == 16
    assert evidence["estimated_rows"] == 16
    assert evidence["response_bytes"] == 340
    assert evidence["query_retry_count"] == 0
    assert all(item["状态"] == "通过" for item in evidence["query_decisions"])


def test_正式批次如实保留Binance公开端点超时():
    evidence = json.loads((FORMAL_ROOT / "binance-evidence.json").read_text(encoding="utf-8"))
    assert evidence["transport"] == "ubuntu-curl-ipv4-verified-https"
    assert len(evidence["requests"]) == 7
    assert {item["reason"] for item in evidence["requests"]} == {"HTTPS_REQUEST_FAILED_28"}
    assert {item["status"] for item in evidence["requests"]} == {"failed"}
