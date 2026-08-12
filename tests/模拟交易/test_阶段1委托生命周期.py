from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "模拟交易" / "验证阶段1委托生命周期.py"
CONFIG = ROOT / "config" / "模拟交易" / "任务-000103阶段1委托生命周期.json"
FORMAL_BATCH = "stage1-simulated-lifecycle-20260812T175300Z-0638c3587854"


@pytest.fixture(scope="module")
def module():
    spec = importlib.util.spec_from_file_location("stage1_simulated_lifecycle", SCRIPT)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.fixture()
def config():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


@pytest.fixture()
def metadata():
    return {
        "protocol": "zhishi-stage1-simulated-lifecycle-metadata/1",
        "uid": 0,
        "select_capability": True,
        "option_files_disabled": True,
        "login_path_redirected": True,
        "credential_environment_cleared": True,
        "metadata_query_count": 4,
        "client_sha256": "a" * 64,
        "client_version_sha256": "b" * 64,
        "tables": [["order_book_raw_snapshots", "InnoDB", "7938"]],
        "columns": [
            ["order_book_raw_snapshots", "snapshot_id", "1", "varchar", "NO", ""],
            ["order_book_raw_snapshots", "exchange", "2", "varchar", "NO", ""],
            ["order_book_raw_snapshots", "symbol", "3", "varchar", "NO", ""],
            ["order_book_raw_snapshots", "capture_ts_ms", "4", "bigint", "NO", ""],
            ["order_book_raw_snapshots", "capture_reason", "5", "varchar", "NO", ""],
            ["order_book_raw_snapshots", "trigger_signal_id", "6", "varchar", "YES", ""],
            ["order_book_raw_snapshots", "trigger_event_id", "7", "varchar", "YES", ""],
            ["order_book_raw_snapshots", "bucket_ts_sec", "8", "bigint", "YES", ""],
            ["order_book_raw_snapshots", "payload_json", "9", "longtext", "YES", ""],
            ["order_book_raw_snapshots", "payload_msgpack", "10", "longblob", "YES", ""],
            ["order_book_raw_snapshots", "payload_size_bytes", "11", "bigint", "NO", ""],
            ["order_book_raw_snapshots", "payload_json_full", "12", "longtext", "NO", ""],
            ["order_book_raw_snapshots", "created_at", "13", "bigint", "NO", ""],
        ],
        "table_privileges": [["order_book_raw_snapshots", "SELECT", "NO"]],
        "indexes": [
            ["order_book_raw_snapshots", "idx_raw_snapshot_symbol_capture", "1", "1", "symbol"],
            ["order_book_raw_snapshots", "idx_raw_snapshot_symbol_capture", "1", "2", "capture_ts_ms"],
            ["order_book_raw_snapshots", "PRIMARY", "0", "1", "snapshot_id"],
        ],
        "load1": 0.1,
        "cpu_count": 8,
    }


@pytest.fixture()
def payload():
    return {
        "lastUpdateId": 12,
        "E": 900,
        "T": 901,
        "bids": [["100.0", "2.0"]],
        "asks": [["101.0", "3.0"]],
    }


def test_config_fixes_bounded_scope(module, config):
    module.validate_config(config)
    assert config["资源上限"]["每标的快照"] == 256
    assert config["资源上限"]["RSS字节"] == 268435456


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM order_book_raw_snapshots",
        "SELECT * FROM order_book_raw_snapshots LIMIT 1",
        "SELECT snapshot_id FROM order_book_raw_snapshots",
        "SELECT snapshot_id FROM order_book_raw_snapshots LIMIT 1; DROP TABLE x",
    ],
)
def test_sql_rejects_write_wildcard_or_unbounded_query(module, config, sql):
    with pytest.raises(ValueError):
        module.validate_business_sql(sql, config)


def test_query_is_totally_ordered(module, metadata, config):
    intent = {"batch_id": "stage1-simulated-lifecycle-20260812T173100Z-3c28981760e0", "data_cutoff_ms": 2000}
    plan = module.build_query_plan({"metadata": metadata}, intent, config)
    assert len(plan["queries"]) == 2
    assert all("`capture_ts_ms` DESC,`snapshot_id` DESC" in item["SQL"] for item in plan["queries"])
    assert all("LIMIT 256" in item["SQL"] for item in plan["queries"])


def test_duplicate_member_identity_fails_closed(module):
    rows = [{"capture_ts_ms": 1, "snapshot_id": "x"}] * 2
    with pytest.raises(ValueError, match="MEMBER_IDENTITY_DUPLICATE"):
        module.validate_member_order(rows)


def test_capture_time_never_becomes_market_event_time(module, payload):
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    assert row["market_event_time_ms"] == payload["E"]
    assert row["source_arrival_time_ms"] is None
    assert row["confirmed_visible_time_ms"] == 1100
    assert row["time_semantics_status"] == "unknown"


def test_missing_event_time_keeps_time_gate_unknown(module, payload):
    payload.pop("E")
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    assert row["market_event_time_ms"] is None
    assert row["time_semantics_status"] == "unknown"


def test_binance_compact_depth_fields_are_supported(module, payload):
    payload["b"] = payload.pop("bids")
    payload["a"] = payload.pop("asks")
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    assert row["book_valid"] is True


def test_orderbook_wrapper_binds_exact_event_and_arrival_fields(module, payload):
    wrapper = {
        "symbol": "BTCUSDT",
        "payload": {
            "bids": payload["bids"],
            "asks": payload["asks"],
            "last_event_time_ms": 900,
            "last_local_recv_ts_ms": 950,
        },
    }
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(wrapper)],
        collected_at_ms=1100,
    )
    assert row["market_event_time_ms"] == 900
    assert row["source_arrival_time_ms"] == 950
    assert row["time_semantics_status"] == "pass"
    assert row["confirmed_visible_time_ms"] == 950


def test_orderbook_object_levels_are_supported(module):
    wrapper = {
        "payload": {
            "bids": [{"price": "100.0", "quantity": "2.0", "notional": "200.0"}],
            "asks": [{"price": "101.0", "quantity": "3.0", "notional": "303.0"}],
            "last_event_time_ms": 900,
            "last_local_recv_ts_ms": 950,
        }
    }
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(wrapper)],
        collected_at_ms=1100,
    )
    assert row["book_valid"] is True
    assert row["time_semantics_status"] == "pass"


def test_future_event_time_fails_closed(module, payload):
    payload["E"] = 1200
    with pytest.raises(ValueError, match="FUTURE_EVENT_TIME"):
        module.normalize_snapshot(
            ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
            collected_at_ms=1100,
        )


def test_invalid_transition_fails_closed(module):
    with pytest.raises(ValueError, match="STATE_TRANSITION_INVALID"):
        module.transition("created", "filled")


def test_passive_order_never_fakes_queue_fill(module, payload):
    member = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    result = module.simulate_member(member, "被动限价撤销", "做多", "基准")
    assert result["terminal_state"] == "canceled"
    assert result["reason_code"] == "QUEUE_IDENTITY_UNAVAILABLE"


def test_symmetric_simulation_is_deterministic(module, payload):
    member = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    frozen = {"schema_version": "zhishi-simulated-order-frozen-input/v1", "members": [member]}
    first = module.simulate(frozen)
    second = module.simulate(frozen)
    assert first == second
    assert first["scenario_count"] == 12
    assert {row["direction"] for row in first["results"]} == {"做多", "做空"}


def test_validate_explain_rejects_full_scan(module):
    plan = {"query_block": {"table": {"access_type": "ALL", "key": None, "rows": 1}}}
    with pytest.raises(ValueError):
        module.validate_explain(plan, allowed_indexes={"idx_raw_snapshot_symbol_capture"}, max_rows=10000)


def test_redacted_member_does_not_persist_book_values(module, payload):
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    text = json.dumps(row, ensure_ascii=False)
    assert "100.0" not in text
    assert "101.0" not in text
    assert "2.0" not in text
    assert "3.0" not in text
    assert "bids" not in row and "asks" not in row


def test_formal_batch_manifest_and_replays_are_reproducible(module):
    result = module.validate_batch(ROOT, FORMAL_BATCH)
    assert result == {
        "status": "ok",
        "batch_id": FORMAL_BATCH,
        "manifest_sha256": "7b22affe9e64f339e2c4e4dfa77608b26d9539db6a2852d60916d252e5f8c88a",
        "summary_sha256": "21ac790a66d717a322387c3ac69d788c83193a28a8d2a11748b55b4e05cf76a2",
    }
    intent = json.loads(
        (
            ROOT
            / "artifacts"
            / "模拟交易"
            / "阶段1委托生命周期"
            / FORMAL_BATCH
            / "intent.json"
        ).read_text(encoding="utf-8")
    )
    assert intent["base_script_sha256"] == module.sha256_path(Path(module.BASE.__file__))
