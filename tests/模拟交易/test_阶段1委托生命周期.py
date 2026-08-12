from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "模拟交易" / "验证阶段1委托生命周期.py"
CONFIG = ROOT / "config" / "模拟交易" / "任务-000103阶段1委托生命周期.json"
FORMAL_BATCH = "stage1-simulated-lifecycle-20260812T181724Z-6e2d4fbdd7e3"


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


@pytest.fixture()
def proven_wrapper(payload):
    return {
        "snapshot_schema_version": 1,
        "source": "canonical_book",
        "payload": {
            "bids": payload["bids"],
            "asks": payload["asks"],
            "last_event_time_ms": 900,
            "last_local_recv_ts_ms": 950,
        },
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
    rows = [
        {
            "symbol": "BTCUSDT",
            "capture_ts_ms": 1,
            "snapshot_identity_sha256": "a" * 64,
            "member_sequence": 0,
        }
    ] * 2
    with pytest.raises(ValueError, match="MEMBER_IDENTITY_DUPLICATE"):
        module.validate_member_order(rows)


def test_same_timestamp_uses_raw_snapshot_id_before_redaction(module):
    rows = [
        ["z", "BTCUSDT", "1000", "1001", "{}"],
        ["y", "BTCUSDT", "1000", "1001", "{}"],
    ]
    module.validate_raw_member_order(rows)
    with pytest.raises(ValueError, match="MEMBER_ORDER_INVALID"):
        module.validate_raw_member_order(list(reversed(rows)))


def test_redacted_order_uses_sequence_not_snapshot_hash(module):
    rows = [
        {
            "symbol": "BTCUSDT",
            "capture_ts_ms": 1000,
            "snapshot_identity_sha256": "f" * 64,
            "snapshot_id_sha256": "0" * 64,
            "member_sequence": 0,
        },
        {
            "symbol": "BTCUSDT",
            "capture_ts_ms": 1000,
            "snapshot_identity_sha256": "0" * 64,
            "snapshot_id_sha256": "f" * 64,
            "member_sequence": 1,
        },
    ]
    module.validate_member_order(rows)


def test_bounded_process_stops_before_stdout_limit_is_exceeded(module):
    with pytest.raises(RuntimeError, match="PROCESS_STDOUT_LIMIT_EXCEEDED"):
        module._run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
            input_bytes=b"",
            timeout=5,
            max_stdout=1024,
            max_stderr=1024,
        )


def test_remote_query_program_enforces_memory_and_stream_limits(module):
    program = module._remote_query_program(
        [{"query_id": "q", "SQL": "SELECT 1 LIMIT 256"}],
        explain_only=False,
    )
    assert "setrlimit" in program
    assert "selectors.DefaultSelector" in program
    assert "capture_output=True" not in program
    assert "remote_peak_rss_bytes" in program


def test_task_fingerprint_excludes_delivery_execution_record(module, tmp_path):
    task = tmp_path / "task.md"
    task.write_text(
        "# task\n\n- 状态：待执行\n- 实现提交SHA：`" + "a" * 40 + "`\n\n"
        "## 合同\n\n固定正文。\n\n## 执行记录\n\n- 交付物：甲\n",
        encoding="utf-8",
    )
    first = module._normalized_task_fingerprint(task)
    task.write_text(
        "# task\n\n- 状态：待评审\n- 实现提交SHA：`" + "b" * 40 + "`\n\n"
        "## 合同\n\n固定正文。\n\n## 执行记录\n\n- 交付物：乙\n",
        encoding="utf-8",
    )
    assert module._normalized_task_fingerprint(task) == first


def test_published_validation_recomputes_semantics(module, config, tmp_path, monkeypatch):
    source = (
        ROOT
        / "artifacts"
        / "模拟交易"
        / "阶段1委托生命周期"
        / FORMAL_BATCH
    )
    copied = tmp_path / FORMAL_BATCH
    shutil.copytree(source, copied)
    lifecycle_path = copied / "lifecycle.json"
    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    lifecycle["terminal_counts"] = {"unknown": lifecycle["scenario_count"]}
    lifecycle_path.write_text(
        json.dumps(lifecycle, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = lifecycle_path.read_bytes()
    manifest["files"]["lifecycle.json"] = {
        "sha256": module.sha256_bytes(payload),
        "bytes": len(payload),
    }
    manifest["total_bytes"] = sum(item["bytes"] for item in manifest["files"].values())
    manifest["manifest_payload_sha256"] = module.sha256_bytes(
        module.canonical_bytes(manifest["files"])
    )
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    intent = json.loads((copied / "intent.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_batch_directory", lambda _root, _batch: copied)
    monkeypatch.setattr(
        module,
        "_assert_intent",
        lambda _root, _batch: (intent, config, copied),
    )
    with pytest.raises(ValueError, match="LIFECYCLE_RESULT_DRIFT"):
        module.validate_batch(tmp_path, FORMAL_BATCH)


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


def test_orderbook_wrapper_binds_exact_event_and_arrival_fields(module, proven_wrapper):
    row = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(proven_wrapper)],
        collected_at_ms=1100,
    )
    assert row["market_event_time_ms"] == 900
    assert row["source_arrival_time_ms"] == 950
    assert row["time_semantics_status"] == "pass"
    assert row["confirmed_visible_time_ms"] == 950


def test_orderbook_object_levels_are_supported(module):
    wrapper = {
        "snapshot_schema_version": 1,
        "source": "canonical_book",
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


def test_passive_order_never_fakes_queue_fill(module, proven_wrapper):
    member = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(proven_wrapper)],
        collected_at_ms=1100,
    )
    result = module.simulate_member(member, "被动限价撤销", "做多", "基准")
    assert result["terminal_state"] == "canceled"
    assert result["reason_code"] == "QUEUE_IDENTITY_UNAVAILABLE"


def test_unknown_time_prevents_all_lifecycle_actions(module, payload):
    member = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(payload)],
        collected_at_ms=1100,
    )
    result = module.simulate_member(member, "被动限价撤销", "做多", "基准")
    assert result["terminal_state"] == "unknown"
    assert result["events"] == []
    assert result["reason_code"] == "SOURCE_TIME_SEMANTICS_INCOMPLETE"


def test_symmetric_simulation_is_deterministic(module, proven_wrapper):
    member = module.normalize_snapshot(
        ["id", "BTCUSDT", "1000", "1001", json.dumps(proven_wrapper)],
        collected_at_ms=1100,
    )
    frozen = {"schema_version": "zhishi-simulated-order-frozen-input/v1", "members": [member]}
    first = module.simulate(frozen)
    second = module.simulate(frozen)
    assert first == second
    assert first["scenario_count"] == 12
    assert {row["direction"] for row in first["results"]} == {"做多", "做空"}
    assert len(first["groups"]) == 672
    assert {row["stage"] for row in first["groups"]} == {
        "created",
        "sent",
        "acknowledged",
        "evaluated",
        "terminal",
    }
    assert {row["contract"] for row in first["groups"]} == {"BTCUSDT永续合约", "ETHUSDT永续合约"}
    assert {row["result_status"] for row in first["groups"]} == {
        "created",
        "sent",
        "acknowledged",
        "evaluated",
        "filled",
        "canceled",
        "unknown",
    }
    assert all(
        set(row["state_counts"])
        == {"created", "sent", "acknowledged", "evaluated", "filled", "canceled", "unknown"}
        for row in first["groups"]
    )


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
        "manifest_sha256": "5a33fefc7df36d71ba82dd7a8af10f4d54fa54b2545ef4fb5cef07f2e73d5339",
        "summary_sha256": "fab695309dda98012b970187cf79208c5ae8fbb8b7775b00a89d07984cfcad7f",
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
