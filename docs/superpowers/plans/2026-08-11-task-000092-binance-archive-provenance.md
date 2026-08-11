# Task 000092 Binance Archive Provenance Implementation Plan

<!-- markdownlint-disable MD013 -->

> **For Codex:** REQUIRED SUB-SKILL: Use test-driven-development for implementation and verification-before-completion before delivery.

**Goal:** Validate the fixed local Binance BTC/ETH archive set without copying source data, bind every accepted ZIP to its CHECKSUM and the fixed public object listing, and publish a compact immutable provenance batch.

**Architecture:** A standard-library Python CLI loads an immutable JSON contract, deterministically discovers three allowlisted groups, validates official listing facts, streams local SHA-256 checks, inspects bounded ZIP schema facts, and atomically publishes split JSON evidence plus a summary. Unit tests use only temporary miniature archives and injected listing fixtures; the real run is single-process and read-only.

**Tech Stack:** Python 3 standard library, `/usr/bin/curl`, JSON/JSONL, Markdown, unittest.

---

## Task 1: Freeze execution state and contracts

- [x] Move task-000092 and the board from `待执行` to `执行中`.
- [x] Record the exact branch and RFC3339 start time.
- [x] Add the source-identity contract and fixed JSON configuration.
- [x] Confirm all network URLs, local roots, limits, counters and failure codes are literal and versioned.

## Task 2: Drive the validator with failing tests

- [x] Create `tests/数据/test_验证Binance历史归档来源身份.py` before the implementation exists.
- [x] Cover strict discovery, checksum parsing, streaming hash, ZIP member safety, schema fingerprinting, official object matching, deterministic ordering and no-overwrite publication.
- [x] Run the focused test and record the expected RED caused by the missing implementation.
- [x] Add negative tests for symlinks, traversal, pairing, invalid ETag, size drift, unsafe URL/prefix and no-overwrite output.

## Task 3: Implement the smallest compliant validator

- [x] Add `config/数据/任务-000092Binance历史归档来源身份.json` with exact local and remote allowlists.
- [x] Add `scripts/数据/验证Binance历史归档来源身份.py` using only the standard library and direct argument-array curl invocation.
- [x] Keep hashing and ZIP reads bounded and serial; never extract, copy, rename or write to source paths.
- [x] Publish compact JSON shards, exclusions, summary and fingerprints through an atomic new directory.
- [x] Run focused tests until GREEN, then the full data test suite.

## Task 4: Produce one real immutable batch

- [x] Measure memory and disk before starting; stop below contract limits.
- [x] Fingerprint the source inventory before the run.
- [x] Fetch only the pinned README and three fixed ListObjectsV1 prefixes with trusted TLS.
- [x] Validate every discovered ZIP/CHECKSUM pair sequentially and write progress without verbose per-row logging.
- [x] Fingerprint the source inventory after the run and prove it is unchanged.
- [x] Verify group and global counter conservation, output size limits and absence of business values or sensitive data.

## Task 5: Deliver and close safely

- [x] Run focused, data and audit tests plus Python compilation; run clean-baseline R&D-center, MarkdownLint, sensitive scan and `git diff --check` after the status commit.
- [x] Update task-000092 and the board to `待评审`, recording the exact batch, commit, PR, results and limits.
- [x] Commit, push and create one task-delivery PR to `main`.
- [ ] Obtain two independent read-only APPROVE reviews, automatically repair any P0/P1 and revalidate the exact head.
- [ ] Trigger the trusted exact-SHA auto-merge workflow, then create and merge the independent completion-state PR.
