# 任务-000071：订单簿共享数据源字段与时间索引合同

<!-- markdownlint-disable MD013 -->

## 合同定位

本合同是任务-000071的设计输入，只定义订单簿源代码声明与远端共享表元数据之间的可复核映射，不是数据库迁移方案，也不是数据质量通过或研究准入结论。

冻结源代码：订单簿系统提交`030499faca3d6955d75c75cbc59656a4981f6c05`。

冻结文件：`src/orderbook_service/storage.py`，SHA-256：`d4fed7bf0fc89666a9836a17f144ef41d2a6d13d829124437032c9787bf9b05d`。

## 16个已登记共享表的声明映射

| 表 | 主键/唯一键 | 事件或研究时间候选 | 到达/采集时间候选 | 关键业务键 | 时间单位 | 远端状态初始值 |
| --- | --- | --- | --- | --- | --- | --- |
| `order_book_feature_buckets` | `exchange,symbol,bucket_ts_sec,aggregation,feature_version` | `bucket_ts_sec` | `created_at`,`updated_at` | `exchange,symbol,aggregation,feature_version` | 秒（桶）；毫秒（审计时间） | 无法判定 |
| `order_book_micro_events` | `event_id` | `ts_ms`,`bucket_ts_sec` | `created_at` | `symbol,event_type` | 毫秒/秒 | 无法判定 |
| `order_book_signals` | `signal_offset`; `signal_id`唯一 | `ts_ms`,`bucket_ts_sec` | `created_at` | `symbol,signal,dedupe_key` | 毫秒/秒 | 无法判定 |
| `raw_input_log` | `log_sequence` | `event_time_ms`,`transaction_time_ms` | `recv_ts_ms`,`local_recv_monotonic_ms` | `exchange,symbol,stream,stream_type,source_sequence` | 毫秒 | 无法判定 |
| `symbol_metadata` | `exchange,symbol` | `metadata_updated_at_ms` | `created_at`,`updated_at` | `exchange,symbol,contract_type` | 毫秒 | 无法判定 |
| `order_book_risk_states` | `risk_id` | `ts_ms` | `created_at` | `symbol,risk_state,reason_code` | 毫秒 | 无法判定 |
| `order_book_health_events` | `event_id` | `ts_ms` | `created_at` | `symbol,component,status_after` | 毫秒 | 无法判定 |
| `order_book_raw_snapshots` | `snapshot_id` | `capture_ts_ms`,`bucket_ts_sec` | `created_at` | `exchange,symbol,capture_reason` | 毫秒/秒 | 无法判定 |
| `order_book_signal_delivery_acks` | `delivery_id` | `sent_ts_ms`,`acked_ts_ms` | `created_at`,`updated_at` | `signal_offset,subscriber_id,delivery_channel` | 毫秒 | 无法判定 |
| `order_book_liquidation_events` | `event_id` | `event_time_ms` | `transaction_time_ms`,`local_recv_ts_ms`,`created_at` | `exchange,symbol,source_kind,order_side` | 毫秒 | 无法判定 |
| `order_book_liquidation_heatmap_buckets` | `symbol,source_kind,bucket_start_ms,price_bucket_start,side` | `bucket_start_ms`,`bucket_end_ms` | `created_at`,`updated_at` | `symbol,source_kind,side` | 毫秒 | 无法判定 |
| `order_book_open_interest` | `symbol,period,timestamp_ms` | `timestamp_ms` | `created_at`,`updated_at` | `symbol,period` | 毫秒 | 无法判定 |
| `order_book_market_structure_snapshots` | `snapshot_id` | `as_of_ms` | `created_at`,`updated_at` | `symbol,structure_version` | 毫秒 | 无法判定 |
| `order_book_public_context_snapshots` | `snapshot_id` | `as_of_ms` | `created_at`,`updated_at` | `symbol,source,provider` | 毫秒 | 无法判定 |
| `order_book_decision_context_snapshots` | `decision_id`; `(symbol,input_snapshot_id,decision_model_version)`唯一 | `decision_time_ms`,`as_of_ms` | `created_at`,`updated_at` | `symbol,input_snapshot_id,decision_model_version` | 毫秒 | 无法判定 |
| `historical_backfill_files` | `data_source,market_type,dataset,symbol,interval_name,file_date` | `file_date`（文件日期，不等同事件时间） | `created_at_ms`,`updated_at_ms` | `data_source,market_type,dataset,symbol,interval_name` | 日期/毫秒 | 无法判定 |

表内字段只是源代码声明。只有远端列类型、键、索引顺序与本表完全匹配，并且已有来源、时区、精度、迟到、修订和截止合同，才可以把相应字段用于质量审计；`created_at`、`updated_at`和文件修改时间不得自动替代事件时间。

## 未登记源代码候选（不执行远端查询）

`order_book_derived_state_revisions`只存在于冻结的`storage.py`源代码声明中，当前任务-000063覆盖矩阵没有对应资产编号，因此不进入任务-000071的远端对象清单。它不能被分配临时编号、不能冒充16个已登记对象，也不能被用来补偿BTC或ETH缺口；如需纳入，必须先建立独立任务合同和数据资产登记。

## 远端复核规则

1. 本任务先将`远程共享表元数据固定入口.py`以root-owned文件安装到白名单Ubuntu，固定协议`zhishi-ro/schema-audit/1`、固定16个目标和目标清单SHA-256、固定字段白名单、资源合同和脚本指纹；批次结束后撤销临时调用密钥并记录撤销事实。
2. 固定入口只读取`information_schema.COLUMNS`、`information_schema.STATISTICS`以及固定只读身份的`CURRENT_USER()`/`SHOW GRANTS`授权快照；按任务-000063资产成员顺序、列序以及`INDEX_NAME`（casefold）、`SEQ_IN_INDEX`和列名（casefold）规范化索引顺序输出指纹，不接受远程命令、任意SQL、未登记对象或业务字段。
3. 列指纹包含`COLUMN_NAME`、`COLUMN_TYPE`、`ORDINAL_POSITION`、`IS_NULLABLE`和`COLUMN_KEY`；索引指纹包含`INDEX_NAME`、`SEQ_IN_INDEX`、`COLUMN_NAME`、`NON_UNIQUE`和`INDEX_TYPE`，以便复核长度/unsigned、空值、主键和唯一性。
4. 逐表状态固定为：`匹配`、`漂移`、`未发现`、`无法判定`、`失败`；未知字段、权限不足、指纹漂移和超限均不能标记为匹配。
5. `匹配`仅表示结构声明一致，不表示有数据、有历史覆盖、有BTC/ETH独立证据或质量通过。
6. 16个表之外的对象不纳入本合同；不得用未登记候选、其它对象、其它标的或SOL数据补齐缺失。
7. 批次只保存对象编号、表身份指纹、结构指纹、状态、原因码和资源事实，不保存列值、业务正文、连接串或凭据。

## 研究尺度与安全边界

主研究尺度固定为4小时、8小时、24小时、48小时；15分钟和1小时只能作为事后结果观察窗口。描述性结构匹配不能推出因果、预测优势、胜率、收益、研究准入或交易许可。

本合同不授权数据库写入、索引变更、数据迁移、生产服务变更、模型训练、回测或交易操作。阶段1总门仍由任务-000037根据完整证据裁决。
