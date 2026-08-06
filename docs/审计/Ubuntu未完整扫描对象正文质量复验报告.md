# Ubuntu未完整扫描对象正文质量复验报告

<!-- markdownlint-disable MD013 -->

- 审计批次：`批次-20260806T043100Z-v5`
- 合同版本指纹：`0acd47b2f1396dc1aadd604d20386fb8b0e6ff346101571f5352424091884d8d`
- 覆盖矩阵指纹：`6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79`
- 规则脚本指纹：`eac097e3ed96c974c9df0d100a589ff7775d9253e8697680e2419d238be63834`
- 数据库对象：92；敏感日志文件：2；合同授权截止：`2026-08-07T00:00:00+08:00`；本批次数据截止：`2026-08-06T12:00:00+08:00`
- 远端入口：仅使用白名单逻辑别名的固定指纹；不写入远端临时文件，不输出用户名、原始日志或业务字段值。

## 状态摘要

| 状态 | 对象数 |
| --- | ---: |
| 通过 | 0 |
| 拒绝 | 0 |
| 无法判定 | 91 |
| 失败 | 1 |
| 未成熟 | 2 |
| 失效 | 0 |
| 未执行 | 0 |
| 合计 | 94 |

## 资源与安全

- 数据库仅在EXPLAIN证明可使用索引后读取单个时间字段的最多64行；每个对象输出最多65536字节、30秒，批次最多600秒/8MiB，串行执行，远端进程内存上限512MiB。
- 未执行COUNT、MIN、MAX或无界全表聚合；无法证明有界索引路径的对象保持无法判定，空样本不解释为未成熟。
- 数据库与日志只输出指纹、计数、状态、资源和错误类别；发生权限不足、超时、未来时间、输入漂移、输出不完整或敏感信息泄漏时失败关闭。
- 这批次不计算胜率、收益、方向、仓位、订单或交易许可；不关闭ZS-DATA-GAP-003/005，不放行阶段2。

## 逐对象脱敏证据

逐对象结果保存在同批次`对象结果.json`；仅包含资产编号、对象指纹、状态、计数、资源与错误类别。

| 资产编号 | 状态 | 记录数 | 已观察记录数 | 错误类别 |
| --- | --- | ---: | ---: | --- |
| DS-000225 | 无法判定 | — | — | no_freezable_time_field |
| DS-000226 | 无法判定 | — | — | no_freezable_time_field |
| DS-000227 | 无法判定 | — | — | no_freezable_time_field |
| DS-000228 | 无法判定 | — | — | time_field_not_indexed |
| DS-000229 | 无法判定 | — | — | time_field_not_indexed |
| DS-000230 | 无法判定 | — | — | no_freezable_time_field |
| DS-000231 | 无法判定 | — | — | no_freezable_time_field |
| DS-000232 | 无法判定 | — | — | time_field_not_indexed |
| DS-000233 | 无法判定 | — | — | no_freezable_time_field |
| DS-000234 | 无法判定 | — | — | time_field_not_indexed |
| DS-000235 | 无法判定 | — | — | no_freezable_time_field |
| DS-000236 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000237 | 无法判定 | — | — | time_field_not_indexed |
| DS-000238 | 无法判定 | — | — | no_freezable_time_field |
| DS-000239 | 无法判定 | — | — | no_freezable_time_field |
| DS-000240 | 无法判定 | — | — | time_field_not_indexed |
| DS-000241 | 无法判定 | — | — | time_field_not_indexed |
| DS-000242 | 无法判定 | — | — | no_freezable_time_field |
| DS-000243 | 无法判定 | — | — | no_freezable_time_field |
| DS-000244 | 无法判定 | — | — | no_freezable_time_field |
| DS-000245 | 无法判定 | — | — | time_field_not_indexed |
| DS-000246 | 无法判定 | — | — | time_field_not_indexed |
| DS-000247 | 无法判定 | — | — | no_freezable_time_field |
| DS-000248 | 无法判定 | — | — | no_freezable_time_field |
| DS-000249 | 无法判定 | — | — | time_field_not_indexed |
| DS-000250 | 无法判定 | — | — | no_freezable_time_field |
| DS-000251 | 无法判定 | — | — | time_field_not_indexed |
| DS-000252 | 无法判定 | — | — | time_field_not_indexed |
| DS-000253 | 无法判定 | — | — | no_freezable_time_field |
| DS-000254 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000255 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000256 | 无法判定 | — | — | time_field_not_indexed |
| DS-000257 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000258 | 无法判定 | — | — | time_field_not_indexed |
| DS-000259 | 无法判定 | — | — | time_field_not_indexed |
| DS-000260 | 失败 | — | 64 | future_timestamp_detected |
| DS-000261 | 无法判定 | — | 36 | bounded_sample_only |
| DS-000262 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000263 | 无法判定 | — | — | time_field_not_indexed |
| DS-000264 | 无法判定 | — | — | time_field_not_indexed |
| DS-000265 | 无法判定 | — | — | time_field_not_indexed |
| DS-000266 | 无法判定 | — | — | time_field_not_indexed |
| DS-000267 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000268 | 无法判定 | — | — | time_field_not_indexed |
| DS-000269 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000270 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000271 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000272 | 无法判定 | — | — | time_field_not_indexed |
| DS-000273 | 无法判定 | — | — | time_field_not_indexed |
| DS-000274 | 无法判定 | — | — | time_field_not_indexed |
| DS-000275 | 无法判定 | — | — | time_field_not_indexed |
| DS-000276 | 无法判定 | — | — | time_field_not_indexed |
| DS-000277 | 无法判定 | — | — | time_field_not_indexed |
| DS-000278 | 无法判定 | — | — | time_field_not_indexed |
| DS-000279 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000280 | 无法判定 | — | — | time_field_not_indexed |
| DS-000281 | 无法判定 | — | — | time_field_not_indexed |
| DS-000282 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000283 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000284 | 无法判定 | — | — | time_field_not_indexed |
| DS-000285 | 无法判定 | — | — | time_field_not_indexed |
| DS-000286 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000287 | 无法判定 | — | — | time_field_not_indexed |
| DS-000288 | 无法判定 | — | — | time_field_not_indexed |
| DS-000289 | 无法判定 | — | — | time_field_not_indexed |
| DS-000290 | 无法判定 | — | — | time_field_not_indexed |
| DS-000291 | 无法判定 | — | — | time_field_not_indexed |
| DS-000292 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000293 | 无法判定 | — | — | time_field_not_indexed |
| DS-000294 | 无法判定 | — | — | time_field_not_indexed |
| DS-000295 | 无法判定 | — | — | no_freezable_time_field |
| DS-000296 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000297 | 无法判定 | — | 20 | bounded_sample_only |
| DS-000298 | 无法判定 | — | — | time_field_not_indexed |
| DS-000299 | 无法判定 | — | 4 | bounded_sample_only |
| DS-000300 | 无法判定 | — | — | time_field_not_indexed |
| DS-000301 | 无法判定 | — | — | time_field_not_indexed |
| DS-000302 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000303 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000304 | 无法判定 | — | 3 | bounded_sample_only |
| DS-000305 | 无法判定 | — | — | time_field_not_indexed |
| DS-000306 | 无法判定 | — | — | time_field_not_indexed |
| DS-000307 | 无法判定 | — | — | time_field_not_indexed |
| DS-000308 | 无法判定 | — | — | time_field_not_indexed |
| DS-000309 | 无法判定 | — | 3 | bounded_sample_only |
| DS-000310 | 无法判定 | — | — | time_field_not_indexed |
| DS-000311 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000312 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000313 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000314 | 无法判定 | — | — | time_field_not_indexed |
| DS-000315 | 无法判定 | — | — | time_field_not_indexed |
| DS-000316 | 无法判定 | — | — | time_field_not_indexed |
| DS-000222 | 未成熟 | 0 | — | — |
| DS-000223 | 未成熟 | 0 | — | — |

## 结论与限制

- 本批次只证明白名单对象在当前截止事实下可执行的结构性质量观察；描述性状态不能推导因果、预测优势、胜率、收益或交易许可。
- 三个输入身份漂移文件不在本批次授权范围，继续沿用任务-000063的拒绝事实；BTC/ETH不跨标的补偿，SOL不进入前向范围。
- 数据库有界样本不能替代全量正文质量证明；无法判定、失败和未成熟状态均保留，不缩小分母。

---

# Ubuntu未完整扫描对象正文质量复验报告

<!-- markdownlint-disable MD013 -->

- 审计批次：`批次-20260806T044500Z-v6`
- 合同版本指纹：`0acd47b2f1396dc1aadd604d20386fb8b0e6ff346101571f5352424091884d8d`
- 覆盖矩阵指纹：`6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79`
- 规则脚本指纹：`fe21d68e2b6424d80a3856e4b64e5170ba962402bc80bd943caca5bf06fe3fe3`
- 数据库对象：92；敏感日志文件：2；合同授权截止：`2026-08-07T00:00:00+08:00`；本批次数据截止：`2026-08-06T12:00:00+08:00`
- 远端入口：仅使用白名单逻辑别名的固定指纹；不写入远端临时文件，不输出用户名、原始日志或业务字段值。

## 状态摘要

| 状态 | 对象数 |
| --- | ---: |
| 通过 | 0 |
| 拒绝 | 0 |
| 无法判定 | 91 |
| 失败 | 1 |
| 未成熟 | 2 |
| 失效 | 0 |
| 未执行 | 0 |
| 合计 | 94 |

## 资源与安全

- 数据库仅在EXPLAIN证明可使用索引后读取单个时间字段的最多64行；每个对象输出最多65536字节、30秒，批次最多600秒/8MiB，串行执行，远端进程内存上限512MiB。
- 未执行COUNT、MIN、MAX或无界全表聚合；无法证明有界索引路径的对象保持无法判定，空样本不解释为未成熟。
- 数据库与日志只输出指纹、计数、状态、资源和错误类别；发生权限不足、超时、未来时间、输入漂移、输出不完整或敏感信息泄漏时失败关闭。
- 这批次不计算胜率、收益、方向、仓位、订单或交易许可；不关闭ZS-DATA-GAP-003/005，不放行阶段2。

## 逐对象脱敏证据

逐对象结果保存在同批次`对象结果.json`；仅包含资产编号、对象指纹、状态、计数、资源与错误类别。

| 资产编号 | 状态 | 记录数 | 已观察记录数 | 错误类别 |
| --- | --- | ---: | ---: | --- |
| DS-000225 | 无法判定 | — | — | no_freezable_time_field |
| DS-000226 | 无法判定 | — | — | no_freezable_time_field |
| DS-000227 | 无法判定 | — | — | no_freezable_time_field |
| DS-000228 | 无法判定 | — | — | time_field_not_indexed |
| DS-000229 | 无法判定 | — | — | time_field_not_indexed |
| DS-000230 | 无法判定 | — | — | no_freezable_time_field |
| DS-000231 | 无法判定 | — | — | no_freezable_time_field |
| DS-000232 | 无法判定 | — | — | time_field_not_indexed |
| DS-000233 | 无法判定 | — | — | no_freezable_time_field |
| DS-000234 | 无法判定 | — | — | time_field_not_indexed |
| DS-000235 | 无法判定 | — | — | no_freezable_time_field |
| DS-000236 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000237 | 无法判定 | — | — | time_field_not_indexed |
| DS-000238 | 无法判定 | — | — | no_freezable_time_field |
| DS-000239 | 无法判定 | — | — | no_freezable_time_field |
| DS-000240 | 无法判定 | — | — | time_field_not_indexed |
| DS-000241 | 无法判定 | — | — | time_field_not_indexed |
| DS-000242 | 无法判定 | — | — | no_freezable_time_field |
| DS-000243 | 无法判定 | — | — | no_freezable_time_field |
| DS-000244 | 无法判定 | — | — | no_freezable_time_field |
| DS-000245 | 无法判定 | — | — | time_field_not_indexed |
| DS-000246 | 无法判定 | — | — | time_field_not_indexed |
| DS-000247 | 无法判定 | — | — | no_freezable_time_field |
| DS-000248 | 无法判定 | — | — | no_freezable_time_field |
| DS-000249 | 无法判定 | — | — | time_field_not_indexed |
| DS-000250 | 无法判定 | — | — | no_freezable_time_field |
| DS-000251 | 无法判定 | — | — | time_field_not_indexed |
| DS-000252 | 无法判定 | — | — | time_field_not_indexed |
| DS-000253 | 无法判定 | — | — | no_freezable_time_field |
| DS-000254 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000255 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000256 | 无法判定 | — | — | time_field_not_indexed |
| DS-000257 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000258 | 无法判定 | — | — | time_field_not_indexed |
| DS-000259 | 无法判定 | — | — | time_field_not_indexed |
| DS-000260 | 失败 | — | 64 | future_timestamp_detected |
| DS-000261 | 无法判定 | — | 36 | bounded_sample_only |
| DS-000262 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000263 | 无法判定 | — | — | time_field_not_indexed |
| DS-000264 | 无法判定 | — | — | time_field_not_indexed |
| DS-000265 | 无法判定 | — | — | time_field_not_indexed |
| DS-000266 | 无法判定 | — | — | time_field_not_indexed |
| DS-000267 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000268 | 无法判定 | — | — | time_field_not_indexed |
| DS-000269 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000270 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000271 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000272 | 无法判定 | — | — | time_field_not_indexed |
| DS-000273 | 无法判定 | — | — | time_field_not_indexed |
| DS-000274 | 无法判定 | — | — | time_field_not_indexed |
| DS-000275 | 无法判定 | — | — | time_field_not_indexed |
| DS-000276 | 无法判定 | — | — | time_field_not_indexed |
| DS-000277 | 无法判定 | — | — | time_field_not_indexed |
| DS-000278 | 无法判定 | — | — | time_field_not_indexed |
| DS-000279 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000280 | 无法判定 | — | — | time_field_not_indexed |
| DS-000281 | 无法判定 | — | — | time_field_not_indexed |
| DS-000282 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000283 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000284 | 无法判定 | — | — | time_field_not_indexed |
| DS-000285 | 无法判定 | — | — | time_field_not_indexed |
| DS-000286 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000287 | 无法判定 | — | — | time_field_not_indexed |
| DS-000288 | 无法判定 | — | — | time_field_not_indexed |
| DS-000289 | 无法判定 | — | — | time_field_not_indexed |
| DS-000290 | 无法判定 | — | — | time_field_not_indexed |
| DS-000291 | 无法判定 | — | — | time_field_not_indexed |
| DS-000292 | 无法判定 | — | 64 | bounded_sample_only |
| DS-000293 | 无法判定 | — | — | time_field_not_indexed |
| DS-000294 | 无法判定 | — | — | time_field_not_indexed |
| DS-000295 | 无法判定 | — | — | no_freezable_time_field |
| DS-000296 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000297 | 无法判定 | — | 20 | bounded_sample_only |
| DS-000298 | 无法判定 | — | — | time_field_not_indexed |
| DS-000299 | 无法判定 | — | 4 | bounded_sample_only |
| DS-000300 | 无法判定 | — | — | time_field_not_indexed |
| DS-000301 | 无法判定 | — | — | time_field_not_indexed |
| DS-000302 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000303 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000304 | 无法判定 | — | 3 | bounded_sample_only |
| DS-000305 | 无法判定 | — | — | time_field_not_indexed |
| DS-000306 | 无法判定 | — | — | time_field_not_indexed |
| DS-000307 | 无法判定 | — | — | time_field_not_indexed |
| DS-000308 | 无法判定 | — | — | time_field_not_indexed |
| DS-000309 | 无法判定 | — | 3 | bounded_sample_only |
| DS-000310 | 无法判定 | — | — | time_field_not_indexed |
| DS-000311 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000312 | 无法判定 | — | 0 | empty_sample_not_maturity |
| DS-000313 | 无法判定 | — | 6 | bounded_sample_only |
| DS-000314 | 无法判定 | — | — | time_field_not_indexed |
| DS-000315 | 无法判定 | — | — | time_field_not_indexed |
| DS-000316 | 无法判定 | — | — | time_field_not_indexed |
| DS-000222 | 未成熟 | 0 | — | — |
| DS-000223 | 未成熟 | 0 | — | — |

## 结论与限制

- 本批次只证明白名单对象在当前截止事实下可执行的结构性质量观察；描述性状态不能推导因果、预测优势、胜率、收益或交易许可。
- 三个输入身份漂移文件不在本批次授权范围，继续沿用任务-000063的拒绝事实；BTC/ETH不跨标的补偿，SOL不进入前向范围。
- 数据库有界样本不能替代全量正文质量证明；无法判定、失败和未成熟状态均保留，不缩小分母。
