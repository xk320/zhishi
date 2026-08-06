# Ubuntu未完整扫描对象正文质量复验报告

<!-- markdownlint-disable MD013 -->

- 审计批次：`批次-20260806T040336Z-v4`
- 合同版本指纹：`0acd47b2f1396dc1aadd604d20386fb8b0e6ff346101571f5352424091884d8d`
- 覆盖矩阵指纹：`6fae22c00a2599207dd388e25b444500ca2988b982cc2c2d2c18bb9b04ef3d79`
- 规则脚本指纹：`a3e1e5b933d3674015800d8b424b8bf0f97ba9d3038fe11e58c31758d5f5bcc7`
- 数据库对象：92；敏感日志文件：2；合同授权截止：`2026-08-07T00:00:00+08:00`；本批次数据截止：`2026-08-06T12:00:00+08:00`
- 远端入口：仅使用白名单逻辑别名`ubuntu`；不写入远端临时文件，不输出用户名、原始日志或业务字段值。

## 状态摘要

| 状态 | 对象数 |
| --- | ---: |
| 通过 | 19 |
| 拒绝 | 0 |
| 无法判定 | 33 |
| 失败 | 5 |
| 未成熟 | 37 |
| 失效 | 0 |
| 未执行 | 0 |
| 合计 | 94 |

## 资源与安全

- 数据库逐对象最多读取65536字节、30秒，串行执行，远端进程内存上限512MiB；日志逐对象最多32768字节、批次最多65536字节、30秒，内存上限512MiB。
- 数据库只输出记录数、时间字段可解析计数、状态和指纹；日志只输出脱敏计数、状态和内容指纹。
- 发生权限不足、超时、未来时间、输入漂移、输出不完整或敏感信息泄漏时，状态保持失败安全，不发布半批次。
- 这批次不计算胜率、收益、方向、仓位、订单或交易许可；不关闭ZS-DATA-GAP-003/005，不放行阶段2。

## 逐对象脱敏证据

逐对象结果保存在同批次`对象结果.jsonl`；仅包含资产编号、对象指纹、状态、计数、资源与错误类别。

| 资产编号 | 状态 | 记录数 | 错误类别 |
| --- | --- | ---: | --- |
| DS-000225 | 无法判定 | 6722 | no_freezable_time_field |
| DS-000226 | 未成熟 | 0 | empty_object |
| DS-000227 | 未成熟 | 0 | empty_object |
| DS-000228 | 未成熟 | 0 | empty_object |
| DS-000229 | 无法判定 | 250 | time_alignment_incomplete |
| DS-000230 | 无法判定 | 5283 | no_freezable_time_field |
| DS-000231 | 无法判定 | 5285 | no_freezable_time_field |
| DS-000232 | 无法判定 | 93 | time_alignment_incomplete |
| DS-000233 | 无法判定 | 91 | no_freezable_time_field |
| DS-000234 | 无法判定 | 21 | time_alignment_incomplete |
| DS-000235 | 未成熟 | 0 | empty_object |
| DS-000236 | 未成熟 | 0 | empty_object |
| DS-000237 | 未成熟 | 0 | empty_object |
| DS-000238 | 未成熟 | 0 | empty_object |
| DS-000239 | 无法判定 | 2214031 | no_freezable_time_field |
| DS-000240 | 无法判定 | 1 | time_alignment_incomplete |
| DS-000241 | 无法判定 | 37682063 | time_alignment_incomplete |
| DS-000242 | 未成熟 | 0 | empty_object |
| DS-000243 | 未成熟 | 0 | empty_object |
| DS-000244 | 未成熟 | 0 | empty_object |
| DS-000245 | 未成熟 | 0 | empty_object |
| DS-000246 | 未成熟 | 0 | empty_object |
| DS-000247 | 未成熟 | 0 | empty_object |
| DS-000248 | 未成熟 | 0 | empty_object |
| DS-000249 | 未成熟 | 0 | empty_object |
| DS-000250 | 未成熟 | 0 | empty_object |
| DS-000251 | 未成熟 | 0 | empty_object |
| DS-000252 | 无法判定 | 1610 | time_alignment_incomplete |
| DS-000253 | 无法判定 | 1 | no_freezable_time_field |
| DS-000254 | 通过 | 8017 | — |
| DS-000255 | 无法判定 | 4039 | time_alignment_incomplete |
| DS-000256 | 通过 | 11 | — |
| DS-000257 | 无法判定 | 1781 | time_alignment_incomplete |
| DS-000258 | 通过 | 397 | — |
| DS-000259 | 未成熟 | 0 | empty_object |
| DS-000260 | 失败 | 2042 | future_timestamp_detected |
| DS-000261 | 无法判定 | 36 | time_alignment_incomplete |
| DS-000262 | 无法判定 | 940 | time_alignment_incomplete |
| DS-000263 | 通过 | 68 | — |
| DS-000264 | 通过 | 790 | — |
| DS-000265 | 通过 | 31 | — |
| DS-000266 | 通过 | 230 | — |
| DS-000267 | 通过 | 369 | — |
| DS-000268 | 未成熟 | 0 | empty_object |
| DS-000269 | 未成熟 | 0 | empty_object |
| DS-000270 | 无法判定 | 212 | time_alignment_incomplete |
| DS-000271 | 通过 | 38833 | — |
| DS-000272 | 通过 | 10 | — |
| DS-000273 | 通过 | 2 | — |
| DS-000274 | 通过 | 31 | — |
| DS-000275 | 通过 | 14 | — |
| DS-000276 | 通过 | 1 | — |
| DS-000277 | 通过 | 42 | — |
| DS-000278 | 无法判定 | 2190 | time_alignment_incomplete |
| DS-000279 | 无法判定 | 556804 | time_alignment_incomplete |
| DS-000280 | 失败 | — | query_timeout |
| DS-000281 | 无法判定 | 41319 | time_alignment_incomplete |
| DS-000282 | 无法判定 | 29917 | time_alignment_incomplete |
| DS-000283 | 无法判定 | 27422 | time_alignment_incomplete |
| DS-000284 | 无法判定 | 589844 | time_alignment_incomplete |
| DS-000285 | 失败 | — | query_timeout |
| DS-000286 | 无法判定 | 24319 | time_alignment_incomplete |
| DS-000287 | 无法判定 | 268441 | time_alignment_incomplete |
| DS-000288 | 无法判定 | 4392 | time_alignment_incomplete |
| DS-000289 | 失败 | — | query_timeout |
| DS-000290 | 无法判定 | 114602 | time_alignment_incomplete |
| DS-000291 | 无法判定 | 1851931 | time_alignment_incomplete |
| DS-000292 | 失败 | — | query_timeout |
| DS-000293 | 无法判定 | 2 | time_alignment_incomplete |
| DS-000294 | 未成熟 | 0 | empty_object |
| DS-000295 | 无法判定 | 1 | no_freezable_time_field |
| DS-000296 | 通过 | 6 | — |
| DS-000297 | 无法判定 | 20 | time_alignment_incomplete |
| DS-000298 | 未成熟 | 0 | empty_object |
| DS-000299 | 无法判定 | 4 | time_alignment_incomplete |
| DS-000300 | 未成熟 | 0 | empty_object |
| DS-000301 | 未成熟 | 0 | empty_object |
| DS-000302 | 通过 | 6 | — |
| DS-000303 | 未成熟 | 0 | empty_object |
| DS-000304 | 无法判定 | 3 | time_alignment_incomplete |
| DS-000305 | 未成熟 | 0 | empty_object |
| DS-000306 | 未成熟 | 0 | empty_object |
| DS-000307 | 未成熟 | 0 | empty_object |
| DS-000308 | 未成熟 | 0 | empty_object |
| DS-000309 | 通过 | 3 | — |
| DS-000310 | 未成熟 | 0 | empty_object |
| DS-000311 | 未成熟 | 0 | empty_object |
| DS-000312 | 未成熟 | 0 | empty_object |
| DS-000313 | 通过 | 6 | — |
| DS-000314 | 未成熟 | 0 | empty_object |
| DS-000315 | 未成熟 | 0 | empty_object |
| DS-000316 | 未成熟 | 0 | empty_object |
| DS-000222 | 未成熟 | 0 | — |
| DS-000223 | 未成熟 | 0 | — |

## 结论与限制

- 本批次只证明白名单对象在当前截止事实下可执行的结构性质量观察；描述性状态不能推导因果、预测优势、胜率、收益或交易许可。
- 三个输入身份漂移文件不在本批次授权范围，继续沿用任务-000063的拒绝事实；BTC/ETH不跨标的补偿，SOL不进入前向范围。
- 空日志记录为`未成熟`，任何未知、失败和未成熟状态均保留，不缩小分母。
