# Binance 历史归档来源身份合同

<!-- markdownlint-disable MD013 -->

## 目的

本合同定义本机固定 Binance USDⓈ-M 历史归档的逐成员来源身份证明。通过只表示文件与同名官方 CHECKSUM、固定公开对象清单和有界 Schema 事实闭合，不表示时间质量、研究准入、预测优势或交易许可。

## 固定范围

- 本地根：`/Volumes/data/data/binance/futures/um`。
- 已证明候选组：`trades/BTCUSDT`、`trades/ETHUSDT`、`aggTrades/BTCUSDT`。
- 远端端点：`https://s3-ap-northeast-1.amazonaws.com/data.binance.vision`。
- 远端前缀：`data/futures/um/daily/trades/BTCUSDT/`、`data/futures/um/daily/trades/ETHUSDT/`、`data/futures/um/daily/aggTrades/BTCUSDT/`。
- `klines_1d/BTCUSDT.csv`和`klines_1d/ETHUSDT.csv`没有同名官方 CHECKSUM，只作为`无法判定`观察项，不进入归档成员分母。

## 成员身份与证明链

每个成员按“精确合约、数据对象、日期、ZIP文件名”唯一标识，必须同时满足：

1. ZIP和同名`.CHECKSUM`均为固定目录直属普通文件，名称严格匹配；
2. 以1MiB块复算ZIP SHA-256并与CHECKSUM全等；
3. 官方清单存在精确ZIP键与CHECKSUM键，ZIP字节数全等；
4. 本地CHECKSUM完整字节MD5与官方CHECKSUM小对象非分段ETag全等；
5. ZIP只有一个同名直属CSV成员，有界首行可解析并形成Schema确切版本。

任一环不闭合时不得标记`已证明`。远端键缺失为`无法判定`；内容、大小、ETag、ZIP或Schema矛盾为`拒绝`；执行异常、未成熟和失效分别保留独立计数，不得缩小分母。

## 九字段来源身份

每个已证明成员记录：来源提供者、交易场所、市场类型、标的身份、精确合约、数据对象、Schema确切版本、授权边界和字段中文映射。来源提供者与交易场所固定为Binance，市场类型固定为USDⓈ-M合约，BTC与ETH独立统计。

逐笔成交映射为成交编号、成交价格、成交数量、计价资产成交额、事件时间和买方是否挂单方；聚合成交映射为聚合成交编号、成交价格、成交数量、首末成交编号、事件时间和买方是否挂单方。批次不得保存业务行、价格、数量或成交明细。

## 官方规则身份

官方规则固定为`binance/binance-public-data`提交`5c7f3197591c0d54d85dc43066226bc4c671d47a`的README，URL与预期SHA-256由配置固定。该规则说明公开历史数据按日/月归档，并为每个ZIP提供同目录CHECKSUM；URL、提交或内容哈希漂移即失败关闭。

## 不可变批次

批次目录只允许首次原子创建，禁止覆盖。批次保存输入清单前后指纹、配置/任务/执行器/curl/README/远端清单/Schema/授权指纹，标准JSON成员分片、排除项、逐组与总计数和资源事实。单文件小于5MiB、总输出小于25MiB。

## 安全与解释边界

验证单进程串行，不跟随符号链接，不解压落盘，不复制、删除、移动、重命名、修复或写回源文件。网络只读访问固定公开端点，使用系统TLS与主机名校验，不跟随重定向，不使用认证、代理凭据或证书降级。

本合同不修改任务-000084的旧630成员或状态，不访问Ubuntu、数据库、账户、生产服务或交易系统，不进行模型、回测、模拟交易或真实交易。来源证明不能单独推出完整性、连续性、无重复、因果、预测优势、胜率、收益、研究准入或交易许可。
