# WAF - Web Application Firewall

一个轻量级的 WAF 系统，可以识别和拦截 L4 和 L7 层的网络攻击，主要防御 Web 攻击。

## 功能特性

### L4 层防护 (传输层)
- TCP/UDP 协议识别
- 连接限流、DDoS 防护
- 异常端口检测
- SYN flood 防护
- 端口扫描检测

### L7 层防护 (应用层)
- HTTP/1.1 请求解析
- HTTP/2 直连流量解析（prior knowledge / cleartext h2）
- HTTP/3 请求解析（需 `--features http3` 且配置证书）
- HTTP/3 / QUIC datagram 元数据识别
- SQL 注入检测
- XSS 攻击检测
- 路径遍历防护
- 命令注入检测
- 恶意文件上传检测

## 技术栈

- **Rust 2021 Edition**
- **Tokio** - 异步运行时
- **pnet** - 底层网络包捕获
- **regex** - 正则表达式规则引擎
- **axum** - HTTP API 服务器
- **serde** - 序列化/反序列化

## 项目结构

```
src/
├── main.rs              # 主入口
├── core/                # 核心逻辑
│   ├── mod.rs          # 模块定义
│   ├── engine.rs       # WAF 引擎
│   └── packet.rs       # 数据包和检测结果定义
├── l4/                 # L4 层检测
│   └── mod.rs          # 传输层检测逻辑
├── l7/                 # L7 层检测
│   └── mod.rs          # 应用层检测逻辑
├── rules/              # 规则引擎
│   └── mod.rs          # 规则匹配和管理
├── config/             # 配置管理
│   ├── mod.rs          # 配置结构和加载
│   ├── l4.rs           # L4 配置
│   └── l7.rs           # L7 配置
├── metrics/            # 统计监控
│   └── mod.rs          # 指标收集和统计
└── api/                # 管理 API
    └── mod.rs          # REST API 接口
```

## 快速开始

### 编译

```bash
cargo build
```

### 运行

```bash
cargo run
```

程序会启动一个轻量 HTTP 检测服务，默认监听 `0.0.0.0:8080`。
你可以直接用 `curl` 验证：

```bash
curl -i http://127.0.0.1:8080/
curl -i "http://127.0.0.1:8080/?q=' OR '1'='1"
```

默认会优先读取以下配置文件：

- `config/waf.json`
- `config/minimal.json`
- `waf.json`

也可以通过环境变量显式指定：

```bash
WAF_CONFIG=./config/minimal.json cargo run
```

### 检查代码

```bash
cargo check
```

## 配置

配置文件支持以下选项：

- **interface**: 监听的网络接口
- **runtime_profile**: 运行档位，支持 `minimal` / `standard`
- **listen_addrs**: WAF 监听地址数组（旧版 `listen_addr` 仍会在加载时自动兼容转换）
- **tcp_upstream_addr**: HTTP/1.1 over TCP 放行流量的回源地址，未配置时返回本地检测结果
- **udp_upstream_addr**: UDP 放行流量的回源地址，未配置时仅检测不转发
- **api_enabled**: 管理 API 开关
- **api_bind**: 管理 API 监听地址
- **bloom_enabled**: Bloom Filter 开关
- **l4_bloom_false_positive_verification**: L4 Bloom 命中后是否用精确集合校验，便于验证假阳性
- **l7_bloom_false_positive_verification**: L7 Bloom 命中后是否用精确集合校验，便于验证假阳性
- **maintenance_interval_secs**: 统一维护任务周期
- **sqlite_enabled**: SQLite 持久化开关
- **sqlite_path**: SQLite 数据库文件路径
- **sqlite_auto_migrate**: 启动时自动建表
- **sqlite_rules_enabled**: 使用 SQLite 作为规则持久化和热加载来源
- **l4_config**: L4 层防护配置
  - ddos_protection_enabled: DDoS 防护开关
  - advanced_ddos_enabled: 高级 DDoS 检测开关
  - connection_rate_limit: 连接速率限制
  - syn_flood_threshold: SYN flood 阈值
  - scan_enabled: 端口扫描检测开关
  - max_tracked_ips: 最大跟踪 IP 数
  - max_blocked_ips: 最大封禁 IP 数
  - state_ttl_secs: 状态生存时间
- **l7_config**: L7 层防护配置
  - http_inspection_enabled: HTTP 检测开关
  - max_request_size: 最大请求大小
  - prefilter_enabled: 轻量预筛开关
  - enable_sql_injection_detection: SQL 注入检测开关
  - enable_xss_detection: XSS 检测开关
  - enable_path_traversal_detection: 路径遍历检测开关
  - enable_command_injection_detection: 命令注入检测开关

## 布隆过滤器使用说明

### 功能概述
布隆过滤器提供高效的空间和查询性能，用于快速过滤已知的恶意 IP、端口、URL、用户代理等特征。

### 配置选项
- **bloom_enabled**: 布隆过滤器总开关（默认 false）
- **l4_bloom_false_positive_verification**: L4 层假阳性验证（默认 false）
- **l7_bloom_false_positive_verification**: L7 层假阳性验证（默认 false）

### 使用模式

#### 1. 仅启用布隆过滤器（高性能模式）
```json
{
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": false,
  "l7_bloom_false_positive_verification": false
}
```
此模式下，布隆过滤器命中即判定为恶意，可能有少量假阳性。

#### 2. 启用假阳性验证（精确模式）
```json
{
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": true,
  "l7_bloom_false_positive_verification": true
}
```
此模式下，布隆过滤器命中后会使用精确集合进行二次验证，消除假阳性，但会消耗更多内存。

#### 3. 关闭布隆过滤器（默认模式）
```json
{
  "bloom_enabled": false,
  "l4_bloom_false_positive_verification": false,
  "l7_bloom_false_positive_verification": false
}
```
完全禁用布隆过滤器功能。

### 性能影响
- **内存占用**：L4 层约 750KB + L7 层约 3.75MB（基础模式）
- **假阳性验证**：启用验证时会额外占用内存用于精确集合存储
- **查询延迟**：假阳性验证会增加查询时间，但消除了误报风险

### 示例配置文件
参考 [config/bloom_filter_demo.json](config/bloom_filter_demo.json) 了解如何启用布隆过滤器功能。

## SQLite 持久化

启用 SQLite 后，系统会在后台异步写入以下信息：

- `security_events`: L4/L7 拦截事件
- `blocked_ips`: 由限流触发的封禁记录
- `rules`: 持久化规则表，可作为规则加载来源
- 启用 `api` feature 时，`/metrics` 会额外返回上述持久化统计摘要

示例配置：

```json
{
  "sqlite_enabled": true,
  "sqlite_path": "data/waf.db",
  "sqlite_auto_migrate": true,
  "sqlite_rules_enabled": true
}
```

TCP 代理示例：

```json
{
  "listen_addrs": ["0.0.0.0:8080"],
  "tcp_upstream_addr": "127.0.0.1:18080"
}
```

当前 TCP 回源已支持：

- HTTP/1.1 请求原样检测与转发
- HTTP/2 直连请求解析后转成统一请求对象，再按 HTTP/1.1 语义回源

说明：
- `Upgrade: h2c` 首包仍按 HTTP/1.1 检测，避免把升级握手误判成完整 h2 会话
- 上游若返回 `chunked` 响应，WAF 会在转回 HTTP/2 前做基础解块
- 当 `http3_config.certificate_path` 和 `http3_config.private_key_path` 同时配置后，WAF 会在 `http3_config.listen_addr` 上额外启动一个 TLS listener，并通过 ALPN 自动处理 `h2` / `http/1.1`
- 这条 TLS listener 与 UDP 的 QUIC listener 可以共用同一个地址，例如都绑定 `0.0.0.0:8443`
- 若以 `cargo run --features http3` 构建，且同样配置了证书与私钥，WAF 还会在相同 `listen_addr` 上启动真正的 QUIC / HTTP/3 listener

UDP 转发示例：

```json
{
  "listen_addrs": ["0.0.0.0:5353"],
  "udp_upstream_addr": "127.0.0.1:8053"
}
```

当前 UDP 链路会在 L4 检测通过后，将 datagram 转发到 `udp_upstream_addr`，等待上游响应，再把响应回给原始客户端。

当 `http3_config.enabled=true` 时，UDP 链路还会额外识别 QUIC / HTTP/3 datagram，并把以下元数据送入现有 L7 / 规则引擎：

- QUIC header form（long / short）
- packet type（initial / handshake / retry / short 等）
- QUIC version
- source / destination connection id

说明：
- 默认构建下，HTTP/3 仍然只做 QUIC 元数据检测
- 启用 `http3` feature 且配置证书后，WAF 会真正接受 HTTP/3 请求，解析 header/body，并复用现有 L7 检测链路
- HTTP/3 放行请求当前仍会降级为 HTTP/1.1 回源到 `tcp_upstream_addr`

### 本地验证 HTTP/2 / HTTP/3

仓库内提供了一个最小 HTTP/3 smoke client：

```bash
cargo run --example http3_smoke --features http3 -- https://127.0.0.1:8443/ /path/to/cert.pem
```

下面是一套可直接复用的本地联调流程：

1. 生成自签证书（同时包含 `127.0.0.1` 和 `localhost`）：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /tmp/waf-http3-key.pem \
  -out /tmp/waf-http3-cert.pem \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

2. 准备一个临时配置，并把 `http3_config.certificate_path` / `private_key_path` 指向上面的证书与私钥。

3. 启动 WAF：

```bash
WAF_CONFIG=/path/to/http3-local.json cargo run --features http3
```

4. 验证 HTTPS + ALPN h2：

```bash
curl --http2 -k https://127.0.0.1:8443/
```

5. 验证真正的 HTTP/3：

```bash
cargo run --example http3_smoke --features http3 -- https://127.0.0.1:8443/ /tmp/waf-http3-cert.pem
```

默认没有配置 `tcp_upstream_addr` 时，HTTP/2 / HTTP/3 放行请求会返回本地 `allowed` 响应，适合先做协议链路冒烟。

当前实现不会把数据库查询放进请求热路径，拦截事件通过异步队列写入 SQLite。
当 `sqlite_rules_enabled=true` 时，启动阶段会先把 JSON 配置中的规则做一次“只插入不覆盖”的种子导入，再从 SQLite 读取规则，并在维护周期里检查规则表是否变化后自动热重载。

启用 `api` feature 且 `sqlite_rules_enabled=true` 后，可通过以下接口管理规则：

- `GET /rules`: 列出当前 SQLite 规则
- `GET /rules/:id`: 查询单条规则
- `POST /rules`: 创建规则
- `PUT /rules/:id`: 更新规则
- `DELETE /rules/:id`: 删除规则
- `GET /events`: 查询持久化安全事件，支持 `limit`、`offset`、`layer`、`source_ip`、`action`、`blocked_only`、`created_from`、`created_to`、`sort_by`、`sort_direction`
- `GET /blocked-ips`: 查询封禁历史，支持 `limit`、`offset`、`ip`、`active_only`、`blocked_from`、`blocked_to`、`sort_by`、`sort_direction`

排序白名单：

- `/events`: `created_at`、`source_ip`、`dest_port`
- `/blocked-ips`: `blocked_at`、`expires_at`、`ip`
- `sort_direction`: `asc` 或 `desc`

规则写入 API 后会立即刷新内存中的规则集，无需等待下一个维护周期。

## 部署建议

低配服务器优先使用 [config/minimal.json](/Users/wnluo/Desktop/code/waf/config/minimal.json)。

- 设置 `max_concurrent_tasks`（默认 128）为服务器能承受的最大并发，超过上限的连接会立即丢弃，避免 0.5GB 内存被任务队列挤满。
- `maintenance_interval_secs` 在低配模式默认 60 秒，无需额外日志；如需更频繁的统计，请在标准模式中调小。
- Bloom Filter 现支持 `bloom_filter_scale`（0.1~1.0）。低配模式默认 0.5，可根据可用内存手动调节。
- 建议关闭 API 和 Bloom Filter
- 建议保留预筛和核心 L7 规则
- 建议使用 `cargo build --release --no-default-features` 产出仅含 HTTP/1.1 的最小二进制，必要时再用 `--features api,http2` 等增量开启功能。
- 部署前清理 `target` 并仅上传 `target/release/waf` 与配置文件，可把二进制 `strip` 后压到 <4MB，减少 1GB 磁盘压力。

标准配置可参考 [config/standard.json](/Users/wnluo/Desktop/code/waf/config/standard.json)。

## 检测能力

### SQL 注入检测
- `' OR '1'='1` 等常见注入模式
- UNION SELECT、DROP TABLE 等危险操作
- 注释符 `--`、`/* */` 等注入技巧

### XSS 检测
- `<script>` 标签
- JavaScript 伪协议
- 事件处理器 `onXXX`

### 路径遍历检测
- `../` 模式
- `..\` 模式

### 命令注入检测
- 管道操作符 `|`
- 分号分隔符 `;`
- 反引号执行

## 性能考虑

- 使用 Tokio 异步运行时提高并发性能
- 原子操作进行指标统计，无锁设计
- 正则表达式预编译，避免重复编译开销
- 零拷贝网络包处理

## 后续开发计划

- [ ] 实现实际的包捕获功能
- [ ] 添加配置文件加载支持
- [ ] 完善规则热重载功能
- [ ] 添加日志审计
- [ ] 实现 eBPF 高性能过滤
- [ ] 添加 Web 管理界面
- [ ] 支持更多协议（如 DNS、SMTP 等）
- [ ] 集成威胁情报库

## 许可证

MIT License
