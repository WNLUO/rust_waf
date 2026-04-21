# Rust WAF

一个基于 Rust 构建的高性能 Web 应用防火墙（WAF），支持 L4/L7 双层防护、HTTP/1.1、HTTP/2、HTTP/3（QUIC）协议，并附带 Vue 3 管理控制台。

---

## 目录

- [功能特性](#功能特性)
- [架构概览](#架构概览)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
  - [环境要求](#环境要求)
  - [配置](#配置)
  - [运行后端](#运行后端)
  - [运行前端](#运行前端)
- [项目结构](#项目结构)
- [配置说明](#配置说明)
- [API 接口](#api-接口)
- [前端页面](#前端页面)

---

## 功能特性

### 安全防护
- **L4 网络层防护**：DDoS 高级防御、IP 访问控制、Bloom Filter 快速黑名单匹配、TCP/UDP 代理
- **L7 应用层防护**：CC 攻击防御（IP/Host/Route/热点路径多维度限速）、慢速攻击防御、行为分析、访客指纹识别
- **规则引擎**：支持 L4/L7 自定义规则，规则持久化至 SQLite，支持动态热加载
- **AI 智能审计**：对接 OpenAI Compatible 接口，自动审计流量并生成临时防护策略
- **自适应防护**：根据系统压力与流量模式自动调整防护强度（观察 / 主动 / 关闭 三种模式）
- **Bot 检测**：爬虫识别与 Bot 验证，内置浏览器指纹挑战机制

### 网关能力
- **多协议支持**：HTTP/1.0、HTTP/1.1、HTTP/2、HTTP/3（QUIC）
- **TLS 终止**：基于 rustls，支持 TLSv1.2 / TLSv1.3，自动生成自签名证书
- **HTTP → HTTPS 重定向**、HSTS 支持
- **反向代理**：TCP/UDP 双栈上游转发，动态上游健康检查
- **Header 操作**：请求/响应 Header 添加、删除、改写
- **真实 IP 提取**：支持 X-Forwarded-For、CF-Connecting-IP 等自定义 Header 及可信代理 CIDR

### 管理与可观测性
- **REST API**：Axum 实现，Bearer Token 鉴权，提供完整管理接口
- **WebSocket 实时推送**：管理控制台通过 WS 实时接收事件与状态更新
- **流量地图**：可视化流量来源与决策分布
- **安全事件**：记录、检索、标注攻击事件
- **指标采集**：系统资源、请求量、阻断量等多维度指标
- **SafeLine 集成**：支持与 SafeLine 平台双向同步站点、证书、封禁 IP 及安全事件

---

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│                    Vue 3 管理控制台                       │
│           (Vite + TypeScript + Tailwind CSS)              │
└────────────────────────┬────────────────────────────────┘
                         │ REST API / WebSocket
┌────────────────────────▼────────────────────────────────┐
│                   Axum REST API Server                    │
│              (Bearer Token Auth · /api/*)                 │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                      WAF Engine                          │
│   ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│   │  L4 层防护   │  │  L7 层防护   │  │  规则引擎   │  │
│   │ DDoS / IP   │  │ CC / 慢攻击  │  │ L4 / L7 规则│  │
│   │ Bloom Filter│  │ 行为分析     │  │ SQLite 存储 │  │
│   └──────────────┘  └──────────────┘  └─────────────┘  │
│   ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│   │ 协议检测     │  │  AI 审计     │  │ Bot 检测    │  │
│   │ HTTP1/2/3   │  │ 自适应防护   │  │ 访客智能    │  │
│   └──────────────┘  └──────────────┘  └─────────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │    SQLite (data/)   │
              └─────────────────────┘
```

---

## 技术栈

### 后端
| 技术 | 用途 |
|------|------|
| Rust | 主语言 |
| Tokio | 异步运行时（多线程） |
| Axum 0.7 | REST API / WebSocket |
| Hyper 1.0 / h2 | HTTP/1.1、HTTP/2 |
| Quinn / h3 / h3-quinn | HTTP/3（QUIC） |
| rustls / tokio-rustls | TLS 终止 |
| SQLx + SQLite | 持久化存储 |
| reqwest | AI 审计 / SafeLine HTTP 客户端 |
| hickory-resolver | 异步 DNS 解析 |
| rcgen | 自签名证书生成 |
| sysinfo | 系统资源监控 |
| DashMap | 高并发共享状态 |

### 前端
| 技术 | 用途 |
|------|------|
| Vue 3 | UI 框架 |
| TypeScript | 类型安全 |
| Vite | 构建工具 |
| Vue Router 4 | 客户端路由 |
| Tailwind CSS 4 | 样式 |
| ECharts 5 / echarts-gl | 图表与 3D 可视化 |
| Lucide Vue Next | 图标库 |
| JSZip | 压缩包处理 |

---

## 快速开始

### 环境要求

- **Rust** 1.75+ （推荐使用 `rustup` 安装）
- **Node.js** 18+（前端开发）
- **SQLite**（运行时自动创建，无需手动安装）

### 配置

复制示例配置文件并按需修改：

```bash
cp .env.example .env
```

`.env` 主要配置项：

```env
# 运行模式：standard | lite
WAF_RUNTIME_PROFILE=standard

# 是否启用管理 API
WAF_API_ENABLED=true

# 管理 API 监听地址
WAF_API_BIND=127.0.0.1:3740

# WAF 监听地址（可配置多个，逗号分隔）
WAF_LISTEN_ADDRS=127.0.0.1:18080

# SQLite 数据库路径
WAF_SQLITE_PATH=data/waf.db

# 从 SQLite 加载规则
WAF_SQLITE_RULES_ENABLED=true

# 可选：上游服务器地址
# WAF_TCP_UPSTREAM_ADDR=127.0.0.1:9443
# WAF_UDP_UPSTREAM_ADDR=127.0.0.1:9443
```

### 运行后端

```bash
# 开发模式
cargo run

# 生产构建
cargo build --release
./target/release/waf
```

默认情况下，WAF 监听 `0.0.0.0:66`（HTTP）和 `0.0.0.0:660`（HTTPS），管理 API 监听 `127.0.0.1:3740`。

启动时会自动完成以下初始化：
- 创建 SQLite 数据库并执行数据迁移
- 若无本地证书，自动生成自签名 TLS 证书
- 从数据库加载配置并应用环境变量覆盖

### 运行前端

```bash
cd vue
npm install

# 开发模式
npm run dev

# 生产构建
npm run build

# 类型检查
npm run typecheck

# 格式检查
npm run format:check
```

---

## 项目结构

```
rust_waf/
├── src/                        # Rust 后端
│   ├── main.rs                 # 程序入口
│   ├── lib.rs                  # 库入口，启动逻辑
│   ├── api/                    # REST API（Axum）
│   │   ├── router.rs           # 路由注册
│   │   ├── auth.rs             # Bearer Token 鉴权中间件
│   │   ├── state.rs            # API 共享状态
│   │   ├── system_handlers.rs  # 仪表盘、指标、AI 相关接口
│   │   ├── events_handlers.rs  # 安全事件、行为、封禁 IP 接口
│   │   ├── settings_handlers.rs# L4/L7/全局配置接口
│   │   ├── sites_handlers/     # 站点与证书管理接口
│   │   ├── safeline_handlers.rs# SafeLine 集成接口
│   │   ├── rules/              # 规则管理接口
│   │   ├── realtime.rs         # WebSocket 实时推送
│   │   ├── ai_audit/           # AI 审计接口
│   │   └── metrics.rs          # Prometheus 指标接口
│   ├── config/                 # 配置系统
│   │   ├── types.rs            # Config 主结构体
│   │   ├── env.rs              # 环境变量覆盖逻辑
│   │   ├── l4.rs               # L4 层配置
│   │   ├── l7.rs               # L7 层配置
│   │   ├── gateway.rs          # 网关配置（TLS、Header、重定向）
│   │   ├── http3.rs            # HTTP/3 配置
│   │   ├── rules.rs            # 规则配置结构
│   │   └── normalize.rs        # 配置规范化
│   ├── core/                   # WAF 核心引擎
│   │   ├── engine/             # 引擎主体，流量处理调度
│   │   ├── rule_engine.rs      # 规则匹配执行
│   │   ├── adaptive_protection.rs # 自适应防护
│   │   ├── auto_tuning/        # 自动调优模块
│   │   ├── bot_intelligence.rs # Bot 行为分析
│   │   ├── bot_verifier.rs     # Bot 验证挑战
│   │   ├── visitor_intelligence/ # 访客智能分析
│   │   ├── traffic_map/        # 流量地图数据采集
│   │   ├── ai_defense_runtime/ # AI 防御运行时
│   │   ├── ai_temp_policy.rs   # AI 临时策略
│   │   ├── gateway.rs          # 网关逻辑
│   │   ├── packet.rs           # 数据包信息
│   │   ├── resource_budget.rs  # 资源预算管理
│   │   ├── resource_sentinel.rs# 资源哨兵（过载保护）
│   │   ├── self_protection.rs  # 自我保护机制
│   │   ├── system_pressure.rs  # 系统压力感知
│   │   └── system_profile.rs   # 系统性能档案
│   ├── l4/                     # L4 层防护
│   │   ├── connection/         # TCP/UDP 连接处理
│   │   ├── behavior/           # L4 行为分析
│   │   ├── bloom_filter/       # Bloom Filter 黑名单
│   │   └── inspector.rs        # L4 流量检测
│   ├── l7/                     # L7 层防护
│   │   ├── cc_guard/           # CC 攻击防御
│   │   ├── behavior_guard/     # 行为异常防护
│   │   ├── bloom_filter/       # Bloom Filter 黑名单
│   │   ├── slow_attack_guard.rs# 慢速攻击防御
│   │   └── ip_access.rs        # IP 访问控制
│   ├── protocol/               # 协议解析与处理
│   │   # HTTP/1、HTTP/2、HTTP/3 Handler，协议自动检测
│   ├── bloom_filter/           # 全局 Bloom Filter 实现
│   ├── integrations/           # 外部集成
│   │   └── safeline/           # SafeLine 平台同步
│   ├── metrics/                # 指标采集与快照
│   ├── rules/                  # 规则加载与管理
│   ├── storage/                # SQLite 数据访问层
│   │   ├── models/             # 数据模型
│   │   ├── store/              # Store 实现（CRUD）
│   │   ├── schema.rs           # 数据库 Schema
│   │   └── query.rs            # 查询构建
│   └── tls.rs                  # TLS 配置工具
│
├── vue/                        # Vue 3 前端
│   ├── src/
│   │   ├── app/
│   │   │   ├── App.vue         # 根组件
│   │   │   ├── layout/         # 全局布局
│   │   │   └── router/         # 路由配置
│   │   ├── features/           # 功能模块（按页面划分）
│   │   │   ├── dashboard/      # 仪表盘（AI 审计、流量地图、Bot 状态）
│   │   │   ├── sites/          # 站点管理
│   │   │   ├── certificates/   # 证书管理
│   │   │   ├── rules/          # 规则管理（L4/L7）
│   │   │   ├── actions/        # 动作配置
│   │   │   ├── l4/             # L4 配置
│   │   │   ├── l7/             # L7 配置
│   │   │   ├── events/         # 安全事件
│   │   │   ├── behavior/       # 行为分析 & 访客情报
│   │   │   ├── blocked/        # 封禁 IP 管理
│   │   │   ├── settings/       # 系统设置
│   │   │   └── home/           # 首页
│   │   └── shared/             # 通用组件与工具
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── tsconfig.json
│
├── scripts/                    # 压测与调试脚本（Python/Shell）
├── .env.example                # 配置示例
├── Cargo.toml                  # Rust 依赖与构建配置
└── README.md
```

---

## 配置说明

### 环境变量

所有配置均可通过环境变量覆盖，变量名以 `WAF_` 为前缀：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `WAF_RUNTIME_PROFILE` | `standard` | 运行模式（`standard` / `lite`） |
| `WAF_API_ENABLED` | `true` | 是否启用管理 REST API |
| `WAF_API_BIND` | `127.0.0.1:3740` | 管理 API 监听地址 |
| `WAF_LISTEN_ADDRS` | `0.0.0.0:66` | WAF HTTP 监听地址（逗号分隔） |
| `WAF_SQLITE_PATH` | `data/waf.db` | SQLite 数据库路径 |
| `WAF_SQLITE_RULES_ENABLED` | `true` | 是否从数据库加载规则 |
| `WAF_TCP_UPSTREAM_ADDR` | — | TCP 上游服务器地址 |
| `WAF_UDP_UPSTREAM_ADDR` | — | UDP 上游服务器地址 |

### 默认端口

| 服务 | 端口 | 协议 |
|------|------|------|
| WAF HTTP 入口 | 66 | HTTP |
| WAF HTTPS 入口 | 660 | HTTPS / HTTP/2 |
| WAF HTTP/3 入口 | 660 | QUIC |
| 管理 API | 3740 | HTTP |

### Cargo Features

| Feature | 默认 | 说明 |
|---------|------|------|
| `api` | ✅ | 启用 Axum 管理 REST API |
| `http3` | ✅ | 启用 HTTP/3（QUIC）支持 |
| `http2` | ✅ | 启用 HTTP/2 支持 |
| `capture` | ❌ | 启用 pnet 原始包捕获（需要 root 权限） |

禁用 HTTP/3 构建：

```bash
cargo build --release --no-default-features --features api
```

---

## API 接口

管理 API 基础路径：`http://<WAF_API_BIND>`

### 鉴权

启用 Bearer Token 鉴权后，所有受保护接口需在请求头中携带：

```
Authorization: Bearer <token>
```

### 主要接口分组

| 路径前缀 | 说明 |
|----------|------|
| `GET /health` | 健康检查（无需鉴权） |
| `GET /ws/admin` | WebSocket 实时推送（无需鉴权） |
| `GET /metrics` | 系统指标 |
| `GET /dashboard/traffic-map` | 流量地图快照 |
| `GET /dashboard/ai-audit-*` | AI 审计报告与状态 |
| `GET /dashboard/bot-*` | Bot 检测状态与洞察 |
| `GET/PUT /l4/config` | L4 层配置 |
| `GET/PUT /l7/config` | L7 层配置 |
| `GET/PUT /settings` | 全局设置 |
| `GET /events` | 安全事件列表 |
| `GET /blocked-ips` | 封禁 IP 列表 |
| `GET/POST/PUT/DELETE /sites/local` | 站点管理 |
| `GET/POST/PUT/DELETE /certificates/local` | 本地证书管理 |
| `POST /certificates/local/generate` | 生成自签名证书 |
| `POST /integrations/safeline/*` | SafeLine 集成操作 |
| `GET/PUT /rules/*` | 规则管理 |

---

## 前端页面

| 路由 | 页面 | 功能 |
|------|------|------|
| `/` | 首页 | 项目概览 |
| `/admin` | 仪表盘 | AI 审计摘要、自动化概览、Bot 状态、流量地图 |
| `/admin/sites` | 站点管理 | 创建/编辑/删除反向代理站点 |
| `/admin/certificates` | 证书管理 | 本地证书上传、生成、SafeLine 同步 |
| `/admin/rules` | 规则管理 | 查看/编辑全局 WAF 规则 |
| `/admin/l4` | L4 配置 | DDoS 防护、Bloom Filter、信任 CDN CIDR 等 |
| `/admin/l4/rules` | L4 规则 | L4 层自定义规则 |
| `/admin/l7` | L7 配置 | CC 防御、慢攻击、HTTP/2、健康检查等 |
| `/admin/l7/rules` | L7 规则 | L7 层自定义规则 |
| `/admin/events` | 安全事件 | 攻击事件记录与标注 |
| `/admin/behavior` | 行为分析 | 访客行为画像 |
| `/admin/intelligence` | 访客情报 | 指纹档案与会话分析 |
| `/admin/blocked` | 封禁管理 | IP 封禁列表与批量解封 |
| `/admin/actions` | 动作配置 | 规则命中后的响应动作 |
| `/admin/settings` | 系统设置 | 全局配置、管理员鉴权、SafeLine 集成 |
