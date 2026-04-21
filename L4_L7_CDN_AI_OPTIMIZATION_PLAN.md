# Rust WAF L4/L7 CDN 场景自动化智能化优化方案

## 1. 背景

本方案基于当前代码分析和 2 核 512 MB CDN 场景压测结果制定。

压测链路：

```text
用户 -> CDN -> Rust WAF -> 雷池 WAF -> nginx
```

当前测试环境中雷池 WAF 和 nginx 未部署，因此用模拟后端代替后半段。

压测结论：

| 场景 | CPU 最高 | 内存最高 | 是否 CPU 先满 | 是否内存爆掉 |
|---|---:|---:|---|---|
| 常规 CDN CC | 约 201.89% | 约 84.2 MB | 是 | 否 |
| 高级 CDN CC | 约 202.99% | 约 180 MB | 是 | 否 |

核心判断：

| 判断项 | 结论 |
|---|---|
| 当前主要瓶颈 | CPU |
| 当前非主要瓶颈 | 内存 |
| 高级 CC 的主要风险 | 分散真实用户 IP、路径和请求头，导致更多请求进入 L7 计算路径 |
| 优化主线 | 更早、更便宜地做防御决策，并让 L4、L7、资源压力、AI 策略形成闭环 |

## 2. 当前关键逻辑分析

| 模块 | 当前位置 | 当前作用 | 主要问题 |
|---|---|---|---|
| HTTP/1 入口 | `src/core/engine/network/http1/connection.rs` | 请求头解析、真实 IP 识别、L4/L7/规则/代理主流程 | 攻击时每个请求要经过较长判断链 |
| CDN 真实 IP 识别 | `src/core/engine/policy/routing.rs`、`src/core/engine/policy/request.rs` | 从可信 CDN 转发头中解析真实用户 IP | 已有基础能力，但还缺少更强的 CDN 可信链校验 |
| L4 行为引擎 | `src/l4/behavior/engine.rs`、`src/l4/behavior/policy.rs` | 连接桶、请求桶、CDN 双身份、风险评分、降级策略 | L4 策略主要影响延迟和连接关闭，对 L7 收紧信号不够强 |
| L7 CC | `src/l7/cc_guard/runtime.rs` | 按 IP、Host、Route、热点路径做滑动窗口限流 | 高级 CC 下统计维度多，CPU 成本较高 |
| L7 行为分析 | `src/l7/behavior_guard/guard.rs` | 行为画像、聚合行为、异常挑战/拦截 | 生存模式会跳过，但进入生存模式依赖压力判断 |
| 运行时压力 | `src/core/runtime_state/mod.rs` | 根据存储队列、代理延迟、身份压力、L7 摩擦等判断压力 | 缺少直接 CPU 压力输入 |
| 资源预算 | `src/core/resource_budget.rs` | 根据机器容量和压力切换 full/balanced/lean/survival | 生存模式已有，但对 L7 快速拒绝还不够激进 |
| AI 临时策略 | `src/core/ai_defense_runtime`、`src/storage/store/ai_temp_policy_repo.rs` | 自动策略、临时策略、效果记录 | 已有基础，但需要和 L4/L7 热点压力更紧密联动 |

## 3. 总体设计目标

| 目标 | 说明 |
|---|---|
| CPU 优先保护 | CPU 快满时，优先保证 WAF 自身存活和后端可用 |
| CDN 不误杀 | 不能简单封 CDN 节点，要继续区分 CDN peer 和真实用户 IP |
| 高级 CC 早处理 | 分散 IP、随机 UA、多路径攻击要尽量在便宜路径中识别 |
| L4/L7 联动 | L4 发现高风险后，应直接影响 L7 阈值、挑战、drop 策略 |
| 自动化闭环 | 观测 -> 自动收紧 -> 效果评估 -> 续期/回滚 |
| 文档同步 | 每完成一个阶段，必须同步更新本文档的状态和结果 |

## 4. 分阶段实施计划

### 阶段 0：建立基线和文档约束

状态：待用户确认后开始

目标：

| 项目 | 内容 |
|---|---|
| 目的 | 明确当前压测基线、测试环境、代码入口和后续阶段约束 |
| 是否改代码 | 否 |
| 是否需要复测 | 否 |

任务：

| 编号 | 任务 |
|---:|---|
| 0.1 | 保留远端测试环境 `/root/rust_waf_test`，不删除容器、脚本、压测结果 |
| 0.2 | 在本文档记录每个阶段的开始时间、完成时间、改动文件、验证结果 |
| 0.3 | 每个阶段完成后暂停，等待用户确认后再进入下一阶段 |

完成标准：

| 标准 | 说明 |
|---|---|
| 文档存在 | 根目录有本文档 |
| 阶段拆分清楚 | 用户可以按阶段批准 |
| 无代码变更 | 不影响当前运行逻辑 |

阶段结果：

| 项目 | 当前值 |
|---|---|
| 完成状态 | 已创建初版文档 |
| 改动文件 | `L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 是否等待确认 | 是 |

---

### 阶段 1：CPU 压力感知进入运行时压力模型

状态：已完成

目标：

让运行时压力判断不再只依赖队列、延迟、L7 摩擦等间接信号，而是直接感知 CPU 压力。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/core/runtime_state/mod.rs` | 运行时压力评分入口 |
| `src/core/resource_budget.rs` | 根据压力切换资源预算 |
| `src/core/system_profile.rs` 或相关系统采集模块 | 采集进程/容器 CPU 信息 |
| `src/api/metrics.rs` | 暴露 CPU 压力指标 |

拟修改点：

| 编号 | 修改 |
|---:|---|
| 1.1 | 已增加容器 CPU 使用率采样，优先读取 cgroup v2 的 `cpu.stat` 和 `cpu.max` |
| 1.2 | 请求 permit 等待压力本阶段未单独新增，现有 `trusted_proxy_permit_drops` 等指标继续参与自动调参；后续可在阶段 2/3 中进一步细化 |
| 1.3 | 最近请求处理耗时本阶段未单独新增，现有代理平均延迟继续参与压力评分 |
| 1.4 | 已将 CPU 压力纳入 `runtime_pressure_snapshot()` 的评分 |
| 1.5 | 已在 `/metrics` 中输出 CPU 压力相关字段 |

设计原则：

| 原则 | 说明 |
|---|---|
| 低成本 | CPU 采样不能每个请求读取系统文件 |
| 平滑 | 用滑动窗口或 EWMA，避免瞬时抖动 |
| 可解释 | 指标要能说明为什么进入 high/attack |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | `cargo test runtime_pressure` |
| 指标检查 | 查看 `/metrics` 新增字段 |
| 压测检查 | CDN CC 下观察是否更早进入 survival |

完成后必须更新：

| 文档项 | 要写入的内容 |
|---|---|
| 阶段状态 | 已完成/有阻塞 |
| 改动文件 | 列出实际修改文件 |
| 验证结果 | 写明测试命令和结果 |
| 下一阶段建议 | 是否建议继续阶段 2 |

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/core/system_pressure.rs`、`src/core/mod.rs`、`src/core/runtime_state/mod.rs`、`src/api/metrics.rs`、`src/api/types/metrics.rs`、`src/api/tests.rs`、`src/core/resource_sentinel.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增能力 | 运行时压力模型现在可以读取容器 CPU 使用率，并把 CPU 压力作为进入 elevated/high/attack 的评分输入 |
| 新增指标 | `runtime_pressure_cpu_percent`、`runtime_pressure_cpu_score`、`runtime_pressure_cpu_sample_available` |
| 请求 metadata | `runtime.pressure.cpu_percent`、`runtime.pressure.cpu_score`、`runtime.pressure.cpu_sample_available` |
| 采样方式 | 最多每秒采样一次，避免每个请求频繁读取系统文件 |
| 压力阈值 | CPU >= 70% 加 1 分，>= 85% 加 2 分，>= 95% 加 3 分 |
| 已验证 | `cargo fmt --check`、`cargo test cpu_pressure_score -- --nocapture`、`cargo test runtime_state -- --nocapture`、`cargo test test_build_metrics_response_without_sources -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段优先完成 CPU 直接感知；permit 等待和请求耗时的更细粒度接入留到统一早期防御决策阶段继续扩展 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 2 |

---

### 阶段 2：新增统一早期防御决策层

状态：已完成

目标：

在 L4 请求策略之后、昂贵 L7 分析之前，增加统一决策层，尽早决定放行、挑战、丢弃、关闭连接或进入轻量路径。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/core/engine/network/http1/connection.rs` | HTTP/1 主流程接入点 |
| `src/core/engine/network/http2/connection.rs` | HTTP/2 主流程接入点 |
| `src/core/engine/network/http3/connection.rs` | HTTP/3 主流程接入点 |
| `src/core/engine/network/decision.rs` 或新增模块 | 统一决策类型和执行逻辑 |
| `src/l4/behavior/policy.rs` | L4 策略输出增强 |

拟新增结构：

```rust
enum EarlyDefenseAction {
    Allow,
    LightweightL7,
    Challenge,
    Drop,
    Close,
}

struct EarlyDefenseDecision {
    action: EarlyDefenseAction,
    reason: String,
    force_close: bool,
    route_threshold_scale_percent: Option<u32>,
    host_threshold_scale_percent: Option<u32>,
}
```

拟修改点：

| 编号 | 修改 |
|---:|---|
| 2.1 | 已通过早期防御层读取 L4 risk、L4 overload、runtime depth、CPU score，并输出 L7 阈值收紧 hint |
| 2.2 | 已在 HTTP/1、HTTP/2、HTTP/3 主流程中增加 `evaluate_early_defense()` |
| 2.3 | 已支持高压下对高风险 L4 bucket、未解析 CDN 身份、伪造转发头等情况提前 drop |
| 2.4 | 已将早期决策结果写入 metadata，供 L7 CC、日志和事件使用 |
| 2.5 | 已覆盖 HTTP/1、HTTP/2、HTTP/3 三个入口 |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | 新增 early defense decision 测试 |
| 集成测试 | HTTP/1/2/3 分别验证 drop/challenge/allow |
| 压测检查 | 常规 CDN CC 下 CPU 峰值应降低或更快进入保护 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/core/engine/network/early_defense.rs`、`src/core/engine/network.rs`、`src/core/engine/network/http1/connection.rs`、`src/core/engine/network/http2/connection.rs`、`src/core/engine/network/http3/connection.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增能力 | 在 L4 请求策略之后、黑名单和复杂 L7 逻辑之前，统一执行早期防御决策 |
| 早期 drop 条件 | 高 CPU 压力下的 L4 高风险 bucket、生存模式下未解析 CDN 身份、生存模式下 L4 请求预算软拒绝、压力下伪造转发头 |
| 轻量 L7 条件 | L4 suspicious/high 但未达到 drop 条件时，自动收紧 L7 CC 的 route/host 阈值 |
| 新增 metadata | `early_defense.action`、`early_defense.reason`、`ai.cc.route_threshold_scale_percent`、`ai.cc.host_threshold_scale_percent` |
| 行为一致性 | HTTP/1 直接关闭连接，HTTP/2 reset 请求路径，HTTP/3 结束请求处理；三者都会记录事件、L7 反馈和 AI route 结果 |
| 已验证 | `cargo fmt --check`、`cargo test early_defense -- --nocapture`、`cargo test drop_decision -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段先建立统一早期决策框架和保守 drop 条件；更细的 CC 轻量计数模式留到阶段 3 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 3 |

---

### 阶段 3：L7 CC 轻量快速通道

状态：已完成

目标：

在 high/attack/survival 下减少 L7 CC 每个请求的统计成本，让热点路径先进入快速判断，避免高级 CC 把 CPU 耗在多维 bucket 维护上。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/l7/cc_guard/runtime.rs` | CC 主判断逻辑 |
| `src/l7/cc_guard/counters.rs` | 滑动窗口计数器 |
| `src/l7/cc_guard/types.rs` | 类型和阈值 |
| `src/l7/cc_guard/tests.rs` | 测试 |

拟修改点：

| 编号 | 修改 |
|---:|---|
| 3.1 | 已根据 `runtime.defense.depth` 和早期防御 metadata 切换 CC 跟踪模式 |
| 3.2 | survival 下进入 minimal 模式，保留最核心的 IP/Host/Route/Hot path 计数，不再维护 page window、weighted bucket、distinct client bucket |
| 3.3 | lean 或早期防御 lightweight 下进入 core 模式，跳过 page window 和 weighted bucket；API 请求仍保留热点路径 distinct client 计数 |
| 3.4 | API 热点路径继续通过现有 hot path 计数和阶段 2 的阈值收紧触发更快拦截 |
| 3.5 | 正常 rich 模式下保留静态资源宽松策略，压力模式下降低跟踪成本 |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | CC 阈值、轻量模式、静态资源例外 |
| 压测检查 | 高级 CDN CC 下 CPU 峰值、RPS、拦截量对比 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/l7/cc_guard/types.rs`、`src/l7/cc_guard/runtime.rs`、`src/l7/cc_guard/tests.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增模式 | `rich`、`core`、`minimal` |
| rich 模式 | 正常/低压时使用，保留 page window、weighted bucket、distinct hot path client |
| core 模式 | lean 或早期防御 lightweight 时使用，跳过 page window 和 weighted bucket，API 热点路径保留 distinct client 统计 |
| minimal 模式 | survival 时使用，跳过 page window、weighted bucket、distinct client，保留核心计数以减少 CPU 消耗 |
| 新增 metadata | `l7.cc.tracking_mode` |
| 已验证 | `cargo fmt --check`、`cargo test l7::cc_guard -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段主要减少高压下 L7 CC 的 per-request 统计成本；更强的 CDN 双身份联动留到阶段 4 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 4 |

---

### 阶段 4：L4 与 L7 的 CDN 双身份联动增强

状态：已完成

目标：

保留“CDN 节点不误封”的前提下，让 L4 同时从真实用户和 CDN 节点压力中给 L7 输出更强、更清晰的防御信号。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/l4/behavior/engine.rs` | 双身份 bucket 和 policy 合并 |
| `src/l4/behavior/policy.rs` | 风险评分和策略输出 |
| `src/core/engine/policy/routing.rs` | CDN 身份解析 |
| `src/l7/cc_guard/runtime.rs` | 接收 L4 输出的阈值缩放 |

拟修改点：

| 编号 | 修改 |
|---:|---|
| 4.1 | 已在 L4 policy 增加 `l7_route_threshold_scale_percent` |
| 4.2 | 已在 L4 policy 增加 `l7_host_threshold_scale_percent` |
| 4.3 | CDN peer 高压时仍不直接封 CDN，但会通过 L7 阈值缩放收紧其承载的 route/host |
| 4.4 | 已输出真实用户 bucket 风险和 CDN peer bucket 风险，合并策略时取更严格 L7 hint |
| 4.5 | unresolved CDN 身份和 spoofed forwarded header 会输出更强的 L7 收紧和 survival hint |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | trusted CDN forwarded、unresolved、spoofed header |
| 压测检查 | CDN 高级 CC 下拦截更早，后端成功请求更可控 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/l4/behavior/mod.rs`、`src/l4/behavior/policy.rs`、`src/l4/behavior/engine.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增 L4 policy 字段 | `l7_route_threshold_scale_percent`、`l7_host_threshold_scale_percent`、`route_survival_hint` |
| 新增 metadata | `l4.client_bucket_risk`、`l4.client_bucket_score`、`l4.peer_bucket_risk`、`l4.peer_bucket_score`、`l4.l7_route_threshold_scale_percent`、`l4.l7_host_threshold_scale_percent`、`l4.route_survival_hint` |
| L7 联动方式 | L4 将阈值缩放写入 `ai.cc.route_threshold_scale_percent` 和 `ai.cc.host_threshold_scale_percent`，L7 CC 会直接读取这些值 |
| CDN 处理方式 | `trusted_cdn_forwarded` 同时计算真实用户 bucket 和 CDN peer bucket，不封 CDN 节点，但会合并更严格的 L7 策略 |
| 身份异常处理 | `trusted_cdn_unresolved` 会收紧 route/host 阈值并关闭 keep-alive；`spoofed_forward_header` 会更激进收紧并给出 survival hint |
| 已验证 | `cargo fmt --check`、`cargo test l4::behavior -- --nocapture`、`cargo test early_defense -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段完成 L4 到 L7 的策略桥接；后续阶段 5 将减少高压下事件持久化和日志写入成本 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 5 |

---

### 阶段 5：事件日志与持久化降级

状态：已完成

目标：

攻击时大量重复事件不能拖垮主请求链路。高压下应该聚合、采样、瘦身，而不是完整记录每个细节。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/core/engine/policy/inspection/persistence.rs` | 安全事件持久化 |
| `src/storage/store/lifecycle.rs` | SQLite 写入队列压力降级和聚合 |
| `src/core/engine/policy/inspection/tests.rs` | HTTP inspection 持久化降级测试 |
| `src/storage/tests/queue_pressure.rs` | SQLite 队列压力测试 |

拟修改点：

| 编号 | 修改 |
|---:|---|
| 5.1 | 已在 `runtime.aggregate_events`、`runtime.pressure.trim_event_persistence` 或全局 trim 压力下聚合 HTTP block/drop/respond 等事件 |
| 5.2 | 高频重复事件保留为 `summary`，记录 action、原始 reason、route、时间窗口和计数，不再记录完整 client identity |
| 5.3 | SQLite 队列 elevated/critical 压力下继续对详情瘦身，并将 block/drop 纳入可聚合高价值事件 |
| 5.4 | 现有 storage metrics 继续暴露队列深度、容量和 dropped 计数；聚合事件以 `summary` 安全事件形式可查询 |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | queue pressure、event aggregation |
| 压测检查 | SQLite 队列不持续堆积 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/core/engine/policy/inspection/persistence.rs`、`src/core/engine/policy/inspection/tests.rs`、`src/storage/store/lifecycle.rs`、`src/storage/tests/queue_pressure.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增能力 | 高压 trim 下 HTTP drop/block/respond 不再完整写入每条事件，而是聚合成 `summary` 事件 |
| 队列降级 | SQLite 队列临界压力下，`block`/`drop` 也会优先聚合保留，避免因写队列满导致关键防御事件完全丢失 |
| 详情瘦身 | 聚合事件只保留压力模式、原始动作、原始原因、route、时间窗口、计数和来源范围，不写完整客户端身份详情 |
| 保留丢弃计数 | 不可聚合事件在队列满时仍会计入 `dropped_security_events`，用于判断存储压力是否仍然过高 |
| 已验证 | `cargo fmt --check`、`cargo test trim_event_persistence -- --nocapture`、`cargo test queue_pressure -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段降低高压下日志和 SQLite 持久化对主请求链路的拖累，同时保留 block/drop 的可审计摘要 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 6 |

---

### 阶段 6：AI 临时策略闭环增强

状态：已完成

目标：

把已有 AI 临时策略变成真正闭环：自动生成、自动应用、自动评估、自动续期或撤销。

涉及文件：

| 文件 | 作用 |
|---|---|
| `src/core/ai_defense_runtime` | AI 防御运行时 |
| `src/storage/store/ai_temp_policy_repo.rs` | 临时策略存储和效果统计 |
| `src/core/engine/runtime/engine_impl/maintenance.rs` | 临时策略自动治理、续期和撤销 |
| `src/core/engine/network/http1/connection.rs` | HTTP/1 本地策略结果回写 |
| `src/core/engine/network/http2/connection.rs` | HTTP/2 本地策略结果回写 |
| `src/core/engine/network/http3/connection.rs` | HTTP/3 本地策略结果回写 |
| `src/api/metrics.rs`、`src/api/types/metrics.rs` | `/metrics` 暴露临时策略闭环状态 |

拟修改点：

| 编号 | 修改 |
|---:|---|
| 6.1 | 已保留并验证热点路径、访客智能生成短期策略的现有自动生成路径 |
| 6.2 | 已补齐本地 `add_temp_block`/自定义本地响应的 outcome 回写，和后端代理结果一起进入效果统计 |
| 6.3 | 已让自动治理循环直接参考 `effective` outcome，策略有效且临近过期时可自动续期 |
| 6.4 | 已让自动治理循环直接参考 `harmful`、误伤和上游错误反馈，触发自动撤销 |
| 6.5 | 已在 `/metrics` 暴露 active/effective/harmful/hits/observations/extensions/revoked 等临时策略闭环指标 |

验证方式：

| 验证 | 命令或方式 |
|---|---|
| 单元测试 | temp policy outcome、续期、撤销 |
| 压测检查 | 高级 CC 后生成的策略是否降低后续压力 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成 |
| 改动文件 | `src/core/engine/network/http1/connection.rs`、`src/core/engine/network/http2/connection.rs`、`src/core/engine/network/http3/connection.rs`、`src/core/tests/policy_effects.rs`、`src/core/engine/runtime/engine_impl/maintenance.rs`、`src/api/metrics.rs`、`src/api/types/metrics.rs`、`src/api/system_handlers/mod.rs`、`src/api/realtime.rs`、`src/api/tests.rs`、`L4_L7_CDN_AI_OPTIMIZATION_PLAN.md` |
| 新增闭环 | AI 临时策略命中后会记录 hit；代理响应、本地 block、本地 challenge/自定义响应都会写入 outcome，用于判断有效、无效或疑似误伤 |
| 自动续期 | outcome 为 `effective` 或压力改善明显时，临近过期的策略可有限续期 |
| 自动撤销 | outcome 为 `harmful`、误伤事件过多或上游错误比例过高时，自动撤销策略并记录撤销原因 |
| 新增指标 | `/metrics.ai_temp_policies` 包含 active、max_active、auto_applied、effective、warming、neutral、harmful、total_hits、total_observations、auto_extensions、auto_revoked_count |
| 已验证 | `cargo fmt --check`、`cargo test policy_effects -- --nocapture`、`cargo test test_build_metrics_response -- --nocapture`、`cargo test ai_defense_runtime -- --nocapture`、`cargo test ai_route_profiles -- --nocapture`、`cargo check` |
| 验证结果 | 通过 |
| 阶段说明 | 本阶段没有重写 AI 生成逻辑，而是补齐效果回写、自动治理和指标可见性，让现有 AI 临时策略真正形成观测、应用、评估、续期、撤销闭环 |
| 是否等待确认 | 是，等待用户确认是否进入阶段 7 复测 |

---

### 阶段 7：复测与报告

状态：已完成（常规 CDN CC / 高级 CDN CC 复测，长时间高级 CDN CC 待确认）

目标：

在保留的远端测试环境中，对修改前后的常规 CDN CC、高级 CDN CC 做对比。

开测判断：

| 项目 | 判断 |
|---|---|
| 是否具备开测条件 | 具备 |
| 是否还需要补功能阶段 | 暂不需要 |
| 主要前置条件 | 必须先把当前本地工作区代码完整同步到远端测试目录 |
| 主要风险 | 如果远端仍运行旧代码，复测结果无法代表阶段 1-6 的优化效果 |
| 测试方案文档 | `STAGE7_CDN_CC_TEST_PLAN.md` |

测试环境：

| 项目 | 值 |
|---|---|
| 远端目录 | `/root/rust_waf_test` |
| 结果目录 | `/root/rust_waf_test/cdn-report-artifacts` |
| 是否删除环境 | 否 |

复测项目：

| 场景 | 并发 | 持续时间 | 关注指标 |
|---|---:|---:|---|
| 常规 CDN CC | 512 | 90 秒 | CPU、内存、拦截、后端成功 |
| 高级 CDN CC | 512 | 120 秒 | CPU、内存、拦截、后端成功 |
| 长时间高级 CDN CC | 待定 | 10-30 分钟 | 稳定性、误伤、队列 |

报告必须包含：

| 项目 | 内容 |
|---|---|
| 修改前后 CPU 对比 | 峰值、平均值、进入 survival 时间 |
| 修改前后内存对比 | 峰值、是否 OOM |
| L4/L7 拦截对比 | L4、L7、早期 drop、挑战 |
| 后端保护效果 | 后端成功/失败、平均代理延迟 |
| 智能化效果 | 自动策略数量、命中、续期/撤销 |
| 结论 | 是否达到优化目标 |

完成后必须更新本文档。

阶段结果：

| 项目 | 内容 |
|---|---|
| 完成日期 | 2026-04-19 |
| 完成状态 | 已完成常规 CDN CC 和高级 CDN CC 复测；长时间高级 CDN CC 未执行，按要求等待用户确认 |
| 远端结果目录 | `/root/rust_waf_test/cdn-report-artifacts/2026-04-19-stage7-235144` |
| 关键产物 | `stage7-summary.md`、`stage7-system.csv`、`stage7-metrics.csv`、`stage7-events.jsonl`、`stage7-commands.log`、`raw/` |
| 常规 CDN CC 结果 | CPU 峰值 `201.45%`，CPU 平均 `119.76%`，内存峰值 `52.4 MB`，无 OOM，后端成功率 `100.00%`，`blocked_l7=204311`，`trusted_proxy_l4_degrade_actions=200352`，AI 命中 `6` |
| 高级 CDN CC 结果 | CPU 峰值 `195.78%`，CPU 平均 `179.58%`，内存峰值 `121.3 MB`，无 OOM，后端成功率 `98.89%`，`blocked_l7=196123`，`l7_cc_challenges=530`，`trusted_proxy_l4_degrade_actions=192840`，活跃 AI 临时策略 `6` 条 |
| 对旧基线结论 | 常规 CDN CC 的 CPU 峰值仅下降 `0.44` 个百分点，但内存峰值下降 `31.8 MB`；高级 CDN CC 的 CPU 峰值下降 `7.21` 个百分点，内存峰值下降 `58.7 MB` |
| 运行时结论 | 两组正式复测都进入 `runtime_pressure_level=attack` 和 `runtime_defense_depth=survival`，说明 CPU 感知、早期防御和 L7 轻量模式已实际触发 |
| 存储/事件结论 | SQLite 队列深度保持 `0`，未出现 dropped events，本轮复测未观察到事件持久化成为瓶颈 |
| 风险与遗留 | 健康检查在当前脚本口径下也会迅速进入高压态；长时间高级 CDN CC 仍需用户确认后补跑 |

## 5. 阶段推进规则

| 规则 | 内容 |
|---|---|
| 逐阶段执行 | 未经用户确认，不进入下一阶段 |
| 每阶段更新文档 | 每次代码修改完成后，同步更新本文档 |
| 保留测试环境 | 不删除远端 `/root/rust_waf_test` |
| 小步提交 | 每阶段控制改动范围，避免一次性大重构 |
| 先测再报 | 每阶段完成后尽量运行相关测试 |
| 中文汇报 | 阶段完成报告使用中文 |

## 6. 当前状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| 阶段 0 | 已完成文档初版 | 用户已确认进入阶段 1 |
| 阶段 1 | 已完成 | CPU 压力感知已接入运行时压力模型 |
| 阶段 2 | 已完成 | 统一早期防御决策已接入 HTTP/1、HTTP/2、HTTP/3 |
| 阶段 3 | 已完成 | L7 CC 已支持 rich/core/minimal 跟踪模式 |
| 阶段 4 | 已完成 | L4 policy 已能向 L7 输出 route/host 阈值缩放和 survival hint |
| 阶段 5 | 已完成 | 高压下 HTTP 防御事件和 SQLite 队列压力事件已支持聚合、瘦身和关键 block/drop 摘要保留 |
| 阶段 6 | 已完成 | AI 临时策略已补齐 hit/outcome 反馈、自动续期/撤销治理和 `/metrics` 闭环指标 |
| 阶段 7 | 已完成 | 已完成常规 CDN CC / 高级 CDN CC 复测并产出中文报告，高级场景约 `1654` TPS |
| 阶段 8 | 已完成 | 新增 `survival_fast` 与 hot block cache，高级 120 秒达到 `2049.57` TPS，10 分钟约 `1919.03` TPS |
| 阶段 9 | 已完成 | fast path 三态化、hot cache 自适应续期、四层 cache，高级 120 秒最佳 `2151.73` TPS |
| 阶段 10 | 已完成 | HTTP/1 hot-cache drop 前移到 request permit 前，高级 120 秒 `2372.50` TPS，600 秒 `2342.41` TPS |
| 阶段 11 | 已完成 | 严谨验证：open-loop 2200 / 120s 与 2100 / 600s 纯攻击通过；10k IP 高基数基本稳定；混合正常流量未通过 |
| 阶段 12 | 进行中 | 正常用户保活第一目标达成；修复 survival fast / hard block 持久化 IP 误伤后，2200 RPS 混合 600s 三组均达到 `100.00%`；纯攻击 2600 target / 600s 达到 `2594.69` TPS；95/5 混合 2600 target / 180s 正常成功率 `100.00%` |

当前以 `CURRENT_OPTIMIZATION_STATUS.md` 作为后续承接的权威状态文档。

## 7. 下一步

下一步继续 Stage 12：在正常用户保活已过第一目标后，推进更高边界和更复杂混合口径。

| 优先级 | 任务 | 目的 |
|---|---|---|
| P0 | 建立 normal-only 基线 | 100 RPS 已达 `96.47%`，200 RPS 已达 `95.75%`，下一步补 50 RPS 阶梯点 |
| P0 | 增强合法身份 survival allow / challenge bypass | 已完成：低风险稳定身份支持 verified normal lane |
| P0 | 收敛 hot cache scope | 已完成：site / route 级热缓存不再直接吞掉低风险稳定身份请求 |
| P0 | 排查 normal-only 无响应 | 已确认主要不是 L4/permit/proxy；正常保活先围绕混合长测继续推进 |
| P0 | 拆 `blocked_l7` 来源 | 已完成：新增 early defense / L7 drop reason 指标，定位到 survival fast block 持久化 IP 导致共享真实 IP 被 local blocked IP 误伤 |
| P0 | 修复 blocked IP 误伤 | 已完成：survival fast `cc_fast_block` 只 drop 当前请求，不再持久化真实 IP |
| P0 | 修复 hard block 持久化误伤 | 已完成：分布式 API / hot path hard block 不再持久化共享真实 IP，单 IP 高压和静态资源确定性误用仍可持久化 |
| P1 | 重跑 95/5、90/10、80/20 混合流量 | 短测分别达到 `95.76%`、`95.10%`、`94.78%`；180s 达到 `95.86%`、`97.55%`、`98.84%`；600s 三组均达到 `100.00%` |
| P1 | 600s 混合长测 | 已完成：95/5、90/10、80/20 均无正常侧 `0/403/429`，`blocked_client_ip=0`，`proxy_failures=0` |
| P1 | 用 open-loop 复核 2500+ 纯攻击边界 | 已完成：2600 target 下 120s 达到 `2571.06` TPS，600s 达到 `2594.69` TPS，无 OOM、无队列积压 |
| P1 | 用 open-loop 探测 2500+ 混合边界 | 已完成 95/5 / 2600 target / 180s：实际发送 `2575.28` RPS，正常成功率 `100.00%`，`blocked_client_ip=0`，`proxy_failures=0` |
| P2 | 补混合 2500+ 600s 与更多比例 | 下一步补 95/5 / 2600 target / 600s，再扩展 90/10、80/20 |

当前准确结论：

```text
高级 CDN CC 的 2000+ TPS 已在 2 核 / 512MB 的纯攻击 multi closed-loop 和 open-loop 口径下达成。
10k IP 高基数低频场景基本稳定。
混合正常业务流量短测已达到第一目标；Stage 12 把 normal-only 100 RPS 从 4.13% 提升到 96.47%，normal-only 200 RPS 达到 95.75%，95/5、90/10、80/20 混合短测分别达到 95.76%、95.10%、94.78%。
新增 reason 指标后确认 early defense 不是剩余主要误伤来源，真正问题是 survival fast block 把共享真实 IP 持久化进 local blocked IP。
修复 survival fast 后 180s 长测达到 95.86%、97.55%、98.84%。
600s 首轮 95/5 暴露 full L7 CC hard block 仍会持久化分布式热点 API 的共享真实 IP；修复后，600s 95/5、90/10、80/20 均达到 100.00%，blocked_client_ip=0，proxy_failures=0。
2500+ 边界复核已推进：纯攻击 2600 target / 600s 达到 2594.69 effective TPS；95/5 混合 2600 target / 180s 实际发送 2575.28 RPS，正常成功率 100.00%。
下一步补混合 2500+ 的 600s 验证，并扩展到 90/10、80/20 和更复杂混合矩阵。
```
