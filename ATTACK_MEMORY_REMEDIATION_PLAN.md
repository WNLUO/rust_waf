# 攻击态内存治理方案

## 目标

本文档用于指导当前 WAF 项目完成一次面向攻击态的内存治理改造。目标不是只做参数微调，而是把系统从“高保真观测优先”调整为“攻击态稳态优先”。

完成后应满足以下核心目标：

1. 攻击流量上升时，内存占用不再随请求总量近线性增长。
2. 单个模块的内存增长存在明确上界，且上界可配置、可观测。
3. 大请求体和大上游响应不再通过全量缓冲放大 RSS 峰值。
4. 系统在攻击态能自动退化为低状态模式，但仍保持基本防护能力。
5. 所有关键改造都能通过压测、指标和现场部署验证。

## 当前问题总结

### 1. L7 CC 防护存在事件级状态堆积

当前 `src/l7/cc_guard` 中的多个计数器使用 `DashMap<String, Counter>` 搭配 `VecDeque<Instant>` 或 `VecDeque<(Instant, weight)>` 保存窗口内事件。

这会导致：

1. 内存复杂度接近“窗口内总请求数”而不是“bucket 数量”。
2. 攻击流量越密集，单 bucket 内部事件链越长。
3. overflow shard 只限制 key 数量，不限制事件数量。

### 2. distinct 客户端统计会保存大量真实字符串

`hot_path_client_buckets` 使用 `DistinctSlidingWindowCounter`，内部同时维护：

1. 事件队列
2. `HashMap<String, u32>` 计数

在高基数 IP 攻击下，这部分会额外持有大量真实 IP 字符串。

### 3. 清理机制偏温和，无法快速回落峰值

当前清理逻辑主要依赖：

1. 请求路径附带触发
2. 固定 batch 清理
3. 较宽松 stale 条件

问题在于：

1. 高峰期内存先涨，回收滞后。
2. 已创建对象不会因为进入高压模式而被快速收缩。

### 4. 行为防护保留样本数据，攻击态仍有额外开销

`src/l7/behavior_guard` 会对身份、聚合身份、突发路由保留样本和状态。虽然单 bucket 上限存在，但总 bucket 数量较大，攻击态会形成第二梯队内存占用。

### 5. 请求体和上游响应存在全量缓冲

当前项目对以下路径存在整块读入内存的实现：

1. HTTP/2 请求体
2. HTTP/3 请求体
3. HTTP/1 上游响应
4. HTTP/2 上游响应

这会导致：

1. 并发大 body 请求时，内存快速堆高。
2. 并发大响应时，网关自身持有整份回源内容。
3. 请求转发时还存在额外 clone 和重组。

### 6. 运行时预算系统存在，但仍偏软限制

当前 `resource_budget` 和 `DefenseDepth` 已经存在，但仍主要作用于：

1. bucket 数上限
2. 样本采样
3. 聚合事件

缺少真正意义上的：

1. 固定空间状态结构
2. 按字节控制的内存预算
3. 超预算后的主动收缩

## 改造原则

本次改造遵循以下原则：

1. 攻击态优先保证内存稳态，再追求观测精细度。
2. 所有高频状态结构优先改为固定空间或近似结构。
3. 所有大 body 路径优先改为流式或前缀检测。
4. 正常态和攻击态使用不同的状态复杂度。
5. 每一步都能单独验证收益，避免一次性大改不可控。

## 总体改造方案

## Phase 1：重构 L7 CC 计数器为固定空间窗口

### 目标

把 `src/l7/cc_guard/counters.rs` 中依赖事件队列的窗口结构改为固定空间 ring buffer 或固定槽时间桶。

### 设计要求

1. 普通计数器改为按秒槽位计数，不再保存每次请求的 `Instant`。
2. 加权计数器改为按秒累加权重，不再保存每次请求权重事件。
3. fast window 与普通窗口尽量统一实现风格，减少重复状态模型。
4. 单 bucket 内存占用必须固定，不可随请求量增长。

### 建议实现

建议新增统一窗口结构，例如：

1. `FixedWindowCounter`
2. `FixedWeightedWindowCounter`

每个结构保存：

1. 固定长度槽位数组
2. 每槽的 `tick`
3. 每槽的 `count` 或 `weighted_count`

### 影响文件

1. `src/l7/cc_guard/counters.rs`
2. `src/l7/cc_guard/types.rs`
3. `src/l7/cc_guard/tracking.rs`
4. `src/l7/cc_guard/runtime.rs`

### 预期收益

1. CC 防护从“事件数驱动内存增长”变成“bucket 数驱动内存增长”。
2. 攻击态下单 bucket 不再被海量事件撑爆。

## Phase 2：distinct 统计改为近似结构，禁止 overflow 保留真实集合

### 目标

处理 `DistinctSlidingWindowCounter` 在高基数攻击下保存大量真实字符串的问题。

### 设计要求

1. 正常态允许较小上限的真实 distinct 集合。
2. 一旦进入 overflow shard 或高压模式，自动切换为近似 distinct 统计。
3. overflow shard 中禁止继续保存真实客户端 IP 字符串。

### 可选实现

可按复杂度选择：

1. 简化版 bitmap + hash 估计
2. capped distinct sketch
3. HyperLogLog

第一阶段建议优先使用实现成本较低的 capped sketch 或 bitmap 方案。

### 影响文件

1. `src/l7/cc_guard/counters.rs`
2. `src/l7/cc_guard/types.rs`
3. `src/l7/cc_guard/runtime.rs`
4. `src/l7/cc_guard/helpers.rs`

### 预期收益

1. 分布式攻击打同一路径时，不再额外保存大量真实 IP 字符串。
2. overflow shard 真正具备“总内存上界”。

## Phase 3：把攻击态切换为真正的低状态模式

### 目标

让 `DefenseDepth` 不只是调小参数，而是切换状态复杂度。

### 设计要求

1. `Full/Balanced` 允许 richer tracking。
2. `Lean` 默认关闭页面窗口和部分 weighted tracking。
3. `Survival` 仅保留核心计数：
   1. IP
   2. host-route
   3. route burst
   4. hot block cache
4. `Survival` 不再做 per-identity 深度画像和真实 distinct 字符串跟踪。

### 影响文件

1. `src/l7/cc_guard/runtime.rs`
2. `src/l7/cc_guard/types.rs`
3. `src/l7/behavior_guard/guard.rs`
4. `src/core/resource_budget.rs`
5. `src/core/runtime_state/mod.rs`

### 预期收益

1. 攻击态下状态复杂度明显下降。
2. 资源预算从“软调优”变成“模式切换”。

## Phase 4：把请求体处理改为 preview + 流式

### 目标

避免大请求体在网关中整块持有和重复拷贝。

### 设计要求

1. 小请求体可继续完整缓冲。
2. 大请求体只保留前缀 preview 用于检测。
3. 超过 preview 上限后，后续 body 应直接流式透传或按策略拒绝。
4. `UnifiedHttpRequest` 不应默认总是持有完整 `Vec<u8>`。

### 建议方向

把请求体模型改为以下之一：

1. `Bytes`
2. `Arc<[u8]>`
3. `BodyPreview + FullBodyOptional`

第一阶段可先实现：

1. 仅缓存前 `N` KB 检测内容
2. 其余部分不再存入 `request.body`

### 影响文件

1. `src/protocol/unified.rs`
2. `src/protocol/http1.rs`
3. `src/protocol/http2.rs`
4. `src/core/engine/network/http1/connection.rs`
5. `src/core/engine/network/http2/connection.rs`
6. `src/core/engine/network/http3/body.rs`
7. `src/core/engine/proxy/connection/request.rs`

### 预期收益

1. 大 body 攻击下单请求内存显著下降。
2. 减少请求转发链路的 body clone。

## Phase 5：把上游响应处理改为流式 + 有界检测

### 目标

消除 HTTP/1 与 HTTP/2 回源响应的全量收集问题。

### 设计要求

1. 默认响应走流式转发。
2. 内容检测仅针对前缀窗口。
3. SafeLine 检测最多读取配置上限，例如 32KB 或 64KB。
4. 超过检测上限后不再继续缓冲完整响应。
5. 网关自身不因大响应而持有整份 body。

### 需要处理的现状

1. HTTP/1 上游响应当前通过 `response_bytes` 累积。
2. HTTP/2 上游响应当前通过 `collect().await?.to_bytes().to_vec()` 收集。

### 影响文件

1. `src/core/engine/proxy/connection/http1.rs`
2. `src/core/engine/proxy/connection/http2.rs`
3. `src/core/engine/proxy/response.rs`
4. `src/core/engine/proxy/safeline.rs`
5. `src/core/engine/network/http1/proxy_flow.rs`
6. `src/core/engine/network/http2/proxy_flow.rs`
7. `src/core/engine/network/http3/proxy_flow.rs`

### 预期收益

1. 大响应不再制造 RSS 峰值。
2. 回源攻击和上游大错误页不再轻易打爆网关内存。

## Phase 6：引入后台主动清理和硬水位

### 目标

让状态回收从“请求附带式”升级为“后台主动式”。

### 设计要求

1. 为 CC guard 和 behavior guard 增加后台 sweep。
2. sweep 频率与状态规模相关，而不是只与请求数相关。
3. 引入 soft watermark 和 hard watermark。
4. 超过 hard watermark 时，立即执行 aggressive cleanup。
5. 进入高压模式后，对已有状态做主动收缩，而不是只限制新增状态。

### 影响文件

1. `src/l7/cc_guard/tracking.rs`
2. `src/l7/behavior_guard/guard/observation.rs`
3. `src/core/mod.rs`
4. `src/core/runtime_state/mod.rs`
5. 可能新增后台任务文件

### 预期收益

1. 内存峰值回落更快。
2. 攻击结束后状态不再长时间滞留。

## Phase 7：建立按字节的内存预算与观测指标

### 目标

让系统能基于“估算状态字节数”和“在途缓冲字节数”做决策。

### 设计要求

至少增加以下指标：

1. `l7_cc_bucket_count`
2. `l7_cc_overflow_bucket_hits`
3. `l7_cc_estimated_bytes`
4. `behavior_bucket_count`
5. `behavior_estimated_bytes`
6. `inflight_request_body_bytes`
7. `inflight_upstream_response_buffer_bytes`
8. `streaming_response_bypass_count`
9. `attack_mode_switch_total`
10. `aggressive_cleanup_total`

### 影响文件

1. `src/metrics/mod.rs`
2. `src/api/metrics.rs`
3. `src/core/runtime_state/mod.rs`
4. `src/l7/cc_guard`
5. `src/l7/behavior_guard`
6. `src/core/engine/proxy`

### 预期收益

1. 可以明确知道到底是哪一类对象在吃内存。
2. 后续部署到测试服务器后更容易定位是否还有残留热点。

## 建议实施顺序

建议按以下顺序推进，每一步都先完成代码和测试，再进入下一步：

1. Phase 1：固定空间 CC 计数器
2. Phase 2：distinct 近似化
3. Phase 3：攻击态低状态模式
4. Phase 5：上游响应流式化
5. Phase 4：请求体 preview 化
6. Phase 6：后台主动清理
7. Phase 7：按字节预算和监控补全

原因：

1. Phase 1 和 Phase 2 直接解决当前最大状态热点。
2. Phase 5 直接解决最危险的大响应峰值问题。
3. Phase 4 影响请求模型较大，适合在代理链路稳住后再做。
4. Phase 6 和 Phase 7 适合作为体系化收尾。

## 代码级改造清单

## 第一批必须修改

1. `src/l7/cc_guard/counters.rs`
2. `src/l7/cc_guard/types.rs`
3. `src/l7/cc_guard/tracking.rs`
4. `src/l7/cc_guard/runtime.rs`
5. `src/l7/cc_guard/helpers.rs`

## 第二批必须修改

1. `src/core/engine/proxy/connection/http1.rs`
2. `src/core/engine/proxy/connection/http2.rs`
3. `src/core/engine/proxy/safeline.rs`
4. `src/core/engine/proxy/response.rs`

## 第三批高概率修改

1. `src/protocol/unified.rs`
2. `src/protocol/http1.rs`
3. `src/protocol/http2.rs`
4. `src/core/engine/network/http2/connection.rs`
5. `src/core/engine/network/http3/body.rs`
6. `src/core/engine/proxy/connection/request.rs`

## 第四批联动修改

1. `src/l7/behavior_guard/guard.rs`
2. `src/l7/behavior_guard/guard/observation.rs`
3. `src/core/resource_budget.rs`
4. `src/core/runtime_state/mod.rs`
5. `src/metrics/mod.rs`
6. `src/api/metrics.rs`

## 测试与验收标准

## 一、功能正确性验收

### 基础功能

1. HTTP/1、HTTP/2、HTTP/3 正常代理链路保持可用。
2. 原有 L7 CC 挑战、阻断、延迟逻辑保持基本一致。
3. 原有行为防护、burst gate、aggregate enforcement 仍可工作。
4. SafeLine 响应识别在有界检测模式下仍可命中。

### 回归要求

1. 现有测试应全部通过。
2. 与 CC、behavior、proxy 相关的测试需补齐。
3. 新增 fixed-window 结构必须有单测覆盖边界条件。

## 二、内存验收

### 压测场景 A：高基数小请求攻击

场景定义：

1. 大量不同源 IP
2. 小 GET 请求
3. 命中相同 host 或热点 route

验收标准：

1. 内存不随总请求数持续线性上涨。
2. 峰值后趋于平台。
3. 平台值应明显低于改造前。
4. overflow shard 命中上升时，状态字节数仍受控。

### 压测场景 B：热点路径分布式攻击

场景定义：

1. 大量来源
2. 集中打单一路径
3. 强化 `hot_path_client_buckets`

验收标准：

1. distinct 统计不再因真实 IP 字符串增长而推高内存。
2. route/hot-path 状态内存稳定。

### 压测场景 C：大 body 请求

场景定义：

1. 并发 POST/PUT
2. body 接近 `max_request_size`
3. 或刻意使用大量中型请求体

验收标准：

1. 在途 request body 内存可观测。
2. 改造后峰值显著下降。
3. clone 次数下降，RSS 抖动减弱。

### 压测场景 D：大响应回源

场景定义：

1. 上游返回大 body
2. 多并发回源
3. 同时启用 SafeLine 检测路径

验收标准：

1. 网关不再完整持有每个响应。
2. RSS 峰值与并发关系显著改善。
3. 响应前缀检测命中仍正常。

## 三、性能验收

### 吞吐与延迟

验收标准：

1. 正常流量下 p95 延迟不可明显恶化。
2. 攻击态下吞吐下降应可控，且以内存稳定为优先。
3. 后台 sweep 不得造成明显的长尾停顿。

## 四、运行时模式切换验收

验收标准：

1. 压力升高后能自动进入低状态模式。
2. 压力下降后能平稳恢复正常模式。
3. 模式切换过程无明显功能错乱。
4. 日志和指标可看到切换原因与次数。

## 五、部署验收

部署到测试服务器后，至少观察以下内容：

1. RSS 曲线
2. VIRT 与 RSS 差值变化
3. 高压时 bucket 数和估算字节数
4. inflight request body bytes
5. inflight upstream response buffer bytes
6. 事件落库队列压力
7. 进入 `Lean/Survival` 的次数和时长

## 风险点与注意事项

### 1. 计数器语义变化风险

从事件队列改为固定槽计数后，窗口边界行为会和原实现有轻微差异。需要通过单测确认阈值附近行为是否可接受。

### 2. distinct 近似化误差

近似 distinct 结构会引入误差，需要控制误差不影响挑战/阻断阈值判断过多。

### 3. 流式响应改造的协议复杂度

HTTP/1、HTTP/2、HTTP/3 的响应链路改造复杂度较高，应优先保证正确性和协议兼容性。

### 4. SafeLine 检测命中率变化

从全量响应改为前缀检测后，需要确认现有 SafeLine 特征是否主要位于响应前部。

### 5. 请求模型调整带来的联动修改

若 `UnifiedHttpRequest.body` 形态变化，可能联动多处检测和转发逻辑，需要分阶段推进。

## 推荐交付方式

建议按 3 个主要 PR 分批落地：

### PR 1：状态结构稳态化

范围：

1. Phase 1
2. Phase 2
3. Phase 3 的一部分

目标：

1. 先把 CC 状态从事件级改成固定空间
2. 让攻击态的状态复杂度先稳定下来

### PR 2：代理链路有界化

范围：

1. Phase 5
2. Phase 4 的 preview 部分

目标：

1. 解决大响应和大 body 的峰值问题
2. 降低在途缓冲和 clone

### PR 3：后台治理与观测补全

范围：

1. Phase 6
2. Phase 7
3. 行为防护联动收敛

目标：

1. 让系统具备自动回收、自动降级和可观测性

## 本文档对应的下一步执行建议

得到确认后，推荐按以下顺序开始代码修改：

1. 先做 PR 1 中的 CC 固定空间改造
2. 在本地完成单测和压力回归
3. 再做代理链路有界化
4. 你提供测试服务器后部署并做攻击模拟验证

## 完成定义

当满足以下条件时，本次治理可视为完成：

1. CC 状态不再按事件数增长。
2. overflow shard 不再保存大量真实 distinct 字符串。
3. 上游响应不再全量缓冲。
4. 请求体不再默认整块复制多次。
5. 攻击态内存曲线出现明显平台，而不是持续爬升。
6. 所有关键指标可观测。
7. 测试服务器验证通过。
