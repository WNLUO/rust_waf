# Rust WAF 真正自适应（Auto）方案（前后端完整提案）

## 1. 目标重述（为什么要升级方案）

你提出的核心点完全正确：
- 仅按 `nano/small/medium/large` 分档，不是真正的 Auto。
- 真正 Auto 应该是“目标驱动 + 闭环控制”，而不是“机器标签驱动”。

本提案将方案升级为：
1. 冷启动探测（Bootstrap）
2. 运行时闭环控制（Controller）
3. 安全边界与回退（Safety）

并且保留：
- 新手可用（少量高层开关）
- 专家可控（手动/锁定字段）
- 可观测、可回滚

---

## 2. 当前问题与链路（前后端）

### 2.1 后端现状

1. 配置链路
- 配置结构：`src/config/types.rs`, `src/config/l4.rs`, `src/config/l7.rs`
- 归一化：`src/config/normalize/*`
- 配置生效：`src/api/settings_handlers.rs` -> runtime refresh

2. 问题触发点
- `bucket request budget exceeded` 来自 L4 行为预算拒绝：
  - `src/core/engine/network/http1.rs`
  - `src/core/engine/network/http2.rs`
  - `src/l4/behavior/policy.rs`
- `525` 更可能在 TLS/接入链路：预握手拒绝、握手超时、上游握手失败。

3. 已有基础（可复用）
- 已新增 TLS 指标（如 pre-handshake reject、handshake timeout）。
- CC/L7 已支持更细粒度权重与窗口参数。
- 说明：系统已经具备“观测 + 参数化”的底座，适合做闭环控制。

### 2.2 前端现状

1. 设置页入口
- `/admin/settings`
- 文件：`vue/src/features/settings/pages/AdminSettingsPage.vue`

2. 使用痛点
- 参数很多，新手难理解。
- 手动调参难以适配不同机器与动态流量。

---

## 3. 新方案总览：从“档位配置”升级为“闭环 Auto”

### 3.1 三层架构

1. `Bootstrap`（冷启动探测，30~90 秒）
- 启动后不立即固定参数。
- 用小窗口探测“当前真实承载能力”。
- 输出初始有效参数（effective config）。

2. `Controller`（运行时闭环，每 30 秒）
- 持续读取 SLO 指标。
- 按控制规则小步调参，直到收敛在目标区间。

3. `Safety`（硬边界、冷却、回滚）
- 每次最多改动 <= X%。
- 调整后进入 cooldown。
- 连续异常触发自动回退到最近稳定快照。

### 3.2 控制目标（不是按机器，而是按结果）

默认 SLO（可配置）：
- TLS 握手超时率：`< 0.3%`
- 预算误拒绝率（bucket reject / legit req）：`< 0.5%`
- 95 分位延迟：`< 目标阈值`
- 525 事件率：持续趋近 0

控制器目标：
- 当 SLO 超标时自动修正。
- 当系统稳定时逐步提升吞吐利用率。

---

## 4. 后端详细设计（可直接实施）

### 4.1 配置模型（新增）

在 `Config` 中新增：

```rust
pub struct AutoTuningConfig {
    pub mode: AutoMode,                    // off | observe | active
    pub intent: AutoIntent,                // conservative | balanced | aggressive
    pub bootstrap_secs: u64,               // 默认 60
    pub control_interval_secs: u64,        // 默认 30
    pub cooldown_secs: u64,                // 默认 120
    pub max_step_percent: u8,              // 默认 8~10
    pub rollback_window_minutes: u64,      // 默认 10
    pub pinned_fields: Vec<String>,        // 手动锁定字段
    pub slo: AutoSloTargets,               // 各项SLO目标
}
```

说明：
- `observe` 模式只计算建议值不落地，便于灰度验证。
- `active` 才会自动下发参数。

### 4.2 状态存储（运行态）

新增 runtime state（建议 `src/core/auto_tuning/state.rs`）：
- 当前模式、当前有效参数、最近稳定快照。
- 最近 N 个周期指标环形缓冲区。
- 最近一次调参记录（字段、旧值、新值、原因）。
- 控制器状态机：`BOOTSTRAP -> STABLE -> ADJUSTING -> COOLDOWN -> ROLLBACK`。

### 4.3 Bootstrap 冷启动探测

新增模块：`src/core/auto_tuning/bootstrap.rs`

探测输入：
- CPU 可并行度、cgroup 内存上限（只作参考，不作为最终档位决策）。
- 启动前 30~90 秒的真实指标：
  - TLS 握手耗时分布
  - pre-handshake reject 速率
  - bucket reject 速率
  - 基础延迟分位

探测输出：
- 初始 effective 参数（L4 budget、reject threshold、TLS handshake timeout、部分 L7 防护强度）。

关键区别：
- 不再使用固定“机器档位 -> 参数模板”硬映射。
- 机器参数只作为初始先验，最终由实时探测校准。

### 4.4 Controller 闭环算法

新增模块：`src/core/auto_tuning/controller.rs`

每 `control_interval_secs` 执行：
1. 采样最近窗口指标。
2. 与 SLO 比较，计算偏差。
3. 生成调参动作（单步、小幅）。
4. 应用动作（跳过 `pinned_fields`）。
5. 进入 cooldown。

控制策略（第一版使用“规则+比例”混合，稳定优先）：
- 若握手超时率连续 3 个周期超标：
  - 优先增加 `tls_handshake_timeout_ms`（+step）
  - 次级放宽 L4 budget/critical threshold（+step）
- 若 bucket reject 高且延迟正常：
  - 放宽 `behavior_normal_connection_budget_per_minute`
  - 小幅下调 reject 敏感度
- 若延迟飙升且 CPU/内存压力高：
  - 优先增加 delay/排队策略
  - 再收紧预算，避免直接暴力 reject

收敛与防抖：
- 只有“连续 N 个周期同方向偏差”才调参。
- 每次最多改动 `max_step_percent`。
- 冷却期内不重复改同组参数。

### 4.5 Safety 回滚机制

新增模块：`src/core/auto_tuning/safety.rs`

回滚触发（任一满足）：
- 调参后 2~3 个周期指标显著恶化。
- 关键错误（如 525 或 handshake timeout）比调参前上升超过阈值。

回滚动作：
- 回退到最近稳定快照。
- 自动降级 `active -> observe`（可选），等待人工确认。

### 4.6 参数作用优先级

统一优先级：
1. 手动锁定字段（`pinned_fields`）
2. 手动模式显式配置
3. Auto 控制器输出
4. 默认值

即：Auto 永远不覆盖用户锁定/手动硬指定字段。

### 4.7 API 与可观测性

新增/扩展 API 字段（`/l4/config`, `/l7/config`, `/l7/stats` 或 `/metrics`）：
- `auto.mode`, `auto.intent`, `auto.state`
- `last_adjust_at`, `last_adjust_reason`
- `last_adjust_diff`（字段变化摘要）
- `effective_vs_manual_diff`
- `rollback_count_24h`

新增事件：
- `autotune.bootstrap.completed`
- `autotune.adjust.applied`
- `autotune.rollback`

---

## 5. 前端详细设计（/admin/settings）

约束：保持现有页面视觉风格，不改整体样式体系，只新增配置项与信息展示。

### 5.1 新增“自动调优”卡片（顶部）

字段：
- 模式：`关闭` / `观察` / `主动`
- 强度：`保守` / `均衡` / `激进`
- 目标预设：`稳定优先` / `吞吐优先`（可映射到 SLO 模板）

展示信息：
- 当前控制器状态（Bootstrap/Stable/Cooldown...）
- 最近一次调参原因与改动摘要
- 最近一次回滚时间（若有）

### 5.2 高级参数区保持，但降噪

- 保留现有 L4/L7 全参数编辑能力。
- 自动模式下支持“锁定此字段”（加入 `pinned_fields`）。
- 新手默认看高层卡片即可，不必理解全部参数。

### 5.3 交互细节

- `observe` 模式下显示“建议参数差异”，不真正落地。
- 用户可一键“应用建议值到手动配置”。
- 明确提示优先级：锁定字段不会被 Auto 修改。

---

## 6. 迁移与兼容

1. 老配置兼容
- 无 `auto_tuning` 字段时，填充默认：`mode=off`（或按产品策略默认 `observe`）。

2. 渐进发布建议
- Phase 1 上线 `observe` + 可观测，不自动改参数。
- Phase 2 小流量开启 `active`。
- Phase 3 全量启用，并保留一键回退。

3. 数据安全
- 不直接污染用户手动配置原值；Auto 在 runtime effective 层生效。

---

## 7. 分阶段实施计划（执行蓝图）

### Phase 1（低风险，先上）

后端：
1. 新增 `AutoTuningConfig`、runtime state、状态机骨架。
2. 实现 Bootstrap 探测（先用规则法，不上复杂模型）。
3. 指标与事件上报打通。
4. `observe` 模式输出建议值 diff。

前端：
1. `/admin/settings` 新增 Auto 卡片（模式/强度）。
2. 展示 controller 状态与建议差异。
3. 增加字段锁定开关（不改变现有样式体系）。

验收：
- 在 1C0.5G 与高配环境下，建议值明显不同且可解释。
- `observe` 模式不引入行为回归。

### Phase 2（闭环生效）

后端：
1. 开启 `active` 控制器，小步自动调参。
2. 上线 cooldown、防抖、回滚。

前端：
1. 展示最近调参记录。
2. 展示回滚记录与原因。

验收：
- 压测场景下，握手超时率/误拒绝率下降。
- 参数变化平滑，无高频抖动。

### Phase 3（增强）

1. 引入更精细控制器（如 PID-lite 或 bandit 策略）。
2. 分场景策略（夜间低流量、突发攻击、慢启动恢复）。

---

## 8. 针对你当前测试场景的说明

你的测试：
- 几十台省份服务器同时访问 `https://wnluo.com`
- 本机仅访问一次也可能遇到 `525`

解释：
- 这类现象很可能是接入层/TLS 资源被挤压后的连锁反应，不一定是 CC 误拦。
- 真 Auto 方案的价值就在这里：
  - 在“握手超时率/预握手拒绝上升”时优先调握手与预算策略。
  - 不是盲目按机器档位固定参数。

---

## 9. 默认参数建议（第一版）

- `mode=observe`（先观察再自动）
- `intent=balanced`
- `bootstrap_secs=60`
- `control_interval_secs=30`
- `cooldown_secs=120`
- `max_step_percent=8`
- 连续异常判定：`N=3`

---

## 10. 结论

这版方案已经从“机器分档配置”升级为“真正闭环 Auto”：
- 依据实时结果而不是静态档位决策
- 有可解释的调参动作与状态
- 有防抖、回滚、人工接管

可以在不破坏现有前后端结构的前提下渐进落地，先 `observe` 再 `active`，风险可控。
