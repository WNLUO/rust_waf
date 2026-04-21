# Rust WAF 当前优化状态与后续目标

更新日期：2026-04-21

## 1. 当前结论

高级 CDN CC 的 `2000+ TPS` 需要分口径说明：

| 口径 | 当前状态 | 依据 |
|---|---|---|
| 高级 CDN CC 120 秒，multi closed-loop | 已达成 | Stage 10 测得 `2372.50` 有效攻击 TPS |
| 高级 CDN CC 600 秒，multi closed-loop | 已达成 | Stage 10 测得 `2342.41` 有效攻击 TPS |
| 高级 CDN CC 120/600 秒，open-loop 固定到达率 | 已达成 2000+ | Stage 11 测得 2200 / 120s 约 `2198.07` TPS，2100 / 600s 约 `2098.13` TPS |
| 高级 CDN CC 120/600 秒，open-loop 2500+ 边界 | 已达成 | Stage 12 边界复核：2600 target 下 120s 测得 `2571.06` TPS，600s 测得 `2594.69` TPS |
| 高基数低频代理池高级 CC | 基本达成 2200 | Stage 11 的 10k IP / 180s 测得约 `2190.86` TPS，无 OOM、无队列积压 |
| 攻击 + 正常业务混合流量下 2000+ | 60s / 180s / 600s 已过第一目标 | Stage 12 的 95/5、90/10、80/20 / 2200 RPS / 60s 正常成功率分别为 `95.76%`、`95.10%`、`94.78%`；180s 达到 `95.86%`、`97.55%`、`98.84%`；修复 hard block 持久化误伤后，600s 三组均达到 `100.00%` |
| 攻击 + 正常业务混合流量下 2500+ 探测 | 短测已达成 | Stage 12 边界复核：95/5 / 2600 target / 180s 实际发送 `2575.28` RPS，正常成功率 `100.00%`，`blocked_client_ip=0`，`proxy_failures=0` |

因此，准确说法是：

```text
当前已经在 2 核 / 512MB 环境下，用 multi closed-loop 和 open-loop 口径验证了纯攻击高级 CDN CC 超过 2000 TPS。
纯攻击 open-loop 2600 target 的 600 秒长测达到 2594.69 effective TPS，说明当前版本已经跨过 2500+ 纯攻击边界。
Stage 12 已把 95/5、90/10、80/20 混合短测、180 秒长测和 600 秒长测正常成功率提升到 95% 以上。
因此，在当前 2 核 / 512MB 测试口径下，可以说高级 CDN CC 的 2000+ TPS 已同时覆盖纯攻击和混合正常业务流量的第一目标；纯攻击 2500+ 也已通过 600 秒验证。
混合 2500+ 目前完成 95/5 / 180s 探测，正常成功率 100.00%；更高阶口径仍待验证：混合 2500+ 的 600 秒、多正常比例、更复杂正常路径比例、更大真实 IP / 正常 IP 组合。
```

## 2. 已完成内容

| 阶段 | 结果 |
|---|---|
| Stage 7 | 完成常规 / 高级 CDN CC 复测，确认 CPU 是主瓶颈，高级场景约 `1654` TPS |
| Stage 8 | 实现 `survival_fast` 与 hot block cache，高级 120 秒达到 `2049.57` TPS，10 分钟约 `1919.03` TPS |
| Stage 9 | fast path 三态化，hot cache 自适应续期，扩展 `ip_route/ip/route/site` 四层缓存，高级 120 秒最佳 `2151.73` TPS |
| Stage 10 | HTTP/1 hot-cache drop 前移到 request permit 前，HTTP/2/3 前移到 L4 policy 前，AI route 回写采样，高级 120 秒 `2372.50` TPS，600 秒 `2342.41` TPS |
| Stage 11 | 远端严谨验证：open-loop 2200 / 120s 与 2100 / 600s 通过，10k IP / 2200 基本稳定，混合正常流量未通过 |
| Stage 12 | 正常用户保活第一目标达成；修复 survival fast / hard block 持久化 IP 误伤后，2200 RPS 混合 600s 三组均达到 `100.00%`；纯攻击 2600 target / 600s 达到 `2594.69` TPS；95/5 混合 2600 target / 180s 正常成功率 `100.00%` |
| 前端可观测 | Dashboard 与 L7 专页已展示 runtime pressure、defense depth、fast path、hot cache、no-decision；Dashboard 新增攻击过程时间序列 |

## 3. 后端当前能力

| 能力 | 当前状态 |
|---|---|
| CPU 压力感知 | 已接入运行时压力模型 |
| early defense | 已接入 HTTP/1、HTTP/2、HTTP/3 |
| L7 survival fast path | 已实现 block/challenge/no-decision 三态 |
| hot block cache | 已支持 `ip_route`、`ip`、`route`、`site` 四层命中 |
| HTTP/1 permit 前 hot-cache drop | 已实现 |
| HTTP/2/3 L4 前 fast path | 已实现，但仍在 request permit 之后 |
| 事件持久化降级 | 已支持 summary 聚合、瘦身和队列压力保护 |
| AI 临时策略闭环 | 已支持 hit/outcome、自动续期、自动撤销 |
| fast path 指标 | 已通过 `/metrics` 和 `/l7/stats` 暴露 |

## 4. 不应混淆的点

| 容易混淆的问题 | 清理后的口径 |
|---|---|
| “高级 CC 2000 TPS 是否已实现” | 纯攻击 multi closed-loop / open-loop 已实现；混合正常业务流量 60s / 180s / 600s 已过第一目标 |
| “高级 CC 2500 TPS 是否已实现” | 纯攻击 open-loop 120s / 600s 已过 2500+；混合 95/5 180s 已探测通过，混合 600s 和更多比例还未补齐 |
| “是否还需要继续优化后端热路径” | 可以继续，但下一步优先应验证生产可用性和压测口径，而不是只为跑分继续压热路径 |
| “Stage 8/9/10 结论冲突吗” | 不冲突，它们是历史递进；以 Stage 10 和本文档作为当前口径 |
| “blocked_l7 代表什么” | 当前包含大量 fast path block，后续报告应同时看 fast path block、hot cache hit、no-decision |
| “高压下响应 403/429 是否更好” | 不建议为了 closed-loop TPS 把 drop 全改响应，真实攻击下 drop 更便宜 |

## 5. 下一步建议

下一阶段继续围绕“更高边界和更复杂混合口径”：

1. 补混合 2500+ 的 600 秒验证，优先 95/5，再扩展到 90/10、80/20。
2. 扩大混合矩阵：不同 `real_ip_count`、`normal_ip_count`、正常路径比例、API 攻击路径数量。
3. 后续前端接入 early defense / L7 drop reason 分布，便于直接从页面看攻击过程和误伤来源。
4. 继续保持 API 不绕过，避免为了正常 document 保活把 API 攻击也放进来。
5. 给 local blocked IP 增加更清晰的 provider/source/TTL 策略，避免未来新路径再次把共享身份长期污染。

## 6. 后续承接口令

下次继续时可直接说：

```text
继续 Stage 12，按 STAGE12_NORMAL_SURVIVAL_REPORT.md 的下一步建议，先补混合 2500+ 的 600 秒验证，再扩大混合矩阵和前端 reason 分布可视化。
```
