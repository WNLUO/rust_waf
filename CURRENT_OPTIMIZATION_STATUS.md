# Rust WAF 当前优化状态与后续目标

更新日期：2026-04-21

## 1. 当前结论

高级 CDN CC 的 `2000+ TPS` 需要分口径说明：

| 口径 | 当前状态 | 依据 |
|---|---|---|
| 高级 CDN CC 120 秒，multi closed-loop | 已达成 | Stage 10 测得 `2372.50` 有效攻击 TPS |
| 高级 CDN CC 600 秒，multi closed-loop | 已达成 | Stage 10 测得 `2342.41` 有效攻击 TPS |
| 高级 CDN CC 120/600 秒，open-loop 固定到达率 | 已达成 2000+ | Stage 11 测得 2200 / 120s 约 `2198.07` TPS，2100 / 600s 约 `2098.13` TPS |
| 高基数低频代理池高级 CC | 基本达成 2200 | Stage 11 的 10k IP / 180s 测得约 `2190.86` TPS，无 OOM、无队列积压 |
| 攻击 + 正常业务混合流量下 2000+ | 短测已过第一目标，180s 长测未过 | Stage 12 的 95/5、90/10、80/20 / 2200 RPS / 60s 正常成功率分别为 `95.76%`、`95.10%`、`94.78%`；180s 最终为 `86.44%`、`86.28%`、`88.24%` |

因此，准确说法是：

```text
当前已经在 2 核 / 512MB 环境下，用 multi closed-loop 和 open-loop 口径验证了纯攻击高级 CDN CC 超过 2000 TPS。
Stage 12 已把 95/5、90/10、80/20 混合短测正常成功率提升到 90%+，但 180 秒长测仍只有 86%~88%，因此还不能宣称“生产复杂场景下高级 CDN CC 已全面稳定 2000+ TPS”。
```

## 2. 已完成内容

| 阶段 | 结果 |
|---|---|
| Stage 7 | 完成常规 / 高级 CDN CC 复测，确认 CPU 是主瓶颈，高级场景约 `1654` TPS |
| Stage 8 | 实现 `survival_fast` 与 hot block cache，高级 120 秒达到 `2049.57` TPS，10 分钟约 `1919.03` TPS |
| Stage 9 | fast path 三态化，hot cache 自适应续期，扩展 `ip_route/ip/route/site` 四层缓存，高级 120 秒最佳 `2151.73` TPS |
| Stage 10 | HTTP/1 hot-cache drop 前移到 request permit 前，HTTP/2/3 前移到 L4 policy 前，AI route 回写采样，高级 120 秒 `2372.50` TPS，600 秒 `2342.41` TPS |
| Stage 11 | 远端严谨验证：open-loop 2200 / 120s 与 2100 / 600s 通过，10k IP / 2200 基本稳定，混合正常流量未通过 |
| Stage 12 | 正常用户保活短测第一目标达成；180s 长测最终 `86.44%` / `86.28%` / `88.24%`，仍未通过 |
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
| “高级 CC 2000 TPS 是否已实现” | 纯攻击 multi closed-loop 和 open-loop 下已实现；生产混合流量还未通过 |
| “是否还需要继续优化后端热路径” | 可以继续，但下一步优先应验证生产可用性和压测口径，而不是只为跑分继续压热路径 |
| “Stage 8/9/10 结论冲突吗” | 不冲突，它们是历史递进；以 Stage 10 和本文档作为当前口径 |
| “blocked_l7 代表什么” | 当前包含大量 fast path block，后续报告应同时看 fast path block、hot cache hit、no-decision |
| “高压下响应 403/429 是否更好” | 不建议为了 closed-loop TPS 把 drop 全改响应，真实攻击下 drop 更便宜 |

## 5. 下一步建议

下一阶段继续围绕“高压下正常用户是否还能活”：

1. 给 early defense drop 增加按 reason 的 metrics delta，精确拆 `blocked_l7 - l7_cc_fast_path_blocks`。
2. 在 HTTP/1 L4 policy 之后补一次轻量 verified-normal 预检，避免 metadata 写入顺序造成漏保。
3. 分路线重跑 180s：`/`、`/dashboard`、`/health`、`/static/app.js` 单独统计，确认剩余 drop 是否集中在某个正常路径。
4. 继续保持 API 不绕过，避免为了正常 document 保活把 API 攻击也放进来。
5. 后续前端接入 early defense reason 分布。

## 6. 后续承接口令

下次继续时可直接说：

```text
继续 Stage 12，按 STAGE12_NORMAL_SURVIVAL_REPORT.md 的下一步建议，先给 early defense drop 增加 reason 指标，再压低 180s 长测中被计入 blocked_l7 的正常侧 0。
```
