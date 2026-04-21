# Rust WAF 当前优化状态与后续目标

更新日期：2026-04-21

## 1. 当前结论

高级 CDN CC 的 `2000+ TPS` 需要分口径说明：

| 口径 | 当前状态 | 依据 |
|---|---|---|
| 高级 CDN CC 120 秒，multi closed-loop | 已达成 | Stage 10 测得 `2372.50` 有效攻击 TPS |
| 高级 CDN CC 600 秒，multi closed-loop | 已达成 | Stage 10 测得 `2342.41` 有效攻击 TPS |
| 高级 CDN CC 120/600 秒，严格 open-loop 固定到达率 | 未严谨证明 | 当前 open-loop 仍受连接模型、accept、客户端 timeout 影响 |
| 攻击 + 正常业务混合流量下 2000+ | 未验证 | 尚未完成正常用户成功率、误杀率、p95/p99 验证 |
| 高基数低频代理池高级 CC | 未验证 | 需要单独测试 1k/10k IP 场景下四层 hot cache 覆盖率 |

因此，准确说法是：

```text
当前已经在 2 核 / 512MB 环境下，用 multi closed-loop 口径验证了高级 CDN CC 120 秒和 600 秒均超过 2000 TPS。
但还不能宣称“生产复杂场景下高级 CDN CC 已全面稳定 2000+ TPS”，因为严格 open-loop、混合正常流量和高基数低频攻击还没有完成验证。
```

## 2. 已完成内容

| 阶段 | 结果 |
|---|---|
| Stage 7 | 完成常规 / 高级 CDN CC 复测，确认 CPU 是主瓶颈，高级场景约 `1654` TPS |
| Stage 8 | 实现 `survival_fast` 与 hot block cache，高级 120 秒达到 `2049.57` TPS，10 分钟约 `1919.03` TPS |
| Stage 9 | fast path 三态化，hot cache 自适应续期，扩展 `ip_route/ip/route/site` 四层缓存，高级 120 秒最佳 `2151.73` TPS |
| Stage 10 | HTTP/1 hot-cache drop 前移到 request permit 前，HTTP/2/3 前移到 L4 policy 前，AI route 回写采样，高级 120 秒 `2372.50` TPS，600 秒 `2342.41` TPS |
| 前端可观测 | Dashboard 与 L7 专页已展示 runtime pressure、defense depth、fast path、hot cache、no-decision 等指标 |

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
| “高级 CC 2000 TPS 是否已实现” | multi closed-loop 下已实现；严格 open-loop 和生产混合流量还未严谨证明 |
| “是否还需要继续优化后端热路径” | 可以继续，但下一步优先应验证生产可用性和压测口径，而不是只为跑分继续压热路径 |
| “Stage 8/9/10 结论冲突吗” | 不冲突，它们是历史递进；以 Stage 10 和本文档作为当前口径 |
| “blocked_l7 代表什么” | 当前包含大量 fast path block，后续报告应同时看 fast path block、hot cache hit、no-decision |
| “高压下响应 403/429 是否更好” | 不建议为了 closed-loop TPS 把 drop 全改响应，真实攻击下 drop 更便宜 |

## 5. 下一步建议

下一阶段建议从“是否能跑到 2000”转为“是否能可靠生产化”：

1. 补 95/5、90/10、80/20 攻击 / 正常混合流量测试。
2. 记录合法 Cookie/Token 用户成功率、误杀率、p95/p99。
3. 补 1k/10k IP 高基数低频高级 CC，拆分观察 `ip_route/ip/route/site` 各层 hot cache 命中。
4. 用 Tokio async 压测器、vegeta 或 wrk2 做严格 open-loop 固定到达率测试。
5. 区分 client actual send RPS、WAF observed incoming RPS、WAF verdict RPS、proxy RPS。

## 6. 后续承接口令

下次继续时可直接说：

```text
继续 Stage 11，按 CURRENT_OPTIMIZATION_STATUS.md 的下一步建议，先做高级 CC 混合正常流量和高基数低频攻击验证。
```

