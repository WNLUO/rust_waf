# Rust WAF CDN CC 优化总结

更新日期：2026-04-21

本文档合并原根目录中 Stage 7-12、L4/L7/CDN/AI 优化方案和当前状态文档，用作本轮 CDN CC 优化方向的最终承接文档。后续如果进入新的开发方向，以本文档作为历史背景即可，不再需要逐份查阅阶段报告。

## 1. 测试环境与口径

| 项目 | 内容 |
|---|---|
| 测试服务器 | `160.30.230.57` |
| WAF 容器 | `rust_waf_2c512m` |
| 资源限制 | 2 核 / 512MB Docker 容器 |
| 测试链路 | 用户流量 -> CDN 模拟源 -> Rust WAF -> 模拟后端 |
| 主要结果目录 | `/root/rust_waf_test/cdn-report-artifacts` |
| 主要压测方式 | closed-loop、多进程 closed-loop、open-loop、攻击 + 正常业务混合 open-loop |

说明：

```text
95/5 表示 95% 攻击流量 + 5% 正常流量。
90/10 表示 90% 攻击流量 + 10% 正常流量。
80/20 表示 80% 攻击流量 + 20% 正常流量。
```

## 2. 最终结论

| 口径 | 当前状态 | 依据 |
|---|---|---|
| 高级 CDN CC 2000+ TPS，纯攻击 | 已达成 | multi closed-loop、open-loop、600 秒长测均已验证 |
| 高级 CDN CC 2500+ TPS，纯攻击 | 已达成 | open-loop 2600 target / 600s 达到 `2594.69` effective TPS |
| 攻击 + 正常业务混合 2000+ | 已达成第一目标 | 2200 RPS 下 95/5、90/10、80/20 混合 600s 正常成功率均为 `100.00%` |
| 攻击 + 正常业务混合 2500+ | 已完成短测探测 | 95/5 / 2600 target / 180s 实际发送 `2575.28` RPS，正常成功率 `100.00%` |
| 生产复杂口径 | 仍需扩展验证 | 混合 2500+ 的 600s、90/10、80/20 和更多真实 IP / 正常 IP 组合尚未补齐 |

准确说法：

```text
当前版本已经在 2 核 / 512MB 测试环境下验证：
1. 纯攻击高级 CDN CC 已达到 2500+ open-loop，且 600 秒稳定。
2. 2200 RPS 混合正常业务流量已通过 95/5、90/10、80/20 的 600 秒验证。
3. 2500+ 混合流量已通过 95/5 / 180 秒探测，但还不能等同于完整生产复杂口径。
```

## 3. 阶段演进摘要

| 阶段 | 关键结果 |
|---|---|
| Stage 7 | 完成常规 / 高级 CDN CC 复测，确认 CPU 是主要瓶颈，高级场景约 `1654` TPS |
| Stage 8 | 实现 `survival_fast` 与 hot block cache，高级 120s 达到 `2049.57` TPS，10 分钟约 `1919.03` TPS |
| Stage 9 | fast path 三态化、hot cache 自适应续期、扩展 `ip_route/ip/route/site` 四层缓存，高级 120s 最佳 `2151.73` TPS |
| Stage 10 | HTTP/1 hot-cache drop 前移到 request permit 前，HTTP/2/3 前移到 L4 policy 前，高级 120s `2372.50` TPS，600s `2342.41` TPS |
| Stage 11 | 严谨 open-loop 复核，2200 / 120s 与 2100 / 600s 纯攻击通过；10k IP 高基数基本稳定；混合正常流量失败 |
| Stage 12 | 正常用户保活、drop reason 指标、blocked IP 误伤修复、600s 混合验证和 2500+ 边界复核 |

## 4. 核心后端能力

| 能力 | 当前状态 |
|---|---|
| CPU 压力感知 | 已接入运行时压力模型 |
| unified early defense | 已接入 HTTP/1、HTTP/2、HTTP/3 |
| L7 CC 轻量模式 | 已支持 rich / core / minimal |
| survival fast path | 已实现 Block / Challenge / NoDecision 三态，禁止直接 allow/proxy |
| hot block cache | 已支持 `ip_route`、`ip`、`route`、`site` 四层命中 |
| HTTP/1 permit 前 hot-cache drop | 已实现 |
| HTTP/2/3 L4 前 fast path | 已实现，但仍在 request permit 之后 |
| L4/L7 CDN 双身份联动 | 已区分 CDN peer 和真实用户 IP，并向 L7 输出 route/host 收紧信号 |
| 事件持久化降级 | 已支持 summary 聚合、瘦身和队列压力保护 |
| AI 临时策略闭环 | 已支持 hit/outcome、自动续期、自动撤销 |
| drop reason 指标 | 已暴露 early defense 和 L7 drop reason，用于定位误伤来源 |

## 5. 正常用户保活设计

低风险稳定身份条件：

| 条件 | 说明 |
|---|---|
| 方法 | 只允许 `GET` / `HEAD` |
| 路径 | 不允许 `/api/` |
| 请求类型 | 只允许 document / static asset |
| 身份 | `rwaf_fp` Cookie 或 `X-Browser-Fingerprint-Id` 存在；两者同时存在时必须一致 |
| 同源语义 | `Sec-Fetch-Site` 必须是 `same-origin` 或 `same-site` |
| 行为分 | 如果已有 `l7.behavior.score`，必须 `<= 20` |

安全边界：

| 场景 | 策略 |
|---|---|
| API 请求 | 不因为伪造稳定身份而绕过 |
| `ip_route` hot cache | 不绕过 |
| `ip` / `route` / `site` hot cache | 低风险稳定 document/static 可绕过，降低 CDN/NAT 共享 IP 误伤 |
| survival fast block | 只 drop 当前请求，不持久化真实 IP |
| 分布式 API / hot path hard block | 只 drop 当前请求，不持久化共享真实 IP |
| 单 IP 自身达到 IP 阈值 | 仍可持久化 IP |
| 静态资源确定性 hard block | 仍可持久化 IP |

关键修复：

```text
早期失败根因不是代理失败，而是 L7 block 后把共享真实 IP 写入 local blocked IP。
在 CDN/NAT/代理池场景下，攻击 API 和正常 document/static 可能共享真实 IP。
修复 survival fast block 与分布式 hot path hard block 的 IP 持久化后，正常用户保活恢复稳定。
```

## 6. 关键验证结果

### 6.1 纯攻击高级 CDN CC

| 场景 | 实际发送 RPS | effective TPS | CPU avg / max | 内存峰值 | OOM | SQLite queue |
|---|---:|---:|---:|---:|---|---:|
| open-loop 2200 / 120s | `2198.52` | `2198.07` | `114.27% / 146.66%` | `52.5MB` | false | 0 |
| open-loop 2100 / 600s | `2098.21` | `2098.13` | `121.59% / 142.79%` | `109.1MB` | false | 0 |
| open-loop 2600 / 120s | `2571.52` | `2571.06` | `143.63% / 157.97%` | `62.5MB` | false | 0 |
| open-loop 2600 / 600s | `2594.78` | `2594.69` | `152.76% / 171.72%` | `113.4MB` | false | 0 |

### 6.2 2200 RPS 混合正常业务 600 秒

| 场景 | 实际发送 RPS | 正常请求 | 正常 200 | 正常成功率 | `blocked_client_ip` | `proxy_failures` |
|---|---:|---:|---:|---:|---:|---:|
| 95/5 / 600s | `2198.51` | `65684` | `65684` | `100.00%` | 0 | 0 |
| 90/10 / 600s | `2196.84` | `131790` | `131790` | `100.00%` | 0 | 0 |
| 80/20 / 600s | `2196.26` | `263468` | `263468` | `100.00%` | 0 | 0 |

### 6.3 2500+ 混合正常业务探测

| 场景 | target RPS | 实际发送 RPS | 正常请求 | 正常 200 | 正常成功率 | `blocked_client_ip` | `proxy_failures` |
|---|---:|---:|---:|---:|---:|---:|---:|
| 95/5 / 180s | 2500 | `2474.27` | `21851` | `21851` | `100.00%` | 0 | 0 |
| 95/5 / 180s | 2600 | `2575.28` | `23060` | `23060` | `100.00%` | 0 | 0 |

## 7. 前端可观测

已完成：

| 页面 / 模块 | 内容 |
|---|---|
| Dashboard | 新增攻击过程时间序列面板 |
| L7 专页 | 已展示 runtime pressure、defense depth、fast path、hot cache、no-decision 等指标 |
| 类型定义 | `/metrics` 已包含 early defense 和 L7 drop reason 字段 |

后续可补：

| 项目 | 目的 |
|---|---|
| early defense reason 分布 | 从前端直接判断早期 drop 来源 |
| L7 drop reason 分布 | 快速识别 `cc_hot_block`、`cc_hard_block`、`blocked_client_ip` 等来源 |
| 混合压测摘要面板 | 展示 normal success、proxy success、blocked reason 和 runtime depth |

## 8. 不应混淆的点

| 问题 | 准确口径 |
|---|---|
| 高级 CC 2000 TPS 是否已实现 | 是，纯攻击和 2200 RPS 混合正常业务第一目标均已验证 |
| 高级 CC 2500 TPS 是否已实现 | 纯攻击 open-loop 120s / 600s 已实现；混合 95/5 180s 已探测通过 |
| 混合 2500+ 是否已完整生产可宣称 | 还不能，缺 600s 和 90/10、80/20 等比例 |
| `blocked_l7` 代表什么 | 当前大量是 fast path / hot cache block，必须结合 reason 指标看 |
| 高压下是否应该把 drop 全改成 403/429 | 不建议，真实攻击下直接 drop 更便宜 |

## 9. 后续建议

本轮方向已经完成阶段性收束。后续如果继续同方向，建议按以下优先级：

1. 补混合 2500+ 的 600 秒验证，优先 95/5，再扩展 90/10、80/20。
2. 扩大混合矩阵：不同 `real_ip_count`、`normal_ip_count`、正常路径比例、API 攻击路径数量。
3. 前端接入 early defense / L7 drop reason 分布。
4. 给 local blocked IP 增加更清晰的 provider/source/TTL 策略，降低未来新路径污染共享身份的概率。
5. 如果后续开发方向不同，本文档只作为历史能力与约束参考，不要求继续沿 Stage 7-12 节奏推进。

## 10. 远端关键产物

| 类型 | 路径 |
|---|---|
| Stage 12 600s 95/5 | `/root/rust_waf_test/cdn-report-artifacts/stage12-600s-hardfix-20260421-215431` |
| Stage 12 600s 90/10 | `/root/rust_waf_test/cdn-report-artifacts/stage12-600s-hardfix-20260421-220512` |
| Stage 12 600s 80/20 | `/root/rust_waf_test/cdn-report-artifacts/stage12-600s-hardfix-20260421-221546` |
| 2500+ 纯攻击边界 | `/root/rust_waf_test/cdn-report-artifacts/stage12-boundary-20260421-222852` |
| 2500+ 混合探测 | `/root/rust_waf_test/cdn-report-artifacts/stage12-boundary-mixed-20260421-224439` |

## 11. 后续承接口令

如果后续继续 CDN CC 方向，可以直接说：

```text
继续 CDN CC 优化，按 CDN_CC_OPTIMIZATION_SUMMARY.md 的后续建议，先补混合 2500+ 的 600 秒验证。
```

如果后续进入新方向，可以直接说：

```text
忽略 Stage 7-12 的阶段推进方式，只把 CDN_CC_OPTIMIZATION_SUMMARY.md 当作历史背景，开始新的开发方向。
```
