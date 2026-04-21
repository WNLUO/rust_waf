# Stage 12 正常用户保活初步报告

日期：2026-04-21  
测试服务器：`160.30.230.57`  
测试环境：`rust_waf_2c512m`，2 核 / 512MB Docker 容器

## 1. 本轮目标

Stage 11 已经证明纯攻击高级 CDN CC 可以达到 2000+ TPS，但混合正常业务流量失败。因此 Stage 12 的目标从“攻击吞吐”切到“高压下正常用户保活”。

本轮先处理最明确的一类误伤：

```text
site / route 级 hot block cache 在 survival 模式下命中后，会把同站点低风险正常请求一起 drop。
```

## 2. 实现内容

文件：

| 文件 | 改动 |
|---|---|
| `src/l7/cc_guard/helpers.rs` | 新增 `is_survival_low_risk_identity_request()`，识别低风险稳定身份请求，并修正混合 Accept 头导致 document 被误判为 API 的问题 |
| `src/l7/cc_guard/runtime.rs` | survival fast path 对低风险稳定身份请求跳过 ip / route / site 级 hot cache；full L7 CC 计数前也允许 verified normal pass |
| `src/core/engine/network/early_defense.rs` | early defense 尊重 `l7.cc.survival_verified_normal=true`，并在 L7 标记前兜底识别稳定身份 document/static 请求；API 仍不绕过 |
| `src/l4/behavior/policy.rs` | L4 request policy 识别 `l7.cc.survival_verified_normal=true`，清除延迟、强制关闭和阈值收紧 |
| `src/l4/behavior/mod.rs` | 增加 L4 verified normal lane 单测 |
| `src/l7/cc_guard/tests.rs` | 增加低风险身份不被 ip/site hot cache 误伤、API 伪造身份不绕过、混合 Accept 头仍识别为正常 document 的单测 |
| `vue/src/features/dashboard/components/AdminDashboardAttackTimeline.vue` | 新增攻击过程时间序列面板，展示成功代理、快路径拦截、热缓存命中、未决放行、压力和防御深度 |
| `vue/src/features/dashboard/composables/useAdminDashboardPage.ts`、`vue/src/features/dashboard/pages/AdminPage.vue` | 增加 Dashboard 攻击过程采样和页面接入 |
| `scripts/stage12_normal_probe.py` | 新增 normal / mixed probe，自动输出客户端结果和 WAF metrics delta |

低风险稳定身份条件：

| 条件 | 说明 |
|---|---|
| 方法 | 只允许 `GET` / `HEAD` |
| 路径 | 不允许 `/api/` |
| 请求类型 | 只允许 document / static asset；混合 `Accept: text/html,application/xhtml+xml,application/json,*/*` 不再误判为 API |
| 身份 | `rwaf_fp` Cookie 或 `X-Browser-Fingerprint-Id` 存在；两者同时存在时必须一致 |
| 同源语义 | `Sec-Fetch-Site` 必须是 `same-origin` 或 `same-site` |
| 行为分 | 如果已有 `l7.behavior.score`，必须 `<= 20` |

安全边界：

| 热缓存层 | 是否绕过 | 原因 |
|---|---|---|
| `ip_route` | 不绕过 | 具体 IP + 路径已经被确认高风险 |
| `ip` | 低风险稳定身份可绕过 | 允许共享 IP / NAT 下的稳定 document/static 正常请求继续存活 |
| `route` | 低风险稳定身份可绕过 | 降低热点路径误伤 |
| `site` | 低风险稳定身份可绕过 | 降低全站热缓存误伤 |

## 3. 本地验证

已通过：

```text
cargo fmt --check
cargo test l7::cc_guard -- --nocapture
cargo test l4::behavior -- --nocapture
cargo test early_defense -- --nocapture
cargo check
npm run typecheck
npm run build
python3 -m py_compile scripts/cdn_cc_mixed_openloop.py scripts/stage12_normal_probe.py
```

新增关键测试：

| 测试 | 验证点 |
|---|---|
| `survival_fast_path_spares_low_risk_identity_from_site_hot_cache` | site hot cache 命中时，稳定身份的低风险 document 请求不被直接 drop |
| `survival_fast_path_spares_low_risk_identity_from_ip_hot_cache` | 共享 IP 命中 ip hot cache 时，稳定身份的低风险 document 请求不被直接 drop |
| `survival_fast_path_does_not_bypass_api_with_spoofed_identity` | API 路径即使伪造稳定身份也不能绕过 fast block |
| `low_risk_identity_skips_full_l7_cc_pressure_before_survival` | survival 前的 full L7 CC 也不会把稳定身份 document 请求打成热源 |
| `survival_verified_normal_clears_l4_request_friction` | L4 看到 verified normal 后清除 request delay、force close 和阈值收紧 |
| `survival_verified_normal_survives_broad_l4_pressure` | early defense 不再把已验证正常身份按 broad L4 high risk 直接 drop |
| `stable_document_identity_survives_before_l7_verified_marker` | L7 预检尚未打标时，early defense 仍能兜底放行稳定 document 请求 |
| `api_identity_candidate_still_drops_under_l4_pressure` | API 请求即使伪造稳定身份，也不会借 early defense 兜底绕过 |

## 4. 远端验证

远端 release 构建完成：

```text
Finished release profile [optimized]
```

### 4.1 normal-only sanity

对比 Stage 11：

| 场景 | Stage 11 成功率 | Stage 12 成功率 | 说明 |
|---|---:|---:|---|
| normal-only 10 RPS / 30s | 47.00% | 72.33% | 第一刀后改善 |
| normal-only 100 RPS / 30s | 4.13% | 96.47% | 修正 Accept 分类和 verified normal lane 后达成第一目标 |

Stage 12 详细结果：

| 场景 | 正常请求 | 200 | 403 | 429 | 连接关闭/无响应 | 成功率 |
|---|---:|---:|---:|---:|---:|---:|
| 10 RPS | 300 | 217 | 21 | 10 | 52 | 72.33% |
| 100 RPS 第一刀 | 3000 | 839 | 15 | 8 | 2138 | 27.97% |
| 100 RPS Accept 修正后 | 3000 | 2894 | 0 | 8 | 98 | 96.47% |

Accept 修正后 metrics delta：

| 指标 | 结果 |
|---|---:|
| `blocked_l7` | 106 |
| `l7_cc_blocks` | 0 |
| `l7_cc_fast_path_blocks` | 0 |
| `l7_cc_fast_path_no_decisions` | 4163 |
| `l7_cc_hot_cache_hits` | 0 |
| `proxied_requests` | 2894 |
| `proxy_successes` | 2894 |
| `proxy_failures` | 0 |
| `trusted_proxy_permit_drops` | 0 |

### 4.2 95/5 混合短测

场景：2200 RPS，95% 攻击 / 5% 正常，60 秒。

| 指标 | Stage 11 180s | Stage 12 60s |
|---|---:|---:|
| 实际发送 RPS | 2191.94 | 2196.26 |
| 正常请求数 | 19466 | 6581 |
| 正常 200 | 92 | 6302 |
| 正常成功率 | 0.47% | 95.76% |
| client send errors | 0 | 7 |
| 正常 p95 | 110.96ms | 79.76ms |
| 正常 p99 | 140.97ms | 114.92ms |

Stage 12 混合短测 metrics delta：

| 指标 | 结果 |
|---|---:|
| `blocked_l7` | 125600 |
| `l7_cc_fast_path_blocks` | 125342 |
| `l7_cc_hot_cache_hits` | 125337 |
| `proxied_requests` | 6381 |
| `proxy_successes` | 6381 |
| `proxy_failures` | 0 |
| `trusted_proxy_permit_drops` | 0 |
| `trusted_proxy_l4_degrade_actions` | 3485 |

结论：

```text
本轮改动已把 normal-only 100 RPS 提到 96.47%，并把 95/5 混合短测正常成功率提升到 95.76%。
当前已达成 Stage 12 的第一目标。
```

### 4.3 扩展混合验证

场景：2200 RPS，60 秒，补测 normal-only 200 RPS、90/10、80/20。

| 场景 | 实际发送 RPS | 正常请求 | 正常 200 | 403 | 429 | 连接关闭/无响应 | 正常成功率 | 正常 p95 | 正常 p99 | 代理成功率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| normal-only 200 RPS / 30s | 199.95 | 6000 | 5745 | 0 | 4 | 251 | 95.75% | 2.32ms | 2.64ms | 100.00% |
| mixed 90/10 / 2200 RPS / 60s | 2194.94 | 13355 | 12700 | 0 | 0 | 655 | 95.10% | 75.83ms | 93.58ms | 100.00% |
| mixed 80/20 / 2200 RPS / 60s | 2194.79 | 26534 | 25150 | 0 | 0 | 1384 | 94.78% | 82.00ms | 99.79ms | 100.00% |

扩展验证 metrics delta：

| 场景 | `blocked_l7` | `l7_cc_fast_path_blocks` | `l7_cc_hot_cache_hits` | `proxied_requests` | `proxy_successes` | `proxy_failures` | `trusted_proxy_permit_drops` | `trusted_proxy_l4_degrade_actions` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| normal-only 200 RPS | 255 | 0 | 0 | 5745 | 5745 | 0 | 0 | 0 |
| mixed 90/10 | 119115 | 118506 | 118501 | 12797 | 12797 | 0 | 0 | 0 |
| mixed 80/20 | 106625 | 105406 | 105401 | 25264 | 25264 | 0 | 0 | 428 |

扩展验证结论：

```text
normal-only 200 RPS 已达到 95.75%。
90/10 混合在 2200 RPS 下达到 95.10%。
80/20 混合在 2200 RPS 下达到 94.78%，略低于 95% 线，但已经超过 90% 第一目标。
三组代理成功率均为 100%，无 trusted proxy permit drop，剩余损失主要表现为客户端侧 0/超时类无响应，而不是 WAF 主动 403/429 或代理失败。
```

### 4.4 180 秒长测验证

长测先暴露出短测没有覆盖的问题：正常请求的 `0` 基本等于 `blocked_l7 - l7_cc_fast_path_blocks`，说明不是代理失败，而是 early defense / broad hot cache 侧的 drop。随后补了三刀：

| 修复 | 作用 |
|---|---|
| early defense 尊重 `l7.cc.survival_verified_normal=true` | 已经被 L7 survival 预检标记的正常请求，不再被 broad L4 high risk drop |
| 低风险稳定身份绕过 ip hot cache | 共享 IP / NAT 下，攻击 API 不连带吞掉稳定 document/static 请求 |
| early defense 兜底识别稳定身份 document/static | L7 预检尚未打标或部分 bypass 路径下，仍可保护稳定正常请求；API 不绕过 |

180 秒结果：

| 版本 | 95/5 正常成功率 | 90/10 正常成功率 | 80/20 正常成功率 | 结论 |
|---|---:|---:|---:|---|
| 修复前 | 66.67% | 48.22% | 89.74% | 长测不通过，正常侧大量 `0` |
| early defense 尊重 verified normal 后 | 83.44% | 78.53% | 87.74% | 明显改善，但仍未过 90% |
| 再补 ip hot cache 绕过后 | 80.54% | 未完整采用 | 未完整采用 | 单独效果不稳定，继续补 early-defense 兜底 |
| 最终当前版本 | 86.44% | 86.28% | 88.24% | 仍未通过 90% / 95% 长测目标 |

最终当前版本 metrics 摘要：

| 场景 | 正常请求 | 正常 200 | 正常 0 | 正常成功率 | `blocked_l7` | `l7_cc_fast_path_blocks` | `proxied_requests` | `proxy_failures` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 95/5 / 2200 RPS / 180s | 19756 | 17077 | 2679 | 86.44% | 378823 | 376019 | 17166 | 0 |
| 90/10 / 2200 RPS / 180s | 40012 | 34523 | 5489 | 86.28% | 361398 | 355909 | 34523 | 0 |
| 80/20 / 2200 RPS / 180s | 79121 | 69817 | 9304 | 88.24% | 325940 | 316636 | 69833 | 0 |

长测结论：

```text
Stage 12 当前已经证明 60 秒短测过线，但 180 秒长测仍未过线。
本轮三刀把 95/5 从 66.67% 提升到 86.44%，把 90/10 从 48.22% 提升到 86.28%，方向有效但不充分。
代理成功率仍是 100%，proxy_failures 为 0；剩余问题继续集中在被计入 blocked_l7 的早期 drop，而不是后端代理失败。
```

## 5. 当前判断

| 问题 | 结论 |
|---|---|
| 本轮方向是否正确 | 正确，normal-only 和混合流量成功率都有明显提升 |
| 是否已经解决混合正常流量 | 短测过第一目标；180 秒长测最终为 `86.44%` / `86.28%` / `88.24%`，还未通过 |
| 是否影响 API 攻击防护 | 单测确认 API 伪造身份不会绕过 fast block |
| 下一步优先级 | 继续定位 `blocked_l7 - l7_cc_fast_path_blocks` 的早期 drop 来源，并把长测正常成功率先推到 90%+ |

## 6. 下一步建议

1. 给 early defense drop 增加按 reason 的 metrics delta，精确拆 `blocked_l7 - l7_cc_fast_path_blocks`。
2. 在 HTTP/1 L4 policy 之后补一次轻量 verified-normal 预检，避免 metadata 写入顺序造成漏保。
3. 分路线重跑 180s：`/`、`/dashboard`、`/health`、`/static/app.js` 单独统计，确认剩余 drop 是否集中在某个正常路径。
4. 继续保持 API 不绕过，避免为了正常 document 保活把 API 攻击也放进来。
5. 前端已补攻击过程时间序列，后续可接入 early defense reason 分布。
