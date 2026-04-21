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
| `src/l7/cc_guard/runtime.rs` | survival fast path 对低风险稳定身份请求跳过 route / site 级 hot cache；full L7 CC 计数前也允许 verified normal pass |
| `src/l4/behavior/policy.rs` | L4 request policy 识别 `l7.cc.survival_verified_normal=true`，清除延迟、强制关闭和阈值收紧 |
| `src/l4/behavior/mod.rs` | 增加 L4 verified normal lane 单测 |
| `src/l7/cc_guard/tests.rs` | 增加低风险身份不被 site hot cache 误伤、API 伪造身份不绕过、混合 Accept 头仍识别为正常 document 的单测 |
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
| `ip` | 不绕过 | 具体真实 IP 已经被确认高风险 |
| `route` | 低风险稳定身份可绕过 | 降低热点路径误伤 |
| `site` | 低风险稳定身份可绕过 | 降低全站热缓存误伤 |

## 3. 本地验证

已通过：

```text
cargo fmt --check
cargo test l7::cc_guard -- --nocapture
cargo test l4::behavior -- --nocapture
cargo check
python3 -m py_compile scripts/cdn_cc_mixed_openloop.py scripts/stage12_normal_probe.py
```

新增关键测试：

| 测试 | 验证点 |
|---|---|
| `survival_fast_path_spares_low_risk_identity_from_site_hot_cache` | site hot cache 命中时，稳定身份的低风险 document 请求不被直接 drop |
| `survival_fast_path_does_not_bypass_api_with_spoofed_identity` | API 路径即使伪造稳定身份也不能绕过 fast block |
| `low_risk_identity_skips_full_l7_cc_pressure_before_survival` | survival 前的 full L7 CC 也不会把稳定身份 document 请求打成热源 |
| `survival_verified_normal_clears_l4_request_friction` | L4 看到 verified normal 后清除 request delay、force close 和阈值收紧 |

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
当前已达成 Stage 12 的第一目标，但还需要补 90/10、80/20 和更长时间混合测试，并继续压低剩余无响应。
```

## 5. 当前判断

| 问题 | 结论 |
|---|---|
| 本轮方向是否正确 | 正确，normal-only 和混合流量成功率都有明显提升 |
| 是否已经解决混合正常流量 | 95/5 短测已过 90%，但还需要 90/10、80/20 和长测 |
| 是否影响 API 攻击防护 | 单测确认 API 伪造身份不会绕过 fast block |
| 下一步优先级 | 补更长混合测试，并继续降低剩余无响应和行为层误伤 |

## 6. 下一步建议

1. 重跑 normal-only 10/50/100/200 RPS，补全阶梯曲线，目标 normal-only 200 RPS 也达到 95%+。
2. 重跑 95/5、90/10、80/20 混合长测，目标正常成功率 90%+，再继续优化到 99%。
3. 针对剩余 `0` 无响应和少量行为层挑战，继续拆 `l7_behavior_challenges`、`l7_behavior_blocks` 和连接关闭原因。
4. 评估是否需要把 verified normal lane 扩展到 HTTP/2/HTTP/3 的 request permit 前路径。
5. 前端补攻击过程时间序列视图：normal success、fast path block、hot cache hit、runtime depth、L4 degrade 同屏展示。
