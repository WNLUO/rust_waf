# Stage 11 严谨验证报告

日期：2026-04-21  
测试服务器：`160.30.230.57`  
测试环境：`rust_waf_2c512m`，2 核 / 512MB Docker 容器  
远端结果目录：`/root/rust_waf_test/cdn-report-artifacts/2026-04-21-185117-stage11-rigorous`

## 1. 验证目标

Stage 11 不再只验证 closed-loop 跑分，而是把结论拆成三个口径：

| 口径 | 验证目标 |
|---|---|
| 严格 open-loop 高级 CDN CC | 固定到达率下验证 2000+ TPS，不依赖 closed-loop 自动回压 |
| 高基数低频代理池 | 10k 真实 IP 分散攻击下观察 hot cache 覆盖率、CPU、内存和错误 |
| 攻击 + 正常业务混合 | 95/5、90/10 场景下验证正常用户成功率和误杀风险 |

## 2. 测试说明

本轮在远端重新同步代码后，用宿主机挂载目录构建 release，再在 2 核 / 512MB 容器中运行 WAF。

构建命令：

```text
docker run --rm -e CARGO_HOME=/cargo \
  -v /root/rust_waf_test/srcpkg:/src \
  -v /root/rust_waf_test/target:/src/target \
  -v /root/rust_waf_test/cargo-home:/cargo \
  -w /src rust:1-bookworm cargo build --release --locked --offline
```

结果：release 构建完成。

压测脚本：

| 脚本 | 作用 |
|---|---|
| `scripts/run_stage11_rigorous.sh` | 运行 open-loop、高基数、混合流量主场景并采集 metrics / docker stats |
| `scripts/cdn_cc_mixed_openloop.py` | 生成攻击 + 正常业务混合 open-loop 流量 |
| `scripts/run_stage11_mixed_only.sh` | 修正 Host 后单独重跑混合流量 |

注意：第一次混合测试使用了错误 Host，正常请求命中 `example.com` 时返回 404，因此 `mixed-95-5-2200-180` 和 `mixed-90-10-2200-180` 的正常用户结论作废。本报告只引用修正为 `Host: cdn.local` 后的 `mixed-cdnlocal-*` 结果。

## 3. Open-loop 高级 CDN CC

| 场景 | 目标 RPS | 实际发送 RPS | WAF verdict TPS | 错误 | CPU 平均 | CPU 峰值 | 内存峰值 | hot cache 覆盖 | 结论 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `advanced-open-2000-120` | 2000 | 1998.73 | 1998.26 | 0 | 106.00% | 131.52% | 56.9MB | 99.86% | 通过 |
| `advanced-open-2200-120` | 2200 | 2198.52 | 2198.07 | 0 | 114.27% | 146.66% | 52.5MB | 99.87% | 通过 |
| `advanced-open-2500-120` | 2500 | 2478.74 | 2478.30 | 0 | 131.19% | 148.39% | 58.7MB | 99.88% | WAF 通过，压测端未完全打满 2500 |
| `advanced-open-2100-600` | 2100 | 2098.21 | 2098.13 | 0 | 121.59% | 142.79% | 109.1MB | 99.97% | 通过 |

补充指标：

| 场景 | SQLite queue | dropped events | OOM | 说明 |
|---|---:|---:|---|---|
| 2000 / 120s | 0 | 0 | false | 无积压 |
| 2200 / 120s | 0 | 0 | false | 无积压 |
| 2500 / 120s | 0 | 0 | false | Python 调度最大落后约 4685ms，压测端成为限制 |
| 2100 / 600s | 0 | 0 | false | 长测稳定，累计发送约 125.9 万请求 |

结论：

```text
高级 CDN CC 在 2 核 / 512MB 环境下，已经通过 open-loop 口径验证 2000+ TPS。
其中 2200 / 120s 和 2100 / 600s 均稳定通过；2500 / 120s 的 WAF verdict 达到约 2478 TPS，但压测端未完全供给到 2500 RPS。
```

## 4. 高基数低频代理池

场景：`high-card-10000ip-2200-180`

| 指标 | 结果 |
|---|---:|
| 真实 IP 数 | 10000 |
| 目标 RPS | 2200 |
| 实际发送 RPS | 2191.79 |
| WAF verdict TPS | 2190.86 |
| client send errors | 82 |
| CPU 平均 | 137.99% |
| CPU 峰值 | 208.29% |
| 内存峰值 | 138.1MB |
| hot cache 覆盖 | 99.89% |
| fast no-decision | 0.06% |
| SQLite queue | 0 |
| dropped events | 0 |

结论：

```text
10k IP 高基数攻击在 2200 RPS / 180s 下基本通过，WAF 数据面稳定且 hot cache 覆盖率仍接近 99.9%。
但压测端出现 82 次 timeout，CPU 峰值触及 208.29%，后续如果要证明更高边界，应换更专业的 open-loop 压测器。
```

## 5. 混合正常业务流量

修正 Host 为 `cdn.local` 后结果如下：

| 场景 | 正常占比 | 实际发送 RPS | 正常请求数 | 正常 200 | 正常成功率 | WAF effective TPS | proxied | backend 成功率 | CPU 平均 | 内存峰值 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `mixed-cdnlocal-95-5-2200-180` | 5% | 2191.94 | 19466 | 92 | 0.47% | 2192.00 | 228 | 100.00% | 129.18% | 62.5MB |
| `mixed-cdnlocal-90-10-2200-180` | 10% | 2191.62 | 39572 | 92 | 0.23% | 2191.68 | 183 | 100.00% | 133.61% | 71.1MB |

正常-only sanity：

| 场景 | 目标 RPS | 正常请求数 | 正常 200 | 403 | 429 | 连接关闭/无响应 | 正常成功率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| normal-only | 100 | 3000 | 124 | 18 | 13 | 2845 | 4.13% |
| normal-only | 10 | 300 | 141 | 16 | 11 | 132 | 47.00% |

结论：

```text
混合正常业务流量没有通过。
WAF 本身没有 OOM、队列积压或后端失败，但 survival fast path / hot cache 在当前策略下会大量牺牲正常请求。
这说明下一阶段的瓶颈已经不是纯攻击 TPS，而是高压下的正常用户保活、可信身份学习和 hot cache 误伤控制。
```

## 6. 当前总判断

| 问题 | 结论 |
|---|---|
| 高级 CDN CC 2000+ 是否实现 | 纯攻击 open-loop 已实现 |
| 2200 / 120s 是否实现 | 已实现，WAF verdict `2198.07` TPS，client 无错误 |
| 2100 / 600s 是否实现 | 已实现，WAF verdict `2098.13` TPS，client 无错误 |
| 2500 / 120s 是否实现 | WAF 接近实现，压测端实际只供给 `2478.74` RPS |
| 10k IP 高基数是否稳定 | 基本稳定，2200 / 180s 下无 OOM、无队列积压 |
| 混合正常业务是否可生产化 | 未通过，正常成功率低于 1% |
| 下一阶段优先级 | 正常用户保活和误杀控制，高于继续追求纯攻击 TPS |

## 7. 后续优化建议

下一阶段建议定义为 Stage 12：高压正常用户保活。

优先方向：

1. 给已验证指纹、Cookie、session、低风险路径建立更强的 survival allow / challenge bypass 机制。
2. hot cache 命中从纯 block 结果改为携带 scope、置信度、身份质量和正常用户保护条件。
3. 区分攻击路径和静态/健康/首页等低风险路径，避免 site / route 级 cache 在混合流量下扩大误伤面。
4. 增加正常用户基线测试：10、50、100、200 RPS normal-only 先过，再进入 95/5、90/10 混合。
5. 后续继续用 `client actual send RPS`、`WAF verdict TPS`、`proxy RPS`、`normal success rate` 四个口径同时报告。
