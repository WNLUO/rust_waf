# Rust WAF Stage8 战时快路径测试报告

生成日期：2026-04-20

## 结论

本轮 Stage8 已实现 `survival_fast` 战时快路径，并在 2 核 512MB 容器环境下完成常规 CDN CC、高级 CDN CC 短测和高级 CDN CC 10 分钟长测。

核心结论：

- 高级 CDN CC 120 秒短测达到 2049.57 有效攻击 TPS，已达成阶段目标。
- 高级 CDN CC 10 分钟长测稳定在 1919.03 有效攻击 TPS，未达到长期 2000+，但无 OOM、无 SQLite 积压、无 proxy failure。
- 常规 CDN CC 达到 2965.12 有效攻击 TPS，但该轮 CPU 采样不完整，不能单独用来证明资源曲线完全可控。
- 本轮提升主要来自 `survival_fast` 和 hot block cache，大量重复攻击请求在完整 L7 / AI / 事件链路前被便宜处理。
- 当前可准确表述为：Rust WAF 已具备 2 核 512MB 下高级 CDN CC 120 秒 2000+ TPS 能力，并且 10 分钟长测可稳定保持约 1900+ TPS。

不建议表述为：高级 CDN CC 已长期稳定 2000+ TPS。

## 本轮主要改动

| 模块 | 改动 | 目的 |
| --- | --- | --- |
| L7 CC runtime | 新增 `survival_fast` 快路径 | 高压下提前 block/challenge/no decision |
| CC counter | 新增固定 bucket 时间轮 counter | 降低滑窗维护成本和分配 |
| hot block cache | 增加短 TTL 热攻击缓存 | 重复攻击 O(1) 拦截 |
| HTTP/1 入口 | survival 模式下前移快路径到 L4 策略前 | 减少攻击请求进入完整策略链路 |
| event persistence | survival 下采样和降级 | 避免事件构造反噬数据面 |
| feedback | L4 / site defense / AI 信号采样 | 降低控制面反馈成本 |
| AI 临时策略 | 高压下减少策略 clone / 事件输入 | AI 只影响后续策略，不阻塞当前请求 |
| metrics | 新增 fast path / hot cache 指标 | 观察快路径贡献 |
| frontend | Dashboard 补充 fast path 指标展示 | 前端可见战时路径状态 |

## 本地验证

| 命令 | 结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo check` | 通过 |
| `cargo test l7::cc_guard -- --nocapture` | 24 个测试通过 |
| `cargo test trim_event_persistence -- --nocapture` | 通过 |
| `cargo test test_build_metrics_response -- --nocapture` | 通过 |
| `npm test -- --run` | 通过 |
| `npm run build` | 通过 |

## 远端测试环境

| 项目 | 值 |
| --- | --- |
| 测试服务器 | 160.30.230.57 |
| WAF 限制环境 | Docker 2 核 / 512MB |
| 构建方式 | 宿主机借用 Docker 内 Rust 环境构建 release 版本 |
| 主要测试目录 | `/root/rust_waf_test/cdn-report-artifacts` |

## 阶段 7 基线

| 场景 | 有效攻击 TPS | CPU 平均 | CPU 峰值 | 内存峰值 | 后端成功率 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 常规 CDN CC | 约 2274 | 未列入本报告 | 未列入本报告 | 未列入本报告 | 未列入本报告 |
| 高级 CDN CC | 约 1654 | 179.58% | 195.78% | 121.3MB | 98.89% |

## Stage8e 测试结果

### 常规 CDN CC 短测

测试目录：

`/root/rust_waf_test/cdn-report-artifacts/2026-04-20-stage8e-normal-115524`

| 指标 | 结果 |
| --- | ---: |
| 持续时间 | 93.07s |
| 并发 | 512 |
| blocked_l7 | 275925 |
| proxied_requests | 39 |
| 有效攻击总量 | 275964 |
| 有效攻击 TPS | 2965.12 |
| proxy_failures | 0 |
| backend_success_rate | 100.0% |
| sqlite_queue_depth | 0 |
| sqlite_dropped_security_events | 0 |
| p50 | 27.93ms |
| p95 | 45.98ms |
| p99 | 57.74ms |
| fast_path_requests | 275995 |
| fast_path_blocks | 272899 |
| hot_cache_hits | 272251 |

说明：该轮常规 CDN CC 的 CPU 采样不完整，因此常规场景可以表述为已达到约 2965 TPS，但不应单独声称 CPU 曲线已完整验证。

### 高级 CDN CC 120 秒短测

测试目录：

`/root/rust_waf_test/cdn-report-artifacts/2026-04-20-stage8e-advanced-113955`

| 指标 | 结果 |
| --- | ---: |
| 持续时间 | 121.82s |
| 并发 | 512 |
| blocked_l7 | 249671 |
| proxied_requests | 8 |
| 有效攻击总量 | 249679 |
| 有效攻击 TPS | 2049.57 |
| CPU 平均 | 181.10% |
| CPU 峰值 | 195.01% |
| 内存峰值 | 114.5MB |
| proxy_failures | 0 |
| backend_success_rate | 100.0% |
| sqlite_queue_depth | 0 |
| sqlite_dropped_security_events | 0 |
| p50 | 80.43ms |
| p95 | 146.77ms |
| p99 | 242.62ms |
| fast_path_requests | 249673 |
| fast_path_blocks | 244741 |
| hot_cache_hits | 243997 |
| l7_cc_challenges | 0 |

关键比例：

| 指标 | 结果 |
| --- | ---: |
| fast_path 覆盖率 | 约 99.998% |
| fast_path_blocks / blocked_l7 | 约 98.03% |
| hot_cache_hits / fast_path_blocks | 约 99.70% |
| hot_cache_hits / 有效攻击总量 | 约 97.72% |

相比阶段 7 高级 CDN CC 约 1654 TPS，本轮高级短测提升约 23.9%。

### 高级 CDN CC 10 分钟长测

测试目录：

`/root/rust_waf_test/cdn-report-artifacts/2026-04-20-stage8e-advanced-113955/long-advanced-600s`

| 指标 | 结果 |
| --- | ---: |
| 持续时间 | 601.05s |
| 并发 | 512 |
| blocked_l7 | 1153421 |
| proxied_requests | 9 |
| 有效攻击总量 | 1153430 |
| 有效攻击 TPS | 1919.03 |
| CPU 平均 | 176.93% |
| CPU 峰值 | 195.21% |
| 内存峰值 | 130.3MB |
| proxy_failures | 0 |
| backend_success_rate | 100.0% |
| sqlite_queue_depth | 0 |
| sqlite_dropped_security_events | 0 |
| persisted_security_events | 3860 |
| p50 | 73.84ms |
| p95 | 140.04ms |
| p99 | 244.92ms |
| fast_path_requests | 1153424 |
| fast_path_blocks | 1091042 |
| hot_cache_hits | 1088241 |
| l7_cc_challenges | 1731 |

关键比例：

| 指标 | 结果 |
| --- | ---: |
| hot_cache_hits / 有效攻击总量 | 约 94.35% |
| fast_path_blocks / blocked_l7 | 约 94.59% |

长测期间 WAF 容器状态采样为 `running false 0`，含义是容器仍在运行、未 OOM、退出码字段为 0。

## 单核能力估算

| 场景 | 计算方式 | 估算 |
| --- | --- | ---: |
| 高级短测，按平均 CPU | 2049.57 / 1.8110 | 约 1132 TPS/核 |
| 高级短测，按峰值 CPU | 2049.57 / 1.9501 | 约 1051 TPS/核 |
| 高级长测，按平均 CPU | 1919.03 / 1.7693 | 约 1085 TPS/核 |
| 高级长测，按峰值 CPU | 1919.03 / 1.9521 | 约 983 TPS/核 |

当前高级 CDN CC 单核能力大致处于 1000 到 1130 TPS/核，较阶段 7 的约 845 到 921 TPS/核明显提升。

## 结果判断

本轮实现方向正确，并且验证了阶段 7 的核心判断：高级 CDN CC 的主要瓶颈不是 Rust 本身，而是攻击请求默认进入完整热路径后的单位请求成本。

Stage8 将大量恶意请求改为：

`real_ip / host / route -> fast counter -> hot cache -> block/challenge/no decision`

这使重复攻击请求不再反复经过完整 L4 / early feedback / L7 / AI / event 链路。

但当前 120 秒高级 CDN CC 2049.57 TPS 距离 2000 的余量只有约 2.48%，10 分钟长测为 1919.03 TPS，说明长期 2000+ 还没有形成工程余量。

## 当前限制

1. 高级 CDN CC 短测刚刚超过 2000，余量不足。
2. 10 分钟高级 CDN CC 未达到 2000+。
3. 常规 CDN CC 本轮 CPU 采样不完整。
4. 后端成功率 100% 的 proxied 基数很小，不能替代混合正常流量验证。
5. `blocked_l7` 指标语义已经变宽，包含了大量 fast path block，后续应拆分指标口径。
6. 长测 hot cache 覆盖率从短测约 97.72% 降到约 94.35%，需要继续定位。
7. 当前验证重点是攻击阻断，还没有证明攻击期间正常用户体验和误杀率。

## 下一阶段目标

建议下一阶段不再只追求“刚好 2000 TPS”，而是建立余量：

| 场景 | 目标 |
| --- | ---: |
| 高级 CDN CC 120 秒短测 | >= 2200 有效攻击 TPS |
| 高级 CDN CC 10 分钟长测 | >= 2100 有效攻击 TPS |
| 长测 hot_cache_hits / effective_requests | >= 97% |
| 混合流量正常用户成功率 | >= 99.5% |
| 后端 proxy_failures | 0 或可解释 |
| SQLite queue depth | 0 或短暂可恢复 |
| OOM | 0 |

## 推荐下一步

1. 高级 120 秒、600 秒、常规 90 秒各重复 3 轮，记录 min / median / max。
2. 补压测端 CPU、内存、actual RPS、timeout、连接数、TIME_WAIT、网络带宽。
3. 拆分 `blocked_l7` 指标，新增 fast path no decision、cache miss、expired、eviction 等指标。
4. 将 fast path 的安全约束固化为类型和测试：只允许 block/challenge/no decision，不能 allow/proxy。
5. 做 hot cache TTL 自适应，提升长测覆盖率。
6. 增加 IP、IP+route、route、site/global 多层 hot cache 或容量闸门，应对高基数分布式 CC。
7. 增加混合流量测试，验证攻击期间正常用户成功率、误杀率和延迟。
8. 用 open-loop 固定到达率压测模型验证 2000、2200、2500 RPS 的真实承载边界。

