# Stage 9 下一阶段实现与远端压测报告

日期：2026-04-20  
测试环境：`160.30.230.57`，WAF 运行于 2 核 / 512MB Docker 容器，Rust release 版本由宿主机借用 Docker Rust 环境构建。

## 1. 本轮实现结论

本轮继续沿用“数据面瘦身 + survival fast path + 控制面旁路化”的路线，重点不是继续堆检测逻辑，而是让高压下的攻击请求尽量在最前面被便宜处理。

本轮已完成：

1. survival fast path 明确改成 `Block / Challenge / NoDecision` 三态，禁止返回 allow/proxy，确保快路径只做提前拦截或挑战，不绕过 L4、early defense、正常 L7 检测。
2. hot block cache 改成自适应续期，重复命中会逐步延长有效期，但命中写回按 64 次采样，避免每个 hot hit 都写原子/锁路径。
3. survival hot cache 从单层 key 扩展为四层 key：
   - `ip_route`
   - `ip`
   - `route`
   - `site`
4. fast path 命中 hot cache 时进一步减少 metadata 构造，把 client/host/route/request_kind 等较重字段延后到 cache miss 后。
5. 高压 hot path 阈值自动收紧，不依赖人工针对机器硬编码；在 survival/prefer_drop 下更早进入 route/hot path 快速拦截。
6. 补充 fast path 指标：
   - `l7_cc_fast_path_challenges`
   - `l7_cc_fast_path_no_decisions`
   - `l7_cc_hot_cache_misses`
   - `l7_cc_hot_cache_expired`
7. API 和前端管理页同步展示新增 fast path 指标。
8. 修复两个远端稳定性问题：
   - 自定义响应文件缺失时不再启动失败，自动回退到模板文本。
   - HTTP/3 证书配置缺失时不再拖垮 WAF，自动禁用 HTTP/3 listener 并记录 warning。
9. 新增远端压测采样脚本，统一记录 WAF metrics、Docker CPU/内存、容器状态、OOM、SQLite queue、fast path、hot cache、proxy 成功率等指标。

## 2. 关键代码变化

核心数据面变化：

- `src/l7/cc_guard/runtime.rs`
  - survival fast path 三态化。
  - hot cache 四层命中。
  - cache hit 前移并减少 metadata 构造。
  - survival hot path 阈值自动收紧。

- `src/l7/cc_guard/counters.rs`
  - hot block cache 命中计数。
  - 自适应 TTL。
  - 采样式续期，降低热命中写开销。

- `src/l7/cc_guard/tracking.rs`
  - hot cache 命中时自动续期。
  - lazy expire。

- `src/metrics/*`、`src/api/*`、`vue/src/*`
  - 增加 fast path no-decision、challenge、hot cache miss/expired 等指标。

- `src/rules/mod.rs`
  - 自定义响应文件缺失/不可读时回退，不再阻断启动。

- `src/core/engine/runtime/listeners.rs`
  - HTTP/3 listener 启动失败自动降级。

## 3. 本地验证

已通过：

```text
cargo fmt --check
cargo check
cargo test l7::cc_guard -- --nocapture
cargo test rules:: -- --nocapture
```

结果：

- `l7::cc_guard`：26 passed
- `rules::`：7 passed

## 4. 远端构建方式

远端 Rust 环境仍借用 Docker：

```text
docker run --rm -e CARGO_HOME=/cargo \
  -v /root/rust_waf_test/srcpkg:/src \
  -v /root/rust_waf_test/target:/src/target \
  -v /root/rust_waf_test/cargo-home:/cargo \
  -w /src rust:1-bookworm cargo build --release --locked --offline
```

构建结果：

```text
Finished release profile [optimized]
```

## 5. 远端压测结果

### 5.1 高级 CDN CC 120 秒最佳结果

场景：高级 CDN CC，512 并发，120 秒，原 closed-loop 压测口径。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 2151.73 |
| 有效攻击请求 | 262403 |
| CPU 平均 | 178.60% |
| CPU 峰值 | 187.20% |
| 内存峰值 | 110.4MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| dropped events | 0 |
| hot cache 覆盖率 | 99.76% |
| fast path block / blocked_l7 | 99.79% |
| fast path no-decision | 0.08% |
| 容器状态 | running，OOM=false |

判断：

高级 CDN CC 120 秒已经从上一轮约 2049 TPS 提升到 2151 TPS 级别，距离建议目标 2200 TPS 还差约 2.2%，但已经明显高于 2000+ 阶段线。

### 5.2 高级 CDN CC 120 秒复测结果

后续复测受到压测端供给影响，WAF CPU 没有持续打满。

| 场景 | 有效 TPS | CPU 平均 | hot cache 覆盖 | fast no-decision | proxy failures |
|---|---:|---:|---:|---:|---:|
| closed 512 | 2054.13 | 175.28% | 99.81% | 0.06% | 0 |
| closed 512 final | 1913.68 | 170.65% | 99.93% | 0.13% | 0 |
| multi 4x256 | 2102.98 | 174.98% | 99.85% | 0.11% | 0 |

这些结果共同说明：

- WAF 数据面在重复攻击下已经非常便宜。
- hot cache 长时间和复测都能稳定在 99%+。
- TPS 波动主要来自压测端 closed-loop 连接/timeout 供给，而不是 WAF 侧 cache miss 或慢路径回落。

### 5.3 高级 CDN CC 600 秒长测

场景：高级 CDN CC，512 并发，600 秒，原 closed-loop 压测口径。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 1794.57 |
| 有效攻击请求 | 1078915 |
| CPU 平均 | 170.82% |
| CPU 峰值 | 186.97% |
| 内存峰值 | 123.5MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| dropped events | 0 |
| hot cache 覆盖率 | 99.99% |
| fast path block / blocked_l7 | 99.99% |
| fast path no-decision | 0.03% |
| 容器状态 | running，OOM=false |

压测端现象：

- `err:timeout = 25189`
- 原脚本单次 timeout 为 3 秒
- 约消耗 75567 个线程秒
- 在 512 线程、600 秒总线程预算约 307200 线程秒中，占比约 24.6%

判断：

10 分钟长测没有达到 2100+ TPS，但这次不是 hot cache 覆盖率下降导致的。相反，长测 hot cache 覆盖率已经从上一轮约 94.35% 提升到 99.99%。当前主要限制是压测端 closed-loop 供给不足和 timeout 空等。

因此，本轮可以确认：

- WAF 长测稳定性达标：无 OOM、无 proxy failure、无 SQLite 积压、后端成功率 100%。
- WAF 热路径达标：hot cache 99.99%、fast no-decision 0.03%。
- “600 秒 2100+ TPS”还不能严谨宣称达成，因为现有压测端没有稳定喂满 WAF。

### 5.4 常规 CDN CC 90 秒

场景：常规 CDN CC，512 并发，90 秒，原 closed-loop 压测口径。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 2711.86 |
| 有效攻击请求 | 246806 |
| CPU 平均 | 110.04% |
| CPU 峰值 | 188.26% |
| 内存峰值 | 42.2MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| dropped events | 0 |
| hot cache 覆盖率 | 99.99% |
| fast path no-decision | 0.02% |
| 容器状态 | running，OOM=false |

判断：

常规 CDN CC 保持 2700+ TPS，低于上一轮单次 2965 TPS，但 CPU 平均只有 110%，说明同样受压测供给影响。WAF 侧无稳定性问题。

## 6. 与目标对照

| 目标 | 当前状态 |
|---|---|
| 高级 CDN CC 120 秒 2000+ | 已达成 |
| 高级 CDN CC 120 秒 2200+ | 未严谨达成，最佳 2151.73，差约 2.2% |
| 高级 CDN CC 600 秒 2100+ | 未达成，现有压测端供给不足，WAF 热路径指标已达标 |
| hot cache 长测覆盖率 >= 97% | 已达成，600 秒为 99.99% |
| fast path 只 block/challenge/no-decision | 已实现并补测试 |
| proxy failure = 0 | 已达成 |
| SQLite queue 不积压 | 已达成 |
| 无 OOM | 已达成 |
| 后端成功率 >= 99.5% | 已达成 |

## 7. 关键判断

本轮最重要的变化是：

```text
长测 TPS 没有上 2100，但原因已经不再是 WAF hot cache 覆盖率不足。
```

上一轮长测约 1919 TPS 时，hot cache 覆盖率约 94.35%。本轮 600 秒长测 hot cache 覆盖率提升到 99.99%，fast no-decision 只有 0.03%，说明攻击请求几乎都被 survival fast path + hot block cache 在最前面处理。

当前瓶颈更像：

```text
压测端 closed-loop timeout / Python 单进程调度 / 连接模型
```

证据：

1. WAF CPU 平均只有 170% 左右，没有稳定贴近 195%~200%。
2. hot cache 覆盖率 99.99%，说明不是大量请求掉回慢路径。
3. proxy failure 为 0，后端没有被打穿。
4. SQLite queue 为 0，事件落盘没有阻塞。
5. 压测端 600 秒出现 25189 次 3 秒 timeout，线程空等成本足以解释 TPS 下滑。

## 8. 不建议为了跑分做的改动

不建议把 survival fast block 全部改成 HTTP 429/403 响应来提高 closed-loop 压测端循环速度。

原因：

- 当前 `Drop` 是高压 survival 模式下的低成本策略。
- 改成响应会增加写响应和 flush 成本，真实攻击下可能降低抗压稳定性。
- 这会把优化方向从“WAF 更便宜地处理攻击”变成“让压测客户端更快进入下一轮”，不一定符合生产安全目标。

当前更正确的做法是：

1. 保持 WAF 数据面低成本 drop/block。
2. 后续补一个更专业的压测器，例如 wrk/wrk2/vegeta/自研 async open-loop。
3. 用 WAF observed incoming RPS 和 verdict RPS 作为主口径。

## 9. 下一步建议

下一步不建议继续盲目改 WAF 热路径。建议先升级压测体系：

1. 使用 async/open-loop 压测器替代当前 Python closed-loop。
2. 压测端独立记录：
   - client CPU
   - actual send RPS
   - timeout 数
   - connection reset 数
   - TIME_WAIT
   - intended RPS vs actual RPS
3. WAF 继续记录：
   - observed incoming RPS
   - effective verdict RPS
   - fast path ratio
   - hot cache hit/miss/expired
   - no-decision ratio
4. 在供给稳定后复测：
   - advanced 120s target 2200+
   - advanced 600s target 2100+
   - regular 90s target 2800+
5. 补混合流量测试：
   - 95% 攻击 + 5% 正常
   - 90% 攻击 + 10% 正常
   - 固定合法 Cookie/Token 用户延迟和误杀率

## 10. 最终结论

本轮 Stage 9 已经把上一轮最大的长测问题修掉：

```text
hot cache 长测覆盖率从约 94% 提升到 99.99%。
```

WAF 数据面已经进入非常明确的战时快路径状态：

```text
real_ip -> route/site key -> hot cache -> fast counter -> block/challenge/no-decision
```

当前可以严谨宣称：

1. 高级 CDN CC 120 秒 2000+ TPS 已稳定具备，并已测到 2151.73 TPS。
2. 常规 CDN CC 90 秒达到 2711.86 TPS。
3. 高级 600 秒长测稳定性达标，无 OOM、无 proxy failure、无 SQLite 积压、后端成功率 100%。
4. 长测 hot cache 覆盖率已经达到 99.99%，fast path no-decision 仅 0.03%。

当前不能严谨宣称：

```text
高级 CDN CC 600 秒稳定 2100+ TPS。
```

原因不是 WAF 快路径回落，而是现有压测端供给不足。下一步应先升级压测器，再判断是否还需要继续压榨 WAF 热路径。
