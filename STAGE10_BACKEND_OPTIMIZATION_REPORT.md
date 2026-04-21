# Stage 10 后端优化与远端压测报告

日期：2026-04-20  
测试服务器：`160.30.230.57`  
测试环境：`rust_waf_2c512m`，2 核 / 512MB Docker 容器  
远端结果目录：`/root/rust_waf_test/cdn-report-artifacts/2026-04-20-162142-codex-stage10`

## 1. 本轮目标

在批判性复核 Stage 9 后，本轮目标不是只继续堆检测逻辑，而是解决两个实际问题：

1. survival fast path 在 HTTP/1 下仍然会先占用 request permit，导致 hot-cache drop 也可能排队。
2. 压测报告缺少 client actual send / WAF verdict RPS 等辅助口径，容易把压测端供给问题误判为 WAF 上限。

最终目标：

| 项目 | 目标 |
|---|---:|
| 高级 CDN CC 120 秒 | >= 2200 TPS |
| 高级 CDN CC 600 秒 | >= 2100 TPS |
| hot cache 长测覆盖率 | >= 97% |
| proxy failures | 0 |
| SQLite queue | 不积压 |
| OOM | 0 |

## 2. 代码改动

### 2.1 HTTP/1 survival fast path 再前移

文件：`src/core/engine/network/http1/connection.rs`

原先 HTTP/1 已经把 survival CC fast path 放在 L4 request policy 前，但仍然先获取 `request_semaphore`。高压下，大量本可直接 hot-cache drop 的请求会先等待 permit，导致压测端 timeout 和连接供给下降。

本轮改为：

```text
read request head
-> routing/runtime/site annotation
-> survival CC fast path
-> 如果 block/challenge，直接处理
-> 如果 no-decision，才获取 request permit 并进入完整链路
```

同时对 survival fast block 的 AI route result 回写做 1/64 采样，避免每个 hot drop 都更新 AI route bucket。

### 2.2 HTTP/2 / HTTP/3 补 survival fast path 前置

文件：

| 文件 | 改动 |
|---|---|
| `src/core/engine/network/http2/connection.rs` | 在 L4 request policy 前增加 survival CC fast path |
| `src/core/engine/network/http3/connection.rs` | 在 L4 request policy 前增加 survival CC fast path |

这修正了 Stage 9 报告里隐含但代码上不完全一致的问题：HTTP/1 有前置快路径，HTTP/2/3 原先没有同级前置。

### 2.3 L7 hot cache key 按需构造

文件：`src/l7/cc_guard/runtime.rs`

原先 fast path 即使 `ip_route` 第一层命中，也会先构造 `ip`、`route`、`site` 另外三层 hot cache key。

本轮改为按顺序懒构造：

```text
ip_route 命中 -> 立即返回
否则构造并检查 ip
否则构造并检查 route
否则构造并检查 site
```

这降低了 99%+ hot hit 场景下的字符串分配和格式化成本。

### 2.4 压测脚本指标增强

文件：

| 文件 | 改动 |
|---|---|
| `scripts/run_stage9_case.sh` | summary 增加 client actual send、client errors、WAF verdict RPS、WAF proxy RPS |
| `scripts/cdn_cc_openloop.py` | 增加 attempted/sent/error_counts/schedule lag/source-count/RST close |

## 3. 本地验证

已通过：

```text
cargo fmt --check
cargo check
cargo test l7::cc_guard -- --nocapture
cargo test early_defense -- --nocapture
python3 -m py_compile scripts/cdn_cc_openloop.py scripts/cdn_cc_stress_tunable.py
```

关键结果：

| 测试 | 结果 |
|---|---|
| `l7::cc_guard` | 26 passed |
| `early_defense` | 3 passed |

## 4. 远端构建

构建方式：

```text
docker run --rm -e CARGO_HOME=/cargo \
  -v /root/rust_waf_test/srcpkg:/src \
  -v /root/rust_waf_test/target:/src/target \
  -v /root/rust_waf_test/cargo-home:/cargo \
  -w /src rust:1-bookworm cargo build --release --locked --offline
```

结果：

```text
Finished release profile [optimized]
```

## 5. 压测结果

### 5.1 高级 CDN CC 120 秒

场景：`advanced-multi-4x256-ai-sampled`，4 进程 × 256 线程，120 秒。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 2372.50 |
| 有效攻击请求 | 291817 |
| CPU 平均 | 91.91% |
| CPU 峰值 | 196.34% |
| 内存峰值 | 69.8MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| hot cache 覆盖率 | 99.84% |
| fast path no-decision | 0.07% |
| OOM | false |

结论：高级 CDN CC 120 秒已超过 2200 TPS 目标。

### 5.2 高级 CDN CC 600 秒长测

场景：`advanced-multi-4x256-600s`，4 进程 × 256 线程，600 秒。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 2342.41 |
| 有效攻击请求 | 1409333 |
| CPU 平均 | 88.00% |
| CPU 峰值 | 193.43% |
| 内存峰值 | 119.4MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| hot cache 覆盖率 | 99.99% |
| fast path no-decision | 0.02% |
| OOM | false |

结论：高级 CDN CC 600 秒已超过 2100 TPS 目标，并且长测 hot cache 覆盖率稳定。

### 5.3 常规 CDN CC 90 秒

场景：`regular-multi-4x256`，4 进程 × 256 线程，90 秒。

| 指标 | 结果 |
|---|---:|
| 有效攻击 TPS | 2592.35 |
| 有效攻击请求 | 241166 |
| CPU 平均 | 93.81% |
| CPU 峰值 | 188.17% |
| 内存峰值 | 46.4MB |
| 后端成功率 | 100.0% |
| proxy failures | 0 |
| SQLite queue depth | 0 |
| hot cache 覆盖率 | 99.99% |
| fast path no-decision | 0.01% |
| OOM | false |

说明：常规场景稳定性正常，但该口径下 TPS 低于 Stage 9 的 2711.86，CPU 平均不高，仍更像压测端供给限制。

## 6. 对比关键节点

| 阶段/版本 | 场景 | TPS | 说明 |
|---|---|---:|---|
| Stage 9 最佳 | 高级 120 秒 closed 512 | 2151.73 | 未达 2200 |
| 本轮改动前 | 高级 multi 4x256 | 2100.51 | 未达 2200 |
| permit 前移后 | 高级 multi 4x256 | 2157.69 | 明显改善，但未达 2200 |
| AI route 采样后 | 高级 multi 4x256 | 2372.50 | 达成 2200+ |
| 本轮长测 | 高级 multi 4x256 600 秒 | 2342.41 | 达成 2100+ |

## 7. 结论

本轮已经达成 Stage 9 后续目标：

| 目标 | 结果 |
|---|---|
| 高级 CDN CC 120 秒 2200+ | 已达成，2372.50 TPS |
| 高级 CDN CC 600 秒 2100+ | 已达成，2342.41 TPS |
| hot cache 长测 >= 97% | 已达成，99.99% |
| proxy failure = 0 | 已达成 |
| SQLite queue 不积压 | 已达成 |
| 无 OOM | 已达成 |

最关键的工程判断：

```text
Stage 9 的 fast path 方向正确，但 HTTP/1 fast path 还没有完全避开 request permit。
本轮把 hot-cache drop 从 request permit 后移到 request permit 前，才真正形成了战时便宜路径。
```

当前仍需谨慎的地方：

1. 本轮主达标口径是 multi closed-loop，不是严格专业 open-loop。
2. 每请求新建连接的 open-loop 仍暴露出连接/accept/客户端 timeout 供给瓶颈。
3. 还没有完成攻击 + 正常业务混合流量误杀率和正常用户 p95/p99 验证。
4. 高基数低频代理池仍需单独测试四层 hot cache 的真实覆盖能力。

## 7.1 口径澄清

为避免后续讨论混淆，当前关于高级 CDN CC `2000+ TPS` 的准确口径如下：

| 问题 | 当前结论 |
|---|---|
| multi closed-loop 高级 CDN CC 120 秒是否超过 2000 TPS | 是，Stage 10 测得 `2372.50` TPS |
| multi closed-loop 高级 CDN CC 600 秒是否超过 2000 TPS | 是，Stage 10 测得 `2342.41` TPS |
| 严格 open-loop 固定到达率是否已证明 2000+ | 还没有 |
| 攻击 + 正常业务混合流量是否已证明 2000+ | 还没有 |
| 高基数低频代理池高级 CC 是否已证明 2000+ | 还没有 |

因此后续应表述为：

```text
高级 CDN CC 的 2000+ TPS 已在 multi closed-loop 压测口径下达成，但严格 open-loop、混合正常流量和高基数低频攻击还需要继续验证。
```

## 8. 建议下一步

下一阶段建议进入生产可用性验证，而不是继续盲目压热路径：

1. 补 95/5、90/10、80/20 攻击/正常混合流量。
2. 补合法 Cookie/Token 用户的成功率、误杀率、p95/p99。
3. 补 1k/10k IP 高基数低频攻击，拆分观察 `ip_route/ip/route/site` 各层 cache 命中。
4. 若继续追求 open-loop 固定 RPS，应改用 Tokio async 压测器或 vegeta/wrk2，并区分连接模型与 WAF verdict 模型。
