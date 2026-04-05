# 布隆过滤器使用指南

## 概述

本项目为 L4 和 L7 层的布隆过滤器实现了完整的开关控制功能，支持启用/禁用以及假阳性验证。

## 功能特性

### 1. 动态开关控制
- **总开关**：`bloom_enabled` - 控制所有布隆过滤器的启用状态
- **L4 层假阳性验证**：`l4_bloom_false_positive_verification`
- **L7 层假阳性验证**：`l7_bloom_false_positive_verification`

### 2. L4 层布隆过滤器
支持以下特征的过滤：
- IPv4 地址过滤
- IPv6 地址过滤
- IP:Port 组合过滤

### 3. L7 层布隆过滤器
支持以下特征的过滤：
- URL 过滤
- HTTP 方法过滤
- User-Agent 过滤
- Cookie 过滤
- Payload 过滤
- Headers 过滤

## 配置选项

### 配置文件结构

```json
{
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": false,
  "l7_bloom_false_positive_verification": false,
  ...
}
```

### 配置参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `bloom_enabled` | bool | false | 布隆过滤器总开关 |
| `l4_bloom_false_positive_verification` | bool | false | L4 层假阳性验证开关 |
| `l7_bloom_false_positive_verification` | bool | false | L7 层假阳性验证开关 |

## 使用模式

### 模式 1：高性能模式（仅布隆过滤器）

```json
{
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": false,
  "l7_bloom_false_positive_verification": false
}
```

**特点**：
- 布隆过滤器命中即判定为恶意
- 可能存在少量假阳性（误报）
- 内存占用：L4 ~750KB + L7 ~3.75KB
- 查询速度最快

**适用场景**：
- 对性能要求极高的环境
- 可以容忍少量误报
- 内存资源受限

### 模式 2：精确模式（启用假阳性验证）

```json
{
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": true,
  "l7_bloom_false_positive_verification": true
}
```

**特点**：
- 布隆过滤器命中后使用精确集合二次验证
- 完全消除假阳性
- 内存占用：基础内存 + 精确集合存储
- 查询速度略有下降

**适用场景**：
- 对准确性要求高的环境
- 不能容忍误报
- 内存资源充足

### 模式 3：禁用模式（默认）

```json
{
  "bloom_enabled": false,
  "l4_bloom_false_positive_verification": false,
  "l7_bloom_false_positive_verification": false
}
```

**特点**：
- 完全不使用布隆过滤器
- 仅依赖其他检测机制

**适用场景**：
- 不需要布隆过滤器功能
- 调试和测试环境

## 编程接口

### L4 层接口

```rust
// 获取布隆过滤器管理器
let bloom_manager = l4_inspector.get_bloom_manager_mut();

// 动态启用/禁用
l4_inspector.enable_bloom_filter(true);

// 设置假阳性验证
l4_inspector.set_bloom_false_positive_verification(true);

// 添加元素到布隆过滤器
if let Some(bloom_manager) = l4_inspector.get_bloom_manager_mut() {
    bloom_manager.add_ipv4(ipv4_addr);
    bloom_manager.add_ipv6(ipv6_addr);
    bloom_manager.add_ip_port(ip_addr, port);
}
```

### L7 层接口

```rust
// 获取布隆过滤器管理器
let bloom_manager = l7_inspector.get_bloom_manager_mut();

// 动态启用/禁用
l7_inspector.enable_bloom_filter(true);

// 设置假阳性验证
l7_inspector.set_bloom_false_positive_verification(true);

// 获取统计信息
let stats = l7_inspector.get_bloom_statistics();
let fp_stats = l7_inspector.get_bloom_false_positive_stats();
```

## 示例配置文件

### 完整配置示例

参考 `config/bloom_filter_demo.json`：

```json
{
  "interface": "eth0",
  "listen_addr": "0.0.0.0:8080",
  "runtime_profile": "standard",
  "api_enabled": false,
  "api_bind": "127.0.0.1:3000",
  "bloom_enabled": true,
  "l4_bloom_false_positive_verification": true,
  "l7_bloom_false_positive_verification": true,
  "maintenance_interval_secs": 20,
  "l4_config": {
    "ddos_protection_enabled": true,
    "advanced_ddos_enabled": false,
    "connection_rate_limit": 128,
    "syn_flood_threshold": 64,
    "scan_enabled": true,
    "max_tracked_ips": 4096,
    "max_blocked_ips": 1024,
    "state_ttl_secs": 300
  },
  "l7_config": {
    "http_inspection_enabled": true,
    "max_request_size": 8192,
    "prefilter_enabled": true,
    "enable_sql_injection_detection": true,
    "enable_xss_detection": true,
    "enable_path_traversal_detection": true,
    "enable_command_injection_detection": true
  },
  "rules": [],
  "metrics_enabled": true
}
```

## 性能影响

### 内存占用

| 组件 | 基础模式 | 精确模式（验证） |
|------|----------|-----------------|
| L4 IPv4 | ~125KB | + 精确集合 |
| L4 IPv6 | ~125KB | + 精确集合 |
| L4 IP:Port | ~625KB | + 精确集合 |
| L7 URL | ~1MB | + 精确集合 |
| L7 User-Agent | ~750KB | + 精确集合 |
| L7 HTTP Method | ~12.5KB | + 精确集合 |
| L7 其他 | ~1.75MB | + 精确集合 |
| **总计** | **~4.4MB** | **~4.4MB + 精确集合** |

### 查询延迟

- **基础模式**：O(1) 时间复杂度，仅布隆过滤器查询
- **精确模式**：O(1) + O(1) 时间复杂度，布隆过滤器 + 精确集合查询

## 假阳性率

### 理论假阳性率

布隆过滤器的假阳性率取决于以下因素：
- 位数组大小
- 哈希函数数量
- 已插入元素数量

在本项目配置下：
- L4 层：假阳性率 < 1%
- L7 层：假阳性率 < 0.5%

### 验证机制

启用假阳性验证后：
- 布隆过滤器命中 → 精确集合验证 → 最终判定
- 完全消除假阳性，确保准确性

## 日志和调试

### 启用调试日志

设置环境变量启用详细日志：

```bash
RUST_LOG=debug cargo run
```

### 日志输出示例

```
[INFO] Initializing L4 Bloom Filter Manager (enabled: true, false_positive_verification: true)
[DEBUG] Running L4 bloom filter checks
[DEBUG] IPv4 192.168.1.1 matched in bloom filter
[DEBUG] IPv4 Bloom filter hit for 192.168.1.1, exact verification: true
```

## 最佳实践

1. **生产环境**：建议启用假阳性验证，避免误封禁正常用户
2. **高流量环境**：可以仅使用布隆过滤器，牺牲少量准确性换取性能
3. **测试环境**：先禁用布隆过滤器验证其他功能，再逐步启用
4. **监控统计**：定期检查布隆过滤器的统计信息，优化配置

## 故障排查

### 布隆过滤器不生效

检查配置：
1. 确认 `bloom_enabled = true`
2. 检查日志中是否有初始化信息
3. 验证配置文件路径是否正确

### 假阳性过高

解决方案：
1. 启用假阳性验证
2. 增加布隆过滤器位数组大小
3. 调整哈希函数数量
4. 定期清理精确集合

### 内存占用过大

解决方案：
1. 禁用假阳性验证
2. 减小位数组大小
3. 定期清理不需要的过滤器

## 相关文件

- `src/l4/bloom_filter/mod.rs` - L4 层布隆过滤器实现
- `src/l7/bloom_filter/mod.rs` - L7 层布隆过滤器实现
- `src/l4/inspector.rs` - L4 层检查器（集成布隆过滤器）
- `src/l7/mod.rs` - L7 层检查器（集成布隆过滤器）
- `config/bloom_filter_demo.json` - 示例配置文件
- `README.md` - 项目说明文档
