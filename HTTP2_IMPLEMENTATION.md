# HTTP/2.0支持实现说明

## 概述

本项目已经成功实现了HTTP/2.0协议支持，扩展了原有的WAF系统以支持现代HTTP协议版本。实现保持了向后兼容性，同时为未来的HTTP/3.0支持预留了架构。

## 主要功能

### 1. 协议版本检测
- **HTTP/1.1**: 支持传统的HTTP/1.1协议
- **HTTP/2.0**: 支持HTTP/2.0协议，包括：
  - 直接模式（HTTP/2.0预请求）
  - 升级模式（通过HTTP/1.1 Upgrade头）
  - 自动检测和路由

### 2. 统一HTTP请求抽象
- `UnifiedHttpRequest` 结构提供协议无关的HTTP请求表示
- 支持从不同协议版本提取统一信息
- 保留协议特定元数据（如HTTP/2.0流ID）

### 3. 增强的L7检测
- 现有安全检测功能适用于所有HTTP版本
- 支持的攻击检测类型：
  - SQL注入检测
  - XSS攻击检测
  - 路径遍历检测
  - 命令注入检测
- Bloom Filter优化支持所有协议版本

### 4. 配置系统扩展
- 新增 `Http2Config` 配置选项：
  - `enabled`: HTTP/2.0支持开关
  - `max_concurrent_streams`: 最大并发流数
  - `max_frame_size`: 最大帧大小
  - `enable_priorities`: 流优先级支持
  - `initial_window_size`: 初始窗口大小

## 架构设计

### 模块结构
```
src/protocol/
├── mod.rs                    # 协议模块入口
├── detector.rs               # 协议版本检测器
├── http1.rs                  # HTTP/1.1处理器
├── http2.rs                  # HTTP/2.0处理器
└── unified.rs                # 统一请求抽象
```

### 处理流程
```
连接建立
    ↓
协议检测 (ProtocolDetector)
    ↓
协议路由
    ├─→ HTTP/1.1 → Http1Handler
    └─→ HTTP/2.0 → Http2Handler
    ↓
统一请求转换 (UnifiedHttpRequest)
    ↓
L7安全检测 (L7Inspector)
    ↓
协议特定响应
```

## 依赖库

### HTTP/2.0支持
- `hyper = "1.0"`: 高级HTTP库，支持HTTP/1.1和HTTP/2.0
- `h2 = "0.3"`: 低级HTTP/2.0实现
- `http = "1.0"`: HTTP类型定义
- `tower = "0.4"`: 中间件支持

### 预留HTTP/3.0支持
未来可添加的依赖：
- `quinn = "0.10"`: QUIC协议实现
- `h3 = "0.0.4"`: HTTP/3.0 over QUIC
- `rustls = "0.23"`: TLS 1.3支持

## 配置示例

### 标准配置 (config/standard.json)
```json
{
  "l7_config": {
    "http_inspection_enabled": true,
    "max_request_size": 8192,
    "http2_config": {
      "enabled": true,
      "max_concurrent_streams": 100,
      "max_frame_size": 16384,
      "enable_priorities": true,
      "initial_window_size": 65535
    }
  }
}
```

### 最小配置 (config/minimal.json)
```json
{
  "l7_config": {
    "http_inspection_enabled": true,
    "max_request_size": 4096,
    "http2_config": {
      "enabled": false,
      "max_concurrent_streams": 50,
      "max_frame_size": 16384,
      "enable_priorities": true,
      "initial_window_size": 65535
    }
  }
}
```

## 测试

### 测试覆盖
项目包含全面的测试套件：
- 协议版本检测测试
- HTTP/1.1和HTTP/2.0处理器测试
- 统一请求结构测试
- L7安全检测测试
- 配置系统测试

### 运行测试
```bash
cargo test --test http2_tests
```

## 使用方法

### 启动WAF
```bash
# 使用标准配置（启用HTTP/2.0）
cargo run

# 使用最小配置（HTTP/2.0默认禁用）
cargo run
```

### 测试HTTP/2.0支持
```bash
# 测试HTTP/2.0直接模式
curl --http2 -v http://localhost:8080/

# 测试HTTP/2.0升级模式
curl -H "Upgrade: h2c" -H "Connection: Upgrade, HTTP2-Settings" http://localhost:8080/
```

## 技术特点

### 1. 向后兼容
- 完全保持与现有HTTP/1.1实现的兼容性
- 原有API和配置继续正常工作
- 平滑升级路径

### 2. 性能优化
- HTTP/2.0多路复用减少连接开销
- 统一抽象层最小化协议处理开销
- Bloom Filter加速威胁检测

### 3. 安全增强
- 所有安全检测适用于所有HTTP版本
- 协议特定威胁检测
- 流级别的安全监控

### 4. 可扩展性
- 清晰的协议抽象层
- 易于添加新的HTTP版本支持
- 模块化设计便于维护

## 未来扩展

### HTTP/3.0支持预留
- 枚举中已包含 `Http3_0` 变体
- QUIC协议集成预留接口
- 配置系统已为HTTP/3.0预留空间

### 建议的增强功能
1. **完整的HTTP/2.0服务器实现**
   - 使用hyper的完整HTTP/2.0服务器功能
   - 完整的多路复用支持
   - 流级别的优先级和流量控制

2. **TLS/ALPN支持**
   - 实现真正的TLS握手处理
   - ALPN协议协商支持
   - 安全的协议升级

3. **性能优化**
   - 连接池和复用
   - 更高效的协议解析
   - 并发处理优化

4. **监控和统计**
   - 按协议版本的统计
   - HTTP/2.0流级监控
   - 性能指标收集

## 开发说明

### 构建项目
```bash
# 开发构建
cargo build

# 发布构建
cargo build --release
```

### 运行项目
```bash
# 开发模式
cargo run

# 发布模式
cargo run --release
```

### 检查代码
```bash
# 格式检查
cargo fmt --check

# 代码检查
cargo clippy

# 测试
cargo test
```

## 兼容性

### 支持的客户端
- HTTP/1.1: 所有现代浏览器和HTTP客户端
- HTTP/2.0: 支持HTTP/2.0的现代浏览器（Chrome, Firefox, Safari等）
- curl: 支持`--http2`选项
- 各种编程语言的HTTP客户端库

### 平台支持
- Linux: ✅ 完全支持
- macOS: ✅ 完全支持
- Windows: ✅ 完全支持

## 许可证

MIT License

## 贡献指南

欢迎提交问题报告、功能请求和代码贡献。请遵循项目的编码标准和提交指南。

## 联系方式

如有问题或建议，请通过项目的Issue Tracker联系。