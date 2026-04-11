# 项目规范化剩余步骤

本文档只保留当前尚未完成的规范化改造步骤，作为后续执行与编辑基线。

## 当前状态

已完成：

- P0 工程底座
- `lib / bin` 边界整理
- API 第一批拆分：`types`
- API 第二批拆分：`conversions`

---

## 剩余主线步骤

### 1. 拆分 API handlers

目标：让 `src/api/mod.rs` 主要承担路由入口职责，按领域拆分 handler。

- [ ] 按领域拆分 `src/api/mod.rs` 中的 handlers
- [ ] 优先按 `settings / safeline / rules / sites / events` 拆分
- [ ] 让 `src/api/mod.rs` 保持为路由装配入口
- [ ] 保持现有测试全部通过

### 2. 拆分 `src/storage/mod.rs`

目标：降低存储层单文件复杂度，分离 repository、query、model、migration 职责。

- [ ] 拆分 `src/storage/mod.rs`
- [ ] 抽离 query 参数与排序定义
- [ ] 抽离数据模型与 upsert 结构
- [ ] 抽离 migration / schema 初始化逻辑
- [ ] 保持现有测试全部通过

### 3. 拆分 `src/core/engine.rs`

目标：把运行时调度、监听、代理、健康检查等职责拆开。

- [ ] 拆分 `src/core/engine.rs`
- [ ] 按监听器、转发、维护任务、健康检查等职责拆分
- [ ] 保持 `WafEngine` 作为稳定入口
- [ ] 保持现有测试全部通过

### 4. 拆分 `src/integrations/safeline.rs`

目标：把 SafeLine 集成中的客户端、解析、同步逻辑分层。

- [ ] 拆分 `src/integrations/safeline.rs`
- [ ] 抽离 API 客户端
- [ ] 抽离 payload 解析和转换逻辑
- [ ] 抽离同步相关逻辑
- [ ] 保持现有测试全部通过

### 5. 完成 P1 剩余规范项

目标：在主要大文件拆分后，把结构约束正式沉淀为项目规则。

- [ ] 统一测试入口和公共导出策略
- [ ] 梳理前端超大页面拆分方案
- [ ] 制定单文件体量阈值建议
- [ ] 制定 `mod.rs` 使用规范
- [ ] 制定目录命名、文件命名、模块导出约定

---

## 建议执行顺序

1. API handlers
2. storage
3. core engine
4. safeline integration
5. P1 规范补完

---

## 备注区

- 当前阶段：P1
- 下一步：拆分 API handlers
- 备注：
