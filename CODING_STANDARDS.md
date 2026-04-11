# 编码与检查约定

本文档记录当前仓库已落地的最小工程检查约束。

## Rust

- 格式化命令：`cargo fmt`
- 编译检查命令：`cargo check`
- 测试命令：`cargo test`
- 建议本地执行：`cargo clippy --all-targets --all-features`

当前约定：

- 业务代码避免新增裸 `unwrap()` 和 `expect()`
- 优先返回结构化错误，而不是直接 panic
- `src/main.rs` 逐步收敛为启动与装配入口
- 大文件改动优先考虑拆分，而不是继续叠加职责
- 对外稳定入口优先保持不变，内部细节通过子模块下沉

测试与导出约定：

- Rust 统一测试入口为 `cargo test`
- 单模块改动允许先执行 `cargo test <module_name>` 或 `cargo test <test_name>`，最终仍需回归 `cargo test`
- `lib.rs` 与各领域 `mod.rs` 只导出稳定入口，避免把内部 helper 无约束地 `pub`
- 测试优先放在被测模块的 `#[cfg(test)] mod tests` 中；跨模块集成行为优先走 API / storage / engine 的端到端测试

单文件体量建议：

- Rust 普通源码文件建议控制在 `<= 400` 行；超过 `600` 行默认进入拆分评估
- `mod.rs` 建议控制在 `<= 250` 行；超过 `350` 行时优先把 handler、model、query、helper 下沉到子模块
- 单个函数建议控制在 `<= 80` 行；超过 `120` 行时优先抽离步骤函数

`mod.rs` 使用规范：

- `mod.rs` 优先承担模块入口、路由装配、导出边界、共享类型别名
- 避免在 `mod.rs` 中堆叠大量业务处理逻辑、SQL 拼装细节或协议解析细节
- 只有当目录需要明确模块边界时使用 `mod.rs`；纯叶子模块优先使用独立文件

命名与导出约定：

- 目录名使用领域语义复数或集合名，如 `api`、`storage`、`integrations`
- 文件名使用职责语义，优先 `*_handlers.rs`、`*_query.rs`、`*_models.rs`、`*_schema.rs`、`*_maintenance.rs`
- 默认最小可见性：能 `pub(super)` 就不放大到 `pub`
- 对外暴露的数据结构使用名词；动作函数使用动词短语；转换函数统一使用 `from_*` / `into_*`

说明：

- 当前 CI 已阻断 `cargo fmt --check`、`cargo check` 和 `cargo test`
- `cargo clippy` 已提供配置文件，但暂未纳入阻断，后续在清理现有告警后再升级为强制校验

## Frontend

- Lint 命令：`npm run lint`
- 类型检查命令：`npm run typecheck`
- 构建命令：`npm run build`
- 格式化命令：`npm run format`

当前约定：

- Vue 与 TypeScript 代码统一通过 ESLint 校验
- 代码格式统一通过 Prettier 处理
- 页面文件过大时优先拆成 `page + section + composable`

前端页面拆分建议：

- 页面文件建议控制在 `<= 300` 行；超过 `500` 行默认进入拆分评估
- 页面状态、过滤器、表单逻辑优先抽到 composable
- 重复布局、卡片、筛选栏、表格区块优先抽到 `components/<domain>` 子目录
- 管理台页面优先按 `overview / filters / table / form-dialog / drawer` 拆分

当前超大页面优先级：

- `vue/src/pages/AdminSitesPage.vue`
- `vue/src/pages/AdminL7Page.vue`
- `vue/src/pages/AdminSettingsPage.vue`
- `vue/src/pages/AdminL4Page.vue`
- `vue/src/pages/AdminRulesPage.vue`
