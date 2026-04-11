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
