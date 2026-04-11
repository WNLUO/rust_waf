# 前端规范整改清单

本文档用于承接本轮 Vue 前端代码规范检查结果，聚焦可执行的整改项，而不是重复描述问题现象。

适用范围：

- `vue/` 子项目

当前检查结论：

- `npm run lint` 通过
- `npm run typecheck` 通过
- `Prettier --check` 未通过，存在较多格式漂移
- 多个管理台页面明显超过当前项目建议的体量阈值

## 整改目标

- 让前端规范从“文档约定”升级为“自动化约束”
- 让页面职责从“大而全”收敛为“页面装配 + 组件分区 + composable”
- 让新增代码遵循统一结构，避免继续放大超大页面和脚本复杂度

## P0 工程检查闭环

### 1. 补齐格式化校验

- [x] 在 `vue/package.json` 增加 `format:check`，统一使用 `prettier --check .`
- [ ] 将 `format:check` 纳入本地提交流程或 CI
- [x] 先执行一次 `npm run format`，清理现有格式漂移
- [ ] 后续默认以格式化后的结果作为 review 基线，避免混入无意义 diff

### 2. 明确前端阻断项

- [x] 统一前端最小检查集：`npm run lint`
- [x] 统一前端最小检查集：`npm run typecheck`
- [x] 统一前端最小检查集：`npm run build`
- [x] 统一前端最小检查集：`npm run format:check`
- [x] 在根目录规范文档中补充“前端 CI 阻断项已启用/待启用”状态说明

### 3. 收敛 ESLint 例外规则

- [ ] 复核 `vue/attributes-order` 是否需要继续关闭
- [ ] 复核 `vue/multi-word-component-names` 是否需要全局关闭
- [ ] 对必须保留的例外规则补充原因说明，写入 `CODING_STANDARDS.md`
- [ ] 优先避免“全局关闭规则”，改为按目录或按场景收敛例外

## P1 目录与职责分层

### 4. 固化前端目录职责

- [ ] `pages/` 仅保留页面级装配、路由入口、少量页面状态
- [ ] `components/<domain>/` 承接区块 UI、表格区、筛选栏、弹窗、表单区
- [ ] `composables/` 承接页面状态管理、副作用、轮询、筛选器、提交流程
- [ ] `lib/` 承接 API 请求、纯数据转换、表单 payload 组装、领域 helper
- [ ] 新增页面功能时，默认先判断是否应落在 section / dialog / composable，而不是直接追加到页面文件

### 5. 建立页面拆分准入线

- [ ] 页面文件超过 300 行时进入拆分提醒
- [ ] 页面文件超过 500 行时默认不再继续叠加职责
- [ ] 单个 section 超过 200 行时继续拆分
- [ ] 单个 composable 超过 250 行时拆为查询、提交、映射或过滤子能力
- [ ] 新增大功能时先给出拆分落点，再开始写代码

## P1 超大页面治理

### 6. 按优先级拆分现有超大页面

- [ ] 优先拆分 `vue/src/pages/AdminSitesPage.vue`
- [ ] 优先拆分 `vue/src/pages/AdminL7Page.vue`
- [ ] 优先拆分 `vue/src/pages/AdminSettingsPage.vue`
- [ ] 优先拆分 `vue/src/pages/AdminL4Page.vue`
- [ ] 优先拆分 `vue/src/pages/AdminRulesPage.vue`
- [ ] 继续跟进 `vue/src/pages/AdminSafeLinePage.vue`

### 7. 管理台页面统一拆分模板

- [ ] 页面层保留 `Page.vue`
- [ ] 概览区抽为 `OverviewSection`
- [ ] 筛选区抽为 `FilterBar` 或 `FiltersSection`
- [ ] 列表区抽为 `TableSection` 或 `ListSection`
- [ ] 编辑区抽为 `EditorDialog` / `FormDialog`
- [ ] 状态与副作用抽为 `use<PageName>` composable

## P2 代码风格统一

### 8. 统一导入与格式风格

- [ ] 全项目统一使用 Prettier 结果作为唯一格式基线
- [ ] 避免同仓库同时出现单双引号、分号风格混用
- [ ] 导入顺序至少做到“框架库 / 第三方库 / 本地模块”分组稳定
- [ ] 路由、组件、工具函数的相对导入风格保持一致

### 9. 统一状态命名与交互命名

- [ ] 加载态统一使用 `loading / refreshing / saving / testing` 这一类动名词
- [ ] 错误与成功反馈统一使用 `error`、`successMessage` 等稳定命名
- [ ] 事件处理函数统一使用 `handle*`
- [ ] 打开/关闭类函数统一使用 `open*`、`close*`
- [ ] 数据加载类函数统一使用 `load*`、`fetch*`，避免同一语义混用

### 10. 统一副作用与轮询写法

- [ ] `onMounted` 中的加载逻辑优先抽到独立 `load*` 函数
- [ ] 定时器统一成对处理：创建时记录，卸载时清理
- [ ] `watch` 只保留必要依赖，避免把复杂业务直接塞进回调
- [ ] 页面级轮询逻辑优先下沉到 composable，避免页面脚本持续膨胀

## P2 复用与抽象

### 11. 提升共享逻辑复用率

- [ ] 对重复出现的筛选、分页、空态、状态标签进行抽象
- [ ] 对重复出现的列表转换、状态映射、文案格式化下沉到 `lib/` 或 `composables/`
- [ ] 将规则表单、站点表单、配置表单中的 payload 组装与回填逻辑改为纯函数
- [ ] 将 API 响应到视图模型的映射从页面中抽离

### 12. 控制类型文件和接口边界

- [ ] `lib/types.ts` 过大时按领域拆分，如 `rules.ts`、`sites.ts`、`settings.ts`
- [ ] 页面只引入所需领域类型，避免所有类型都堆在单文件
- [ ] 领域枚举值优先收敛为字面量联合或常量映射，减少散落 magic string

## P3 文档与协作约定


### 14. 形成增量治理机制

- [ ] 新功能开发默认不向超大页面继续堆叠
- [ ] 涉及超大页面的需求，优先顺手拆出一个 section 或 composable
- [ ] review 时把“是否新增职责堆积”作为固定检查项
- [ ] 每完成一页拆分，同步更新本清单状态

## 建议执行顺序

1. 先补 `format:check` 和前端检查闭环
2. 统一执行一次格式化，清掉历史噪音
3. 从 `AdminSitesPage` 开始做第一页拆分
4. 按既有优先级继续拆 `AdminL7Page`、`AdminSettingsPage`
5. 拆分过程中同步补齐文档和 ESLint 规则说明

## 完成标准

- 前端最小检查集全部可稳定执行
- Prettier 校验进入自动化流程
- 超大页面不再继续增长，并开始按优先级下降
- 页面、组件、composable、lib 的职责边界清晰
- 规范文档与实际工程约束保持一致
