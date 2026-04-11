# 前端规范整改清单

本文档用于承接本轮 Vue 前端代码规范检查结果，聚焦已落地现状、仍需整改的缺口，以及下一步治理优先级。

适用范围：

- `vue/` 子项目

本轮扫描时间：

- 2026-04-11

## 当前检查结论

- `npm run lint` 通过
- `npm run typecheck` 通过
- `npm run build` 通过
- `npm run format:check` 通过
- `CODING_STANDARDS.md` 已补充前端检查闭环、目录职责与页面拆分建议
- `vue/eslint.config.js` 已恢复并启用 `vue/attributes-order`
- `vue/multi-word-component-names` 已恢复为默认开启，仅保留 `App` 例外
- `AdminSitesPage.vue` 已降到 `166` 行
- `AdminL7Page.vue` 已降到 `145` 行
- `AdminSettingsPage.vue` 已降到 `160` 行
- `AdminL4Page.vue` 已降到 `127` 行
- `AdminRulesPage.vue` 已降到 `106` 行
- 仍存在明显超大页面：`AdminSafeLinePage.vue` `761` 行
- 仍存在明显超大脚本：`useAdminSites.ts` `661` 行、`lib/types.ts` `600` 行

## 体量扫描摘要

页面文件现状：

- 超过 `500` 行：`AdminSafeLinePage.vue`、`AdminL7RulesPage.vue`、`AdminL4RulesPage.vue`
- 超过 `300` 行：另有 `AdminEventsPage.vue`、`AdminL4BlocklistPage.vue`、`AdminPage.vue`、`AdminL4PortsPage.vue`
- 已完成拆分并回到建议阈值内：`AdminSitesPage.vue`、`AdminL7Page.vue`、`AdminSettingsPage.vue`、`AdminL4Page.vue`、`AdminRulesPage.vue`

组件与状态层现状：

- `components/<domain>/`、`composables/`、`lib/` 已形成分层，但体量分布不均
- `AdminL7ConfigSection.vue` `497` 行、`AdminSitesTableSection.vue` `373` 行、`AdminSettingsSafeLineSection.vue` `334` 行，已进入下一轮 section 拆分范围
- `AdminL4ConfigSection.vue` 已降到 `50` 行，`AdminL4RuntimeInsightsSection.vue` 为 `160` 行，`AdminL4ConfigFormCard.vue` 为 `202` 行，说明 L4 页面拆分已基本完成，剩余仅是表单卡片边界微调
- `useAdminSites.ts` `661` 行、`useAdminSettings.ts` `462` 行、`useAdminL7.ts` `369` 行，说明页面拆分后仍需继续收口副作用和流程编排
- `useAdminL4.ts` 已控制在 `231` 行，基本贴近当前 composable 体量目标
- `AdminRuleEditorDialog.vue` `453` 行，已替代页面内联弹窗逻辑，但后续仍建议继续拆出“基础信息表单”和“响应模板编辑区”
- `useAdminRules.ts` 已控制在 `239` 行，接近当前 composable 体量目标

命名与风格抽样结论：

- `loading / refreshing / saving / testing`
- `error / successMessage`
- `handle* / open* / close* / load* / fetch*`

以上命名模式在多个页面和组件中已经出现，说明项目已形成初步统一，但仍未由 lint 规则或目录约束完全自动化保障。

## 整改目标

- 让前端规范从“文档约定”升级为“自动化约束”
- 让页面职责从“大而全”收敛为“页面装配 + 组件分区 + composable”
- 让新增代码遵循统一结构，避免继续放大超大页面和脚本复杂度

## P0 工程检查闭环

### 1. 补齐格式化校验

- [x] 在 `vue/package.json` 增加 `format:check`，统一使用 `prettier --check .`
- [x] 将 `format:check` 纳入本地提交流程或 CI
- [x] 先执行一次 `npm run format`，清理现有格式漂移
- [ ] 后续默认以格式化后的结果作为 review 基线，避免混入无意义 diff

### 2. 明确前端阻断项

- [x] 统一前端最小检查集：`npm run lint`
- [x] 统一前端最小检查集：`npm run typecheck`
- [x] 统一前端最小检查集：`npm run build`
- [x] 统一前端最小检查集：`npm run format:check`
- [x] 在根目录规范文档中补充“前端 CI 阻断项已启用/待启用”状态说明

### 3. 收敛 ESLint 例外规则

- [x] 复核 `vue/attributes-order` 是否需要继续关闭
- [x] 复核 `vue/multi-word-component-names` 是否需要全局关闭
- [x] 对必须保留的例外规则补充原因说明，写入 `CODING_STANDARDS.md`
- [x] 优先避免“全局关闭规则”，改为按目录或按场景收敛例外

## P1 目录与职责分层

### 4. 固化前端目录职责

- [x] `pages/` 仅保留页面级装配、路由入口、少量页面状态
- [x] `components/<domain>/` 承接区块 UI、表格区、筛选栏、弹窗、表单区
- [x] `composables/` 承接页面状态管理、副作用、轮询、筛选器、提交流程
- [x] `lib/` 承接 API 请求、纯数据转换、表单 payload 组装、领域 helper
- [x] 新增页面功能时，默认先判断是否应落在 section / dialog / composable，而不是直接追加到页面文件

### 5. 建立页面拆分准入线

- [x] 页面文件超过 300 行时进入拆分提醒
- [x] 页面文件超过 500 行时默认不再继续叠加职责
- [ ] 单个 section 超过 200 行时继续拆分
- [ ] 单个 composable 超过 250 行时拆为查询、提交、映射或过滤子能力
- [ ] 新增大功能时先给出拆分落点，再开始写代码

说明：

- 页面 `300 / 500` 行阈值已写入 `CODING_STANDARDS.md`，但目前仍属于文档约束，尚未自动化阻断
- `section 200` 行与 `composable 250` 行阈值还未写入统一规范，也未形成 review 固定动作

## P1 超大页面治理

### 6. 按优先级拆分现有超大页面

- [x] 优先拆分 `vue/src/pages/AdminSitesPage.vue`
- [x] 优先拆分 `vue/src/pages/AdminL7Page.vue`
- [x] 优先拆分 `vue/src/pages/AdminSettingsPage.vue`
- [x] 优先拆分 `vue/src/pages/AdminL4Page.vue`
- [x] 优先拆分 `vue/src/pages/AdminRulesPage.vue`
- [ ] 继续跟进 `vue/src/pages/AdminSafeLinePage.vue`

### 7. 管理台页面统一拆分模板

- [x] 页面层保留 `Page.vue`
- [x] 概览区抽为 `OverviewSection`
- [x] 筛选区抽为 `FilterBar` 或 `FiltersSection`
- [x] 列表区抽为 `TableSection` 或 `ListSection`
- [x] 编辑区抽为 `EditorDialog` / `FormDialog`
- [x] 状态与副作用抽为 `use<PageName>` composable

## P2 代码风格统一

### 8. 统一导入与格式风格

- [x] 全项目统一使用 Prettier 结果作为唯一格式基线
- [x] 避免同仓库同时出现单双引号、分号风格混用
- [ ] 导入顺序至少做到“框架库 / 第三方库 / 本地模块”分组稳定
- [x] 路由、组件、工具函数的相对导入风格保持一致

说明：

- 目前格式风格已经由 Prettier 统一收敛
- 导入分组尚未看到自动化约束，后续如继续治理可补 import sorting 规则

### 9. 统一状态命名与交互命名

- [x] 加载态统一使用 `loading / refreshing / saving / testing` 这一类动名词
- [x] 错误与成功反馈统一使用 `error`、`successMessage` 等稳定命名
- [x] 事件处理函数统一使用 `handle*`
- [x] 打开/关闭类函数统一使用 `open*`、`close*`
- [x] 数据加载类函数统一使用 `load*`、`fetch*`，避免同一语义混用

说明：

- 该项基于页面、组件与 `lib/api.ts` 抽样结果判定为“基本达成”
- 后续仍建议继续减少同一页面内 `load*` 与 `fetch*` 同时承担页面逻辑的混用情况

### 10. 统一副作用与轮询写法

- [x] `onMounted` 中的加载逻辑优先抽到独立 `load*` 函数
- [x] 定时器统一成对处理：创建时记录，卸载时清理
- [ ] `watch` 只保留必要依赖，避免把复杂业务直接塞进回调
- [ ] 页面级轮询逻辑优先下沉到 composable，避免页面脚本持续膨胀

说明：

- `onMounted(load*)` 模式已在多个页面落地
- `AdminPage.vue` 等页面仍存在页面级轮询逻辑，后续建议继续下沉

## P2 复用与抽象

### 11. 提升共享逻辑复用率

- [ ] 对重复出现的筛选、分页、空态、状态标签进行抽象
- [x] 对重复出现的列表转换、状态映射、文案格式化下沉到 `lib/` 或 `composables/`
- [x] 将规则表单、站点表单、配置表单中的 payload 组装与回填逻辑改为纯函数
- [x] 将 API 响应到视图模型的映射从页面中抽离

### 12. 控制类型文件和接口边界

- [ ] `lib/types.ts` 过大时按领域拆分，如 `rules.ts`、`sites.ts`、`settings.ts`
- [x] 页面只引入所需领域类型，避免所有类型都堆在单文件
- [x] 领域枚举值优先收敛为字面量联合或常量映射，减少散落 magic string

## P3 文档与协作约定

### 13. 补齐清单维护规则

- [x] 清单状态以实际代码扫描结果为准，不仅记录规划项
- [x] 每次完成页面拆分后同步回写体量变化与后续重点
- [x] 允许在清单中补充“说明”与“证据”，避免只保留空泛勾选项

### 14. 形成增量治理机制

- [x] 新功能开发默认不向超大页面继续堆叠
- [x] 涉及超大页面的需求，优先顺手拆出一个 section 或 composable
- [x] review 时把“是否新增职责堆积”作为固定检查项
- [x] 每完成一页拆分，同步更新本清单状态

## 下一步建议执行顺序

1. 优先拆分 `AdminSafeLinePage.vue`，避免继续把副作用留在页面层
2. 将 `useAdminSites.ts` 再拆为查询、编辑器状态、远端同步三类子能力
3. 将 `lib/types.ts` 按 `rules / sites / settings / safeline / dashboard` 进行领域拆分
4. 视后续需求再微调 `AdminL4ConfigFormCard.vue` 与 `AdminRuleEditorDialog.vue`，尽量继续压缩 section / dialog 体量
5. 补充对 `section / composable` 体量阈值的文档约束，后续再考虑是否接入自动化校验

## 完成标准

- 前端最小检查集全部可稳定执行
- Prettier 校验进入自动化流程
- 超大页面不再继续增长，并开始按优先级下降
- 页面、组件、composable、lib 的职责边界清晰
- 规范文档与实际工程约束保持一致
