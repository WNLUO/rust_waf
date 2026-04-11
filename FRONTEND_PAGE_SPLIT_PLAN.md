# 前端超大页面拆分方案

本文档用于承接 P1 阶段前端超大页面治理，给出按优先级执行的拆分落点。

## 优先级

1. `vue/src/pages/AdminSitesPage.vue` 约 1595 行
2. `vue/src/pages/AdminL7Page.vue` 约 1382 行
3. `vue/src/pages/AdminSettingsPage.vue` 约 1197 行
4. `vue/src/pages/AdminL4Page.vue` 约 805 行
5. `vue/src/pages/AdminRulesPage.vue` 约 763 行
6. `vue/src/pages/AdminSafeLinePage.vue` 约 761 行

## 拆分模板

推荐结构：

- `pages/<PageName>.vue`
- `components/<domain>/<PageName>OverviewSection.vue`
- `components/<domain>/<PageName>FilterBar.vue`
- `components/<domain>/<PageName>TableSection.vue`
- `components/<domain>/<PageName>EditorDialog.vue`
- `composables/use<PageName>.ts`

## 页面级建议

### `AdminSitesPage`

- 拆成站点列表、证书列表、同步链路三个 section
- 站点表单与证书表单分别独立 dialog 组件
- 数据加载、缓存刷新、联动提交逻辑下沉到 `useAdminSites`

### `AdminL7Page`

- 拆成运行状态、全局配置、HTTP/2、HTTP/3、健康检查五个 section
- 表单校验和 payload 组装下沉到 `useAdminL7Config`

### `AdminSettingsPage`

- 拆成网关设置、通知设置、SafeLine 设置三个 section
- SafeLine 连通性测试与保存逻辑拆到 `useAdminSettings`

### `AdminL4Page`

- 拆成运行状态、基础策略、限速策略、布隆过滤器四个 section
- 表单状态与保存逻辑下沉到 `useAdminL4Config`

### `AdminRulesPage`

- 拆成规则列表、规则编辑器、模板插件列表三个 section
- 规则草稿、校验、模板填充逻辑下沉到 `useAdminRules`

## 落地阈值

- 页面超过 500 行时，不再继续向页面文件直接叠加功能
- 单 section 超过 200 行时，继续按展示区和交互区拆分
- composable 超过 250 行时，继续拆分为查询、提交、映射三个子能力
