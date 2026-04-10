<script setup lang="ts">
import { computed, reactive, ref, onMounted } from "vue";
import {
  createRule,
  deleteRule,
  fetchRuleActionPlugins,
  fetchRuleActionTemplates,
  fetchRulesList,
  installRuleActionPlugin,
  updateRule,
} from "../lib/api";
import type {
  RuleActionPluginItem,
  RuleActionTemplateItem,
  RuleDraft,
  RuleItem,
  RulesResponse,
} from "../lib/types";
import AppLayout from "../components/layout/AppLayout.vue";
import StatusBadge from "../components/ui/StatusBadge.vue";
import { useFormatters } from "../composables/useFormatters";
import {
  Plus,
  Edit3,
  Trash2,
  Check,
  Save,
  Search,
  RefreshCw,
  X,
} from "lucide-vue-next";

const { severityLabel, actionLabel, layerLabel } = useFormatters();

const loading = ref(true);
const saving = ref(false);
const installingPlugin = ref(false);
const error = ref("");
const rulesPayload = ref<RulesResponse>({ rules: [] });
const isRuleModalOpen = ref(false);
const pluginInstallUrl = ref("");
const installedPlugins = ref<RuleActionPluginItem[]>([]);
const pluginTemplates = ref<RuleActionTemplateItem[]>([]);

const isPluginActionValue = (value: string) => value.startsWith("plugin:");
const toPluginActionValue = (templateId: string) => `plugin:${templateId}`;
const selectedPluginTemplate = computed(() =>
  pluginTemplates.value.find((item) => item.template_id === ruleForm.plugin_template_id),
);
const displayActionLabel = (rule: RuleItem) => {
  if (rule.plugin_template_id) {
    const template = pluginTemplates.value.find(
      (item) => item.template_id === rule.plugin_template_id,
    );
    if (template) return `插件 · ${template.name}`;
  }
  return actionLabel(rule.action);
};

const defaultResponseTemplate = () => ({
  status_code: 403,
  content_type: "text/html; charset=utf-8",
  body_source: "inline_text",
  gzip: true,
  body_text: "",
  body_file_path: "",
  headers: [],
});

const ruleForm = reactive<RuleDraft>({
  id: "",
  name: "",
  enabled: true,
  layer: "l7",
  pattern: "",
  action: "block",
  severity: "high",
  response_template: defaultResponseTemplate(),
});

const ruleFilters = reactive({
  search: "",
  layer: "all",
  action: "all",
  severity: "all",
  status: "all",
});

const filteredRules = computed(() =>
  rulesPayload.value.rules.filter((rule) => {
    if (ruleFilters.layer !== "all" && rule.layer !== ruleFilters.layer)
      return false;
    if (ruleFilters.action !== "all" && rule.action !== ruleFilters.action)
      return false;
    if (
      ruleFilters.severity !== "all" &&
      rule.severity !== ruleFilters.severity
    )
      return false;
    if (
      ruleFilters.status !== "all" &&
      rule.enabled !== (ruleFilters.status === "enabled")
    )
      return false;
    if (!ruleFilters.search.trim()) return true;
    const keyword = ruleFilters.search.trim().toLowerCase();
    return (
      rule.name.toLowerCase().includes(keyword) ||
      rule.id.toLowerCase().includes(keyword) ||
      rule.pattern.toLowerCase().includes(keyword)
    );
  }),
);

const loadRules = async () => {
  loading.value = true;
  try {
    const [rules, plugins, templates] = await Promise.all([
      fetchRulesList(),
      fetchRuleActionPlugins(),
      fetchRuleActionTemplates(),
    ]);
    rulesPayload.value = rules;
    installedPlugins.value = plugins.plugins;
    pluginTemplates.value = templates.templates;
    error.value = "";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取规则失败";
  } finally {
    loading.value = false;
  }
};

const openCreateRule = () => {
  Object.assign(ruleForm, {
    id: "",
    name: "",
    enabled: true,
    layer: "l7",
    pattern: "",
    action: "block",
    severity: "high",
    plugin_template_id: null,
    response_template: defaultResponseTemplate(),
  });
  isRuleModalOpen.value = true;
};

const openEditRule = (rule: RuleItem) => {
  Object.assign(ruleForm, {
    ...rule,
    action: rule.plugin_template_id
      ? toPluginActionValue(rule.plugin_template_id)
      : rule.action,
    response_template: rule.response_template
      ? {
          ...rule.response_template,
          headers: [...rule.response_template.headers],
        }
      : defaultResponseTemplate(),
  });
  isRuleModalOpen.value = true;
};

const handleCreateOrUpdateRule = async () => {
  saving.value = true;
  try {
    const pluginTemplate = ruleForm.plugin_template_id
      ? pluginTemplates.value.find(
          (item) => item.template_id === ruleForm.plugin_template_id,
        )
      : null;
    const isPluginAction = isPluginActionValue(ruleForm.action);
    const payload: RuleDraft = {
      ...ruleForm,
      action: isPluginAction ? "respond" : ruleForm.action,
      layer: pluginTemplate?.layer || ruleForm.layer,
      severity: pluginTemplate?.severity || ruleForm.severity,
      pattern: pluginTemplate?.pattern || ruleForm.pattern,
      plugin_template_id: pluginTemplate?.template_id || null,
      response_template:
        (pluginTemplate?.layer || ruleForm.layer) === "l7" &&
        ((isPluginAction && pluginTemplate) || ruleForm.action === "respond")
          ? {
              status_code: Number(
                pluginTemplate?.response_template.status_code ||
                  ruleForm.response_template?.status_code ||
                  403,
              ),
              content_type:
                pluginTemplate?.response_template.content_type ||
                ruleForm.response_template?.content_type ||
                "text/html; charset=utf-8",
              body_source:
                pluginTemplate?.response_template.body_source ||
                ruleForm.response_template?.body_source ||
                "inline_text",
              gzip: Boolean(
                pluginTemplate?.response_template.gzip ??
                  ruleForm.response_template?.gzip,
              ),
              body_text:
                pluginTemplate?.response_template.body_text ||
                ruleForm.response_template?.body_text ||
                "",
              body_file_path:
                pluginTemplate?.response_template.body_file_path ||
                ruleForm.response_template?.body_file_path?.trim() ||
                "",
              headers: (
                pluginTemplate?.response_template.headers ||
                ruleForm.response_template?.headers ||
                []
              ).filter(
                (item) => item.key.trim(),
              ),
            }
          : null,
    };
    if (ruleForm.id) {
      await updateRule(payload);
    } else {
      await createRule(payload);
    }
    isRuleModalOpen.value = false;
    await loadRules();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "规则保存失败";
  } finally {
    saving.value = false;
  }
};

const onActionChange = () => {
  if (isPluginActionValue(ruleForm.action)) {
    const templateId = ruleForm.action.slice("plugin:".length);
    const template = pluginTemplates.value.find((item) => item.template_id === templateId);
    if (!template) return;
    ruleForm.plugin_template_id = template.template_id;
    Object.assign(ruleForm, {
      layer: template.layer,
      pattern: template.pattern,
      severity: template.severity,
      response_template: {
        ...template.response_template,
        headers: [...template.response_template.headers],
      },
    });
    return;
  }

  ruleForm.plugin_template_id = null;
  if (ruleForm.layer !== "l7" && ruleForm.action === "respond") {
    ruleForm.action = "block";
  }
};

const addResponseHeader = () => {
  ruleForm.response_template?.headers.push({ key: "", value: "" });
};

const removeResponseHeader = (index: number) => {
  ruleForm.response_template?.headers.splice(index, 1);
};

const handleInstallPlugin = async () => {
  const packageUrl = pluginInstallUrl.value.trim();
  if (!packageUrl) {
    error.value = "请输入插件包 URL";
    return;
  }

  installingPlugin.value = true;
  try {
    await installRuleActionPlugin(packageUrl);
    pluginInstallUrl.value = "";
    await loadRules();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "插件安装失败";
  } finally {
    installingPlugin.value = false;
  }
};

const toggleRuleStatus = async (rule: RuleItem) => {
  try {
    await updateRule({ ...rule, enabled: !rule.enabled });
    await loadRules();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "更新规则状态失败";
  }
};

const handleDeleteRule = async (id: string) => {
  if (!window.confirm("确认删除这条规则吗？")) return;
  try {
    await deleteRule(id);
    await loadRules();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "规则删除失败";
  }
};

onMounted(loadRules);
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="loadRules"
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="loading"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': loading }" />
        刷新规则
      </button>
    </template>

    <div class="space-y-6">
      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <label
          class="flex flex-1 min-w-[200px] items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500"
        >
          <Search :size="14" />
          <input
            v-model="ruleFilters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索名称 / ID / 匹配内容"
          />
        </label>
        <select
          v-model="ruleFilters.layer"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">七层</option>
        </select>
        <select
          v-model="ruleFilters.action"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="respond">自定义响应</option>
        </select>
        <select
          v-model="ruleFilters.severity"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部级别</option>
          <option value="low">低</option>
          <option value="medium">中</option>
          <option value="high">高</option>
          <option value="critical">紧急</option>
        </select>
        <select
          v-model="ruleFilters.status"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部状态</option>
          <option value="enabled">启用</option>
          <option value="disabled">停用</option>
        </select>
        <button
          @click="openCreateRule"
          class="inline-flex items-center gap-2 ml-auto rounded-[18px] bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-600/90 shrink-0"
        >
          <Plus :size="16" />
          新建规则
        </button>
      </div>

      <div class="rounded-[28px] border border-white/70 bg-white/60 p-4">
        <div class="flex flex-wrap items-center gap-3">
          <div class="min-w-[220px] flex-1">
            <p class="text-sm font-medium text-stone-900">规则模板插件</p>
            <p class="text-xs text-slate-500">
              输入 zip 包 URL，系统会下载并安装为可选的 `respond` 模板。
            </p>
          </div>
          <input
            v-model="pluginInstallUrl"
            type="text"
            class="min-w-[240px] flex-1 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
            placeholder="https://example.com/plugins/gzip-block.zip"
          />
          <button
            @click="handleInstallPlugin"
            class="inline-flex items-center gap-2 rounded-[18px] bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
            :disabled="installingPlugin"
          >
            {{ installingPlugin ? "安装中..." : "安装插件" }}
          </button>
        </div>

        <div v-if="installedPlugins.length" class="mt-4 flex flex-wrap gap-2">
          <span
            v-for="plugin in installedPlugins"
            :key="plugin.plugin_id"
            class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-stone-700"
          >
            {{ plugin.name }} v{{ plugin.version }}
          </span>
        </div>
      </div>

      <div
        class="overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-slate-50 text-sm text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">状态</th>
                <th class="px-4 py-3 font-medium">规则名称</th>
                <th class="px-4 py-3 font-medium">层级</th>
                <th class="px-4 py-3 font-medium">级别</th>
                <th class="px-4 py-3 font-medium">动作</th>
                <th class="px-4 py-3 font-medium">匹配内容</th>
                <th class="px-4 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rule in filteredRules"
                :key="rule.id"
                class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
              >
                <td class="px-4 py-3">
                  <StatusBadge
                    :text="rule.enabled ? '启用' : '停用'"
                    :type="rule.enabled ? 'success' : 'muted'"
                    compact
                  />
                </td>
                <td class="px-4 py-3 font-semibold">{{ rule.name }}</td>
                <td class="px-4 py-3">{{ layerLabel(rule.layer) }}</td>
                <td class="px-4 py-3">{{ severityLabel(rule.severity) }}</td>
                <td class="px-4 py-3">{{ displayActionLabel(rule) }}</td>
                <td
                  class="max-w-[360px] px-4 py-3 font-mono text-xs text-slate-500"
                >
                  {{ rule.pattern }}
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      @click="openEditRule(rule)"
                      class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                    >
                      <Edit3 :size="14" />
                      编辑
                    </button>
                    <button
                      @click="toggleRuleStatus(rule)"
                      class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                    >
                      <Check :size="14" />
                      {{ rule.enabled ? "停用" : "启用" }}
                    </button>
                    <button
                      @click="handleDeleteRule(rule.id)"
                      class="inline-flex items-center gap-1 rounded-full border border-red-500/20 px-3 py-2 text-xs text-red-600 transition hover:bg-red-500/8"
                    >
                      <Trash2 :size="14" />
                      删除
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredRules.length && !loading">
                <td
                  colspan="7"
                  class="px-4 py-6 text-center text-sm text-slate-500"
                >
                  当前还没有可显示的规则。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div
      v-if="isRuleModalOpen"
      class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="isRuleModalOpen = false"
      ></div>
      <div
        class="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-[28px] border border-slate-200 bg-[#fffaf4] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)] md:p-6"
      >
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm tracking-wide text-blue-700">
              {{ ruleForm.id ? "编辑规则" : "新建规则" }}
            </p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">
              {{ ruleForm.id ? "调整现有策略" : "创建新的防护策略" }}
            </h3>
          </div>
          <button
            @click="isRuleModalOpen = false"
            class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
          >
            <X :size="18" />
          </button>
        </div>

        <form @submit.prevent="handleCreateOrUpdateRule" class="mt-3 space-y-6">
          <div class="space-y-2">
            <label class="text-sm text-slate-500">规则名称</label>
            <input
              v-model="ruleForm.name"
              type="text"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              required
            />
          </div>

          <div class="grid gap-4 md:grid-cols-3">
            <div class="space-y-2">
              <label class="text-sm text-slate-500">层级</label>
              <select
                v-model="ruleForm.layer"
                @change="onActionChange"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                :disabled="!!ruleForm.plugin_template_id"
              >
                <option value="l4">四层</option>
                <option value="l7">七层</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-slate-500">级别</label>
              <select
                v-model="ruleForm.severity"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                :disabled="!!ruleForm.plugin_template_id"
              >
                <option value="low">低</option>
                <option value="medium">中</option>
                <option value="high">高</option>
                <option value="critical">紧急</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-slate-500">动作</label>
              <select
                v-model="ruleForm.action"
                @change="onActionChange"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              >
                <option value="block">拦截</option>
                <option value="allow">放行</option>
                <option value="alert">告警</option>
                <option value="respond" :disabled="ruleForm.layer !== 'l7'">
                  自定义响应
                </option>
                <option
                  v-for="template in pluginTemplates"
                  :key="template.template_id"
                  :value="toPluginActionValue(template.template_id)"
                >
                  插件 · {{ template.name }}
                </option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">匹配内容</label>
            <textarea
              v-model="ruleForm.pattern"
              rows="6"
              class="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500"
              required
              :disabled="!!ruleForm.plugin_template_id"
            ></textarea>
          </div>

          <div
            v-if="
              ruleForm.layer === 'l7' &&
              (ruleForm.action === 'respond' || !!ruleForm.plugin_template_id)
            "
            class="space-y-4 rounded-2xl border border-blue-100 bg-blue-50/60 p-4"
          >
            <div>
              <p class="text-sm font-medium text-stone-900">命中后直接回包</p>
              <p class="text-xs text-slate-500">
                <template v-if="selectedPluginTemplate">
                  当前使用插件动作 `{{ selectedPluginTemplate.name }}`，配置已由插件预设。
                </template>
                <template v-else>
                  这里写原始文本内容，服务端会按需压缩并自动补齐
                  `Content-Encoding`。
                </template>
              </p>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div class="space-y-2">
                <label class="text-sm text-slate-500">HTTP 状态码</label>
                <input
                  v-model.number="ruleForm.response_template!.status_code"
                  type="number"
                  min="100"
                  max="599"
                  class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                  :disabled="!!ruleForm.plugin_template_id"
                />
              </div>

              <div class="space-y-2">
                <label class="text-sm text-slate-500">Content-Type</label>
                <input
                  v-model="ruleForm.response_template!.content_type"
                  type="text"
                  class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                  :disabled="!!ruleForm.plugin_template_id"
                />
              </div>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-slate-500">响应体来源</label>
              <select
                v-model="ruleForm.response_template!.body_source"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              >
                <option value="inline_text">直接填写文本</option>
                <option value="file">读取文件</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-slate-500">
                {{
                  ruleForm.response_template!.body_source === "file"
                    ? "文件路径"
                    : "响应内容"
                }}
              </label>
              <input
                v-if="ruleForm.response_template!.body_source === 'file'"
                v-model="ruleForm.response_template!.body_file_path"
                type="text"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
                placeholder="例如 block-page.html 或 pages/block-page.html"
                :disabled="!!ruleForm.plugin_template_id"
              />
              <textarea
                v-else
                v-model="ruleForm.response_template!.body_text"
                rows="8"
                class="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500"
                placeholder="例如返回一段 HTML、JSON 或说明文本"
                :disabled="!!ruleForm.plugin_template_id"
              ></textarea>
            </div>

            <label
              class="flex items-center gap-3 rounded-xl border border-slate-200 bg-white/80 p-4"
            >
              <input
                v-model="ruleForm.response_template!.gzip"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
                :disabled="!!ruleForm.plugin_template_id"
              />
              <span class="text-sm text-stone-800">
                自动 gzip 压缩并添加 `Content-Encoding: gzip`
              </span>
            </label>

            <div class="space-y-3">
              <div class="flex items-center justify-between">
                <label class="text-sm text-slate-500">附加响应头</label>
                <button
                  type="button"
                  @click="addResponseHeader"
                  class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  :disabled="!!ruleForm.plugin_template_id"
                >
                  添加 Header
                </button>
              </div>

              <div
                v-for="(header, index) in ruleForm.response_template!.headers"
                :key="index"
                class="grid gap-3 md:grid-cols-[1fr_1fr_auto]"
              >
                <input
                  v-model="header.key"
                  type="text"
                  class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
                  placeholder="Header 名称"
                  :disabled="!!ruleForm.plugin_template_id"
                />
                <input
                  v-model="header.value"
                  type="text"
                  class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
                  placeholder="Header 值"
                  :disabled="!!ruleForm.plugin_template_id"
                />
                <button
                  type="button"
                  @click="removeResponseHeader(index)"
                  class="rounded-full border border-red-500/20 px-3 py-2 text-xs text-red-600 transition hover:bg-red-500/8"
                  :disabled="!!ruleForm.plugin_template_id"
                >
                  删除
                </button>
              </div>
            </div>
          </div>

          <label
            class="flex items-center gap-3 rounded-xl border border-slate-200 bg-white/70 p-4"
          >
            <input
              v-model="ruleForm.enabled"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
            />
            <span class="text-sm text-stone-800">保存后立即启用这条规则</span>
          </label>

          <button
            type="submit"
            class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-blue-600 px-4 py-3 text-base font-semibold text-white shadow-sm transition hover:-translate-y-0.5 disabled:opacity-60"
            :disabled="saving"
          >
            <Save :size="18" />
            保存规则
          </button>
        </form>
      </div>
    </div>
  </AppLayout>
</template>
