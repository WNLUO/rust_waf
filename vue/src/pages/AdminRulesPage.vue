<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { ArrowRight, PencilLine, RefreshCw, X } from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import {
  fetchActionIdeaPresets,
  fetchL7Config,
  fetchLocalSites,
  fetchRuleActionTemplates,
  updateLocalSite,
} from '../lib/api'
import type {
  ActionIdeaPreset,
  L7ConfigPayload,
  LocalSiteDraft,
  LocalSiteItem,
  RuleActionTemplateItem,
  SafeLineInterceptConfigPayload,
} from '../lib/types'
import { useFormatters } from '../composables/useFormatters'

type PolicyMode =
  | 'inherit'
  | 'disabled'
  | 'pass'
  | 'drop'
  | 'global_replace'
  | 'global_block'
  | 'template_replace'
  | 'template_block'
  | 'legacy_replace'
  | 'legacy_block'

const route = useRoute()
const router = useRouter()
const { formatTimestamp } = useFormatters()

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const siteKeyword = ref('')
const localSites = ref<LocalSiteItem[]>([])
const actionTemplates = ref<RuleActionTemplateItem[]>([])
const actionIdeaPresets = ref<ActionIdeaPreset[]>([])
const l7Config = ref<L7ConfigPayload | null>(null)
const editingSite = ref<LocalSiteItem | null>(null)
const isEditorOpen = ref(false)

const policyForm = reactive<{
  mode: PolicyMode
  templateId: string
}>({
  mode: 'inherit',
  templateId: '',
})

const isInlineJsIdea = (idea: ActionIdeaPreset) => idea.id === 'inline-js'

const wrapInlineJsContent = (script: string, title: string) => `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title || '内嵌JS动作'}</title>
  <style>
    body { font-family: sans-serif; background: #f8fafc; color: #0f172a; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { background: white; border-radius: 20px; padding: 32px; box-shadow: 0 20px 60px rgba(15, 23, 42, 0.12); max-width: 560px; }
  </style>
</head>
<body>
  <main class="card">
    <h1>请求已被动作页面接管</h1>
    <p id="message">页面已正常返回，内嵌脚本会在这里执行。</p>
  </main>
  <script>
${script}
  <\/script>
</body>
</html>`

function cloneHeaders(headers: { key: string; value: string }[]) {
  return headers.map((header) => ({ ...header }))
}

function cloneResponseTemplate(
  template: SafeLineInterceptConfigPayload['response_template'],
) {
  return {
    ...template,
    headers: cloneHeaders(template.headers),
  }
}

function cloneSafelineIntercept(
  value: SafeLineInterceptConfigPayload | null | undefined,
): SafeLineInterceptConfigPayload | null {
  if (!value) return null
  return {
    ...value,
    response_template: cloneResponseTemplate(value.response_template),
  }
}

function siteDraftFromItem(site: LocalSiteItem): LocalSiteDraft {
  return {
    name: site.name,
    primary_hostname: site.primary_hostname,
    hostnames: [...site.hostnames],
    listen_ports: [...site.listen_ports],
    upstreams: [...site.upstreams],
    safeline_intercept: cloneSafelineIntercept(site.safeline_intercept),
    enabled: site.enabled,
    tls_enabled: site.tls_enabled,
    local_certificate_id: site.local_certificate_id,
    source: site.source,
    sync_mode: site.sync_mode,
    notes: site.notes,
    last_synced_at: site.last_synced_at,
  }
}

function normalizeTemplateHeaders(headers: { key: string; value: string }[]) {
  return headers
    .map((item) => ({
      key: item.key.trim().toLowerCase(),
      value: item.value.trim(),
    }))
    .filter((item) => item.key)
    .sort((left, right) =>
      `${left.key}:${left.value}`.localeCompare(`${right.key}:${right.value}`),
    )
}

function sameResponseTemplate(
  left: SafeLineInterceptConfigPayload['response_template'] | null | undefined,
  right: SafeLineInterceptConfigPayload['response_template'] | null | undefined,
) {
  if (!left || !right) return false
  return (
    left.status_code === right.status_code &&
    left.content_type === right.content_type &&
    left.body_source === right.body_source &&
    left.gzip === right.gzip &&
    left.body_text === right.body_text &&
    left.body_file_path === right.body_file_path &&
    JSON.stringify(normalizeTemplateHeaders(left.headers)) ===
      JSON.stringify(normalizeTemplateHeaders(right.headers))
  )
}

const enabledActionTemplates = computed(() =>
  [
    ...actionTemplates.value,
    ...actionIdeaPresets.value
      .filter((idea) => !idea.requires_upload || idea.uploaded_file_ready)
      .map((idea) => ({
      template_id: `${idea.plugin_id}:${idea.template_local_id}`,
      plugin_id: idea.plugin_id,
      name: idea.title,
      description: `${idea.template_description}${
        idea.has_overrides ? '（含已保存自定义内容）' : '（系统内置方案）'
      }`,
      layer: 'l7',
      action: 'respond',
      pattern: idea.pattern,
      severity: idea.severity,
      response_template: {
        status_code: idea.status_code,
        content_type: idea.content_type,
        body_source: idea.body_source,
        gzip: idea.gzip,
        body_text:
          idea.body_source === 'inline_text'
            ? isInlineJsIdea(idea)
              ? wrapInlineJsContent(idea.response_content, idea.title)
              : idea.response_content
            : '',
        body_file_path: idea.body_source === 'file' ? idea.runtime_body_file_path : '',
        headers: idea.headers,
      },
      updated_at: idea.updated_at,
    })),
  ].filter((item) => item.layer === 'l7'),
)

const pendingTemplate = computed(() => {
  const templateId =
    typeof route.query.template === 'string' ? route.query.template : ''
  return (
    enabledActionTemplates.value.find((item) => item.template_id === templateId) ??
    null
  )
})

function actionLabelForConfig(config: SafeLineInterceptConfigPayload | null) {
  if (!config) return '继承全局'
  if (!config.enabled) return '本站不接管'
  switch (config.action) {
    case 'pass':
      return '透传雷池原始响应'
    case 'drop':
      return '直接丢弃响应'
    case 'replace':
      return '替换为自定义动作'
    case 'replace_and_block_ip':
      return '替换并封禁来源 IP'
    default:
      return config.action
  }
}

function matchedTemplateForSite(site: LocalSiteItem) {
  const config = site.safeline_intercept
  if (!config?.enabled) return null
  return (
    enabledActionTemplates.value.find((template) =>
      sameResponseTemplate(template.response_template, config.response_template),
    ) ?? null
  )
}

function templateLabelForSite(site: LocalSiteItem) {
  const config = site.safeline_intercept
  if (!config?.enabled) return '-'
  if (config.action !== 'replace' && config.action !== 'replace_and_block_ip') {
    return '-'
  }
  if (
    l7Config.value &&
    sameResponseTemplate(
      config.response_template,
      l7Config.value.safeline_intercept.response_template,
    )
  ) {
    return '全局默认拦截页'
  }
  return matchedTemplateForSite(site)?.name ?? '历史自定义动作'
}

const filteredSites = computed(() => {
  const keyword = siteKeyword.value.trim().toLowerCase()
  return localSites.value
    .filter((site) => {
      if (!keyword) return true
      return [
        site.name,
        site.primary_hostname,
        site.hostnames.join(' '),
        site.notes,
        actionLabelForConfig(site.safeline_intercept),
        templateLabelForSite(site),
      ]
        .join(' ')
        .toLowerCase()
        .includes(keyword)
    })
    .sort((left, right) =>
      left.primary_hostname.localeCompare(right.primary_hostname, 'zh-CN'),
    )
})

function clearFeedback() {
  error.value = ''
  successMessage.value = ''
}

async function loadRulesCenter() {
  loading.value = true
  clearFeedback()
  try {
    const [sitesResponse, templatesResponse, l7Response, ideasResponse] = await Promise.all([
      fetchLocalSites(),
      fetchRuleActionTemplates(),
      fetchL7Config(),
      fetchActionIdeaPresets(),
    ])
    localSites.value = sitesResponse.sites
    actionTemplates.value = templatesResponse.templates
    actionIdeaPresets.value = ideasResponse.ideas
    l7Config.value = l7Response
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取规则中心失败'
  } finally {
    loading.value = false
  }
}

function resetEditorFromSite(site: LocalSiteItem) {
  const config = cloneSafelineIntercept(site.safeline_intercept)
  const matchedTemplate =
    enabledActionTemplates.value.find((template) =>
      sameResponseTemplate(template.response_template, config?.response_template),
    ) ?? null

  policyForm.templateId = matchedTemplate?.template_id ?? ''

  if (!config) {
    policyForm.mode = pendingTemplate.value ? 'template_replace' : 'inherit'
    if (pendingTemplate.value) {
      policyForm.templateId = pendingTemplate.value.template_id
    }
    return
  }

  if (!config.enabled) {
    policyForm.mode = 'disabled'
    return
  }

  if (config.action === 'pass') {
    policyForm.mode = 'pass'
    return
  }

  if (config.action === 'drop') {
    policyForm.mode = 'drop'
    return
  }

  const sameAsGlobal =
    l7Config.value &&
    sameResponseTemplate(
      config.response_template,
      l7Config.value.safeline_intercept.response_template,
    )

  if (config.action === 'replace') {
    if (sameAsGlobal) {
      policyForm.mode = 'global_replace'
    } else if (matchedTemplate) {
      policyForm.mode = 'template_replace'
    } else {
      policyForm.mode = 'legacy_replace'
    }
    return
  }

  if (config.action === 'replace_and_block_ip') {
    if (sameAsGlobal) {
      policyForm.mode = 'global_block'
    } else if (matchedTemplate) {
      policyForm.mode = 'template_block'
    } else {
      policyForm.mode = 'legacy_block'
    }
    return
  }

  policyForm.mode = 'inherit'
}

async function clearPendingTemplateQuery() {
  if (typeof route.query.template !== 'string') return
  const nextQuery = { ...route.query }
  delete nextQuery.template
  await router.replace({ query: nextQuery })
}

async function openPolicyEditor(site: LocalSiteItem) {
  editingSite.value = site
  resetEditorFromSite(site)
  isEditorOpen.value = true
  if (pendingTemplate.value) {
    await clearPendingTemplateQuery()
  }
}

function closePolicyEditor() {
  isEditorOpen.value = false
  editingSite.value = null
  policyForm.mode = 'inherit'
  policyForm.templateId = ''
}

const selectedTemplate = computed(() =>
  enabledActionTemplates.value.find(
    (item) => item.template_id === policyForm.templateId,
  ) ?? null,
)

const canSavePolicy = computed(() => {
  if (!editingSite.value || !l7Config.value) return false
  if (policyForm.mode === 'legacy_replace' || policyForm.mode === 'legacy_block') {
    return false
  }
  if (
    (policyForm.mode === 'template_replace' ||
      policyForm.mode === 'template_block') &&
    !selectedTemplate.value
  ) {
    return false
  }
  return true
})

function buildInterceptOverride(): SafeLineInterceptConfigPayload | null {
  if (!l7Config.value) return null
  const base = cloneSafelineIntercept(l7Config.value.safeline_intercept)
  if (!base) return null

  switch (policyForm.mode) {
    case 'inherit':
      return null
    case 'disabled':
      return {
        ...base,
        enabled: false,
      }
    case 'pass':
      return {
        ...base,
        enabled: true,
        action: 'pass',
      }
    case 'drop':
      return {
        ...base,
        enabled: true,
        action: 'drop',
      }
    case 'global_replace':
      return {
        ...base,
        enabled: true,
        action: 'replace',
        response_template: cloneResponseTemplate(base.response_template),
      }
    case 'global_block':
      return {
        ...base,
        enabled: true,
        action: 'replace_and_block_ip',
        response_template: cloneResponseTemplate(base.response_template),
      }
    case 'template_replace':
      return selectedTemplate.value
        ? {
            ...base,
            enabled: true,
            action: 'replace',
            response_template: cloneResponseTemplate(
              selectedTemplate.value.response_template,
            ),
          }
        : null
    case 'template_block':
      return selectedTemplate.value
        ? {
            ...base,
            enabled: true,
            action: 'replace_and_block_ip',
            response_template: cloneResponseTemplate(
              selectedTemplate.value.response_template,
            ),
          }
        : null
    default:
      return null
  }
}

async function savePolicy() {
  if (!editingSite.value || !canSavePolicy.value) return
  saving.value = true
  clearFeedback()
  try {
    const payload = siteDraftFromItem(editingSite.value)
    payload.safeline_intercept = buildInterceptOverride()
    await updateLocalSite(editingSite.value.id, payload)
    successMessage.value = `站点 ${editingSite.value.name} 的雷池接管策略已更新。`
    closePolicyEditor()
    await loadRulesCenter()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存站点策略失败'
  } finally {
    saving.value = false
  }
}

onMounted(loadRulesCenter)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-2">
        <RouterLink
          to="/admin/actions"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
        >
          动作中心
          <ArrowRight :size="14" />
        </RouterLink>
        <button
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          :disabled="loading"
          @click="loadRulesCenter"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': loading }" />
          刷新规则中心
        </button>
      </div>
    </template>

    <div class="space-y-6">
      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-xl border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div
        v-if="pendingTemplate"
        class="rounded-2xl border border-blue-200 bg-blue-50 px-4 py-4 text-sm text-blue-900"
      >
        已从动作中心带入模板
        <span class="font-semibold">{{ pendingTemplate.name }}</span>
        。现在选择一个站点，点击“配置动作”即可直接套用。
      </div>

      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <label
          class="flex min-w-[240px] flex-1 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500"
        >
          <input
            v-model="siteKeyword"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索站点名 / 域名 / 当前动作"
          />
        </label>
        <RouterLink
          to="/admin/sites"
          class="ml-auto inline-flex items-center gap-2 rounded-[18px] bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-600/90"
        >
          去站点管理
        </RouterLink>
      </div>

      <div
        class="overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-slate-50 text-sm text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">站点</th>
                <th class="px-4 py-3 font-medium">检测来源</th>
                <th class="px-4 py-3 font-medium">当前动作</th>
                <th class="px-4 py-3 font-medium">动作模板</th>
                <th class="px-4 py-3 font-medium">覆盖状态</th>
                <th class="px-4 py-3 font-medium">更新时间</th>
                <th class="px-4 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="site in filteredSites"
                :key="site.id"
                class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
              >
                <td class="px-4 py-3">
                  <div class="min-w-[240px]">
                    <p class="font-semibold text-stone-900">{{ site.name }}</p>
                    <p class="mt-1 font-mono text-xs text-slate-500">
                      {{ site.primary_hostname }}
                    </p>
                  </div>
                </td>
                <td class="px-4 py-3">雷池拦截响应</td>
                <td class="px-4 py-3">
                  {{ actionLabelForConfig(site.safeline_intercept) }}
                </td>
                <td class="px-4 py-3">
                  <span class="text-slate-600">{{
                    templateLabelForSite(site)
                  }}</span>
                </td>
                <td class="px-4 py-3">
                  <StatusBadge
                    :text="
                      site.safeline_intercept ? '站点级覆盖' : '继承全局默认'
                    "
                    :type="site.safeline_intercept ? 'info' : 'muted'"
                    compact
                  />
                </td>
                <td class="px-4 py-3">
                  <span class="font-mono text-xs text-slate-500">
                    {{ formatTimestamp(site.updated_at) }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                      @click="openPolicyEditor(site)"
                    >
                      <PencilLine :size="14" />
                      配置动作
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredSites.length && !loading">
                <td
                  colspan="7"
                  class="px-4 py-6 text-center text-sm text-slate-500"
                >
                  当前没有可配置的站点，或者搜索结果为空。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div
      v-if="isEditorOpen && editingSite"
      class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closePolicyEditor"
      ></div>
      <div
        class="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-[28px] border border-slate-200 bg-[#fffaf4] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)] md:p-6"
      >
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm tracking-wide text-blue-700">简化规则配置</p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">
              {{ editingSite.name }}
            </h3>
            <p class="mt-2 text-sm text-slate-500">
              语义固定为：
              <span class="font-medium text-stone-900">
                当 {{ editingSite.primary_hostname }} 被雷池判定拦截后
              </span>
              ，rust 执行下面这个动作。
            </p>
          </div>
          <button
            class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePolicyEditor"
          >
            <X :size="18" />
          </button>
        </div>

        <div class="mt-6 space-y-5">
          <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
            <p class="text-sm font-medium text-stone-900">动作类型</p>
            <p class="mt-1 text-xs leading-6 text-slate-500">
              这里不再手工填写拦截页内容。需要页面或 JSON 响应时，请先去动作中心准备模板，再回来绑定到站点。
            </p>

            <select
              v-model="policyForm.mode"
              class="mt-3 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="inherit">继承全局默认接管策略</option>
              <option value="disabled">本站点不接管雷池拦截</option>
              <option value="pass">透传雷池原始响应</option>
              <option value="drop">直接丢弃响应</option>
              <option value="global_replace">使用全局默认拦截页</option>
              <option value="global_block">使用全局默认拦截页并封禁来源 IP</option>
              <option value="template_replace">使用动作中心模板</option>
              <option value="template_block">使用动作中心模板并封禁来源 IP</option>
              <option
                v-if="policyForm.mode === 'legacy_replace'"
                value="legacy_replace"
              >
                历史自定义动作（需切换为模板）
              </option>
              <option
                v-if="policyForm.mode === 'legacy_block'"
                value="legacy_block"
              >
                历史自定义动作并封禁 IP（需切换为模板）
              </option>
            </select>
          </div>

          <div
            v-if="
              policyForm.mode === 'template_replace' ||
              policyForm.mode === 'template_block' ||
              policyForm.mode === 'legacy_replace' ||
              policyForm.mode === 'legacy_block'
            "
            class="rounded-2xl border border-slate-200 bg-slate-50 p-4"
          >
            <div
              class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
            >
              <div>
                <p class="text-sm font-medium text-stone-900">动作模板</p>
                <p class="mt-1 text-xs leading-6 text-slate-500">
                  模板来自动作中心，通常由插件提供，也可以复用已经安装好的响应页动作。
                </p>
              </div>
              <RouterLink
                to="/admin/actions"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                去动作中心
                <ArrowRight :size="14" />
              </RouterLink>
            </div>

            <div
              v-if="
                policyForm.mode === 'legacy_replace' ||
                policyForm.mode === 'legacy_block'
              "
              class="mt-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
            >
              当前站点使用的是旧的自定义响应内容，已经不在简化规则中心里直接编辑了。请选择“全局默认拦截页”或动作中心里的模板后再保存。
            </div>

            <select
              v-model="policyForm.templateId"
              class="mt-3 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="">请选择动作模板</option>
              <option
                v-for="template in enabledActionTemplates"
                :key="template.template_id"
                :value="template.template_id"
              >
                {{ template.name }} · {{ template.response_template.content_type }}
              </option>
            </select>

            <div
              v-if="selectedTemplate"
              class="mt-3 rounded-xl border border-slate-200 bg-white px-4 py-4"
            >
              <div class="flex flex-wrap gap-2">
                <StatusBadge
                  :text="selectedTemplate.layer.toUpperCase()"
                  type="info"
                  compact
                />
                <StatusBadge
                  :text="`HTTP ${selectedTemplate.response_template.status_code}`"
                  type="muted"
                  compact
                />
                <StatusBadge
                  :text="
                    selectedTemplate.response_template.gzip ? 'gzip 开' : 'gzip 关'
                  "
                  type="muted"
                  compact
                />
              </div>
              <p class="mt-3 text-sm font-medium text-stone-900">
                {{ selectedTemplate.name }}
              </p>
              <p class="mt-1 text-sm leading-6 text-slate-500">
                {{
                  selectedTemplate.description ||
                  '这个动作模板会作为雷池拦截后的替换响应。'
                }}
              </p>
              <p class="mt-2 font-mono text-xs text-slate-500">
                {{ selectedTemplate.response_template.content_type }}
              </p>
            </div>
          </div>

          <div class="flex flex-wrap items-center gap-2">
            <button
              :disabled="!canSavePolicy || saving"
              class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
              @click="savePolicy"
            >
              {{ saving ? '保存中...' : '保存站点动作' }}
            </button>
            <button
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="closePolicyEditor"
            >
              取消
            </button>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
