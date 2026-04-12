<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { ArrowRight, PencilLine, RefreshCw } from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import AdminSiteActionFlowDialog from '../components/rules/AdminSiteActionFlowDialog.vue'
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
import { useFlashMessages } from '../composables/useNotifications'

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

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '规则中心',
  successTitle: '规则中心',
  errorDuration: 5600,
  successDuration: 3200,
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

async function clearPendingTemplateQuery() {
  if (typeof route.query.template !== 'string') return
  const nextQuery = { ...route.query }
  delete nextQuery.template
  await router.replace({ query: nextQuery })
}

async function openPolicyEditor(site: LocalSiteItem) {
  editingSite.value = site
  isEditorOpen.value = true
  if (pendingTemplate.value) {
    await clearPendingTemplateQuery()
  }
}

function closePolicyEditor() {
  isEditorOpen.value = false
  editingSite.value = null
}

async function savePolicy(payload: SafeLineInterceptConfigPayload | null) {
  if (!editingSite.value) return
  saving.value = true
  clearFeedback()
  try {
    const draft = siteDraftFromItem(editingSite.value)
    draft.safeline_intercept = cloneSafelineIntercept(payload)
    await updateLocalSite(editingSite.value.id, draft)
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

    <AdminSiteActionFlowDialog
      :open="isEditorOpen"
      :site="editingSite"
      :l7-config="l7Config"
      :templates="enabledActionTemplates"
      :pending-template="pendingTemplate"
      :saving="saving"
      @close="closePolicyEditor"
      @save="savePolicy"
    />
  </AppLayout>
</template>
