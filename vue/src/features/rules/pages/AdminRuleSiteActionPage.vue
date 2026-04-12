<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import AppLayout from '@/app/layout/AppLayout.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  fetchActionIdeaPresets,
  fetchRuleActionTemplatePreview,
  fetchRuleActionTemplates,
} from '@/shared/api/rules'
import { fetchL7Config } from '@/shared/api/l7'
import { fetchLocalSites, updateLocalSite } from '@/shared/api/sites'
import type {
  ActionIdeaPreset,
  L7ConfigPayload,
  LocalSiteDraft,
  LocalSiteItem,
  RuleActionTemplateItem,
  SafeLineInterceptConfigPayload,
} from '@/shared/types'
import { useFlashMessages } from '@/shared/composables/useNotifications'

type ResponseMode =
  | 'inherit'
  | 'disabled'
  | 'pass'
  | 'drop'
  | 'global_template'
  | 'template'
  | 'legacy'

const route = useRoute()

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const site = ref<LocalSiteItem | null>(null)
const l7Config = ref<L7ConfigPayload | null>(null)
const actionTemplates = ref<RuleActionTemplateItem[]>([])
const actionIdeaPresets = ref<ActionIdeaPreset[]>([])
const previewLoading = ref(false)
const previewError = ref('')
const previewBody = ref('')
const previewMeta = ref<{
  statusCode: number
  contentType: string
  truncated: boolean
} | null>(null)

const flowDraft = reactive<{
  responseMode: ResponseMode
  templateId: string
  blockIp: boolean
}>({
  responseMode: 'inherit',
  templateId: '',
  blockIp: false,
})

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '站点动作',
  successTitle: '站点动作',
  errorDuration: 5600,
  successDuration: 3200,
})

const siteId = computed(() => Number(route.params.id))

const isInlineJsIdea = (idea: ActionIdeaPreset) => idea.id === 'inline-js'

const wrapInlineJsContent = (script: string, title: string) => `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title || '内嵌JS动作'}</title>
</head>
<body>
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

function siteDraftFromItem(item: LocalSiteItem): LocalSiteDraft {
  return {
    name: item.name,
    primary_hostname: item.primary_hostname,
    hostnames: [...item.hostnames],
    listen_ports: [...item.listen_ports],
    upstreams: [...item.upstreams],
    safeline_intercept: cloneSafelineIntercept(item.safeline_intercept),
    enabled: item.enabled,
    tls_enabled: item.tls_enabled,
    local_certificate_id: item.local_certificate_id,
    source: item.source,
    sync_mode: item.sync_mode,
    notes: item.notes,
    last_synced_at: item.last_synced_at,
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
        description: idea.template_description,
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
          body_file_path:
            idea.body_source === 'file' ? idea.runtime_body_file_path : '',
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

const selectedTemplate = computed(() =>
  enabledActionTemplates.value.find(
    (item) => item.template_id === flowDraft.templateId,
  ) ?? null,
)

const persistedTemplateIds = computed(
  () => new Set(actionTemplates.value.map((item) => item.template_id)),
)

const matchedTemplate = computed(() => {
  const config = site.value?.safeline_intercept
  if (!config?.enabled) return null
  return (
    enabledActionTemplates.value.find((template) =>
      sameResponseTemplate(template.response_template, config.response_template),
    ) ?? null
  )
})

const currentSummary = computed(() => {
  const config = site.value?.safeline_intercept
  if (!config) return '继承全局'
  if (!config.enabled) return '不接管'
  if (config.action === 'pass') return '透传原始响应'
  if (config.action === 'drop') return '直接丢弃'
  if (
    l7Config.value &&
    sameResponseTemplate(
      config.response_template,
      l7Config.value.safeline_intercept.response_template,
    )
  ) {
    return config.action === 'replace_and_block_ip'
      ? '全局默认页面 + 封禁 IP'
      : '全局默认页面'
  }
  return matchedTemplate.value
    ? `${matchedTemplate.value.name}${
        config.action === 'replace_and_block_ip' ? ' + 封禁 IP' : ''
      }`
    : '历史自定义动作'
})

const pendingSummary = computed(() => {
  switch (flowDraft.responseMode) {
    case 'inherit':
      return '继承全局'
    case 'disabled':
      return '不接管'
    case 'pass':
      return '透传原始响应'
    case 'drop':
      return '直接丢弃'
    case 'global_template':
      return flowDraft.blockIp ? '全局默认页面 + 封禁 IP' : '全局默认页面'
    case 'template':
      return selectedTemplate.value
        ? `${selectedTemplate.value.name}${flowDraft.blockIp ? ' + 封禁 IP' : ''}`
        : '请选择模板'
    default:
      return '请切换为新方案'
  }
})

const responseOptions = [
  { id: 'inherit', label: '继承全局' },
  { id: 'disabled', label: '不接管' },
  { id: 'pass', label: '透传原始响应' },
  { id: 'drop', label: '直接丢弃' },
  { id: 'global_template', label: '全局默认页面' },
  { id: 'template', label: '站点模板' },
]

function resetDraft() {
  const config = cloneSafelineIntercept(site.value?.safeline_intercept)
  previewBody.value = ''
  previewMeta.value = null
  previewError.value = ''

  if (!config) {
    flowDraft.responseMode = pendingTemplate.value ? 'template' : 'inherit'
    flowDraft.templateId = pendingTemplate.value?.template_id ?? ''
    flowDraft.blockIp = false
    return
  }

  flowDraft.blockIp = config.action === 'replace_and_block_ip'

  if (!config.enabled) {
    flowDraft.responseMode = 'disabled'
    flowDraft.templateId = ''
    return
  }
  if (config.action === 'pass') {
    flowDraft.responseMode = 'pass'
    flowDraft.templateId = ''
    return
  }
  if (config.action === 'drop') {
    flowDraft.responseMode = 'drop'
    flowDraft.templateId = ''
    return
  }
  if (config.action === 'replace' || config.action === 'replace_and_block_ip') {
    const sameAsGlobal =
      l7Config.value &&
      sameResponseTemplate(
        config.response_template,
        l7Config.value.safeline_intercept.response_template,
      )
    if (sameAsGlobal) {
      flowDraft.responseMode = 'global_template'
      flowDraft.templateId = ''
      return
    }
    if (matchedTemplate.value) {
      flowDraft.responseMode = 'template'
      flowDraft.templateId = matchedTemplate.value.template_id
      return
    }
    flowDraft.responseMode = 'legacy'
    flowDraft.templateId = ''
    return
  }

  flowDraft.responseMode = 'inherit'
  flowDraft.templateId = ''
  flowDraft.blockIp = false
}

const pendingPayload = computed(() => {
  if (!l7Config.value) return null
  const base = cloneSafelineIntercept(l7Config.value.safeline_intercept)
  if (!base) return null
  switch (flowDraft.responseMode) {
    case 'inherit':
      return null
    case 'disabled':
      return { ...base, enabled: false }
    case 'pass':
      return { ...base, enabled: true, action: 'pass' }
    case 'drop':
      return { ...base, enabled: true, action: 'drop' }
    case 'global_template':
      return {
        ...base,
        enabled: true,
        action: flowDraft.blockIp ? 'replace_and_block_ip' : 'replace',
        response_template: cloneResponseTemplate(base.response_template),
      }
    case 'template':
      return selectedTemplate.value
        ? {
            ...base,
            enabled: true,
            action: flowDraft.blockIp ? 'replace_and_block_ip' : 'replace',
            response_template: cloneResponseTemplate(
              selectedTemplate.value.response_template,
            ),
          }
        : null
    default:
      return null
  }
})

const canSave = computed(() => {
  if (!site.value || !l7Config.value) return false
  if (flowDraft.responseMode === 'legacy') return false
  if (flowDraft.responseMode === 'template' && !selectedTemplate.value) return false
  return true
})

async function loadPreview() {
  if (!selectedTemplate.value) {
    previewBody.value = ''
    previewMeta.value = null
    previewError.value = ''
    return
  }

  if (!persistedTemplateIds.value.has(selectedTemplate.value.template_id)) {
    previewBody.value =
      selectedTemplate.value.response_template.body_source === 'inline_text'
        ? selectedTemplate.value.response_template.body_text
        : selectedTemplate.value.response_template.body_file_path ||
          '文件型模板，当前页只显示文件路径。'
    previewMeta.value = {
      statusCode: selectedTemplate.value.response_template.status_code,
      contentType: selectedTemplate.value.response_template.content_type,
      truncated: false,
    }
    previewError.value = ''
    return
  }

  previewLoading.value = true
  previewError.value = ''
  try {
    const payload = await fetchRuleActionTemplatePreview(
      selectedTemplate.value.template_id,
    )
    previewBody.value = payload.body_preview
    previewMeta.value = {
      statusCode: payload.status_code,
      contentType: payload.content_type,
      truncated: payload.truncated,
    }
  } catch (e) {
    previewError.value = e instanceof Error ? e.message : '读取模板预览失败'
  } finally {
    previewLoading.value = false
  }
}

async function loadPage() {
  loading.value = true
  error.value = ''
  try {
    const [sitesResponse, templatesResponse, l7Response, ideasResponse] =
      await Promise.all([
        fetchLocalSites(),
        fetchRuleActionTemplates(),
        fetchL7Config(),
        fetchActionIdeaPresets(),
      ])
    actionTemplates.value = templatesResponse.templates
    actionIdeaPresets.value = ideasResponse.ideas
    l7Config.value = l7Response
    site.value =
      sitesResponse.sites.find((item) => item.id === siteId.value) ?? null
    if (!site.value) {
      throw new Error(`站点 ${siteId.value} 不存在`)
    }
    resetDraft()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取站点动作配置失败'
  } finally {
    loading.value = false
  }
}

async function savePolicy() {
  if (!site.value || !canSave.value) return
  saving.value = true
  error.value = ''
  try {
    const draft = siteDraftFromItem(site.value)
    draft.safeline_intercept = cloneSafelineIntercept(pendingPayload.value)
    await updateLocalSite(site.value.id, draft)
    successMessage.value = `站点 ${site.value.name} 的动作已更新。`
    await loadPage()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存站点动作失败'
  } finally {
    saving.value = false
  }
}

watch(
  () => flowDraft.templateId,
  () => {
    if (flowDraft.responseMode === 'template') {
      void loadPreview()
    }
  },
)

onMounted(loadPage)
</script>

<template>
  <AppLayout>
    <div class="space-y-6">
      <div class="flex items-center justify-between gap-3">
        <div>
          <RouterLink
            to="/admin/rules"
            class="text-sm text-slate-500 transition hover:text-slate-900"
          >
            规则中心
          </RouterLink>
          <h1 class="mt-2 text-2xl font-semibold text-slate-900">
            {{ site?.name || '站点动作' }}
          </h1>
          <p class="mt-1 font-mono text-sm text-slate-500">
            {{ site?.primary_hostname || '' }}
          </p>
        </div>
        <div class="flex gap-2">
          <StatusBadge :text="`当前: ${currentSummary}`" type="muted" />
          <StatusBadge :text="`待保存: ${pendingSummary}`" type="info" />
        </div>
      </div>

      <div
        class="rounded-xl border border-slate-200 bg-white p-5"
        v-if="!loading && site"
      >
        <div class="overflow-x-auto">
          <div class="min-w-[760px]">
            <div class="grid grid-cols-[1fr_48px_1fr_48px_1fr_48px_1fr] items-center gap-2">
              <div class="rounded-lg border border-slate-300 bg-slate-50 px-4 py-4 text-center text-sm text-slate-700">
                请求命中站点
              </div>
              <div class="text-center text-slate-300">→</div>
              <div class="rounded-lg border border-slate-300 bg-slate-50 px-4 py-4 text-center text-sm text-slate-700">
                雷池拦截判定
              </div>
              <div class="text-center text-slate-300">→</div>
              <div class="rounded-lg border border-blue-300 bg-blue-50 px-4 py-4 text-center text-sm font-medium text-blue-700">
                响应动作
              </div>
              <div class="text-center text-slate-300">→</div>
              <div class="rounded-lg border border-amber-300 bg-amber-50 px-4 py-4 text-center text-sm font-medium text-amber-700">
                附加动作
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="!loading && site" class="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <section class="rounded-xl border border-slate-200 bg-white p-5">
          <h2 class="text-base font-semibold text-slate-900">响应动作</h2>
          <div class="mt-4 grid gap-3 sm:grid-cols-2">
            <button
              v-for="option in responseOptions"
              :key="option.id"
              class="rounded-lg border px-4 py-3 text-left text-sm transition"
              :class="
                flowDraft.responseMode === option.id
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'
              "
              @click="flowDraft.responseMode = option.id as ResponseMode"
            >
              {{ option.label }}
            </button>
          </div>

          <div
            v-if="flowDraft.responseMode === 'legacy'"
            class="mt-4 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
          >
            当前是历史自定义动作，请改成全局默认页面或站点模板后再保存。
          </div>

          <div
            v-if="flowDraft.responseMode === 'template'"
            class="mt-5 space-y-3"
          >
            <h3 class="text-sm font-medium text-slate-900">模板</h3>
            <div class="grid gap-3 max-h-[24rem] overflow-y-auto pr-1">
              <button
                v-for="template in enabledActionTemplates"
                :key="template.template_id"
                class="rounded-lg border px-4 py-3 text-left transition"
                :class="
                  flowDraft.templateId === template.template_id
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-slate-200 bg-white hover:border-slate-300'
                "
                @click="flowDraft.templateId = template.template_id"
              >
                <div class="flex items-center justify-between gap-3">
                  <span class="font-medium text-slate-900">{{ template.name }}</span>
                  <span class="text-xs text-slate-500">
                    HTTP {{ template.response_template.status_code }}
                  </span>
                </div>
              </button>
            </div>
          </div>
        </section>

        <section class="space-y-6">
          <div class="rounded-xl border border-slate-200 bg-white p-5">
            <h2 class="text-base font-semibold text-slate-900">附加动作</h2>
            <button
              class="mt-4 w-full rounded-lg border px-4 py-3 text-left text-sm transition"
              :class="
                flowDraft.blockIp
                  ? 'border-amber-400 bg-amber-50 text-amber-800'
                  : 'border-slate-200 bg-white text-slate-700 hover:border-slate-300'
              "
              @click="flowDraft.blockIp = !flowDraft.blockIp"
            >
              封禁来源 IP
            </button>
          </div>

          <div
            v-if="flowDraft.responseMode === 'template'"
            class="rounded-xl border border-slate-200 bg-white p-5"
          >
            <h2 class="text-base font-semibold text-slate-900">模板预览</h2>
            <p v-if="previewLoading" class="mt-4 text-sm text-slate-500">
              正在读取预览...
            </p>
            <p v-else-if="previewError" class="mt-4 text-sm text-red-600">
              {{ previewError }}
            </p>
            <div v-else-if="previewMeta" class="mt-4 space-y-3">
              <div class="flex gap-2">
                <StatusBadge :text="`HTTP ${previewMeta.statusCode}`" type="muted" compact />
                <StatusBadge :text="previewMeta.contentType" type="info" compact />
              </div>
              <pre class="overflow-auto rounded-lg bg-slate-50 p-4 text-xs text-slate-700 whitespace-pre-wrap">{{ previewBody }}</pre>
            </div>
            <p v-else class="mt-4 text-sm text-slate-500">请选择模板。</p>
          </div>

          <div class="rounded-xl border border-slate-200 bg-white p-5">
            <h2 class="text-base font-semibold text-slate-900">保存</h2>
            <p class="mt-3 text-sm text-slate-600">{{ pendingSummary }}</p>
            <div class="mt-4 flex gap-3">
              <button
                :disabled="!canSave || saving"
                class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                @click="savePolicy"
              >
                {{ saving ? '保存中...' : '保存' }}
              </button>
              <RouterLink
                to="/admin/rules"
                class="rounded-lg border border-slate-200 px-4 py-2 text-sm text-slate-700 transition hover:border-slate-300"
              >
                返回
              </RouterLink>
            </div>
          </div>
        </section>
      </div>
    </div>
  </AppLayout>
</template>
