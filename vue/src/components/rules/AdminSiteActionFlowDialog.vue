<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight, Eye, Network, Shield, ShieldBan, X, Zap } from 'lucide-vue-next'
import StatusBadge from '../ui/StatusBadge.vue'
import { fetchRuleActionTemplatePreview } from '../../lib/api'
import type {
  L7ConfigPayload,
  LocalSiteItem,
  RuleActionTemplateItem,
  SafeLineInterceptConfigPayload,
} from '../../lib/types'

type ResponseMode =
  | 'inherit'
  | 'disabled'
  | 'pass'
  | 'drop'
  | 'global_template'
  | 'template'
  | 'legacy'

const props = defineProps<{
  open: boolean
  site: LocalSiteItem | null
  l7Config: L7ConfigPayload | null
  templates: RuleActionTemplateItem[]
  pendingTemplate?: RuleActionTemplateItem | null
  saving?: boolean
}>()

const emit = defineEmits<{
  close: []
  save: [payload: SafeLineInterceptConfigPayload | null]
}>()

const activeNode = ref<'entry' | 'decision' | 'response' | 'extras'>('response')
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

const selectedTemplate = computed(() =>
  props.templates.find((item) => item.template_id === flowDraft.templateId) ?? null,
)

const matchedTemplate = computed(() => {
  const site = props.site
  const config = site?.safeline_intercept
  if (!site || !config?.enabled) return null
  return (
    props.templates.find((template) =>
      sameResponseTemplate(template.response_template, config.response_template),
    ) ?? null
  )
})

const currentSummary = computed(() => {
  const config = props.site?.safeline_intercept
  if (!config) {
    return {
      response: '继承全局默认接管策略',
      template: '跟随全局',
      extra: '无站点级附加动作',
      status: '继承中',
    }
  }
  if (!config.enabled) {
    return {
      response: '本站点不接管雷池拦截',
      template: '-',
      extra: '无',
      status: '站点级覆盖',
    }
  }

  const blockIp = config.action === 'replace_and_block_ip'
  let response = ''
  let template = '-'

  if (config.action === 'pass') {
    response = '透传雷池原始响应'
  } else if (config.action === 'drop') {
    response = '直接丢弃响应'
  } else if (config.action === 'replace' || config.action === 'replace_and_block_ip') {
    response = '替换为自定义动作'
    if (
      props.l7Config &&
      sameResponseTemplate(
        config.response_template,
        props.l7Config.safeline_intercept.response_template,
      )
    ) {
      template = '全局默认拦截页'
    } else {
      template = matchedTemplate.value?.name ?? '历史自定义动作'
    }
  } else {
    response = config.action
  }

  return {
    response,
    template,
    extra: blockIp ? '封禁来源 IP' : '无',
    status: '站点级覆盖',
  }
})

const responseCards = computed(() => [
  {
    id: 'inherit',
    title: '继承全局',
    description: '完全沿用系统默认接管策略，本站不再单独覆盖。',
    chip: currentSummary.value.status,
  },
  {
    id: 'disabled',
    title: '不接管',
    description: '雷池拦截后，rust 不再替换或接管响应。',
    chip: '最保守',
  },
  {
    id: 'pass',
    title: '透传原始响应',
    description: '保留雷池当前返回内容，不做二次包装。',
    chip: '直通',
  },
  {
    id: 'drop',
    title: '直接丢弃',
    description: '适合极简阻断场景，不返回自定义内容。',
    chip: '无响应体',
  },
  {
    id: 'global_template',
    title: '全局默认页面',
    description: '使用系统统一拦截页，便于保持所有站点一致。',
    chip: '统一模板',
  },
  {
    id: 'template',
    title: '站点模板动作',
    description: '按站点挑选动作中心模板，适合差异化接管。',
    chip: `${props.templates.length} 个模板`,
  },
])

const canSave = computed(() => {
  if (!props.site || !props.l7Config) return false
  if (flowDraft.responseMode === 'legacy') return false
  if (flowDraft.responseMode === 'template' && !selectedTemplate.value) return false
  return true
})

const pendingPayload = computed(() => {
  if (!props.l7Config) return null
  const base = cloneSafelineIntercept(props.l7Config.safeline_intercept)
  if (!base) return null

  switch (flowDraft.responseMode) {
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

const pendingSummary = computed(() => {
  switch (flowDraft.responseMode) {
    case 'inherit':
      return '继承全局默认接管策略'
    case 'disabled':
      return '本站点不接管雷池拦截'
    case 'pass':
      return '透传雷池原始响应'
    case 'drop':
      return '直接丢弃'
    case 'global_template':
      return flowDraft.blockIp
        ? '使用全局默认拦截页，并封禁来源 IP'
        : '使用全局默认拦截页'
    case 'template':
      return selectedTemplate.value
        ? `${selectedTemplate.value.name}${flowDraft.blockIp ? '，并封禁来源 IP' : ''}`
        : '请选择模板'
    default:
      return '请先完成配置'
  }
})

async function loadSelectedTemplatePreview() {
  if (!selectedTemplate.value) {
    previewBody.value = ''
    previewMeta.value = null
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
  } catch (error) {
    previewBody.value = ''
    previewMeta.value = null
    previewError.value = error instanceof Error ? error.message : '读取模板预览失败'
  } finally {
    previewLoading.value = false
  }
}

function resetFlowDraft() {
  const config = cloneSafelineIntercept(props.site?.safeline_intercept)
  previewBody.value = ''
  previewMeta.value = null
  previewError.value = ''
  activeNode.value = 'response'

  if (!config) {
    flowDraft.responseMode = props.pendingTemplate ? 'template' : 'inherit'
    flowDraft.templateId = props.pendingTemplate?.template_id ?? ''
    flowDraft.blockIp = false
    if (props.pendingTemplate) {
      void loadSelectedTemplatePreview()
    }
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
      props.l7Config &&
      sameResponseTemplate(
        config.response_template,
        props.l7Config.safeline_intercept.response_template,
      )

    if (sameAsGlobal) {
      flowDraft.responseMode = 'global_template'
      flowDraft.templateId = ''
      return
    }

    if (matchedTemplate.value) {
      flowDraft.responseMode = 'template'
      flowDraft.templateId = matchedTemplate.value.template_id
      void loadSelectedTemplatePreview()
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

function selectResponseMode(mode: ResponseMode) {
  flowDraft.responseMode = mode
  activeNode.value = mode === 'template' ? 'response' : 'extras'
  if (mode !== 'template') {
    flowDraft.templateId = ''
    previewBody.value = ''
    previewMeta.value = null
    previewError.value = ''
  } else if (props.pendingTemplate && !flowDraft.templateId) {
    flowDraft.templateId = props.pendingTemplate.template_id
    void loadSelectedTemplatePreview()
  }
}

watch(
  () => [props.open, props.site?.id, props.templates.length, props.pendingTemplate?.template_id],
  () => {
    if (props.open && props.site) {
      resetFlowDraft()
    }
  },
  { immediate: true },
)

watch(
  () => flowDraft.templateId,
  (value, previous) => {
    if (flowDraft.responseMode !== 'template') return
    if (value && value !== previous) {
      void loadSelectedTemplatePreview()
    }
    if (!value) {
      previewBody.value = ''
      previewMeta.value = null
      previewError.value = ''
    }
  },
)
</script>

<template>
  <div
    v-if="open && site"
    class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/45 backdrop-blur-sm"
      @click="emit('close')"
    ></div>

    <div
      class="relative max-h-[calc(100vh-2rem)] w-full max-w-6xl overflow-y-auto rounded-[32px] border border-[#d7e6f8] bg-[linear-gradient(135deg,#fffaf4_0%,#f5fbff_48%,#f8f5ff_100%)] p-5 shadow-[0_30px_120px_rgba(15,23,42,0.28)] md:max-h-[calc(100vh-3rem)] md:p-6"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-[0.24em] text-sky-700">站点动作流程编排</p>
          <h3 class="mt-2 text-3xl font-semibold text-slate-900">
            {{ site.name }}
          </h3>
          <p class="mt-2 text-sm text-slate-600">
            以
            <span class="font-mono text-slate-900">{{ site.primary_hostname }}</span>
            为对象，把雷池拦截后的接管路径直接编排成一张流程图。
          </p>
        </div>
        <button
          class="flex h-11 w-11 items-center justify-center rounded-full border border-white/80 bg-white/80 text-slate-600 transition hover:border-sky-300 hover:text-sky-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div class="mt-6 grid gap-5 xl:grid-cols-[1.35fr_0.95fr]">
        <section class="rounded-[28px] border border-white/80 bg-white/72 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-900">网络流程图</p>
              <p class="mt-1 text-xs leading-6 text-slate-500">
                点击节点即可调整配置，后续加新功能时也可以直接新增节点。
              </p>
            </div>
            <StatusBadge :text="pendingSummary" type="info" />
          </div>

          <div class="mt-5 overflow-x-auto">
            <div class="min-w-[760px]">
              <div class="grid gap-4 md:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr] md:items-center">
                <button
                  class="rounded-[24px] border px-4 py-4 text-left transition"
                  :class="
                    activeNode === 'entry'
                      ? 'border-sky-400 bg-sky-50 shadow-[0_12px_30px_rgba(14,165,233,0.18)]'
                      : 'border-slate-200 bg-white/85 hover:border-sky-300'
                  "
                  @click="activeNode = 'entry'"
                >
                  <div class="flex items-center gap-3">
                    <div class="rounded-2xl bg-slate-900 p-3 text-white">
                      <Network :size="18" />
                    </div>
                    <div>
                      <p class="text-xs uppercase tracking-[0.2em] text-slate-400">入口</p>
                      <p class="mt-1 font-semibold text-slate-900">请求命中站点</p>
                    </div>
                  </div>
                  <p class="mt-3 text-sm leading-6 text-slate-600">
                    用户请求进入当前站点匹配流程，主域名为 {{ site.primary_hostname }}。
                  </p>
                </button>

                <div class="flex justify-center text-slate-300">
                  <ArrowRight :size="28" />
                </div>

                <button
                  class="rounded-[24px] border px-4 py-4 text-left transition"
                  :class="
                    activeNode === 'decision'
                      ? 'border-sky-400 bg-sky-50 shadow-[0_12px_30px_rgba(14,165,233,0.18)]'
                      : 'border-slate-200 bg-white/85 hover:border-sky-300'
                  "
                  @click="activeNode = 'decision'"
                >
                  <div class="flex items-center gap-3">
                    <div class="rounded-2xl bg-amber-500 p-3 text-white">
                      <Shield :size="18" />
                    </div>
                    <div>
                      <p class="text-xs uppercase tracking-[0.2em] text-slate-400">判定</p>
                      <p class="mt-1 font-semibold text-slate-900">雷池拦截决策</p>
                    </div>
                  </div>
                  <p class="mt-3 text-sm leading-6 text-slate-600">
                    放行则正常回源；只有拦截命中后，才会进入下面的 rust 接管动作。
                  </p>
                </button>

                <div class="flex justify-center text-slate-300">
                  <ArrowRight :size="28" />
                </div>

                <button
                  class="rounded-[24px] border px-4 py-4 text-left transition"
                  :class="
                    activeNode === 'response'
                      ? 'border-indigo-400 bg-indigo-50 shadow-[0_12px_30px_rgba(99,102,241,0.18)]'
                      : 'border-slate-200 bg-white/85 hover:border-indigo-300'
                  "
                  @click="activeNode = 'response'"
                >
                  <div class="flex items-center gap-3">
                    <div class="rounded-2xl bg-indigo-600 p-3 text-white">
                      <Zap :size="18" />
                    </div>
                    <div>
                      <p class="text-xs uppercase tracking-[0.2em] text-slate-400">主动作</p>
                      <p class="mt-1 font-semibold text-slate-900">响应动作</p>
                    </div>
                  </div>
                  <p class="mt-3 text-sm leading-6 text-slate-600">
                    当前待生效方案：{{ pendingSummary }}。
                  </p>
                </button>

                <div class="flex justify-center text-slate-300">
                  <ArrowRight :size="28" />
                </div>

                <button
                  class="rounded-[24px] border px-4 py-4 text-left transition"
                  :class="
                    activeNode === 'extras'
                      ? 'border-rose-400 bg-rose-50 shadow-[0_12px_30px_rgba(244,63,94,0.18)]'
                      : 'border-slate-200 bg-white/85 hover:border-rose-300'
                  "
                  @click="activeNode = 'extras'"
                >
                  <div class="flex items-center gap-3">
                    <div class="rounded-2xl bg-rose-600 p-3 text-white">
                      <ShieldBan :size="18" />
                    </div>
                    <div>
                      <p class="text-xs uppercase tracking-[0.2em] text-slate-400">附加动作</p>
                      <p class="mt-1 font-semibold text-slate-900">扩展能力</p>
                    </div>
                  </div>
                  <p class="mt-3 text-sm leading-6 text-slate-600">
                    先保留“封禁来源 IP”作为独立开关，后续可继续加 webhook、标签、事件等。
                  </p>
                </button>
              </div>
            </div>
          </div>

          <div class="mt-5 grid gap-4 lg:grid-cols-2">
            <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-sm font-semibold text-slate-900">当前生效配置</p>
              <div class="mt-3 space-y-3 text-sm text-slate-600">
                <div>
                  <p class="text-xs uppercase tracking-[0.16em] text-slate-400">响应动作</p>
                  <p class="mt-1 text-slate-900">{{ currentSummary.response }}</p>
                </div>
                <div>
                  <p class="text-xs uppercase tracking-[0.16em] text-slate-400">模板来源</p>
                  <p class="mt-1 text-slate-900">{{ currentSummary.template }}</p>
                </div>
                <div>
                  <p class="text-xs uppercase tracking-[0.16em] text-slate-400">附加动作</p>
                  <p class="mt-1 text-slate-900">{{ currentSummary.extra }}</p>
                </div>
              </div>
            </div>

            <div class="rounded-2xl border border-slate-200 bg-slate-900 p-4 text-slate-100">
              <p class="text-sm font-semibold">保存后将生效</p>
              <p class="mt-3 text-lg font-semibold">{{ pendingSummary }}</p>
              <p class="mt-2 text-sm leading-6 text-slate-300">
                作用范围仅限当前站点，不会影响其他站点和全局默认配置。
              </p>
            </div>
          </div>
        </section>

        <section class="space-y-4">
          <div class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-slate-900">主动作配置</p>
                <p class="mt-1 text-xs leading-6 text-slate-500">
                  先确定拦截后返回什么，再决定是否添加附加动作。
                </p>
              </div>
              <StatusBadge
                :text="activeNode === 'response' ? '正在编辑' : '点击流程节点切换'"
                :type="activeNode === 'response' ? 'info' : 'muted'"
              />
            </div>

            <div class="mt-4 grid gap-3">
              <button
                v-for="card in responseCards"
                :key="card.id"
                class="rounded-2xl border px-4 py-4 text-left transition"
                :class="
                  flowDraft.responseMode === card.id
                    ? 'border-indigo-400 bg-indigo-50'
                    : 'border-slate-200 bg-slate-50 hover:border-indigo-300 hover:bg-white'
                "
                @click="selectResponseMode(card.id as ResponseMode)"
              >
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="font-semibold text-slate-900">{{ card.title }}</p>
                    <p class="mt-1 text-sm leading-6 text-slate-600">
                      {{ card.description }}
                    </p>
                  </div>
                  <StatusBadge
                    :text="card.chip"
                    :type="flowDraft.responseMode === card.id ? 'info' : 'muted'"
                    compact
                  />
                </div>
              </button>
            </div>

            <div
              v-if="flowDraft.responseMode === 'legacy'"
              class="mt-4 rounded-2xl border border-amber-300 bg-amber-50 px-4 py-4 text-sm text-amber-900"
            >
              当前站点挂的是历史自定义动作，已经不适合继续用下拉模式维护了。建议直接迁移成“全局默认页面”或“站点模板动作”。
            </div>
          </div>

          <div
            v-if="flowDraft.responseMode === 'template'"
            class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-slate-900">模板动作节点</p>
                <p class="mt-1 text-xs leading-6 text-slate-500">
                  这里用卡片挑选模板，比单个下拉框更适合后续继续扩展。
                </p>
              </div>
              <RouterLink
                to="/admin/actions"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-stone-700 transition hover:border-sky-300 hover:text-sky-700"
              >
                去动作中心
                <ArrowRight :size="14" />
              </RouterLink>
            </div>

            <div class="mt-4 grid max-h-[18rem] gap-3 overflow-y-auto pr-1">
              <button
                v-for="template in templates"
                :key="template.template_id"
                class="rounded-2xl border px-4 py-4 text-left transition"
                :class="
                  flowDraft.templateId === template.template_id
                    ? 'border-sky-400 bg-sky-50'
                    : 'border-slate-200 bg-slate-50 hover:border-sky-300 hover:bg-white'
                "
                @click="flowDraft.templateId = template.template_id"
              >
                <div class="flex items-start justify-between gap-3">
                  <div>
                    <p class="font-semibold text-slate-900">{{ template.name }}</p>
                    <p class="mt-1 text-sm leading-6 text-slate-600">
                      {{ template.description || '动作中心模板' }}
                    </p>
                  </div>
                  <div class="flex flex-wrap justify-end gap-2">
                    <StatusBadge
                      :text="`HTTP ${template.response_template.status_code}`"
                      type="muted"
                      compact
                    />
                    <StatusBadge
                      :text="template.response_template.content_type"
                      type="info"
                      compact
                    />
                  </div>
                </div>
              </button>
            </div>

            <div class="mt-4 rounded-2xl border border-slate-200 bg-slate-950 p-4 text-slate-100">
              <div class="flex items-center gap-2">
                <Eye :size="16" />
                <p class="text-sm font-semibold">模板预览</p>
              </div>
              <p v-if="previewLoading" class="mt-3 text-sm text-slate-300">
                正在读取模板预览...
              </p>
              <p v-else-if="previewError" class="mt-3 text-sm text-rose-300">
                {{ previewError }}
              </p>
              <div v-else-if="previewMeta" class="mt-3">
                <div class="flex flex-wrap gap-2">
                  <StatusBadge :text="`HTTP ${previewMeta.statusCode}`" type="muted" compact />
                  <StatusBadge :text="previewMeta.contentType" type="info" compact />
                  <StatusBadge
                    :text="previewMeta.truncated ? '已截断预览' : '完整预览'"
                    type="muted"
                    compact
                  />
                </div>
                <pre class="mt-3 max-h-56 overflow-auto rounded-2xl bg-slate-900 p-4 text-xs leading-6 text-slate-200 whitespace-pre-wrap">{{ previewBody }}</pre>
              </div>
              <p v-else class="mt-3 text-sm text-slate-300">
                先选择一个模板，再查看它会返回什么内容。
              </p>
            </div>
          </div>

          <div class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-slate-900">附加动作节点</p>
                <p class="mt-1 text-xs leading-6 text-slate-500">
                  这里单独承载扩展能力，后续新增节点时不需要重构主动作模型。
                </p>
              </div>
              <StatusBadge
                :text="activeNode === 'extras' ? '正在编辑' : '可独立扩展'"
                :type="activeNode === 'extras' ? 'info' : 'muted'"
              />
            </div>

            <button
              class="mt-4 w-full rounded-2xl border px-4 py-4 text-left transition"
              :class="
                flowDraft.blockIp
                  ? 'border-rose-400 bg-rose-50'
                  : 'border-slate-200 bg-slate-50 hover:border-rose-300 hover:bg-white'
              "
              @click="flowDraft.blockIp = !flowDraft.blockIp"
            >
              <div class="flex items-start justify-between gap-3">
                <div>
                  <p class="font-semibold text-slate-900">封禁来源 IP</p>
                  <p class="mt-1 text-sm leading-6 text-slate-600">
                    拦截命中后，把来源 IP 一并加入封禁流程。后面如果你想加事件标签、回调通知，也可以继续按这个区域扩展。
                  </p>
                </div>
                <StatusBadge
                  :text="flowDraft.blockIp ? '已启用' : '未启用'"
                  :type="flowDraft.blockIp ? 'warning' : 'muted'"
                />
              </div>
            </button>
          </div>

          <div class="flex flex-wrap items-center gap-3">
            <button
              :disabled="!canSave || saving"
              class="inline-flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-sky-600/90 disabled:cursor-not-allowed disabled:opacity-60"
              @click="emit('save', pendingPayload)"
            >
              {{ saving ? '保存中...' : '保存流程动作' }}
            </button>
            <button
              class="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
              @click="emit('close')"
            >
              取消
            </button>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
