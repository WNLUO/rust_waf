import { computed, reactive, ref, watch } from 'vue'
import { fetchRuleActionTemplatePreview } from '@/shared/api/rules'
import type {
  L7ConfigPayload,
  LocalSiteItem,
  RuleActionTemplateItem,
  SafeLineInterceptConfigPayload,
} from '@/shared/types'

export type ResponseMode =
  | 'inherit'
  | 'disabled'
  | 'pass'
  | 'drop'
  | 'global_template'
  | 'template'
  | 'legacy'

export type FlowNode = 'entry' | 'decision' | 'response' | 'extras'

export interface TemplatePreviewMeta {
  statusCode: number
  contentType: string
  truncated: boolean
}

interface UseAdminSiteActionFlowOptions {
  l7Config: L7ConfigPayload | null
  open: boolean
  pendingTemplate?: RuleActionTemplateItem | null
  site: LocalSiteItem | null
  templates: RuleActionTemplateItem[]
}

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

export function useAdminSiteActionFlow(options: UseAdminSiteActionFlowOptions) {
  const activeNode = ref<FlowNode>('response')
  const previewLoading = ref(false)
  const previewError = ref('')
  const previewBody = ref('')
  const previewMeta = ref<TemplatePreviewMeta | null>(null)
  const flowDraft = reactive<{
    responseMode: ResponseMode
    templateId: string
    blockIp: boolean
  }>({
    responseMode: 'inherit',
    templateId: '',
    blockIp: false,
  })

  const selectedTemplate = computed(
    () =>
      options.templates.find(
        (item) => item.template_id === flowDraft.templateId,
      ) ?? null,
  )

  const matchedTemplate = computed(() => {
    const site = options.site
    const config = site?.safeline_intercept
    if (!site || !config?.enabled) return null
    return (
      options.templates.find((template) =>
        sameResponseTemplate(
          template.response_template,
          config.response_template,
        ),
      ) ?? null
    )
  })

  const currentSummary = computed(() => {
    const config = options.site?.safeline_intercept
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
    let response = config.action
    let template = '-'

    if (config.action === 'pass') {
      response = '透传雷池原始响应'
    } else if (config.action === 'drop') {
      response = '直接丢弃响应'
    } else if (
      config.action === 'replace' ||
      config.action === 'replace_and_block_ip'
    ) {
      response = '替换为自定义动作'
      if (
        options.l7Config &&
        sameResponseTemplate(
          config.response_template,
          options.l7Config.safeline_intercept.response_template,
        )
      ) {
        template = '全局默认拦截页'
      } else {
        template = matchedTemplate.value?.name ?? '历史自定义动作'
      }
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
      id: 'inherit' as ResponseMode,
      title: '继承全局',
      description: '完全沿用系统默认接管策略，本站不再单独覆盖。',
      chip: currentSummary.value.status,
    },
    {
      id: 'disabled' as ResponseMode,
      title: '不接管',
      description: '雷池拦截后，rust 不再替换或接管响应。',
      chip: '最保守',
    },
    {
      id: 'pass' as ResponseMode,
      title: '透传原始响应',
      description: '保留雷池当前返回内容，不做二次包装。',
      chip: '直通',
    },
    {
      id: 'drop' as ResponseMode,
      title: '直接丢弃',
      description: '适合极简阻断场景，不返回自定义内容。',
      chip: '无响应体',
    },
    {
      id: 'global_template' as ResponseMode,
      title: '全局默认页面',
      description: '使用系统统一拦截页，便于保持所有站点一致。',
      chip: '统一模板',
    },
    {
      id: 'template' as ResponseMode,
      title: '站点模板动作',
      description: '按站点挑选动作中心模板，适合差异化接管。',
      chip: `${options.templates.length} 个模板`,
    },
  ])

  const canSave = computed(() => {
    if (!options.site || !options.l7Config) return false
    if (flowDraft.responseMode === 'legacy') return false
    if (flowDraft.responseMode === 'template' && !selectedTemplate.value) {
      return false
    }
    return true
  })

  const pendingPayload = computed(() => {
    if (!options.l7Config) return null
    const base = cloneSafelineIntercept(options.l7Config.safeline_intercept)
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

  function resetPreview() {
    previewBody.value = ''
    previewMeta.value = null
    previewError.value = ''
  }

  async function loadSelectedTemplatePreview() {
    if (!selectedTemplate.value) {
      resetPreview()
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
      previewError.value =
        error instanceof Error ? error.message : '读取模板预览失败'
    } finally {
      previewLoading.value = false
    }
  }

  function resetFlowDraft() {
    const config = cloneSafelineIntercept(options.site?.safeline_intercept)
    resetPreview()
    activeNode.value = 'response'

    if (!config) {
      flowDraft.responseMode = options.pendingTemplate ? 'template' : 'inherit'
      flowDraft.templateId = options.pendingTemplate?.template_id ?? ''
      flowDraft.blockIp = false
      if (options.pendingTemplate) {
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

    if (
      config.action === 'replace' ||
      config.action === 'replace_and_block_ip'
    ) {
      const sameAsGlobal =
        options.l7Config &&
        sameResponseTemplate(
          config.response_template,
          options.l7Config.safeline_intercept.response_template,
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

  function setActiveNode(node: FlowNode) {
    activeNode.value = node
  }

  function selectResponseMode(mode: ResponseMode) {
    flowDraft.responseMode = mode
    activeNode.value = mode === 'template' ? 'response' : 'extras'
    if (mode !== 'template') {
      flowDraft.templateId = ''
      resetPreview()
    } else if (options.pendingTemplate && !flowDraft.templateId) {
      flowDraft.templateId = options.pendingTemplate.template_id
      void loadSelectedTemplatePreview()
    }
  }

  function selectTemplate(templateId: string) {
    flowDraft.templateId = templateId
  }

  function toggleBlockIp() {
    flowDraft.blockIp = !flowDraft.blockIp
  }

  watch(
    () => [
      options.open,
      options.site?.id,
      options.templates.length,
      options.pendingTemplate?.template_id,
    ],
    () => {
      if (options.open && options.site) {
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
        resetPreview()
      }
    },
  )

  return {
    activeNode,
    canSave,
    currentSummary,
    flowDraft,
    pendingPayload,
    pendingSummary,
    previewBody,
    previewError,
    previewLoading,
    previewMeta,
    responseCards,
    selectResponseMode,
    selectTemplate,
    setActiveNode,
    toggleBlockIp,
  }
}
