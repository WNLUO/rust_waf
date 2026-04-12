import { computed, onMounted, ref } from 'vue'
import {
  deleteRuleActionPlugin,
  fetchActionIdeaPresets,
  fetchRuleActionPlugins,
  fetchRuleActionTemplatePreview,
  fetchRuleActionTemplates,
  updateActionIdeaPreset,
  updateRuleActionPlugin,
  uploadActionIdeaGzip,
  uploadRuleActionPlugin,
} from '@/shared/api/client'
import type {
  ActionIdeaPreset,
  RuleActionPluginItem,
  RuleActionTemplateItem,
  RuleActionTemplatePreviewResponse,
} from '@/shared/types'

export interface ActionIdeaCard extends ActionIdeaPreset {
  template: RuleActionTemplateItem | null
  ctaPath: string
}

const defaultFakeSqlError =
  "SQL syntax error near '\\'' at line 1\nWarning: mysql_fetch_assoc() expects parameter 1 to be resource, boolean given in /var/www/html/search.php on line 42"
const defaultFakeSqlResult =
  'query result: admin | 5f4dcc3b5aa765d61d8327deb882cf99 | super_admin'
const defaultFakeXssPayload = "<script>alert('xss')<\\/script>"
const defaultTarpitBody = 'processing request, please wait...'
const defaultRandomStatuses = '500,502,403'
const defaultRandomSuccessRate = 25
const defaultRandomSuccessBody = 'request completed successfully'
const defaultRandomFailureBody = 'upstream system unstable, retry later'

const ideaTemplateMatchers: Record<
  string,
  (templates: RuleActionTemplateItem[]) => RuleActionTemplateItem | null
> = {
  'json-honeypot': (templates) =>
    templates.find((item) =>
      item.response_template.content_type.includes('application/json'),
    ) ?? null,
  'inline-js': (templates) =>
    templates.find(
      (item) =>
        item.response_template.content_type.includes('text/html') ||
        item.name.includes('JS'),
    ) ?? null,
  'browser-fingerprint-js': (templates) =>
    templates.find(
      (item) =>
        item.response_template.content_type.includes('text/html') ||
        item.name.includes('JS'),
    ) ?? null,
  'gzip-response': () => null,
  'maintenance-page': (templates) =>
    templates.find(
      (item) => item.name.includes('Block') || item.name.includes('Hello'),
    ) ?? null,
  'redirect-302': () => null,
}

export function useAdminActions() {
  const loading = ref(true)
  const refreshing = ref(false)
  const installingPlugin = ref(false)
  const savingIdea = ref(false)
  const uploadingIdeaAsset = ref(false)
  const error = ref('')
  const installedPlugins = ref<RuleActionPluginItem[]>([])
  const pluginTemplates = ref<RuleActionTemplateItem[]>([])
  const actionIdeas = ref<ActionIdeaPreset[]>([])
  const previewOpen = ref(false)
  const previewLoading = ref(false)
  const previewTitle = ref('')
  const previewSourceLabel = ref('')
  const previewPayload = ref<RuleActionTemplatePreviewResponse | null>(null)
  const previewIdeaId = ref('')
  const editingPreviewTitle = ref(false)
  const previewDraftTitle = ref('')
  const previewDraftStatusCode = ref(200)
  const previewDraftContentType = ref('')
  const previewDraftContent = ref('')
  const previewDraftSqlError = ref('')
  const previewDraftSqlResult = ref('')
  const previewDraftXssPayload = ref('')
  const previewDraftTarpitBytesPerChunk = ref(1)
  const previewDraftTarpitIntervalMs = ref(1000)
  const previewDraftTarpitBody = ref('')
  const previewDraftRandomStatuses = ref(defaultRandomStatuses)
  const previewDraftRandomSuccessRate = ref(defaultRandomSuccessRate)
  const previewDraftRandomSuccessBody = ref(defaultRandomSuccessBody)
  const previewDraftRandomFailureBody = ref(defaultRandomFailureBody)
  const pagePreviewOpen = ref(false)
  const downloadingIdeaId = ref('')
  const uploadingIdeaId = ref('')

  const templateCount = computed(() => pluginTemplates.value.length)
  const pluginsById = computed(
    () => new Map(installedPlugins.value.map((item) => [item.plugin_id, item])),
  )
  const actionIdeasById = computed(
    () => new Map(actionIdeas.value.map((item) => [item.id, item])),
  )

  const funIdeaCards = computed<ActionIdeaCard[]>(() =>
    actionIdeas.value.map((idea) => {
      const templateMatcher = ideaTemplateMatchers[idea.id] ?? (() => null)
      const template = templateMatcher(pluginTemplates.value)
      return {
        ...idea,
        template,
        ctaPath: template
          ? `/admin/rules?template=${encodeURIComponent(template.template_id)}`
          : idea.fallback_path,
      }
    }),
  )

  const currentPreviewIdea = computed(() =>
    previewIdeaId.value
      ? actionIdeasById.value.get(previewIdeaId.value) ?? null
      : null,
  )
  const previewIsActionIdea = computed(() => Boolean(currentPreviewIdea.value))

  const previewRenderedBody = computed(() =>
    previewIsActionIdea.value
      ? currentPreviewIdea.value && isInlineJsIdea(currentPreviewIdea.value)
        ? wrapInlineJsContent(
            previewDraftContent.value,
            previewDraftTitle.value || previewTitle.value,
          )
        : currentPreviewIdea.value && isRedirectIdea(currentPreviewIdea.value)
          ? wrapRedirectContent(
              previewDraftContent.value,
              previewDraftTitle.value || previewTitle.value,
            )
          : currentPreviewIdea.value && isFakeSqlIdea(currentPreviewIdea.value)
            ? wrapFakeSqlContent(
                escapeHtml(
                  previewDraftSqlError.value.trim() || defaultFakeSqlError,
                ),
                escapeHtml(
                  previewDraftSqlResult.value.trim() || defaultFakeSqlResult,
                ),
              )
            : currentPreviewIdea.value && isFakeXssIdea(currentPreviewIdea.value)
              ? wrapFakeXssContent(
                  escapeHtml(
                    previewDraftXssPayload.value.trim() ||
                      defaultFakeXssPayload,
                  ),
                )
              : currentPreviewIdea.value && isTarpitIdea(currentPreviewIdea.value)
                ? previewDraftTarpitBody.value.trim() || defaultTarpitBody
                : currentPreviewIdea.value &&
                    isRandomErrorIdea(currentPreviewIdea.value)
                  ? `失败状态码: ${
                      parseRandomStatuses(
                        previewDraftRandomStatuses.value,
                      ).join(', ') || defaultRandomStatuses
                    }\n成功概率: ${previewDraftRandomSuccessRate.value}%\n\n失败文案:\n${
                      previewDraftRandomFailureBody.value.trim() ||
                      defaultRandomFailureBody
                    }\n\n成功文案:\n${
                      previewDraftRandomSuccessBody.value.trim() ||
                      defaultRandomSuccessBody
                    }`
                  : previewDraftContent.value
      : (previewPayload.value?.body_preview ?? ''),
  )

  const previewRandomErrorSummary = computed(() => ({
    statuses: parseRandomStatuses(previewDraftRandomStatuses.value),
    successRate: Math.min(
      100,
      Math.max(0, Math.floor(previewDraftRandomSuccessRate.value || 0)),
    ),
    successBody:
      previewDraftRandomSuccessBody.value.trim() || defaultRandomSuccessBody,
    failureBody:
      previewDraftRandomFailureBody.value.trim() || defaultRandomFailureBody,
  }))

  const previewCanPagePreview = computed(() => {
    const idea = currentPreviewIdea.value
    if (idea?.requires_upload) return false
    return (
      (
        previewIsActionIdea.value
          ? previewDraftContentType.value
          : (previewPayload.value?.content_type ?? '')
      ).includes('text/html')
    )
  })

  const previewDirty = computed(() => {
    const idea = currentPreviewIdea.value
    if (!idea) return false
    return (
      previewDraftTitle.value !== idea.title ||
      previewDraftStatusCode.value !== idea.status_code ||
      previewDraftContentType.value !== idea.content_type ||
      (!idea.requires_upload &&
        (isFakeSqlIdea(idea)
          ? wrapFakeSqlContent(
              escapeHtml(
                previewDraftSqlError.value.trim() || defaultFakeSqlError,
              ),
              escapeHtml(
                previewDraftSqlResult.value.trim() || defaultFakeSqlResult,
              ),
            ) !== idea.response_content
          : isFakeXssIdea(idea)
            ? wrapFakeXssContent(
                escapeHtml(
                  previewDraftXssPayload.value.trim() || defaultFakeXssPayload,
                ),
              ) !== idea.response_content
            : isTarpitIdea(idea)
              ? serializeTarpitConfig(
                  Math.max(
                    1,
                    Math.floor(previewDraftTarpitBytesPerChunk.value || 1),
                  ),
                  Math.max(
                    1,
                    Math.floor(previewDraftTarpitIntervalMs.value || 1000),
                  ),
                  previewDraftTarpitBody.value.trim() || defaultTarpitBody,
                ) !== idea.response_content
              : isRandomErrorIdea(idea)
                ? serializeRandomErrorConfig(
                    previewDraftRandomStatuses.value,
                    Math.min(
                      100,
                      Math.max(
                        0,
                        Math.floor(previewDraftRandomSuccessRate.value || 0),
                      ),
                    ),
                    previewDraftRandomSuccessBody.value.trim() ||
                      defaultRandomSuccessBody,
                    previewDraftRandomFailureBody.value.trim() ||
                      defaultRandomFailureBody,
                  ) !== idea.response_content
                : previewDraftContent.value !== idea.response_content))
    )
  })

  const loadActionCenter = async () => {
    loading.value = true
    refreshing.value = true
    try {
      const [plugins, templates, ideas] = await Promise.all([
        fetchRuleActionPlugins(),
        fetchRuleActionTemplates(),
        fetchActionIdeaPresets(),
      ])
      installedPlugins.value = plugins.plugins
      pluginTemplates.value = templates.templates
      actionIdeas.value = ideas.ideas
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取动作中心失败'
    } finally {
      loading.value = false
      refreshing.value = false
    }
  }

  const installPlugin = async (file: File) => {
    installingPlugin.value = true
    try {
      await uploadRuleActionPlugin(file)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件安装失败'
    } finally {
      installingPlugin.value = false
    }
  }

  const togglePluginStatus = async (plugin: RuleActionPluginItem) => {
    try {
      await updateRuleActionPlugin(plugin.plugin_id, !plugin.enabled)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '更新插件状态失败'
    }
  }

  const deletePlugin = async (pluginId: string) => {
    if (!window.confirm('确认卸载这个动作插件吗？相关动作模板会一并移除。')) {
      return
    }
    try {
      await deleteRuleActionPlugin(pluginId)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件卸载失败'
    }
  }

  const openTemplatePreview = async (template: RuleActionTemplateItem) => {
    previewLoading.value = true
    previewOpen.value = true
    previewIdeaId.value = ''
    editingPreviewTitle.value = false
    previewDraftTitle.value = ''
    previewDraftStatusCode.value = 200
    previewDraftContentType.value = ''
    previewDraftContent.value = ''
    pagePreviewOpen.value = false
    previewTitle.value = template.name
    previewSourceLabel.value = `模板动作 · ${
      pluginsById.value.get(template.plugin_id)?.name || template.plugin_id
    }`
    try {
      previewPayload.value = await fetchRuleActionTemplatePreview(
        template.template_id,
      )
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取模板预览失败'
      previewOpen.value = false
    } finally {
      previewLoading.value = false
    }
  }

  const openGeneratedPreview = (idea: ActionIdeaPreset) => {
    previewOpen.value = true
    previewLoading.value = false
    previewIdeaId.value = idea.id
    editingPreviewTitle.value = false
    previewDraftTitle.value = idea.title
    previewDraftStatusCode.value = idea.status_code
    previewDraftContentType.value = idea.content_type
    previewDraftContent.value = idea.response_content
    previewDraftSqlError.value = ''
    previewDraftSqlResult.value = ''
    previewDraftXssPayload.value = ''
    previewDraftTarpitBytesPerChunk.value = 1
    previewDraftTarpitIntervalMs.value = 1000
    previewDraftTarpitBody.value = ''
    previewDraftRandomStatuses.value = defaultRandomStatuses
    previewDraftRandomSuccessRate.value = defaultRandomSuccessRate
    previewDraftRandomSuccessBody.value = defaultRandomSuccessBody
    previewDraftRandomFailureBody.value = defaultRandomFailureBody
    if (isFakeSqlIdea(idea)) {
      const fields = extractFakeSqlFields(idea.response_content)
      previewDraftSqlError.value = fields.error
      previewDraftSqlResult.value = fields.result
    }
    if (isFakeXssIdea(idea)) {
      previewDraftXssPayload.value = extractFakeXssPayload(
        idea.response_content,
      )
    }
    if (isTarpitIdea(idea)) {
      const config = extractTarpitConfig(idea.response_content)
      previewDraftTarpitBytesPerChunk.value = config.bytesPerChunk
      previewDraftTarpitIntervalMs.value = config.intervalMs
      previewDraftTarpitBody.value = config.bodyText
    }
    if (isRandomErrorIdea(idea)) {
      const config = extractRandomErrorConfig(idea.response_content)
      previewDraftRandomStatuses.value = config.statuses
      previewDraftRandomSuccessRate.value = config.successRate
      previewDraftRandomSuccessBody.value = config.successBody
      previewDraftRandomFailureBody.value = config.failureBody
    }
    previewTitle.value = idea.title
    previewSourceLabel.value = idea.has_overrides
      ? '动作方案 · 已保存自定义版本'
      : '动作方案 · 系统默认值'
    previewPayload.value = createActionIdeaPreviewPayload(idea)
  }

  const closePreview = () => {
    previewOpen.value = false
    previewLoading.value = false
    previewTitle.value = ''
    previewSourceLabel.value = ''
    previewPayload.value = null
    previewIdeaId.value = ''
    editingPreviewTitle.value = false
    previewDraftTitle.value = ''
    previewDraftStatusCode.value = 200
    previewDraftContentType.value = ''
    previewDraftContent.value = ''
    previewDraftSqlError.value = ''
    previewDraftSqlResult.value = ''
    previewDraftXssPayload.value = ''
    previewDraftTarpitBytesPerChunk.value = 1
    previewDraftTarpitIntervalMs.value = 1000
    previewDraftTarpitBody.value = ''
    previewDraftRandomStatuses.value = defaultRandomStatuses
    previewDraftRandomSuccessRate.value = defaultRandomSuccessRate
    previewDraftRandomSuccessBody.value = defaultRandomSuccessBody
    previewDraftRandomFailureBody.value = defaultRandomFailureBody
    pagePreviewOpen.value = false
  }

  const downloadGeneratedPlugin = async (ideaId: string) => {
    const idea = actionIdeasById.value.get(ideaId)
    if (!idea) return
    if (idea.requires_upload) {
      error.value =
        '响应Gzip 需要先在预览弹窗里上传 gzip 文件，不提供本地样例下载。'
      return
    }

    downloadingIdeaId.value = ideaId
    try {
      const { default: JSZip } = await import('jszip')
      const zip = new JSZip()
      zip.file(
        'manifest.json',
        JSON.stringify(
          {
            plugin_id: idea.plugin_id,
            name: idea.plugin_name,
            version: '1.0.0',
            description: idea.plugin_description,
            templates: [
              {
                id: idea.template_local_id,
                name: idea.title,
                description: idea.template_description,
                layer: 'l7',
                action: 'respond',
                pattern: idea.pattern,
                severity: idea.severity,
                response_template: {
                  status_code: idea.status_code,
                  content_type: idea.content_type,
                  body_source: 'file',
                  gzip: idea.gzip,
                  body_text: '',
                  body_file_path: idea.response_file_path,
                  headers: idea.headers,
                },
              },
            ],
          },
          null,
          2,
        ),
      )
      zip.file(
        `responses/${idea.response_file_path}`,
        isRedirectIdea(idea)
          ? wrapRedirectContent(idea.response_content, idea.title)
          : isTarpitIdea(idea)
            ? extractTarpitConfig(idea.response_content).bodyText
            : isRandomErrorIdea(idea)
              ? extractRandomErrorConfig(idea.response_content).failureBody
              : isFakeSqlIdea(idea)
                ? wrapFakeSqlContent(
                    extractFakeSqlFields(idea.response_content).error,
                    extractFakeSqlFields(idea.response_content).result,
                  )
                : isFakeXssIdea(idea)
                  ? wrapFakeXssContent(
                      extractFakeXssPayload(idea.response_content),
                    )
                  : idea.id === 'inline-js'
                    ? wrapInlineJsContent(idea.response_content, idea.title)
                    : idea.response_content,
      )

      const blob = await zip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = idea.file_name
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } finally {
      downloadingIdeaId.value = ''
    }
  }

  const saveActionIdeaPreview = async () => {
    const idea = currentPreviewIdea.value
    if (!idea) return
    if (!previewDraftTitle.value.trim()) {
      error.value = '动作名称不能为空'
      return
    }
    if (!previewDraftContentType.value.trim()) {
      error.value = '内容类型不能为空'
      return
    }
    if (
      !Number.isInteger(previewDraftStatusCode.value) ||
      previewDraftStatusCode.value < 100 ||
      previewDraftStatusCode.value > 599
    ) {
      error.value = '状态码必须在 100 到 599 之间'
      return
    }
    if (!idea.requires_upload && !previewDraftContent.value.trim()) {
      if (!isFakeSqlIdea(idea) && !isFakeXssIdea(idea)) {
        error.value = '原始内容不能为空'
        return
      }
    }
    if (isFakeSqlIdea(idea)) {
      if (
        !previewDraftSqlError.value.trim() ||
        !previewDraftSqlResult.value.trim()
      ) {
        error.value = 'SQL 假回显需要同时填写错误文案和伪结果'
        return
      }
    }
    if (isFakeXssIdea(idea) && !previewDraftXssPayload.value.trim()) {
      error.value = 'XSS 假回显需要填写 payload'
      return
    }
    if (isTarpitIdea(idea)) {
      if (
        !Number.isInteger(previewDraftTarpitBytesPerChunk.value) ||
        previewDraftTarpitBytesPerChunk.value <= 0
      ) {
        error.value = '每次发送字节数必须大于 0'
        return
      }
      if (
        !Number.isInteger(previewDraftTarpitIntervalMs.value) ||
        previewDraftTarpitIntervalMs.value <= 0
      ) {
        error.value = '每次间隔毫秒必须大于 0'
        return
      }
      if (!previewDraftTarpitBody.value.trim()) {
        error.value = '拖延文案不能为空'
        return
      }
    }
    if (isRandomErrorIdea(idea)) {
      if (!parseRandomStatuses(previewDraftRandomStatuses.value).length) {
        error.value = '请至少填写一个有效的失败状态码，例如 500,502,403'
        return
      }
      if (
        !Number.isInteger(previewDraftRandomSuccessRate.value) ||
        previewDraftRandomSuccessRate.value < 0 ||
        previewDraftRandomSuccessRate.value > 100
      ) {
        error.value = '成功概率必须在 0 到 100 之间'
        return
      }
      if (!previewDraftRandomSuccessBody.value.trim()) {
        error.value = '成功文案不能为空'
        return
      }
      if (!previewDraftRandomFailureBody.value.trim()) {
        error.value = '失败文案不能为空'
        return
      }
    }

    savingIdea.value = true
    try {
      const responseContent = isFakeSqlIdea(idea)
        ? wrapFakeSqlContent(
            escapeHtml(previewDraftSqlError.value.trim()),
            escapeHtml(previewDraftSqlResult.value.trim()),
          )
        : isFakeXssIdea(idea)
          ? wrapFakeXssContent(
              escapeHtml(previewDraftXssPayload.value.trim()),
            )
          : isTarpitIdea(idea)
            ? serializeTarpitConfig(
                Math.max(1, Math.floor(previewDraftTarpitBytesPerChunk.value)),
                Math.max(1, Math.floor(previewDraftTarpitIntervalMs.value)),
                previewDraftTarpitBody.value.trim(),
              )
            : isRandomErrorIdea(idea)
              ? serializeRandomErrorConfig(
                  previewDraftRandomStatuses.value,
                  Math.min(
                    100,
                    Math.max(
                      0,
                      Math.floor(previewDraftRandomSuccessRate.value),
                    ),
                  ),
                  previewDraftRandomSuccessBody.value.trim(),
                  previewDraftRandomFailureBody.value.trim(),
                )
              : idea.requires_upload
                ? ''
                : previewDraftContent.value
      const updated = await updateActionIdeaPreset(idea.id, {
        title: previewDraftTitle.value,
        status_code: previewDraftStatusCode.value,
        content_type: previewDraftContentType.value,
        response_content: responseContent,
      })
      actionIdeas.value = actionIdeas.value.map((item) =>
        item.id === updated.id ? updated : item,
      )
      previewTitle.value = updated.title
      previewSourceLabel.value = '动作方案 · 已保存自定义版本'
      previewPayload.value = createActionIdeaPreviewPayload(updated)
      previewDraftTitle.value = updated.title
      previewDraftStatusCode.value = updated.status_code
      previewDraftContentType.value = updated.content_type
      previewDraftContent.value = updated.response_content
      if (isFakeSqlIdea(updated)) {
        const fields = extractFakeSqlFields(updated.response_content)
        previewDraftSqlError.value = fields.error
        previewDraftSqlResult.value = fields.result
      }
      if (isFakeXssIdea(updated)) {
        previewDraftXssPayload.value = extractFakeXssPayload(
          updated.response_content,
        )
      }
      if (isTarpitIdea(updated)) {
        const config = extractTarpitConfig(updated.response_content)
        previewDraftTarpitBytesPerChunk.value = config.bytesPerChunk
        previewDraftTarpitIntervalMs.value = config.intervalMs
        previewDraftTarpitBody.value = config.bodyText
      }
      if (isRandomErrorIdea(updated)) {
        const config = extractRandomErrorConfig(updated.response_content)
        previewDraftRandomStatuses.value = config.statuses
        previewDraftRandomSuccessRate.value = config.successRate
        previewDraftRandomSuccessBody.value = config.successBody
        previewDraftRandomFailureBody.value = config.failureBody
      }
      editingPreviewTitle.value = false
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存动作方案失败'
    } finally {
      savingIdea.value = false
    }
  }

  const openPagePreview = () => {
    if (!previewCanPagePreview.value) return
    pagePreviewOpen.value = true
  }

  const closePagePreview = () => {
    pagePreviewOpen.value = false
  }

  const uploadIdeaAsset = async (file: File) => {
    const idea = currentPreviewIdea.value
    if (!file || !idea?.requires_upload) return

    uploadingIdeaAsset.value = true
    uploadingIdeaId.value = idea.id
    try {
      const payload = await uploadActionIdeaGzip(idea.id, file)
      const updated = payload.idea
      actionIdeas.value = actionIdeas.value.map((item) =>
        item.id === updated.id ? updated : item,
      )
      previewPayload.value = createActionIdeaPreviewPayload(updated)
      previewDraftTitle.value = updated.title
      previewDraftStatusCode.value = updated.status_code
      previewDraftContentType.value = updated.content_type
      previewDraftContent.value = updated.response_content
      previewSourceLabel.value = '动作方案 · 已保存自定义版本'
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '上传 gzip 文件失败'
    } finally {
      uploadingIdeaAsset.value = false
      uploadingIdeaId.value = ''
    }
  }

  onMounted(loadActionCenter)

  return {
    closePagePreview,
    closePreview,
    copyToClipboard,
    currentPreviewIdea,
    defaultRandomStatuses,
    deletePlugin,
    downloadingIdeaId,
    downloadGeneratedPlugin,
    editingPreviewTitle,
    error,
    funIdeaCards,
    installPlugin,
    installedPlugins,
    installingPlugin,
    isFakeSqlIdea,
    isFakeXssIdea,
    isInlineJsIdea,
    isRandomErrorIdea,
    isRedirectIdea,
    isTarpitIdea,
    loadActionCenter,
    loading,
    openGeneratedPreview,
    openPagePreview,
    openTemplatePreview,
    pagePreviewOpen,
    performanceClass,
    pluginsById,
    pluginTemplates,
    previewCanPagePreview,
    previewDirty,
    previewDraftContent,
    previewDraftContentType,
    previewDraftRandomFailureBody,
    previewDraftRandomStatuses,
    previewDraftRandomSuccessBody,
    previewDraftRandomSuccessRate,
    previewDraftSqlError,
    previewDraftSqlResult,
    previewDraftStatusCode,
    previewDraftTarpitBody,
    previewDraftTarpitBytesPerChunk,
    previewDraftTarpitIntervalMs,
    previewDraftTitle,
    previewDraftXssPayload,
    previewIsActionIdea,
    previewLoading,
    previewOpen,
    previewPayload,
    previewRandomErrorSummary,
    previewRenderedBody,
    previewResponse,
    previewSourceLabel,
    previewTitle,
    refreshing,
    saveActionIdeaPreview,
    savingIdea,
    templateCount,
    togglePluginStatus,
    uploadingIdeaAsset,
    uploadingIdeaId,
    uploadIdeaAsset,
  }
}

function previewResponse(template: RuleActionTemplateItem) {
  if (template.response_template.body_source === 'file') {
    return `文件响应 · ${template.response_template.body_file_path}`
  }
  return template.response_template.body_text.trim() || '内联文本响应'
}

function performanceClass(value: '低' | '中') {
  return value === '低'
    ? 'bg-emerald-100 text-emerald-700'
    : 'bg-amber-100 text-amber-700'
}

async function copyToClipboard(value: string) {
  await navigator.clipboard.writeText(value)
}

function isInlineJsIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'inline-js' || idea?.id === 'browser-fingerprint-js'
}

function isRedirectIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'redirect-302'
}

function isFakeSqlIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'fake-sql-echo'
}

function isFakeXssIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'fake-xss-echo'
}

function isTarpitIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'smart-tarpit'
}

function isRandomErrorIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'random-error-system'
}

function wrapRedirectContent(target: string, title: string) {
  const normalizedTarget = target.trim() || 'https://www.war.gov/'
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="refresh" content="0;url=${normalizedTarget}" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title || '302跳转'}</title>
  <style>
    body { font-family: sans-serif; background: #f8fafc; color: #0f172a; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { background: white; border-radius: 20px; padding: 32px; box-shadow: 0 20px 60px rgba(15, 23, 42, 0.12); max-width: 560px; }
    a { color: #2563eb; }
  </style>
</head>
<body>
  <main class="card">
    <h1>${title || '302跳转'}</h1>
    <p>正在跳转到 <a href="${normalizedTarget}">${normalizedTarget}</a>。</p>
  </main>
</body>
</html>`
}

function wrapFakeSqlContent(sqlError: string, sqlResult: string) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Database Result</title>
  <style>
    body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0f172a; color: #e2e8f0; padding: 32px; }
    .panel { max-width: 920px; margin: 0 auto; background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 24px; box-shadow: 0 16px 48px rgba(15, 23, 42, 0.35); }
    .error { color: #fca5a5; white-space: pre-wrap; }
    .result { margin-top: 18px; padding: 16px; border-radius: 12px; background: #020617; border: 1px solid #1e293b; color: #93c5fd; }
  </style>
</head>
<body>
  <main class="panel">
    <div class="error">${sqlError || defaultFakeSqlError}</div>
    <div class="result">${sqlResult || defaultFakeSqlResult}</div>
  </main>
</body>
</html>`
}

function wrapFakeXssContent(payload: string) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Preview</title>
  <style>
    body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #111827; color: #e5e7eb; padding: 32px; }
    .panel { max-width: 920px; margin: 0 auto; background: #0f172a; border: 1px solid #334155; border-radius: 16px; padding: 24px; }
    .hint { color: #93c5fd; margin-bottom: 12px; }
    .echo { border-radius: 12px; padding: 16px; background: #020617; border: 1px solid #1e293b; white-space: pre-wrap; color: #fca5a5; }
  </style>
</head>
<body>
  <main class="panel">
    <div class="hint">payload reflected successfully</div>
    <div class="echo">${payload || defaultFakeXssPayload}</div>
  </main>
</body>
</html>`
}

function decodeHtmlEntities(value: string) {
  return value
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&amp;', '&')
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function extractTarpitConfig(content: string) {
  try {
    const parsed = JSON.parse(content) as {
      bytes_per_chunk?: number
      chunk_interval_ms?: number
      body_text?: string
    }
    return {
      bytesPerChunk:
        Number.isFinite(parsed.bytes_per_chunk) &&
        (parsed.bytes_per_chunk ?? 0) > 0
          ? Math.floor(parsed.bytes_per_chunk as number)
          : 1,
      intervalMs:
        Number.isFinite(parsed.chunk_interval_ms) &&
        (parsed.chunk_interval_ms ?? 0) > 0
          ? Math.floor(parsed.chunk_interval_ms as number)
          : 1000,
      bodyText: parsed.body_text?.trim() || defaultTarpitBody,
    }
  } catch {
    return {
      bytesPerChunk: 1,
      intervalMs: 1000,
      bodyText: content.trim() || defaultTarpitBody,
    }
  }
}

function serializeTarpitConfig(
  bytesPerChunk: number,
  intervalMs: number,
  bodyText: string,
) {
  return JSON.stringify({
    bytes_per_chunk: bytesPerChunk,
    chunk_interval_ms: intervalMs,
    body_text: bodyText,
  })
}

function parseRandomStatuses(value: string) {
  return value
    .split(',')
    .map((item) => Number(item.trim()))
    .filter(
      (item) => Number.isInteger(item) && item >= 100 && item <= 599 && item !== 200,
    )
}

function extractRandomErrorConfig(content: string) {
  try {
    const parsed = JSON.parse(content) as {
      failure_statuses?: number[]
      success_rate_percent?: number
      success_body?: string
      failure_body?: string
    }
    const statuses = Array.isArray(parsed.failure_statuses)
      ? parsed.failure_statuses
          .map((item) => Number(item))
          .filter(
            (item) =>
              Number.isInteger(item) && item >= 100 && item <= 599 && item !== 200,
          )
      : []
    return {
      statuses: statuses.length ? statuses.join(',') : defaultRandomStatuses,
      successRate:
        Number.isFinite(parsed.success_rate_percent) &&
        (parsed.success_rate_percent ?? -1) >= 0
          ? Math.min(
              100,
              Math.max(0, Math.floor(parsed.success_rate_percent as number)),
            )
          : defaultRandomSuccessRate,
      successBody: parsed.success_body?.trim() || defaultRandomSuccessBody,
      failureBody: parsed.failure_body?.trim() || defaultRandomFailureBody,
    }
  } catch {
    return {
      statuses: defaultRandomStatuses,
      successRate: defaultRandomSuccessRate,
      successBody: defaultRandomSuccessBody,
      failureBody: content.trim() || defaultRandomFailureBody,
    }
  }
}

function serializeRandomErrorConfig(
  statuses: string,
  successRate: number,
  successBody: string,
  failureBody: string,
) {
  return JSON.stringify({
    failure_statuses: parseRandomStatuses(statuses),
    success_rate_percent: successRate,
    success_body: successBody,
    failure_body: failureBody,
  })
}

function extractFakeSqlFields(content: string) {
  const errorMatch = content.match(/<div class="error">([\s\S]*?)<\/div>/)
  const resultMatch = content.match(/<div class="result">([\s\S]*?)<\/div>/)
  return {
    error:
      decodeHtmlEntities(errorMatch?.[1] ?? '').trim() || defaultFakeSqlError,
    result:
      decodeHtmlEntities(resultMatch?.[1] ?? '').trim() || defaultFakeSqlResult,
  }
}

function extractFakeXssPayload(content: string) {
  const payloadMatch = content.match(/<div class="echo">([\s\S]*?)<\/div>/)
  return (
    decodeHtmlEntities(payloadMatch?.[1] ?? '').trim() || defaultFakeXssPayload
  )
}

function wrapInlineJsContent(script: string, title: string) {
  return `<!doctype html>
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
}

function createActionIdeaPreviewPayload(idea: ActionIdeaPreset) {
  return {
    template_id: `${idea.plugin_id}:${idea.template_local_id}`,
    name: idea.title,
    content_type: idea.content_type,
    status_code: idea.status_code,
    gzip: idea.gzip,
    body_source: idea.body_source,
    body_preview: idea.requires_upload
      ? `已上传文件：${idea.uploaded_file_name || '未上传 gzip 文件'}`
      : isRedirectIdea(idea)
        ? wrapRedirectContent(idea.response_content, idea.title)
        : isInlineJsIdea(idea)
          ? wrapInlineJsContent(idea.response_content, idea.title)
          : idea.response_content,
    truncated: false,
  } satisfies RuleActionTemplatePreviewResponse
}
