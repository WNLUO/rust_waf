import { computed, ref, type ComputedRef, type Ref } from 'vue'
import {
  fetchRuleActionTemplatePreview,
  updateActionIdeaPreset,
  uploadActionIdeaGzip,
} from '@/shared/api/rules'
import type {
  ActionIdeaPreset,
  RuleActionPluginItem,
  RuleActionTemplateItem,
  RuleActionTemplatePreviewResponse,
} from '@/shared/types'
import {
  buildActionIdeaInlineResponseBody,
  buildActionIdeaPreviewBody,
  copyToClipboard,
  createActionIdeaPreviewPayload,
  defaultFakeSqlError,
  defaultFakeSqlResult,
  defaultFakeXssPayload,
  defaultRandomFailureBody,
  defaultRandomStatuses,
  defaultRandomSuccessBody,
  defaultRandomSuccessRate,
  defaultTarpitBody,
  escapeHtml,
  extractFakeSqlFields,
  extractFakeXssPayload,
  extractRandomErrorConfig,
  extractTarpitConfig,
  parseRandomStatuses,
  performanceClass,
  previewResponse,
  serializeRandomErrorConfig,
  serializeTarpitConfig,
  wrapFakeSqlContent,
  wrapFakeXssContent,
  wrapInlineJsContent,
  wrapRedirectContent,
} from '@/features/actions/utils/actionIdeaPreview'
import {
  isFakeSqlIdea,
  isFakeXssIdea,
  isInlineJsIdea,
  isRandomErrorIdea,
  isRedirectIdea,
  isTarpitIdea,
} from '@/features/actions/utils/actionIdeaPredicates'

interface UseAdminActionPreviewOptions {
  actionIdeas: Ref<ActionIdeaPreset[]>
  actionIdeasById: ComputedRef<Map<string, ActionIdeaPreset>>
  error: Ref<string>
  pluginsById: ComputedRef<Map<string, RuleActionPluginItem>>
}

export function useAdminActionPreview({
  actionIdeas,
  actionIdeasById,
  error,
  pluginsById,
}: UseAdminActionPreviewOptions) {
  const savingIdea = ref(false)
  const uploadingIdeaAsset = ref(false)
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

  const currentPreviewIdea = computed(() =>
    previewIdeaId.value
      ? (actionIdeasById.value.get(previewIdeaId.value) ?? null)
      : null,
  )
  const previewIsActionIdea = computed(() => Boolean(currentPreviewIdea.value))

  const previewRenderedBody = computed(() =>
    previewIsActionIdea.value
      ? currentPreviewIdea.value?.requires_upload
        ? previewPayload.value?.body_preview ||
          buildActionIdeaPreviewBody(currentPreviewIdea.value)
        : currentPreviewIdea.value && isInlineJsIdea(currentPreviewIdea.value)
          ? wrapInlineJsContent(
              previewDraftContent.value,
              previewDraftTitle.value || previewTitle.value,
            )
          : currentPreviewIdea.value && isRedirectIdea(currentPreviewIdea.value)
            ? wrapRedirectContent(
                previewDraftContent.value,
                previewDraftTitle.value || previewTitle.value,
              )
            : currentPreviewIdea.value &&
                isFakeSqlIdea(currentPreviewIdea.value)
              ? wrapFakeSqlContent(
                  escapeHtml(
                    previewDraftSqlError.value.trim() || defaultFakeSqlError,
                  ),
                  escapeHtml(
                    previewDraftSqlResult.value.trim() || defaultFakeSqlResult,
                  ),
                )
              : currentPreviewIdea.value &&
                  isFakeXssIdea(currentPreviewIdea.value)
                ? wrapFakeXssContent(
                    escapeHtml(
                      previewDraftXssPayload.value.trim() ||
                        defaultFakeXssPayload,
                    ),
                  )
                : currentPreviewIdea.value &&
                    isTarpitIdea(currentPreviewIdea.value)
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
    if (idea?.requires_upload) {
      return (
        previewDraftContentType.value.includes('text/html') &&
        Boolean(idea.uploaded_body_preview?.trim())
      )
    }
    return (
      previewIsActionIdea.value
        ? previewDraftContentType.value
        : (previewPayload.value?.content_type ?? '')
    ).includes('text/html')
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

  function resetPreviewDrafts() {
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
  }

  function applyIdeaPreviewDrafts(idea: ActionIdeaPreset) {
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
  }

  const openTemplatePreview = async (template: RuleActionTemplateItem) => {
    previewLoading.value = true
    previewOpen.value = true
    previewIdeaId.value = ''
    resetPreviewDrafts()
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
    pagePreviewOpen.value = false
    applyIdeaPreviewDrafts(idea)
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
    resetPreviewDrafts()
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
        isFakeSqlIdea(idea)
          ? wrapFakeSqlContent(
              extractFakeSqlFields(idea.response_content).error,
              extractFakeSqlFields(idea.response_content).result,
            )
          : isFakeXssIdea(idea)
            ? wrapFakeXssContent(extractFakeXssPayload(idea.response_content))
            : isRandomErrorIdea(idea)
              ? idea.response_content
              : buildActionIdeaInlineResponseBody(idea),
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
          ? wrapFakeXssContent(escapeHtml(previewDraftXssPayload.value.trim()))
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
      applyIdeaPreviewDrafts(updated)
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
      applyIdeaPreviewDrafts(updated)
      previewSourceLabel.value = '动作方案 · 已保存自定义版本'
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '上传 gzip 文件失败'
    } finally {
      uploadingIdeaAsset.value = false
      uploadingIdeaId.value = ''
    }
  }

  return {
    closePagePreview,
    closePreview,
    copyToClipboard,
    currentPreviewIdea,
    defaultRandomStatuses,
    downloadingIdeaId,
    editingPreviewTitle,
    isFakeSqlIdea,
    isFakeXssIdea,
    isInlineJsIdea,
    isRandomErrorIdea,
    isRedirectIdea,
    isTarpitIdea,
    openGeneratedPreview,
    openPagePreview,
    openTemplatePreview,
    pagePreviewOpen,
    performanceClass,
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
    saveActionIdeaPreview,
    savingIdea,
    uploadIdeaAsset,
    uploadingIdeaAsset,
    uploadingIdeaId,
    downloadGeneratedPlugin,
  }
}
