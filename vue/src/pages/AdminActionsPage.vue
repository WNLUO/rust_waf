<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { Check, Copy, PencilLine, Plus, RefreshCw, X } from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import AdminRulesPluginSection from '../components/rules/AdminRulesPluginSection.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import {
  fetchActionIdeaPresets,
  deleteRuleActionPlugin,
  fetchRuleActionTemplatePreview,
  fetchRuleActionPlugins,
  fetchRuleActionTemplates,
  uploadActionIdeaGzip,
  updateActionIdeaPreset,
  updateRuleActionPlugin,
  uploadRuleActionPlugin,
} from '../lib/api'
import type {
  ActionIdeaPreset,
  RuleActionPluginItem,
  RuleActionTemplatePreviewResponse,
  RuleActionTemplateItem,
} from '../lib/types'

const loading = ref(true)
const refreshing = ref(false)
const installingPlugin = ref(false)
const savingIdea = ref(false)
const uploadingIdeaAsset = ref(false)
const error = ref('')
const installedPlugins = ref<RuleActionPluginItem[]>([])
const pluginTemplates = ref<RuleActionTemplateItem[]>([])
const actionIdeas = ref<ActionIdeaPreset[]>([])
const pluginFileInput = ref<HTMLInputElement | null>(null)
const actionIdeaFileInput = ref<HTMLInputElement | null>(null)
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
const previewDraftRandomStatuses = ref('500,502,403')
const previewDraftRandomSuccessRate = ref(25)
const previewDraftRandomSuccessBody = ref('')
const previewDraftRandomFailureBody = ref('')
const pagePreviewOpen = ref(false)
const downloadingIdeaId = ref('')
const uploadingIdeaId = ref('')

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

const templateCount = computed(() => pluginTemplates.value.length)
const pluginsById = computed(() =>
  new Map(installedPlugins.value.map((item) => [item.plugin_id, item])),
)
const actionIdeasById = computed(
  () => new Map(actionIdeas.value.map((item) => [item.id, item])),
)

const funIdeaCards = computed(() =>
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

const handleInstallPlugin = async (file: File) => {
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

const openPluginPicker = () => {
  if (installingPlugin.value) return
  pluginFileInput.value?.click()
}

const handlePluginFilePicked = async (event: Event) => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0] ?? null
  input.value = ''
  if (!file) return
  await handleInstallPlugin(file)
}

const togglePluginStatus = async (plugin: RuleActionPluginItem) => {
  try {
    await updateRuleActionPlugin(plugin.plugin_id, !plugin.enabled)
    await loadActionCenter()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新插件状态失败'
  }
}

const handleDeletePlugin = async (pluginId: string) => {
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

const previewResponse = (template: RuleActionTemplateItem) => {
  if (template.response_template.body_source === 'file') {
    return `文件响应 · ${template.response_template.body_file_path}`
  }
  return template.response_template.body_text.trim() || '内联文本响应'
}

const performanceClass = (value: '低' | '中') =>
  value === '低'
    ? 'bg-emerald-100 text-emerald-700'
    : 'bg-amber-100 text-amber-700'

const copyToClipboard = async (value: string) => {
  await navigator.clipboard.writeText(value)
}

const isInlineJsIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'inline-js' || idea?.id === 'browser-fingerprint-js'

const isRedirectIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'redirect-302'

const isFakeSqlIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'fake-sql-echo'

const isFakeXssIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'fake-xss-echo'

const isTarpitIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'smart-tarpit'

const isRandomErrorIdea = (idea: ActionIdeaPreset | null | undefined) =>
  idea?.id === 'random-error-system'

const wrapRedirectContent = (target: string, title: string) => {
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

const wrapFakeSqlContent = (sqlError: string, sqlResult: string) => `<!doctype html>
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

const wrapFakeXssContent = (payload: string) => `<!doctype html>
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

const decodeHtmlEntities = (value: string) =>
  value
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&amp;', '&')

const escapeHtml = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')

const extractTarpitConfig = (content: string) => {
  try {
    const parsed = JSON.parse(content) as {
      bytes_per_chunk?: number
      chunk_interval_ms?: number
      body_text?: string
    }
    return {
      bytesPerChunk:
        Number.isFinite(parsed.bytes_per_chunk) && (parsed.bytes_per_chunk ?? 0) > 0
          ? Math.floor(parsed.bytes_per_chunk as number)
          : 1,
      intervalMs:
        Number.isFinite(parsed.chunk_interval_ms) && (parsed.chunk_interval_ms ?? 0) > 0
          ? Math.floor(parsed.chunk_interval_ms as number)
          : 1000,
      bodyText:
        parsed.body_text?.trim() || defaultTarpitBody,
    }
  } catch {
    return {
      bytesPerChunk: 1,
      intervalMs: 1000,
      bodyText: content.trim() || defaultTarpitBody,
    }
  }
}

const serializeTarpitConfig = (bytesPerChunk: number, intervalMs: number, bodyText: string) =>
  JSON.stringify({
    bytes_per_chunk: bytesPerChunk,
    chunk_interval_ms: intervalMs,
    body_text: bodyText,
  })

const parseRandomStatuses = (value: string) =>
  value
    .split(',')
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isInteger(item) && item >= 100 && item <= 599 && item !== 200)

const extractRandomErrorConfig = (content: string) => {
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
          .filter((item) => Number.isInteger(item) && item >= 100 && item <= 599 && item !== 200)
      : []
    return {
      statuses: statuses.length ? statuses.join(',') : defaultRandomStatuses,
      successRate:
        Number.isFinite(parsed.success_rate_percent) && (parsed.success_rate_percent ?? -1) >= 0
          ? Math.min(100, Math.max(0, Math.floor(parsed.success_rate_percent as number)))
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

const serializeRandomErrorConfig = (
  statuses: string,
  successRate: number,
  successBody: string,
  failureBody: string,
) =>
  JSON.stringify({
    failure_statuses: parseRandomStatuses(statuses),
    success_rate_percent: successRate,
    success_body: successBody,
    failure_body: failureBody,
  })

const extractFakeSqlFields = (content: string) => {
  const errorMatch = content.match(/<div class="error">([\s\S]*?)<\/div>/)
  const resultMatch = content.match(/<div class="result">([\s\S]*?)<\/div>/)
  return {
    error: decodeHtmlEntities(errorMatch?.[1] ?? '').trim() || defaultFakeSqlError,
    result: decodeHtmlEntities(resultMatch?.[1] ?? '').trim() || defaultFakeSqlResult,
  }
}

const extractFakeXssPayload = (content: string) => {
  const payloadMatch = content.match(/<div class="echo">([\s\S]*?)<\/div>/)
  return decodeHtmlEntities(payloadMatch?.[1] ?? '').trim() || defaultFakeXssPayload
}

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

const createActionIdeaPreviewPayload = (
  idea: ActionIdeaPreset,
): RuleActionTemplatePreviewResponse => ({
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
})

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
    previewPayload.value = await fetchRuleActionTemplatePreview(template.template_id)
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
    previewDraftXssPayload.value = extractFakeXssPayload(idea.response_content)
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
    error.value = '响应Gzip 需要先在预览弹窗里上传 gzip 文件，不提供本地样例下载。'
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
        ? wrapFakeXssContent(extractFakeXssPayload(idea.response_content))
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

const currentPreviewIdea = computed(() =>
  previewIdeaId.value ? actionIdeasById.value.get(previewIdeaId.value) ?? null : null,
)

const previewIsActionIdea = computed(() => Boolean(currentPreviewIdea.value))

const previewRenderedBody = computed(() =>
  previewIsActionIdea.value
    ? currentPreviewIdea.value && isInlineJsIdea(currentPreviewIdea.value)
      ? wrapInlineJsContent(previewDraftContent.value, previewDraftTitle.value || previewTitle.value)
      : currentPreviewIdea.value && isRedirectIdea(currentPreviewIdea.value)
        ? wrapRedirectContent(previewDraftContent.value, previewDraftTitle.value || previewTitle.value)
      : currentPreviewIdea.value && isFakeSqlIdea(currentPreviewIdea.value)
        ? wrapFakeSqlContent(
            escapeHtml(previewDraftSqlError.value.trim() || defaultFakeSqlError),
            escapeHtml(previewDraftSqlResult.value.trim() || defaultFakeSqlResult),
          )
      : currentPreviewIdea.value && isFakeXssIdea(currentPreviewIdea.value)
        ? wrapFakeXssContent(escapeHtml(previewDraftXssPayload.value.trim() || defaultFakeXssPayload))
      : currentPreviewIdea.value && isTarpitIdea(currentPreviewIdea.value)
        ? previewDraftTarpitBody.value.trim() || defaultTarpitBody
      : currentPreviewIdea.value && isRandomErrorIdea(currentPreviewIdea.value)
        ? `失败状态码: ${parseRandomStatuses(previewDraftRandomStatuses.value).join(', ') || defaultRandomStatuses}\n成功概率: ${previewDraftRandomSuccessRate.value}%\n\n失败文案:\n${previewDraftRandomFailureBody.value.trim() || defaultRandomFailureBody}\n\n成功文案:\n${previewDraftRandomSuccessBody.value.trim() || defaultRandomSuccessBody}`
      : previewDraftContent.value
    : (previewPayload.value?.body_preview ?? ''),
)

const previewRandomErrorSummary = computed(() => ({
  statuses: parseRandomStatuses(previewDraftRandomStatuses.value),
  successRate: Math.min(100, Math.max(0, Math.floor(previewDraftRandomSuccessRate.value || 0))),
  successBody: previewDraftRandomSuccessBody.value.trim() || defaultRandomSuccessBody,
  failureBody: previewDraftRandomFailureBody.value.trim() || defaultRandomFailureBody,
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
            escapeHtml(previewDraftSqlError.value.trim() || defaultFakeSqlError),
            escapeHtml(previewDraftSqlResult.value.trim() || defaultFakeSqlResult),
          ) !== idea.response_content
        : isFakeXssIdea(idea)
          ? wrapFakeXssContent(
              escapeHtml(previewDraftXssPayload.value.trim() || defaultFakeXssPayload),
            ) !== idea.response_content
          : isTarpitIdea(idea)
            ? serializeTarpitConfig(
                Math.max(1, Math.floor(previewDraftTarpitBytesPerChunk.value || 1)),
                Math.max(1, Math.floor(previewDraftTarpitIntervalMs.value || 1000)),
                previewDraftTarpitBody.value.trim() || defaultTarpitBody,
              ) !== idea.response_content
          : isRandomErrorIdea(idea)
            ? serializeRandomErrorConfig(
                previewDraftRandomStatuses.value,
                Math.min(100, Math.max(0, Math.floor(previewDraftRandomSuccessRate.value || 0))),
                previewDraftRandomSuccessBody.value.trim() || defaultRandomSuccessBody,
                previewDraftRandomFailureBody.value.trim() || defaultRandomFailureBody,
              ) !== idea.response_content
          : previewDraftContent.value !== idea.response_content))
  )
})

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
    if (!previewDraftSqlError.value.trim() || !previewDraftSqlResult.value.trim()) {
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
            Math.min(100, Math.max(0, Math.floor(previewDraftRandomSuccessRate.value))),
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
      previewDraftXssPayload.value = extractFakeXssPayload(updated.response_content)
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

const openActionIdeaAssetPicker = () => {
  if (!currentPreviewIdea.value?.requires_upload || uploadingIdeaAsset.value) return
  actionIdeaFileInput.value?.click()
}

const handleActionIdeaAssetPicked = async (event: Event) => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0] ?? null
  input.value = ''
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
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
        @click="loadActionCenter"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新动作库
      </button>
      <input
        ref="actionIdeaFileInput"
        type="file"
        accept=".gz,application/gzip,application/x-gzip"
        class="hidden"
        @change="handleActionIdeaAssetPicked"
      />
    </template>

    <div class="space-y-6">
      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <AdminRulesPluginSection
        :installed-plugins="installedPlugins"
        @delete-plugin="handleDeletePlugin"
        @toggle-plugin="togglePluginStatus"
      />

      <CyberCard
        title="模板动作"
        sub-title="当前已安装插件提供的现成动作模板，适合快速落地 respond 场景。"
      >
        <template #header-action>
          <input
            ref="pluginFileInput"
            type="file"
            accept=".zip,application/zip"
            class="hidden"
            @change="handlePluginFilePicked"
          />
          <button
            class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
            :disabled="installingPlugin"
            @click="openPluginPicker"
          >
            <Plus :size="14" />
            {{ installingPlugin ? '上传中...' : '上传动作插件' }}
          </button>
        </template>
        <div v-if="loading" class="flex h-32 items-center justify-center">
          <RefreshCw class="animate-spin text-blue-700" :size="24" />
        </div>
        <div
          v-else-if="!templateCount"
          class="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
        >
          当前还没有可用的模板动作。你可以先在本页安装动作插件，再回来浏览动作库。
        </div>
        <div v-else class="grid gap-4 xl:grid-cols-2">
          <article
            v-for="template in pluginTemplates"
            :key="template.template_id"
            class="rounded-[24px] border border-slate-200 bg-[linear-gradient(180deg,_rgba(255,255,255,0.96),_rgba(246,250,255,0.96))] p-5 shadow-sm"
          >
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p class="text-lg font-semibold text-slate-900">
                  {{ template.name }}
                </p>
                <p class="mt-1 text-sm text-slate-500">
                  来自
                  {{
                    pluginsById.get(template.plugin_id)?.name || template.plugin_id
                  }}
                </p>
              </div>
              <div class="flex flex-wrap gap-2 text-xs">
                <span class="rounded-full bg-blue-100 px-2.5 py-1 text-blue-700">
                  {{ template.layer.toUpperCase() }}
                </span>
                <span class="rounded-full bg-slate-100 px-2.5 py-1 text-slate-700">
                  {{ template.response_template.status_code }}
                </span>
                <span
                  class="rounded-full px-2.5 py-1"
                  :class="performanceClass('中')"
                >
                  gzip {{ template.response_template.gzip ? '开' : '关' }}
                </span>
              </div>
            </div>

            <p class="mt-4 text-sm leading-6 text-slate-600">
              {{ template.description || '这是一个可直接套用的响应动作模板。' }}
            </p>

            <div class="mt-4 grid gap-3 md:grid-cols-2">
              <div class="rounded-2xl bg-white px-4 py-3">
                <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
                  内容类型
                </p>
                <p class="mt-2 text-sm font-medium text-slate-800">
                  {{ template.response_template.content_type }}
                </p>
              </div>
              <div class="rounded-2xl bg-white px-4 py-3">
                <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
                  预设匹配
                </p>
                <p class="mt-2 font-mono text-xs text-slate-700">
                  {{ template.pattern }}
                </p>
              </div>
            </div>

            <div class="mt-4 rounded-2xl border border-slate-200 bg-white px-4 py-3">
              <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
                响应预览
              </p>
              <p class="mt-2 line-clamp-2 text-sm text-slate-700">
                {{ previewResponse(template) }}
              </p>
            </div>

            <div class="mt-4 flex flex-wrap gap-3">
              <RouterLink
                :to="`/admin/rules?template=${encodeURIComponent(template.template_id)}`"
                class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
              >
                去规则中心绑定
              </RouterLink>
              <RouterLink
                to="/admin/rules"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                查看规则中心
              </RouterLink>
              <button
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="openTemplatePreview(template)"
              >
                预览响应
              </button>
            </div>
          </article>
        </div>
      </CyberCard>

      <CyberCard
        title="动作方案"
        sub-title="围绕品牌呈现、通知提示、调试验证和对抗策略整理的可复用方案。能直接复用现有模板时，会优先给出最快路径。"
      >
        <div class="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(220px,1fr))] 2xl:[grid-template-columns:repeat(5,minmax(0,1fr))]">
          <article
            v-for="idea in funIdeaCards"
            :key="idea.id"
            class="relative flex min-h-[238px] h-full flex-col overflow-hidden rounded-[20px] border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,250,245,0.96),_rgba(245,250,255,0.96))] p-4 shadow-sm"
          >
            <div class="relative flex h-full flex-col">
              <div class="flex items-start justify-between gap-4">
                <h3 class="text-[17px] font-semibold leading-6 text-slate-900">
                  {{ idea.title }}
                </h3>
                <span
                  class="ml-auto shrink-0 rounded-full bg-stone-900 px-2.5 py-1 text-[11px] text-white"
                >
                  {{ idea.mood }}
                </span>
              </div>

              <div v-if="idea.template" class="mt-2 flex flex-wrap gap-1.5 text-[11px]">
                <span class="rounded-full bg-blue-100 px-2.5 py-1 text-blue-700">
                  可直接复用模板
                </span>
                <span
                  v-if="idea.requires_upload"
                  class="rounded-full bg-slate-100 px-2.5 py-1 text-slate-700"
                >
                  需上传 gzip
                </span>
                <span
                  v-if="idea.has_overrides"
                  class="rounded-full bg-amber-100 px-2.5 py-1 text-amber-700"
                >
                  已自定义
                </span>
              </div>

              <div class="mt-3 flex-1 rounded-2xl border border-white/80 bg-white/85 px-3 py-3">
                <p class="text-[11px] uppercase tracking-[0.14em] text-slate-400">
                  实现方式
                </p>
                <p class="mt-2 text-sm leading-6 text-slate-700">
                  {{ idea.mechanism }}
                </p>
                <div
                  v-if="idea.template"
                  class="mt-3 flex items-center gap-2 rounded-xl bg-blue-50 px-2.5 py-2"
                >
                  <span class="text-[11px] uppercase tracking-[0.12em] text-blue-500">
                    推荐模板
                  </span>
                  <span class="truncate text-xs font-medium text-blue-800">
                    {{ idea.template.name }}
                  </span>
                </div>
              </div>

              <div class="mt-3 grid grid-cols-2 gap-2">
                <button
                  class="inline-flex items-center justify-center gap-2 rounded-full bg-stone-900 px-3 py-2 text-xs font-medium text-white transition hover:bg-stone-800"
                  @click="openGeneratedPreview(idea)"
                >
                  预览动作
                </button>
                <button
                  class="inline-flex items-center justify-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  :disabled="idea.requires_upload"
                  @click="downloadGeneratedPlugin(idea.id)"
                >
                  {{
                    idea.requires_upload
                      ? '需在弹窗上传'
                      : downloadingIdeaId === idea.id
                        ? '打包中...'
                        : '下载插件样例'
                  }}
                </button>
              </div>
            </div>
          </article>
        </div>
      </CyberCard>
    </div>

    <div
      v-if="previewOpen"
      class="fixed inset-0 z-[100] overflow-y-auto px-4 py-6 md:py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closePreview"
      ></div>
      <div
        class="relative mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-5xl flex-col rounded-xl border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:min-h-[calc(100vh-4rem)] md:max-h-[calc(100vh-4rem)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">{{ previewSourceLabel }}</p>
            <div class="mt-2 flex items-center gap-3">
              <template v-if="previewIsActionIdea && editingPreviewTitle">
                <input
                  v-model="previewDraftTitle"
                  type="text"
                  class="w-full max-w-md rounded-xl border border-slate-200 bg-white px-3 py-2 text-xl font-semibold text-stone-900 outline-none transition focus:border-blue-500/50"
                />
                <button
                  class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
                  :disabled="savingIdea"
                  @click="saveActionIdeaPreview"
                >
                  <Check :size="18" />
                </button>
              </template>
              <template v-else>
                <h3 class="text-2xl font-semibold text-stone-900">
                  {{ previewIsActionIdea ? previewDraftTitle || previewTitle : previewTitle }}
                </h3>
                <button
                  v-if="previewIsActionIdea"
                  class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="editingPreviewTitle = true"
                >
                  <PencilLine :size="16" />
                </button>
              </template>
            </div>
          </div>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePreview"
          >
            <X :size="18" />
          </button>
        </div>

        <div v-if="previewLoading" class="flex flex-1 items-center justify-center">
          <RefreshCw class="animate-spin text-blue-700" :size="24" />
        </div>

        <template v-else-if="previewPayload">
          <div class="mt-4 flex min-h-0 flex-1 flex-col overflow-hidden">
            <div
              class="grid gap-3"
              :class="previewIsActionIdea ? 'md:grid-cols-2' : 'md:grid-cols-4'"
            >
              <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
                <p class="text-xs tracking-wide text-slate-500">状态码</p>
                <template v-if="previewIsActionIdea">
                  <input
                    v-model.number="previewDraftStatusCode"
                    type="number"
                    min="100"
                    max="599"
                    class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-lg font-semibold text-stone-900 outline-none transition focus:border-blue-500/50"
                  />
                </template>
                <p v-else class="mt-2 text-lg font-semibold text-stone-900">
                  {{ previewPayload.status_code }}
                </p>
              </div>
              <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
                <p class="text-xs tracking-wide text-slate-500">内容类型</p>
                <template v-if="previewIsActionIdea">
                  <input
                    v-model="previewDraftContentType"
                    type="text"
                    class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-stone-900 outline-none transition focus:border-blue-500/50"
                  />
                </template>
                <p v-else class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.content_type }}
                </p>
              </div>
              <div
                v-if="!previewIsActionIdea"
                class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3"
              >
                <p class="text-xs tracking-wide text-slate-500">Body 来源</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.body_source }}
                </p>
              </div>
              <div
                v-if="!previewIsActionIdea"
                class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3"
              >
                <p class="text-xs tracking-wide text-slate-500">gzip</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.gzip ? '开启' : '关闭' }}
                </p>
              </div>
            </div>

            <div class="mt-4 min-h-0 flex-1 overflow-y-auto pr-1">
                <div
                  v-if="previewIsActionIdea && currentPreviewIdea?.requires_upload"
                  class="rounded-xl border border-slate-200 bg-white/80 p-5"
                >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="text-xs tracking-wide text-slate-500">Gzip 文件</p>
                    <p class="mt-2 text-sm text-stone-800">
                      {{
                        currentPreviewIdea.uploaded_file_name ||
                        '还没有上传 gzip 文件'
                      }}
                    </p>
                  </div>
                  <button
                    class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
                    :disabled="uploadingIdeaAsset"
                    @click="openActionIdeaAssetPicker"
                  >
                    <RefreshCw
                      v-if="uploadingIdeaAsset && uploadingIdeaId === currentPreviewIdea.id"
                      :size="14"
                      class="animate-spin"
                    />
                    {{
                      uploadingIdeaAsset && uploadingIdeaId === currentPreviewIdea.id
                        ? '上传中...'
                        : currentPreviewIdea.uploaded_file_ready
                          ? '重新上传 Gzip'
                          : '上传 Gzip 文件'
                    }}
                  </button>
                </div>
                <p class="mt-3 text-xs leading-6 text-slate-500">
                  这里上传的是已经压缩好的 `.gz` 文件。系统会把它保存在本地数据目录里，更新代码时不会覆盖。
                </p>
              </div>

              <div class="mt-4 rounded-xl border border-slate-200 bg-white/80 p-5">
                <div class="flex items-center justify-between gap-4">
                  <p class="text-xs tracking-wide text-slate-500">
                    {{
                      previewIsActionIdea && currentPreviewIdea?.requires_upload
                        ? '文件说明'
                        : '原始内容'
                    }}
                  </p>
                  <span
                    v-if="previewPayload.truncated"
                    class="rounded-full bg-amber-100 px-2.5 py-1 text-[11px] text-amber-700"
                  >
                    已截断
                  </span>
                </div>
                <div
                  v-if="previewIsActionIdea && !currentPreviewIdea?.requires_upload"
                  class="mt-3 space-y-3"
                >
                  <p
                    v-if="currentPreviewIdea && isInlineJsIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写的是纯 JavaScript 代码。系统会自动把它内嵌进一个正常 HTML 页面后再返回。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isRedirectIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写的是跳转目标 URL。系统会自动写入 `Location` 头，并返回一个 302 响应。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isFakeSqlIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里分别配置伪造的 SQL 错误文案和查询结果，让攻击者误以为注入已经成功。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isFakeXssIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写一个要被“假装反射”的 payload。系统会把它放进伪造的回显页面里。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isTarpitIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里配置慢速返回的节奏和拖延文案。保存后会按设定的字节数与间隔缓慢响应。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里配置失败状态码、成功概率和两套文案。运行时会随机决定这次请求是成功还是失败。
                  </p>
                  <div
                    v-if="currentPreviewIdea && isRedirectIdea(currentPreviewIdea)"
                    class="rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(248,250,252,0.96),_rgba(239,246,255,0.96))] p-4"
                  >
                    <label class="block text-xs tracking-wide text-slate-500">
                      跳转链接
                    </label>
                    <div
                      class="mt-3 flex items-center gap-3 rounded-2xl border border-blue-200 bg-white px-4 py-3 shadow-[0_10px_30px_rgba(37,99,235,0.08)]"
                    >
                      <span
                        class="shrink-0 rounded-full bg-blue-50 px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.14em] text-blue-700"
                      >
                        URL
                      </span>
                      <input
                        v-model="previewDraftContent"
                        type="url"
                        placeholder="https://www.war.gov/"
                        class="w-full bg-transparent text-sm text-stone-900 outline-none placeholder:text-slate-400"
                        spellcheck="false"
                        autocomplete="off"
                      />
                    </div>
                    <p class="mt-3 text-xs leading-6 text-slate-500">
                      支持填写完整的 `http://` 或 `https://` 地址。保存后命中规则会直接返回 302 跳转。
                    </p>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isFakeSqlIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,250,245,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        错误文案
                      </label>
                      <textarea
                        v-model="previewDraftSqlError"
                        class="mt-3 min-h-32 w-full rounded-2xl border border-rose-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-rose-400/70"
                        placeholder="SQL syntax error near '...'"
                      ></textarea>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        伪结果
                      </label>
                      <input
                        v-model="previewDraftSqlResult"
                        type="text"
                        class="mt-3 w-full rounded-2xl border border-sky-200 bg-white px-4 py-3 font-mono text-sm text-stone-900 outline-none transition focus:border-sky-400/70"
                        placeholder="query result: admin | hash | role"
                      />
                    </div>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isFakeXssIdea(currentPreviewIdea)"
                    class="rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(248,250,252,0.96),_rgba(255,245,245,0.96))] p-4"
                  >
                    <label class="block text-xs tracking-wide text-slate-500">
                      回显 payload
                    </label>
                    <div
                      class="mt-3 rounded-2xl border border-amber-200 bg-white px-4 py-3 shadow-[0_10px_30px_rgba(245,158,11,0.08)]"
                    >
                      <input
                        v-model="previewDraftXssPayload"
                        type="text"
                        class="w-full bg-transparent font-mono text-sm text-stone-900 outline-none placeholder:text-slate-400"
                        placeholder="<script>alert('xss')</script>"
                        spellcheck="false"
                        autocomplete="off"
                      />
                    </div>
                    <p class="mt-3 text-xs leading-6 text-slate-500">
                      这个 payload 会被编码后嵌进预览页，用来制造“已经被页面反射”的假象。
                    </p>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isTarpitIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(240,253,244,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div class="grid gap-4 md:grid-cols-2">
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          每次发送字节数
                        </label>
                        <input
                          v-model.number="previewDraftTarpitBytesPerChunk"
                          type="number"
                          min="1"
                          class="mt-3 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-emerald-400/70"
                        />
                      </div>
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          每次间隔毫秒
                        </label>
                        <input
                          v-model.number="previewDraftTarpitIntervalMs"
                          type="number"
                          min="1"
                          step="100"
                          class="mt-3 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-emerald-400/70"
                        />
                      </div>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        拖延文案
                      </label>
                      <textarea
                        v-model="previewDraftTarpitBody"
                        class="mt-3 min-h-28 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-emerald-400/70"
                        placeholder="processing request, please wait..."
                      ></textarea>
                    </div>
                    <p class="text-xs leading-6 text-slate-500">
                      例如 `1` 字节 + `1000ms` 间隔，配合 30 多字节正文，就会把一次请求拖到 30 秒以上。
                    </p>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,247,237,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div class="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          失败状态码列表
                        </label>
                        <input
                          v-model="previewDraftRandomStatuses"
                          type="text"
                          class="mt-3 w-full rounded-2xl border border-amber-200 bg-white px-4 py-3 font-mono text-sm text-stone-900 outline-none transition focus:border-amber-400/70"
                          placeholder="500,502,403"
                        />
                      </div>
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          成功概率（%）
                        </label>
                        <input
                          v-model.number="previewDraftRandomSuccessRate"
                          type="number"
                          min="0"
                          max="100"
                          class="mt-3 w-full rounded-2xl border border-amber-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-amber-400/70"
                        />
                      </div>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        成功文案
                      </label>
                      <textarea
                        v-model="previewDraftRandomSuccessBody"
                        class="mt-3 min-h-24 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-emerald-400/70"
                        placeholder="request completed successfully"
                      ></textarea>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        失败文案
                      </label>
                      <textarea
                        v-model="previewDraftRandomFailureBody"
                        class="mt-3 min-h-28 w-full rounded-2xl border border-rose-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-rose-400/70"
                        placeholder="upstream system unstable, retry later"
                      ></textarea>
                    </div>
                    <p class="text-xs leading-6 text-slate-500">
                      失败时会从你填写的状态码里随机挑一个；成功时固定返回 `200` 和成功文案。
                    </p>
                  </div>
                  <textarea
                    v-else
                    v-model="previewDraftContent"
                    class="min-h-[min(42vh,28rem)] w-full rounded-xl border border-slate-200 bg-white px-3 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-blue-500/50"
                  ></textarea>
                </div>
                <div
                  v-else-if="previewIsActionIdea && currentPreviewIdea?.requires_upload"
                  class="mt-3 rounded-xl border border-dashed border-slate-200 bg-slate-50 px-4 py-4 text-sm leading-6 text-slate-600"
                >
                  这个动作不会编辑文本内容，而是直接返回你上传的 gzip 文件。
                  <br />
                  建议配合合适的 `内容类型` 使用，例如 `text/html; charset=utf-8` 或 `application/json`。
                </div>
                <div
                  v-else-if="previewIsActionIdea && currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                  class="mt-3 grid gap-4"
                >
                  <div class="grid gap-3 md:grid-cols-3">
                    <div class="rounded-2xl border border-amber-200 bg-amber-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-amber-700">可能失败状态</p>
                      <p class="mt-2 font-mono text-lg font-semibold text-stone-900">
                        {{ previewRandomErrorSummary.statuses.join(', ') || defaultRandomStatuses }}
                      </p>
                    </div>
                    <div class="rounded-2xl border border-emerald-200 bg-emerald-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-emerald-700">成功概率</p>
                      <p class="mt-2 text-lg font-semibold text-stone-900">
                        {{ previewRandomErrorSummary.successRate }}%
                      </p>
                    </div>
                    <div class="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-slate-500">运行效果</p>
                      <p class="mt-2 text-sm leading-6 text-stone-700">
                        同一路径会呈现时好时坏的故障感，干扰攻击者判断。
                      </p>
                    </div>
                  </div>
                  <div class="grid gap-4 md:grid-cols-2">
                    <div class="rounded-2xl border border-rose-200 bg-white px-5 py-4 shadow-sm">
                      <div class="flex items-center justify-between gap-3">
                        <p class="text-sm font-medium text-stone-900">失败响应示意</p>
                        <span class="rounded-full bg-rose-100 px-2.5 py-1 text-xs font-medium text-rose-700">
                          {{ previewRandomErrorSummary.statuses[0] ?? 500 }}
                        </span>
                      </div>
                      <pre class="mt-4 whitespace-pre-wrap break-all font-mono text-sm leading-6 text-stone-800">{{ previewRandomErrorSummary.failureBody }}</pre>
                    </div>
                    <div class="rounded-2xl border border-emerald-200 bg-white px-5 py-4 shadow-sm">
                      <div class="flex items-center justify-between gap-3">
                        <p class="text-sm font-medium text-stone-900">成功响应示意</p>
                        <span class="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700">
                          200
                        </span>
                      </div>
                      <pre class="mt-4 whitespace-pre-wrap break-all font-mono text-sm leading-6 text-stone-800">{{ previewRandomErrorSummary.successBody }}</pre>
                    </div>
                  </div>
                </div>
                <pre
                  v-else
                  class="mt-3 max-h-[min(48vh,32rem)] overflow-auto whitespace-pre-wrap break-all font-mono text-sm leading-7 text-stone-800"
                >{{ previewRenderedBody }}</pre>
              </div>
            </div>

            <div class="mt-4 flex flex-wrap gap-3">
              <button
                v-if="!currentPreviewIdea?.requires_upload"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="copyToClipboard(previewRenderedBody)"
              >
                <Copy :size="14" />
                复制内容
              </button>
              <button
                v-if="previewIsActionIdea"
                class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
                :disabled="savingIdea || !previewDirty"
                @click="saveActionIdeaPreview"
              >
                <RefreshCw v-if="savingIdea" :size="14" class="animate-spin" />
                {{ savingIdea ? '保存中...' : '保存修改' }}
              </button>
              <button
                v-if="previewCanPagePreview"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="openPagePreview"
              >
                页面预览
              </button>
              <button
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="closePreview"
              >
                关闭
              </button>
            </div>
          </div>
        </template>
      </div>
    </div>

    <div
      v-if="pagePreviewOpen"
      class="fixed inset-0 z-[110] overflow-y-auto px-4 py-6 md:py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/45 backdrop-blur-sm"
        @click="closePagePreview"
      ></div>
      <div
        class="relative mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-6xl flex-col rounded-xl border border-white/85 bg-white p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:min-h-[calc(100vh-4rem)] md:max-h-[calc(100vh-4rem)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">页面预览</p>
            <h3 class="mt-2 text-2xl font-semibold text-stone-900">
              {{ previewIsActionIdea ? previewDraftTitle || previewTitle : previewTitle }}
            </h3>
          </div>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePagePreview"
          >
            <X :size="18" />
          </button>
        </div>

        <div class="mt-4 min-h-0 flex-1 overflow-hidden rounded-xl border border-slate-200 bg-white">
          <iframe
            class="h-full min-h-[70vh] w-full bg-white"
            :srcdoc="previewRenderedBody"
          ></iframe>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
