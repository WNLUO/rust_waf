import type {
  ActionIdeaPreset,
  RuleResponseTemplate,
  RuleActionTemplateItem,
  RuleActionTemplatePreviewResponse,
} from '@/shared/types'
import {
  isInlineJsIdea,
  isRedirectIdea,
  isTarpitIdea,
} from './actionIdeaPredicates'

export interface ActionIdeaCard extends ActionIdeaPreset {
  template: RuleActionTemplateItem | null
  ctaPath: string
}

export const defaultFakeSqlError =
  "SQL syntax error near '\\'' at line 1\nWarning: mysql_fetch_assoc() expects parameter 1 to be resource, boolean given in /var/www/html/search.php on line 42"
export const defaultFakeSqlResult =
  'query result: admin | 5f4dcc3b5aa765d61d8327deb882cf99 | super_admin'
export const defaultFakeXssPayload = "<script>alert('xss')<\\/script>"
export const defaultTarpitBody = 'processing request, please wait...'
export const defaultRandomStatuses = '500,502,403'
export const defaultRandomSuccessRate = 25
export const defaultRandomSuccessBody = 'request completed successfully'
export const defaultRandomFailureBody = 'upstream system unstable, retry later'

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

export function toActionIdeaCards(
  actionIdeas: ActionIdeaPreset[],
  pluginTemplates: RuleActionTemplateItem[],
): ActionIdeaCard[] {
  return actionIdeas.map((idea) => {
    const templateMatcher = ideaTemplateMatchers[idea.id] ?? (() => null)
    const template = templateMatcher(pluginTemplates)
    return {
      ...idea,
      template,
      ctaPath: template
        ? `/admin/rules?template=${encodeURIComponent(template.template_id)}`
        : idea.fallback_path,
    }
  })
}

export function previewResponse(template: RuleActionTemplateItem) {
  if (template.response_template.body_source === 'file') {
    return `文件响应 · ${template.response_template.body_file_path}`
  }
  return template.response_template.body_text.trim() || '内联文本响应'
}

export function performanceClass(value: '低' | '中') {
  return value === '低'
    ? 'bg-emerald-100 text-emerald-700'
    : 'bg-amber-100 text-amber-700'
}

export async function copyToClipboard(value: string) {
  await navigator.clipboard.writeText(value)
}

export function wrapRedirectContent(target: string, title: string) {
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

export function wrapFakeSqlContent(sqlError: string, sqlResult: string) {
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

export function wrapFakeXssContent(payload: string) {
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

export function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

export function extractTarpitConfig(content: string) {
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

export function serializeTarpitConfig(
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

export function parseRandomStatuses(value: string) {
  return value
    .split(',')
    .map((item) => Number(item.trim()))
    .filter(
      (item) =>
        Number.isInteger(item) && item >= 100 && item <= 599 && item !== 200,
    )
}

export function extractRandomErrorConfig(content: string) {
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
              Number.isInteger(item) &&
              item >= 100 &&
              item <= 599 &&
              item !== 200,
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

export function serializeRandomErrorConfig(
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

export function extractFakeSqlFields(content: string) {
  const errorMatch = content.match(/<div class="error">([\s\S]*?)<\/div>/)
  const resultMatch = content.match(/<div class="result">([\s\S]*?)<\/div>/)
  return {
    error:
      decodeHtmlEntities(errorMatch?.[1] ?? '').trim() || defaultFakeSqlError,
    result:
      decodeHtmlEntities(resultMatch?.[1] ?? '').trim() || defaultFakeSqlResult,
  }
}

export function extractFakeXssPayload(content: string) {
  const payloadMatch = content.match(/<div class="echo">([\s\S]*?)<\/div>/)
  return (
    decodeHtmlEntities(payloadMatch?.[1] ?? '').trim() || defaultFakeXssPayload
  )
}

export function wrapInlineJsContent(script: string, title: string) {
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
  </script>
</body>
</html>`
}

export function buildActionIdeaInlineResponseBody(idea: ActionIdeaPreset) {
  if (isRedirectIdea(idea)) {
    return wrapRedirectContent(idea.response_content, idea.title)
  }
  if (isInlineJsIdea(idea)) {
    return wrapInlineJsContent(idea.response_content, idea.title)
  }
  if (isTarpitIdea(idea)) {
    return extractTarpitConfig(idea.response_content).bodyText
  }
  return idea.response_content
}

export function buildActionIdeaPreviewBody(idea: ActionIdeaPreset) {
  if (idea.requires_upload) {
    return (
      idea.uploaded_body_preview?.trim() ||
      idea.uploaded_body_preview_notice?.trim() ||
      `已上传文件：${idea.uploaded_file_name || '未上传 gzip 文件'}`
    )
  }
  return buildActionIdeaInlineResponseBody(idea)
}

export function buildActionIdeaResponseTemplate(
  idea: ActionIdeaPreset,
): RuleResponseTemplate {
  return {
    status_code: idea.status_code,
    content_type: idea.content_type,
    body_source: idea.body_source,
    gzip: idea.gzip,
    body_text:
      idea.body_source === 'inline_text'
        ? buildActionIdeaInlineResponseBody(idea)
        : '',
    body_file_path:
      idea.body_source === 'file' ? idea.runtime_body_file_path : '',
    headers: idea.headers,
  }
}

export function createActionIdeaPreviewPayload(idea: ActionIdeaPreset) {
  return {
    template_id: `${idea.plugin_id}:${idea.template_local_id}`,
    name: idea.title,
    content_type: idea.content_type,
    status_code: idea.status_code,
    gzip: idea.gzip,
    body_source: idea.body_source,
    body_preview: buildActionIdeaPreviewBody(idea),
    truncated: idea.requires_upload ? idea.uploaded_body_truncated : false,
  } satisfies RuleActionTemplatePreviewResponse
}
