<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import {
  Bot,
  Copy,
  FileJson,
  FileText,
  RefreshCw,
  Shield,
  Wand2,
  X,
} from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import AdminRulesPluginSection from '../components/rules/AdminRulesPluginSection.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import {
  deleteRuleActionPlugin,
  fetchRuleActionTemplatePreview,
  fetchRuleActionPlugins,
  fetchRuleActionTemplates,
  installRuleActionPlugin,
  updateRuleActionPlugin,
  uploadRuleActionPlugin,
} from '../lib/api'
import type {
  RuleActionPluginItem,
  RuleActionTemplatePreviewResponse,
  RuleActionTemplateItem,
} from '../lib/types'

type FunActionIdea = {
  id: string
  title: string
  mood: string
  summary: string
  mechanism: string
  performance: '低' | '中'
  fallbackPath: string
  templateMatcher: (templates: RuleActionTemplateItem[]) => RuleActionTemplateItem | null
}

type GeneratedPluginDefinition = {
  pluginId: string
  fileName: string
  manifest: Record<string, unknown>
  responseFilePath: string
  responseContent: string
  preview: RuleActionTemplatePreviewResponse
}

const loading = ref(true)
const refreshing = ref(false)
const installingPlugin = ref(false)
const error = ref('')
const installedPlugins = ref<RuleActionPluginItem[]>([])
const pluginTemplates = ref<RuleActionTemplateItem[]>([])
const pluginInstallUrl = ref('')
const pluginInstallFile = ref<File | null>(null)
const pluginInstallSha256 = ref('')
const previewOpen = ref(false)
const previewLoading = ref(false)
const previewTitle = ref('')
const previewSourceLabel = ref('')
const previewPayload = ref<RuleActionTemplatePreviewResponse | null>(null)
const downloadingIdeaId = ref('')

const funActionIdeas: FunActionIdea[] = [
  {
    id: 'brand-block',
    title: '品牌化拦截页',
    mood: '正式',
    summary: '把默认 403 升级为带品牌、联络入口和操作建议的页面。',
    mechanism: '优先复用 HTML 模板插件，没有模板时回退到自定义 respond。',
    performance: '中',
    fallbackPath: '/admin/rules',
    templateMatcher: (templates) =>
      templates.find(
        (item) =>
          item.response_template.content_type.includes('text/html') ||
          item.name.includes('HTML'),
      ) ?? null,
  },
  {
    id: 'json-honeypot',
    title: 'JSON 蜜罐响应',
    mood: '迷惑',
    summary: '对扫描器返回结构化 JSON，让自动化攻击以为请求成功。',
    mechanism: '优先复用 JSON 插件模板，没有模板时用自定义 respond 构造。',
    performance: '中',
    fallbackPath: '/admin/rules',
    templateMatcher: (templates) =>
      templates.find((item) =>
        item.response_template.content_type.includes('application/json'),
      ) ?? null,
  },
  {
    id: 'debug-echo',
    title: '调试回显页',
    mood: '调试',
    summary: '做一个简化回显页，用来验证规则是否按预期命中。',
    mechanism: '通过自定义 respond 快速搭一个内联文本或 HTML 页面。',
    performance: '中',
    fallbackPath: '/admin/rules',
    templateMatcher: () => null,
  },
  {
    id: 'scanner-misdirection',
    title: '扫描器误导页',
    mood: '对抗',
    summary: '给自动化工具返回静态成功页或伪接口数据，降低即时反馈。',
    mechanism: '推荐用 HTML 或 JSON 模板动作来做低成本误导。',
    performance: '中',
    fallbackPath: '/admin/rules',
    templateMatcher: (templates) => templates[0] ?? null,
  },
  {
    id: 'maintenance-page',
    title: '轻量维护页',
    mood: '运营',
    summary: '在命中特定路径或来源时返回维护公告，不影响整体站点。',
    mechanism: '用 respond 搭一个静态公告，比切全站维护更细粒度。',
    performance: '中',
    fallbackPath: '/admin/rules',
    templateMatcher: (templates) =>
      templates.find((item) =>
        item.name.includes('Block') || item.name.includes('Hello'),
      ) ?? null,
  },
]

const installedPluginCount = computed(
  () => installedPlugins.value.filter((item) => item.enabled).length,
)
const templateCount = computed(() => pluginTemplates.value.length)
const pluginsById = computed(() =>
  new Map(installedPlugins.value.map((item) => [item.plugin_id, item])),
)

const funIdeaCards = computed(() =>
  funActionIdeas.map((idea) => {
    const template = idea.templateMatcher(pluginTemplates.value)
    return {
      ...idea,
      template,
      ctaPath: template
        ? `/admin/rules?template=${encodeURIComponent(template.template_id)}`
        : idea.fallbackPath,
    }
  }),
)

const generatedPluginDefinitions = computed<Record<string, GeneratedPluginDefinition>>(() => ({
  'brand-block': {
    pluginId: 'brand-block-fun',
    fileName: 'brand-block-fun.zip',
    responseFilePath: 'brand-block.html',
    responseContent: `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>访问已受控</title>
  <style>
    body { margin: 0; font-family: "Segoe UI", sans-serif; background: linear-gradient(135deg, #f8fafc, #e0f2fe); color: #0f172a; }
    .shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .card { width: min(720px, 100%); background: rgba(255,255,255,0.9); border: 1px solid rgba(148,163,184,0.25); border-radius: 28px; padding: 32px; box-shadow: 0 24px 80px rgba(15,23,42,0.14); }
    .tag { display: inline-block; padding: 6px 12px; background: #0f172a; color: white; border-radius: 999px; font-size: 12px; letter-spacing: 0.1em; }
    h1 { margin: 18px 0 12px; font-size: 34px; }
    p { line-height: 1.8; color: #334155; }
  </style>
</head>
<body>
  <main class="shell">
    <section class="card">
      <span class="tag">SECURITY GATE</span>
      <h1>当前访问已被安全策略接管</h1>
      <p>这是一个适合生产场景的品牌化拦截页示例。</p>
      <p>你可以替换品牌名、工单入口、运维联系方式和恢复建议，让用户知道接下来该做什么。</p>
    </section>
  </main>
</body>
</html>`,
    preview: {
      template_id: 'brand-block-fun:brand_block_page',
      name: '品牌化拦截页',
      content_type: 'text/html; charset=utf-8',
      status_code: 403,
      gzip: true,
      body_source: 'file',
      body_preview: '品牌化 HTML 拦截页预览',
      truncated: false,
    },
    manifest: {
      plugin_id: 'brand-block-fun',
      name: 'Brand Block Fun',
      version: '1.0.0',
      description: '品牌化拦截页示例插件',
      templates: [
        {
          id: 'brand_block_page',
          name: '品牌化拦截页',
          description: '返回可品牌化的 HTML 拦截页',
          layer: 'l7',
          action: 'respond',
          pattern: '(?i)forbidden|blocked|intercepted',
          severity: 'high',
          response_template: {
            status_code: 403,
            content_type: 'text/html; charset=utf-8',
            body_source: 'file',
            gzip: true,
            body_text: '',
            body_file_path: 'brand-block.html',
            headers: [{ key: 'cache-control', value: 'no-store' }],
          },
        },
      ],
    },
  },
  'json-honeypot': {
    pluginId: 'json-honeypot-fun',
    fileName: 'json-honeypot-fun.zip',
    responseFilePath: 'honeypot.json',
    responseContent: JSON.stringify(
      {
        status: 'ok',
        trace_id: 'demo-honeypot-001',
        message: 'request accepted',
        note: 'this is a deceptive sample response for scanners',
      },
      null,
      2,
    ),
    preview: {
      template_id: 'json-honeypot-fun:json_honeypot',
      name: 'JSON 蜜罐响应',
      content_type: 'application/json; charset=utf-8',
      status_code: 200,
      gzip: true,
      body_source: 'file',
      body_preview: '{ "status": "ok" }',
      truncated: false,
    },
    manifest: {
      plugin_id: 'json-honeypot-fun',
      name: 'JSON Honeypot Fun',
      version: '1.0.0',
      description: 'JSON 蜜罐响应示例插件',
      templates: [
        {
          id: 'json_honeypot',
          name: 'JSON 蜜罐响应',
          description: '给扫描器返回结构化成功响应',
          layer: 'l7',
          action: 'respond',
          pattern: '(?i)wp-admin|phpmyadmin|scanner|probe',
          severity: 'high',
          response_template: {
            status_code: 200,
            content_type: 'application/json; charset=utf-8',
            body_source: 'file',
            gzip: true,
            body_text: '',
            body_file_path: 'honeypot.json',
            headers: [{ key: 'cache-control', value: 'no-store' }],
          },
        },
      ],
    },
  },
  'debug-echo': {
    pluginId: 'debug-echo-fun',
    fileName: 'debug-echo-fun.zip',
    responseFilePath: 'debug-echo.txt',
    responseContent: `Debug Echo Sample
-----------------
method={{method}}
uri={{uri}}
source_ip={{source_ip}}
matched_rule={{rule_id}}

Use this as a friendly placeholder page while you validate matching behavior.`,
    preview: {
      template_id: 'debug-echo-fun:debug_echo',
      name: '调试回显页',
      content_type: 'text/plain; charset=utf-8',
      status_code: 200,
      gzip: false,
      body_source: 'file',
      body_preview: 'Debug Echo Sample',
      truncated: false,
    },
    manifest: {
      plugin_id: 'debug-echo-fun',
      name: 'Debug Echo Fun',
      version: '1.0.0',
      description: '调试回显页示例插件',
      templates: [
        {
          id: 'debug_echo',
          name: '调试回显页',
          description: '返回简单文本回显页，用于调试规则命中',
          layer: 'l7',
          action: 'respond',
          pattern: '(?i)debug|preview|echo',
          severity: 'medium',
          response_template: {
            status_code: 200,
            content_type: 'text/plain; charset=utf-8',
            body_source: 'file',
            gzip: false,
            body_text: '',
            body_file_path: 'debug-echo.txt',
            headers: [{ key: 'cache-control', value: 'no-store' }],
          },
        },
      ],
    },
  },
  'scanner-misdirection': {
    pluginId: 'scanner-misdirection-fun',
    fileName: 'scanner-misdirection-fun.zip',
    responseFilePath: 'scanner-ok.html',
    responseContent: `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>OK</title></head>
<body><h1>200 OK</h1><p>Resource indexed successfully.</p></body>
</html>`,
    preview: {
      template_id: 'scanner-misdirection-fun:scanner_ok',
      name: '扫描器误导页',
      content_type: 'text/html; charset=utf-8',
      status_code: 200,
      gzip: true,
      body_source: 'file',
      body_preview: '<h1>200 OK</h1>',
      truncated: false,
    },
    manifest: {
      plugin_id: 'scanner-misdirection-fun',
      name: 'Scanner Misdirection Fun',
      version: '1.0.0',
      description: '扫描器误导页示例插件',
      templates: [
        {
          id: 'scanner_ok',
          name: '扫描器误导页',
          description: '对自动化工具返回看似正常的静态页面',
          layer: 'l7',
          action: 'respond',
          pattern: '(?i)scan|crawler|nmap|nikto',
          severity: 'medium',
          response_template: {
            status_code: 200,
            content_type: 'text/html; charset=utf-8',
            body_source: 'file',
            gzip: true,
            body_text: '',
            body_file_path: 'scanner-ok.html',
            headers: [{ key: 'cache-control', value: 'no-store' }],
          },
        },
      ],
    },
  },
  'maintenance-page': {
    pluginId: 'maintenance-page-fun',
    fileName: 'maintenance-page-fun.zip',
    responseFilePath: 'maintenance.html',
    responseContent: `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>维护中</title></head>
<body style="font-family: sans-serif; padding: 48px;">
  <h1>服务维护中</h1>
  <p>当前入口正在进行短时维护，请稍后重试。</p>
</body>
</html>`,
    preview: {
      template_id: 'maintenance-page-fun:maintenance_page',
      name: '轻量维护页',
      content_type: 'text/html; charset=utf-8',
      status_code: 503,
      gzip: true,
      body_source: 'file',
      body_preview: '<h1>服务维护中</h1>',
      truncated: false,
    },
    manifest: {
      plugin_id: 'maintenance-page-fun',
      name: 'Maintenance Page Fun',
      version: '1.0.0',
      description: '轻量维护页示例插件',
      templates: [
        {
          id: 'maintenance_page',
          name: '轻量维护页',
          description: '只对命中的请求返回维护公告',
          layer: 'l7',
          action: 'respond',
          pattern: '(?i)maintenance|upgrade|pause',
          severity: 'medium',
          response_template: {
            status_code: 503,
            content_type: 'text/html; charset=utf-8',
            body_source: 'file',
            gzip: true,
            body_text: '',
            body_file_path: 'maintenance.html',
            headers: [
              { key: 'cache-control', value: 'no-store' },
              { key: 'retry-after', value: '120' },
            ],
          },
        },
      ],
    },
  },
}))

const loadActionCenter = async () => {
  loading.value = true
  refreshing.value = true
  try {
    const [plugins, templates] = await Promise.all([
      fetchRuleActionPlugins(),
      fetchRuleActionTemplates(),
    ])
    installedPlugins.value = plugins.plugins
    pluginTemplates.value = templates.templates
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取动作中心失败'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

const handleInstallPlugin = async () => {
  const packageUrl = pluginInstallUrl.value.trim()
  if (!packageUrl && !pluginInstallFile.value) {
    error.value = '请输入插件包 URL 或选择本地 zip 文件'
    return
  }

  installingPlugin.value = true
  try {
    if (pluginInstallFile.value) {
      await uploadRuleActionPlugin(
        pluginInstallFile.value,
        pluginInstallSha256.value,
      )
    } else {
      await installRuleActionPlugin(packageUrl, pluginInstallSha256.value)
    }
    pluginInstallUrl.value = ''
    pluginInstallFile.value = null
    pluginInstallSha256.value = ''
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

const openTemplatePreview = async (template: RuleActionTemplateItem) => {
  previewLoading.value = true
  previewOpen.value = true
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

const openGeneratedPreview = (ideaId: string, title: string) => {
  const generated = generatedPluginDefinitions.value[ideaId]
  if (!generated) return
  previewOpen.value = true
  previewLoading.value = false
  previewTitle.value = title
  previewSourceLabel.value = '好玩的动作 · 本地生成示例插件'
  previewPayload.value = {
    ...generated.preview,
    body_preview: generated.responseContent,
  }
}

const closePreview = () => {
  previewOpen.value = false
  previewLoading.value = false
  previewTitle.value = ''
  previewSourceLabel.value = ''
  previewPayload.value = null
}

const downloadGeneratedPlugin = async (ideaId: string) => {
  const generated = generatedPluginDefinitions.value[ideaId]
  if (!generated) return

  downloadingIdeaId.value = ideaId
  try {
    const { default: JSZip } = await import('jszip')
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify(generated.manifest, null, 2))
    zip.file(`responses/${generated.responseFilePath}`, generated.responseContent)

    const blob = await zip.generateAsync({
      type: 'blob',
      compression: 'DEFLATE',
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = generated.fileName
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  } finally {
    downloadingIdeaId.value = ''
  }
}

const previewIsHtml = computed(() =>
  previewPayload.value?.content_type.includes('text/html') ?? false,
)

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
    </template>

    <div class="space-y-6">
      <section
        class="overflow-hidden rounded-[28px] border border-slate-200 bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.16),_transparent_35%),linear-gradient(135deg,_#fffdf8,_#f7fbff_50%,_#eef6ff)] p-6 shadow-[0_24px_60px_rgba(46,86,160,0.08)]"
      >
        <div class="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div class="max-w-2xl">
            <p class="text-sm font-medium tracking-[0.18em] text-blue-700">
              ACTION HUB
            </p>
            <h1 class="mt-3 text-3xl font-semibold tracking-tight text-slate-900">
              把“规则命中后做什么”集中管理
            </h1>
            <p class="mt-3 text-sm leading-7 text-slate-600">
              这里集中展示可复用的动作模板、插件能力，以及一些适合演示或运营场景的动作方案。
              插件的安装、启停和卸载也都统一收在这里，规则中心只负责把动作绑定到站点。
            </p>
          </div>

          <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div class="rounded-2xl border border-white/70 bg-white/80 px-4 py-3">
              <p class="text-xs uppercase tracking-[0.18em] text-slate-500">
                已启用插件
              </p>
              <p class="mt-2 text-2xl font-semibold text-slate-900">
                {{ installedPluginCount }}
              </p>
            </div>
            <div class="rounded-2xl border border-white/70 bg-white/80 px-4 py-3">
              <p class="text-xs uppercase tracking-[0.18em] text-slate-500">
                模板动作
              </p>
              <p class="mt-2 text-2xl font-semibold text-slate-900">
                {{ templateCount }}
              </p>
            </div>
            <div class="rounded-2xl border border-white/70 bg-white/80 px-4 py-3">
              <p class="text-xs uppercase tracking-[0.18em] text-slate-500">
                动作方案
              </p>
              <p class="mt-2 text-2xl font-semibold text-slate-900">
                {{ funIdeaCards.length }}
              </p>
            </div>
          </div>
        </div>
      </section>

      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <AdminRulesPluginSection
        :installed-plugins="installedPlugins"
        :installing-plugin="installingPlugin"
        :plugin-install-file="pluginInstallFile"
        :plugin-install-sha256="pluginInstallSha256"
        :plugin-install-url="pluginInstallUrl"
        @delete-plugin="handleDeletePlugin"
        @install="handleInstallPlugin"
        @toggle-plugin="togglePluginStatus"
        @update:plugin-install-file="pluginInstallFile = $event"
        @update:plugin-install-sha256="pluginInstallSha256 = $event"
        @update:plugin-install-url="pluginInstallUrl = $event"
      />

      <CyberCard
        title="模板动作"
        sub-title="当前已安装插件提供的现成动作模板，适合快速落地 respond 场景。"
      >
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
        title="好玩的动作"
        sub-title="偏演示、对抗或运营场景的动作灵感。能直接复用现有模板时，会优先给出最快路径。"
      >
        <div class="grid gap-4 xl:grid-cols-2">
          <article
            v-for="idea in funIdeaCards"
            :key="idea.id"
            class="relative overflow-hidden rounded-[24px] border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,250,245,0.96),_rgba(245,250,255,0.96))] p-5 shadow-sm"
          >
            <div class="absolute right-4 top-4 opacity-15">
              <component
                :is="
                  idea.id === 'json-honeypot'
                    ? FileJson
                    : idea.id === 'brand-block'
                      ? Shield
                      : idea.id === 'debug-echo'
                        ? Wand2
                        : idea.id === 'scanner-misdirection'
                          ? Bot
                          : FileText
                "
                :size="44"
              />
            </div>

            <div class="relative">
              <div class="flex flex-wrap items-center gap-2 text-xs">
                <span class="rounded-full bg-stone-900 px-2.5 py-1 text-white">
                  {{ idea.mood }}
                </span>
                <span
                  class="rounded-full px-2.5 py-1"
                  :class="performanceClass(idea.performance)"
                >
                  性能 {{ idea.performance }}
                </span>
                <span
                  class="rounded-full px-2.5 py-1"
                  :class="
                    idea.template
                      ? 'bg-blue-100 text-blue-700'
                      : 'bg-slate-100 text-slate-600'
                  "
                >
                  {{ idea.template ? '现成模板可用' : '通过 respond 即可实现' }}
                </span>
              </div>

              <h3 class="mt-4 text-xl font-semibold text-slate-900">
                {{ idea.title }}
              </h3>
              <p class="mt-3 text-sm leading-6 text-slate-600">
                {{ idea.summary }}
              </p>

              <div class="mt-4 rounded-2xl border border-white/80 bg-white/80 px-4 py-3">
                <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
                  实现方式
                </p>
                <p class="mt-2 text-sm text-slate-700">
                  {{ idea.mechanism }}
                </p>
                <p v-if="idea.template" class="mt-2 text-xs text-blue-700">
                  推荐模板：{{ idea.template.name }}
                </p>
              </div>

              <div class="mt-4 flex flex-wrap gap-3">
                <RouterLink
                  :to="idea.ctaPath"
                  class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
                >
                  立即试试
                </RouterLink>
                <RouterLink
                  to="/admin/rules"
                  class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
                >
                  管理规则
                </RouterLink>
                <button
                  class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="openGeneratedPreview(idea.id, idea.title)"
                >
                  预览动作
                </button>
                <button
                  class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="downloadGeneratedPlugin(idea.id)"
                >
                  {{ downloadingIdeaId === idea.id ? '打包中...' : '下载示例插件' }}
                </button>
              </div>
            </div>
          </article>
        </div>
      </CyberCard>

      <section class="grid gap-4 lg:grid-cols-3">
        <CyberCard title="当前能力边界" sub-title="动作中心帮助快速判断什么适合上生产。">
          <div class="space-y-3 text-sm leading-6 text-slate-600">
            <p>内置动作是最稳的基础能力，适合高频生产路径。</p>
            <p>模板动作更适合快速复用品牌页、JSON 响应和演示页。</p>
            <p>需要动态逻辑、条件分支或外部联动时，后续更适合做独立原生能力，而不是继续堆模板。</p>
          </div>
        </CyberCard>

        <CyberCard title="适合生产" sub-title="优先考虑这些动作组合。">
          <div class="flex flex-wrap gap-2">
            <span class="rounded-full bg-emerald-100 px-3 py-1 text-xs text-emerald-700">
              block + alert
            </span>
            <span class="rounded-full bg-emerald-100 px-3 py-1 text-xs text-emerald-700">
              品牌化 HTML 拦截页
            </span>
            <span class="rounded-full bg-emerald-100 px-3 py-1 text-xs text-emerald-700">
              维护公告页
            </span>
            <span class="rounded-full bg-emerald-100 px-3 py-1 text-xs text-emerald-700">
              JSON 受控返回
            </span>
          </div>
        </CyberCard>

        <CyberCard title="更偏演示" sub-title="好玩，但更适合测试、灰度或对抗实验。">
          <div class="flex flex-wrap gap-2">
            <span class="rounded-full bg-amber-100 px-3 py-1 text-xs text-amber-700">
              扫描器误导页
            </span>
            <span class="rounded-full bg-amber-100 px-3 py-1 text-xs text-amber-700">
              调试回显页
            </span>
            <span class="rounded-full bg-amber-100 px-3 py-1 text-xs text-amber-700">
              蜜罐 JSON
            </span>
            <span class="rounded-full bg-amber-100 px-3 py-1 text-xs text-amber-700">
              彩蛋页
            </span>
          </div>
        </CyberCard>
      </section>
    </div>

    <div
      v-if="previewOpen"
      class="fixed inset-0 z-[100] flex items-center justify-center px-4 py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closePreview"
      ></div>
      <div
        class="relative w-full max-w-5xl rounded-xl border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">{{ previewSourceLabel }}</p>
            <h3 class="mt-2 text-2xl font-semibold text-stone-900">
              {{ previewTitle }}
            </h3>
          </div>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePreview"
          >
            <X :size="18" />
          </button>
        </div>

        <div v-if="previewLoading" class="flex h-56 items-center justify-center">
          <RefreshCw class="animate-spin text-blue-700" :size="24" />
        </div>

        <template v-else-if="previewPayload">
          <div class="mt-4 grid gap-3 md:grid-cols-4">
            <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
              <p class="text-xs tracking-wide text-slate-500">状态码</p>
              <p class="mt-2 text-lg font-semibold text-stone-900">
                {{ previewPayload.status_code }}
              </p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
              <p class="text-xs tracking-wide text-slate-500">内容类型</p>
              <p class="mt-2 text-sm font-medium text-stone-900">
                {{ previewPayload.content_type }}
              </p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
              <p class="text-xs tracking-wide text-slate-500">Body 来源</p>
              <p class="mt-2 text-sm font-medium text-stone-900">
                {{ previewPayload.body_source }}
              </p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
              <p class="text-xs tracking-wide text-slate-500">gzip</p>
              <p class="mt-2 text-sm font-medium text-stone-900">
                {{ previewPayload.gzip ? '开启' : '关闭' }}
              </p>
            </div>
          </div>

          <div
            v-if="previewIsHtml"
            class="mt-4 overflow-hidden rounded-xl border border-slate-200 bg-white"
          >
            <div class="border-b border-slate-200 bg-slate-50 px-4 py-2 text-xs text-slate-500">
              页面预览
            </div>
            <iframe
              class="h-[320px] w-full bg-white"
              :srcdoc="previewPayload.body_preview"
            ></iframe>
          </div>

          <div class="mt-4 rounded-xl border border-slate-200 bg-white/80 p-5">
            <div class="flex items-center justify-between gap-4">
              <p class="text-xs tracking-wide text-slate-500">原始内容</p>
              <span
                v-if="previewPayload.truncated"
                class="rounded-full bg-amber-100 px-2.5 py-1 text-[11px] text-amber-700"
              >
                已截断
              </span>
            </div>
            <pre
              class="mt-3 max-h-[320px] overflow-auto whitespace-pre-wrap break-all font-mono text-sm leading-7 text-stone-800"
            >{{ previewPayload.body_preview }}</pre>
          </div>

          <div class="mt-4 flex flex-wrap gap-3">
            <button
              class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="copyToClipboard(previewPayload.body_preview)"
            >
              <Copy :size="14" />
              复制内容
            </button>
            <button
              class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="closePreview"
            >
              关闭
            </button>
          </div>
        </template>
      </div>
    </div>
  </AppLayout>
</template>
