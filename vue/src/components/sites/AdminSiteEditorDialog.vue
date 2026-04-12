<script setup lang="ts">
import { computed } from 'vue'
import { PencilLine, RotateCcw, Trash2, X } from 'lucide-vue-next'
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
} from '../../lib/types'
import StatusBadge from '../ui/StatusBadge.vue'

const props = defineProps<{
  actions: {
    deletingLocalSite: boolean
    loadingCertificates: boolean
    savingLocalSite: boolean
  }
  currentLocalSite: LocalSiteItem | null
  editingLocalSiteId: number | null
  editorTitle: string
  formatNumber: (value?: number) => string
  formatTimestamp: (timestamp?: number | null) => string
  defaultSafelineInterceptConfig: NonNullable<LocalSiteDraft['safeline_intercept']>
  hostnamesText: string
  isOpen: boolean
  listenPortsText: string
  localCertificates: LocalCertificateItem[]
  localSiteForm: LocalSiteDraft
  localSitesCount: number
  upstreamsText: string
}>()

const emit = defineEmits<{
  close: []
  remove: []
  reset: []
  save: []
  'update:form': [value: LocalSiteDraft]
  'update:hostnamesText': [value: string]
  'update:listenPortsText': [value: string]
  'update:upstreamsText': [value: string]
}>()

function updateForm<K extends keyof LocalSiteDraft>(
  key: K,
  value: LocalSiteDraft[K],
) {
  emit('update:form', {
    ...props.localSiteForm,
    [key]: value,
  })
}

function cloneSafelineIntercept(
  value: LocalSiteDraft['safeline_intercept'],
): LocalSiteDraft['safeline_intercept'] {
  if (!value) return null
  return {
    ...value,
    response_template: {
      ...value.response_template,
      headers: value.response_template.headers.map((header) => ({ ...header })),
    },
  }
}

function ensureSafelineInterceptConfig(): NonNullable<
  LocalSiteDraft['safeline_intercept']
> {
  const existing = props.localSiteForm.safeline_intercept
  if (existing) {
    return existing
  }
  const next = cloneSafelineIntercept(
    props.defaultSafelineInterceptConfig,
  ) as NonNullable<LocalSiteDraft['safeline_intercept']>
  updateForm('safeline_intercept', next)
  return next
}

function updateSafelineIntercept(
  patch: Partial<NonNullable<LocalSiteDraft['safeline_intercept']>>,
) {
  const current = ensureSafelineInterceptConfig()
  updateForm('safeline_intercept', {
    ...current,
    ...patch,
  } as NonNullable<LocalSiteDraft['safeline_intercept']>)
}

function updateSafelineResponseTemplate(
  patch: Partial<
    NonNullable<LocalSiteDraft['safeline_intercept']>['response_template']
  >,
) {
  const current = ensureSafelineInterceptConfig()
  updateSafelineIntercept({
    response_template: {
      ...current.response_template,
      ...patch,
    },
  })
}

const nameModel = computed({
  get: () => props.localSiteForm.name,
  set: (value: string) => updateForm('name', value),
})

const primaryHostnameModel = computed({
  get: () => props.localSiteForm.primary_hostname,
  set: (value: string) => updateForm('primary_hostname', value),
})

const certificateIdModel = computed({
  get: () => props.localSiteForm.local_certificate_id,
  set: (value: number | null) => updateForm('local_certificate_id', value),
})

const notesModel = computed({
  get: () => props.localSiteForm.notes,
  set: (value: string) => updateForm('notes', value),
})

const enabledModel = computed({
  get: () => props.localSiteForm.enabled,
  set: (value: boolean) => updateForm('enabled', value),
})

const tlsEnabledModel = computed({
  get: () => props.localSiteForm.tls_enabled,
  set: (value: boolean) => updateForm('tls_enabled', value),
})

const syncModeModel = computed({
  get: () => props.localSiteForm.sync_mode,
  set: (value: string) => updateForm('sync_mode', value),
})

const safelineOverrideEnabledModel = computed({
  get: () => props.localSiteForm.safeline_intercept !== null,
  set: (value: boolean) =>
    updateForm(
      'safeline_intercept',
      value
        ? (cloneSafelineIntercept(
            props.defaultSafelineInterceptConfig,
          ) as NonNullable<LocalSiteDraft['safeline_intercept']>)
        : null,
    ),
})

const safelineInterceptActionModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.action ??
    props.defaultSafelineInterceptConfig.action,
  set: (value: string) => updateSafelineIntercept({ action: value }),
})

const safelineInterceptMatchModeModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.match_mode ??
    props.defaultSafelineInterceptConfig.match_mode,
  set: (value: string) => updateSafelineIntercept({ match_mode: value }),
})

const safelineInterceptEnabledModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.enabled ??
    props.defaultSafelineInterceptConfig.enabled,
  set: (value: boolean) => updateSafelineIntercept({ enabled: value }),
})

const safelineInterceptMaxBodyBytesModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.max_body_bytes ??
    props.defaultSafelineInterceptConfig.max_body_bytes,
  set: (value: number) => updateSafelineIntercept({ max_body_bytes: value }),
})

const safelineInterceptBlockDurationModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.block_duration_secs ??
    props.defaultSafelineInterceptConfig.block_duration_secs,
  set: (value: number) =>
    updateSafelineIntercept({ block_duration_secs: value }),
})

const safelineResponseStatusCodeModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.status_code ??
    props.defaultSafelineInterceptConfig.response_template.status_code,
  set: (value: number) =>
    updateSafelineResponseTemplate({ status_code: value }),
})

const safelineResponseContentTypeModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.content_type ??
    props.defaultSafelineInterceptConfig.response_template.content_type,
  set: (value: string) =>
    updateSafelineResponseTemplate({ content_type: value }),
})

const safelineResponseBodySourceModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.body_source ??
    props.defaultSafelineInterceptConfig.response_template.body_source,
  set: (value: string) =>
    updateSafelineResponseTemplate({ body_source: value }),
})

const safelineResponseGzipModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.gzip ??
    props.defaultSafelineInterceptConfig.response_template.gzip,
  set: (value: boolean) => updateSafelineResponseTemplate({ gzip: value }),
})

const safelineResponseBodyTextModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.body_text ??
    props.defaultSafelineInterceptConfig.response_template.body_text,
  set: (value: string) => updateSafelineResponseTemplate({ body_text: value }),
})

const safelineResponseBodyFilePathModel = computed({
  get: () =>
    props.localSiteForm.safeline_intercept?.response_template.body_file_path ??
    props.defaultSafelineInterceptConfig.response_template.body_file_path,
  set: (value: string) =>
    updateSafelineResponseTemplate({ body_file_path: value }),
})

const safelineResponseHeadersTextModel = computed({
  get: () => {
    const headers =
      props.localSiteForm.safeline_intercept?.response_template.headers ??
      props.defaultSafelineInterceptConfig.response_template.headers
    return headers.map((header) => `${header.key}: ${header.value}`).join('\n')
  },
  set: (value: string) => {
    const headers = value
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [key, ...rest] = line.split(':')
        return {
          key: key?.trim() || '',
          value: rest.join(':').trim(),
        }
      })
      .filter((header) => header.key)
    updateSafelineResponseTemplate({ headers })
  },
})
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>
    <div
      class="relative max-h-[calc(100vh-2rem)] w-full max-w-6xl overflow-y-auto rounded-[28px] border border-slate-200 bg-white shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)]"
    >
      <div class="border-b border-slate-200 px-4 py-4 md:px-6">
        <div
          class="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between"
        >
          <div>
            <p class="text-sm font-semibold text-stone-900">
              {{ editorTitle }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              在这里直接维护本地运行站点。保存后会写入数据库，重启服务后生效。
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :text="
                actions.loadingCertificates
                  ? '证书读取中'
                  : `可选证书 ${formatNumber(localCertificates.length)} 张`
              "
              :type="actions.loadingCertificates ? 'muted' : 'info'"
              compact
            />
            <StatusBadge
              :text="`本地站点 ${formatNumber(localSitesCount)} 条`"
              type="muted"
              compact
            />
            <button
              class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="emit('close')"
            >
              <X :size="18" />
            </button>
          </div>
        </div>
      </div>

      <div class="space-y-4 px-4 py-4 md:px-6 md:py-6">
        <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="mb-3">
            <p class="text-sm font-medium text-stone-900">站点信息</p>
            <p class="mt-1 text-xs text-slate-500">
              这里填写站点本身的入口配置，包括域名、端口、证书和下游地址。
            </p>
          </div>
          <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">站点名称</span>
              <input
                v-model="nameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 Portal"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">主域名</span>
              <input
                v-model="primaryHostnameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 portal.example.com"
              />
            </label>
            <label class="space-y-1.5 xl:col-span-1">
              <span class="text-xs text-slate-500">证书</span>
              <select
                v-model="certificateIdModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
              >
                <option :value="null">未设置</option>
                <option
                  v-for="certificate in localCertificates"
                  :key="certificate.id"
                  :value="certificate.id"
                >
                  #{{ certificate.id }} · {{ certificate.name }}
                </option>
              </select>
            </label>
            <label class="space-y-1.5 md:col-span-2 xl:col-span-3">
              <span class="text-xs text-slate-500">附加域名</span>
              <input
                :value="hostnamesText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="多个域名用逗号分隔"
                @input="
                  emit(
                    'update:hostnamesText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">监听端口</span>
              <input
                :value="listenPortsText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 660"
                @input="
                  emit(
                    'update:listenPortsText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
            </label>
            <label class="space-y-1.5 md:col-span-2 xl:col-span-2">
              <span class="text-xs text-slate-500">下游地址</span>
              <input
                :value="upstreamsText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="多个地址用逗号分隔，例如 127.0.0.1:880 或 https://127.0.0.1:9443"
                @input="
                  emit(
                    'update:upstreamsText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
              <span class="block text-xs text-slate-400">
                当前运行时会优先使用第一个有效下游地址。
              </span>
            </label>
            <label class="space-y-1.5 md:col-span-2 xl:col-span-3">
              <span class="text-xs text-slate-500">备注</span>
              <textarea
                v-model="notesModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                rows="2"
              />
            </label>
          </div>
        </section>

        <section class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div class="mb-4">
            <p class="text-sm font-medium text-stone-900">运行设置</p>
            <p class="mt-1 text-xs text-slate-500">
              控制这个站点是否启用，以及是否参与本地 TLS 证书匹配。
            </p>
          </div>
          <div class="grid gap-3 md:grid-cols-2">
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="enabledModel"
                class="mt-0.5 accent-blue-600"
                type="checkbox"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用站点</span
                >
                <span class="mt-0.5 block text-xs text-slate-500"
                  >关闭后不会参与运行时匹配。</span
                >
              </span>
            </label>
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="tlsEnabledModel"
                class="mt-0.5 accent-blue-600"
                type="checkbox"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用 TLS</span
                >
                <span class="mt-0.5 block text-xs text-slate-500"
                  >启用后会参与 SNI 证书匹配。</span
                >
              </span>
            </label>
          </div>
        </section>

        <section class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div class="mb-4">
            <p class="text-sm font-medium text-stone-900">联动设置</p>
            <p class="mt-1 text-xs text-slate-500">
              这里控制这个站点与雷池之间的同步行为，不会改变站点本体字段的保存。
            </p>
          </div>
          <div class="grid gap-3 md:grid-cols-[minmax(0,16rem)_1fr]">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">同步模式</span>
              <select
                v-model="syncModeModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="manual">手动</option>
                <option value="pull_only">仅回流</option>
                <option value="push_only">仅推送</option>
                <option value="bidirectional">双向同步</option>
              </select>
            </label>
            <div
              class="rounded-lg border border-slate-200 bg-white px-3 py-3 text-xs leading-5 text-slate-500"
            >
              <p>站点同步和证书同步已经拆分，这里只控制站点与雷池之间的联动方向。</p>
              <p class="mt-1">
                选择“仅回流”或“仅推送”后，后续相关同步操作会按这个模式受限。
              </p>
            </div>
          </div>
        </section>

        <section class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div
            class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between"
          >
            <div>
              <p class="text-sm font-medium text-stone-900">高级策略</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                默认继承全局 SafeLine 接管策略。只有在这个站点需要特殊行为时，才开启覆盖。
              </p>
            </div>
            <label
              class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-stone-700"
            >
              <input
                v-model="safelineOverrideEnabledModel"
                type="checkbox"
                class="accent-blue-600"
              />
              启用站点级覆盖
            </label>
          </div>

          <div
            v-if="!localSiteForm.safeline_intercept"
            class="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-3 text-xs text-slate-500"
          >
            <p>
              当前继承全局策略：
              <span class="font-medium text-stone-900">
                {{
                  defaultSafelineInterceptConfig.enabled
                    ? '已启用接管'
                    : '未启用接管'
                }}
              </span>
            </p>
            <p class="mt-1">
              动作 {{ defaultSafelineInterceptConfig.action }}，匹配
              {{ defaultSafelineInterceptConfig.match_mode }}。
            </p>
          </div>

          <div
            v-else
            class="mt-4 space-y-4 rounded-lg border border-slate-200 bg-white p-4"
          >
              <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500">是否启用接管</span>
                  <select
                    v-model="safelineInterceptEnabledModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  >
                    <option :value="true">启用</option>
                    <option :value="false">关闭</option>
                  </select>
                </label>
                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500">接管动作</span>
                  <select
                    v-model="safelineInterceptActionModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  >
                    <option value="replace">替换为自定义响应</option>
                    <option value="drop">直接丢弃响应</option>
                    <option value="replace_and_block_ip">替换并封禁来源 IP</option>
                    <option value="pass">透传雷池原始响应</option>
                  </select>
                </label>
                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500">匹配模式</span>
                  <select
                    v-model="safelineInterceptMatchModeModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  >
                    <option value="strict">strict</option>
                    <option value="relaxed">relaxed</option>
                  </select>
                </label>
                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500">响应体检测上限</span>
                  <input
                    v-model.number="safelineInterceptMaxBodyBytesModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                    type="number"
                    min="0"
                    step="1024"
                  />
                </label>
              </div>

              <label class="space-y-1.5 md:max-w-xs">
                <span class="text-xs text-slate-500">封禁时长（秒）</span>
                <input
                  v-model.number="safelineInterceptBlockDurationModel"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  type="number"
                  min="0"
                  step="60"
                />
              </label>

              <div
                v-if="
                  safelineInterceptActionModel === 'replace' ||
                  safelineInterceptActionModel === 'replace_and_block_ip'
                "
                class="space-y-4 rounded-lg border border-slate-200 bg-slate-50 p-4"
              >
                <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <label class="space-y-1.5">
                    <span class="text-xs text-slate-500">响应状态码</span>
                    <input
                      v-model.number="safelineResponseStatusCodeModel"
                      class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                      type="number"
                      min="200"
                      max="599"
                    />
                  </label>
                  <label class="space-y-1.5 md:col-span-2">
                    <span class="text-xs text-slate-500">Content-Type</span>
                    <input
                      v-model="safelineResponseContentTypeModel"
                      class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                      type="text"
                      placeholder="text/html; charset=utf-8"
                    />
                  </label>
                  <label
                    class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-white p-3"
                  >
                    <input
                      v-model="safelineResponseGzipModel"
                      type="checkbox"
                      class="mt-0.5 accent-blue-600"
                    />
                    <span>
                      <span class="block text-sm font-medium text-stone-900"
                        >启用 gzip</span
                      >
                      <span class="mt-0.5 block text-xs text-slate-500"
                        >对替换后的回包执行压缩。</span
                      >
                    </span>
                  </label>
                </div>

                <div class="grid gap-3 md:grid-cols-2">
                  <label class="space-y-1.5">
                    <span class="text-xs text-slate-500">响应体来源</span>
                    <select
                      v-model="safelineResponseBodySourceModel"
                      class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                    >
                      <option value="inline_text">内联文本</option>
                      <option value="file">文件</option>
                    </select>
                  </label>
                  <label
                    v-if="safelineResponseBodySourceModel === 'file'"
                    class="space-y-1.5"
                  >
                    <span class="text-xs text-slate-500">响应文件路径</span>
                    <input
                      v-model="safelineResponseBodyFilePathModel"
                      class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                      type="text"
                      placeholder="/path/to/block.html"
                    />
                  </label>
                </div>

                <label
                  v-if="safelineResponseBodySourceModel === 'inline_text'"
                  class="space-y-1.5"
                >
                  <span class="text-xs text-slate-500">响应正文</span>
                  <textarea
                    v-model="safelineResponseBodyTextModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 font-mono text-sm outline-none transition focus:border-blue-500"
                    rows="6"
                    placeholder="输入这个站点专属的拦截页面 HTML 或文本"
                  />
                </label>

                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500"
                    >附加响应头（每行 `Key: Value`）</span
                  >
                  <textarea
                    v-model="safelineResponseHeadersTextModel"
                    class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 font-mono text-sm outline-none transition focus:border-blue-500"
                    rows="4"
                    placeholder="X-Block-Source: rust-waf"
                  />
                </label>
              </div>
            </div>
        </section>

        <div
          class="sticky bottom-0 flex flex-wrap items-center gap-2 border-t border-slate-200 bg-white/95 px-1 pt-2 backdrop-blur"
        >
          <button
            :disabled="actions.savingLocalSite"
            class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('save')"
          >
            <PencilLine :size="14" />
            {{
              actions.savingLocalSite
                ? '保存中...'
                : editingLocalSiteId === null
                  ? '创建本地站点'
                  : '保存本地站点'
            }}
          </button>
          <button
            class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="emit('reset')"
          >
            <RotateCcw :size="14" />
            重置表单
          </button>
          <button
            v-if="editingLocalSiteId !== null"
            :disabled="actions.deletingLocalSite"
            class="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-medium text-red-700 transition hover:border-red-400 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('remove')"
          >
            <Trash2 :size="14" />
            {{ actions.deletingLocalSite ? '删除中...' : '删除本地站点' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
