<script setup lang="ts">
import { computed, ref } from 'vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  listFieldClass,
  numberInputClass,
  type L7ConfigForm,
} from '@/features/l7/utils/adminL7'

const props = defineProps<{
  form: L7ConfigForm
  trustedProxyCidrsText: string
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
}>()

const emit = defineEmits<{
  'update:form': [value: L7ConfigForm]
  'update:trustedProxyCidrsText': [value: string]
  'update:dropUnmatchedRequests': [value: boolean]
}>()

function updateForm<K extends keyof L7ConfigForm>(
  key: K,
  value: L7ConfigForm[K],
) {
  emit('update:form', { ...props.form, [key]: value })
}

function fieldModel<K extends keyof L7ConfigForm>(key: K) {
  return computed({
    get: () => props.form[key],
    set: (value) => updateForm(key, value),
  })
}

const http2Enabled = fieldModel('http2_enabled')
const bloomEnabled = fieldModel('bloom_enabled')
const bloomVerifyEnabled = fieldModel('bloom_false_positive_verification')
const healthcheckEnabled = fieldModel('upstream_healthcheck_enabled')
const http3Enabled = fieldModel('http3_enabled')
const runtimeProfile = fieldModel('runtime_profile')
const failureMode = fieldModel('upstream_failure_mode')
const maxRequestSize = fieldModel('max_request_size')
const firstByteTimeout = fieldModel('first_byte_timeout_ms')
const readIdleTimeout = fieldModel('read_idle_timeout_ms')
const tlsHandshakeTimeout = fieldModel('tls_handshake_timeout_ms')
const proxyConnectTimeout = fieldModel('proxy_connect_timeout_ms')
const proxyWriteTimeout = fieldModel('proxy_write_timeout_ms')
const proxyReadTimeout = fieldModel('proxy_read_timeout_ms')
const bloomFilterScale = fieldModel('bloom_filter_scale')
const healthcheckInterval = fieldModel('upstream_healthcheck_interval_secs')
const healthcheckTimeout = fieldModel('upstream_healthcheck_timeout_ms')
const http2MaxStreams = fieldModel('http2_max_concurrent_streams')
const http2MaxFrameSize = fieldModel('http2_max_frame_size')
const http2InitialWindowSize = fieldModel('http2_initial_window_size')
const http2EnablePriorities = fieldModel('http2_enable_priorities')
const http3MaxStreams = fieldModel('http3_max_concurrent_streams')
const http3IdleTimeout = fieldModel('http3_idle_timeout_secs')
const http3Mtu = fieldModel('http3_mtu')
const http3MaxFrameSize = fieldModel('http3_max_frame_size')
const http3QpackTableSize = fieldModel('http3_qpack_table_size')
const http3CertificatePath = fieldModel('http3_certificate_path')
const http3PrivateKeyPath = fieldModel('http3_private_key_path')
const http3ConnectionMigration = fieldModel('http3_enable_connection_migration')
const http3Tls13Enabled = fieldModel('http3_enable_tls13')

function updateCcDefense(patch: Partial<L7ConfigForm['cc_defense']>) {
  updateForm('cc_defense', {
    ...props.form.cc_defense,
    ...patch,
  })
}

const ccDefenseEnabled = computed({
  get: () => props.form.cc_defense.enabled,
  set: (value: boolean) => updateCcDefense({ enabled: value }),
})

const ccRequestWindow = computed({
  get: () => props.form.cc_defense.request_window_secs,
  set: (value: number) => updateCcDefense({ request_window_secs: value }),
})

const ccIpChallengeThreshold = computed({
  get: () => props.form.cc_defense.ip_challenge_threshold,
  set: (value: number) => updateCcDefense({ ip_challenge_threshold: value }),
})

const ccIpBlockThreshold = computed({
  get: () => props.form.cc_defense.ip_block_threshold,
  set: (value: number) => updateCcDefense({ ip_block_threshold: value }),
})

const ccHostChallengeThreshold = computed({
  get: () => props.form.cc_defense.host_challenge_threshold,
  set: (value: number) => updateCcDefense({ host_challenge_threshold: value }),
})

const ccHostBlockThreshold = computed({
  get: () => props.form.cc_defense.host_block_threshold,
  set: (value: number) => updateCcDefense({ host_block_threshold: value }),
})

const ccRouteChallengeThreshold = computed({
  get: () => props.form.cc_defense.route_challenge_threshold,
  set: (value: number) => updateCcDefense({ route_challenge_threshold: value }),
})

const ccRouteBlockThreshold = computed({
  get: () => props.form.cc_defense.route_block_threshold,
  set: (value: number) => updateCcDefense({ route_block_threshold: value }),
})

const ccHotPathChallengeThreshold = computed({
  get: () => props.form.cc_defense.hot_path_challenge_threshold,
  set: (value: number) => updateCcDefense({ hot_path_challenge_threshold: value }),
})

const ccHotPathBlockThreshold = computed({
  get: () => props.form.cc_defense.hot_path_block_threshold,
  set: (value: number) => updateCcDefense({ hot_path_block_threshold: value }),
})

const ccDelayThresholdPercent = computed({
  get: () => props.form.cc_defense.delay_threshold_percent,
  set: (value: number) => updateCcDefense({ delay_threshold_percent: value }),
})

const ccDelayMs = computed({
  get: () => props.form.cc_defense.delay_ms,
  set: (value: number) => updateCcDefense({ delay_ms: value }),
})

const ccChallengeTtl = computed({
  get: () => props.form.cc_defense.challenge_ttl_secs,
  set: (value: number) => updateCcDefense({ challenge_ttl_secs: value }),
})

const ccChallengeCookieName = computed({
  get: () => props.form.cc_defense.challenge_cookie_name,
  set: (value: string) => updateCcDefense({ challenge_cookie_name: value }),
})

function updateSafelineIntercept(
  patch: Partial<L7ConfigForm['safeline_intercept']>,
) {
  updateForm('safeline_intercept', {
    ...props.form.safeline_intercept,
    ...patch,
  })
}

function updateSafelineResponseTemplate(
  patch: Partial<L7ConfigForm['safeline_intercept']['response_template']>,
) {
  updateSafelineIntercept({
    response_template: {
      ...props.form.safeline_intercept.response_template,
      ...patch,
    },
  })
}

const safelineInterceptEnabled = computed({
  get: () => props.form.safeline_intercept.enabled,
  set: (value: boolean) => updateSafelineIntercept({ enabled: value }),
})

const safelineInterceptAction = computed({
  get: () => props.form.safeline_intercept.action,
  set: (value: string) => updateSafelineIntercept({ action: value }),
})

const safelineInterceptMatchMode = computed({
  get: () => props.form.safeline_intercept.match_mode,
  set: (value: string) => updateSafelineIntercept({ match_mode: value }),
})

const safelineInterceptMaxBodyBytes = computed({
  get: () => props.form.safeline_intercept.max_body_bytes,
  set: (value: number) => updateSafelineIntercept({ max_body_bytes: value }),
})

const safelineInterceptBlockDuration = computed({
  get: () => props.form.safeline_intercept.block_duration_secs,
  set: (value: number) =>
    updateSafelineIntercept({ block_duration_secs: value }),
})

const safelineResponseStatusCode = computed({
  get: () => props.form.safeline_intercept.response_template.status_code,
  set: (value: number) =>
    updateSafelineResponseTemplate({ status_code: value }),
})

const safelineResponseContentType = computed({
  get: () => props.form.safeline_intercept.response_template.content_type,
  set: (value: string) =>
    updateSafelineResponseTemplate({ content_type: value }),
})

const contentTypeDialogOpen = ref(false)
const contentTypeDraft = ref('')
const contentTypeOptions = [
  'text/html; charset=utf-8',
  'text/plain; charset=utf-8',
  'application/json; charset=utf-8',
  'text/xml; charset=utf-8',
]

function openContentTypeDialog() {
  contentTypeDraft.value = safelineResponseContentType.value
  contentTypeDialogOpen.value = true
}

function selectContentTypeOption(value: string) {
  contentTypeDraft.value = value
}

function confirmContentTypeDialog() {
  safelineResponseContentType.value = contentTypeDraft.value.trim()
  contentTypeDialogOpen.value = false
}

function closeContentTypeDialog() {
  contentTypeDialogOpen.value = false
}

const safelineResponseBodySource = computed({
  get: () => props.form.safeline_intercept.response_template.body_source,
  set: (value: string) =>
    updateSafelineResponseTemplate({ body_source: value }),
})

const safelineResponseGzip = computed({
  get: () => props.form.safeline_intercept.response_template.gzip,
  set: (value: boolean) => updateSafelineResponseTemplate({ gzip: value }),
})

const safelineResponseBodyText = computed({
  get: () => props.form.safeline_intercept.response_template.body_text,
  set: (value: string) => updateSafelineResponseTemplate({ body_text: value }),
})

const safelineResponseBodyFilePath = computed({
  get: () => props.form.safeline_intercept.response_template.body_file_path,
  set: (value: string) =>
    updateSafelineResponseTemplate({ body_file_path: value }),
})

const safelineResponseHeadersText = computed({
  get: () =>
    props.form.safeline_intercept.response_template.headers
      .map((header) => `${header.key}: ${header.value}`)
      .join('\n'),
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
  <section
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
  >
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm tracking-wider text-blue-700">HTTP 配置</p>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>启用 HTTP/2</span>
        <input
          v-model="http2Enabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>未命中站点时直接断开连接</span>
        <input
          :checked="dropUnmatchedRequests"
          :disabled="dropUnmatchedRequestsDisabled"
          type="checkbox"
          class="ui-switch"
          @change="
            emit(
              'update:dropUnmatchedRequests',
              ($event.target as HTMLInputElement).checked,
            )
          "
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>启用 Bloom</span>
        <input
          v-model="bloomEnabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>启用上游健康检查</span>
        <input
          v-model="healthcheckEnabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>启用 Bloom 误判校验</span>
        <input
          v-model="bloomVerifyEnabled"
          :disabled="!form.bloom_enabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>启用 HTTP/3</span>
        <input
          v-model="http3Enabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
        <span>允许使用优先级信息处理 HTTP/2 请求</span>
        <input
          v-model="http2EnablePriorities"
          type="checkbox"
          class="ui-switch"
        />
      </label>
    </div>

    <div class="mt-4 border-t border-slate-200 pt-4">
      <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
        <label class="text-sm text-stone-700">
        运行档位
        <select
          v-model="runtimeProfile"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="minimal">精简模式</option>
          <option value="standard">标准模式</option>
        </select>
        </label>
        <label class="text-sm text-stone-700">
        上游失败模式
        <select
          v-model="failureMode"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="fail_open">故障放行</option>
          <option value="fail_close">故障关闭</option>
        </select>
        </label>
        <label class="text-sm text-stone-700 md:col-span-2 xl:col-span-4">
          可信代理网段
          <textarea
            :value="trustedProxyCidrsText"
            :class="listFieldClass"
            placeholder="每行一个，例如 203.0.113.0/24"
            @input="
              emit(
                'update:trustedProxyCidrsText',
                ($event.target as HTMLTextAreaElement).value,
              )
            "
          />
        </label>
      </div>
    </div>

    <div class="mt-4 border-t border-slate-200 pt-4">
      <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
      <label class="l7-inline-field text-sm text-stone-700"
        >最大请求体大小<input
          v-model.number="maxRequestSize"
          type="number"
          min="1024"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >首字节超时(ms)<input
          v-model.number="firstByteTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >空闲读取超时(ms)<input
          v-model.number="readIdleTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >TLS 握手超时(ms)<input
          v-model.number="tlsHandshakeTimeout"
          type="number"
          min="500"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >代理连接超时(ms)<input
          v-model.number="proxyConnectTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >代理写超时(ms)<input
          v-model.number="proxyWriteTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >代理读超时(ms)<input
          v-model.number="proxyReadTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >Bloom 缩放系数<input
          v-model.number="bloomFilterScale"
          type="number"
          min="0.1"
          step="0.1"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >健康检查间隔(s)<input
          v-model.number="healthcheckInterval"
          type="number"
          min="1"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >健康检查超时(ms)<input
          v-model.number="healthcheckTimeout"
          type="number"
          min="100"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >HTTP/2 最大并发流<input
          v-model.number="http2MaxStreams"
          type="number"
          min="1"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >HTTP/2 最大帧<input
          v-model.number="http2MaxFrameSize"
          type="number"
          min="1024"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
        >HTTP/2 初始窗口<input
          v-model.number="http2InitialWindowSize"
          type="number"
          min="1024"
          :class="numberInputClass"
      /></label>
      </div>
    </div>

    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">L7 CC 防护</p>
        </div>
        <div class="flex flex-wrap gap-3">
          <label
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
          >
            <span>启用 CC 守卫</span>
            <input
              v-model="ccDefenseEnabled"
              type="checkbox"
              class="ui-switch"
            />
          </label>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700"
          >滑窗时长(s)<input
            v-model.number="ccRequestWindow"
            type="number"
            min="3"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >延迟触发比例(%)<input
            v-model.number="ccDelayThresholdPercent"
            type="number"
            min="25"
            max="95"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >延迟时长(ms)<input
            v-model.number="ccDelayMs"
            type="number"
            min="0"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >IP Challenge 阈值<input
            v-model.number="ccIpChallengeThreshold"
            type="number"
            min="10"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >IP 429 阈值<input
            v-model.number="ccIpBlockThreshold"
            type="number"
            min="10"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >Host Challenge 阈值<input
            v-model.number="ccHostChallengeThreshold"
            type="number"
            min="5"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >Host 429 阈值<input
            v-model.number="ccHostBlockThreshold"
            type="number"
            min="5"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >路由 Challenge 阈值<input
            v-model.number="ccRouteChallengeThreshold"
            type="number"
            min="3"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >路由 429 阈值<input
            v-model.number="ccRouteBlockThreshold"
            type="number"
            min="3"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >热点路径 Challenge 阈值<input
            v-model.number="ccHotPathChallengeThreshold"
            type="number"
            min="32"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >热点路径 429 阈值<input
            v-model.number="ccHotPathBlockThreshold"
            type="number"
            min="32"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >Challenge TTL(s)<input
            v-model.number="ccChallengeTtl"
            type="number"
            min="30"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >Challenge Cookie 名称<input
            v-model="ccChallengeCookieName"
            type="text"
            placeholder="例如 rwaf_cc"
            :class="numberInputClass"
        /></label>
      </div>
    </div>

    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">
            SafeLine 响应接管
          </p>
        </div>
        <div class="flex flex-wrap gap-3">
          <label
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
          >
            <span>启用响应接管</span>
            <input
              v-model="safelineInterceptEnabled"
              type="checkbox"
              class="ui-switch"
            />
          </label>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700">
          默认动作
          <select
            v-model="safelineInterceptAction"
            class="l7-inline-select"
          >
            <option value="replace">替换响应</option>
            <option value="pass">放行</option>
            <option value="drop">直接丢弃</option>
            <option value="replace_and_block_ip">替换并封禁 IP</option>
          </select>
        </label>
        <label class="l7-inline-field text-sm text-stone-700">
          匹配模式
          <select
            v-model="safelineInterceptMatchMode"
            class="l7-inline-select"
          >
            <option value="strict">严格匹配</option>
            <option value="relaxed">宽松匹配</option>
          </select>
        </label>
        <label class="l7-inline-field text-sm text-stone-700"
          >识别最大响应体(bytes)<input
            v-model.number="safelineInterceptMaxBodyBytes"
            type="number"
            min="256"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >本地封禁时长(s)<input
            v-model.number="safelineInterceptBlockDuration"
            type="number"
            min="30"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >替换状态码<input
            v-model.number="safelineResponseStatusCode"
            type="number"
            min="100"
            max="599"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
          >替换 Content-Type<button
            type="button"
            :class="`${numberInputClass} l7-inline-button`"
            @click="openContentTypeDialog"
          >
            {{ safelineResponseContentType || '点击选择或输入' }}
          </button>
        </label>
        <div class="text-sm text-stone-700">
          响应体来源
          <select
            v-model="safelineResponseBodySource"
            class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500/40"
          >
            <option value="inline_text">内联文本</option>
            <option value="file">文件</option>
          </select>
        </div>
      </div>

      <div
        v-if="contentTypeDialogOpen"
        class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
        @click.self="closeContentTypeDialog"
      >
        <div
          class="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_24px_60px_rgba(15,23,42,0.18)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-sm tracking-wider text-blue-700">Content-Type</p>
              <h3 class="mt-2 text-lg font-semibold text-stone-900">
                选择或输入替换 Content-Type
              </h3>
            </div>
            <button
              type="button"
              class="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-stone-600 transition hover:border-slate-300 hover:text-stone-900"
              @click="closeContentTypeDialog"
            >
              关闭
            </button>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <button
              v-for="option in contentTypeOptions"
              :key="option"
              type="button"
              class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-300 hover:text-blue-700"
              @click="selectContentTypeOption(option)"
            >
              {{ option }}
            </button>
          </div>

          <label class="mt-4 block text-sm text-stone-700">
            自定义输入
            <input
              v-model="contentTypeDraft"
              type="text"
              placeholder="例如 text/html; charset=utf-8"
              class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-left outline-none transition focus:border-blue-500"
            />
          </label>

          <div class="mt-5 flex justify-end gap-2">
            <button
              type="button"
              class="rounded-lg border border-slate-200 px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300 hover:text-stone-900"
              @click="closeContentTypeDialog"
            >
              取消
            </button>
            <button
              type="button"
              class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700"
              @click="confirmContentTypeDialog"
            >
              确定
            </button>
          </div>
        </div>
      </div>
    </div>

    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">HTTP/3 配置</p>
        </div>
        <div class="flex flex-wrap gap-3">
          <label
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
          >
            <span>连接迁移支持</span>
            <input
              v-model="http3ConnectionMigration"
              type="checkbox"
              class="ui-switch"
            />
          </label>
          <label
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
          >
            <span>TLS 1.3</span>
            <input
              v-model="http3Tls13Enabled"
              type="checkbox"
              class="ui-switch"
            />
          </label>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700"
          >最大并发流<input
            v-model.number="http3MaxStreams"
            type="number"
            min="1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >空闲超时(s)<input
            v-model.number="http3IdleTimeout"
            type="number"
            min="1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >MTU<input
            v-model.number="http3Mtu"
            type="number"
            min="1200"
            max="1500"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >最大帧大小<input
            v-model.number="http3MaxFrameSize"
            type="number"
            min="65536"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >QPACK 表大小<input
            v-model.number="http3QpackTableSize"
            type="number"
            min="1024"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
          >证书路径<input
            v-model="http3CertificatePath"
            type="text"
            placeholder="例如 /path/to/cert.pem"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
          >私钥路径<input
            v-model="http3PrivateKeyPath"
            type="text"
            placeholder="例如 /path/to/key.pem"
            :class="numberInputClass"
        /></label>
      </div>
    </div>
  </section>
</template>

<style scoped>
.l7-inline-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}

.l7-inline-field :deep(input),
.l7-inline-field :deep(select),
.l7-inline-field :deep(.numberInputClass) {
  width: 5rem;
  margin-top: 0 !important;
  border-radius: 0.375rem;
  border: 1px solid rgb(203 213 225);
  background: transparent;
  padding: 0.25rem 0.5rem;
  box-shadow: none;
  text-align: center;
  transition: border-color 0.2s ease;
}

.l7-inline-field :deep(input[type="text"]) {
  width: 10rem;
  text-align: left;
}

.l7-inline-field :deep(input[type='number']::-webkit-outer-spin-button),
.l7-inline-field :deep(input[type='number']::-webkit-inner-spin-button) {
  -webkit-appearance: none;
  margin: 0;
}

.l7-inline-field :deep(input[type='number']) {
  -moz-appearance: textfield;
  appearance: textfield;
}

.l7-inline-select {
  width: auto;
  min-width: 8.5rem;
}

.l7-inline-button {
  width: auto;
  min-width: 12rem;
  text-align: center;
  cursor: pointer;
}

.l7-inline-field :deep(input:focus),
.l7-inline-field :deep(select:focus) {
  border-color: rgba(59, 130, 246, 0.65);
}

.l7-toggle-field {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.ui-switch {
  appearance: none;
  width: 2.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: rgb(203 213 225);
  position: relative;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 9999px;
  background: white;
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: rgb(37 99 235);
}

.ui-switch:checked::after {
  transform: translateX(1rem);
}

.ui-switch:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
