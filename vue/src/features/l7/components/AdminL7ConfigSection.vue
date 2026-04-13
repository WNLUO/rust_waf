<script setup lang="ts">
import { computed } from 'vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  listFieldClass,
  numberInputClass,
  type L7ConfigForm,
} from '@/features/l7/utils/adminL7'

const props = defineProps<{
  form: L7ConfigForm
  listenAddrsText: string
  trustedProxyCidrsText: string
}>()

const emit = defineEmits<{
  'update:form': [value: L7ConfigForm]
  'update:listenAddrsText': [value: string]
  'update:trustedProxyCidrsText': [value: string]
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
        <h3 class="mt-2 text-2xl font-semibold text-stone-900">
          HTTP 接入与代理参数
        </h3>
      </div>
      <div class="flex flex-wrap gap-3">
        <StatusBadge
          :text="form.http2_enabled ? 'HTTP/2 已启用' : 'HTTP/2 未启用'"
          :type="form.http2_enabled ? 'info' : 'muted'"
        />
      </div>
    </div>

    <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <span class="flex items-center justify-between gap-3">
          <span class="font-medium">启用 HTTP/2</span>
          <input
            v-model="http2Enabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </span>
        <span class="mt-2 block text-xs leading-6 text-slate-500"
          >启用后可处理 h2 / TLS ALPN 路由到的请求。</span
        >
      </label>
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <span class="flex items-center justify-between gap-3">
          <span class="font-medium">启用 Bloom</span>
          <input
            v-model="bloomEnabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </span>
        <span class="mt-2 block text-xs leading-6 text-slate-500"
          >控制全局 Bloom 过滤能力，关闭后误判校验也会随之失效。</span
        >
      </label>
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <span class="flex items-center justify-between gap-3">
          <span class="font-medium">启用上游健康检查</span>
          <input
            v-model="healthcheckEnabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </span>
        <span class="mt-2 block text-xs leading-6 text-slate-500"
          >关闭后故障状态仅来自实时代理结果，不再主动探测。</span
        >
      </label>
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <span class="flex items-center justify-between gap-3">
          <span class="font-medium">启用 Bloom 误判校验</span>
          <input
            v-model="bloomVerifyEnabled"
            :disabled="!form.bloom_enabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </span>
        <span class="mt-2 block text-xs leading-6 text-slate-500"
          >启用后会为命中结果追加精确校验，适合误判敏感场景。</span
        >
      </label>
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <span class="flex items-center justify-between gap-3">
          <span class="font-medium">启用 HTTP/3</span>
          <input
            v-model="http3Enabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </span>
        <span class="mt-2 block text-xs leading-6 text-slate-500"
          >启用后会尝试监听 QUIC / HTTP/3 入口。</span
        >
      </label>
      <div
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <p class="font-medium">运行档位</p>
        <select
          v-model="runtimeProfile"
          class="mt-3 w-full rounded-[16px] border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="minimal">minimal</option>
          <option value="standard">standard</option>
        </select>
        <p class="mt-2 text-xs leading-6 text-slate-500">
          会影响 HTTP 接入参数的收敛范围，以及多监听场景下的运行能力。
        </p>
      </div>
      <div
        class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
      >
        <p class="font-medium">上游失败模式</p>
        <select
          v-model="failureMode"
          class="mt-3 w-full rounded-[16px] border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="fail_open">fail_open</option>
          <option value="fail_close">fail_close</option>
        </select>
        <p class="mt-2 text-xs leading-6 text-slate-500">
          上游不可用时选择放行还是拒绝请求。
        </p>
      </div>
    </div>

    <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <label class="text-sm text-stone-700 md:col-span-2">
        监听地址（由站点页“全局入口”维护）
        <textarea
          :value="listenAddrsText"
          :class="listFieldClass"
          placeholder="请前往 /admin/sites 配置统一 HTTP 入口端口"
          disabled
        />
      </label>
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
      <label class="text-sm text-stone-700 md:col-span-2">
        HTTP/2 优先级支持
        <span
          class="mt-2 flex items-center gap-3 rounded-[18px] border border-slate-200 bg-white px-4 py-3"
        >
          <input
            v-model="http2EnablePriorities"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
          <span class="text-sm text-stone-800"
            >允许使用优先级信息处理 HTTP/2 请求</span
          >
        </span>
      </label>
    </div>

    <div class="mt-4">
      <label class="text-sm text-stone-700">
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

    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">L7 CC 防护</p>
          <h4 class="mt-2 text-xl font-semibold text-stone-900">
            基于真实来源 IP 的滑窗与 Challenge
          </h4>
        </div>
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            :text="form.cc_defense.enabled ? 'CC 守卫已启用' : 'CC 守卫已关闭'"
            :type="form.cc_defense.enabled ? 'success' : 'warning'"
          />
          <StatusBadge
            :text="`窗口 ${form.cc_defense.request_window_secs}s`"
            type="info"
          />
          <StatusBadge
            :text="`Cookie ${form.cc_defense.challenge_cookie_name}`"
            type="muted"
          />
        </div>
      </div>

      <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <label
          class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
        >
          <span class="flex items-center justify-between gap-3">
            <span class="font-medium">启用 CC 守卫</span>
            <input
              v-model="ccDefenseEnabled"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
            />
          </span>
          <span class="mt-2 block text-xs leading-6 text-slate-500"
            >按真实客户端 IP、Host 和路由统计请求速率，并执行延迟、Challenge 或 429。</span
          >
        </label>
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
          <h4 class="mt-2 text-xl font-semibold text-stone-900">
            默认接管雷池拦截响应
          </h4>
        </div>
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            :text="
              form.safeline_intercept.enabled ? '默认接管已启用' : '默认接管已关闭'
            "
            :type="form.safeline_intercept.enabled ? 'success' : 'warning'"
          />
          <StatusBadge
            :text="`动作 ${form.safeline_intercept.action}`"
            type="info"
          />
          <StatusBadge
            :text="`匹配 ${form.safeline_intercept.match_mode}`"
            :type="
              form.safeline_intercept.match_mode === 'strict'
                ? 'success'
                : 'warning'
            "
          />
        </div>
      </div>

      <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <label class="l7-toggle-field text-sm text-stone-700">
        <span class="font-medium">启用响应接管</span>
        <input
          v-model="safelineInterceptEnabled"
          type="checkbox"
          class="h-4 w-4 accent-blue-600"
        />
      </label>
        <div
          class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
        >
          <p class="font-medium">默认动作</p>
          <select
            v-model="safelineInterceptAction"
            class="mt-3 w-full rounded-[16px] border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
          >
            <option value="replace">replace</option>
            <option value="pass">pass</option>
            <option value="drop">drop</option>
            <option value="replace_and_block_ip">replace_and_block_ip</option>
          </select>
          <p class="mt-2 text-xs leading-6 text-slate-500">
            推荐默认使用 replace，把雷池命中统一替换为品牌化拦截页。
          </p>
        </div>
        <div
          class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-stone-800"
        >
          <p class="font-medium">匹配模式</p>
          <select
            v-model="safelineInterceptMatchMode"
            class="mt-3 w-full rounded-[16px] border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
          >
            <option value="strict">strict</option>
            <option value="relaxed">relaxed</option>
          </select>
          <p class="mt-2 text-xs leading-6 text-slate-500">
            strict 只认强指纹；relaxed 才会接受状态码兜底。
          </p>
        </div>
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
          >替换 Content-Type<input
            v-model="safelineResponseContentType"
            type="text"
            placeholder="text/html; charset=utf-8"
            :class="numberInputClass"
        /></label>
        <div class="text-sm text-stone-700">
          响应体来源
          <select
            v-model="safelineResponseBodySource"
            class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500/40"
          >
            <option value="inline_text">inline_text</option>
            <option value="file">file</option>
          </select>
        </div>
        <label class="text-sm text-stone-700">
          启用 gzip
          <span
            class="mt-2 flex items-center gap-3 rounded-[18px] border border-slate-200 bg-white px-4 py-3"
          >
            <input
              v-model="safelineResponseGzip"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
            />
            <span class="text-sm text-stone-800">压缩替换后的响应体</span>
          </span>
        </label>
      </div>

      <div class="mt-4 grid gap-3 xl:grid-cols-2">
        <label class="text-sm text-stone-700">
          内联响应体
          <textarea
            v-model="safelineResponseBodyText"
            :class="listFieldClass"
            placeholder="在 inline_text 模式下使用"
          />
        </label>
        <div class="space-y-3">
          <label class="l7-inline-field text-sm text-stone-700">
            响应文件路径
            <input
              v-model="safelineResponseBodyFilePath"
              type="text"
              placeholder="例如 plugins/brand-block/page.html"
              :class="numberInputClass"
            />
          </label>
          <label class="text-sm text-stone-700">
            额外响应头
            <textarea
              v-model="safelineResponseHeadersText"
              :class="listFieldClass"
              placeholder="每行一个，例如 cache-control: no-store"
            />
          </label>
        </div>
      </div>
    </div>

    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">HTTP/3 配置</p>
          <h4 class="mt-2 text-xl font-semibold text-stone-900">
            QUIC 与 TLS 1.3 入口参数
          </h4>
        </div>
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            :text="form.http3_enabled ? 'HTTP/3 已启用' : 'HTTP/3 未启用'"
            :type="form.http3_enabled ? 'success' : 'muted'"
          />
          <StatusBadge
            :text="form.http3_enable_tls13 ? 'TLS1.3 开启' : 'TLS1.3 关闭'"
            :type="form.http3_enable_tls13 ? 'info' : 'warning'"
          />
        </div>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <div class="text-sm text-stone-700 md:col-span-2">
          HTTP/3 监听地址
          <div :class="numberInputClass">
            {{ form.http3_listen_addr || '跟随全局 HTTPS 入口' }}
          </div>
          <p class="mt-2 text-xs leading-5 text-slate-500">
            QUIC 端口固定跟随“站点页 / 全局入口”的 HTTPS 入口端口，这里不再单独配置。
          </p>
        </div>
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
        <label class="text-sm text-stone-700">
          连接迁移支持
          <span
            class="mt-2 flex items-center gap-3 rounded-[18px] border border-slate-200 bg-white px-4 py-3"
          >
            <input
              v-model="http3ConnectionMigration"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
            />
            <span class="text-sm text-stone-800">允许连接迁移</span>
          </span>
        </label>
        <label class="l7-toggle-field text-sm text-stone-700">
          <span class="font-medium">TLS 1.3</span>
          <input
            v-model="http3Tls13Enabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
          />
        </label>
      </div>
    </div>
  </section>
</template>

<style scoped>
.l7-inline-field {
  display: flex;
  align-items: center;
  justify-content: space-between;
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
  text-align: right;
  transition: border-color 0.2s ease;
}

.l7-inline-field :deep(input[type="text"]) {
  width: 10rem;
  text-align: left;
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
</style>
