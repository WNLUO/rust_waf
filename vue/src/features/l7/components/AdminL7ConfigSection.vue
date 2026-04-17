<script setup lang="ts">
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'
import { listFieldClass, numberInputClass } from '@/features/l7/utils/adminL7'
import { useAdminL7ConfigSection } from '@/features/l7/composables/useAdminL7ConfigSection'

const props = defineProps<{
  form: L7ConfigForm
  trustedProxyCidrsText: string
  autoTuningRuntime?: AutoTuningRuntimePayload | null
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
  compatibilityMode?: boolean
  hideAdaptiveManagedSections?: boolean
}>()

const emit = defineEmits<{
  'update:form': [value: L7ConfigForm]
  'update:trustedProxyCidrsText': [value: string]
  'update:dropUnmatchedRequests': [value: boolean]
}>()

const {
  http2Enabled,
  http10Enabled,
  http10Saving,
  bloomEnabled,
  bloomVerifyEnabled,
  healthcheckEnabled,
  http3Enabled,
  runtimeProfile,
  failureMode,
  upstreamProtocolPolicy,
  upstreamHttp1StrictMode,
  upstreamHttp1AllowConnectionReuse,
  rejectAmbiguousHttp1Requests,
  rejectHttp1TransferEncodingRequests,
  rejectBodyOnSafeHttpMethods,
  rejectExpect100Continue,
  maxRequestSize,
  firstByteTimeout,
  readIdleTimeout,
  tlsHandshakeTimeout,
  proxyConnectTimeout,
  proxyWriteTimeout,
  proxyReadTimeout,
  bloomFilterScale,
  healthcheckInterval,
  healthcheckTimeout,
  http2MaxStreams,
  http2MaxFrameSize,
  http2InitialWindowSize,
  http2EnablePriorities,
  http3MaxStreams,
  http3IdleTimeout,
  http3Mtu,
  http3MaxFrameSize,
  http3QpackTableSize,
  http3CertificatePath,
  http3PrivateKeyPath,
  http3ConnectionMigration,
  http3Tls13Enabled,
  autoTuningMode,
  autoTuningIntent,
  autoRuntimeAdjustEnabled,
  autoBootstrapSecs,
  autoControlIntervalSecs,
  autoCooldownSecs,
  autoMaxStepPercent,
  autoRollbackWindowMinutes,
  autoTlsHandshakeTimeoutRatePercent,
  autoBucketRejectRatePercent,
  autoP95ProxyLatencyMs,
  autoPinnedFieldsText,
  autoEffectEvaluation,
  hotspotView,
  autoRiskLeaderboard,
  autoRiskByHost,
  autoRiskByRoute,
  hotspotHeatmapCards,
  autoEffectStatusLabel,
  autoEffectStatusClass,
  formatSignedNumber,
  formatSignedInteger,
  segmentLabel,
  segmentStatusLabel,
  adjustReasonLabel,
  riskSeverityClass,
  hostRiskSeverityClass,
  hotspotViewButtonClass,
  ccDefenseEnabled,
  ccRequestWindow,
  ccIpChallengeThreshold,
  ccIpBlockThreshold,
  ccHostChallengeThreshold,
  ccHostBlockThreshold,
  ccRouteChallengeThreshold,
  ccRouteBlockThreshold,
  ccHotPathChallengeThreshold,
  ccHotPathBlockThreshold,
  ccDelayThresholdPercent,
  ccDelayMs,
  ccChallengeTtl,
  ccChallengeCookieName,
  ccHardRouteBlockMultiplier,
  ccHardHostBlockMultiplier,
  ccHardIpBlockMultiplier,
  ccHardHotPathBlockMultiplier,
  slowAttackDefenseEnabled,
  slowAttackHeaderMinRate,
  slowAttackBodyMinRate,
  slowAttackIdleKeepaliveTimeout,
  slowAttackEventWindow,
  slowAttackMaxEvents,
  slowAttackBlockDuration,
  safelineInterceptEnabled,
  safelineInterceptAction,
  safelineInterceptMatchMode,
  safelineInterceptMaxBodyBytes,
  safelineInterceptBlockDuration,
  safelineResponseStatusCode,
  safelineResponseContentType,
  contentTypeDialogOpen,
  contentTypeDraft,
  contentTypeOptions,
  handleHttp10Toggle,
  openContentTypeDialog,
  selectContentTypeOption,
  confirmContentTypeDialog,
  closeContentTypeDialog,
  safelineResponseBodySource,
} = useAdminL7ConfigSection(props, emit)
</script>

<template>
  <section
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
  >
    <div
      v-if="compatibilityMode"
      class="mb-4 rounded-xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-sm leading-6 text-amber-900"
    >
      当前处于 L7 兼容模式。这里编辑的是历史 CC /
      自动调优细粒度参数，仅用于旧策略回滚或专项排障，不作为自动控制器的常规入口。
    </div>
    <div
      v-else-if="hideAdaptiveManagedSections"
      class="mb-4 rounded-xl border border-blue-100 bg-blue-50/70 px-4 py-3 text-sm leading-6 text-blue-900"
    >
      当前展示的是 L7 独立运行项。CC
      防护阈值与自动调优细项已交由自动化接管，并收纳到兼容层入口。
    </div>
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm tracking-wider text-blue-700">
          HTTP 配置（独立运行项）
        </p>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用 HTTP/1.0</span>
        <input
          :checked="http10Enabled"
          :disabled="http10Saving"
          type="checkbox"
          class="ui-switch"
          @change="
            handleHttp10Toggle(($event.target as HTMLInputElement).checked)
          "
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用 HTTP/2</span>
        <input v-model="http2Enabled" type="checkbox" class="ui-switch" />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
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
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用 Bloom</span>
        <input v-model="bloomEnabled" type="checkbox" class="ui-switch" />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用上游健康检查</span>
        <input v-model="healthcheckEnabled" type="checkbox" class="ui-switch" />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用 Bloom 误判校验</span>
        <input
          v-model="bloomVerifyEnabled"
          :disabled="!form.bloom_enabled"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用 HTTP/3</span>
        <input v-model="http3Enabled" type="checkbox" class="ui-switch" />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>允许使用优先级信息处理 HTTP/2 请求</span>
        <input
          v-model="http2EnablePriorities"
          type="checkbox"
          class="ui-switch"
        />
      </label>
    </div>

    <div
      v-if="!hideAdaptiveManagedSections"
      class="mt-4 border-t border-slate-200 pt-4"
    >
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
        <label class="text-sm text-stone-700">
          上游协议策略
          <select
            v-model="upstreamProtocolPolicy"
            class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          >
            <option value="http2_preferred">优先 HTTP/2</option>
            <option value="http2_only">仅 HTTP/2</option>
            <option value="auto">自动选择</option>
            <option value="http1_only">仅 HTTP/1.1</option>
          </select>
        </label>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>启用上游 HTTP/1 严格模式</span>
          <input
            v-model="upstreamHttp1StrictMode"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>允许上游 HTTP/1 连接复用</span>
          <input
            v-model="upstreamHttp1AllowConnectionReuse"
            :disabled="form.upstream_http1_strict_mode"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>拒绝歧义 HTTP/1 请求</span>
          <input
            v-model="rejectAmbiguousHttp1Requests"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>拒绝请求 Transfer-Encoding</span>
          <input
            v-model="rejectHttp1TransferEncodingRequests"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>拒绝 GET/HEAD/OPTIONS 携带 body</span>
          <input
            v-model="rejectBodyOnSafeHttpMethods"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>拒绝 Expect: 100-continue</span>
          <input
            v-model="rejectExpect100Continue"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>
    </div>

    <div class="mt-4 border-t border-slate-200 pt-4">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">
            慢速攻击防护（独立运行项）
          </p>
          <p class="mt-1 text-xs leading-5 text-slate-500">
            覆盖慢速 header、慢速 body 和 idle keep-alive
            占坑，命中后自动断连、记事件，并在窗口内升级封禁。
          </p>
        </div>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>启用慢速攻击防护</span>
          <input
            v-model="slowAttackDefenseEnabled"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <label class="text-sm text-stone-700">
          Header 最低速率(B/s)
          <input
            v-model.number="slowAttackHeaderMinRate"
            type="number"
            min="1"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          Body 最低速率(B/s)
          <input
            v-model.number="slowAttackBodyMinRate"
            type="number"
            min="1"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          Keep-Alive 空闲超时(ms)
          <input
            v-model.number="slowAttackIdleKeepaliveTimeout"
            type="number"
            min="100"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          统计窗口(s)
          <input
            v-model.number="slowAttackEventWindow"
            type="number"
            min="10"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          窗口升级阈值
          <input
            v-model.number="slowAttackMaxEvents"
            type="number"
            min="1"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          升级封禁时长(s)
          <input
            v-model.number="slowAttackBlockDuration"
            type="number"
            min="30"
            :class="numberInputClass"
          />
        </label>
      </div>
    </div>

    <div class="mt-4 border-t border-slate-200 pt-4">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">
            自动调优（自动化接管项）
          </p>
        </div>
        <label
          class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
        >
          <span>运行时微调</span>
          <input
            v-model="autoRuntimeAdjustEnabled"
            :disabled="autoTuningMode !== 'active'"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label class="text-sm text-stone-700">
          调优模式
          <select
            v-model="autoTuningMode"
            class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          >
            <option value="off">关闭</option>
            <option value="observe">观察模式</option>
            <option value="active">主动模式</option>
          </select>
        </label>
        <label class="text-sm text-stone-700">
          防护强度
          <select
            v-model="autoTuningIntent"
            class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          >
            <option value="conservative">保守</option>
            <option value="balanced">均衡</option>
            <option value="aggressive">激进</option>
          </select>
        </label>
        <label class="text-sm text-stone-700">
          启动探测窗口(s)
          <input
            v-model.number="autoBootstrapSecs"
            type="number"
            min="10"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          控制周期(s)
          <input
            v-model.number="autoControlIntervalSecs"
            type="number"
            min="10"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          冷却时间(s)
          <input
            v-model.number="autoCooldownSecs"
            type="number"
            min="30"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          单步最大调整(%)
          <input
            v-model.number="autoMaxStepPercent"
            type="number"
            min="1"
            max="25"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          回滚窗口(分钟)
          <input
            v-model.number="autoRollbackWindowMinutes"
            type="number"
            min="5"
            :class="numberInputClass"
          />
        </label>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700"
          >握手超时率目标(%)<input
            v-model.number="autoTlsHandshakeTimeoutRatePercent"
            type="number"
            min="0.1"
            step="0.1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >预算误拒绝率目标(%)<input
            v-model.number="autoBucketRejectRatePercent"
            type="number"
            min="0.1"
            step="0.1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >P95 代理延迟目标(ms)<input
            v-model.number="autoP95ProxyLatencyMs"
            type="number"
            min="50"
            :class="numberInputClass"
        /></label>
      </div>

      <label class="mt-4 block text-sm text-stone-700">
        锁定字段 (一行一个，锁定后不受自动调优影响)
        <textarea
          v-model="autoPinnedFieldsText"
          :class="listFieldClass"
          placeholder="例如：l7_config.tls_handshake_timeout_ms"
        />
      </label>

      <div
        v-if="autoTuningRuntime"
        class="mt-3 rounded-lg border border-slate-200 bg-white/70 px-3 py-2 text-xs text-stone-600"
      >
        <p>
          当前状态: {{ autoTuningRuntime.controller_state }} | CPU:
          {{ autoTuningRuntime.detected_cpu_cores }} | 内存上限(MB):
          {{ autoTuningRuntime.detected_memory_limit_mb ?? 'unknown' }}
        </p>
        <p class="mt-1">
          观测值: 握手超时率
          {{
            autoTuningRuntime.last_observed_tls_handshake_timeout_rate_percent.toFixed(
              2,
            )
          }}% / 预算拒绝率
          {{
            autoTuningRuntime.last_observed_bucket_reject_rate_percent.toFixed(
              2,
            )
          }}% / 平均代理延迟
          {{ autoTuningRuntime.last_observed_avg_proxy_latency_ms }}ms
        </p>
        <p class="mt-1">
          最近动作:
          {{ adjustReasonLabel(autoTuningRuntime.last_adjust_reason) }} | 24h
          回滚: {{ autoTuningRuntime.rollback_count_24h }}
        </p>
        <p v-if="autoTuningRuntime.last_adjust_diff.length" class="mt-1">
          动作说明:
          {{ autoTuningRuntime.last_adjust_diff.join(' | ') }}
        </p>
        <template v-if="autoEffectEvaluation">
          <p class="mt-1">
            最近效果:
            <span :class="autoEffectStatusClass">{{
              autoEffectStatusLabel
            }}</span>
            | 样本 {{ autoEffectEvaluation.sample_requests }}
            <span v-if="autoEffectEvaluation.observed_at !== null">
              | 评估时间
              {{
                new Date(
                  autoEffectEvaluation.observed_at * 1000,
                ).toLocaleString()
              }}
            </span>
          </p>
          <p class="mt-1">
            变化: 握手超时率
            {{
              formatSignedNumber(
                autoEffectEvaluation.handshake_timeout_rate_delta_percent,
              )
            }}pp / 预算拒绝率
            {{
              formatSignedNumber(
                autoEffectEvaluation.bucket_reject_rate_delta_percent,
              )
            }}pp / 平均代理延迟
            {{
              formatSignedInteger(
                autoEffectEvaluation.avg_proxy_latency_delta_ms,
              )
            }}ms
          </p>
          <p class="mt-1">说明: {{ autoEffectEvaluation.summary }}</p>
          <p v-if="autoEffectEvaluation.segments.length" class="mt-1">
            分层观测:
            {{
              autoEffectEvaluation.segments
                .map(
                  (segment) =>
                    `${segmentLabel(segment)} ${segmentStatusLabel(segment.status)} (${segment.sample_requests} req / ${formatSignedInteger(segment.avg_proxy_latency_delta_ms)}ms / ${formatSignedNumber(segment.failure_rate_delta_percent)}pp)`,
                )
                .join(' | ')
            }}
          </p>
          <div
            v-if="autoRiskLeaderboard.length"
            class="mt-3 rounded-lg border border-slate-200 bg-slate-50/80 p-3"
          >
            <p class="text-xs font-semibold tracking-wider text-slate-600">
              业务风险榜单
            </p>
            <div class="mt-2 space-y-2">
              <div
                v-for="segment in autoRiskLeaderboard"
                :key="`${segment.scope_type}-${segment.scope_key}`"
                class="rounded-lg border px-3 py-2"
                :class="riskSeverityClass(segment.status)"
              >
                <p class="text-xs font-semibold">
                  {{ segmentLabel(segment) }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  {{ segmentStatusLabel(segment.status) }} | 样本
                  {{ segment.sample_requests }} | 延迟
                  {{
                    formatSignedInteger(segment.avg_proxy_latency_delta_ms)
                  }}ms | 失败率
                  {{ formatSignedNumber(segment.failure_rate_delta_percent) }}pp
                </p>
              </div>
            </div>
          </div>
          <div
            v-if="autoRiskByHost.length || autoRiskByRoute.length"
            class="mt-3 rounded-lg border border-slate-200 bg-white/75 p-3"
          >
            <div class="flex flex-wrap items-center justify-between gap-2">
              <p class="text-xs font-semibold tracking-wider text-slate-600">
                热点图视图
              </p>
              <div class="flex items-center gap-2">
                <button
                  type="button"
                  class="rounded-full border px-3 py-1 text-[11px] font-semibold transition"
                  :class="hotspotViewButtonClass('host')"
                  @click="hotspotView = 'host'"
                >
                  Host
                </button>
                <button
                  type="button"
                  class="rounded-full border px-3 py-1 text-[11px] font-semibold transition"
                  :class="hotspotViewButtonClass('route')"
                  @click="hotspotView = 'route'"
                >
                  Route
                </button>
              </div>
            </div>
            <div class="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <div
                v-for="item in hotspotHeatmapCards"
                :key="'host' in item ? item.host : item.route"
                class="rounded-xl border px-3 py-3 shadow-sm transition"
                :class="hostRiskSeverityClass(item)"
              >
                <p class="text-xs font-semibold">
                  {{ 'host' in item ? item.host : item.route }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  风险段 {{ item.regressed_count + item.stable_count }} | 样本
                  {{ item.sample_requests }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  热度 {{ formatSignedInteger(item.max_latency_delta_ms) }}ms /
                  {{
                    formatSignedNumber(item.max_failure_rate_delta_percent)
                  }}pp
                </p>
                <p class="mt-2 text-[11px] leading-5 opacity-80">
                  主要热点: {{ item.top_label }}
                </p>
              </div>
            </div>
          </div>
        </template>
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

    <div
      v-if="!hideAdaptiveManagedSections"
      class="mt-3 border-t border-slate-200 pt-6"
    >
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">
            L7 CC 防护（自动化接管项）
          </p>
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
          >IP 挑战阈值<input
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
          >主机挑战阈值<input
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
          >路由挑战阈值<input
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
          >热点路径挑战阈值<input
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
          >挑战有效期(秒)<input
            v-model.number="ccChallengeTtl"
            type="number"
            min="30"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >挑战 Cookie 名称<input
            v-model="ccChallengeCookieName"
            type="text"
            placeholder="例如 rwaf_cc"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >硬阈值-路由倍率<input
            v-model.number="ccHardRouteBlockMultiplier"
            type="number"
            min="1"
            max="20"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >硬阈值-Host 倍率<input
            v-model.number="ccHardHostBlockMultiplier"
            type="number"
            min="1"
            max="20"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >硬阈值-IP 倍率<input
            v-model.number="ccHardIpBlockMultiplier"
            type="number"
            min="1"
            max="20"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >硬阈值-热点路径倍率<input
            v-model.number="ccHardHotPathBlockMultiplier"
            type="number"
            min="1"
            max="20"
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
            SafeLine 响应接管（独立运行项）
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
          <select v-model="safelineInterceptAction" class="l7-inline-select">
            <option value="replace">替换响应</option>
            <option value="pass">放行</option>
            <option value="drop">直接丢弃</option>
            <option value="replace_and_block_ip">替换并封禁 IP</option>
          </select>
        </label>
        <label class="l7-inline-field text-sm text-stone-700">
          匹配模式
          <select v-model="safelineInterceptMatchMode" class="l7-inline-select">
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
          <p class="text-sm tracking-wider text-blue-700">
            HTTP/3 配置（独立运行项）
          </p>
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

.l7-inline-field :deep(input[type='text']) {
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
