<script setup lang="ts">
import type { Ref, WritableComputedRef } from 'vue'
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>
type HotspotView = 'host' | 'route'

const props = defineProps<{
  controls: {
    autoTuningMode: ModelRef<string>
    autoTuningIntent: ModelRef<string>
    autoRuntimeAdjustEnabled: ModelRef<boolean>
    autoBootstrapSecs: ModelRef<number>
    autoControlIntervalSecs: ModelRef<number>
    autoCooldownSecs: ModelRef<number>
    autoMaxStepPercent: ModelRef<number>
    autoRollbackWindowMinutes: ModelRef<number>
    autoTlsHandshakeTimeoutRatePercent: ModelRef<number>
    autoBucketRejectRatePercent: ModelRef<number>
    autoP95ProxyLatencyMs: ModelRef<number>
    autoPinnedFieldsText: ModelRef<string>
    autoEffectEvaluation: Ref<any | null>
    hotspotView: Ref<HotspotView>
    autoRiskLeaderboard: Ref<any[]>
    autoRiskByHost: Ref<any[]>
    autoRiskByRoute: Ref<any[]>
    hotspotHeatmapCards: Ref<any[]>
    autoEffectStatusLabel: Ref<string>
    autoEffectStatusClass: Ref<string>
  }
  runtime: AutoTuningRuntimePayload | null
  helpers: {
    formatSignedNumber: (value: number, digits?: number) => string
    formatSignedInteger: (value: number) => string
    segmentLabel: (segment: any) => string
    segmentStatusLabel: (status: string) => string
    adjustReasonLabel: (reason: string | null) => string
    riskSeverityClass: (status: string) => string
    hostRiskSeverityClass: (item: any) => string
    hotspotViewButtonClass: (view: HotspotView) => string
  }
  numberInputClass: string
  listFieldClass: string
}>()

function formatSegmentObservation(segment: any) {
  return `${props.helpers.segmentLabel(segment)} ${props.helpers.segmentStatusLabel(segment.status)} (${segment.sample_requests} req / ${props.helpers.formatSignedInteger(segment.avg_proxy_latency_delta_ms)}ms / ${props.helpers.formatSignedNumber(segment.failure_rate_delta_percent)}pp)`
}
</script>

<template>
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
            v-model="controls.autoRuntimeAdjustEnabled.value"
            :disabled="controls.autoTuningMode.value !== 'active'"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label class="text-sm text-stone-700">
          调优模式
          <select
            v-model="controls.autoTuningMode.value"
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
            v-model="controls.autoTuningIntent.value"
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
            v-model.number="controls.autoBootstrapSecs.value"
            type="number"
            min="10"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          控制周期(s)
          <input
            v-model.number="controls.autoControlIntervalSecs.value"
            type="number"
            min="10"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          冷却时间(s)
          <input
            v-model.number="controls.autoCooldownSecs.value"
            type="number"
            min="30"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          单步最大调整(%)
          <input
            v-model.number="controls.autoMaxStepPercent.value"
            type="number"
            min="1"
            max="25"
            :class="numberInputClass"
          />
        </label>
        <label class="text-sm text-stone-700">
          回滚窗口(分钟)
          <input
            v-model.number="controls.autoRollbackWindowMinutes.value"
            type="number"
            min="5"
            :class="numberInputClass"
          />
        </label>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700"
          >握手超时率目标(%)<input
            v-model.number="controls.autoTlsHandshakeTimeoutRatePercent.value"
            type="number"
            min="0.1"
            step="0.1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >预算误拒绝率目标(%)<input
            v-model.number="controls.autoBucketRejectRatePercent.value"
            type="number"
            min="0.1"
            step="0.1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >P95 代理延迟目标(ms)<input
            v-model.number="controls.autoP95ProxyLatencyMs.value"
            type="number"
            min="50"
            :class="numberInputClass"
        /></label>
      </div>

      <label class="mt-4 block text-sm text-stone-700">
        锁定字段 (一行一个，锁定后不受自动调优影响)
        <textarea
          v-model="controls.autoPinnedFieldsText.value"
          :class="listFieldClass"
          placeholder="例如：l7_config.tls_handshake_timeout_ms"
        />
      </label>

      <div
        v-if="runtime"
        class="mt-3 rounded-lg border border-slate-200 bg-white/70 px-3 py-2 text-xs text-stone-600"
      >
        <p>
          当前状态: {{ runtime.controller_state }} | CPU:
          {{ runtime.detected_cpu_cores }} | 内存上限(MB):
          {{ runtime.detected_memory_limit_mb ?? 'unknown' }}
        </p>
        <p class="mt-1">
          观测值: 握手超时率
          {{
            runtime.last_observed_tls_handshake_timeout_rate_percent.toFixed(
              2,
            )
          }}% / 预算拒绝率
          {{
            runtime.last_observed_bucket_reject_rate_percent.toFixed(
              2,
            )
          }}% / 平均代理延迟
          {{ runtime.last_observed_avg_proxy_latency_ms }}ms
        </p>
        <p class="mt-1">
          最近动作:
          {{ helpers.adjustReasonLabel(runtime.last_adjust_reason) }} | 24h
          回滚: {{ runtime.rollback_count_24h }}
        </p>
        <p v-if="runtime.last_adjust_diff.length" class="mt-1">
          动作说明:
          {{ runtime.last_adjust_diff.join(' | ') }}
        </p>
        <template v-if="controls.autoEffectEvaluation.value">
          <p class="mt-1">
            最近效果:
            <span :class="controls.autoEffectStatusClass.value">{{
              controls.autoEffectStatusLabel.value
            }}</span>
            | 样本 {{ controls.autoEffectEvaluation.value.sample_requests }}
            <span v-if="controls.autoEffectEvaluation.value.observed_at !== null">
              | 评估时间
              {{
                new Date(
                  controls.autoEffectEvaluation.value.observed_at * 1000,
                ).toLocaleString()
              }}
            </span>
          </p>
          <p class="mt-1">
            变化: 握手超时率
            {{
              helpers.formatSignedNumber(
                controls.autoEffectEvaluation.value.handshake_timeout_rate_delta_percent,
              )
            }}pp / 预算拒绝率
            {{
              helpers.formatSignedNumber(
                controls.autoEffectEvaluation.value.bucket_reject_rate_delta_percent,
              )
            }}pp / 平均代理延迟
            {{
              helpers.formatSignedInteger(
                controls.autoEffectEvaluation.value.avg_proxy_latency_delta_ms,
              )
            }}ms
          </p>
          <p class="mt-1">说明: {{ controls.autoEffectEvaluation.value.summary }}</p>
          <p v-if="controls.autoEffectEvaluation.value.segments.length" class="mt-1">
            分层观测:
            {{
              controls.autoEffectEvaluation.value.segments
                .map(formatSegmentObservation)
                .join(' | ')
            }}
          </p>
          <div
            v-if="controls.autoRiskLeaderboard.value.length"
            class="mt-3 rounded-lg border border-slate-200 bg-slate-50/80 p-3"
          >
            <p class="text-xs font-semibold tracking-wider text-slate-600">
              业务风险榜单
            </p>
            <div class="mt-2 space-y-2">
              <div
                v-for="segment in controls.autoRiskLeaderboard.value"
                :key="`${segment.scope_type}-${segment.scope_key}`"
                class="rounded-lg border px-3 py-2"
                :class="helpers.riskSeverityClass(segment.status)"
              >
                <p class="text-xs font-semibold">
                  {{ helpers.segmentLabel(segment) }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  {{ helpers.segmentStatusLabel(segment.status) }} | 样本
                  {{ segment.sample_requests }} | 延迟
                  {{
                    helpers.formatSignedInteger(segment.avg_proxy_latency_delta_ms)
                  }}ms | 失败率
                  {{ helpers.formatSignedNumber(segment.failure_rate_delta_percent) }}pp
                </p>
              </div>
            </div>
          </div>
          <div
            v-if="controls.autoRiskByHost.value.length || controls.autoRiskByRoute.value.length"
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
                  :class="helpers.hotspotViewButtonClass('host')"
                  @click="controls.hotspotView.value = 'host'"
                >
                  Host
                </button>
                <button
                  type="button"
                  class="rounded-full border px-3 py-1 text-[11px] font-semibold transition"
                  :class="helpers.hotspotViewButtonClass('route')"
                  @click="controls.hotspotView.value = 'route'"
                >
                  Route
                </button>
              </div>
            </div>
            <div class="mt-2 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              <div
                v-for="item in controls.hotspotHeatmapCards.value"
                :key="'host' in item ? item.host : item.route"
                class="rounded-xl border px-3 py-3 shadow-sm transition"
                :class="helpers.hostRiskSeverityClass(item)"
              >
                <p class="text-xs font-semibold">
                  {{ 'host' in item ? item.host : item.route }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  风险段 {{ item.regressed_count + item.stable_count }} | 样本
                  {{ item.sample_requests }}
                </p>
                <p class="mt-1 text-[11px] leading-5">
                  热度 {{ helpers.formatSignedInteger(item.max_latency_delta_ms) }}ms /
                  {{
                    helpers.formatSignedNumber(item.max_failure_rate_delta_percent)
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

.l7-inline-field :deep(input[type='number']::-webkit-outer-spin-button),
.l7-inline-field :deep(input[type='number']::-webkit-inner-spin-button) {
  -webkit-appearance: none;
  margin: 0;
}

.l7-inline-field :deep(input[type='number']) {
  -moz-appearance: textfield;
  appearance: textfield;
}

.l7-inline-field :deep(input:focus),
.l7-inline-field :deep(select:focus) {
  border-color: rgba(59, 130, 246, 0.65);
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
</style>
