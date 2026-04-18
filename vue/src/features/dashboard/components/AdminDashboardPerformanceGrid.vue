<script setup lang="ts">
import MetricWidget from '@/shared/ui/MetricWidget.vue'

type PerformanceGaugeCard = {
  kind: 'gauge'
  label: string
  value: string
  gaugeValue: string
  primaryLabel: string
  primaryValue: string
  secondaryLabel: string
  secondaryValue: string
  percent: number
  tone: string
  color: string
  track: string
}

type PerformanceIoCard = {
  kind: 'io'
  label: string
  readValue: string
  writeValue: string
  readPercent: number
  writePercent: number
  tone: string
  color: string
  track: string
}

export type PerformanceCard = PerformanceGaugeCard | PerformanceIoCard
type MetricTrend = 'up' | 'down' | 'neutral'

defineProps<{
  cards: PerformanceCard[]
  totalPackets: number
  totalBytes: number
  totalPacketSeries: number[]
  packetSparkMax: number
  latencyValue: number
  proxyFailCloseRejections: number
  latencyTrend: MetricTrend
  latencySeries: number[]
  latencySparkMax: number
  successRate: string
  proxySuccesses: number
  proxyFailures: number
  successRateTrend: MetricTrend
  proxySuccessPercent: number
  blockedPackets: number
  blockedL4: number
  blockedL7: number
  blockedTrend: MetricTrend
  formatNumber: (value: number) => string
  formatBytes: (value: number) => string
  formatLatency: (value: number) => string
}>()
</script>

<template>
  <section class="grid grid-cols-2 gap-2 lg:grid-cols-4 2xl:grid-cols-7">
    <div
      v-for="card in cards"
      :key="card.label"
      class="flex min-h-[5.75rem] min-w-0 flex-col rounded-xl border px-2.5 py-2 shadow-sm"
      :class="card.tone"
    >
      <p class="truncate text-xs font-medium opacity-75">
        {{ card.label }}
      </p>
      <div
        v-if="card.kind === 'gauge'"
        class="mt-1.5 flex min-w-0 items-center gap-2.5"
      >
        <div
          class="relative grid h-12 w-12 shrink-0 place-items-center rounded-full"
          :style="{
            background: `conic-gradient(${card.color} ${card.percent * 3.6}deg, ${card.track} 0deg)`,
          }"
        >
          <div
            class="grid h-9 w-9 place-items-center rounded-full bg-white text-[10px] font-semibold text-slate-950 shadow-inner"
            :title="card.value"
          >
            {{ card.gaugeValue }}
          </div>
        </div>
        <div class="grid min-w-0 flex-1 gap-1 leading-none">
          <div class="flex min-w-0 items-baseline justify-between gap-2">
            <p class="text-[10px] leading-3 text-slate-500">
              {{ card.primaryLabel }}
            </p>
            <p
              class="truncate text-xs font-semibold leading-4 text-slate-950"
              :title="card.primaryValue"
            >
              {{ card.primaryValue }}
            </p>
          </div>
          <div class="flex min-w-0 items-baseline justify-between gap-2">
            <p class="text-[10px] leading-3 text-slate-500">
              {{ card.secondaryLabel }}
            </p>
            <p
              class="truncate text-xs font-semibold leading-4 text-slate-950"
              :title="card.secondaryValue"
            >
              {{ card.secondaryValue }}
            </p>
          </div>
        </div>
      </div>
      <div v-else class="mt-2 min-w-0">
        <div class="grid gap-1.5 text-[11px]">
          <div class="min-w-0">
            <div class="flex min-w-0 items-baseline justify-between gap-2">
              <p class="text-slate-500">Read</p>
              <p
                class="truncate font-semibold leading-4 text-slate-950"
                :title="card.readValue"
              >
                {{ card.readValue }}
              </p>
            </div>
            <div class="mt-0.5 h-1 overflow-hidden rounded-full bg-slate-100">
              <div
                class="h-full rounded-full bg-indigo-600"
                :style="{ width: `${card.readPercent}%` }"
              ></div>
            </div>
          </div>
          <div class="min-w-0">
            <div class="flex min-w-0 items-baseline justify-between gap-2">
              <p class="text-slate-500">Write</p>
              <p
                class="truncate font-semibold leading-4 text-slate-950"
                :title="card.writeValue"
              >
                {{ card.writeValue }}
              </p>
            </div>
            <div class="mt-0.5 h-1 overflow-hidden rounded-full bg-slate-100">
              <div
                class="h-full rounded-full bg-cyan-600"
                :style="{ width: `${card.writePercent}%` }"
              ></div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <MetricWidget
      label="累计处理报文"
      :value="formatNumber(Math.round(totalPackets))"
      :hint="`累计处理 ${formatBytes(totalBytes)}`"
      :series="totalPacketSeries"
      :series-min="0"
      :series-max="packetSparkMax"
      ambient-series
      no-top-line
      trend-placement="corner"
      filled
    />
    <MetricWidget
      label="平均代理延迟"
      :value="formatLatency(latencyValue)"
      :hint="`失败关闭次数 ${formatNumber(proxyFailCloseRejections)}`"
      :trend="latencyTrend"
      :series="latencySeries"
      :series-min="0"
      :series-max="latencySparkMax"
      ambient-series
      no-top-line
      trend-placement="corner"
      filled
    />
    <MetricWidget
      label="代理成功率"
      :value="successRate"
      :hint="`成功 ${formatNumber(proxySuccesses)} / 失败 ${formatNumber(proxyFailures)}`"
      :trend="successRateTrend"
      :progress="proxySuccessPercent"
      no-top-line
      trend-placement="corner"
      filled
    />
    <MetricWidget
      label="累计拦截次数"
      :value="formatNumber(blockedPackets)"
      :hint="`四层 ${formatNumber(blockedL4)} / HTTP ${formatNumber(blockedL7)}`"
      :trend="blockedTrend"
      no-top-line
      trend-placement="corner"
      filled
    />
  </section>
</template>
