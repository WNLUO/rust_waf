<script setup lang="ts">
import { computed, ref } from 'vue'
import { Activity, ArrowUpRight, Shield, TimerReset } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'
import type { L7StatsPayload } from '@/shared/types'

const props = defineProps<{
  configForm: L7ConfigForm
  failureModeLabel: string
  formatLatency: (micros?: number) => string
  formatNumber: (value?: number) => string
  formatTimestamp: (timestamp?: number | null) => string
  http1SecurityLabel: string
  http3StatusLabel: string
  http3StatusType: 'success' | 'warning' | 'error' | 'muted' | 'info'
  proxySuccessRate: string
  protocolTags: Array<{
    text: string
    type: 'success' | 'warning' | 'error' | 'muted' | 'info'
  }>
  runtimeProfileLabel: string
  runtimeStatus: boolean
  stats: L7StatsPayload | null
  upstreamProtocolLabel: string
  upstreamStatusText: string
  upstreamStatusType: 'success' | 'warning' | 'error' | 'muted' | 'info'
}>()

const hotspotView = ref<'host' | 'route'>('host')

const autoEffectEvaluation = computed(() => props.stats?.auto_tuning.last_effect_evaluation ?? null)

const autoRiskLeaderboard = computed(() => {
  const segments = autoEffectEvaluation.value?.segments ?? []
  return [...segments]
    .filter((segment) => segment.status !== 'low_sample')
    .sort((left, right) => {
      const leftScore =
        (left.status === 'regressed' ? 1000 : left.status === 'stable' ? 300 : 0) +
        left.sample_requests * 10 +
        Math.max(left.avg_proxy_latency_delta_ms, 0) +
        Math.max(left.failure_rate_delta_percent, 0) * 20
      const rightScore =
        (right.status === 'regressed' ? 1000 : right.status === 'stable' ? 300 : 0) +
        right.sample_requests * 10 +
        Math.max(right.avg_proxy_latency_delta_ms, 0) +
        Math.max(right.failure_rate_delta_percent, 0) * 20
      return rightScore - leftScore
    })
    .slice(0, 5)
})

const autoRiskByHost = computed(() => {
  const buckets = new Map<
    string,
    {
      host: string
      sample_requests: number
      regressed_count: number
      stable_count: number
      max_latency_delta_ms: number
      max_failure_rate_delta_percent: number
      top_label: string
    }
  >()

  for (const segment of autoEffectEvaluation.value?.segments ?? []) {
    const host = segment.host || ''
    if (!host) continue
    const entry = buckets.get(host) ?? {
      host,
      sample_requests: 0,
      regressed_count: 0,
      stable_count: 0,
      max_latency_delta_ms: 0,
      max_failure_rate_delta_percent: 0,
      top_label: segmentLabel(segment),
    }
    entry.sample_requests += segment.sample_requests
    if (segment.status === 'regressed') entry.regressed_count += 1
    if (segment.status === 'stable') entry.stable_count += 1
    entry.max_latency_delta_ms = Math.max(entry.max_latency_delta_ms, Math.max(segment.avg_proxy_latency_delta_ms, 0))
    entry.max_failure_rate_delta_percent = Math.max(
      entry.max_failure_rate_delta_percent,
      Math.max(segment.failure_rate_delta_percent, 0),
    )
    if (segment.status === 'regressed') entry.top_label = segmentLabel(segment)
    buckets.set(host, entry)
  }

  return [...buckets.values()]
    .sort((left, right) => {
      const leftScore =
        left.regressed_count * 1000 +
        left.sample_requests * 10 +
        left.max_latency_delta_ms +
        left.max_failure_rate_delta_percent * 20
      const rightScore =
        right.regressed_count * 1000 +
        right.sample_requests * 10 +
        right.max_latency_delta_ms +
        right.max_failure_rate_delta_percent * 20
      return rightScore - leftScore
    })
    .slice(0, 4)
})

const autoRiskByRoute = computed(() => {
  const buckets = new Map<
    string,
    {
      route: string
      sample_requests: number
      regressed_count: number
      stable_count: number
      max_latency_delta_ms: number
      max_failure_rate_delta_percent: number
      top_label: string
    }
  >()

  for (const segment of autoEffectEvaluation.value?.segments ?? []) {
    const route = segment.route || ''
    if (!route) continue
    const entry = buckets.get(route) ?? {
      route,
      sample_requests: 0,
      regressed_count: 0,
      stable_count: 0,
      max_latency_delta_ms: 0,
      max_failure_rate_delta_percent: 0,
      top_label: segmentLabel(segment),
    }
    entry.sample_requests += segment.sample_requests
    if (segment.status === 'regressed') entry.regressed_count += 1
    if (segment.status === 'stable') entry.stable_count += 1
    entry.max_latency_delta_ms = Math.max(entry.max_latency_delta_ms, Math.max(segment.avg_proxy_latency_delta_ms, 0))
    entry.max_failure_rate_delta_percent = Math.max(
      entry.max_failure_rate_delta_percent,
      Math.max(segment.failure_rate_delta_percent, 0),
    )
    if (segment.status === 'regressed') entry.top_label = segmentLabel(segment)
    buckets.set(route, entry)
  }

  return [...buckets.values()]
    .sort((left, right) => {
      const leftScore =
        left.regressed_count * 1000 +
        left.sample_requests * 10 +
        left.max_latency_delta_ms +
        left.max_failure_rate_delta_percent * 20
      const rightScore =
        right.regressed_count * 1000 +
        right.sample_requests * 10 +
        right.max_latency_delta_ms +
        right.max_failure_rate_delta_percent * 20
      return rightScore - leftScore
    })
    .slice(0, 6)
})

const hotspotHeatmapCards = computed(() =>
  hotspotView.value === 'host' ? autoRiskByHost.value : autoRiskByRoute.value,
)

function formatSignedNumber(value: number, digits = 2) {
  const normalized = Number.isFinite(value) ? value : 0
  const fixed = normalized.toFixed(digits)
  return normalized > 0 ? `+${fixed}` : fixed
}

function formatSignedInteger(value: number) {
  const normalized = Number.isFinite(value) ? Math.round(value) : 0
  return normalized > 0 ? `+${normalized}` : `${normalized}`
}

function requestKindLabel(kind: string) {
  switch (kind) {
    case 'document':
      return '页面'
    case 'api':
      return 'API'
    case 'static':
      return '静态资源'
    default:
      return kind
  }
}

function segmentLabel(segment: {
  scope_type: string
  host: string | null
  route: string | null
  request_kind: string
  scope_key: string
}) {
  switch (segment.scope_type) {
    case 'request_kind':
      return `流量 ${requestKindLabel(segment.request_kind)}`
    case 'host':
      return `Host ${segment.host || segment.scope_key}`
    case 'route':
      return `Route ${segment.route || segment.scope_key}`
    case 'host_route':
      return `${segment.host || 'unknown-host'} ${segment.route || 'unknown-route'}`
    default:
      return segment.scope_key
  }
}

function segmentStatusLabel(status: string) {
  switch (status) {
    case 'improved':
      return '改善'
    case 'regressed':
      return '恶化'
    case 'stable':
      return '基本稳定'
    case 'low_sample':
      return '样本偏少'
    default:
      return status
  }
}

function riskSeverityClass(status: string) {
  switch (status) {
    case 'regressed':
      return 'border-rose-200 bg-rose-50 text-rose-700'
    case 'stable':
      return 'border-amber-200 bg-amber-50 text-amber-700'
    case 'improved':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700'
    default:
      return 'border-slate-200 bg-slate-50 text-slate-600'
  }
}

function hotspotCardClass(item: { regressed_count: number; stable_count: number }) {
  if (item.regressed_count > 0) return 'border-rose-200 bg-rose-50 text-rose-700'
  if (item.stable_count > 0) return 'border-amber-200 bg-amber-50 text-amber-700'
  return 'border-emerald-200 bg-emerald-50 text-emerald-700'
}

function hotspotViewButtonClass(view: 'host' | 'route') {
  return hotspotView.value === view
    ? 'border-blue-500 bg-blue-50 text-blue-700'
    : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'
}
</script>

<template>
  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="请求侧策略拦截"
      :value="formatNumber(stats?.blocked_requests || 0)"
      hint="来自请求规则与响应策略的累计阻断次数"
      :icon="Shield"
      trend="up"
    />
    <MetricWidget
      label="代理请求总数"
      :value="formatNumber(stats?.proxied_requests || 0)"
      :hint="`成功 ${formatNumber(stats?.proxy_successes || 0)} / 失败 ${formatNumber(stats?.proxy_failures || 0)}`"
      :icon="Activity"
    />
    <MetricWidget
      label="代理成功率"
      :value="proxySuccessRate"
      :hint="`失败关闭拒绝 ${formatNumber(stats?.proxy_fail_close_rejections || 0)}`"
      :icon="ArrowUpRight"
    />
    <MetricWidget
      label="平均代理延迟"
      :value="formatLatency(stats?.average_proxy_latency_micros || 0)"
      hint="仅统计成功代理请求"
      :icon="TimerReset"
      trend="down"
    />
  </section>

  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="CC 挑战次数"
      :value="formatNumber(stats?.cc_challenge_requests || 0)"
      hint="返回挑战页或挑战响应的累计次数"
      :icon="Shield"
    />
    <MetricWidget
      label="CC 429 次数"
      :value="formatNumber(stats?.cc_block_requests || 0)"
      hint="达到硬阈值后直接拒绝的累计次数"
      :icon="Activity"
      trend="up"
    />
    <MetricWidget
      label="CC 延迟处置"
      :value="formatNumber(stats?.cc_delayed_requests || 0)"
      hint="命中软压制并执行延迟的累计次数"
      :icon="TimerReset"
    />
    <MetricWidget
      label="挑战后放行"
      :value="formatNumber(stats?.cc_verified_pass_requests || 0)"
      :hint="`Cookie 标记 ${configForm.cc_defense.challenge_cookie_name} 验证通过后继续放行`"
      :icon="ArrowUpRight"
    />
  </section>

  <section class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
    <CyberCard title="协议支持" sub-title="网页协议与监听入口摘要">
      <template #header-action>
        <div class="self-end flex flex-wrap justify-end gap-2">
          <StatusBadge
            v-for="item in protocolTags"
            :key="item.text"
            :text="item.text"
            :type="item.type"
          />
        </div>
      </template>
      <div class="space-y-4">
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">监听地址</p>
            <div class="mt-3 space-y-2 text-sm text-stone-800">
              <p v-for="addr in configForm.listen_addrs" :key="addr">
                {{ addr }}
              </p>
              <p v-if="!configForm.listen_addrs.length" class="text-slate-500">
                暂无监听入口
              </p>
            </div>
          </div>
          <div class="rounded-xl bg-slate-50 p-4">
              <p class="text-xs tracking-wide text-slate-500">HTTP/3 监听入口</p>
            <p class="mt-3 text-sm text-stone-800">
              {{
                configForm.http3_enabled
                  ? configForm.http3_listen_addr || '已启用'
                  : '未启用 HTTP/3'
              }}
            </p>
          </div>
        </div>
        <div class="grid gap-3 md:grid-cols-3">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">
              HTTP/2 最大并发请求流
            </p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_max_concurrent_streams) }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">HTTP/2 最大帧</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_max_frame_size) }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">初始窗口</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_initial_window_size) }}
            </p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="代理链路摘要"
      sub-title="上游地址、健康状态与真实来源解析"
    >
      <template #header-action>
        <div class="self-end flex flex-wrap justify-end gap-2">
          <StatusBadge
            :text="`上游 ${upstreamStatusText}`"
            :type="upstreamStatusType"
          />
          <StatusBadge :text="`协议 ${upstreamProtocolLabel}`" type="info" />
          <StatusBadge
            :text="http1SecurityLabel"
            :type="configForm.upstream_http1_strict_mode ? 'success' : 'warning'"
          />
          <StatusBadge :text="`失败模式 ${failureModeLabel}`" type="warning" />
          <StatusBadge
            :text="
              configForm.upstream_healthcheck_enabled
                ? '健康检查开启'
                : '健康检查关闭'
            "
            :type="
              configForm.upstream_healthcheck_enabled ? 'success' : 'muted'
            "
          />
        </div>
      </template>
      <div class="space-y-4">
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">上游地址</p>
            <p class="mt-3 text-sm text-stone-800">
              {{ configForm.upstream_endpoint || '未配置上游地址' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">H1 风险收紧</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                [
                  configForm.reject_ambiguous_http1_requests ? '拒绝歧义长度' : '允许歧义长度',
                  configForm.reject_http1_transfer_encoding_requests ? '拒绝请求 TE' : '允许请求 TE',
                  configForm.reject_body_on_safe_http_methods ? '拒绝安全方法携带 body' : '允许安全方法携带 body',
                  configForm.reject_expect_100_continue ? '拒绝 Expect: 100-continue' : '允许 Expect: 100-continue',
                ].join('，')
              }}
            </p>
          </div>
        </div>
        <div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">可信代理网段</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                configForm.trusted_proxy_cidrs.length
                  ? configForm.trusted_proxy_cidrs.join('，')
                  : '未配置，默认仅信任直连对端'
              }}
            </p>
          </div>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">最近健康检查</p>
          <p class="mt-3 text-sm text-stone-800">
            {{
              stats?.upstream_last_check_at
                ? formatTimestamp(stats.upstream_last_check_at)
                : '暂无检查记录'
            }}
          </p>
          <p
            v-if="stats?.upstream_last_error"
            class="mt-2 text-sm text-red-600"
          >
            最近错误：{{ stats.upstream_last_error }}
          </p>
        </div>
      </div>
    </CyberCard>
  </section>

  <section class="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
    <CyberCard
      title="HTTP/3 运行状态"
      sub-title="编译能力、证书就绪度与监听启动结果"
    >
      <template #header-action>
        <div class="self-end flex flex-wrap justify-end gap-2">
          <StatusBadge
            :text="`状态 ${http3StatusLabel}`"
            :type="http3StatusType"
          />
          <StatusBadge
            :text="
              stats?.http3_feature_available ? '已编译 HTTP/3' : '未编译 HTTP/3'
            "
            :type="stats?.http3_feature_available ? 'info' : 'warning'"
          />
          <StatusBadge
            :text="stats?.http3_listener_started ? '监听已启动' : '监听未启动'"
            :type="stats?.http3_listener_started ? 'success' : 'muted'"
          />
        </div>
      </template>
      <div class="space-y-5">
        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">配置启用</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_configured_enabled ? '是' : '否' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">TLS 1.3</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_tls13_enabled ? '开启' : '关闭' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">证书路径</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_certificate_configured ? '已配置' : '缺失' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">私钥路径</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_private_key_configured ? '已配置' : '缺失' }}
            </p>
          </div>
        </div>
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">监听结果</p>
            <p class="mt-3 text-sm text-stone-800">
              {{
                stats?.http3_listener_started
                  ? stats?.http3_listener_addr || '监听已启动'
                  : '当前未启动 HTTP/3 监听器'
              }}
            </p>
          </div>
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">启动诊断</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                stats?.http3_last_error ||
                '没有诊断错误，当前状态允许启动 HTTP/3。'
              }}
            </p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="HTTP/3 配置摘要"
      sub-title="便于值班时快速对照配置与运行结果"
    >
      <div class="grid gap-3 md:grid-cols-2">
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">监听地址</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ configForm.http3_listen_addr || '跟随全局 HTTPS 入口' }}
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">最大并发流</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_max_concurrent_streams) }}
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">空闲超时</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_idle_timeout_secs) }} 秒
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">MTU / QPACK</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_mtu) }} /
            {{ formatNumber(configForm.http3_qpack_table_size) }}
          </p>
        </div>
      </div>
    </CyberCard>
  </section>

  <section
    v-if="autoEffectEvaluation"
    class="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]"
  >
    <CyberCard
      title="业务风险榜单"
      sub-title="按最新分层效果评估汇总热点风险段"
    >
      <div class="space-y-2">
        <div
          v-for="segment in autoRiskLeaderboard"
          :key="`${segment.scope_type}-${segment.scope_key}`"
          class="rounded-xl border px-3 py-3"
          :class="riskSeverityClass(segment.status)"
        >
          <p class="text-sm font-semibold">
            {{ segmentLabel(segment) }}
          </p>
          <p class="mt-2 text-xs leading-5">
            {{ segmentStatusLabel(segment.status) }} |
            样本 {{ segment.sample_requests }} |
            延迟 {{ formatSignedInteger(segment.avg_proxy_latency_delta_ms) }}ms |
            失败率 {{ formatSignedNumber(segment.failure_rate_delta_percent) }}pp
          </p>
        </div>
        <p
          v-if="!autoRiskLeaderboard.length"
          class="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-4 text-sm text-slate-500"
        >
          当前还没有足够的分层风险样本。
        </p>
      </div>
    </CyberCard>

    <CyberCard
      title="热点图视图"
      sub-title="在 Host 与 Route 两个维度切换查看热点热区"
    >
      <template #header-action>
        <div class="self-end flex items-center gap-2">
          <button
            type="button"
            class="rounded-full border px-3 py-1 text-xs font-semibold transition"
            :class="hotspotViewButtonClass('host')"
            @click="hotspotView = 'host'"
          >
            Host
          </button>
          <button
            type="button"
            class="rounded-full border px-3 py-1 text-xs font-semibold transition"
            :class="hotspotViewButtonClass('route')"
            @click="hotspotView = 'route'"
          >
            Route
          </button>
        </div>
      </template>
      <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-2">
        <div
          v-for="item in hotspotHeatmapCards"
          :key="'host' in item ? item.host : item.route"
          class="rounded-xl border px-3 py-3 shadow-sm"
          :class="hotspotCardClass(item)"
        >
          <p class="text-sm font-semibold">
            {{ 'host' in item ? item.host : item.route }}
          </p>
          <p class="mt-2 text-xs leading-5">
            风险段 {{ item.regressed_count + item.stable_count }} |
            样本 {{ item.sample_requests }}
          </p>
          <p class="mt-1 text-xs leading-5">
            热度 {{ formatSignedInteger(item.max_latency_delta_ms) }}ms /
            {{ formatSignedNumber(item.max_failure_rate_delta_percent) }}pp
          </p>
          <p class="mt-2 text-xs leading-5 opacity-80">
            主要热点: {{ item.top_label }}
          </p>
        </div>
        <p
          v-if="!hotspotHeatmapCards.length"
          class="rounded-xl border border-dashed border-slate-200 bg-slate-50 px-3 py-4 text-sm text-slate-500 md:col-span-2"
        >
          当前热点图还没有可展示的 Host / Route 风险样本。
        </p>
      </div>
    </CyberCard>
  </section>
</template>
