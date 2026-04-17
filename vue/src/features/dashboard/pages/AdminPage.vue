<script setup lang="ts">
import { defineAsyncComponent } from 'vue'
import { RouterLink } from 'vue-router'
import AppLayout from '@/app/layout/AppLayout.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import { Activity, Database, Gauge, RefreshCw, Shield } from 'lucide-vue-next'
import { useAdminDashboardPage } from '@/features/dashboard/composables/useAdminDashboardPage'

const AdminEventMapSection = defineAsyncComponent(
  () => import('@/features/dashboard/components/AdminEventMapSection.vue'),
)

const {
  dashboard,
  trafficMap,
  trafficEvents,
  l4Stats,
  l7Stats,
  loading,
  refreshing,
  metricsHistory,
  formatBytes,
  formatNumber,
  formatLatency,
  successRate,
  requestStatus,
  autoSlo,
  adaptiveRuntime,
  adaptiveManaged,
  adaptivePressureType,
  runtimePressureType,
  storageInsights,
  storageDegradedReasons,
  storageInsightType,
  formatShortTime,
  hotspotEventsRoute,
  summaryEventsRoute,
  autoStateStyles,
  tlsTimeoutState,
  bucketRejectState,
  latencyState,
  fetchData,
} = useAdminDashboardPage()
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs text-slate-500 whitespace-nowrap">{{
          requestStatus
        }}</span>
        <button
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          :disabled="refreshing"
          @click="fetchData()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          同步
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-6 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="累计处理报文"
          :value="formatNumber(dashboard?.metrics.total_packets || 0)"
          :hint="`累计流量 ${formatBytes(dashboard?.metrics.total_bytes || 0)}`"
          :icon="Activity"
          :series="metricsHistory.totalPackets"
        />
        <MetricWidget
          label="累计拦截次数"
          :value="formatNumber(dashboard?.metrics.blocked_packets || 0)"
          :hint="`四层 ${formatNumber(dashboard?.metrics.blocked_l4 || 0)} / HTTP ${formatNumber(dashboard?.metrics.blocked_l7 || 0)}`"
          :icon="Shield"
          trend="up"
          :series="metricsHistory.blockRate"
        />
        <MetricWidget
          label="平均代理延迟"
          :value="
            formatLatency(dashboard?.metrics.average_proxy_latency_micros || 0)
          "
          :hint="`失败关闭次数 ${formatNumber(dashboard?.metrics.proxy_fail_close_rejections || 0)}`"
          :icon="Gauge"
          trend="down"
          :series="metricsHistory.latency"
        />
        <MetricWidget
          label="代理成功率"
          :value="successRate"
          :hint="`成功 ${formatNumber(dashboard?.metrics.proxy_successes || 0)} / 失败 ${formatNumber(dashboard?.metrics.proxy_failures || 0)}`"
          :icon="Database"
        />
      </section>

      <section class="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <AdminEventMapSection
          :traffic-map="trafficMap"
          :traffic-events="trafficEvents"
        />

        <CyberCard title="运行摘要">
          <div class="grid gap-4">
            <div class="rounded-xl border border-amber-200 bg-amber-50/70 p-4">
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p class="text-xs text-amber-700/80">挑战 / 429 拦截</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.l7_cc_challenges || 0) }}
                    /
                    {{ formatNumber(dashboard?.metrics.l7_cc_blocks || 0) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-amber-700/80">延迟处置 / 放行</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.l7_cc_delays || 0) }}
                    /
                    {{
                      formatNumber(
                        dashboard?.metrics.l7_cc_verified_passes || 0,
                      )
                    }}
                  </p>
                </div>
              </div>
            </div>

            <div class="rounded-xl bg-slate-50 px-4 py-3">
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <p class="text-xs text-slate-500">成功</p>
                  <p class="mt-0.5 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-500">上游代理失败</p>
                  <p class="mt-0.5 text-2xl font-semibold text-red-600">
                    {{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}
                  </p>
                </div>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div class="rounded-xl border border-slate-200 p-4">
                <div class="flex items-center justify-between gap-3">
                  <p class="text-xs text-slate-500">上游状态</p>
                  <StatusBadge
                    :text="dashboard?.health.upstream_healthy ? '可用' : '异常'"
                    :type="
                      dashboard?.health.upstream_healthy ? 'success' : 'error'
                    "
                  />
                </div>
                <p class="mt-2 text-2xl font-semibold text-slate-900">
                  {{ dashboard?.health.upstream_healthy ? '健康' : '异常降级' }}
                </p>
              </div>
              <div class="rounded-xl border border-slate-200 p-4">
                <p class="text-xs text-slate-500">最近检查</p>
                <p class="mt-2 text-lg font-semibold text-slate-900">
                  {{
                    dashboard?.health.upstream_last_check_at
                      ? new Intl.DateTimeFormat('zh-CN', {
                          month: '2-digit',
                          day: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        }).format(
                          new Date(
                            dashboard.health.upstream_last_check_at * 1000,
                          ),
                        )
                      : '暂无记录'
                  }}
                </p>
                <p
                  v-if="dashboard?.health.upstream_last_error"
                  class="mt-2 truncate text-xs text-red-600"
                  :title="dashboard.health.upstream_last_error"
                >
                  {{ dashboard.health.upstream_last_error }}
                </p>
              </div>
            </div>

            <div class="rounded-xl border border-slate-200 p-4">
              <div class="flex items-center justify-between gap-3">
                <p class="text-xs text-slate-500">运行时压力</p>
                <StatusBadge
                  :text="dashboard?.metrics.runtime_pressure_level || 'normal'"
                  :type="runtimePressureType"
                />
              </div>
              <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p class="text-xs text-slate-500">SQLite 队列占用</p>
                  <p class="mt-1 text-lg font-semibold text-stone-900">
                    {{
                      formatNumber(
                        dashboard?.metrics
                          .runtime_pressure_storage_queue_percent || 0,
                      )
                    }}%
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-500">攻击态降级</p>
                  <p class="mt-1 text-lg font-semibold text-stone-900">
                    {{
                      dashboard?.metrics.runtime_pressure_drop_delay ||
                      dashboard?.metrics.runtime_pressure_trim_event_persistence
                        ? '已启用'
                        : '未启用'
                    }}
                  </p>
                </div>
              </div>
              <p class="mt-3 text-xs leading-5 text-slate-500">
                {{
                  dashboard?.metrics.runtime_pressure_drop_delay
                    ? '当前会优先收紧 delay 处置，避免 worker 被 sleep 型流量拖住。'
                    : dashboard?.metrics.runtime_pressure_trim_event_persistence
                      ? '当前会裁剪低价值事件持久化，优先保证主链吞吐。'
                      : '当前处于常态观测模式，未触发运行时降级。'
                }}
              </p>
            </div>

            <div class="rounded-xl border border-slate-200 p-4">
              <div class="flex items-center justify-between gap-3">
                <p class="text-xs text-slate-500">存储退化洞察</p>
                <StatusBadge
                  :text="
                    storageInsights.active_bucket_count > 0
                      ? `热点 ${formatNumber(storageInsights.hotspot_sources.length)}`
                      : '未激活'
                  "
                  :type="storageInsightType"
                />
              </div>
              <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p class="text-xs text-slate-500">聚合桶 / 聚合事件</p>
                  <p class="mt-1 text-lg font-semibold text-stone-900">
                    {{ formatNumber(storageInsights.active_bucket_count) }} /
                    {{ formatNumber(storageInsights.active_event_count) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-500">长尾桶 / 长尾事件</p>
                  <p class="mt-1 text-lg font-semibold text-stone-900">
                    {{ formatNumber(storageInsights.long_tail_bucket_count) }} /
                    {{ formatNumber(storageInsights.long_tail_event_count) }}
                  </p>
                </div>
              </div>
              <div
                v-if="storageDegradedReasons.length"
                class="mt-3 flex flex-wrap gap-2"
              >
                <span
                  v-for="reason in storageDegradedReasons"
                  :key="reason"
                  class="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] text-amber-700"
                >
                  {{ reason }}
                </span>
              </div>
              <div
                v-if="storageInsights.hotspot_sources.length"
                class="mt-3 space-y-2"
              >
                <RouterLink
                  v-for="hotspot in storageInsights.hotspot_sources"
                  :key="`${hotspot.source_ip}-${hotspot.action}-${hotspot.route}-${hotspot.time_window_start}`"
                  :to="
                    hotspotEventsRoute(
                      hotspot.source_ip,
                      hotspot.route,
                      hotspot.time_window_start,
                      hotspot.time_window_end,
                    )
                  "
                  class="block rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 transition hover:border-blue-300 hover:bg-blue-50/60"
                >
                  <div class="flex items-center justify-between gap-3">
                    <p class="font-medium text-stone-900">
                      {{ hotspot.source_ip }}
                    </p>
                    <p class="text-xs text-slate-500">
                      {{ formatNumber(hotspot.count) }} 次
                    </p>
                  </div>
                  <p class="mt-1 text-xs text-slate-500">
                    {{ hotspot.action }} · {{ hotspot.route || '无路由' }} ·
                    {{ formatShortTime(hotspot.time_window_start) }} -
                    {{ formatShortTime(hotspot.time_window_end) }}
                  </p>
                </RouterLink>
              </div>
              <div v-else class="mt-3 text-xs leading-5 text-slate-500">
                当前没有活跃的热点聚合，低价值事件仍以常态方式记录。
              </div>
              <RouterLink
                :to="summaryEventsRoute"
                class="mt-3 inline-flex items-center rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 transition hover:border-blue-300 hover:text-blue-700"
              >
                查看全部摘要事件
              </RouterLink>
            </div>

            <div class="rounded-xl border border-slate-200 p-4">
              <p class="text-xs text-slate-500">本地数据库状态</p>
              <div class="mt-3 flex items-center justify-between">
                <p class="text-lg font-semibold text-stone-900">
                  {{ dashboard?.metrics.sqlite_enabled ? '已启用' : '未启用' }}
                </p>
                <StatusBadge
                  :text="
                    dashboard?.metrics.sqlite_enabled ? '持久化可用' : '未连接'
                  "
                  :type="
                    dashboard?.metrics.sqlite_enabled ? 'success' : 'muted'
                  "
                />
              </div>
            </div>
          </div>
        </CyberCard>
      </section>

      <section
        class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <div class="flex items-center justify-between gap-3">
          <div>
            <p class="text-sm tracking-wider text-blue-700">CC 防护摘要</p>
            <p class="mt-1 text-xs text-slate-500">
              展示挑战、硬拦截、延迟处置与验证放行的整体情况
            </p>
          </div>
          <StatusBadge
            :text="
              (dashboard?.metrics.l7_cc_challenges || 0) +
                (dashboard?.metrics.l7_cc_blocks || 0) >
              0
                ? '防护活跃'
                : '暂无命中'
            "
            :type="
              (dashboard?.metrics.l7_cc_challenges || 0) +
                (dashboard?.metrics.l7_cc_blocks || 0) >
              0
                ? 'warning'
                : 'muted'
            "
          />
        </div>

        <div class="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <p class="text-xs text-slate-500">挑战次数</p>
            <p class="mt-2 text-2xl font-semibold text-slate-900">
              {{ formatNumber(dashboard?.metrics.l7_cc_challenges || 0) }}
            </p>
            <p class="mt-2 text-xs text-slate-500">已返回验证页或验证响应</p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <p class="text-xs text-slate-500">硬拦截次数</p>
            <p class="mt-2 text-2xl font-semibold text-slate-900">
              {{ formatNumber(dashboard?.metrics.l7_cc_blocks || 0) }}
            </p>
            <p class="mt-2 text-xs text-slate-500">HTTP 拦截中的直接拒绝部分</p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <p class="text-xs text-slate-500">延迟处置次数</p>
            <p class="mt-2 text-2xl font-semibold text-slate-900">
              {{ formatNumber(dashboard?.metrics.l7_cc_delays || 0) }}
            </p>
            <p class="mt-2 text-xs text-slate-500">命中软阈值后执行延迟</p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <p class="text-xs text-slate-500">验证后放行次数</p>
            <p class="mt-2 text-2xl font-semibold text-slate-900">
              {{ formatNumber(dashboard?.metrics.l7_cc_verified_passes || 0) }}
            </p>
            <p class="mt-2 text-xs text-slate-500">已完成挑战验证并继续放行</p>
          </div>
        </div>
      </section>

      <section
        v-if="adaptiveManaged && adaptiveRuntime"
        class="rounded-xl border border-emerald-200 bg-[linear-gradient(135deg,rgba(240,253,244,0.92),rgba(236,253,245,0.88),rgba(239,246,255,0.9))] p-4 shadow-sm"
      >
        <div
          class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between"
        >
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <p class="text-sm tracking-wider text-emerald-700">自适应防护</p>
              <StatusBadge
                :text="adaptiveRuntime.system_pressure"
                :type="adaptivePressureType"
              />
            </div>
            <p class="text-sm leading-6 text-stone-700">
              当前按 {{ adaptiveRuntime.mode }} /
              {{ adaptiveRuntime.goal }} 自动调节 L4 与
              L7。首页展示的是运行时主策略，不再把细粒度阈值当主操作面板。
            </p>
          </div>
          <div class="grid gap-3 text-sm text-stone-700 md:grid-cols-2">
            <div class="rounded-lg border border-white/80 bg-white/70 p-3">
              <p class="text-xs text-slate-500">L4 连接预算</p>
              <p class="mt-1 font-semibold text-stone-900">
                {{ adaptiveRuntime.l4.normal_connection_budget_per_minute }} /
                {{ adaptiveRuntime.l4.suspicious_connection_budget_per_minute }}
                /
                {{ adaptiveRuntime.l4.high_risk_connection_budget_per_minute }}
              </p>
            </div>
            <div class="rounded-lg border border-white/80 bg-white/70 p-3">
              <p class="text-xs text-slate-500">L7 挑战 / 封禁阈值</p>
              <p class="mt-1 font-semibold text-stone-900">
                {{ adaptiveRuntime.l7.ip_challenge_threshold }} /
                {{ adaptiveRuntime.l7.ip_block_threshold }}
              </p>
            </div>
          </div>
        </div>
        <div
          v-if="adaptiveRuntime.reasons.length"
          class="mt-3 flex flex-wrap gap-2"
        >
          <span
            v-for="reason in adaptiveRuntime.reasons"
            :key="reason"
            class="rounded-full border border-white/80 bg-white/70 px-2.5 py-1 text-xs text-stone-700"
          >
            {{ reason }}
          </span>
        </div>
      </section>

      <section class="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm tracking-wider text-blue-700">L7 自动调优</p>
            <StatusBadge
              :text="l7Stats?.auto_tuning.mode || 'off'"
              :type="
                l7Stats?.auto_tuning.mode === 'active'
                  ? 'success'
                  : l7Stats?.auto_tuning.mode === 'observe'
                    ? 'warning'
                    : 'muted'
              "
            />
          </div>
          <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">控制器状态</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ l7Stats?.auto_tuning.controller_state || 'unknown' }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">最近动作</p>
              <p
                class="mt-1 font-semibold text-slate-900 truncate"
                :title="l7Stats?.auto_tuning.last_adjust_reason || ''"
              >
                {{ l7Stats?.auto_tuning.last_adjust_reason || 'none' }}
              </p>
            </div>
            <div
              :class="`rounded-lg border p-3 ${autoStateStyles[tlsTimeoutState]}`"
            >
              <p class="text-xs text-slate-500">握手超时率</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_tls_handshake_timeout_rate_percent || 0
                  ).toFixed(2)
                }}%
              </p>
              <p class="mt-1 text-[11px]">
                目标 ≤
                {{ autoSlo.tls_handshake_timeout_rate_percent.toFixed(2) }}%
              </p>
            </div>
            <div
              :class="`rounded-lg border p-3 ${autoStateStyles[bucketRejectState]}`"
            >
              <p class="text-xs text-slate-500">预算拒绝率</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_bucket_reject_rate_percent || 0
                  ).toFixed(2)
                }}%
              </p>
              <p class="mt-1 text-[11px]">
                目标 ≤ {{ autoSlo.bucket_reject_rate_percent.toFixed(2) }}%
              </p>
            </div>
            <div
              :class="`rounded-lg border p-3 ${autoStateStyles[latencyState]}`"
            >
              <p class="text-xs text-slate-500">平均代理延迟</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    l7Stats?.auto_tuning.last_observed_avg_proxy_latency_ms ||
                      0,
                  )
                }}
                ms
              </p>
              <p class="mt-1 text-[11px]">
                目标 ≤ {{ formatNumber(autoSlo.p95_proxy_latency_ms) }} ms
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">24h 回滚次数</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l7Stats?.auto_tuning.rollback_count_24h || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 预握手拒绝累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    dashboard?.metrics.tls_pre_handshake_rejections || 0,
                  )
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 握手超时累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(dashboard?.metrics.tls_handshake_timeouts || 0)
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 握手失败累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(dashboard?.metrics.tls_handshake_failures || 0)
                }}
              </p>
            </div>
          </div>
          <p class="mt-3 text-xs text-slate-500">
            资源探测: CPU
            {{ l7Stats?.auto_tuning.detected_cpu_cores || 0 }} cores / 内存上限
            {{ l7Stats?.auto_tuning.detected_memory_limit_mb ?? 'unknown' }} MB
          </p>
        </div>

        <div class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm tracking-wider text-blue-700">L4 自动防护</p>
            <StatusBadge
              :text="l4Stats?.behavior.overview.overload_level || 'normal'"
              :type="
                l4Stats?.behavior.overview.overload_level === 'critical'
                  ? 'error'
                  : l4Stats?.behavior.overview.overload_level === 'high'
                    ? 'warning'
                    : 'success'
              "
            />
          </div>
          <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">Bucket 总数</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l4Stats?.behavior.overview.bucket_count || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">高风险 Bucket</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    l4Stats?.behavior.overview.high_risk_buckets || 0,
                  )
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">事件丢弃</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(l4Stats?.behavior.overview.dropped_events || 0)
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">预算拒绝累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    dashboard?.metrics.l4_bucket_budget_rejections || 0,
                  )
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">推荐 normal budget</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    l7Stats?.auto_tuning.recommendation
                      .l4_normal_connection_budget_per_minute || 0,
                  )
                }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">推荐 TLS 握手超时</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{
                  formatNumber(
                    l7Stats?.auto_tuning.recommendation
                      .tls_handshake_timeout_ms || 0,
                  )
                }}
                ms
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  </AppLayout>
</template>
