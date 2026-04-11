<script setup lang="ts">
import { Activity, Ban, Database, Shield } from 'lucide-vue-next'
import MetricWidget from '../ui/MetricWidget.vue'
import StatusBadge from '../ui/StatusBadge.vue'
import type { L4StatsPayload } from '../../lib/types'

defineProps<{
  formatNumber: (value?: number) => string
  meta: {
    runtime_enabled: boolean
    bloom_enabled: boolean
    bloom_false_positive_verification: boolean
    runtime_profile: string
  }
  runtimeProfileLabel: string
  runtimeStatus: boolean
  stats: L4StatsPayload | null
  topPortsCount: number
}>()
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
    <div
      class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
    >
      <div class="max-w-3xl">
        <p class="text-sm tracking-wider text-blue-700">L4 管理</p>
      </div>
      <div class="flex flex-wrap gap-3">
        <StatusBadge
          :text="runtimeStatus ? '运行中' : '未启用'"
          :type="runtimeStatus ? 'success' : 'warning'"
        />
        <StatusBadge :text="`配置档位 ${runtimeProfileLabel}`" type="info" />
        <StatusBadge
          :text="meta.bloom_enabled ? 'Bloom 已启用' : 'Bloom 未启用'"
          :type="meta.bloom_enabled ? 'info' : 'muted'"
        />
        <StatusBadge
          :text="
            meta.bloom_false_positive_verification
              ? '误判校验开启'
              : '误判校验关闭'
          "
          :type="meta.bloom_false_positive_verification ? 'success' : 'muted'"
        />
      </div>
    </div>
  </section>

  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="活跃连接"
      :value="formatNumber(stats?.connections.active_connections || 0)"
      :hint="`累计连接 ${formatNumber(stats?.connections.total_connections || 0)}`"
      :icon="Activity"
    />
    <MetricWidget
      label="当前封禁数"
      :value="formatNumber(stats?.connections.blocked_connections || 0)"
      :hint="`限流命中 ${formatNumber(stats?.connections.rate_limit_hits || 0)}`"
      :icon="Ban"
      trend="up"
    />
    <MetricWidget
      label="DDoS 事件"
      :value="formatNumber(stats?.ddos_events || 0)"
      :hint="`防御动作 ${formatNumber(stats?.defense_actions || 0)}`"
      :icon="Shield"
      trend="up"
    />
    <MetricWidget
      label="端口观测数"
      :value="formatNumber(topPortsCount)"
      :hint="`协议异常 ${formatNumber(stats?.protocol_anomalies || 0)} / 流量计数 ${formatNumber(stats?.traffic || 0)}`"
      :icon="Database"
    />
  </section>
</template>
