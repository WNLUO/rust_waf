<script setup lang="ts">
import { Activity, Ban, Database, Shield } from 'lucide-vue-next'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import type { L4StatsPayload } from '@/shared/types'

defineProps<{
  formatNumber: (value?: number) => string
  stats: L4StatsPayload | null
  topPortsCount: number
}>()
</script>

<template>
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
      :hint="
        (stats?.protocol_anomalies || 0) > 0 || (stats?.traffic || 0) > 0
          ? `协议异常 ${formatNumber(stats?.protocol_anomalies || 0)} / 流量计数 ${formatNumber(stats?.traffic || 0)}`
          : '协议异常与总流量统计当前仍以预留字段返回'
      "
      :icon="Database"
    />
  </section>
</template>
