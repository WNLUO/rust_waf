<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L4StatsPayload } from '@/shared/types'

defineProps<{
  formatNumber: (value?: number) => string
  formatBytes: (value?: number) => string
  stats: L4StatsPayload | null
  topPorts: L4StatsPayload['per_port_stats']
}>()
</script>

<template>
  <CyberCard
    title="端口维度统计"
    sub-title="优先按拦截量、DDoS 事件和连接量排序，便于快速看出热点端口。"
    no-padding
  >
    <div v-if="topPorts.length" class="overflow-x-auto">
      <table class="min-w-full border-collapse text-left">
        <thead class="bg-slate-50 text-sm text-slate-500">
          <tr>
            <th class="px-4 py-3 font-medium">目标端口</th>
            <th class="px-4 py-3 font-medium">连接数</th>
            <th class="px-4 py-3 font-medium">拦截数</th>
            <th class="px-4 py-3 font-medium">DDoS 事件</th>
            <th class="px-4 py-3 font-medium">处理字节</th>
            <th class="px-4 py-3 font-medium">关注度</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in topPorts"
            :key="item.port"
            class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
          >
            <td class="px-4 py-3 font-mono font-semibold">
              {{ item.port }}
            </td>
            <td class="px-4 py-3">{{ formatNumber(item.connections) }}</td>
            <td class="px-4 py-3">{{ formatNumber(item.blocks) }}</td>
            <td class="px-4 py-3">{{ formatNumber(item.ddos_events) }}</td>
            <td class="px-4 py-3">
              {{
                item.bytes_processed > 0
                  ? formatNumber(item.bytes_processed)
                  : '未接入'
              }}
            </td>
            <td class="px-4 py-3">
              <StatusBadge
                :text="
                  item.blocks > 0 || item.ddos_events > 0
                    ? '重点关注'
                    : '流量观测'
                "
                :type="
                  item.blocks > 0 || item.ddos_events > 0 ? 'warning' : 'muted'
                "
                compact
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="px-4 py-6 text-center text-sm text-slate-500">
      当前还没有端口级统计数据，通常意味着运行中的 L4 检测尚未接收到流量。
    </div>
  </CyberCard>
</template>
