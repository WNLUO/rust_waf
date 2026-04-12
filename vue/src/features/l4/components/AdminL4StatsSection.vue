<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'
import type { L4StatsPayload } from '@/shared/types'

defineProps<{
  blockedCapacityLabel: string
  blockedCapacityTone: 'success' | 'warning' | 'error'
  configForm: L4ConfigForm
  formatBytes: (value?: number) => string
  formatNumber: (value?: number) => string
  stats: L4StatsPayload | null
  topPorts: L4StatsPayload['per_port_stats']
  totalProcessedBytes: number
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
              {{ formatNumber(item.bytes_processed) }}
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

  <section class="grid gap-4 lg:grid-cols-3">
    <CyberCard title="限流阈值" sub-title="用于快速复核当前保存的关键阈值。">
      <div class="space-y-3 text-sm text-stone-700">
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>每秒连接阈值</span>
          <span class="font-mono font-semibold text-stone-900">{{
            formatNumber(configForm.connection_rate_limit)
          }}</span>
        </div>
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>突发判定阈值</span>
          <span class="font-mono font-semibold text-stone-900">{{
            formatNumber(configForm.syn_flood_threshold)
          }}</span>
        </div>
      </div>
    </CyberCard>

    <CyberCard title="容量上限" sub-title="帮助判断跟踪表和封禁表的容量预估。">
      <div class="space-y-3 text-sm text-stone-700">
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>跟踪 IP 上限</span>
          <span class="font-mono font-semibold text-stone-900">{{
            formatNumber(configForm.max_tracked_ips)
          }}</span>
        </div>
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>封禁表上限</span>
          <span class="font-mono font-semibold text-stone-900">{{
            formatNumber(configForm.max_blocked_ips)
          }}</span>
        </div>
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>当前封禁占用</span>
          <div class="flex items-center gap-2">
            <span class="font-mono font-semibold text-stone-900">
              {{ formatNumber(stats?.connections.blocked_connections || 0) }}
              / {{ formatNumber(configForm.max_blocked_ips) }}
            </span>
            <StatusBadge
              :text="blockedCapacityLabel"
              :type="blockedCapacityTone"
              compact
            />
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard title="清理策略" sub-title="维护任务会按这个 TTL 回收过期状态。">
      <div class="space-y-3 text-sm text-stone-700">
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>状态 TTL</span>
          <span class="font-mono font-semibold text-stone-900"
            >{{ formatNumber(configForm.state_ttl_secs) }} 秒</span
          >
        </div>
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>Bloom 缩放</span>
          <span class="font-mono font-semibold text-stone-900">{{
            configForm.bloom_filter_scale.toFixed(2)
          }}</span>
        </div>
        <div
          class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
        >
          <span>端口画像累计流量</span>
          <span class="font-mono font-semibold text-stone-900">
            {{ formatBytes(totalProcessedBytes) }}
          </span>
        </div>
      </div>
    </CyberCard>
  </section>
</template>
