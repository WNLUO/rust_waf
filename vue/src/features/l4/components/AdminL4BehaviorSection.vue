<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L4BehaviorOverview, L4BucketItem } from '@/shared/types'
import { AlertTriangle, Layers3, RadioTower, Shield } from 'lucide-vue-next'

defineProps<{
  behaviorOverview: L4BehaviorOverview
  formatBytes: (value?: number) => string
  formatNumber: (value?: number) => string
  formatTimestamp: (value?: number | null) => string
  topBuckets: L4BucketItem[]
}>()

const riskType = (risk: L4BucketItem['risk_level']) => {
  if (risk === 'high') return 'error'
  if (risk === 'suspicious') return 'warning'
  return 'success'
}

const riskText = (risk: L4BucketItem['risk_level']) => {
  if (risk === 'high') return '高风险'
  if (risk === 'suspicious') return '可疑'
  return '正常'
}

const modeText = (mode: string) => {
  if (mode === 'tighten') return '收紧'
  if (mode === 'degrade') return '降级'
  return '放行'
}

const hasL7Signals = (bucket: L4BucketItem) =>
  bucket.l7_block_hits > 0 || bucket.safeline_hits > 0
</script>

<template>
  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="L4.5 分桶数"
      :value="formatNumber(behaviorOverview.bucket_count)"
      :hint="`细粒度 ${formatNumber(behaviorOverview.fine_grained_buckets)} / coarse ${formatNumber(behaviorOverview.coarse_buckets)} / peer-only ${formatNumber(behaviorOverview.peer_only_buckets)}`"
      :icon="Layers3"
    />
    <MetricWidget
      label="雷池反馈命中"
      :value="formatNumber(behaviorOverview.safeline_feedback_hits)"
      :hint="`L7 拦截反馈 ${formatNumber(behaviorOverview.l7_feedback_hits)}`"
      :icon="Shield"
      trend="up"
    />
    <MetricWidget
      label="高风险分桶"
      :value="formatNumber(behaviorOverview.high_risk_buckets)"
      :hint="
        behaviorOverview.overload_level !== 'normal'
          ? `当前处于 ${behaviorOverview.overload_level} 过载态`
          : '当前未触发过载保护'
      "
      :icon="AlertTriangle"
      :trend="behaviorOverview.high_risk_buckets ? 'up' : undefined"
    />
    <MetricWidget
      label="系统负载态"
      :value="
        behaviorOverview.overload_level === 'critical'
          ? 'Critical'
          : behaviorOverview.overload_level === 'high'
            ? 'High'
            : 'Normal'
      "
      :hint="
        behaviorOverview.overload_reason ||
        `丢弃事件 ${formatNumber(behaviorOverview.dropped_events)}`
      "
      :icon="RadioTower"
      :trend="behaviorOverview.overload_level !== 'normal' ? 'up' : 'down'"
    />
  </section>

  <CyberCard
    title="连接群风险分桶"
    sub-title="按 (cdn_ip, authority, alpn, transport) 聚合，优先展示最需要被收紧策略的回源连接群。"
    no-padding
  >
    <div v-if="topBuckets.length" class="max-h-[32rem] overflow-auto">
      <table class="min-w-full border-collapse text-left">
        <thead class="bg-slate-50 text-sm text-slate-500">
          <tr>
            <th class="px-4 py-3 font-medium">回源桶</th>
            <th class="px-4 py-3 font-medium">风险</th>
            <th class="px-4 py-3 font-medium">实时活动</th>
            <th class="px-4 py-3 font-medium">L7 联动</th>
            <th class="px-4 py-3 font-medium">连接策略</th>
            <th class="px-4 py-3 font-medium">累计流量</th>
            <th class="px-4 py-3 font-medium">最近出现</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="bucket in topBuckets"
            :key="`${bucket.peer_ip}-${bucket.authority}-${bucket.alpn}-${bucket.transport}`"
            class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
          >
            <td class="px-4 py-3 align-top">
              <div class="space-y-1">
                <div class="font-mono font-semibold text-stone-900">
                  {{ bucket.peer_ip }}
                </div>
                <div class="text-xs text-slate-500">
                  {{ bucket.authority }} / {{ bucket.alpn }} / {{ bucket.transport }}
                </div>
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div class="flex flex-col items-start gap-2">
                <StatusBadge
                  :text="`${riskText(bucket.risk_level)} · ${bucket.risk_score}`"
                  :type="riskType(bucket.risk_level)"
                  compact
                />
                <span
                  v-if="bucket.policy.reject_new_connections"
                  class="inline-flex w-fit items-center rounded-full border border-red-200 bg-red-50 px-2 py-0.5 text-[11px] font-semibold tracking-wide text-red-700"
                >
                  拒绝新连接
                </span>
                <span
                  v-if="
                    bucket.protocol_hint &&
                    bucket.protocol_hint !== 'n/a' &&
                    bucket.protocol_hint !== bucket.alpn
                  "
                  class="text-xs text-slate-500"
                >
                  {{ bucket.protocol_hint }}
                </span>
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div class="text-xs text-slate-600">
                10s 连接
                <span class="font-medium text-stone-900">{{
                  formatNumber(bucket.recent_connections_10s)
                }}</span>
                · 请求
                <span class="font-medium text-stone-900">{{
                  formatNumber(bucket.recent_requests_10s)
                }}</span>
                · 120s 反馈
                <span
                  :class="
                    bucket.recent_feedback_120s > 0
                      ? 'font-medium text-amber-700'
                      : 'font-medium text-stone-900'
                  "
                >
                  {{ formatNumber(bucket.recent_feedback_120s) }}
                </span>
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div v-if="hasL7Signals(bucket)" class="flex flex-wrap gap-1.5 text-xs">
                <span
                  class="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 font-medium text-amber-700"
                >
                  L7 拦截 {{ formatNumber(bucket.l7_block_hits) }}
                </span>
                <span
                  class="inline-flex items-center rounded-full border border-cyan-200 bg-cyan-50 px-2 py-0.5 font-medium text-cyan-700"
                >
                  雷池命中 {{ formatNumber(bucket.safeline_hits) }}
                </span>
              </div>
              <div v-else>
                <span
                  class="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-600"
                >
                  无联动命中
                </span>
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div class="flex flex-col items-start gap-2">
                <StatusBadge
                  :text="`${modeText(bucket.policy.mode)} / ${formatNumber(bucket.policy.connection_budget_per_minute)} rpm`"
                  :type="riskType(bucket.risk_level)"
                  compact
                />
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div class="space-y-1 text-xs text-slate-600">
                <div>{{ formatBytes(bucket.total_bytes) }}</div>
                <div>{{ formatNumber(bucket.total_requests) }} 累计请求</div>
              </div>
            </td>
            <td class="px-4 py-3 align-top text-xs text-slate-500">
              {{ formatTimestamp(bucket.last_seen_at) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="px-4 py-6 text-center text-sm text-slate-500">
      当前还没有形成可展示的连接群分桶，通常意味着尚未收到足够的 HTTP 或 TLS 回源流量。
    </div>
  </CyberCard>
</template>
