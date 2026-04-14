<script setup lang="ts">
import { computed } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL4ArchitectureSection from '@/features/l4/components/AdminL4ArchitectureSection.vue'
import AdminL4BehaviorSection from '@/features/l4/components/AdminL4BehaviorSection.vue'
import AdminL4OverviewSection from '@/features/l4/components/AdminL4OverviewSection.vue'
import AdminL4RuntimeInsightsSection from '@/features/l4/components/AdminL4RuntimeInsightsSection.vue'
import AdminL4StatsSection from '@/features/l4/components/AdminL4StatsSection.vue'
import { useAdminL4 } from '@/features/l4/composables/useAdminL4'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const { formatBytes, formatNumber, formatTimestamp } = useFormatters()
const {
  behaviorOverview,
  blockedCapacityLabel,
  blockedCapacityTone,
  bloomPanels,
  configForm,
  error,
  falsePositivePanels,
  lastUpdated,
  loading,
  meta,
  refreshAll,
  refreshing,
  stats,
  successMessage,
  topBuckets,
  topPorts,
  totalProcessedBytes,
} = useAdminL4()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L4 管理',
  successTitle: 'L4 管理',
  errorDuration: 5600,
  successDuration: 3200,
})

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return '等待首次拉取'
  return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(lastUpdated.value))}`
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs text-slate-500 whitespace-nowrap">{{
          lastUpdatedLabel
        }}</span>
        <button
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          :disabled="refreshing"
          @click="refreshAll()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-6 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入 L4 管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <section
        v-if="meta.adaptive_managed_fields && meta.adaptive_runtime"
        class="rounded-2xl border border-emerald-200 bg-[linear-gradient(135deg,rgba(240,253,244,0.95),rgba(236,253,245,0.88),rgba(239,246,255,0.9))] p-4 shadow-sm"
      >
        <p class="text-sm font-semibold text-emerald-800">L4 已由自适应控制器主导</p>
        <p class="mt-2 text-sm leading-6 text-stone-700">
          当前系统压力为 {{ meta.adaptive_runtime.system_pressure }}，连接预算、延迟和拒绝阈值都按运行时状态自动调整。这里保留的是观测视图，不再建议把 L4 当成手工调阈值页面。
        </p>
      </section>
      <AdminL4OverviewSection
        :format-number="formatNumber"
        :stats="stats"
        :top-ports-count="topPorts.length"
      />
      <AdminL4BehaviorSection
        :behavior-overview="behaviorOverview"
        :format-bytes="formatBytes"
        :format-number="formatNumber"
        :format-timestamp="formatTimestamp"
        :top-buckets="topBuckets"
      />
      <AdminL4RuntimeInsightsSection
        :bloom-panels="bloomPanels"
        :false-positive-panels="falsePositivePanels"
        :format-number="formatNumber"
        :format-bytes="formatBytes"
        :meta="meta"
        :config-form="configForm"
        :stats="stats"
        :top-ports="topPorts"
        :total-processed-bytes="totalProcessedBytes"
        :blocked-capacity-label="blockedCapacityLabel"
        :blocked-capacity-tone="blockedCapacityTone"
      />
      <AdminL4StatsSection
        :format-bytes="formatBytes"
        :format-number="formatNumber"
        :stats="stats"
        :top-ports="topPorts"
      />
      <AdminL4ArchitectureSection />
    </div>
  </AppLayout>
</template>
