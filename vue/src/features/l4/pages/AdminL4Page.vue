<script setup lang="ts">
import { computed } from 'vue'
import { RefreshCw, Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL4ArchitectureSection from '@/features/l4/components/AdminL4ArchitectureSection.vue'
import AdminL4BehaviorSection from '@/features/l4/components/AdminL4BehaviorSection.vue'
import AdminL4ConfigSection from '@/features/l4/components/AdminL4ConfigSection.vue'
import AdminL4OverviewSection from '@/features/l4/components/AdminL4OverviewSection.vue'
import AdminL4StatsSection from '@/features/l4/components/AdminL4StatsSection.vue'
import L4SectionNav from '@/features/l4/components/L4SectionNav.vue'
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
  runtimeProfileLabel,
  runtimeStatus,
  saveConfig,
  saving,
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
        <button
          class="inline-flex items-center gap-2 rounded-full bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:-translate-y-0.5 disabled:opacity-60"
          :disabled="saving || loading"
          @click="saveConfig"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存配置' }}
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
      <L4SectionNav />

      <AdminL4OverviewSection
        :format-number="formatNumber"
        :meta="meta"
        :runtime-profile-label="runtimeProfileLabel"
        :runtime-status="runtimeStatus"
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
      <AdminL4ConfigSection
        :bloom-panels="bloomPanels"
        :false-positive-panels="falsePositivePanels"
        :form="configForm"
        :format-number="formatNumber"
        :format-bytes="formatBytes"
        :meta="meta"
        :stats="stats"
        :top-ports="topPorts"
        :total-processed-bytes="totalProcessedBytes"
        :blocked-capacity-label="blockedCapacityLabel"
        :blocked-capacity-tone="blockedCapacityTone"
        @update:form="Object.assign(configForm, $event)"
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
