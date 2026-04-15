<script setup lang="ts">
import { computed } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL7OverviewSection from '@/features/l7/components/AdminL7OverviewSection.vue'
import { useAdminL7 } from '@/features/l7/composables/useAdminL7'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const { formatLatency, formatNumber, formatTimestamp } = useFormatters()

const {
  configForm,
  error,
  failureModeLabel,
  http1SecurityLabel,
  http3StatusLabel,
  http3StatusType,
  lastUpdated,
  loading,
  meta,
  protocolTags,
  proxySuccessRate,
  refreshAll,
  runtimeProfileLabel,
  runtimeStatus,
  stats,
  successMessage,
  upstreamProtocolLabel,
  upstreamStatusText,
  upstreamStatusType,
  refreshing,
} = useAdminL7()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L7 管理',
  successTitle: 'L7 管理',
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
        <span class="text-xs whitespace-nowrap text-slate-500">{{
          lastUpdatedLabel
        }}</span>
        <button
          :disabled="refreshing"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
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
        <p class="text-sm text-slate-500">正在载入 HTTP 接入管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <section
        v-if="meta.adaptive_managed_fields && meta.adaptive_runtime"
        class="rounded-2xl border border-emerald-200 bg-[linear-gradient(135deg,rgba(240,253,244,0.95),rgba(236,253,245,0.88),rgba(239,246,255,0.9))] p-4 shadow-sm"
      >
        <p class="text-sm font-semibold text-emerald-800">L7 已由自适应控制器主导</p>
        <p class="mt-2 text-sm leading-6 text-stone-700">
          当前系统压力为 {{ meta.adaptive_runtime.system_pressure }}。CC 窗口、延迟和 challenge / block 阈值会按运行时状态自动收紧或放宽，这里优先作为观测面板使用。
        </p>
        <p class="mt-2 text-xs leading-5 text-slate-500">
          旧的 CC 阈值和自动调优细项已归档到 `advanced_compatibility` 兼容层，主视图优先展示自动控制器当前生效策略。
        </p>
      </section>
      <AdminL7OverviewSection
        :config-form="configForm"
        :failure-mode-label="failureModeLabel"
        :format-latency="formatLatency"
        :format-number="formatNumber"
        :format-timestamp="formatTimestamp"
        :http1-security-label="http1SecurityLabel"
        :http3-status-label="http3StatusLabel"
        :http3-status-type="http3StatusType"
        :protocol-tags="protocolTags"
        :proxy-success-rate="proxySuccessRate"
        :runtime-profile-label="runtimeProfileLabel"
        :runtime-status="runtimeStatus"
        :stats="stats"
        :upstream-protocol-label="upstreamProtocolLabel"
        :upstream-status-text="upstreamStatusText"
        :upstream-status-type="upstreamStatusType"
      />
    </div>
  </AppLayout>
</template>
