<script setup lang="ts">
import { computed } from 'vue'
import { RefreshCw, Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import L7SectionNav from '@/features/l7/components/L7SectionNav.vue'
import AdminL7ActivitySection from '@/features/l7/components/AdminL7ActivitySection.vue'
import AdminL7ConfigSection from '@/features/l7/components/AdminL7ConfigSection.vue'
import AdminL7OverviewSection from '@/features/l7/components/AdminL7OverviewSection.vue'
import { useAdminL7 } from '@/features/l7/composables/useAdminL7'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const { actionLabel, formatLatency, formatNumber, formatTimestamp } =
  useFormatters()

const {
  blockL7Rules,
  configForm,
  enabledL7Rules,
  error,
  events,
  failureModeLabel,
  http3StatusLabel,
  http3StatusType,
  l7Rules,
  lastUpdated,
  listenAddrsText,
  loading,
  protocolTags,
  proxySuccessRate,
  realIpHeadersText,
  refreshAll,
  runtimeProfileLabel,
  runtimeStatus,
  saveConfig,
  saving,
  stats,
  successMessage,
  trustedProxyCidrsText,
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
        <button
          :disabled="saving || loading"
          class="inline-flex items-center gap-2 rounded-full bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:-translate-y-0.5 disabled:opacity-60"
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
        <p class="text-sm text-slate-500">正在载入 HTTP 接入管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <L7SectionNav />

      <AdminL7OverviewSection
        :config-form="configForm"
        :failure-mode-label="failureModeLabel"
        :format-latency="formatLatency"
        :format-number="formatNumber"
        :format-timestamp="formatTimestamp"
        :http3-status-label="http3StatusLabel"
        :http3-status-type="http3StatusType"
        :protocol-tags="protocolTags"
        :proxy-success-rate="proxySuccessRate"
        :runtime-profile-label="runtimeProfileLabel"
        :runtime-status="runtimeStatus"
        :stats="stats"
        :upstream-status-text="upstreamStatusText"
        :upstream-status-type="upstreamStatusType"
      />
      <AdminL7ConfigSection
        :form="configForm"
        :listen-addrs-text="listenAddrsText"
        :real-ip-headers-text="realIpHeadersText"
        :trusted-proxy-cidrs-text="trustedProxyCidrsText"
        @update:form="Object.assign(configForm, $event)"
        @update:listen-addrs-text="listenAddrsText = $event"
        @update:real-ip-headers-text="realIpHeadersText = $event"
        @update:trusted-proxy-cidrs-text="trustedProxyCidrsText = $event"
      />

      <AdminL7ActivitySection
        :action-label="actionLabel"
        :block-l7-rules="blockL7Rules"
        :enabled-l7-rules="enabledL7Rules"
        :events="events"
        :format-number="formatNumber"
        :format-timestamp="formatTimestamp"
        :l7-rules="l7Rules"
      />
    </div>
  </AppLayout>
</template>
