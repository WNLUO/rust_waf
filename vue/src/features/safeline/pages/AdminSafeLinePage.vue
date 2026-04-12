<script setup lang="ts">
import { RefreshCw } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminSafeLineActionsSection from '@/features/safeline/components/AdminSafeLineActionsSection.vue'
import AdminSafeLineMappingsSection from '@/features/safeline/components/AdminSafeLineMappingsSection.vue'
import AdminSafeLineOverviewSection from '@/features/safeline/components/AdminSafeLineOverviewSection.vue'
import { useAdminSafeLine } from '@/features/safeline/composables/useAdminSafeLine'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const { formatTimestamp } = useFormatters()

const {
  actions,
  authMode,
  clearPrimary,
  error,
  hasSavedConfig,
  loadRemoteSites,
  loading,
  refreshSyncState,
  runBlockedPull,
  runBlockedPush,
  runConnectionTest,
  runEventSync,
  saveMappings,
  selectPrimary,
  settings,
  sortedDrafts,
  successMessage,
  syncCards,
  syncStatusText,
  syncStatusType,
  testResult,
} = useAdminSafeLine()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '雷池联动',
  successTitle: '雷池联动',
  errorDuration: 5600,
  successDuration: 3200,
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="actions.refreshing || loading"
        @click="refreshSyncState"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': actions.refreshing }" />
        刷新联动状态
      </button>
    </template>

    <div class="space-y-6">
      <div
        v-if="loading"
        class="rounded-xl border border-white/80 bg-white/75 px-4 py-6 text-center text-sm text-slate-500 shadow-sm"
      >
        正在加载雷池联动面板...
      </div>

      <template v-else>
        <section class="grid gap-4 xl:grid-cols-[1fr_1.1fr] xl:items-start">
          <AdminSafeLineOverviewSection
            :actions="actions"
            :auth-mode="authMode"
            :has-saved-config="hasSavedConfig"
            :settings="settings"
            :test-result="testResult"
            @load-sites="loadRemoteSites"
            @test="runConnectionTest"
          />

          <AdminSafeLineActionsSection
            :actions="actions"
            :format-timestamp="formatTimestamp"
            :sync-cards="syncCards"
            :sync-status-text="syncStatusText"
            :sync-status-type="syncStatusType"
            @pull-blocked="runBlockedPull"
            @push-blocked="runBlockedPush"
            @refresh="refreshSyncState"
            @sync-events="runEventSync"
          />
        </section>

        <AdminSafeLineMappingsSection
          :actions="actions"
          :format-timestamp="formatTimestamp"
          :sorted-drafts="sortedDrafts"
          @clear-primary="clearPrimary"
          @save="saveMappings"
          @select-primary="selectPrimary"
        />
      </template>
    </div>
  </AppLayout>
</template>
