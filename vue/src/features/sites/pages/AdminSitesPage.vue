<script setup lang="ts">
import AdminSiteEditorDialog from '@/features/sites/components/AdminSiteEditorDialog.vue'
import AdminSitesSyncDialog from '@/features/sites/components/AdminSitesSyncDialog.vue'
import AdminSitesSummarySection from '@/features/sites/components/AdminSitesSummarySection.vue'
import AdminSitesTableSection from '@/features/sites/components/AdminSitesTableSection.vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import { useAdminSites } from '@/features/sites/composables/useAdminSites'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import { useRouter } from 'vue-router'

const router = useRouter()

const { formatNumber, formatTimestamp } = useFormatters()

const {
  actions,
  currentLocalSite,
  defaultSafelineInterceptConfig,
  editorTitle,
  editingLocalSiteId,
  error,
  filteredRows,
  filters,
  hasSavedConfig,
  hostnamesText,
  isLocalSiteModalOpen,
  isRemoteSyncDialogOpen,
  localActionLabel,
  localCertificates,
  localSiteForm,
  localSites,
  openCreateLocalSiteModal,
  openRemoteSyncDialog,
  primaryDraft,
  remoteSyncCandidates,
  remoteSitePullOptions,
  refreshPageData,
  removeCurrentLocalSite,
  resetLocalSiteForm,
  rowSyncText,
  saveLocalSite,
  sitesLoadedAt,
  selectedRemoteSiteIds,
  selectRecommendedRemoteSites,
  clearRemoteSiteSelection,
  closeRemoteSyncDialog,
  successMessage,
  syncLocalSite,
  syncSelectedRemoteSites,
  syncingRemoteSelection,
  totalLocalSites,
  totalSyncErrors,
  totalEnabledLocalSites,
  totalSitesWithRemoteLink,
  toggleRemoteSitePullOption,
  toggleRemoteSiteSelection,
  closeLocalSiteModal,
  editLocalSite,
  loading,
  upstreamsText,
} = useAdminSites(formatTimestamp)

function openGlobalSettingsPage() {
  router.push('/admin/global-settings')
}

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '站点管理',
  successTitle: '站点管理',
  errorDuration: 5600,
  successDuration: 3200,
})
</script>

<template>
  <AppLayout>
    <div class="min-w-0 space-y-4">
      <AdminSitesSummarySection
        :actions="actions"
        :filtered-rows-count="filteredRows.length"
        :format-number="formatNumber"
        :has-saved-config="hasSavedConfig"
        :keyword="filters.keyword"
        :primary-draft="primaryDraft"
        :sites-loaded-at="sitesLoadedAt"
        :state="filters.state"
        :total-enabled-local-sites="totalEnabledLocalSites"
        :total-local-sites="totalLocalSites"
        :total-sync-errors="totalSyncErrors"
        :total-sites-with-remote-link="totalSitesWithRemoteLink"
        @create-local-site="openCreateLocalSiteModal"
        @load-remote="openRemoteSyncDialog"
        @open-global-settings="openGlobalSettingsPage"
        @refresh="refreshPageData"
        @update:keyword="filters.keyword = $event"
        @update:state="filters.state = $event"
      />
      <div
        v-if="loading"
        class="rounded-xl border border-white/80 bg-white/75 px-4 py-6 text-center text-sm text-slate-500 shadow-sm"
      >
        正在读取站点管理数据...
      </div>

      <AdminSitesTableSection
        v-else
        :filtered-rows="filteredRows"
        :format-timestamp="formatTimestamp"
        :has-saved-config="hasSavedConfig"
        :local-action-label="localActionLabel"
        :row-sync-text="rowSyncText"
        @edit-local-site="editLocalSite"
        @sync-local-site="syncLocalSite"
      />
    </div>

    <AdminSiteEditorDialog
      :actions="actions"
      :current-local-site="currentLocalSite"
      :editing-local-site-id="editingLocalSiteId"
      :editor-title="editorTitle"
      :format-number="formatNumber"
      :format-timestamp="formatTimestamp"
      :default-safeline-intercept-config="defaultSafelineInterceptConfig"
      :hostnames-text="hostnamesText"
      :is-open="isLocalSiteModalOpen"
      :local-certificates="localCertificates"
      :local-site-form="localSiteForm"
      :local-sites-count="localSites.length"
      :upstreams-text="upstreamsText"
      @close="closeLocalSiteModal"
      @remove="removeCurrentLocalSite"
      @reset="resetLocalSiteForm"
      @save="saveLocalSite"
      @update:form="Object.assign(localSiteForm, $event)"
      @update:hostnames-text="hostnamesText = $event"
      @update:upstreams-text="upstreamsText = $event"
    />

    <AdminSitesSyncDialog
      :is-open="isRemoteSyncDialogOpen"
      :loading="actions.loadingSites"
      :saving="syncingRemoteSelection"
      :candidates="remoteSyncCandidates"
      :selected-site-ids="selectedRemoteSiteIds"
      :site-pull-options="remoteSitePullOptions"
      @close="closeRemoteSyncDialog"
      @submit="syncSelectedRemoteSites"
      @toggle-field="toggleRemoteSitePullOption"
      @toggle-site="toggleRemoteSiteSelection"
      @select-recommended="selectRecommendedRemoteSites"
      @clear-selection="clearRemoteSiteSelection"
      @reload="openRemoteSyncDialog"
    />
  </AppLayout>
</template>
