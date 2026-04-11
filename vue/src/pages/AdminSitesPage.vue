<script setup lang="ts">
import { Link2 } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'
import AdminSiteEditorDialog from '../components/sites/AdminSiteEditorDialog.vue'
import AdminSitesSummarySection from '../components/sites/AdminSitesSummarySection.vue'
import AdminSitesTableSection from '../components/sites/AdminSitesTableSection.vue'
import AppLayout from '../components/layout/AppLayout.vue'
import { useAdminSites } from '../composables/useAdminSites'
import { useFormatters } from '../composables/useFormatters'

const { formatNumber, formatTimestamp } = useFormatters()

const {
  actions,
  currentLocalSite,
  editorTitle,
  editingLocalSiteId,
  error,
  filteredRows,
  filters,
  hasSavedConfig,
  hostnamesText,
  isLocalSiteModalOpen,
  listenPortsText,
  loadRemoteSites,
  localActionLabel,
  localCertificates,
  localSiteForm,
  localSites,
  openCreateLocalSiteModal,
  primaryDraft,
  refreshPageData,
  remoteActionLabel,
  removeCurrentLocalSite,
  resetLocalSiteForm,
  rowActionPending,
  rowBusy,
  rowSyncText,
  runConnectionTest,
  saveLocalSite,
  sites,
  sitesLoadedAt,
  successMessage,
  syncLocalSite,
  syncRemoteSite,
  testResult,
  totalLinkedSites,
  totalLocalOnly,
  totalLocalSites,
  totalMapped,
  totalMissingRemote,
  totalOrphaned,
  totalSyncErrors,
  totalUnmapped,
  closeLocalSiteModal,
  editLocalSite,
  loading,
  upstreamsText,
} = useAdminSites(formatTimestamp)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <RouterLink
        to="/admin/safeline"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90"
      >
        <Link2 :size="12" />
        编辑映射
      </RouterLink>
    </template>

    <div class="min-w-0 space-y-4">
      <AdminSitesSummarySection
        :actions="actions"
        :filtered-rows-count="filteredRows.length"
        :format-number="formatNumber"
        :has-saved-config="hasSavedConfig"
        :keyword="filters.keyword"
        :primary-draft="primaryDraft"
        :scope="filters.scope"
        :sites-count="sites.length"
        :sites-loaded-at="sitesLoadedAt"
        :state="filters.state"
        :test-result="testResult"
        :total-linked-sites="totalLinkedSites"
        :total-local-only="totalLocalOnly"
        :total-local-sites="totalLocalSites"
        :total-mapped="totalMapped"
        :total-missing-remote="totalMissingRemote"
        :total-orphaned="totalOrphaned"
        :total-sync-errors="totalSyncErrors"
        :total-unmapped="totalUnmapped"
        @load-remote="loadRemoteSites"
        @refresh="refreshPageData"
        @test="runConnectionTest"
        @update:keyword="filters.keyword = $event"
        @update:scope="filters.scope = $event"
        @update:state="filters.state = $event"
      />

      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-xl border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

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
        :remote-action-label="remoteActionLabel"
        :row-action-pending="rowActionPending"
        :row-busy="rowBusy"
        :row-sync-text="rowSyncText"
        :sites-loaded-at="sitesLoadedAt"
        @create-local-site="openCreateLocalSiteModal"
        @edit-local-site="editLocalSite"
        @sync-local-site="syncLocalSite"
        @sync-remote-site="syncRemoteSite"
      />
    </div>

    <AdminSiteEditorDialog
      :actions="actions"
      :current-local-site="currentLocalSite"
      :editing-local-site-id="editingLocalSiteId"
      :editor-title="editorTitle"
      :format-number="formatNumber"
      :format-timestamp="formatTimestamp"
      :hostnames-text="hostnamesText"
      :is-open="isLocalSiteModalOpen"
      :listen-ports-text="listenPortsText"
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
      @update:listen-ports-text="listenPortsText = $event"
      @update:upstreams-text="upstreamsText = $event"
    />
  </AppLayout>
</template>
