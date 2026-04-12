<script setup lang="ts">
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminCertificatesPreflightSection from '@/features/certificates/components/AdminCertificatesPreflightSection.vue'
import AdminCertificatesTableSection from '@/features/certificates/components/AdminCertificatesTableSection.vue'
import AdminCertificatesToolbarSection from '@/features/certificates/components/AdminCertificatesToolbarSection.vue'
import { useAdminCertificates } from '@/features/certificates/composables/useAdminCertificates'
import AdminCertificateEditorDialog from '@/features/sites/components/AdminCertificateEditorDialog.vue'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const {
  allSelected,
  autoPushableIds,
  bindRemoteCertificate,
  bindingIds,
  certificateMatchPreviews,
  certificates,
  closeDialog,
  deletingIds,
  dialogMode,
  dialogOpen,
  domainsText,
  error,
  form,
  formatTimestamp,
  loadCertificateMatchPreview,
  loadCertificates,
  loading,
  openCreateDialog,
  openEditDialog,
  openingEditor,
  preflightSummary,
  preflightingAll,
  previewingIds,
  pullingSafeLine,
  pushAutoMatchedCertificates,
  pushingIds,
  pushSelectedCertificates,
  pushSingleCertificate,
  readingClipboard,
  removeSelectedCertificates,
  removeSingleCertificate,
  runCertificatePreflight,
  saving,
  selectedIds,
  submitDialog,
  successMessage,
  syncFromSafeLine,
  syncStatusText,
  syncStatusTone,
  toggleSelectAll,
  toggleSelection,
  tryFillCertificateFromClipboard,
  unbindRemoteCertificate,
} = useAdminCertificates()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '证书管理',
  successTitle: '证书管理',
  errorDuration: 5600,
  successDuration: 3200,
})
</script>

<template>
  <AppLayout>
    <div class="space-y-4">
      <AdminCertificatesToolbarSection
        :certificates-count="certificates.length"
        :deleting-ids-count="deletingIds.length"
        :preflighting-all="preflightingAll"
        :pulling-safe-line="pullingSafeLine"
        :pushing-ids-count="pushingIds.length"
        :selected-count="selectedIds.length"
        @create="openCreateDialog"
        @preflight="runCertificatePreflight"
        @push-selected="pushSelectedCertificates"
        @refresh="loadCertificates"
        @remove-selected="removeSelectedCertificates"
        @sync="syncFromSafeLine"
      />

      <div
        v-if="loading"
        class="rounded-xl border border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-500 shadow-sm"
      >
        正在读取证书列表...
      </div>

      <AdminCertificatesPreflightSection
        :auto-pushable-count="autoPushableIds.length"
        :preflight-summary="preflightSummary"
        :pushing-ids-count="pushingIds.length"
        @push-auto-matched="pushAutoMatchedCertificates"
      />

      <AdminCertificatesTableSection
        v-if="!loading"
        :all-selected="allSelected"
        :binding-ids="bindingIds"
        :certificate-match-previews="certificateMatchPreviews"
        :certificates="certificates"
        :deleting-ids="deletingIds"
        :format-timestamp="formatTimestamp"
        :opening-editor="openingEditor"
        :previewing-ids="previewingIds"
        :pushing-ids="pushingIds"
        :selected-ids="selectedIds"
        :sync-status-text="syncStatusText"
        :sync-status-tone="syncStatusTone"
        @bind-remote="bindRemoteCertificate"
        @edit="openEditDialog"
        @preview="loadCertificateMatchPreview"
        @push="pushSingleCertificate"
        @remove="removeSingleCertificate"
        @toggle-selection="toggleSelection"
        @toggle-select-all="toggleSelectAll"
        @unbind="unbindRemoteCertificate"
      />
    </div>

    <AdminCertificateEditorDialog
      :form="form"
      :is-open="dialogOpen"
      :mode="dialogMode"
      :reading-clipboard="readingClipboard"
      :saving="saving"
      :domains-text="domainsText"
      @close="closeDialog"
      @submit="submitDialog"
      @fill-clipboard="tryFillCertificateFromClipboard"
      @update:form="Object.assign(form, $event)"
      @update:domains-text="domainsText = $event"
    />
  </AppLayout>
</template>
