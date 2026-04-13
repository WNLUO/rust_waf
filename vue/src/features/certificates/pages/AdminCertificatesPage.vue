<script setup lang="ts">
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminCertificatesPreflightSection from '@/features/certificates/components/AdminCertificatesPreflightSection.vue'
import AdminCertificatesTableSection from '@/features/certificates/components/AdminCertificatesTableSection.vue'
import AdminCertificatesToolbarSection from '@/features/certificates/components/AdminCertificatesToolbarSection.vue'
import { useAdminCertificates } from '@/features/certificates/composables/useAdminCertificates'
import AdminGenerateCertificateDialog from '@/features/settings/components/AdminGenerateCertificateDialog.vue'
import AdminCertificateEditorDialog from '@/features/sites/components/AdminCertificateEditorDialog.vue'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const {
  allSelected,
  autoPushableIds,
  bindingIds,
  certificateMatchPreviews,
  certificates,
  closeGenerateModal,
  closeDialog,
  deletingIds,
  dialogMode,
  dialogOpen,
  domainsText,
  error,
  form,
  formatTimestamp,
  generateCertificate,
  generateCertificateForm,
  generatingCertificate,
  loadCertificateMatchPreview,
  loading,
  openGenerateModal,
  openCreateDialog,
  openEditDialog,
  openingEditor,
  preflightSummary,
  previewingIds,
  pullingSafeLine,
  pushAutoMatchedCertificates,
  pushingIds,
  pushSingleCertificate,
  readingClipboard,
  removeSelectedCertificates,
  removeSingleCertificate,
  saving,
  selectedIds,
  showGenerateModal,
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
        :deleting-ids-count="deletingIds.length"
        :generating-certificate="generatingCertificate"
        :pulling-safe-line="pullingSafeLine"
        :selected-count="selectedIds.length"
        @create="openCreateDialog"
        @generate="openGenerateModal"
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

    <AdminGenerateCertificateDialog
      :form="generateCertificateForm"
      :generating-certificate="generatingCertificate"
      :is-open="showGenerateModal"
      :saving-default-certificate="saving"
      @close="closeGenerateModal"
      @submit="generateCertificate"
      @update:form="Object.assign(generateCertificateForm, $event)"
    />
  </AppLayout>
</template>
