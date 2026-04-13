<script setup lang="ts">
import { Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminGenerateCertificateDialog from '@/features/settings/components/AdminGenerateCertificateDialog.vue'
import AdminSettingsCertificatesSection from '@/features/settings/components/AdminSettingsCertificatesSection.vue'
import AdminSettingsGlobalSection from '@/features/settings/components/AdminSettingsGlobalSection.vue'
import AdminSettingsSystemSection from '@/features/settings/components/AdminSettingsSystemSection.vue'
import AdminUploadCertificateDialog from '@/features/settings/components/AdminUploadCertificateDialog.vue'
import { useAdminSettings } from '@/features/settings/composables/useAdminSettings'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const {
  deletingCertificateId,
  error,
  generateCertificate,
  generateCertificateForm,
  handleDefaultCertificateChange,
  globalEntryForm,
  loadSafeLineSites,
  loading,
  loadingCertificates,
  loadingSites,
  localCertificates,
  openGenerateModal,
  openUploadModal,
  persistDefaultCertificate,
  readingClipboard,
  removeCertificate,
  runSafeLineTest,
  saveMappings,
  saveSettings,
  saving,
  savingCertificate,
  savingDefaultCertificate,
  savingMappings,
  showGenerateModal,
  showUploadModal,
  sites,
  successMessage,
  systemSettings,
  testResult,
  testing,
  tryFillCertificateFromClipboard,
  uploadCertificate,
  uploadCertificateDomainsText,
  uploadCertificateForm,
  closeGenerateModal,
  closeUploadModal,
  generatingCertificate,
} = useAdminSettings()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '系统设置',
  successTitle: '系统设置',
  errorDuration: 5600,
  successDuration: 3200,
})

</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        :disabled="saving || loading"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
        @click="saveSettings"
      >
        <Save :size="12" />
        {{ saving ? '保存中...' : '保存设置' }}
      </button>
    </template>

    <div class="space-y-4">
      <div
        v-if="loading"
        class="rounded-lg border border-slate-200 bg-white/75 px-4 py-3 text-sm text-slate-500 shadow-[0_10px_25px_rgba(90,60,30,0.05)]"
      >
        正在从数据库加载设置...
      </div>
      <div class="space-y-4">
        <AdminSettingsSystemSection
          :global-entry-form="globalEntryForm"
          :loading="loading"
          :loading-sites="loadingSites"
          :local-certificates="localCertificates"
          :saving-default-certificate="savingDefaultCertificate"
          :saving-mappings="savingMappings"
          :sites="sites"
          :system-settings="systemSettings"
          :test-result="testResult"
          :testing="testing"
          @default-certificate-change="handleDefaultCertificateChange"
          @load-sites="loadSafeLineSites"
          @save-mappings="saveMappings"
          @test="runSafeLineTest"
          @update:global-entry-form="Object.assign(globalEntryForm, $event)"
          @update:system-settings="Object.assign(systemSettings, $event)"
        />

        <AdminSettingsCertificatesSection
          :deleting-certificate-id="deletingCertificateId"
          :generating-certificate="generatingCertificate"
          :loading-certificates="loadingCertificates"
          :local-certificates="localCertificates"
          :saving-certificate="savingCertificate"
          :saving-default-certificate="savingDefaultCertificate"
          :system-settings="systemSettings"
          @generate="openGenerateModal"
          @remove="removeCertificate"
          @set-default="persistDefaultCertificate"
          @upload="openUploadModal"
        />

        <AdminSettingsGlobalSection />
      </div>
    </div>

    <AdminGenerateCertificateDialog
      :form="generateCertificateForm"
      :generating-certificate="generatingCertificate"
      :is-open="showGenerateModal"
      :saving-default-certificate="savingDefaultCertificate"
      @close="closeGenerateModal"
      @submit="generateCertificate"
      @update:form="Object.assign(generateCertificateForm, $event)"
    />

    <AdminUploadCertificateDialog
      :form="uploadCertificateForm"
      :is-open="showUploadModal"
      :reading-clipboard="readingClipboard"
      :saving-certificate="savingCertificate"
      :upload-certificate-domains-text="uploadCertificateDomainsText"
      @close="closeUploadModal"
      @fill-clipboard="tryFillCertificateFromClipboard"
      @submit="uploadCertificate"
      @update:form="Object.assign(uploadCertificateForm, $event)"
      @update:upload-certificate-domains-text="
        uploadCertificateDomainsText = $event
      "
    />
  </AppLayout>
</template>
