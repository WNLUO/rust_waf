<script setup lang="ts">
import { Save } from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import AdminGenerateCertificateDialog from '../components/settings/AdminGenerateCertificateDialog.vue'
import AdminSettingsCertificatesSection from '../components/settings/AdminSettingsCertificatesSection.vue'
import AdminSettingsSafeLineSection from '../components/settings/AdminSettingsSafeLineSection.vue'
import AdminSettingsSystemSection from '../components/settings/AdminSettingsSystemSection.vue'
import AdminUploadCertificateDialog from '../components/settings/AdminUploadCertificateDialog.vue'
import { useAdminSettings } from '../composables/useAdminSettings'
import { useFlashMessages } from '../composables/useNotifications'

const {
  clearSiteData,
  clearingSiteData,
  deletingCertificateId,
  error,
  generateCertificate,
  generateCertificateForm,
  handleDefaultCertificateChange,
  loadSafeLineSites,
  loading,
  loadingCertificates,
  loadingSites,
  localCertificates,
  mappingDrafts,
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
  sitesLoadedAt,
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

async function handleClearSiteData() {
  if (!window.confirm('确认清空所有站点数据吗？这会删除本地站点、映射、同步链路和缓存站点，但不会删除证书。')) {
    return
  }
  await clearSiteData()
}

function formatTimestamp(timestamp: number | null) {
  if (!timestamp) return '暂无'
  return new Date(timestamp * 1000).toLocaleString('zh-CN', { hour12: false })
}
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
          :clearing-site-data="clearingSiteData"
          :local-certificates="localCertificates"
          :saving-default-certificate="savingDefaultCertificate"
          :system-settings="systemSettings"
          @clear-site-data="handleClearSiteData"
          @default-certificate-change="handleDefaultCertificateChange"
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

        <AdminSettingsSafeLineSection
          :format-timestamp="formatTimestamp"
          :loading="loading"
          :loading-sites="loadingSites"
          :mapping-drafts="mappingDrafts"
          :saving-mappings="savingMappings"
          :sites="sites"
          :sites-loaded-at="sitesLoadedAt"
          :system-settings="systemSettings"
          :test-result="testResult"
          :testing="testing"
          @load-sites="loadSafeLineSites"
          @save-mappings="saveMappings"
          @test="runSafeLineTest"
          @update:system-settings="Object.assign(systemSettings, $event)"
        />
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
