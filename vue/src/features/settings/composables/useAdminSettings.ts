import { onMounted } from 'vue'
import { useAdminSettingsCertificates } from '@/features/settings/composables/useAdminSettingsCertificates'
import { useAdminSettingsSafeLine } from '@/features/settings/composables/useAdminSettingsSafeLine'
import { useAdminSettingsState } from '@/features/settings/composables/useAdminSettingsState'
import { useAdminSettingsSystem } from '@/features/settings/composables/useAdminSettingsSystem'

export function useAdminSettings() {
  const state = useAdminSettingsState()
  const system = useAdminSettingsSystem({ state })
  const safeLine = useAdminSettingsSafeLine({ state })
  const certificates = useAdminSettingsCertificates({
    loadSettings: system.loadSettings,
    state,
  })

  onMounted(async () => {
    await system.loadSettings()
    await certificates.loadCertificates()
    await safeLine.loadMappings()
  })

  return {
    clearSiteData: system.clearSiteData,
    clearingSiteData: state.clearingSiteData,
    closeGenerateModal: certificates.closeGenerateModal,
    closeUploadModal: certificates.closeUploadModal,
    deletingCertificateId: state.deletingCertificateId,
    error: state.error,
    generateCertificate: certificates.generateCertificate,
    generateCertificateForm: state.generateCertificateForm,
    generatingCertificate: state.generatingCertificate,
    handleDefaultCertificateChange: certificates.handleDefaultCertificateChange,
    loadSafeLineSites: safeLine.loadSafeLineSites,
    loading: state.loading,
    loadingCertificates: state.loadingCertificates,
    loadingSites: state.loadingSites,
    localCertificates: state.localCertificates,
    mappingDrafts: safeLine.mappingDrafts,
    openGenerateModal: certificates.openGenerateModal,
    openUploadModal: certificates.openUploadModal,
    persistDefaultCertificate: certificates.persistDefaultCertificate,
    readingClipboard: state.readingClipboard,
    removeCertificate: certificates.removeCertificate,
    runSafeLineTest: safeLine.runSafeLineTest,
    saveMappings: safeLine.saveMappings,
    saveSettings: system.saveSettings,
    saving: state.saving,
    savingCertificate: state.savingCertificate,
    savingDefaultCertificate: state.savingDefaultCertificate,
    savingMappings: state.savingMappings,
    showGenerateModal: state.showGenerateModal,
    showUploadModal: state.showUploadModal,
    sites: state.sites,
    sitesLoadedAt: state.sitesLoadedAt,
    successMessage: state.successMessage,
    systemSettings: state.systemSettings,
    testResult: state.testResult,
    testing: state.testing,
    tryFillCertificateFromClipboard:
      certificates.tryFillCertificateFromClipboard,
    uploadCertificate: certificates.uploadCertificate,
    uploadCertificateDomainsText: state.uploadCertificateDomainsText,
    uploadCertificateForm: state.uploadCertificateForm,
  }
}
