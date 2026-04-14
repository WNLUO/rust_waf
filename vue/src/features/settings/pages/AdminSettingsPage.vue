<script setup lang="ts">
import { computed, ref } from 'vue'
import { Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL4ConfigFormCard from '@/features/l4/components/AdminL4ConfigFormCard.vue'
import { useAdminL4 } from '@/features/l4/composables/useAdminL4'
import AdminL7AdvancedGlobalSection from '@/features/l7/components/AdminL7AdvancedGlobalSection.vue'
import AdminL7ConfigSection from '@/features/l7/components/AdminL7ConfigSection.vue'
import { useAdminL7 } from '@/features/l7/composables/useAdminL7'
import AdminSettingsSystemSection from '@/features/settings/components/AdminSettingsSystemSection.vue'
import AdminUploadCertificateDialog from '@/features/settings/components/AdminUploadCertificateDialog.vue'
import { useAdminSettings } from '@/features/settings/composables/useAdminSettings'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const {
  error,
  handleDefaultCertificateChange,
  globalEntryForm,
  loadSafeLineSites,
  loading,
  loadingSites,
  localCertificates,
  readingClipboard,
  runSafeLineTest,
  saveMappings,
  saveSettings,
  saving,
  savingCertificate,
  savingDefaultCertificate,
  savingMappings,
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
  closeUploadModal,
} = useAdminSettings()

const {
  configForm: l4ConfigForm,
  error: l4Error,
  loading: l4Loading,
  saveConfig: saveL4Config,
  saving: savingL4,
  successMessage: l4SuccessMessage,
} = useAdminL4()

const {
  configForm: l7ConfigForm,
  error: l7Error,
  loading: l7Loading,
  saveConfig: saveL7Config,
  saving: savingL7,
  stats: l7Stats,
  successMessage: l7SuccessMessage,
  trustedProxyCidrsText,
} = useAdminL7()

const savingAll = ref(false)
const advancedGlobalSectionRef = ref<{
  saveSettings: () => Promise<boolean>
} | null>(null)

const disableSaveAll = computed(
  () =>
    savingAll.value ||
    saving.value ||
    loading.value ||
    savingL4.value ||
    savingL7.value,
)

async function saveAllSettings() {
  if (savingAll.value) return

  savingAll.value = true
  try {
    const saveSystemOk = await saveSettings()
    const saveL4Ok = await saveL4Config()
    const saveAdvancedGlobalOk =
      (await advancedGlobalSectionRef.value?.saveSettings()) ?? true
    const saveL7Ok = await saveL7Config()

    if (
      !saveSystemOk ||
      !saveL4Ok ||
      !saveAdvancedGlobalOk ||
      !saveL7Ok
    ) {
      return
    }
  } finally {
    savingAll.value = false
  }
}

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '系统设置',
  successTitle: '系统设置',
  errorDuration: 5600,
  successDuration: 3200,
})

useFlashMessages({
  error: l4Error,
  success: l4SuccessMessage,
  errorTitle: 'L4 管理',
  successTitle: 'L4 管理',
  errorDuration: 5600,
  successDuration: 3200,
})

useFlashMessages({
  error: l7Error,
  success: l7SuccessMessage,
  errorTitle: 'L7 管理',
  successTitle: 'L7 管理',
  errorDuration: 5600,
  successDuration: 3200,
})

</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        :disabled="disableSaveAll"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
        @click="saveAllSettings"
      >
        <Save :size="12" />
        {{ savingAll ? '保存全部中...' : '保存设置' }}
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

        <section
          class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
        >
          <div
            class="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
          >
            <div>
              <p class="text-sm tracking-wider text-blue-700">L4 管理</p>
            </div>
            <div class="flex items-center gap-2">
              <label
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
              >
                <span>启用 DDoS 防护</span>
                <input
                  v-model="l4ConfigForm.ddos_protection_enabled"
                  type="checkbox"
                  class="ui-switch"
                />
              </label>
              <label
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
              >
                <span>高级 DDoS 判定</span>
                <input
                  v-model="l4ConfigForm.advanced_ddos_enabled"
                  type="checkbox"
                  class="ui-switch"
                />
              </label>
            </div>
          </div>

          <div
            v-if="l4Loading"
            class="rounded-lg border border-slate-200 bg-white/75 px-4 py-3 text-sm text-slate-500 shadow-[0_10px_25px_rgba(90,60,30,0.05)]"
          >
            正在加载 L4 配置...
          </div>
          <AdminL4ConfigFormCard
            v-else
            :form="l4ConfigForm"
            @update:form="Object.assign(l4ConfigForm, $event)"
          />
        </section>

        <section class="space-y-4">
          <div
            class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
          >
            <div
              class="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
            >
              <div>
                <p class="text-sm tracking-wider text-blue-700">L7 管理</p>
              </div>
              <div class="flex items-center gap-2">
              </div>
            </div>

          <div
            v-if="l7Loading"
            class="rounded-lg border border-slate-200 bg-white/75 px-4 py-3 text-sm text-slate-500 shadow-[0_10px_25px_rgba(90,60,30,0.05)]"
          >
            正在加载 L7 配置...
          </div>
          <AdminL7ConfigSection
            v-if="!l7Loading"
            :form="l7ConfigForm"
            :trusted-proxy-cidrs-text="trustedProxyCidrsText"
            :auto-tuning-runtime="l7Stats?.auto_tuning ?? null"
            :drop-unmatched-requests="systemSettings.drop_unmatched_requests"
            :drop-unmatched-requests-disabled="saving || loading"
            @update:form="Object.assign(l7ConfigForm, $event)"
            @update:drop-unmatched-requests="
              systemSettings.drop_unmatched_requests = $event
            "
            @update:trusted-proxy-cidrs-text="trustedProxyCidrsText = $event"
            />
          </div>

          <AdminL7AdvancedGlobalSection ref="advancedGlobalSectionRef" />
        </section>
      </div>
    </div>

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

<style scoped>
.ui-switch {
  appearance: none;
  width: 2.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: rgb(203 213 225);
  position: relative;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 9999px;
  background: white;
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: rgb(37 99 235);
}

.ui-switch:checked::after {
  transform: translateX(1rem);
}

.ui-switch:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
