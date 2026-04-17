<script setup lang="ts">
import { computed, ref } from 'vue'
import { Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminTrustedCdnDialog from '@/features/l4/components/AdminTrustedCdnDialog.vue'
import { useAdminL4 } from '@/features/l4/composables/useAdminL4'
import AdminL7AdvancedGlobalSection from '@/features/l7/components/AdminL7AdvancedGlobalSection.vue'
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

const savingAll = ref(false)
const trustedCdnDialogOpen = ref(false)
const advancedGlobalSectionRef = ref<{
  saveSettings: () => Promise<boolean>
} | null>(null)

const disableSaveAll = computed(
  () =>
    savingAll.value ||
    saving.value ||
    loading.value ||
    savingL4.value,
)

const adaptiveProtectionEnabled = computed(
  () => systemSettings.adaptive_protection.enabled,
)

async function saveAllSettings() {
  if (savingAll.value) return

  savingAll.value = true
  try {
    const saveSystemOk = await saveSettings()
    const saveL4Ok = await saveL4Config()
    const saveAdvancedGlobalOk =
      (await advancedGlobalSectionRef.value?.saveSettings()) ?? true

    if (!saveSystemOk || !saveL4Ok || !saveAdvancedGlobalOk) {
      return
    }
  } finally {
    savingAll.value = false
  }
}

async function saveTrustedCdnSettings() {
  const ok = await saveL4Config()
  if (ok) {
    trustedCdnDialogOpen.value = false
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
              <p class="mt-1 text-xs text-slate-500">
                主页面保留业务开关和资源边界；预算、延迟和拒绝阈值由运行时自动收敛。
              </p>
            </div>
            <div class="flex items-center gap-2">
              <button
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="trustedCdnDialogOpen = true"
              >
                CDN来源库（可选）
              </button>
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
          <div
            v-else-if="adaptiveProtectionEnabled"
            class="space-y-3 rounded-2xl border border-dashed border-slate-200 bg-slate-50/80 px-4 py-5 text-sm leading-6 text-slate-600"
          >
            <p>
              自适应防护已接管 L4 行为引擎预算、过载延迟和拒绝阈值，这一组参数已从主区域收起，避免线上继续依赖手工阈值。
            </p>
            <p>
              连接速率、SYN 阈值、跟踪容量、封禁表容量、状态保留和 Bloom 缩放均由系统按运行压力自动管理。
            </p>
          </div>
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
                <p class="mt-1 text-xs text-slate-500">
                  主页面保留协议开关、上游策略和联动运行项；CC 阈值、采样、超时和自动调优细项由系统闭环管理。
                </p>
              </div>
              <div class="flex items-center gap-2"></div>
            </div>

            <div
              class="space-y-3 rounded-2xl border border-dashed border-slate-200 bg-slate-50/80 px-4 py-5 text-sm leading-6 text-slate-600"
            >
              <p>
                自适应防护已接管 L7 CC 窗口、延迟和 challenge / block 阈值。系统会按当前压力、握手异常、代理延迟和机器资源自动调节，这一组参数不再建议在主页面人工维护。
              </p>
              <p>
                HTTP/2、HTTP/3、真实来源、TLS、转发 Header 和上游策略等业务意图已集中在高级配置、证书和站点动作中维护。
              </p>
            </div>
          </div>

          <AdminL7AdvancedGlobalSection
            ref="advancedGlobalSectionRef"
          />
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

    <AdminTrustedCdnDialog
      :form="l4ConfigForm"
      :is-open="trustedCdnDialogOpen"
      :saving="savingL4"
      @close="trustedCdnDialogOpen = false"
      @save="saveTrustedCdnSettings"
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
