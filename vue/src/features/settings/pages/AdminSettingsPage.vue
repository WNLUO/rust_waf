<script setup lang="ts">
import { computed, ref } from 'vue'
import { Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL4ConfigFormCard from '@/features/l4/components/AdminL4ConfigFormCard.vue'
import AdminL4CompatibilityDialog from '@/features/l4/components/AdminL4CompatibilityDialog.vue'
import AdminTrustedCdnDialog from '@/features/l4/components/AdminTrustedCdnDialog.vue'
import { useAdminL4 } from '@/features/l4/composables/useAdminL4'
import AdminL7AdvancedGlobalSection from '@/features/l7/components/AdminL7AdvancedGlobalSection.vue'
import AdminL7CompatibilityDialog from '@/features/l7/components/AdminL7CompatibilityDialog.vue'
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
  compatibilityForm: l4CompatibilityForm,
  configForm: l4ConfigForm,
  error: l4Error,
  loading: l4Loading,
  meta: l4Meta,
  saveConfig: saveL4Config,
  saveCompatibilityConfig: saveL4CompatibilityConfig,
  saving: savingL4,
  successMessage: l4SuccessMessage,
} = useAdminL4()

const {
  compatibilityForm: l7CompatibilityForm,
  configForm: l7ConfigForm,
  error: l7Error,
  loading: l7Loading,
  meta: l7Meta,
  saveConfig: saveL7Config,
  saveCompatibilityConfig: saveL7CompatibilityConfig,
  saving: savingL7,
  stats: l7Stats,
  successMessage: l7SuccessMessage,
  trustedProxyCidrsText,
} = useAdminL7()

const savingAll = ref(false)
const trustedCdnDialogOpen = ref(false)
const l4CompatibilityOpen = ref(false)
const l7CompatibilityOpen = ref(false)
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

const adaptiveProtectionEnabled = computed(
  () => systemSettings.adaptive_protection.enabled,
)
const adaptiveRuntime = computed(
  () => l7Meta.value.adaptive_runtime ?? l4Meta.value.adaptive_runtime,
)
const adaptivePressureTone = computed(() => {
  const pressure = adaptiveRuntime.value?.system_pressure ?? 'normal'
  if (pressure === 'attack') return 'bg-rose-50 text-rose-700 border-rose-200'
  if (pressure === 'high') return 'bg-amber-50 text-amber-700 border-amber-200'
  if (pressure === 'elevated') return 'bg-sky-50 text-sky-700 border-sky-200'
  return 'bg-emerald-50 text-emerald-700 border-emerald-200'
})
const adaptivePressureLabel = computed(() => {
  const pressure = adaptiveRuntime.value?.system_pressure ?? 'normal'
  if (pressure === 'attack') return '攻击态'
  if (pressure === 'high') return '高压态'
  if (pressure === 'elevated') return '升压态'
  return '正常态'
})

async function saveAllSettings() {
  if (savingAll.value) return

  savingAll.value = true
  try {
    const saveSystemOk = await saveSettings()
    const saveL4Ok = adaptiveProtectionEnabled.value
      ? true
      : await saveL4Config()
    const saveAdvancedGlobalOk =
      (await advancedGlobalSectionRef.value?.saveSettings()) ?? true
    const saveL7Ok = adaptiveProtectionEnabled.value
      ? true
      : await saveL7Config()

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
          v-if="adaptiveProtectionEnabled && adaptiveRuntime"
          class="rounded-xl border border-emerald-100 bg-[linear-gradient(135deg,rgba(240,253,244,0.92),rgba(236,253,245,0.88),rgba(239,246,255,0.9))] p-4 shadow-[0_18px_48px_rgba(32,72,48,0.08)]"
        >
          <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div class="space-y-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-sm tracking-wider text-emerald-700">自适应防护状态</span>
                <span
                  class="rounded-full border px-3 py-1 text-xs font-medium"
                  :class="adaptivePressureTone"
                >
                  {{ adaptivePressureLabel }}
                </span>
              </div>
              <p class="text-sm text-stone-700">
                当前按 {{ adaptiveRuntime.mode }} 模式、{{ adaptiveRuntime.goal }} 目标自动调节 L4 / L7。系统设置页会优先展示自动策略，高级阈值保留在兼容入口中。
              </p>
            </div>
            <div class="grid gap-2 text-xs text-stone-700 md:grid-cols-2">
              <div class="rounded-xl border border-white/70 bg-white/70 px-3 py-2">
                <p class="text-slate-500">L4 连接预算</p>
                <p class="mt-1 font-medium text-stone-900">
                  {{ adaptiveRuntime.l4.normal_connection_budget_per_minute }} / {{ adaptiveRuntime.l4.suspicious_connection_budget_per_minute }} / {{ adaptiveRuntime.l4.high_risk_connection_budget_per_minute }}
                </p>
              </div>
              <div class="rounded-xl border border-white/70 bg-white/70 px-3 py-2">
                <p class="text-slate-500">L7 阈值</p>
                <p class="mt-1 font-medium text-stone-900">
                  {{ adaptiveRuntime.l7.ip_challenge_threshold }} / {{ adaptiveRuntime.l7.ip_block_threshold }}
                </p>
              </div>
            </div>
          </div>
          <div
            v-if="adaptiveRuntime.reasons.length"
            class="mt-3 flex flex-wrap gap-2 text-xs text-stone-700"
          >
            <span
              v-for="reason in adaptiveRuntime.reasons"
              :key="reason"
              class="rounded-full border border-white/80 bg-white/70 px-2.5 py-1"
            >
              {{ reason }}
            </span>
          </div>
        </section>

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
              <button
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="trustedCdnDialogOpen = true"
              >
                可信CDN配置
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
              自适应防护已接管 L4 连接预算、延迟和拒绝阈值。这里的细粒度参数已从常规入口收起，避免线上继续依赖手工阈值。
            </p>
            <div class="flex flex-wrap items-center gap-3">
              <button
                class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="l4CompatibilityOpen = true"
              >
                打开兼容层入口
              >
                查看 / 编辑归档参数
              </button>
            </div>
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
          <div
            v-else-if="adaptiveProtectionEnabled"
            class="space-y-3 rounded-2xl border border-dashed border-slate-200 bg-slate-50/80 px-4 py-5 text-sm leading-6 text-slate-600"
          >
            <p>
              自适应防护已接管 L7 CC 窗口、延迟和 challenge / block 阈值。系统会按当前压力、握手异常、代理延迟和机器资源自动调节，常规场景不再建议手动维护这一组数值。
            </p>
            <div class="flex flex-wrap items-center gap-3">
              <button
                class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="l7CompatibilityOpen = true"
              >
                打开兼容层入口
              >
                查看 / 编辑归档参数
              </button>
            </div>
          </div>
          <AdminL7ConfigSection
            v-else-if="!l7Loading"
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

          <AdminL7AdvancedGlobalSection
            v-if="!adaptiveProtectionEnabled"
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

    <AdminL4CompatibilityDialog
      :form="l4CompatibilityForm"
      :is-open="l4CompatibilityOpen"
      :saving="savingL4"
      @close="l4CompatibilityOpen = false"
      @save="saveL4CompatibilityConfig"
      @update:form="Object.assign(l4CompatibilityForm, $event)"
    />

    <AdminL7CompatibilityDialog
      :form="l7CompatibilityForm"
      :is-open="l7CompatibilityOpen"
      :saving="savingL7"
      :trusted-proxy-cidrs-text="trustedProxyCidrsText"
      :auto-tuning-runtime="l7Stats?.auto_tuning ?? null"
      :drop-unmatched-requests="systemSettings.drop_unmatched_requests"
      :drop-unmatched-requests-disabled="saving || loading"
      @close="l7CompatibilityOpen = false"
      @save="saveL7CompatibilityConfig"
      @update:form="Object.assign(l7CompatibilityForm, $event)"
      @update:drop-unmatched-requests="
        systemSettings.drop_unmatched_requests = $event
      "
      @update:trusted-proxy-cidrs-text="trustedProxyCidrsText = $event"
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
