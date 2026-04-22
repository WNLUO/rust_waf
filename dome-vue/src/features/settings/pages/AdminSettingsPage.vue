<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RefreshCw, Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL7AdvancedGlobalSection from '@/features/l7/components/AdminL7AdvancedGlobalSection.vue'
import AdminSettingsSystemSection from '@/features/settings/components/AdminSettingsSystemSection.vue'
import AdminUploadCertificateDialog from '@/features/settings/components/AdminUploadCertificateDialog.vue'
import { useAdminSettings } from '@/features/settings/composables/useAdminSettings'
import {
  fetchBotInsights,
  fetchBotVerifierStatus,
  refreshBotVerifierStatus,
} from '@/shared/api/dashboard'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import type { BotInsightsResponse, BotVerifierStatusResponse } from '@/shared/types'

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

const savingAll = ref(false)
const botVerifierLoading = ref(false)
const botVerifierRefreshing = ref(false)
const botVerifierStatus = ref<BotVerifierStatusResponse | null>(null)
const botInsights = ref<BotInsightsResponse | null>(null)
const advancedGlobalSectionRef = ref<{
  saveSettings: () => Promise<boolean>
} | null>(null)

const disableSaveAll = computed(
  () =>
    savingAll.value ||
    saving.value ||
    loading.value,
)

async function saveAllSettings() {
  if (savingAll.value) return

  savingAll.value = true
  try {
    const saveSystemOk = await saveSettings()
    const saveAdvancedGlobalOk =
      (await advancedGlobalSectionRef.value?.saveSettings()) ?? true

    if (!saveSystemOk || !saveAdvancedGlobalOk) {
      return
    }
  } finally {
    savingAll.value = false
  }
}

const formatBotVerifierTime = (unix: number | null) => {
  if (!unix) return '-'
  return new Date(unix * 1000).toLocaleString()
}

const botVerifierStatusText = (status: string) => {
  if (status === 'ready') return '可用'
  if (status === 'degraded') return '降级'
  return '等待刷新'
}

const loadBotVerifierStatus = async () => {
  botVerifierLoading.value = true
  try {
    const [status, insights] = await Promise.all([
      fetchBotVerifierStatus(),
      fetchBotInsights(),
    ])
    botVerifierStatus.value = status
    botInsights.value = insights
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取爬虫校验状态失败'
  } finally {
    botVerifierLoading.value = false
  }
}

const addBotCrawler = () => {
  systemSettings.bot_detection.crawlers.push({
    enabled: true,
    name: 'CustomBot',
    provider: null,
    category: 'custom',
    policy: 'observe',
    tokens: ['custombot'],
  })
}

const removeBotCrawler = (index: number) => {
  systemSettings.bot_detection.crawlers.splice(index, 1)
}

const updateCrawlerTokens = (index: number, value: string) => {
  const crawler = systemSettings.bot_detection.crawlers[index]
  if (!crawler) return
  crawler.tokens = value.split(',').map((item) => item.trim()).filter(Boolean)
}

const addBotProvider = () => {
  systemSettings.bot_detection.providers.push({
    enabled: true,
    id: 'custom',
    urls: ['https://example.com/bot-ranges.json'],
    mirror_urls: [],
    format: 'json_recursive',
    reverse_dns_enabled: false,
    reverse_dns_suffixes: [],
  })
}

const removeBotProvider = (index: number) => {
  systemSettings.bot_detection.providers.splice(index, 1)
}

const updateProviderUrls = (index: number, value: string) => {
  const provider = systemSettings.bot_detection.providers[index]
  if (!provider) return
  provider.urls = value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

const updateProviderMirrorUrls = (index: number, value: string) => {
  const provider = systemSettings.bot_detection.providers[index]
  if (!provider) return
  provider.mirror_urls = value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

const updateProviderDnsSuffixes = (index: number, value: string) => {
  const provider = systemSettings.bot_detection.providers[index]
  if (!provider) return
  provider.reverse_dns_suffixes = value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

const refreshBotVerifier = async () => {
  botVerifierRefreshing.value = true
  try {
    botVerifierStatus.value = await refreshBotVerifierStatus()
    successMessage.value = '爬虫官方 IP 库刷新完成'
  } catch (e) {
    error.value = e instanceof Error ? e.message : '刷新爬虫官方 IP 库失败'
  } finally {
    botVerifierRefreshing.value = false
  }
}

onMounted(loadBotVerifierStatus)

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

        <AdminL7AdvancedGlobalSection ref="advancedGlobalSectionRef" />

        <section class="rounded-md border border-slate-200 bg-white p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 class="text-sm font-semibold text-slate-900">
                爬虫官方 IP 校验
              </h2>
              <p class="mt-1 text-xs text-slate-500">
                Google / Bing 官方 IP 库后台缓存，失败时自动降级为 UA 库识别。
              </p>
            </div>
            <button
              class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
              :disabled="botVerifierRefreshing"
              @click="refreshBotVerifier"
            >
              <RefreshCw
                :size="14"
                :class="{ 'animate-spin': botVerifierRefreshing }"
              />
              {{ botVerifierRefreshing ? '刷新中' : '手动刷新' }}
            </button>
          </div>
          <div v-if="botVerifierLoading" class="mt-3 text-sm text-slate-500">
            正在读取校验状态...
          </div>
          <div v-else class="mt-3 overflow-x-auto">
            <table class="w-full min-w-[720px] text-sm">
              <thead class="text-xs text-slate-500">
                <tr class="border-b border-slate-200">
                  <th class="py-2 text-left font-medium">Provider</th>
                  <th class="py-2 text-left font-medium">状态</th>
                  <th class="py-2 text-left font-medium">CIDR 数</th>
                  <th class="py-2 text-left font-medium">最后成功</th>
                  <th class="py-2 text-left font-medium">最后刷新</th>
                  <th class="py-2 text-left font-medium">错误</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="provider in botVerifierStatus?.providers || []"
                  :key="provider.provider"
                  class="border-b border-slate-100 text-slate-700"
                >
                  <td class="py-2 font-mono">{{ provider.provider }}</td>
                  <td class="py-2">
                    {{ botVerifierStatusText(provider.status) }}
                  </td>
                  <td class="py-2">{{ provider.range_count }}</td>
                  <td class="py-2">
                    {{ formatBotVerifierTime(provider.last_success_at) }}
                  </td>
                  <td class="py-2">
                    {{ formatBotVerifierTime(provider.last_refresh_at) }}
                  </td>
                  <td class="max-w-[20rem] truncate py-2 text-xs text-rose-600">
                    {{ provider.last_error || '-' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="mt-4 grid gap-3 md:grid-cols-4">
            <div class="rounded-md border border-slate-200 p-3">
              <div class="text-xs text-slate-500">Bot 事件</div>
              <div class="mt-1 text-xl font-semibold text-slate-900">
                {{ botInsights?.total_bot_events || 0 }}
              </div>
            </div>
            <div
              v-for="item in botInsights?.by_trust_class || []"
              :key="item.key"
              class="rounded-md border border-slate-200 p-3"
            >
              <div class="text-xs text-slate-500">{{ item.key }}</div>
              <div class="mt-1 text-xl font-semibold text-slate-900">
                {{ item.count }}
              </div>
            </div>
          </div>
        </section>

        <section class="rounded-md border border-slate-200 bg-white p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 class="text-sm font-semibold text-slate-900">爬虫识别库</h2>
              <p class="mt-1 text-xs text-slate-500">
                UA token 命中后进入 claimed / verified / suspect 分层。
              </p>
            </div>
            <label class="inline-flex items-center gap-2 text-sm text-slate-700">
              <input
                v-model="systemSettings.bot_detection.enabled"
                type="checkbox"
                class="accent-blue-600"
              />
              启用识别
            </label>
          </div>
          <div class="mt-4 space-y-3">
            <div
              v-for="(crawler, index) in systemSettings.bot_detection.crawlers"
              :key="`${crawler.name}-${index}`"
              class="grid gap-2 rounded-md border border-slate-200 p-3 md:grid-cols-6"
            >
              <label class="flex items-center gap-2 text-xs text-slate-600">
                <input v-model="crawler.enabled" type="checkbox" class="accent-blue-600" />
                启用
              </label>
              <input v-model="crawler.name" class="rounded-md border border-slate-300 px-2 py-1 text-sm" />
              <input v-model="crawler.provider" placeholder="provider" class="rounded-md border border-slate-300 px-2 py-1 text-sm" />
              <input v-model="crawler.category" placeholder="category" class="rounded-md border border-slate-300 px-2 py-1 text-sm" />
              <select v-model="crawler.policy" class="rounded-md border border-slate-300 px-2 py-1 text-sm">
                <option value="reduce_friction">reduce_friction</option>
                <option value="observe">observe</option>
                <option value="strict">strict</option>
              </select>
              <button class="rounded-md border border-rose-200 px-2 py-1 text-xs text-rose-700" @click="removeBotCrawler(index)">
                删除
              </button>
              <input
                class="rounded-md border border-slate-300 px-2 py-1 text-sm md:col-span-6"
                :value="crawler.tokens.join(', ')"
                placeholder="tokens, comma separated"
                @input="updateCrawlerTokens(index, ($event.target as HTMLInputElement).value)"
              />
            </div>
            <button class="rounded-md border border-slate-300 px-3 py-1.5 text-xs text-slate-700" @click="addBotCrawler">
              新增爬虫
            </button>
          </div>
        </section>

        <section class="rounded-md border border-slate-200 bg-white p-4">
          <div class="flex items-center justify-between">
            <h2 class="text-sm font-semibold text-slate-900">官方 IP Provider</h2>
            <button class="rounded-md border border-slate-300 px-3 py-1.5 text-xs text-slate-700" @click="addBotProvider">
              新增 Provider
            </button>
          </div>
          <div class="mt-4 space-y-3">
            <div
              v-for="(provider, index) in systemSettings.bot_detection.providers"
              :key="`${provider.id}-${index}`"
              class="grid gap-2 rounded-md border border-slate-200 p-3 md:grid-cols-4"
            >
              <label class="flex items-center gap-2 text-xs text-slate-600">
                <input v-model="provider.enabled" type="checkbox" class="accent-blue-600" />
                启用
              </label>
              <label class="flex items-center gap-2 text-xs text-slate-600">
                <input v-model="provider.reverse_dns_enabled" type="checkbox" class="accent-blue-600" />
                PTR
              </label>
              <input v-model="provider.id" class="rounded-md border border-slate-300 px-2 py-1 text-sm" />
              <input v-model="provider.format" class="rounded-md border border-slate-300 px-2 py-1 text-sm" />
              <button class="rounded-md border border-rose-200 px-2 py-1 text-xs text-rose-700" @click="removeBotProvider(index)">
                删除
              </button>
              <textarea
                class="rounded-md border border-slate-300 px-2 py-1 text-sm md:col-span-4"
                rows="2"
                :value="provider.urls.join('\n')"
                placeholder="官方 URL，每行一个"
                @input="updateProviderUrls(index, ($event.target as HTMLTextAreaElement).value)"
              ></textarea>
              <textarea
                class="rounded-md border border-slate-300 px-2 py-1 text-sm md:col-span-4"
                rows="2"
                :value="provider.mirror_urls.join('\n')"
                placeholder="镜像/中转 URL，每行一个；留空则使用官方 URL"
                @input="updateProviderMirrorUrls(index, ($event.target as HTMLTextAreaElement).value)"
              ></textarea>
              <input
                class="rounded-md border border-slate-300 px-2 py-1 text-sm md:col-span-4"
                :value="provider.reverse_dns_suffixes.join(', ')"
                placeholder=".googlebot.com, .search.msn.com"
                @input="updateProviderDnsSuffixes(index, ($event.target as HTMLInputElement).value)"
              />
            </div>
          </div>
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
