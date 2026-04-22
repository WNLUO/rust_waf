<script setup lang="ts">
import { computed } from 'vue'
import { Globe2, RefreshCw, Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminL7OverviewSection from '@/features/l7/components/AdminL7OverviewSection.vue'
import { useAdminL7 } from '@/features/l7/composables/useAdminL7'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const { formatLatency, formatNumber, formatTimestamp } = useFormatters()

const {
  configForm,
  error,
  failureModeLabel,
  http1SecurityLabel,
  http3StatusLabel,
  http3StatusType,
  lastUpdated,
  loading,
  protocolTags,
  proxySuccessRate,
  refreshAll,
  runtimeProfileLabel,
  runtimeStatus,
  saveConfig,
  saving,
  stats,
  successMessage,
  upstreamProtocolLabel,
  upstreamStatusText,
  upstreamStatusType,
  refreshing,
} = useAdminL7()

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L7 管理',
  successTitle: 'L7 管理',
  errorDuration: 5600,
  successDuration: 3200,
})

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return '等待首次拉取'
  return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(lastUpdated.value))}`
})

function listText(getter: () => string[], setter: (value: string[]) => void) {
  return computed({
    get: () => getter().join('\n'),
    set: (value: string) => {
      setter(
        value
          .split(/[\n,]/)
          .map((item) => item.trim())
          .filter(Boolean),
      )
    },
  })
}

const domesticCountryCodesText = listText(
  () => configForm.ip_access.domestic_country_codes,
  (value) => {
    configForm.ip_access.domestic_country_codes = value
  },
)
const allowCidrsText = listText(
  () => configForm.ip_access.allow_cidrs,
  (value) => {
    configForm.ip_access.allow_cidrs = value
  },
)
const blockCidrsText = listText(
  () => configForm.ip_access.block_cidrs,
  (value) => {
    configForm.ip_access.block_cidrs = value
  },
)
const domesticCidrsText = listText(
  () => configForm.ip_access.domestic_cidrs,
  (value) => {
    configForm.ip_access.domestic_cidrs = value
  },
)
const countryHeadersText = listText(
  () => configForm.ip_access.geo_headers.country_headers,
  (value) => {
    configForm.ip_access.geo_headers.country_headers = value
  },
)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs whitespace-nowrap text-slate-500">{{
          lastUpdatedLabel
        }}</span>
        <button
          :disabled="refreshing"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          @click="refreshAll()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-6 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入 HTTP 接入管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <AdminL7OverviewSection
        :config-form="configForm"
        :failure-mode-label="failureModeLabel"
        :format-latency="formatLatency"
        :format-number="formatNumber"
        :format-timestamp="formatTimestamp"
        :http1-security-label="http1SecurityLabel"
        :http3-status-label="http3StatusLabel"
        :http3-status-type="http3StatusType"
        :protocol-tags="protocolTags"
        :proxy-success-rate="proxySuccessRate"
        :runtime-profile-label="runtimeProfileLabel"
        :runtime-status="runtimeStatus"
        :stats="stats"
        :upstream-protocol-label="upstreamProtocolLabel"
        :upstream-status-text="upstreamStatusText"
        :upstream-status-type="upstreamStatusType"
      />

      <section
        class="rounded-xl border border-slate-200 bg-white/82 p-4 shadow-sm"
      >
        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div class="flex items-center gap-3">
            <Globe2 :size="20" class="text-blue-700" />
            <div>
              <p class="text-sm font-semibold text-stone-900">地域访问</p>
              <p class="text-xs text-slate-500">
                国内业务、CDN Geo Header、搜索引擎例外与 CIDR 准入策略
              </p>
            </div>
          </div>
          <button
            type="button"
            :disabled="saving"
            class="inline-flex items-center justify-center gap-2 rounded-full bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:opacity-60"
            @click="saveConfig"
          >
            <Save :size="15" />
            {{ saving ? '保存中' : '保存配置' }}
          </button>
        </div>

        <div class="mt-4 grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <div class="space-y-4">
            <div class="grid gap-3 md:grid-cols-2">
              <label class="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-stone-800">
                <span class="font-medium">启用地域访问</span>
                <input v-model="configForm.ip_access.enabled" type="checkbox" class="ui-switch float-right" />
              </label>
              <label class="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-stone-800">
                <span class="font-medium">CDN Geo Header</span>
                <input v-model="configForm.ip_access.geo_headers.enabled" type="checkbox" class="ui-switch float-right" />
              </label>
            </div>

            <div class="grid gap-3 md:grid-cols-3">
              <label class="text-sm text-stone-700">
                <span class="font-medium">模式</span>
                <select v-model="configForm.ip_access.mode" class="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 outline-none focus:border-blue-500">
                  <option value="monitor">观察</option>
                  <option value="domestic_only">国内业务</option>
                  <option value="custom">自定义</option>
                </select>
              </label>
              <label class="text-sm text-stone-700">
                <span class="font-medium">海外动作</span>
                <select v-model="configForm.ip_access.overseas_action" class="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 outline-none focus:border-blue-500">
                  <option value="challenge">挑战</option>
                  <option value="block">禁止</option>
                  <option value="alert">仅告警</option>
                  <option value="allow">放行</option>
                </select>
              </label>
              <label class="text-sm text-stone-700">
                <span class="font-medium">未知地域</span>
                <select v-model="configForm.ip_access.unknown_geo_action" class="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 outline-none focus:border-blue-500">
                  <option value="challenge">挑战</option>
                  <option value="block">禁止</option>
                  <option value="alert">仅告警</option>
                  <option value="allow">放行</option>
                </select>
              </label>
            </div>

            <div class="grid gap-3 md:grid-cols-2">
              <label class="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm text-stone-800">
                <span>仅信任可信代理传入的 Geo Header</span>
                <input v-model="configForm.ip_access.geo_headers.trust_only_from_proxy" type="checkbox" class="ui-switch" />
              </label>
              <label class="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm text-stone-800">
                <span>放行内网 / 本机地址</span>
                <input v-model="configForm.ip_access.allow_private_ips" type="checkbox" class="ui-switch" />
              </label>
              <label class="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm text-stone-800">
                <span>放行服务器公网自保护地址</span>
                <input v-model="configForm.ip_access.allow_server_public_ip" type="checkbox" class="ui-switch" />
              </label>
              <label class="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm text-stone-800">
                <span>放行已验证搜索引擎</span>
                <input v-model="configForm.ip_access.bot_policy.allow_verified_search_bots" type="checkbox" class="ui-switch" />
              </label>
            </div>

            <div class="grid gap-3 md:grid-cols-2">
              <label class="inline-flex items-center justify-between gap-3 rounded-lg border border-slate-200 bg-white p-3 text-sm text-stone-800">
                <span>放行仅 UA 声明的搜索引擎</span>
                <input v-model="configForm.ip_access.bot_policy.allow_claimed_search_bots" type="checkbox" class="ui-switch" />
              </label>
              <label class="text-sm text-stone-700">
                <span class="font-medium">可疑搜索引擎动作</span>
                <select v-model="configForm.ip_access.bot_policy.suspect_bot_action" class="mt-2 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 outline-none focus:border-blue-500">
                  <option value="challenge">挑战</option>
                  <option value="block">禁止</option>
                  <option value="alert">仅告警</option>
                  <option value="allow">放行</option>
                </select>
              </label>
            </div>
          </div>

          <div class="grid gap-3 md:grid-cols-2">
            <label class="text-sm text-stone-700">
              <span class="font-medium">国内国家码</span>
              <textarea v-model="domesticCountryCodesText" class="mt-2 min-h-24 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-blue-500" />
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium">国家 Header</span>
              <textarea v-model="countryHeadersText" class="mt-2 min-h-24 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-blue-500" />
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium">白名单 CIDR</span>
              <textarea v-model="allowCidrsText" class="mt-2 min-h-28 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-blue-500" placeholder="203.0.113.0/24" />
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium">黑名单 CIDR</span>
              <textarea v-model="blockCidrsText" class="mt-2 min-h-28 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-blue-500" placeholder="198.51.100.10/32" />
            </label>
            <label class="text-sm text-stone-700 md:col-span-2">
              <span class="font-medium">国内 CIDR</span>
              <textarea v-model="domesticCidrsText" class="mt-2 min-h-32 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-blue-500" placeholder="1.0.1.0/24" />
            </label>
          </div>
        </div>
      </section>
    </div>
  </AppLayout>
</template>
