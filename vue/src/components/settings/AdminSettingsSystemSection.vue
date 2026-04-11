<script setup lang="ts">
import { computed } from 'vue'
import { Settings } from 'lucide-vue-next'
import type { LocalCertificateItem } from '../../lib/types'
import type { SystemSettingsForm } from '../../lib/adminSettings'

const props = defineProps<{
  localCertificates: LocalCertificateItem[]
  savingDefaultCertificate: boolean
  systemSettings: SystemSettingsForm
}>()

const emit = defineEmits<{
  defaultCertificateChange: [event: Event]
  'update:systemSettings': [value: SystemSettingsForm]
}>()

function updateSystemSettings(patch: Partial<SystemSettingsForm>) {
  emit('update:systemSettings', {
    ...props.systemSettings,
    ...patch,
  })
}

const gatewayName = computed({
  get: () => props.systemSettings.gateway_name,
  set: (value: string) => updateSystemSettings({ gateway_name: value }),
})
const autoRefreshSeconds = computed({
  get: () => props.systemSettings.auto_refresh_seconds,
  set: (value: number) => updateSystemSettings({ auto_refresh_seconds: value }),
})
const httpsListenAddr = computed({
  get: () => props.systemSettings.https_listen_addr,
  set: (value: string) => updateSystemSettings({ https_listen_addr: value }),
})
const apiEndpoint = computed({
  get: () => props.systemSettings.api_endpoint,
  set: (value: string) => updateSystemSettings({ api_endpoint: value }),
})
const retainDays = computed({
  get: () => props.systemSettings.retain_days,
  set: (value: number) => updateSystemSettings({ retain_days: value }),
})
const notificationLevel = computed({
  get: () => props.systemSettings.notification_level,
  set: (value: SystemSettingsForm['notification_level']) =>
    updateSystemSettings({ notification_level: value }),
})
const defaultCertificateId = computed({
  get: () => props.systemSettings.default_certificate_id,
  set: (value: number | null) =>
    updateSystemSettings({ default_certificate_id: value }),
})
const upstreamEndpoint = computed({
  get: () => props.systemSettings.upstream_endpoint,
  set: (value: string) => updateSystemSettings({ upstream_endpoint: value }),
})
</script>

<template>
  <div
    class="rounded-xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
  >
    <div class="flex items-center gap-3">
      <div
        class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-blue-700"
      >
        <Settings :size="20" />
      </div>
      <div>
        <p class="text-xs tracking-wide text-blue-700">控制台参数</p>
        <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
          基础运行配置
        </h3>
      </div>
    </div>

    <div class="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <label class="space-y-1">
        <span class="text-xs text-slate-500">网关名称</span>
        <input
          v-model="gatewayName"
          type="text"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">自动刷新频率（秒）</span>
        <input
          v-model.number="autoRefreshSeconds"
          type="number"
          min="3"
          max="60"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">统一 HTTPS 入口</span>
        <input
          v-model="httpsListenAddr"
          type="text"
          placeholder="例如 0.0.0.0:660"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">控制面 API 地址</span>
        <input
          v-model="apiEndpoint"
          type="text"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">事件保留天数</span>
        <input
          v-model.number="retainDays"
          type="number"
          min="1"
          max="365"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">通知级别</span>
        <select
          v-model="notificationLevel"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="critical">仅高风险事件</option>
          <option value="blocked_only">仅拦截事件</option>
          <option value="all">全部事件</option>
        </select>
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">默认证书</span>
        <select
          v-model="defaultCertificateId"
          :disabled="savingDefaultCertificate"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          @change="emit('defaultCertificateChange', $event)"
        >
          <option :value="null">未设置</option>
          <option
            v-for="certificate in localCertificates"
            :key="certificate.id"
            :value="certificate.id"
          >
            #{{ certificate.id }} · {{ certificate.name }}
          </option>
        </select>
      </label>
      <label class="space-y-1 md:col-span-2 xl:col-span-1">
        <span class="text-xs text-slate-500">默认回源地址</span>
        <input
          v-model="upstreamEndpoint"
          type="text"
          placeholder="未命中站点时使用，可留空"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
    </div>
  </div>
</template>
