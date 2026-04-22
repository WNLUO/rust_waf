<script setup lang="ts">
import { computed } from 'vue'
import { PencilLine, RotateCcw, Trash2, X } from 'lucide-vue-next'
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
} from '@/shared/types'
import StatusBadge from '@/shared/ui/StatusBadge.vue'

const props = defineProps<{
  actions: {
    deletingLocalSite: boolean
    loadingCertificates: boolean
    savingLocalSite: boolean
  }
  currentLocalSite: LocalSiteItem | null
  editingLocalSiteId: number | null
  editorTitle: string
  formatNumber: (value?: number) => string
  formatTimestamp: (timestamp?: number | null) => string
  hostnamesText: string
  isOpen: boolean
  localCertificates: LocalCertificateItem[]
  localSiteForm: LocalSiteDraft
  localSitesCount: number
  upstreamsText: string
}>()

const emit = defineEmits<{
  close: []
  remove: []
  reset: []
  save: []
  'update:form': [value: LocalSiteDraft]
  'update:hostnamesText': [value: string]
  'update:upstreamsText': [value: string]
}>()

function updateForm<K extends keyof LocalSiteDraft>(
  key: K,
  value: LocalSiteDraft[K],
) {
  emit('update:form', {
    ...props.localSiteForm,
    [key]: value,
  })
}

const nameModel = computed({
  get: () => props.localSiteForm.name,
  set: (value: string) => updateForm('name', value),
})

const primaryHostnameModel = computed({
  get: () => props.localSiteForm.primary_hostname,
  set: (value: string) => updateForm('primary_hostname', value),
})

const certificateIdModel = computed({
  get: () => props.localSiteForm.local_certificate_id,
  set: (value: number | null) => updateForm('local_certificate_id', value),
})

const enabledModel = computed({
  get: () => props.localSiteForm.enabled,
  set: (value: boolean) => updateForm('enabled', value),
})

const tlsEnabledModel = computed({
  get: () => props.localSiteForm.tls_enabled,
  set: (value: boolean) => updateForm('tls_enabled', value),
})
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>
    <div
      class="relative max-h-[calc(100vh-2rem)] w-full max-w-6xl overflow-y-auto rounded-[28px] border border-slate-200 bg-white shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)]"
    >
      <div class="border-b border-slate-200 px-4 py-4 md:px-6">
        <div
          class="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between"
        >
          <div>
            <p class="text-sm font-semibold text-stone-900">
              {{ editorTitle }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              在这里直接维护本地运行站点。保存后会写入数据库，重启服务后生效。
            </p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :text="
                actions.loadingCertificates
                  ? '证书读取中'
                  : `可选证书 ${formatNumber(localCertificates.length)} 张`
              "
              :type="actions.loadingCertificates ? 'muted' : 'info'"
              compact
            />
            <StatusBadge
              :text="`本地站点 ${formatNumber(localSitesCount)} 条`"
              type="muted"
              compact
            />
            <button
              class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="emit('close')"
            >
              <X :size="18" />
            </button>
          </div>
        </div>
      </div>

      <div class="space-y-4 px-4 py-4 md:px-6 md:py-6">
        <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="mb-3">
            <p class="text-sm font-medium text-stone-900">站点信息</p>
            <p class="mt-1 text-xs text-slate-500">
              这里填写站点本身的入口配置，包括域名、证书和下游地址。
            </p>
          </div>
          <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">站点名称</span>
              <input
                v-model="nameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 Portal"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">主域名</span>
              <input
                v-model="primaryHostnameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 portal.example.com"
              />
            </label>
            <label class="space-y-1.5 xl:col-span-1">
              <span class="text-xs text-slate-500">证书</span>
              <select
                v-model="certificateIdModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
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
            <label class="space-y-1.5 md:col-span-2 xl:col-span-3">
              <span class="text-xs text-slate-500">附加域名</span>
              <input
                :value="hostnamesText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="多个域名用逗号分隔"
                @input="
                  emit(
                    'update:hostnamesText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
            </label>
            <label class="space-y-1.5 md:col-span-2 xl:col-span-2">
              <span class="text-xs text-slate-500">下游地址</span>
              <input
                :value="upstreamsText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="多个地址用逗号分隔，例如 127.0.0.1:880 或 https://127.0.0.1:9443"
                @input="
                  emit(
                    'update:upstreamsText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
              <span class="block text-xs text-slate-400">
                当前运行时会优先使用第一个有效下游地址。
              </span>
            </label>
          </div>
        </section>

        <div class="flex flex-wrap items-center gap-4 px-1">
          <label class="inline-flex cursor-pointer items-center gap-2.5">
            <input
              v-model="enabledModel"
              type="checkbox"
              class="sr-only"
            />
            <span
              class="relative h-5 w-9 rounded-full transition-colors"
              :class="enabledModel ? 'bg-blue-600' : 'bg-slate-300'"
            >
              <span
                class="absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform"
                :class="enabledModel ? 'translate-x-4' : 'translate-x-0'"
              ></span>
            </span>
            <span class="text-xs font-medium text-stone-800">启用站点</span>
          </label>
          <label class="inline-flex cursor-pointer items-center gap-2.5">
            <input
              v-model="tlsEnabledModel"
              type="checkbox"
              class="sr-only"
            />
            <span
              class="relative h-5 w-9 rounded-full transition-colors"
              :class="tlsEnabledModel ? 'bg-blue-600' : 'bg-slate-300'"
            >
              <span
                class="absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform"
                :class="tlsEnabledModel ? 'translate-x-4' : 'translate-x-0'"
              ></span>
            </span>
            <span class="text-xs font-medium text-stone-800">启用 TLS</span>
          </label>
        </div>

        <div
          class="sticky bottom-0 flex flex-wrap items-center gap-2 border-t border-slate-200 bg-white/95 px-1 pt-2 backdrop-blur"
        >
          <button
            :disabled="actions.savingLocalSite"
            class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('save')"
          >
            <PencilLine :size="14" />
            {{
              actions.savingLocalSite
                ? '保存中...'
                : editingLocalSiteId === null
                  ? '创建本地站点'
                  : '保存本地站点'
            }}
          </button>
          <button
            class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="emit('reset')"
          >
            <RotateCcw :size="14" />
            重置表单
          </button>
          <button
            v-if="editingLocalSiteId !== null"
            :disabled="actions.deletingLocalSite"
            class="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-medium text-red-700 transition hover:border-red-400 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('remove')"
          >
            <Trash2 :size="14" />
            {{ actions.deletingLocalSite ? '删除中...' : '删除本地站点' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
