<script setup lang="ts">
import { computed } from 'vue'
import { PencilLine, RotateCcw, Trash2, X } from 'lucide-vue-next'
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
} from '../../lib/types'
import StatusBadge from '../ui/StatusBadge.vue'

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
  listenPortsText: string
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
  'update:listenPortsText': [value: string]
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

const notesModel = computed({
  get: () => props.localSiteForm.notes,
  set: (value: string) => updateForm('notes', value),
})

const enabledModel = computed({
  get: () => props.localSiteForm.enabled,
  set: (value: boolean) => updateForm('enabled', value),
})

const tlsEnabledModel = computed({
  get: () => props.localSiteForm.tls_enabled,
  set: (value: boolean) => updateForm('tls_enabled', value),
})

const syncModeModel = computed({
  get: () => props.localSiteForm.sync_mode,
  set: (value: string) => updateForm('sync_mode', value),
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

      <div
        class="grid gap-4 px-4 py-4 md:px-6 md:py-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)]"
      >
        <div class="space-y-4">
          <div class="grid gap-4 md:grid-cols-2">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">站点名称</span>
              <input
                v-model="nameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 Portal"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">主域名</span>
              <input
                v-model="primaryHostnameModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 portal.example.com"
              />
            </label>
            <label class="space-y-1.5 md:col-span-2">
              <span class="text-xs text-slate-500">Hostnames</span>
              <input
                :value="hostnamesText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
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
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">监听端口</span>
              <input
                :value="listenPortsText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 660"
                @input="
                  emit(
                    'update:listenPortsText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">证书</span>
              <select
                v-model="certificateIdModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
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
            <label class="space-y-1.5 md:col-span-2">
              <span class="text-xs text-slate-500">上游地址</span>
              <input
                :value="upstreamsText"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="多个地址用逗号分隔，例如 127.0.0.1:880"
                @input="
                  emit(
                    'update:upstreamsText',
                    ($event.target as HTMLInputElement).value,
                  )
                "
              />
              <span class="block text-xs text-slate-400">
                当前运行时会优先使用第一个有效上游地址。
              </span>
            </label>
            <label class="space-y-1.5 md:col-span-2">
              <span class="text-xs text-slate-500">备注</span>
              <textarea
                v-model="notesModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                rows="3"
              />
            </label>
          </div>

          <div class="grid gap-3 md:grid-cols-3">
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="enabledModel"
                class="mt-0.5 accent-blue-600"
                type="checkbox"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用站点</span
                >
                <span class="mt-0.5 block text-xs text-slate-500"
                  >关闭后不会参与运行时匹配。</span
                >
              </span>
            </label>
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="tlsEnabledModel"
                class="mt-0.5 accent-blue-600"
                type="checkbox"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用 TLS 站点证书</span
                >
                <span class="mt-0.5 block text-xs text-slate-500"
                  >启用后会参与 SNI 证书匹配。</span
                >
              </span>
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">同步模式</span>
              <select
                v-model="syncModeModel"
                class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="manual">手动</option>
                <option value="pull_only">仅回流</option>
                <option value="push_only">仅推送</option>
                <option value="bidirectional">双向同步</option>
              </select>
            </label>
          </div>

          <div class="flex flex-wrap items-center gap-2">
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

        <div
          class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4"
        >
          <div>
            <p class="text-sm font-medium text-stone-900">编辑提示</p>
            <p class="mt-1 text-xs leading-5 text-slate-500">
              你可以直接从右侧对账列表点“编辑本地”带入，也可以手动新建。对同一个域名，建议统一走系统设置里的
              HTTPS 入口端口。
            </p>
          </div>
          <div class="grid gap-2 text-xs text-slate-500">
            <p>监听端口：建议填统一入口端口，例如 `660`。</p>
            <p>
              证书：TLS 站点建议绑定真实证书；`IP:660`
              回包用系统设置里的默认证书。
            </p>
            <p>上游地址：支持 `127.0.0.1:880` 或 `http://127.0.0.1:880`。</p>
            <p>
              保存后写入数据库，当前服务需要重启才会加载新的监听与站点路由。
            </p>
          </div>
          <div
            v-if="currentLocalSite"
            class="rounded-lg border border-slate-200 bg-white px-3 py-3 text-xs text-slate-500"
          >
            <p class="font-medium text-stone-900">
              {{ currentLocalSite.name }}
            </p>
            <p class="mt-1">
              最近更新：{{ formatTimestamp(currentLocalSite.updated_at) }}
            </p>
            <p class="mt-1">
              当前主域名：{{ currentLocalSite.primary_hostname }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
