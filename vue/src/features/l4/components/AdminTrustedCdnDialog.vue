<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import { computed } from 'vue'
import { RefreshCw, Save, ShieldCheck, X } from 'lucide-vue-next'
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'

const props = defineProps<{
  form: L4ConfigForm
  isOpen: boolean
  saving: boolean
}>()

const emit = defineEmits<{
  close: []
  save: []
}>()

const manualCidrsText = computed({
  get: () => props.form.trusted_cdn.manual_cidrs.join('\n'),
  set: (value: string) => {
    props.form.trusted_cdn.manual_cidrs = value
      .split('\n')
      .map((item) => item.trim())
      .filter(Boolean)
  },
})

const syncIntervalValueText = computed({
  get: () => String(props.form.trusted_cdn.sync_interval_value ?? ''),
  set: (value: string) => {
    const digitsOnly = value.replace(/[^\d]/g, '')
    props.form.trusted_cdn.sync_interval_value = digitsOnly
      ? Number.parseInt(digitsOnly, 10)
      : 1
  },
})

const effectivePreviewCount = computed(() => {
  const values = new Set<string>()
  for (const cidr of props.form.trusted_cdn.manual_cidrs) {
    if (cidr) values.add(cidr)
  }
  if (props.form.trusted_cdn.edgeone_overseas.enabled) {
    for (const cidr of props.form.trusted_cdn.edgeone_overseas.synced_cidrs) {
      if (cidr) values.add(cidr)
    }
  }
  if (props.form.trusted_cdn.aliyun_esa.enabled) {
    for (const cidr of props.form.trusted_cdn.aliyun_esa.synced_cidrs) {
      if (cidr) values.add(cidr)
    }
  }
  return values.size
})

function formatSyncTime(timestamp: number | null) {
  if (!timestamp) return '尚未同步'
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(timestamp * 1000)
}

function statusLabel(status: string) {
  if (status === 'success') return '同步成功'
  if (status === 'error') return '同步失败'
  return '等待同步'
}

function statusClass(status: string) {
  if (status === 'success')
    return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  if (status === 'error') return 'border-rose-200 bg-rose-50 text-rose-700'
  return 'border-slate-200 bg-slate-50 text-slate-600'
}
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[120] flex items-center justify-center px-4 py-8"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>
    <div
      class="relative w-full max-w-5xl rounded-[28px] border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)]"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-wide text-blue-700">可信 CDN 配置</p>
          <h3 class="mt-2 text-2xl font-semibold text-stone-900">
            管理 L4 层可信 CDN 节点
          </h3>
          <p class="mt-2 text-sm leading-6 text-slate-500">
            这里配置的手动网段和厂商同步结果会并入 L4
            可信来源列表，同时参与真实来源识别链路。
          </p>
        </div>
        <button
          class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div
        class="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]"
      >
        <section
          class="space-y-3 rounded-2xl border border-slate-200 bg-white/90 p-4"
        >
          <div class="flex items-center justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-stone-900">手动可信网段</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                支持手动输入单个 IP 或 CIDR，每行一条。
              </p>
            </div>
            <span
              class="rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-xs text-blue-700"
            >
              当前 {{ props.form.trusted_cdn.manual_cidrs.length }} 条
            </span>
          </div>

          <textarea
            v-model="manualCidrsText"
            rows="12"
            class="w-full rounded-[18px] border border-slate-200 bg-white px-3.5 py-3 font-mono text-xs outline-none transition focus:border-blue-500"
            placeholder="例如&#10;1.1.1.1/32&#10;203.0.113.0/24"
          />

          <div
            class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
          >
            <div
              class="flex items-center gap-2 text-sm font-medium text-stone-900"
            >
              <ShieldCheck :size="16" class="text-blue-700" />
              生效结果预览
            </div>
            <p class="mt-2 text-xs leading-5 text-slate-500">
              当前会生效 {{ effectivePreviewCount }} 条可信 CDN IP/IP 段。保存后
              5 秒内会按配置触发首次自动同步。
            </p>
          </div>
        </section>

        <section
          class="space-y-4 rounded-2xl border border-slate-200 bg-white/90 p-4"
        >
          <div class="grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_9rem]">
            <label class="space-y-1.5">
              <span class="text-xs font-medium text-slate-500"
                >自动同步周期</span
              >
              <input
                v-model="syncIntervalValueText"
                type="text"
                inputmode="numeric"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                placeholder="12"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs font-medium text-slate-500">时间单位</span>
              <select
                v-model="props.form.trusted_cdn.sync_interval_unit"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="minute">分钟</option>
                <option value="hour">小时</option>
                <option value="day">天</option>
              </select>
            </label>
            <div class="space-y-1.5">
              <span class="text-xs font-medium text-slate-500">说明</span>
              <div
                class="rounded-[16px] border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-xs leading-5 text-slate-500"
              >
                所有开启的内置厂商共用这个周期。
              </div>
            </div>
          </div>

          <section
            class="rounded-2xl border border-slate-200 bg-slate-50/70 p-4"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">
                  EdgeOne 国际版免费 CDN
                </p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  使用 EdgeOne 官方公开 IP 数据自动同步海外免费 CDN 节点。
                </p>
              </div>
              <label
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700"
              >
                <span>启用</span>
                <input
                  v-model="props.form.trusted_cdn.edgeone_overseas.enabled"
                  type="checkbox"
                  class="ui-switch"
                />
              </label>
            </div>

            <div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
              <span
                class="rounded-full border px-3 py-1"
                :class="
                  statusClass(
                    props.form.trusted_cdn.edgeone_overseas.last_sync_status,
                  )
                "
              >
                {{
                  statusLabel(
                    props.form.trusted_cdn.edgeone_overseas.last_sync_status,
                  )
                }}
              </span>
              <span
                class="rounded-full border border-slate-200 bg-white px-3 py-1 text-slate-600"
              >
                已同步
                {{
                  props.form.trusted_cdn.edgeone_overseas.synced_cidrs.length
                }}
                条
              </span>
              <span class="text-slate-500">
                最近同步：{{
                  formatSyncTime(
                    props.form.trusted_cdn.edgeone_overseas.last_synced_at,
                  )
                }}
              </span>
            </div>

            <p
              v-if="props.form.trusted_cdn.edgeone_overseas.last_sync_message"
              class="mt-3 rounded-[16px] border border-slate-200 bg-white px-3.5 py-3 text-xs leading-5 text-slate-600"
            >
              {{ props.form.trusted_cdn.edgeone_overseas.last_sync_message }}
            </p>
          </section>

          <section
            class="rounded-2xl border border-slate-200 bg-slate-50/70 p-4"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">阿里云 ESA</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  通过 ESA 官方 OpenAPI 获取站点回源白名单，需填写站点 ID 和
                  AccessKey。
                </p>
              </div>
              <label
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700"
              >
                <span>启用</span>
                <input
                  v-model="props.form.trusted_cdn.aliyun_esa.enabled"
                  type="checkbox"
                  class="ui-switch"
                />
              </label>
            </div>

            <div class="mt-3 grid gap-3 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs font-medium text-slate-500">Site ID</span>
                <input
                  v-model="props.form.trusted_cdn.aliyun_esa.site_id"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  placeholder="例如 123456"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs font-medium text-slate-500"
                  >API Endpoint</span
                >
                <input
                  v-model="props.form.trusted_cdn.aliyun_esa.endpoint"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  placeholder="esa.cn-hangzhou.aliyuncs.com"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs font-medium text-slate-500"
                  >AccessKey ID</span
                >
                <input
                  v-model="props.form.trusted_cdn.aliyun_esa.access_key_id"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  placeholder="LTAI..."
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs font-medium text-slate-500"
                  >AccessKey Secret</span
                >
                <input
                  v-model="props.form.trusted_cdn.aliyun_esa.access_key_secret"
                  type="password"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  placeholder="填写 ESA OpenAPI Secret"
                />
              </label>
            </div>

            <div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
              <span
                class="rounded-full border px-3 py-1"
                :class="
                  statusClass(
                    props.form.trusted_cdn.aliyun_esa.last_sync_status,
                  )
                "
              >
                {{
                  statusLabel(
                    props.form.trusted_cdn.aliyun_esa.last_sync_status,
                  )
                }}
              </span>
              <span
                class="rounded-full border border-slate-200 bg-white px-3 py-1 text-slate-600"
              >
                已同步
                {{ props.form.trusted_cdn.aliyun_esa.synced_cidrs.length }} 条
              </span>
              <span class="text-slate-500">
                最近同步：{{
                  formatSyncTime(
                    props.form.trusted_cdn.aliyun_esa.last_synced_at,
                  )
                }}
              </span>
            </div>

            <p
              v-if="props.form.trusted_cdn.aliyun_esa.last_sync_message"
              class="mt-3 rounded-[16px] border border-slate-200 bg-white px-3.5 py-3 text-xs leading-5 text-slate-600"
            >
              {{ props.form.trusted_cdn.aliyun_esa.last_sync_message }}
            </p>
          </section>
        </section>
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          :disabled="saving"
          class="inline-flex items-center gap-2 rounded-lg border border-blue-500/25 bg-white px-4 py-2 text-sm font-medium text-blue-700 transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('save')"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存可信 CDN 配置' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white/75 px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300"
          @click="emit('close')"
        >
          关闭
        </button>
        <span class="inline-flex items-center gap-2 text-xs text-slate-500">
          <RefreshCw :size="13" />
          保存后后台会按周期自动更新，并把结果追加到可信列表中。
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ui-switch {
  appearance: none;
  width: 2.75rem;
  height: 1.5rem;
  border-radius: 9999px;
  background: linear-gradient(
    135deg,
    rgba(148, 163, 184, 0.8),
    rgba(100, 116, 139, 0.75)
  );
  position: relative;
  outline: none;
  cursor: pointer;
  transition:
    background 0.2s ease,
    box-shadow 0.2s ease;
  box-shadow: inset 0 1px 3px rgba(15, 23, 42, 0.16);
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: #fff;
  box-shadow: 0 6px 14px rgba(15, 23, 42, 0.18);
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: linear-gradient(
    135deg,
    rgba(37, 99, 235, 0.92),
    rgba(14, 165, 233, 0.92)
  );
}

.ui-switch:checked::after {
  transform: translateX(1.25rem);
}
</style>
