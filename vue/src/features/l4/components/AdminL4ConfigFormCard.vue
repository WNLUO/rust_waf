<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'

const props = defineProps<{
  form: L4ConfigForm
}>()

const emit = defineEmits<{
  'update:form': [value: L4ConfigForm]
}>()

const numberInputClass =
  'mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40'

function patchForm(patch: Partial<L4ConfigForm>) {
  emit('update:form', { ...props.form, ...patch })
}
</script>

<template>
  <CyberCard
    title="L4 防护配置"
    sub-title="保存到数据库后，重启服务即可让新配置接管运行时实例。"
  >
    <div class="grid gap-3 md:grid-cols-2">
      <label
        class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-stone-700"
      >
        <div class="flex items-center justify-between gap-4">
          <div>
            <p class="font-medium text-stone-900">启用 DDoS 防护</p>
            <p class="mt-1 text-xs leading-6 text-slate-500">
              关闭后仍会保留页面配置，但运行时不会做 DDoS 判定。
            </p>
          </div>
          <input
            :checked="form.ddos_protection_enabled"
            type="checkbox"
            class="h-5 w-5 accent-blue-600"
            @change="
              patchForm({
                ddos_protection_enabled: ($event.target as HTMLInputElement)
                  .checked,
              })
            "
          />
        </div>
      </label>

      <label
        class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-stone-700"
      >
        <div class="flex items-center justify-between gap-4">
          <div>
            <p class="font-medium text-stone-900">高级 DDoS 判定</p>
            <p class="mt-1 text-xs leading-6 text-slate-500">
              额外使用更长窗口观测持续连接洪泛。
            </p>
          </div>
          <input
            :checked="form.advanced_ddos_enabled"
            type="checkbox"
            class="h-5 w-5 accent-blue-600"
            @change="
              patchForm({
                advanced_ddos_enabled: ($event.target as HTMLInputElement)
                  .checked,
              })
            "
          />
        </div>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">每秒连接速率阈值</span>
        <input
          :value="form.connection_rate_limit"
          type="number"
          min="1"
          step="1"
          :class="numberInputClass"
          @input="
            patchForm({
              connection_rate_limit: Number(
                ($event.target as HTMLInputElement).value,
              ),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          超过阈值后，连接限流器会拒绝来源地址的新连接。
        </p>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">SYN / 突发阈值</span>
        <input
          :value="form.syn_flood_threshold"
          type="number"
          min="1"
          step="1"
          :class="numberInputClass"
          @input="
            patchForm({
              syn_flood_threshold: Number(
                ($event.target as HTMLInputElement).value,
              ),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          用于判定 1 秒窗口内是否出现连接洪泛。
        </p>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">跟踪 IP 上限</span>
        <input
          :value="form.max_tracked_ips"
          type="number"
          min="1"
          step="1"
          :class="numberInputClass"
          @input="
            patchForm({
              max_tracked_ips: Number(
                ($event.target as HTMLInputElement).value,
              ),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          连接跟踪器能同时维护的来源地址数量。
        </p>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">封禁表上限</span>
        <input
          :value="form.max_blocked_ips"
          type="number"
          min="1"
          step="1"
          :class="numberInputClass"
          @input="
            patchForm({
              max_blocked_ips: Number(
                ($event.target as HTMLInputElement).value,
              ),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          本地限流器允许同时保留的封禁 IP 数量。
        </p>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">状态保留时长（秒）</span>
        <input
          :value="form.state_ttl_secs"
          type="number"
          min="60"
          step="1"
          :class="numberInputClass"
          @input="
            patchForm({
              state_ttl_secs: Number(($event.target as HTMLInputElement).value),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          连接窗口、限流计数和过期封禁的清理周期参考值。
        </p>
      </label>

      <label class="text-sm text-stone-700">
        <span class="font-medium text-stone-900">Bloom 缩放系数</span>
        <input
          :value="form.bloom_filter_scale"
          type="number"
          min="0.1"
          step="0.1"
          :class="numberInputClass"
          @input="
            patchForm({
              bloom_filter_scale: Number(
                ($event.target as HTMLInputElement).value,
              ),
            })
          "
        />
        <p class="mt-2 text-xs text-slate-500">
          影响四层 Bloom Filter 的容量规模，实际值会按运行档位归一化。
        </p>
      </label>
    </div>
  </CyberCard>
</template>
