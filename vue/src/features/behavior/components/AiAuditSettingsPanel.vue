<script setup lang="ts">
import { computed } from 'vue'
import { BrainCircuit } from 'lucide-vue-next'
import type { AiAuditSettingsPayload } from '@/shared/types'

const props = defineProps<{
  form: AiAuditSettingsPayload
  windowSeconds: number
}>()

const emit = defineEmits<{
  'update:windowSeconds': [value: number]
}>()

const windowSecondsModel = computed({
  get: () => props.windowSeconds,
  set: (value) => emit('update:windowSeconds', value),
})
</script>

<template>
  <div class="rounded-2xl border border-slate-200 bg-slate-50/80 p-4">
    <div class="flex items-start justify-between gap-3">
      <div>
        <p class="text-sm font-semibold text-slate-900">模型与服务配置</p>
      </div>
      <div class="rounded-2xl bg-white p-3 text-cyan-700 shadow-sm">
        <BrainCircuit :size="18" />
      </div>
    </div>

    <div class="mt-4 grid gap-3 md:grid-cols-2">
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.enabled"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        启用外部 AI 审计
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">默认服务商</span>
        <select
          v-model="form.provider"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
        >
          <option value="local_rules">本地规则（local_rules）</option>
          <option value="stub_model">占位模型（stub_model）</option>
          <option value="openai_compatible">OpenAI 兼容接口</option>
          <option value="xiaomi_mimo">小米 Mimo</option>
        </select>
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">模型名称</span>
        <input
          v-model="form.model"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="text"
          :placeholder="
            form.provider === 'xiaomi_mimo'
              ? '例如 mimo-v2-flash'
              : '例如 gpt-5.4-mini'
          "
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">接口地址</span>
        <input
          v-model="form.base_url"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="text"
          :placeholder="
            form.provider === 'xiaomi_mimo'
              ? '例如 https://api.xiaomimimo.com/v1'
              : '例如 https://api.example.com/v1'
          "
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">接口密钥</span>
        <input
          v-model="form.api_key"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="password"
          placeholder="留空时外部服务无法真正执行"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">超时预算（毫秒）</span>
        <input
          v-model.number="form.timeout_ms"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="1000"
          step="500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">样本事件上限</span>
        <input
          v-model.number="form.event_sample_limit"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="20"
          step="10"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">近期事件样本</span>
        <input
          v-model.number="form.recent_event_limit"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="0"
          step="1"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">临时策略 TTL（秒）</span>
        <input
          v-model.number="form.temp_policy_ttl_secs"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">临时封禁 TTL（秒）</span>
        <input
          v-model.number="form.temp_block_ttl_secs"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">最低自动执行置信度</span>
        <input
          v-model.number="form.auto_apply_min_confidence"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="0"
          max="100"
          step="5"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500"
          >最大活跃临时策略数</span
        >
        <input
          v-model.number="form.max_active_temp_policies"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="1"
          step="1"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500"
          >冷启动撤销热身（秒）</span
        >
        <input
          v-model.number="form.auto_revoke_warmup_secs"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500"
          >自动审计最小间隔（秒）</span
        >
        <input
          v-model.number="form.auto_audit_interval_secs"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">自动审计冷却（秒）</span>
        <input
          v-model.number="form.auto_audit_cooldown_secs"
          class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
    </div>

    <div class="mt-3 flex flex-wrap gap-3">
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.fallback_to_rules"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        外部服务失败时自动回退到本地规则
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_apply_temp_policies"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        自动执行专项临时策略
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.include_raw_event_samples"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        向模型附带近期事件样本
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.allow_auto_extend_effective_policies"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        允许自动续期有效策略
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_audit_enabled"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        启用后台自动审计
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_audit_on_pressure_high"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        高压力时自动触发
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_audit_on_attack_mode"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        攻击模式时自动触发
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_audit_on_hotspot_shift"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        热点变化时自动触发
      </label>
      <label
        class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
      >
        <input
          v-model="form.auto_audit_force_local_rules_under_attack"
          type="checkbox"
          class="h-4 w-4 accent-cyan-600"
        />
        攻击模式下强制回退本地规则
      </label>
      <span
        class="inline-flex items-center rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-700"
      >
        <code class="rounded bg-white/80 px-1 py-0.5">临时封禁</code>
        <span class="ml-2">仍需人工确认，不参与自动执行</span>
      </span>
      <label class="space-y-1">
        <span class="text-xs font-medium text-slate-500">观察窗口（秒）</span>
        <input
          v-model.number="windowSecondsModel"
          class="w-32 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
          type="number"
          min="60"
          step="60"
        />
      </label>
    </div>
  </div>
</template>
