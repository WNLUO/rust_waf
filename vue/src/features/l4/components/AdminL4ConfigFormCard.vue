<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'

const props = defineProps<{
  form: L4ConfigForm
}>()

const emit = defineEmits<{
  'update:form': [value: L4ConfigForm]
}>()

const numberFieldClass = 'l4-inline-field text-sm text-stone-700'
const numberLabelClass = 'l4-inline-label'
const numberInputClass = 'l4-inline-input'
const numberHintClass = 'l4-inline-hint'

function patchForm(patch: Partial<L4ConfigForm>) {
  emit('update:form', { ...props.form, ...patch })
}
</script>

<template>
  <CyberCard
    title="L4 防护配置"
    sub-title="保存到数据库后，后端会立即刷新运行中的 L4 实例。"
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

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">每秒连接速率阈值</span>
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
        <p :class="numberHintClass">
          超过阈值后，连接限流器会拒绝来源地址的新连接。
        </p>
      </label>

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">SYN / 突发阈值</span>
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
        <p :class="numberHintClass">
          用于判定 1 秒窗口内是否出现连接洪泛。
        </p>
      </label>

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">跟踪 IP 上限</span>
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
        <p :class="numberHintClass">
          连接跟踪器能同时维护的来源地址数量。
        </p>
      </label>

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">封禁表上限</span>
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
        <p :class="numberHintClass">
          本地限流器允许同时保留的封禁 IP 数量。
        </p>
      </label>

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">状态保留时长（秒）</span>
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
        <p :class="numberHintClass">
          连接窗口、限流计数和过期封禁的清理周期参考值。
        </p>
      </label>

      <label :class="numberFieldClass">
        <span :class="numberLabelClass">Bloom 缩放系数</span>
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
        <p :class="numberHintClass">
          影响四层 Bloom Filter 的容量规模，实际值会按运行档位归一化。
        </p>
      </label>
    </div>

    <div class="mt-6 space-y-4">
      <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p class="text-sm font-medium text-stone-900">行为引擎预算</p>
        <p class="mt-1 text-xs leading-6 text-slate-500">
          这些参数决定 L4 分桶在正常、可疑和高风险状态下的连接预算与事件承压上限。
        </p>
      </div>

      <div class="grid gap-3 md:grid-cols-2">
        <label :class="numberFieldClass">
          <span :class="numberLabelClass">事件通道容量</span>
          <input
            :value="form.behavior_event_channel_capacity"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_event_channel_capacity: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">事件丢弃告警阈值</span>
          <input
            :value="form.behavior_drop_critical_threshold"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_drop_critical_threshold: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">分桶降级比例 (%)</span>
          <input
            :value="form.behavior_fallback_ratio_percent"
            type="number"
            min="1"
            max="100"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_fallback_ratio_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">过载封禁阈值</span>
          <input
            :value="form.behavior_overload_blocked_connections_threshold"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_overload_blocked_connections_threshold: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">过载活跃连接阈值</span>
          <input
            :value="form.behavior_overload_active_connections_threshold"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_overload_active_connections_threshold: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">正常桶预算 (rpm)</span>
          <input
            :value="form.behavior_normal_connection_budget_per_minute"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_normal_connection_budget_per_minute: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">可疑桶预算 (rpm)</span>
          <input
            :value="form.behavior_suspicious_connection_budget_per_minute"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_suspicious_connection_budget_per_minute: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">高风险桶预算 (rpm)</span>
          <input
            :value="form.behavior_high_risk_connection_budget_per_minute"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_high_risk_connection_budget_per_minute: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>
      </div>

      <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p class="text-sm font-medium text-stone-900">过载缩放与延迟</p>
        <p class="mt-1 text-xs leading-6 text-slate-500">
          用于控制高负载下预算缩放、软延迟、硬延迟和拒绝新连接的切换边界。
        </p>
      </div>

      <div class="grid gap-3 md:grid-cols-2">
        <label :class="numberFieldClass">
          <span :class="numberLabelClass">高过载预算缩放 (%)</span>
          <input
            :value="form.behavior_high_overload_budget_scale_percent"
            type="number"
            min="1"
            max="100"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_high_overload_budget_scale_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">临界过载预算缩放 (%)</span>
          <input
            :value="form.behavior_critical_overload_budget_scale_percent"
            type="number"
            min="1"
            max="100"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_critical_overload_budget_scale_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">高过载建议延迟 (ms)</span>
          <input
            :value="form.behavior_high_overload_delay_ms"
            type="number"
            min="0"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_high_overload_delay_ms: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">临界过载建议延迟 (ms)</span>
          <input
            :value="form.behavior_critical_overload_delay_ms"
            type="number"
            min="0"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_critical_overload_delay_ms: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">软延迟阈值 (%)</span>
          <input
            :value="form.behavior_soft_delay_threshold_percent"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_soft_delay_threshold_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">硬延迟阈值 (%)</span>
          <input
            :value="form.behavior_hard_delay_threshold_percent"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_hard_delay_threshold_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">软延迟时长 (ms)</span>
          <input
            :value="form.behavior_soft_delay_ms"
            type="number"
            min="0"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_soft_delay_ms: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">硬延迟时长 (ms)</span>
          <input
            :value="form.behavior_hard_delay_ms"
            type="number"
            min="0"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_hard_delay_ms: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">拒绝阈值 (%)</span>
          <input
            :value="form.behavior_reject_threshold_percent"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_reject_threshold_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>

        <label :class="numberFieldClass">
          <span :class="numberLabelClass">临界拒绝阈值 (%)</span>
          <input
            :value="form.behavior_critical_reject_threshold_percent"
            type="number"
            min="1"
            step="1"
            :class="numberInputClass"
            @input="
              patchForm({
                behavior_critical_reject_threshold_percent: Number(
                  ($event.target as HTMLInputElement).value,
                ),
              })
            "
          />
        </label>
      </div>
    </div>
  </CyberCard>
</template>

<style scoped>
.l4-inline-field {
  display: grid;
  gap: 0.45rem;
  padding: 0.62rem 0.72rem;
  border-radius: 0.9rem;
  border: 1px solid rgb(226 232 240);
  background: linear-gradient(
    180deg,
    rgba(248, 250, 252, 0.9) 0%,
    rgba(241, 245, 249, 0.7) 100%
  );
  transition:
    border-color 0.2s ease,
    background-color 0.2s ease,
    box-shadow 0.2s ease;
}

.l4-inline-field:hover {
  border-color: rgb(203 213 225);
}

.l4-inline-field:focus-within {
  border-color: rgba(59, 130, 246, 0.45);
  background: rgb(248 250 252);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.08);
}

.l4-inline-label {
  color: rgb(100 116 139);
  font-size: 0.76rem;
  font-weight: 600;
  line-height: 1.35;
}

.l4-inline-input {
  width: 100%;
  border-radius: 0.72rem;
  border: 1px solid rgb(203 213 225);
  background: rgb(255 255 255);
  padding: 0.52rem 0.72rem;
  font-size: 0.875rem;
  color: rgb(41 37 36);
  outline: none;
  transition:
    border-color 0.2s ease,
    box-shadow 0.2s ease;
  box-shadow: inset 0 1px 0 rgba(148, 163, 184, 0.08);
}

.l4-inline-input:focus {
  border-color: rgba(59, 130, 246, 0.65);
  box-shadow:
    0 0 0 3px rgba(59, 130, 246, 0.12),
    inset 0 1px 0 rgba(148, 163, 184, 0.08);
}

.l4-inline-hint {
  margin-top: 0.1rem;
  color: rgb(100 116 139);
  font-size: 0.74rem;
  line-height: 1.3;
}

@media (min-width: 768px) {
  .l4-inline-field {
    grid-template-columns: minmax(0, 10.25rem) minmax(0, 1fr);
    align-items: center;
    column-gap: 0.75rem;
  }

  .l4-inline-label {
    text-align: right;
  }

  .l4-inline-hint {
    grid-column: 2;
    margin-top: 0.05rem;
  }
}
</style>
