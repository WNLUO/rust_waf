<script setup lang="ts">
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'

const props = defineProps<{
  form: L4ConfigForm
  compatibilityMode?: boolean
}>()

const emit = defineEmits<{
  'update:form': [value: L4ConfigForm]
}>()

const numberFieldClass = 'l4-inline-field text-sm text-stone-700'
const numberLabelClass = 'l4-inline-label'
const numberInputClass = 'l4-inline-input'

function patchForm(patch: Partial<L4ConfigForm>) {
  emit('update:form', { ...props.form, ...patch })
}
</script>

<template>
  <section class="space-y-3">
    <div
      v-if="compatibilityMode"
      class="rounded-xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-sm leading-6 text-amber-900"
    >
      当前处于 L4 兼容模式。这里编辑的是历史细粒度参数，仅用于旧策略回滚或特殊排障，不是自动控制器的主入口。
    </div>
    <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
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
      </label>
    </div>

    <div class="space-y-2 border-t border-slate-200 pt-3">
      <p class="text-sm font-medium text-stone-900">行为引擎预算</p>

      <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
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

      <p class="border-t border-slate-200 pt-3 text-sm font-medium text-stone-900">
        过载缩放与延迟
      </p>

      <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
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
  </section>
</template>

<style scoped>
.l4-inline-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
}

.l4-inline-label {
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}

.l4-inline-input {
  width: 3.6rem;
  border-radius: 0.375rem;
  border: 1px solid rgb(203 213 225);
  background: transparent;
  padding: 0.2rem 0.4rem;
  font-size: 0.875rem;
  color: rgb(41 37 36);
  outline: none;
  text-align: center;
  transition: border-color 0.2s ease;
}

.l4-inline-input:focus {
  border-color: rgba(59, 130, 246, 0.65);
}

.l4-inline-input[type='number']::-webkit-outer-spin-button,
.l4-inline-input[type='number']::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

.l4-inline-input[type='number'] {
  -moz-appearance: textfield;
}

.l4-toggle-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
}

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
</style>
