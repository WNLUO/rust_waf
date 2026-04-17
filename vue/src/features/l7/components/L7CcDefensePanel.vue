<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import type { Ref, WritableComputedRef } from 'vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    ccDefenseEnabled: ModelRef<boolean>
    ccRequestWindow: ModelRef<number>
    ccIpChallengeThreshold: ModelRef<number>
    ccIpBlockThreshold: ModelRef<number>
    ccHostChallengeThreshold: ModelRef<number>
    ccHostBlockThreshold: ModelRef<number>
    ccRouteChallengeThreshold: ModelRef<number>
    ccRouteBlockThreshold: ModelRef<number>
    ccHotPathChallengeThreshold: ModelRef<number>
    ccHotPathBlockThreshold: ModelRef<number>
    ccDelayThresholdPercent: ModelRef<number>
    ccDelayMs: ModelRef<number>
    ccChallengeTtl: ModelRef<number>
    ccChallengeCookieName: ModelRef<string>
    ccHardRouteBlockMultiplier: ModelRef<number>
    ccHardHostBlockMultiplier: ModelRef<number>
    ccHardIpBlockMultiplier: ModelRef<number>
    ccHardHotPathBlockMultiplier: ModelRef<number>
  }
  numberInputClass: string
}>()
</script>

<template>
  <div class="mt-3 border-t border-slate-200 pt-6">
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm tracking-wider text-blue-700">
          L7 CC 防护（自动化接管项）
        </p>
      </div>
      <div class="flex flex-wrap gap-3">
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
        >
          <span>启用 CC 守卫</span>
          <input
            v-model="controls.ccDefenseEnabled.value"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
      <label class="l7-inline-field text-sm text-stone-700"
        >滑窗时长(s)<input
          v-model.number="controls.ccRequestWindow.value"
          type="number"
          min="3"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >延迟触发比例(%)<input
          v-model.number="controls.ccDelayThresholdPercent.value"
          type="number"
          min="25"
          max="95"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >延迟时长(ms)<input
          v-model.number="controls.ccDelayMs.value"
          type="number"
          min="0"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >IP 挑战阈值<input
          v-model.number="controls.ccIpChallengeThreshold.value"
          type="number"
          min="10"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >IP 429 阈值<input
          v-model.number="controls.ccIpBlockThreshold.value"
          type="number"
          min="10"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >主机挑战阈值<input
          v-model.number="controls.ccHostChallengeThreshold.value"
          type="number"
          min="5"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >Host 429 阈值<input
          v-model.number="controls.ccHostBlockThreshold.value"
          type="number"
          min="5"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >路由挑战阈值<input
          v-model.number="controls.ccRouteChallengeThreshold.value"
          type="number"
          min="3"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >路由 429 阈值<input
          v-model.number="controls.ccRouteBlockThreshold.value"
          type="number"
          min="3"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >热点路径挑战阈值<input
          v-model.number="controls.ccHotPathChallengeThreshold.value"
          type="number"
          min="32"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >热点路径 429 阈值<input
          v-model.number="controls.ccHotPathBlockThreshold.value"
          type="number"
          min="32"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >挑战有效期(秒)<input
          v-model.number="controls.ccChallengeTtl.value"
          type="number"
          min="30"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >挑战 Cookie 名称<input
          v-model="controls.ccChallengeCookieName.value"
          type="text"
          placeholder="例如 rwaf_cc"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >硬阈值-路由倍率<input
          v-model.number="controls.ccHardRouteBlockMultiplier.value"
          type="number"
          min="1"
          max="20"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >硬阈值-Host 倍率<input
          v-model.number="controls.ccHardHostBlockMultiplier.value"
          type="number"
          min="1"
          max="20"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >硬阈值-IP 倍率<input
          v-model.number="controls.ccHardIpBlockMultiplier.value"
          type="number"
          min="1"
          max="20"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >硬阈值-热点路径倍率<input
          v-model.number="controls.ccHardHotPathBlockMultiplier.value"
          type="number"
          min="1"
          max="20"
          :class="numberInputClass"
      /></label>
    </div>
  </div>
</template>

<style scoped>
.l7-inline-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}

.l7-inline-field :deep(input),
.l7-inline-field :deep(select),
.l7-inline-field :deep(.numberInputClass) {
  width: 5rem;
  margin-top: 0 !important;
  border-radius: 0.375rem;
  border: 1px solid rgb(203 213 225);
  background: transparent;
  padding: 0.25rem 0.5rem;
  box-shadow: none;
  text-align: center;
  transition: border-color 0.2s ease;
}

.l7-inline-field :deep(input[type='text']) {
  width: 10rem;
  text-align: left;
}

.l7-inline-field :deep(input[type='number']::-webkit-outer-spin-button),
.l7-inline-field :deep(input[type='number']::-webkit-inner-spin-button) {
  -webkit-appearance: none;
  margin: 0;
}

.l7-inline-field :deep(input[type='number']) {
  -moz-appearance: textfield;
  appearance: textfield;
}

.l7-inline-field :deep(input:focus),
.l7-inline-field :deep(select:focus) {
  border-color: rgba(59, 130, 246, 0.65);
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
