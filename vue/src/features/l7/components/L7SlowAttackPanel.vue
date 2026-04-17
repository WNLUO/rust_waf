<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import type { Ref, WritableComputedRef } from 'vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    slowAttackDefenseEnabled: ModelRef<boolean>
    slowAttackHeaderMinRate: ModelRef<number>
    slowAttackBodyMinRate: ModelRef<number>
    slowAttackIdleKeepaliveTimeout: ModelRef<number>
    slowAttackEventWindow: ModelRef<number>
    slowAttackMaxEvents: ModelRef<number>
    slowAttackBlockDuration: ModelRef<number>
  }
  numberInputClass: string
}>()
</script>

<template>
  <div class="mt-4 border-t border-slate-200 pt-4">
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm tracking-wider text-blue-700">
          慢速攻击防护（独立运行项）
        </p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          覆盖慢速 header、慢速 body 和 idle keep-alive
          占坑，命中后自动断连、记事件，并在窗口内升级封禁。
        </p>
      </div>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用慢速攻击防护</span>
        <input
          v-model="controls.slowAttackDefenseEnabled.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
    </div>

    <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      <label class="text-sm text-stone-700">
        Header 最低速率(B/s)
        <input
          v-model.number="controls.slowAttackHeaderMinRate.value"
          type="number"
          min="1"
          :class="numberInputClass"
        />
      </label>
      <label class="text-sm text-stone-700">
        Body 最低速率(B/s)
        <input
          v-model.number="controls.slowAttackBodyMinRate.value"
          type="number"
          min="1"
          :class="numberInputClass"
        />
      </label>
      <label class="text-sm text-stone-700">
        Keep-Alive 空闲超时(ms)
        <input
          v-model.number="controls.slowAttackIdleKeepaliveTimeout.value"
          type="number"
          min="100"
          :class="numberInputClass"
        />
      </label>
      <label class="text-sm text-stone-700">
        统计窗口(s)
        <input
          v-model.number="controls.slowAttackEventWindow.value"
          type="number"
          min="10"
          :class="numberInputClass"
        />
      </label>
      <label class="text-sm text-stone-700">
        窗口升级阈值
        <input
          v-model.number="controls.slowAttackMaxEvents.value"
          type="number"
          min="1"
          :class="numberInputClass"
        />
      </label>
      <label class="text-sm text-stone-700">
        升级封禁时长(s)
        <input
          v-model.number="controls.slowAttackBlockDuration.value"
          type="number"
          min="30"
          :class="numberInputClass"
        />
      </label>
    </div>
  </div>
</template>

<style scoped>
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
