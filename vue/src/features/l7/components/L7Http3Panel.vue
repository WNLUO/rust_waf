<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import type { Ref, WritableComputedRef } from 'vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    http3ConnectionMigration: ModelRef<boolean>
    http3Tls13Enabled: ModelRef<boolean>
    http3MaxStreams: ModelRef<number>
    http3IdleTimeout: ModelRef<number>
    http3Mtu: ModelRef<number>
    http3MaxFrameSize: ModelRef<number>
    http3QpackTableSize: ModelRef<number>
    http3CertificatePath: ModelRef<string>
    http3PrivateKeyPath: ModelRef<string>
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
          HTTP/3 配置（独立运行项）
        </p>
      </div>
      <div class="flex flex-wrap gap-3">
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
        >
          <span>连接迁移支持</span>
          <input
            v-model="controls.http3ConnectionMigration.value"
            type="checkbox"
            class="ui-switch"
          />
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
        >
          <span>TLS 1.3</span>
          <input
            v-model="controls.http3Tls13Enabled.value"
            type="checkbox"
            class="ui-switch"
          />
        </label>
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
      <label class="l7-inline-field text-sm text-stone-700"
        >最大并发流<input
          v-model.number="controls.http3MaxStreams.value"
          type="number"
          min="1"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >空闲超时(s)<input
          v-model.number="controls.http3IdleTimeout.value"
          type="number"
          min="1"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >MTU<input
          v-model.number="controls.http3Mtu.value"
          type="number"
          min="1200"
          max="1500"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >最大帧大小<input
          v-model.number="controls.http3MaxFrameSize.value"
          type="number"
          min="65536"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700"
        >QPACK 表大小<input
          v-model.number="controls.http3QpackTableSize.value"
          type="number"
          min="1024"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
        >证书路径<input
          v-model="controls.http3CertificatePath.value"
          type="text"
          placeholder="例如 /path/to/cert.pem"
          :class="numberInputClass"
      /></label>
      <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
        >私钥路径<input
          v-model="controls.http3PrivateKeyPath.value"
          type="text"
          placeholder="例如 /path/to/key.pem"
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
