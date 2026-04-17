<script setup lang="ts">
import type { Ref, WritableComputedRef } from 'vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    maxRequestSize: ModelRef<number>
    firstByteTimeout: ModelRef<number>
    readIdleTimeout: ModelRef<number>
    tlsHandshakeTimeout: ModelRef<number>
    proxyConnectTimeout: ModelRef<number>
    proxyWriteTimeout: ModelRef<number>
    proxyReadTimeout: ModelRef<number>
    bloomFilterScale: ModelRef<number>
    healthcheckInterval: ModelRef<number>
    healthcheckTimeout: ModelRef<number>
    http2MaxStreams: ModelRef<number>
    http2MaxFrameSize: ModelRef<number>
    http2InitialWindowSize: ModelRef<number>
  }
  numberInputClass: string
}>()
</script>

<template>
    <div class="mt-4 border-t border-slate-200 pt-4">
      <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700"
          >最大请求体大小<input
            v-model.number="controls.maxRequestSize.value"
            type="number"
            min="1024"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >首字节超时(ms)<input
            v-model.number="controls.firstByteTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >空闲读取超时(ms)<input
            v-model.number="controls.readIdleTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >TLS 握手超时(ms)<input
            v-model.number="controls.tlsHandshakeTimeout.value"
            type="number"
            min="500"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >代理连接超时(ms)<input
            v-model.number="controls.proxyConnectTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >代理写超时(ms)<input
            v-model.number="controls.proxyWriteTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >代理读超时(ms)<input
            v-model.number="controls.proxyReadTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >Bloom 缩放系数<input
            v-model.number="controls.bloomFilterScale.value"
            type="number"
            min="0.1"
            step="0.1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >健康检查间隔(s)<input
            v-model.number="controls.healthcheckInterval.value"
            type="number"
            min="1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >健康检查超时(ms)<input
            v-model.number="controls.healthcheckTimeout.value"
            type="number"
            min="100"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >HTTP/2 最大并发流<input
            v-model.number="controls.http2MaxStreams.value"
            type="number"
            min="1"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >HTTP/2 最大帧<input
            v-model.number="controls.http2MaxFrameSize.value"
            type="number"
            min="1024"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
          >HTTP/2 初始窗口<input
            v-model.number="controls.http2InitialWindowSize.value"
            type="number"
            min="1024"
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
</style>
