<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import type { Ref, WritableComputedRef } from 'vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    http10Enabled: Ref<boolean>
    http10Saving: Ref<boolean>
    http2Enabled: ModelRef<boolean>
    bloomEnabled: ModelRef<boolean>
    bloomVerifyEnabled: ModelRef<boolean>
    healthcheckEnabled: ModelRef<boolean>
    http3Enabled: ModelRef<boolean>
    http2EnablePriorities: ModelRef<boolean>
    runtimeProfile: ModelRef<string>
    failureMode: ModelRef<string>
    upstreamProtocolPolicy: ModelRef<string>
    upstreamHttp1StrictMode: ModelRef<boolean>
    upstreamHttp1AllowConnectionReuse: ModelRef<boolean>
    rejectAmbiguousHttp1Requests: ModelRef<boolean>
    rejectHttp1TransferEncodingRequests: ModelRef<boolean>
    rejectBodyOnSafeHttpMethods: ModelRef<boolean>
    rejectExpect100Continue: ModelRef<boolean>
    handleHttp10Toggle: (nextValue: boolean) => unknown
  }
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
  hideAdaptiveManagedSections?: boolean
  updateDropUnmatchedRequests: (value: boolean) => unknown
}>()
</script>

<template>
  <div
    class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
  >
    <div>
      <p class="text-sm tracking-wider text-blue-700">
        HTTP 配置（独立运行项）
      </p>
    </div>
  </div>

  <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用 HTTP/1.0</span>
      <input
        :checked="controls.http10Enabled.value"
        :disabled="controls.http10Saving.value"
        type="checkbox"
        class="ui-switch"
        @change="
          controls.handleHttp10Toggle(
            ($event.target as HTMLInputElement).checked,
          )
        "
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用 HTTP/2</span>
      <input
        v-model="controls.http2Enabled.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>未命中站点时直接断开连接</span>
      <input
        :checked="dropUnmatchedRequests"
        :disabled="dropUnmatchedRequestsDisabled"
        type="checkbox"
        class="ui-switch"
        @change="
          updateDropUnmatchedRequests(
            ($event.target as HTMLInputElement).checked,
          )
        "
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用 Bloom</span>
      <input
        v-model="controls.bloomEnabled.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用上游健康检查</span>
      <input
        v-model="controls.healthcheckEnabled.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用 Bloom 误判校验</span>
      <input
        v-model="controls.bloomVerifyEnabled.value"
        :disabled="!controls.bloomEnabled.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>启用 HTTP/3</span>
      <input
        v-model="controls.http3Enabled.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
    <label
      class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
    >
      <span>允许使用优先级信息处理 HTTP/2 请求</span>
      <input
        v-model="controls.http2EnablePriorities.value"
        type="checkbox"
        class="ui-switch"
      />
    </label>
  </div>

  <div
    v-if="!hideAdaptiveManagedSections"
    class="mt-4 border-t border-slate-200 pt-4"
  >
    <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
      <label class="text-sm text-stone-700">
        运行档位
        <select
          v-model="controls.runtimeProfile.value"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="minimal">精简模式</option>
          <option value="standard">标准模式</option>
        </select>
      </label>
      <label class="text-sm text-stone-700">
        上游失败模式
        <select
          v-model="controls.failureMode.value"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="fail_open">故障放行</option>
          <option value="fail_close">故障关闭</option>
        </select>
      </label>
      <label class="text-sm text-stone-700">
        上游协议策略
        <select
          v-model="controls.upstreamProtocolPolicy.value"
          class="mt-2 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="http2_preferred">优先 HTTP/2</option>
          <option value="http2_only">仅 HTTP/2</option>
          <option value="auto">自动选择</option>
          <option value="http1_only">仅 HTTP/1.1</option>
        </select>
      </label>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>启用上游 HTTP/1 严格模式</span>
        <input
          v-model="controls.upstreamHttp1StrictMode.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>允许上游 HTTP/1 连接复用</span>
        <input
          v-model="controls.upstreamHttp1AllowConnectionReuse.value"
          :disabled="controls.upstreamHttp1StrictMode.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>拒绝歧义 HTTP/1 请求</span>
        <input
          v-model="controls.rejectAmbiguousHttp1Requests.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>拒绝请求 Transfer-Encoding</span>
        <input
          v-model="controls.rejectHttp1TransferEncodingRequests.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>拒绝 GET/HEAD/OPTIONS 携带 body</span>
        <input
          v-model="controls.rejectBodyOnSafeHttpMethods.value"
          type="checkbox"
          class="ui-switch"
        />
      </label>
      <label
        class="inline-flex items-center justify-start gap-3 text-sm text-stone-800"
      >
        <span>拒绝 Expect: 100-continue</span>
        <input
          v-model="controls.rejectExpect100Continue.value"
          type="checkbox"
          class="ui-switch"
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

.ui-switch:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
