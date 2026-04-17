<script setup lang="ts">
import { ArrowRight, Network, Shield, ShieldBan, Zap } from 'lucide-vue-next'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { FlowNode } from '@/features/rules/composables/useAdminSiteActionFlow'
import type { LocalSiteItem } from '@/shared/types'

defineProps<{
  activeNode: FlowNode
  currentSummary: {
    response: string
    template: string
    extra: string
  }
  pendingSummary: string
  site: LocalSiteItem
}>()

const emit = defineEmits<{
  'update:activeNode': [value: FlowNode]
}>()

function activate(node: FlowNode) {
  emit('update:activeNode', node)
}
</script>

<template>
  <section
    class="rounded-[28px] border border-white/80 bg-white/72 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]"
  >
    <div class="flex items-center justify-between gap-3">
      <div>
        <p class="text-sm font-semibold text-slate-900">网络流程图</p>
        <p class="mt-1 text-xs leading-6 text-slate-500">
          点击节点即可调整配置，后续加新功能时也可以直接新增节点。
        </p>
      </div>
      <StatusBadge :text="pendingSummary" type="info" />
    </div>

    <div class="mt-5 overflow-x-auto">
      <div class="min-w-[760px]">
        <div
          class="grid gap-4 md:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr] md:items-center"
        >
          <button
            class="rounded-[24px] border px-4 py-4 text-left transition"
            :class="
              activeNode === 'entry'
                ? 'border-sky-400 bg-sky-50 shadow-[0_12px_30px_rgba(14,165,233,0.18)]'
                : 'border-slate-200 bg-white/85 hover:border-sky-300'
            "
            @click="activate('entry')"
          >
            <div class="flex items-center gap-3">
              <div class="rounded-2xl bg-slate-900 p-3 text-white">
                <Network :size="18" />
              </div>
              <div>
                <p class="text-xs uppercase tracking-[0.2em] text-slate-400">
                  入口
                </p>
                <p class="mt-1 font-semibold text-slate-900">请求命中站点</p>
              </div>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-600">
              用户请求进入当前站点匹配流程，主域名为
              {{ site.primary_hostname }}。
            </p>
          </button>

          <div class="flex justify-center text-slate-300">
            <ArrowRight :size="28" />
          </div>

          <button
            class="rounded-[24px] border px-4 py-4 text-left transition"
            :class="
              activeNode === 'decision'
                ? 'border-sky-400 bg-sky-50 shadow-[0_12px_30px_rgba(14,165,233,0.18)]'
                : 'border-slate-200 bg-white/85 hover:border-sky-300'
            "
            @click="activate('decision')"
          >
            <div class="flex items-center gap-3">
              <div class="rounded-2xl bg-amber-500 p-3 text-white">
                <Shield :size="18" />
              </div>
              <div>
                <p class="text-xs uppercase tracking-[0.2em] text-slate-400">
                  判定
                </p>
                <p class="mt-1 font-semibold text-slate-900">雷池拦截决策</p>
              </div>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-600">
              放行则正常回源；只有拦截命中后，才会进入下面的 rust 接管动作。
            </p>
          </button>

          <div class="flex justify-center text-slate-300">
            <ArrowRight :size="28" />
          </div>

          <button
            class="rounded-[24px] border px-4 py-4 text-left transition"
            :class="
              activeNode === 'response'
                ? 'border-indigo-400 bg-indigo-50 shadow-[0_12px_30px_rgba(99,102,241,0.18)]'
                : 'border-slate-200 bg-white/85 hover:border-indigo-300'
            "
            @click="activate('response')"
          >
            <div class="flex items-center gap-3">
              <div class="rounded-2xl bg-indigo-600 p-3 text-white">
                <Zap :size="18" />
              </div>
              <div>
                <p class="text-xs uppercase tracking-[0.2em] text-slate-400">
                  主动作
                </p>
                <p class="mt-1 font-semibold text-slate-900">响应动作</p>
              </div>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-600">
              当前待生效方案：{{ pendingSummary }}。
            </p>
          </button>

          <div class="flex justify-center text-slate-300">
            <ArrowRight :size="28" />
          </div>

          <button
            class="rounded-[24px] border px-4 py-4 text-left transition"
            :class="
              activeNode === 'extras'
                ? 'border-rose-400 bg-rose-50 shadow-[0_12px_30px_rgba(244,63,94,0.18)]'
                : 'border-slate-200 bg-white/85 hover:border-rose-300'
            "
            @click="activate('extras')"
          >
            <div class="flex items-center gap-3">
              <div class="rounded-2xl bg-rose-600 p-3 text-white">
                <ShieldBan :size="18" />
              </div>
              <div>
                <p class="text-xs uppercase tracking-[0.2em] text-slate-400">
                  附加动作
                </p>
                <p class="mt-1 font-semibold text-slate-900">扩展能力</p>
              </div>
            </div>
            <p class="mt-3 text-sm leading-6 text-slate-600">
              先保留“封禁来源 IP”作为独立开关，后续可继续加
              webhook、标签、事件等。
            </p>
          </button>
        </div>
      </div>
    </div>

    <div class="mt-5 grid gap-4 lg:grid-cols-2">
      <div class="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p class="text-sm font-semibold text-slate-900">当前生效配置</p>
        <div class="mt-3 space-y-3 text-sm text-slate-600">
          <div>
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">
              响应动作
            </p>
            <p class="mt-1 text-slate-900">{{ currentSummary.response }}</p>
          </div>
          <div>
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">
              模板来源
            </p>
            <p class="mt-1 text-slate-900">{{ currentSummary.template }}</p>
          </div>
          <div>
            <p class="text-xs uppercase tracking-[0.16em] text-slate-400">
              附加动作
            </p>
            <p class="mt-1 text-slate-900">{{ currentSummary.extra }}</p>
          </div>
        </div>
      </div>

      <div
        class="rounded-2xl border border-slate-200 bg-slate-900 p-4 text-slate-100"
      >
        <p class="text-sm font-semibold">保存后将生效</p>
        <p class="mt-3 text-lg font-semibold">{{ pendingSummary }}</p>
        <p class="mt-2 text-sm leading-6 text-slate-300">
          作用范围仅限当前站点，不会影响其他站点和全局默认配置。
        </p>
      </div>
    </div>
  </section>
</template>
