<script setup lang="ts">
import { ServerCog } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'

defineProps<{
  bloomPanels: Array<{
    label: string
    value: {
      filter_size: number
      hash_functions: number
      insert_count: number
      hit_count: number
      hit_rate: number
    }
  }>
  falsePositivePanels: Array<{
    label: string
    value: number
  }>
  formatNumber: (value?: number) => string
  meta: {
    runtime_enabled: boolean
    bloom_enabled: boolean
    bloom_false_positive_verification: boolean
    runtime_profile: string
  }
}>()
</script>

<template>
  <div class="space-y-6">
    <CyberCard
      title="运行摘要"
      sub-title="帮助你快速确认当前实例到底在按什么模式跑。"
    >
      <div class="space-y-4 text-sm text-stone-700">
        <div class="rounded-xl border border-slate-200 p-4">
          <div class="flex items-center justify-between gap-4">
            <div>
              <p class="text-xs tracking-wide text-slate-500">当前运行状态</p>
              <p class="mt-2 text-lg font-semibold text-stone-900">
                {{
                  meta.runtime_enabled
                    ? 'L4 检测实例已加载'
                    : 'L4 检测实例未加载'
                }}
              </p>
            </div>
            <ServerCog class="text-blue-700" :size="22" />
          </div>
          <p class="mt-3 leading-6 text-slate-500">
            运行时统计来自内存中的 L4
            Inspector，保存配置后如果不重启，这里的统计仍然对应旧参数。
          </p>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">运行档位</p>
            <p class="mt-2 text-lg font-semibold text-stone-900">
              {{ meta.runtime_profile === 'standard' ? 'standard' : 'minimal' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">Bloom 状态</p>
            <p class="mt-2 text-lg font-semibold text-stone-900">
              {{ meta.bloom_enabled ? '已启用' : '未启用' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">误判校验</p>
            <p class="mt-2 text-lg font-semibold text-stone-900">
              {{ meta.bloom_false_positive_verification ? '开启' : '关闭' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">配置生效方式</p>
            <p class="mt-2 text-lg font-semibold text-stone-900">保存后重启</p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="Bloom 摘要"
      sub-title="如果四层 Bloom 已启用，这里能直接看到三个过滤器的命中概览。"
    >
      <div v-if="bloomPanels.length" class="space-y-4">
        <div
          v-for="item in bloomPanels"
          :key="item.label"
          class="rounded-xl border border-slate-200 bg-slate-50 p-4"
        >
          <div class="flex items-center justify-between gap-4">
            <p class="text-sm font-medium text-stone-900">
              {{ item.label }}
            </p>
            <StatusBadge
              :text="`${(item.value.hit_rate * 100).toFixed(2)}%`"
              type="info"
              compact
            />
          </div>
          <div class="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-500">
            <p>过滤器大小：{{ formatNumber(item.value.filter_size) }}</p>
            <p>哈希函数：{{ formatNumber(item.value.hash_functions) }}</p>
            <p>插入次数：{{ formatNumber(item.value.insert_count) }}</p>
            <p>命中次数：{{ formatNumber(item.value.hit_count) }}</p>
          </div>
        </div>
      </div>
      <div
        v-else
        class="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-500"
      >
        当前没有可展示的 Bloom 运行统计。通常是因为运行中的 L4 实例未启用
        Bloom，或四层检测尚未加载。
      </div>
    </CyberCard>

    <CyberCard
      title="误判校验"
      sub-title="后端已经返回精确校验统计，这里补上展示，方便判断 Bloom 校验成本。"
    >
      <div v-if="falsePositivePanels.length" class="space-y-4">
        <div
          v-for="item in falsePositivePanels"
          :key="item.label"
          class="rounded-xl border border-slate-200 bg-slate-50 p-4"
        >
          <div class="flex items-center justify-between gap-4">
            <p class="text-sm font-medium text-stone-900">
              {{ item.label }}
            </p>
            <StatusBadge
              :text="
                meta.bloom_false_positive_verification ? '校验开启' : '校验关闭'
              "
              :type="
                meta.bloom_false_positive_verification ? 'success' : 'muted'
              "
              compact
            />
          </div>
          <p class="mt-3 text-2xl font-semibold text-stone-900">
            {{ formatNumber(item.value) }}
          </p>
          <p class="mt-2 text-xs leading-6 text-slate-500">
            表示当前运行态里为了降低 Bloom 误判而维护的精确集合大小。
          </p>
        </div>
      </div>
      <div
        v-else
        class="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-500"
      >
        当前没有误判校验统计。通常意味着 Bloom
        未启用，或者运行实例还没有积累到可展示的校验数据。
      </div>
    </CyberCard>
  </div>
</template>
