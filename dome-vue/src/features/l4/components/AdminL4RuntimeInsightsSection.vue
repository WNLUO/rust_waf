<script setup lang="ts">
import { ServerCog } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'
import type { L4StatsPayload } from '@/shared/types'

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
  formatBytes: (value?: number) => string
  meta: {
    runtime_enabled: boolean
    bloom_enabled: boolean
    bloom_false_positive_verification: boolean
    runtime_profile: string
    adaptive_managed_fields: boolean
    adaptive_runtime: import('@/shared/types').AdaptiveProtectionRuntimePayload | null
  }
  configForm: L4ConfigForm
  stats: L4StatsPayload | null
  topPorts: L4StatsPayload['per_port_stats']
  totalProcessedBytes: number
  blockedCapacityLabel: string
  blockedCapacityTone: 'success' | 'warning' | 'error'
}>()

const hasMeasuredPortBytes = (items: L4StatsPayload['per_port_stats']) =>
  items.some((item) => item.bytes_processed > 0)
</script>

<template>
  <div class="space-y-6">
    <section class="grid grid-cols-1 gap-4 xl:grid-cols-3">
    <CyberCard
      title="运行摘要"
      sub-title="帮助你快速确认当前实例到底在按什么模式跑。"
    >
      <div class="space-y-4 text-sm text-stone-700">
        <div
          v-if="meta.adaptive_managed_fields && meta.adaptive_runtime"
          class="rounded-xl border border-emerald-200 bg-emerald-50/80 p-4"
        >
          <p class="text-xs tracking-wide text-emerald-700">自适应接管中</p>
          <p class="mt-2 text-sm leading-6 text-stone-700">
            当前运行态会自动调整连接预算和延迟策略。下面展示的数字是运行时实际生效值，不建议再把它们当作手工阈值维护。
          </p>
          <div class="mt-3 grid gap-3 sm:grid-cols-3 text-xs text-stone-700">
            <p>常规预算：{{ formatNumber(meta.adaptive_runtime.l4.normal_connection_budget_per_minute) }}</p>
            <p>延迟处置：{{ formatNumber(meta.adaptive_runtime.l4.soft_delay_ms) }}ms</p>
            <p>系统压力：{{ meta.adaptive_runtime.system_pressure }}</p>
          </div>
        </div>
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
            Inspector，保存配置后后端会立即刷新运行参数，这里的统计会切换到新实例。
          </p>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">运行档位</p>
            <p class="mt-2 text-lg font-semibold text-stone-900">
              {{ meta.runtime_profile === 'standard' ? '标准模式' : '精简模式' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 p-4">
            <p class="text-xs tracking-wide text-slate-500">布隆过滤器状态</p>
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
            <p class="mt-2 text-lg font-semibold text-stone-900">保存后立即刷新</p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="布隆过滤器摘要"
      sub-title="如果四层布隆过滤器已启用，这里能直接看到三个过滤器的命中概览。"
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
        当前没有可展示的布隆过滤器运行统计。通常是因为运行中的 L4 实例未启用
        布隆过滤器，或四层检测尚未加载。
      </div>
    </CyberCard>

    <CyberCard
      title="误判校验"
      sub-title="后端已经返回精确校验统计，这里补上展示，方便判断布隆过滤器校验成本。"
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
            表示当前运行态里为了降低布隆过滤器误判而维护的精确集合大小。
          </p>
        </div>
      </div>
      <div
        v-else
        class="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-500"
      >
        当前没有误判校验统计。通常意味着布隆过滤器
        未启用，或者运行实例还没有积累到可展示的校验数据。
      </div>
    </CyberCard>
    </section>

    <section class="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <CyberCard
        :title="meta.adaptive_managed_fields ? '当前生效阈值' : '限流阈值'"
        :sub-title="
          meta.adaptive_managed_fields
            ? '这些数值由自适应控制器产出，并反映当前运行态。'
            : '用于快速复核当前保存的关键阈值。'
        "
      >
        <div class="space-y-3 text-sm text-stone-700">
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>每秒连接阈值</span>
            <span class="font-mono font-semibold text-stone-900">{{
              formatNumber(configForm.connection_rate_limit)
            }}</span>
          </div>
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>突发判定阈值</span>
            <span class="font-mono font-semibold text-stone-900">{{
              formatNumber(configForm.syn_flood_threshold)
            }}</span>
          </div>
        </div>
      </CyberCard>

      <CyberCard title="容量上限" sub-title="帮助判断跟踪表和封禁表的容量预估。">
        <div class="space-y-3 text-sm text-stone-700">
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>跟踪 IP 上限</span>
            <span class="font-mono font-semibold text-stone-900">{{
              formatNumber(configForm.max_tracked_ips)
            }}</span>
          </div>
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>封禁表上限</span>
            <span class="font-mono font-semibold text-stone-900">{{
              formatNumber(configForm.max_blocked_ips)
            }}</span>
          </div>
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>当前封禁占用</span>
            <div class="flex items-center gap-2">
              <span class="font-mono font-semibold text-stone-900">
                {{ formatNumber(stats?.connections.blocked_connections || 0) }}
                / {{ formatNumber(configForm.max_blocked_ips) }}
              </span>
              <StatusBadge
                :text="blockedCapacityLabel"
                :type="blockedCapacityTone"
                compact
              />
            </div>
          </div>
        </div>
      </CyberCard>

      <CyberCard title="清理策略" sub-title="维护任务会按这个 TTL 回收过期状态。">
        <div class="space-y-3 text-sm text-stone-700">
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>状态 TTL</span>
            <span class="font-mono font-semibold text-stone-900"
              >{{ formatNumber(configForm.state_ttl_secs) }} 秒</span
            >
          </div>
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>Bloom 缩放</span>
            <span class="font-mono font-semibold text-stone-900">{{
              configForm.bloom_filter_scale.toFixed(2)
            }}</span>
          </div>
          <div
            class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
          >
            <span>端口画像累计流量</span>
            <span
              v-if="hasMeasuredPortBytes(topPorts)"
              class="font-mono font-semibold text-stone-900"
            >
              {{ formatBytes(totalProcessedBytes) }}
            </span>
            <span v-else class="text-xs text-slate-500">
              当前后端尚未累计该指标
            </span>
          </div>
        </div>
      </CyberCard>
    </section>
  </div>
</template>
