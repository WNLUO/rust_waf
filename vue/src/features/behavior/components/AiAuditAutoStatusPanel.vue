<script setup lang="ts">
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { AiAutoAuditStatus } from '@/shared/types'

defineProps<{
  autoAuditStatus: AiAutoAuditStatus | null
  autoAuditStatusText: string
  autoAuditTriggerFlags: string[]
  formatNumber: (value?: number) => string
  formatTimestamp: (value?: number) => string
  truncateMiddle: (value: string | null | undefined, head?: number, tail?: number) => string
  describeAutoTriggerReason: (value: string | null | undefined) => string
}>()
</script>

<template>
        <div class="rounded-2xl border border-slate-200 bg-white p-4">
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="autoAuditStatus?.enabled ? 'info' : 'muted'"
              :text="
                autoAuditStatus?.enabled ? '自动审计已启用' : '自动审计未启用'
              "
            />
            <StatusBadge type="muted" :text="autoAuditStatusText" />
            <StatusBadge
              v-if="autoAuditStatus?.last_trigger_reason"
              type="warning"
              :text="`最近触发 ${describeAutoTriggerReason(autoAuditStatus.last_trigger_reason)}`"
            />
          </div>
          <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div
              class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <p class="text-xs text-slate-400">调度参数</p>
              <p class="mt-1 text-sm font-semibold text-slate-900">
                间隔 {{ formatNumber(autoAuditStatus?.interval_secs ?? 0) }} 秒
              </p>
              <p class="mt-1 text-xs text-slate-500">
                冷却 {{ formatNumber(autoAuditStatus?.cooldown_secs ?? 0) }} 秒
              </p>
            </div>
            <div
              class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <p class="text-xs text-slate-400">触发条件</p>
              <p class="mt-1 text-sm font-semibold text-slate-900">
                {{
                  autoAuditTriggerFlags.length
                    ? autoAuditTriggerFlags.join(' / ')
                    : '暂无'
                }}
              </p>
              <p class="mt-1 text-xs text-slate-500">
                {{
                  autoAuditStatus?.force_local_rules_under_attack
                    ? '攻击模式下会强制回退本地规则'
                    : '攻击模式下保持当前服务商'
                }}
              </p>
            </div>
            <div
              class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <p class="text-xs text-slate-400">最近运行</p>
              <p class="mt-1 text-sm font-semibold text-slate-900">
                {{
                  autoAuditStatus?.last_run_at
                    ? formatTimestamp(autoAuditStatus.last_run_at)
                    : '暂无'
                }}
              </p>
              <p class="mt-1 text-xs text-slate-500">
                最近完成
                {{
                  autoAuditStatus?.last_completed_at
                    ? formatTimestamp(autoAuditStatus.last_completed_at)
                    : '暂无'
                }}
              </p>
            </div>
            <div
              class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <p class="text-xs text-slate-400">最近结果</p>
              <p class="mt-1 text-sm font-semibold text-slate-900">
                {{
                  autoAuditStatus?.last_report_id
                    ? `报告 #${autoAuditStatus.last_report_id}`
                    : '暂无'
                }}
              </p>
              <p class="mt-1 text-xs text-slate-500">
                签名
                {{
                  truncateMiddle(
                    autoAuditStatus?.last_trigger_signature ??
                      autoAuditStatus?.last_observed_signature,
                  )
                }}
              </p>
            </div>
          </div>
        </div>
</template>
