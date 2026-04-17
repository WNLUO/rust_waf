<script setup lang="ts">
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type {
  AiAuditReportHistoryItem,
  AiAuditReportResponse,
} from '@/shared/types'

interface ComparisonSummary {
  baseline: AiAuditReportHistoryItem
  riskDirection: string
  findingsDelta: number
  recommendationsDelta: number
  sampledEventsDelta: number
  identityPressureDelta: number
  l7FrictionDelta: number
  slowAttackDelta: number
  newFindingTitles: string[]
  clearedFindingTitles: string[]
}

defineProps<{
  report: AiAuditReportResponse | null
  riskBadgeType: 'error' | 'warning' | 'success' | 'muted'
  providerStatusText: string
  cachedReportLabel: string
  comparisonSummary: ComparisonSummary | null
  formatNumber: (value?: number) => string
  formatTimestamp: (value?: number) => string
  riskLevelLabel: (value: string | null | undefined) => string
  analysisModeLabel: (value: string | null | undefined) => string
  inputSourceLabel: (value: string | null | undefined) => string
  formatCountItems: (
    items: Array<{ key: string; count: number }>,
    limit?: number,
  ) => string
  describeAutoTriggerReason: (value: string | null | undefined) => string
}>()
</script>

<template>
  <div class="rounded-2xl border border-slate-200 bg-white p-4">
    <div class="flex flex-wrap items-center gap-2">
      <StatusBadge
        :type="riskBadgeType"
        :text="
          report ? `风险 ${riskLevelLabel(report.risk_level)}` : '尚未执行'
        "
      />
      <StatusBadge type="muted" :text="providerStatusText" />
      <StatusBadge type="muted" :text="cachedReportLabel" />
      <StatusBadge
        v-if="report?.summary.current.auto_tuning_last_adjust_reason"
        type="info"
        :text="`最近调优 ${report.summary.current.auto_tuning_last_adjust_reason}`"
      />
    </div>

    <div v-if="report" class="mt-4 space-y-4">
      <div>
        <p class="text-sm font-semibold text-slate-900">
          {{ report.headline }}
        </p>
        <p class="mt-1 text-xs text-slate-500">
          生成时间 {{ formatTimestamp(report.generated_at) }} · 采样事件
          {{ formatNumber(report.summary.sampled_events) }} / 总事件
          {{ formatNumber(report.summary.total_events) }}
        </p>
      </div>

      <div
        v-if="report.executive_summary.length"
        class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
      >
        <p
          class="text-xs font-medium uppercase tracking-[0.18em] text-slate-400"
        >
          审计摘要
        </p>
        <ul class="mt-2 space-y-2 text-sm leading-6 text-slate-700">
          <li
            v-for="(item, index) in report.executive_summary"
            :key="`${index}-${item}`"
          >
            {{ item }}
          </li>
        </ul>
      </div>

      <div class="grid gap-3 md:grid-cols-3">
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">身份解析压力</p>
          <p class="mt-1 text-lg font-semibold text-slate-900">
            {{
              formatNumber(report.summary.current.identity_pressure_percent)
            }}%
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">L7 摩擦压力</p>
          <p class="mt-1 text-lg font-semibold text-slate-900">
            {{
              formatNumber(report.summary.current.l7_friction_pressure_percent)
            }}%
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">慢速攻击压力</p>
          <p class="mt-1 text-lg font-semibold text-slate-900">
            {{
              formatNumber(report.summary.current.slow_attack_pressure_percent)
            }}%
          </p>
        </div>
      </div>

      <div class="grid gap-3 md:grid-cols-4">
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">分析模式</p>
          <p class="mt-1 text-sm font-semibold text-slate-900">
            {{ analysisModeLabel(report.analysis_mode) }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">输入来源</p>
          <p class="mt-1 text-sm font-semibold text-slate-900">
            {{ inputSourceLabel(report.input_profile.source) }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">样本事件</p>
          <p class="mt-1 text-sm font-semibold text-slate-900">
            {{ formatNumber(report.input_profile.sampled_events) }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">近期样本透传</p>
          <p class="mt-1 text-sm font-semibold text-slate-900">
            {{ report.input_profile.raw_samples_included ? '已启用' : '关闭' }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p class="text-xs text-slate-400">近期策略反馈</p>
          <p class="mt-1 text-sm font-semibold text-slate-900">
            {{
              formatNumber(report.input_profile.recent_policy_feedback_count)
            }}
          </p>
        </div>
      </div>

      <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
        <div class="flex flex-wrap items-center gap-2">
          <StatusBadge
            type="info"
            :text="`雷池 ${formatNumber(report.summary.safeline_correlation.safeline_events)}`"
          />
          <StatusBadge
            type="muted"
            :text="`Rust WAF ${formatNumber(report.summary.safeline_correlation.rust_events)}`"
          />
          <StatusBadge
            type="warning"
            :text="`共同热点 host ${formatNumber(report.summary.safeline_correlation.overlap_hosts.length)}`"
          />
          <StatusBadge
            type="warning"
            :text="`共同热点 route ${formatNumber(report.summary.safeline_correlation.overlap_routes.length)}`"
          />
          <StatusBadge
            type="error"
            :text="`持续压力 ${formatNumber(report.summary.safeline_correlation.rust_persistence_percent)}%`"
          />
        </div>
        <div class="mt-3 grid gap-3 md:grid-cols-2">
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              雷池热点主机
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.safeline_top_hosts,
                )
              }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              Rust WAF 热点主机
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.rust_top_hosts,
                )
              }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              共同热点主机
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.overlap_hosts,
                )
              }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              共同热点路径
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.overlap_routes,
                )
              }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              未回落主机
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.persistent_overlap_hosts,
                )
              }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              未回落路径
            </p>
            <p class="mt-2 text-sm text-slate-700">
              {{
                formatCountItems(
                  report.summary.safeline_correlation.persistent_overlap_routes,
                )
              }}
            </p>
          </div>
        </div>
      </div>

      <div
        v-if="comparisonSummary"
        class="rounded-2xl border border-cyan-200 bg-[linear-gradient(135deg,rgba(236,254,255,0.98),rgba(248,250,252,0.96))] px-4 py-3"
      >
        <div class="flex flex-wrap items-center gap-2">
          <StatusBadge
            :type="
              comparisonSummary.riskDirection === 'up'
                ? 'error'
                : comparisonSummary.riskDirection === 'down'
                  ? 'success'
                  : 'muted'
            "
            :text="
              comparisonSummary.riskDirection === 'up'
                ? '风险较上次上升'
                : comparisonSummary.riskDirection === 'down'
                  ? '风险较上次下降'
                  : '风险等级与上次持平'
            "
          />
          <StatusBadge
            type="muted"
            :text="`对比基线 ${formatTimestamp(comparisonSummary.baseline.generated_at)}`"
          />
          <StatusBadge
            v-if="comparisonSummary.baseline.auto_generated"
            type="info"
            text="基线为自动触发"
          />
          <StatusBadge
            v-if="comparisonSummary.baseline.auto_trigger_reason"
            type="warning"
            :text="`基线触发 ${describeAutoTriggerReason(comparisonSummary.baseline.auto_trigger_reason)}`"
          />
        </div>
        <div class="mt-3 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">发现变化</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.findingsDelta >= 0 ? '+' : ''
              }}{{ comparisonSummary.findingsDelta }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">建议变化</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.recommendationsDelta >= 0 ? '+' : ''
              }}{{ comparisonSummary.recommendationsDelta }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">采样事件</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.sampledEventsDelta >= 0 ? '+' : ''
              }}{{ comparisonSummary.sampledEventsDelta }}
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">身份压力</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.identityPressureDelta >= 0 ? '+' : ''
              }}{{ formatNumber(comparisonSummary.identityPressureDelta) }}%
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">L7 摩擦</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.l7FrictionDelta >= 0 ? '+' : ''
              }}{{ formatNumber(comparisonSummary.l7FrictionDelta) }}%
            </p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-2">
            <p class="text-xs text-slate-400">慢攻压力</p>
            <p class="mt-1 text-sm font-semibold text-slate-900">
              {{ comparisonSummary.slowAttackDelta >= 0 ? '+' : ''
              }}{{ formatNumber(comparisonSummary.slowAttackDelta) }}%
            </p>
          </div>
        </div>
        <div class="mt-3 grid gap-3 md:grid-cols-2">
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              新出现的发现
            </p>
            <ul
              v-if="comparisonSummary.newFindingTitles.length"
              class="mt-2 space-y-1 text-sm text-slate-700"
            >
              <li
                v-for="item in comparisonSummary.newFindingTitles"
                :key="item"
              >
                {{ item }}
              </li>
            </ul>
            <p v-else class="mt-2 text-sm text-slate-500">没有新增发现。</p>
          </div>
          <div class="rounded-xl border border-white/80 bg-white/80 px-3 py-3">
            <p
              class="text-xs font-medium uppercase tracking-[0.14em] text-slate-400"
            >
              已消失的发现
            </p>
            <ul
              v-if="comparisonSummary.clearedFindingTitles.length"
              class="mt-2 space-y-1 text-sm text-slate-700"
            >
              <li
                v-for="item in comparisonSummary.clearedFindingTitles"
                :key="item"
              >
                {{ item }}
              </li>
            </ul>
            <p v-else class="mt-2 text-sm text-slate-500">没有消失的发现。</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
