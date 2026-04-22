<script setup lang="ts">
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { AiAuditReportResponse, AiTempPolicyItem } from '@/shared/types'

defineProps<{
  report: AiAuditReportResponse
  activePolicies: AiTempPolicyItem[]
  policiesLoading: boolean
  revokingPolicyId: number | null
  formatNumber: (value?: number) => string
  formatTimestamp: (value?: number) => string
  riskLevelLabel: (value: string | null | undefined) => string
  priorityLabel: (value: string | null | undefined) => string
  actionTypeLabel: (value: string | null | undefined) => string
  formatPolicyEffectMap: (values: Record<string, number>, limit?: number) => string
  formatDelta: (value: number | null, suffix?: string) => string
  revokePolicy: (id: number) => unknown
}>()
</script>

<template>
      <section class="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
        <div class="space-y-4">
          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">发现的问题</p>
            <div
              v-if="!report.findings.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有新增发现。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="finding in report.findings"
                :key="finding.key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="
                      finding.severity === 'high' ||
                      finding.severity === 'critical'
                        ? 'error'
                        : finding.severity === 'medium'
                          ? 'warning'
                          : 'muted'
                    "
                    :text="riskLevelLabel(finding.severity)"
                  />
                  <span class="text-sm font-semibold text-slate-900">{{
                    finding.title
                  }}</span>
                </div>
                <p class="mt-2 text-sm leading-6 text-slate-700">
                  {{ finding.detail }}
                </p>
                <ul
                  v-if="finding.evidence.length"
                  class="mt-2 space-y-1 text-xs leading-5 text-slate-500"
                >
                  <li
                    v-for="(item, index) in finding.evidence"
                    :key="`${finding.key}-${index}`"
                  >
                    {{ item }}
                  </li>
                </ul>
              </article>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">建议动作</p>
            <div
              v-if="!report.recommendations.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有新增建议。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="recommendation in report.recommendations"
                :key="recommendation.key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="
                      recommendation.priority === 'high' ||
                      recommendation.priority === 'urgent'
                        ? 'warning'
                        : 'info'
                    "
                    :text="priorityLabel(recommendation.priority)"
                  />
                  <StatusBadge
                    type="muted"
                    :text="actionTypeLabel(recommendation.action_type)"
                  />
                  <span class="text-sm font-semibold text-slate-900">{{
                    recommendation.title
                  }}</span>
                </div>
                <p class="mt-2 text-sm leading-6 text-slate-700">
                  {{ recommendation.action }}
                </p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  {{ recommendation.rationale }}
                </p>
              </article>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">专项临时策略候选</p>
            <div
              v-if="!report.suggested_local_rules.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有新增专项策略候选。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="rule in report.suggested_local_rules"
                :key="rule.key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="rule.auto_apply ? 'warning' : 'muted'"
                    :text="rule.action"
                  />
                  <StatusBadge
                    type="muted"
                    :text="`${rule.scope_type}:${rule.scope_value}`"
                  />
                  <StatusBadge type="muted" :text="`${rule.ttl_secs}s`" />
                </div>
                <p class="mt-2 text-sm font-semibold text-slate-900">
                  {{ rule.title }}
                </p>
                <p class="mt-1 text-sm text-slate-700">
                  {{ rule.operator }} {{ rule.suggested_value }} ·
                  {{ rule.rationale }}
                </p>
              </article>
            </div>
          </div>
        </div>

        <div class="space-y-4">
          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">最近策略反馈</p>
            <div
              v-if="!report.summary.recent_policy_feedback.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有可供回灌的策略反馈。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="item in report.summary.recent_policy_feedback"
                :key="item.policy_key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge type="muted" :text="item.action" />
                  <StatusBadge type="info" :text="item.action_status" />
                  <StatusBadge
                    type="muted"
                    :text="`${item.scope_type}:${item.scope_value}`"
                  />
                </div>
                <p class="mt-2 text-sm font-semibold text-slate-900">
                  {{ item.title }}
                </p>
                <p class="mt-1 text-sm text-slate-700">
                  {{ item.action_reason }}
                </p>
                <p class="mt-1 text-[11px] text-slate-500">
                  {{
                    item.primary_object
                      ? `主要对象 ${item.primary_object} · ${formatNumber(item.primary_object_hits)} 次`
                      : '暂无主要对象'
                  }}
                  · 命中 {{ formatNumber(item.hit_count) }} ·
                  {{ formatTimestamp(item.updated_at) }}
                </p>
              </article>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">执行说明</p>
            <div
              v-if="!report.execution_notes.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有额外执行说明。
            </div>
            <ul v-else class="mt-3 space-y-2 text-sm leading-6 text-slate-700">
              <li
                v-for="(note, index) in report.execution_notes"
                :key="`${index}-${note}`"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2"
              >
                {{ note }}
              </li>
            </ul>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">近期审计样本</p>
            <div
              v-if="!report.summary.recent_events.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前窗口没有近期样本。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="event in report.summary.recent_events.slice(0, 5)"
                :key="event.id"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge type="muted" :text="event.layer" />
                  <StatusBadge
                    v-if="event.decision_summary?.primary_signal"
                    type="info"
                    :text="event.decision_summary.primary_signal"
                  />
                </div>
                <p class="mt-2 text-sm font-medium text-slate-900">
                  {{ event.reason }}
                </p>
                <p class="mt-1 text-xs text-slate-500">
                  {{ event.source_ip }} · {{ event.uri || '-' }} ·
                  {{ formatTimestamp(event.created_at) }}
                </p>
              </article>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <div class="flex items-center justify-between gap-3">
              <p class="text-sm font-semibold text-slate-900">
                当前生效的 AI 临时策略
              </p>
              <StatusBadge
                type="muted"
                :text="`活跃 ${formatNumber(activePolicies.length)}`"
              />
            </div>
            <div v-if="policiesLoading" class="mt-3 text-sm text-slate-500">
              正在加载临时策略...
            </div>
            <div
              v-else-if="!activePolicies.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前没有生效中的 AI 临时策略。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="policy in activePolicies"
                :key="policy.id"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div
                  class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
                >
                  <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                      <StatusBadge
                        :type="
                          policy.action === 'add_temp_block'
                            ? 'error'
                            : 'warning'
                        "
                        :text="policy.action"
                      />
                      <StatusBadge
                        type="muted"
                        :text="`${policy.scope_type}:${policy.scope_value}`"
                      />
                    </div>
                    <p class="mt-2 text-sm font-semibold text-slate-900">
                      {{ policy.title }}
                    </p>
                    <p class="mt-1 text-xs text-slate-500">
                      命中 {{ formatNumber(policy.hit_count) }} · 到期
                      {{ formatTimestamp(policy.expires_at) }}
                    </p>
                    <p class="mt-1 text-sm text-slate-700">
                      {{ policy.rationale }}
                    </p>
                    <p class="mt-1 text-[11px] text-slate-500">
                      自动治理
                      {{
                        policy.effect.auto_revoked
                          ? `已撤销（${policy.effect.auto_revoke_reason || '未知原因'}）`
                          : `已续期 ${formatNumber(policy.effect.auto_extensions)} 次`
                      }}
                      ·
                      {{
                        policy.effect.last_effectiveness_check_at
                          ? `最近评估 ${formatTimestamp(policy.effect.last_effectiveness_check_at)}`
                          : '尚未评估'
                      }}
                    </p>
                    <p class="mt-1 text-[11px] text-slate-500">
                      动作评估 {{ policy.effectiveness.action_status }} ·
                      {{ policy.effectiveness.action_reason }}
                    </p>
                    <p class="mt-1 text-[11px] text-slate-500">
                      主要作用对象
                      {{
                        policy.effectiveness.primary_object
                          ? `${policy.effectiveness.primary_object} · ${formatNumber(policy.effectiveness.primary_object_hits)} 次`
                          : '暂无'
                      }}
                    </p>
                    <div class="mt-3 grid gap-2 md:grid-cols-2">
                      <div
                        class="rounded-xl border border-slate-200 bg-white/80 px-3 py-2"
                      >
                        <p
                          class="text-[11px] uppercase tracking-[0.14em] text-slate-400"
                        >
                          最近命中
                        </p>
                        <p class="mt-1 text-xs text-slate-600">
                          {{ policy.effect.last_match_mode || '未知' }} ·
                          {{
                            policy.effect.last_matched_value ||
                            policy.effect.last_scope_value ||
                            '-'
                          }}
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          {{
                            policy.effect.last_hit_at
                              ? formatTimestamp(policy.effect.last_hit_at)
                              : '暂无命中时间'
                          }}
                        </p>
                      </div>
                      <div
                        class="rounded-xl border border-slate-200 bg-white/80 px-3 py-2"
                      >
                        <p
                          class="text-[11px] uppercase tracking-[0.14em] text-slate-400"
                        >
                          效果摘要
                        </p>
                        <p class="mt-1 text-xs text-slate-600">
                          匹配
                          {{ formatPolicyEffectMap(policy.effect.match_modes) }}
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          动作
                          {{ formatPolicyEffectMap(policy.effect.action_hits) }}
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          对象
                          {{
                            formatPolicyEffectMap(
                              policy.effect.matched_value_hits,
                            )
                          }}
                        </p>
                      </div>
                    </div>
                    <div class="mt-2 grid gap-2 md:grid-cols-3">
                      <div
                        class="rounded-xl border border-slate-200 bg-white/80 px-3 py-2"
                      >
                        <p
                          class="text-[11px] uppercase tracking-[0.14em] text-slate-400"
                        >
                          L7 摩擦
                        </p>
                        <p class="mt-1 text-xs text-slate-600">
                          当前
                          {{
                            formatNumber(
                              policy.effectiveness.current_l7_friction_percent,
                            )
                          }}%
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          变化
                          {{
                            formatDelta(policy.effectiveness.l7_friction_delta)
                          }}
                        </p>
                      </div>
                      <div
                        class="rounded-xl border border-slate-200 bg-white/80 px-3 py-2"
                      >
                        <p
                          class="text-[11px] uppercase tracking-[0.14em] text-slate-400"
                        >
                          身份压力
                        </p>
                        <p class="mt-1 text-xs text-slate-600">
                          当前
                          {{
                            formatNumber(
                              policy.effectiveness
                                .current_identity_pressure_percent,
                            )
                          }}%
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          变化
                          {{
                            formatDelta(
                              policy.effectiveness.identity_pressure_delta,
                            )
                          }}
                        </p>
                      </div>
                      <div
                        class="rounded-xl border border-slate-200 bg-white/80 px-3 py-2"
                      >
                        <p
                          class="text-[11px] uppercase tracking-[0.14em] text-slate-400"
                        >
                          雷池后持续压力
                        </p>
                        <p class="mt-1 text-xs text-slate-600">
                          当前
                          {{
                            formatNumber(
                              policy.effectiveness
                                .current_rust_persistence_percent,
                            )
                          }}%
                        </p>
                        <p class="mt-1 text-[11px] text-slate-500">
                          变化
                          {{
                            formatDelta(
                              policy.effectiveness.rust_persistence_delta,
                            )
                          }}
                        </p>
                      </div>
                    </div>
                    <p class="mt-2 text-[11px] text-slate-500">
                      治理建议 {{ policy.effectiveness.governance_hint }}
                    </p>
                  </div>
                  <button
                    type="button"
                    class="inline-flex items-center justify-center rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
                    :disabled="revokingPolicyId === policy.id"
                    @click="revokePolicy(policy.id)"
                  >
                    {{
                      revokingPolicyId === policy.id ? '撤销中...' : '撤销策略'
                    }}
                  </button>
                </div>
              </article>
            </div>
          </div>
        </div>
      </section>
</template>
