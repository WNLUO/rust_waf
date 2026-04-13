<script setup lang="ts">
import { Activity, ArrowUpRight, Shield, TimerReset } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'
import type { L7StatsPayload } from '@/shared/types'

defineProps<{
  configForm: L7ConfigForm
  failureModeLabel: string
  formatLatency: (micros?: number) => string
  formatNumber: (value?: number) => string
  formatTimestamp: (timestamp?: number | null) => string
  http3StatusLabel: string
  http3StatusType: 'success' | 'warning' | 'error' | 'muted' | 'info'
  proxySuccessRate: string
  protocolTags: Array<{
    text: string
    type: 'success' | 'warning' | 'error' | 'muted' | 'info'
  }>
  runtimeProfileLabel: string
  runtimeStatus: boolean
  stats: L7StatsPayload | null
  upstreamStatusText: string
  upstreamStatusType: 'success' | 'warning' | 'error' | 'muted' | 'info'
}>()
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
    <div
      class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
    >
      <div class="max-w-3xl">
        <p class="text-sm tracking-wider text-blue-700">HTTP 接入管理</p>
      </div>
      <div class="flex flex-wrap gap-3">
        <StatusBadge
          :text="runtimeStatus ? '运行中' : '未启用'"
          :type="runtimeStatus ? 'success' : 'warning'"
        />
        <StatusBadge :text="`配置档位 ${runtimeProfileLabel}`" type="info" />
        <StatusBadge
          :text="configForm.bloom_enabled ? 'Bloom 已启用' : 'Bloom 未启用'"
          :type="configForm.bloom_enabled ? 'info' : 'muted'"
        />
        <StatusBadge
          :text="configForm.cc_defense.enabled ? 'CC 守卫开启' : 'CC 守卫关闭'"
          :type="configForm.cc_defense.enabled ? 'warning' : 'muted'"
        />
        <StatusBadge
          :text="
            configForm.bloom_false_positive_verification
              ? '误判校验开启'
              : '误判校验关闭'
          "
          :type="
            configForm.bloom_false_positive_verification ? 'success' : 'muted'
          "
        />
      </div>
    </div>
  </section>

  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="请求侧策略拦截"
      :value="formatNumber(stats?.blocked_requests || 0)"
      hint="来自请求规则与响应策略的累计阻断次数"
      :icon="Shield"
      trend="up"
    />
    <MetricWidget
      label="代理请求总数"
      :value="formatNumber(stats?.proxied_requests || 0)"
      :hint="`成功 ${formatNumber(stats?.proxy_successes || 0)} / 失败 ${formatNumber(stats?.proxy_failures || 0)}`"
      :icon="Activity"
    />
    <MetricWidget
      label="代理成功率"
      :value="proxySuccessRate"
      :hint="`失败关闭拒绝 ${formatNumber(stats?.proxy_fail_close_rejections || 0)}`"
      :icon="ArrowUpRight"
    />
    <MetricWidget
      label="平均代理延迟"
      :value="formatLatency(stats?.average_proxy_latency_micros || 0)"
      hint="仅统计成功代理请求"
      :icon="TimerReset"
      trend="down"
    />
  </section>

  <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
    <MetricWidget
      label="CC Challenge 次数"
      :value="formatNumber(stats?.cc_challenge_requests || 0)"
      hint="返回挑战页或挑战响应的累计次数"
      :icon="Shield"
    />
    <MetricWidget
      label="CC 429 次数"
      :value="formatNumber(stats?.cc_block_requests || 0)"
      hint="达到硬阈值后直接拒绝的累计次数"
      :icon="Activity"
      trend="up"
    />
    <MetricWidget
      label="CC 延迟处置"
      :value="formatNumber(stats?.cc_delayed_requests || 0)"
      hint="命中软压制并执行延迟的累计次数"
      :icon="TimerReset"
    />
    <MetricWidget
      label="Challenge 放行"
      :value="formatNumber(stats?.cc_verified_pass_requests || 0)"
      :hint="`Cookie ${configForm.cc_defense.challenge_cookie_name} 验证通过后继续放行`"
      :icon="ArrowUpRight"
    />
  </section>

  <section class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
    <CyberCard title="协议支持" sub-title="HTTP 协议与监听入口摘要">
      <div class="space-y-4">
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            v-for="item in protocolTags"
            :key="item.text"
            :text="item.text"
            :type="item.type"
          />
        </div>
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">监听地址</p>
            <div class="mt-3 space-y-2 text-sm text-stone-800">
              <p v-for="addr in configForm.listen_addrs" :key="addr">
                {{ addr }}
              </p>
              <p v-if="!configForm.listen_addrs.length" class="text-slate-500">
                暂无监听入口
              </p>
            </div>
          </div>
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">HTTP/3 监听</p>
            <p class="mt-3 text-sm text-stone-800">
              {{
                configForm.http3_enabled
                  ? configForm.http3_listen_addr || '已启用'
                  : '未启用 HTTP/3'
              }}
            </p>
          </div>
        </div>
        <div class="grid gap-3 md:grid-cols-3">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">
              HTTP/2 最大并发流
            </p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_max_concurrent_streams) }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">HTTP/2 最大帧</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_max_frame_size) }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">初始窗口</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ formatNumber(configForm.http2_initial_window_size) }}
            </p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="代理链路摘要"
      sub-title="上游地址、健康状态与真实来源解析"
    >
      <div class="space-y-4">
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            :text="`上游 ${upstreamStatusText}`"
            :type="upstreamStatusType"
          />
          <StatusBadge :text="`失败模式 ${failureModeLabel}`" type="warning" />
          <StatusBadge
            :text="
              configForm.upstream_healthcheck_enabled
                ? '健康检查开启'
                : '健康检查关闭'
            "
            :type="
              configForm.upstream_healthcheck_enabled ? 'success' : 'muted'
            "
          />
        </div>
        <div class="rounded-xl bg-slate-50 p-4">
          <p class="text-xs tracking-wide text-slate-500">TCP 上游</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ configForm.upstream_endpoint || '未配置上游转发地址' }}
          </p>
        </div>
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">真实 IP 头优先级</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                configForm.real_ip_headers.length
                  ? configForm.real_ip_headers.join(' -> ')
                  : '未配置'
              }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">可信代理网段</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                configForm.trusted_proxy_cidrs.length
                  ? configForm.trusted_proxy_cidrs.join('，')
                  : '未配置，默认仅信任直连对端'
              }}
            </p>
          </div>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">最近健康检查</p>
          <p class="mt-3 text-sm text-stone-800">
            {{
              stats?.upstream_last_check_at
                ? formatTimestamp(stats.upstream_last_check_at)
                : '暂无检查记录'
            }}
          </p>
          <p
            v-if="stats?.upstream_last_error"
            class="mt-2 text-sm text-red-600"
          >
            最近错误：{{ stats.upstream_last_error }}
          </p>
        </div>
      </div>
    </CyberCard>
  </section>

  <section class="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
    <CyberCard
      title="HTTP/3 运行状态"
      sub-title="编译能力、证书就绪度与监听启动结果"
    >
      <div class="space-y-5">
        <div class="flex flex-wrap gap-3">
          <StatusBadge
            :text="`状态 ${http3StatusLabel}`"
            :type="http3StatusType"
          />
          <StatusBadge
            :text="
              stats?.http3_feature_available ? '已编译 HTTP/3' : '未编译 HTTP/3'
            "
            :type="stats?.http3_feature_available ? 'info' : 'warning'"
          />
          <StatusBadge
            :text="stats?.http3_listener_started ? '监听已启动' : '监听未启动'"
            :type="stats?.http3_listener_started ? 'success' : 'muted'"
          />
        </div>
        <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">配置启用</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_configured_enabled ? '是' : '否' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">TLS 1.3</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_tls13_enabled ? '开启' : '关闭' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">证书路径</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_certificate_configured ? '已配置' : '缺失' }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
            <p class="text-xs tracking-wide text-slate-500">私钥路径</p>
            <p class="mt-3 text-2xl font-semibold text-stone-900">
              {{ stats?.http3_private_key_configured ? '已配置' : '缺失' }}
            </p>
          </div>
        </div>
        <div class="grid gap-3 md:grid-cols-2">
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">监听结果</p>
            <p class="mt-3 text-sm text-stone-800">
              {{
                stats?.http3_listener_started
                  ? stats?.http3_listener_addr || '监听已启动'
                  : '当前未启动 HTTP/3 监听器'
              }}
            </p>
          </div>
          <div class="rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">启动诊断</p>
            <p class="mt-3 text-sm leading-7 text-stone-800">
              {{
                stats?.http3_last_error ||
                '没有诊断错误，当前状态允许启动 HTTP/3。'
              }}
            </p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard
      title="HTTP/3 当前配置摘要"
      sub-title="便于值班时快速对照配置与运行结果"
    >
      <div class="grid gap-3 md:grid-cols-2">
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">监听地址</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ configForm.http3_listen_addr || '跟随全局 HTTPS 入口' }}
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">最大并发流</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_max_concurrent_streams) }}
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">空闲超时</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_idle_timeout_secs) }} 秒
          </p>
        </div>
        <div class="rounded-xl border border-slate-200 bg-white/80 p-4">
          <p class="text-xs tracking-wide text-slate-500">MTU / QPACK</p>
          <p class="mt-3 text-sm text-stone-800">
            {{ formatNumber(configForm.http3_mtu) }} /
            {{ formatNumber(configForm.http3_qpack_table_size) }}
          </p>
        </div>
      </div>
    </CyberCard>
  </section>
</template>
