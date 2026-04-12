<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'

const capabilityRows = [
  {
    area: '纯 L4 连接层',
    can: '识别连接暴涨、短连接、连接复用下降、慢连接压力和系统资源占用。',
    cannot: '不能在同一条连接里精确识别哪个具体请求恶意。',
  },
  {
    area: 'L4.5 TLS 元信息',
    can: '在 HTTPS 回源下读取 SNI、ALPN 等握手元信息，并结合回源 IP 做分桶。',
    cannot: '不能把这些指纹当成最终浏览器身份，更多反映的是 CDN 回源行为。',
  },
  {
    area: 'L7 / 雷池联动',
    can: '把雷池和本地 L7 的命中结果回写到 L4 分桶，收紧后续连接策略。',
    cannot: '不能回头精确改写同一条已复用连接里的历史请求结果。',
  },
]

const strategyRows = [
  {
    title: '正常',
    detail: '稳定连接、低反馈命中、分桶风险分低，保持连接复用和常规超时。',
    tone: 'success' as const,
  },
  {
    title: '可疑',
    detail: '连接增长、请求密度或联动反馈异常，缩短复用、优先早关连接。',
    tone: 'warning' as const,
  },
  {
    title: '高风险',
    detail: '明显偏离基线或持续收到 L7/雷池反馈，进入 tighten 策略并收紧连接预算。',
    tone: 'error' as const,
  },
]
</script>

<template>
  <section class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
    <CyberCard
      title="L4 + L4.5 架构定位"
      sub-title="客户端 -> CDN -> Rust(L4/L4.5) -> 雷池WAF(L7) -> 后端。L4 负责异常连接和资源控制，L7 负责请求真相。"
    >
      <div class="space-y-4 text-sm leading-7 text-stone-700">
        <div class="rounded-[18px] border border-slate-200 bg-slate-50 p-4">
          CDN 会隐藏最终用户身份，但不会隐藏回源流量结构异常。这个页面展示的是
          CDN 到 Rust 这一跳的连接群行为，不是最终浏览器个体画像。
        </div>
        <div class="grid gap-3 md:grid-cols-3">
          <div class="rounded-[18px] bg-[#f5f9ff] p-4">
            <p class="text-xs tracking-wide text-blue-700">HTTP 回源</p>
            <p class="mt-2 text-sm text-stone-700">
              基于 Host、协议版本和回源 IP 做分桶，聚焦连接复用与请求密度。
            </p>
          </div>
          <div class="rounded-[18px] bg-[#f8f7ef] p-4">
            <p class="text-xs tracking-wide text-amber-700">HTTPS 回源</p>
            <p class="mt-2 text-sm text-stone-700">
              基于 SNI、ALPN 和回源 IP 做分桶，不解业务 TLS 内容。
            </p>
          </div>
          <div class="rounded-[18px] bg-[#f4faf4] p-4">
            <p class="text-xs tracking-wide text-emerald-700">联动闭环</p>
            <p class="mt-2 text-sm text-stone-700">
              雷池和 L7 负责判断，L4 负责把后续连接策略收紧并降低异常成本。
            </p>
          </div>
        </div>
      </div>
    </CyberCard>

    <CyberCard title="分级处理策略" sub-title="默认以低误伤的软动作优先。">
      <div class="space-y-3">
        <div
          v-for="item in strategyRows"
          :key="item.title"
          class="rounded-[18px] border border-slate-200 bg-slate-50 p-4"
        >
          <div class="flex items-center justify-between gap-3">
            <h3 class="text-sm font-semibold text-stone-900">{{ item.title }}</h3>
            <StatusBadge :text="item.title" :type="item.tone" compact />
          </div>
          <p class="mt-2 text-sm leading-6 text-slate-600">{{ item.detail }}</p>
        </div>
      </div>
    </CyberCard>
  </section>

  <CyberCard title="能力边界" sub-title="这部分很重要，避免把 L4 的事情和 L7 的事情混在一起。">
    <div class="overflow-x-auto">
      <table class="min-w-full border-collapse text-left">
        <thead class="bg-slate-50 text-sm text-slate-500">
          <tr>
            <th class="px-4 py-3 font-medium">层级</th>
            <th class="px-4 py-3 font-medium">能做到</th>
            <th class="px-4 py-3 font-medium">做不到</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in capabilityRows"
            :key="row.area"
            class="border-t border-slate-200 text-sm text-stone-800"
          >
            <td class="px-4 py-3 font-semibold text-stone-900">{{ row.area }}</td>
            <td class="px-4 py-3 text-slate-600">{{ row.can }}</td>
            <td class="px-4 py-3 text-slate-600">{{ row.cannot }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </CyberCard>
</template>
