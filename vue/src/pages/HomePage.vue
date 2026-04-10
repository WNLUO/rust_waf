<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { ArrowRight, Waves, Sparkles } from 'lucide-vue-next'

const highlights = [
  '流量在进入业务前完成识别与分流',
  '统一展示封禁、规则、延迟与持久化指标',
  '适合网关、防护代理与边界入口的日常运营',
]
</script>

<template>
  <div class="relative min-h-screen overflow-hidden text-stone-900">
    <div class="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyber-accent/20 to-transparent pointer-events-none"></div>
    <div class="absolute inset-x-0 top-24 h-px bg-gradient-to-r from-transparent via-cyber-border/80 to-transparent pointer-events-none"></div>
    <div class="absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-[#f3ede5] to-transparent pointer-events-none"></div>

    <main class="relative z-10 mx-auto max-w-7xl px-6 pb-16 md:px-10 md:pb-24">
      <section class="grid gap-10 pt-8 md:grid-cols-[1.15fr_0.85fr] md:items-center md:pt-12">
        <div>
          <div class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/20 bg-white px-4 py-2 text-xs tracking-[0.18em] text-cyber-accent-strong">
            <Sparkles :size="14" />
            全链路流量防护与观测
          </div>

          <h1 class="mt-6 max-w-4xl font-display text-5xl font-semibold leading-[1.05] md:text-7xl">
            把入口流量
            <span class="text-cyber-accent-strong">拦得稳</span>
            ，也要
            <span class="text-cyber-success">看得清</span>
          </h1>

          <p class="mt-6 max-w-2xl text-lg leading-8 text-stone-700">
            这是一个围绕边界防护场景构建的安全网关前端，面向日常值守与突发响应设计。
            从规则管理、攻击事件到封禁名单，所有核心环节都在同一块界面里完成。
          </p>

          <div class="mt-8">
            <RouterLink
              to="/admin"
              class="inline-flex items-center gap-3 rounded-full bg-cyber-accent px-7 py-4 text-base font-semibold text-white transition hover:bg-cyber-accent/90"
            >
              立即查看控制台
              <ArrowRight :size="18" />
            </RouterLink>
          </div>

          <ul class="mt-10 grid gap-3 text-sm text-stone-700 md:grid-cols-3">
            <li
              v-for="item in highlights"
              :key="item"
              class="rounded-2xl border border-cyber-border/60 bg-white px-4 py-4 shadow-sm"
            >
              {{ item }}
            </li>
          </ul>
        </div>

        <div class="relative">
          <div class="rounded-[28px] border border-cyber-border/60 bg-white p-6 shadow-sm md:p-8">
            <div class="flex items-center justify-between rounded-2xl bg-stone-900 px-5 py-4 text-stone-100">
              <div>
                <p class="text-xs tracking-[0.25em] text-stone-400">边界态势</p>
                <p class="mt-2 text-2xl font-semibold">防护运行中</p>
              </div>
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-cyber-success/20">
                <Waves :size="22" class="text-cyber-success" />
              </div>
            </div>

            <div class="mt-5 grid gap-4 md:grid-cols-2">
              <div class="rounded-2xl bg-cyber-surface-strong p-5">
                <p class="text-sm text-cyber-muted">策略执行</p>
                <p class="mt-2 text-3xl font-semibold text-cyber-accent-strong">四层 + 七层</p>
                <p class="mt-3 text-sm leading-6 text-stone-700">将连接层封禁与请求层拦截纳入统一视图，方便值班时快速判断攻击类型。</p>
              </div>
              <div class="rounded-2xl border border-cyber-border/60 bg-white p-5">
                <p class="text-sm text-cyber-muted">观测节奏</p>
                <p class="mt-2 text-3xl font-semibold text-cyber-success">秒级刷新</p>
                <p class="mt-3 text-sm leading-6 text-stone-700">在控制台持续轮询实时数据，既保留速度，也兼顾运维场景下的阅读体验。</p>
              </div>
            </div>

            <div class="mt-5 rounded-2xl border border-cyber-border/60 bg-white p-5">
              <p class="text-sm text-cyber-muted">界面基调</p>
              <div class="mt-4 flex items-center gap-3">
                <span class="h-10 w-10 rounded-full bg-[#7f2f12]"></span>
                <span class="h-10 w-10 rounded-full bg-[#b3541e]"></span>
                <span class="h-10 w-10 rounded-full bg-[#2d6a4f]"></span>
                <span class="h-10 w-10 rounded-full bg-[#f7efe1] border border-cyber-border"></span>
              </div>
              <p class="mt-4 text-sm leading-6 text-stone-700">
                用偏东方纸本质感的暖色界面取代通用科技蓝，让安全平台更克制、更耐看，也更适合中文环境。
              </p>
            </div>
          </div>
        </div>
      </section>
    </main>
  </div>
</template>
