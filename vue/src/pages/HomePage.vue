<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { ArrowRight, Shield, Orbit, ScanSearch, Waves, Sparkles, Blocks } from 'lucide-vue-next'

const features = [
  {
    title: '多层流量治理',
    desc: '统一处理四层连接和七层请求，让拦截、放行、记录形成同一条决策链。',
    icon: Shield,
  },
  {
    title: '实时策略编排',
    desc: '规则可直接在控制台编辑并即时生效，适合快速应对突发攻击与灰度调整。',
    icon: ScanSearch,
  },
  {
    title: '可观测安全态势',
    desc: '把封禁来源、事件走势、上游健康和持久化状态集中展示，便于运维联动。',
    icon: Orbit,
  },
]

const highlights = [
  '流量在进入业务前完成识别与分流',
  '统一展示封禁、规则、延迟与持久化指标',
  '适合网关、防护代理与边界入口的日常运营',
]
</script>

<template>
  <div class="relative min-h-screen overflow-hidden text-stone-900">
    <div class="absolute inset-0 pointer-events-none">
      <div class="absolute -top-24 left-[-12%] h-80 w-80 rounded-full bg-cyber-accent/18 blur-3xl"></div>
      <div class="absolute top-1/3 right-[-10%] h-96 w-96 rounded-full bg-cyber-success/12 blur-3xl"></div>
      <div class="absolute inset-x-0 top-24 h-px bg-gradient-to-r from-transparent via-cyber-accent/30 to-transparent"></div>
    </div>

    <header class="relative z-10 mx-auto flex max-w-7xl items-center justify-between px-6 py-6 md:px-10">
      <div class="flex items-center gap-4">
        <div class="flex h-14 w-14 items-center justify-center rounded-full border border-cyber-accent/20 bg-white/70 shadow-cyber backdrop-blur">
          <Blocks :size="24" class="text-cyber-accent-strong" />
        </div>
        <div>
          <p class="font-display text-2xl font-semibold tracking-[0.18em] text-cyber-accent-strong">玄枢防护网关</p>
          <p class="mt-1 text-sm text-cyber-muted">安全网关总控台</p>
        </div>
      </div>

      <nav class="hidden items-center gap-3 md:flex">
        <a href="#能力概览" class="rounded-full border border-cyber-border/80 px-5 py-2 text-sm text-cyber-muted transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong">
          能力概览
        </a>
        <RouterLink
          to="/admin"
          class="inline-flex items-center gap-2 rounded-full bg-cyber-accent px-5 py-2.5 text-sm font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
        >
          进入控制台
          <ArrowRight :size="16" />
        </RouterLink>
      </nav>
    </header>

    <main class="relative z-10 mx-auto max-w-7xl px-6 pb-16 md:px-10 md:pb-24">
      <section class="grid gap-10 pt-8 md:grid-cols-[1.15fr_0.85fr] md:items-center md:pt-12">
        <div>
          <div class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/20 bg-white/75 px-4 py-2 text-xs tracking-[0.24em] text-cyber-accent-strong shadow-sm backdrop-blur">
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

          <div class="mt-8 flex flex-wrap gap-4">
            <RouterLink
              to="/admin"
              class="inline-flex items-center gap-3 rounded-full bg-cyber-accent px-7 py-4 text-base font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
            >
              立即查看控制台
              <ArrowRight :size="18" />
            </RouterLink>
            <a
              href="#能力概览"
              class="inline-flex items-center gap-3 rounded-full border border-cyber-border bg-white/70 px-7 py-4 text-base font-semibold text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
            >
              了解核心能力
            </a>
          </div>

          <ul class="mt-10 grid gap-3 text-sm text-stone-700 md:grid-cols-3">
            <li
              v-for="item in highlights"
              :key="item"
              class="rounded-[22px] border border-white/70 bg-white/55 px-4 py-4 shadow-[0_10px_30px_rgba(80,55,30,0.06)] backdrop-blur"
            >
              {{ item }}
            </li>
          </ul>
        </div>

        <div class="relative">
          <div class="absolute -left-8 top-10 hidden h-32 w-32 rounded-full border border-cyber-accent/25 md:block"></div>
          <div class="rounded-[36px] border border-white/80 bg-white/72 p-6 shadow-[0_24px_80px_rgba(90,60,30,0.14)] backdrop-blur md:p-8">
            <div class="flex items-center justify-between rounded-[28px] bg-stone-900 px-5 py-4 text-stone-100">
              <div>
                <p class="text-xs tracking-[0.25em] text-stone-400">边界态势</p>
                <p class="mt-2 text-2xl font-semibold">防护运行中</p>
              </div>
              <div class="flex h-12 w-12 items-center justify-center rounded-full bg-cyber-success/20">
                <Waves :size="22" class="text-cyber-success" />
              </div>
            </div>

            <div class="mt-5 grid gap-4 md:grid-cols-2">
              <div class="rounded-[26px] bg-cyber-surface-strong p-5">
                <p class="text-sm text-cyber-muted">策略执行</p>
                <p class="mt-2 text-3xl font-semibold text-cyber-accent-strong">四层 + 七层</p>
                <p class="mt-3 text-sm leading-6 text-stone-700">将连接层封禁与请求层拦截纳入统一视图，方便值班时快速判断攻击类型。</p>
              </div>
              <div class="rounded-[26px] bg-[#f4f7f1] p-5">
                <p class="text-sm text-cyber-muted">观测节奏</p>
                <p class="mt-2 text-3xl font-semibold text-cyber-success">秒级刷新</p>
                <p class="mt-3 text-sm leading-6 text-stone-700">在控制台持续轮询实时数据，既保留速度，也兼顾运维场景下的阅读体验。</p>
              </div>
            </div>

            <div class="mt-5 rounded-[28px] border border-cyber-border/80 bg-white/75 p-5">
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

      <section id="能力概览" class="mt-24">
        <div class="flex items-end justify-between gap-4">
          <div>
            <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">能力概览</p>
            <h2 class="mt-3 font-display text-4xl font-semibold">前端重心围绕“值守”和“处置”展开</h2>
          </div>
        </div>

        <div class="mt-8 grid gap-6 md:grid-cols-3">
          <article
            v-for="feature in features"
            :key="feature.title"
            class="group rounded-[30px] border border-white/80 bg-white/70 p-7 shadow-[0_16px_48px_rgba(80,55,30,0.08)] transition hover:-translate-y-1 hover:shadow-[0_20px_54px_rgba(127,47,18,0.14)]"
          >
            <div class="flex h-14 w-14 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong transition group-hover:bg-cyber-accent group-hover:text-white">
              <component :is="feature.icon" :size="24" />
            </div>
            <h3 class="mt-6 text-2xl font-semibold text-stone-900">{{ feature.title }}</h3>
            <p class="mt-4 text-sm leading-7 text-stone-700">{{ feature.desc }}</p>
          </article>
        </div>
      </section>
    </main>
  </div>
</template>
