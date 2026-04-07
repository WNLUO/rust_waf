<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { ShieldCheck, Zap, Terminal, Globe, ArrowRight } from 'lucide-vue-next'

const features = [
  {
    title: '边缘层过滤',
    desc: '在流量到达业务前完成 L4/L7 深度清洗，毫秒级响应。',
    icon: ShieldCheck
  },
  {
    title: 'Rust 高性能内核',
    desc: '基于内存安全语言构建，极致吞吐，极低资源占用。',
    icon: Zap
  },
  {
    title: '智能规则引擎',
    desc: '动态加载安全策略，支持一键封禁与自动化防护。',
    icon: Terminal
  }
]
</script>

<template>
  <div class="min-h-screen bg-cyber-bg overflow-hidden relative">
    <!-- Background Decor -->
    <div class="absolute inset-0 z-0">
      <div class="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-accent/10 rounded-full blur-[120px]"></div>
      <div class="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-cyber-success/5 rounded-full blur-[120px]"></div>
      <div class="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-overlay"></div>
    </div>

    <!-- Header -->
    <header class="relative z-10 max-w-7xl mx-auto px-8 h-24 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="p-2 bg-cyber-accent rounded-cyber">
          <Globe :size="24" class="text-white" />
        </div>
        <span class="font-bold text-xl tracking-tighter uppercase">Rust WAF Gateway</span>
      </div>
      <nav class="hidden md:flex items-center gap-8 text-sm font-mono text-cyber-muted uppercase tracking-widest">
        <a href="#" class="hover:text-cyber-accent transition-colors">Documentation</a>
        <a href="#" class="hover:text-cyber-accent transition-colors">Security</a>
        <RouterLink to="/admin" class="px-5 py-2 border border-cyber-accent/50 text-cyber-accent rounded-cyber hover:bg-cyber-accent/10 transition-all">
          Console
        </RouterLink>
      </nav>
    </header>

    <!-- Hero -->
    <main class="relative z-10 max-w-7xl mx-auto px-8 pt-20 pb-32">
      <div class="max-w-3xl">
        <div class="inline-flex items-center gap-2 px-3 py-1 bg-white/5 border border-white/10 rounded-full text-[10px] font-mono text-cyber-muted uppercase tracking-widest mb-8">
          <span class="w-1.5 h-1.5 rounded-full bg-cyber-success animate-ping"></span>
          Current Release: v0.9.0 Stable
        </div>
        
        <h1 class="text-6xl md:text-8xl font-black tracking-tighter leading-[0.9] mb-8 uppercase italic">
          Secure. <br/>
          <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyber-accent to-cyber-success">Fast.</span> <br/>
          Resilient.
        </h1>
        
        <p class="text-xl text-cyber-muted leading-relaxed mb-12 max-w-2xl">
          面向下一代业务的 Rust 安全网关。在边缘侧提供工业级的协议识别、流量清洗与动态策略管控。
        </p>

        <div class="flex flex-wrap gap-6">
          <RouterLink to="/admin" class="px-8 py-4 bg-cyber-accent text-white font-bold rounded-cyber flex items-center gap-3 group hover:shadow-cyber transition-all">
            进入控制台
            <ArrowRight :size="20" class="group-hover:translate-x-1 transition-transform" />
          </RouterLink>
          <button class="px-8 py-4 bg-white/5 border border-white/10 text-gray-300 font-bold rounded-cyber hover:bg-white/10 transition-all">
            查看技术白皮书
          </button>
        </div>
      </div>

      <!-- Feature Grid -->
      <div class="grid md:grid-cols-3 gap-8 mt-32">
        <div v-for="f in features" :key="f.title" class="p-8 bg-cyber-surface/50 border border-cyber-border rounded-cyber backdrop-blur-sm group hover:border-cyber-accent/50 transition-all">
          <div class="w-12 h-12 bg-white/5 rounded-cyber flex items-center justify-center mb-6 group-hover:bg-cyber-accent/20 transition-all">
            <component :is="f.icon" :size="24" class="text-cyber-accent" />
          </div>
          <h3 class="text-lg font-bold mb-3 uppercase tracking-tight text-gray-100">{{ f.title }}</h3>
          <p class="text-sm text-cyber-muted leading-relaxed">{{ f.desc }}</p>
        </div>
      </div>
    </main>

    <!-- Footer decoration -->
    <div class="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyber-border to-transparent"></div>
  </div>
</template>
