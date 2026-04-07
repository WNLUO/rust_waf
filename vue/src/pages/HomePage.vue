<script setup lang="ts">
import { RouterLink } from 'vue-router'

const productCards = [
  {
    title: '轻量部署',
    body: '适合低配云主机、边缘节点和中小流量入口，优先承担预过滤、限速和基础代理。',
  },
  {
    title: '高性能扩展',
    body: '在更高配置节点上可承接更多并发连接，并逐步开启更完整的上游联动和策略能力。',
  },
  {
    title: '控制面清晰',
    body: '前台承担产品说明与入口展示，后台聚焦运行、规则、事件、封禁和后续配置管理。',
  },
]

const scenes = [
  '公网业务站点入口',
  'API 网关前置防护',
  '低成本边缘节点过滤',
  '多层 WAF 体系前置层',
]

const roadmap = [
  '性能档位控制与一键切换',
  '自动识别主机规格并给出推荐配置',
  '运行期配置保存与热更新',
  '后台登录、权限与审计日志',
]
</script>

<template>
  <main class="page home-page">
    <section class="home-hero">
      <div class="hero-content">
        <p class="eyebrow">Gateway Front Site</p>
        <h1>面向真实业务的 Rust 安全网关</h1>
        <p class="hero-copy">
          这是系统的前台首页，用于对外展示产品定位、部署场景与能力边界。后台控制台则承担规则、事件、封禁与运行状态管理。
        </p>
        <div class="hero-actions">
          <RouterLink class="primary-button" to="/admin">进入后台控制台</RouterLink>
          <a class="ghost-button" href="#scenes">查看适用场景</a>
        </div>
      </div>

      <div class="hero-board">
        <div class="hero-stat">
          <span>定位</span>
          <strong>前置过滤 + 代理控制</strong>
        </div>
        <div class="hero-stat">
          <span>适配</span>
          <strong>低配到高配服务器</strong>
        </div>
        <div class="hero-stat">
          <span>形态</span>
          <strong>前台站点 + 后台控制台</strong>
        </div>
      </div>
    </section>

    <section class="home-section">
      <div class="section-heading">
        <p class="eyebrow">Core Value</p>
        <h2>为什么拆成前台和后台</h2>
      </div>
      <div class="feature-grid">
        <article v-for="card in productCards" :key="card.title" class="feature-card">
          <h3>{{ card.title }}</h3>
          <p>{{ card.body }}</p>
        </article>
      </div>
    </section>

    <section id="scenes" class="home-section dual-section">
      <article class="panel site-panel">
        <div class="section-heading">
          <p class="eyebrow">Use Cases</p>
          <h2>适用场景</h2>
        </div>
        <ul class="list-stack info-list">
          <li v-for="item in scenes" :key="item" class="list-card info-card">
            <p>{{ item }}</p>
          </li>
        </ul>
      </article>

      <article class="panel site-panel">
        <div class="section-heading">
          <p class="eyebrow">Next Step</p>
          <h2>下一阶段后台规划</h2>
        </div>
        <ul class="list-stack info-list">
          <li v-for="item in roadmap" :key="item" class="list-card info-card">
            <p>{{ item }}</p>
          </li>
        </ul>
      </article>
    </section>
  </main>
</template>
