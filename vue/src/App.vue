<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { createRule, deleteRule, fetchDashboardPayload, unblockIp, updateRule } from './lib/api'
import type { DashboardPayload, RuleDraft, RuleItem } from './lib/types'

const dashboard = ref<DashboardPayload | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const actionMessage = ref('')
const actionError = ref('')
const lastUpdatedAt = ref<number | null>(null)
const autoRefreshEnabled = ref(true)
const pendingRuleId = ref<string | null>(null)
const pendingBlockedIpId = ref<number | null>(null)
let refreshTimer: number | undefined

const ruleForm = reactive<RuleDraft>({
  id: '',
  name: '',
  enabled: true,
  layer: 'l7',
  pattern: '',
  action: 'block',
  severity: 'high',
})

const statusTone = computed(() => {
  if (!dashboard.value) {
    return 'muted'
  }

  return dashboard.value.health.upstream_healthy ? 'good' : 'bad'
})

const headline = computed(() => {
  if (!dashboard.value) {
    return '等待 Rust WAF API 返回状态'
  }

  return dashboard.value.health.upstream_healthy
    ? '前置代理链路健康，可继续向雷池 WAF 稳定转发'
    : '前置代理链路降级，请优先检查 rust_waf 与雷池之间的连通性'
})

const summaryCards = computed(() => {
  if (!dashboard.value) {
    return []
  }

  const { metrics } = dashboard.value
  return [
    {
      label: '接入请求数',
      value: formatNumber(metrics.total_packets),
      hint: `累计流量 ${formatBytes(metrics.total_bytes)}`,
    },
    {
      label: '转发到雷池',
      value: formatNumber(metrics.proxied_requests),
      hint: `成功 ${formatNumber(metrics.proxy_successes)} / 失败 ${formatNumber(metrics.proxy_failures)}`,
    },
    {
      label: '平均代理耗时',
      value: formatLatency(metrics.average_proxy_latency_micros),
      hint: `累计 ${formatLatency(metrics.proxy_latency_micros_total)}`,
    },
    {
      label: '拦截与拒绝',
      value: formatNumber(metrics.blocked_packets),
      hint: `L4 ${metrics.blocked_l4} / L7 ${metrics.blocked_l7} / fail-close ${metrics.proxy_fail_close_rejections}`,
    },
  ]
})

const routeCards = computed(() => {
  if (!dashboard.value) {
    return []
  }

  const { health, metrics } = dashboard.value
  return [
    {
      label: '下游健康',
      value: health.upstream_healthy ? 'Healthy' : 'Degraded',
      hint: health.upstream_last_error ?? '最近一次探测通过',
    },
    {
      label: '健康检查',
      value: `${metrics.upstream_healthcheck_successes}/${metrics.upstream_healthcheck_failures}`,
      hint: '成功次数 / 失败次数',
    },
    {
      label: '活跃规则',
      value: formatNumber(metrics.active_rules),
      hint: `SQLite 规则 ${formatNumber(metrics.persisted_rules)}`,
    },
    {
      label: '持久化事件',
      value: formatNumber(metrics.persisted_security_events),
      hint: `封禁 IP ${formatNumber(metrics.persisted_blocked_ips)}`,
    },
  ]
})

const proxyQuality = computed(() => {
  if (!dashboard.value || dashboard.value.metrics.proxied_requests === 0) {
    return 0
  }

  return Math.round(
    (dashboard.value.metrics.proxy_successes / dashboard.value.metrics.proxied_requests) * 100,
  )
})

const healthQuality = computed(() => {
  if (!dashboard.value) {
    return 0
  }

  const total =
    dashboard.value.metrics.upstream_healthcheck_successes +
    dashboard.value.metrics.upstream_healthcheck_failures

  if (total === 0) {
    return dashboard.value.health.upstream_healthy ? 100 : 0
  }

  return Math.round(
    (dashboard.value.metrics.upstream_healthcheck_successes / total) * 100,
  )
})

const defenseLayers = computed(() => {
  const upstreamState = dashboard.value?.health.upstream_healthy ? '已连通' : '待确认'
  return [
    {
      title: 'CDN 边缘入口',
      description: '负责公网接入、缓存与边缘基础清洗，向 rust_waf 透传真实客户端来源信息。',
      tag: '入口层',
    },
    {
      title: 'Rust 前置网关',
      description: '负责真实 IP 识别、慢连接防护、健康检查、链路代理与轻量化预过滤。',
      tag: '预过滤层',
    },
    {
      title: '雷池 WAF',
      description: `负责深度应用层检测与复杂规则匹配，当前链路状态：${upstreamState}。`,
      tag: '深度检测层',
    },
    {
      title: 'Nginx / 业务服务',
      description: '承接通过双层防护的请求，负责业务反向代理与最终应用交付。',
      tag: '服务层',
    },
  ]
})

const designPrinciples = [
  {
    title: '分层协同',
    body: '将低成本连接治理放在 Rust 前置层，将重型语义检测交给雷池，避免重复消耗。',
  },
  {
    title: '链路可观测',
    body: '通过健康检查、代理成功率和延迟指标，让前置层从黑盒代理变成可验证网关。',
  },
  {
    title: '控制面分离',
    body: '用 Rust API 暴露健康、事件和规则信息，再用 Vue 控制台承载管理台与论文展示。',
  },
]

const researchHighlights = computed(() => {
  if (!dashboard.value) {
    return []
  }

  const { metrics } = dashboard.value
  return [
    {
      title: '链路稳定性',
      value: `${healthQuality.value}%`,
      detail: `基于 ${metrics.upstream_healthcheck_successes + metrics.upstream_healthcheck_failures} 次健康探测估算`,
    },
    {
      title: '代理成功率',
      value: `${proxyQuality.value}%`,
      detail: `转发 ${metrics.proxied_requests} 次，请求成功 ${metrics.proxy_successes} 次`,
    },
    {
      title: '前置阻断规模',
      value: formatNumber(metrics.blocked_packets),
      detail: '说明 Rust 前置层已经开始承担流量减负作用',
    },
  ]
})

async function loadDashboard(force = false) {
  if (force) {
    refreshing.value = true
  }

  error.value = ''

  try {
    dashboard.value = await fetchDashboardPayload()
    lastUpdatedAt.value = Date.now()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载仪表盘失败'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

async function submitRule() {
  actionError.value = ''
  actionMessage.value = ''

  try {
    const payload: RuleDraft = {
      ...ruleForm,
      id: ruleForm.id.trim(),
      name: ruleForm.name.trim(),
      pattern: ruleForm.pattern.trim(),
    }
    const response = await createRule(payload)
    actionMessage.value = response.message
    resetRuleForm()
    await loadDashboard(true)
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : '新增规则失败'
  }
}

async function toggleRule(rule: RuleItem) {
  actionError.value = ''
  actionMessage.value = ''
  pendingRuleId.value = rule.id

  try {
    const response = await updateRule({
      ...rule,
      enabled: !rule.enabled,
    })
    actionMessage.value = response.message
    await loadDashboard(true)
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : '更新规则失败'
  } finally {
    pendingRuleId.value = null
  }
}

async function removeRule(id: string) {
  actionError.value = ''
  actionMessage.value = ''
  pendingRuleId.value = id

  try {
    const response = await deleteRule(id)
    actionMessage.value = response.message
    await loadDashboard(true)
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : '删除规则失败'
  } finally {
    pendingRuleId.value = null
  }
}

async function removeBlockedIp(id: number) {
  actionError.value = ''
  actionMessage.value = ''
  pendingBlockedIpId.value = id

  try {
    const response = await unblockIp(id)
    actionMessage.value = response.message
    await loadDashboard(true)
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : '解除封禁失败'
  } finally {
    pendingBlockedIpId.value = null
  }
}

function resetRuleForm() {
  ruleForm.id = ''
  ruleForm.name = ''
  ruleForm.enabled = true
  ruleForm.layer = 'l7'
  ruleForm.pattern = ''
  ruleForm.action = 'block'
  ruleForm.severity = 'high'
}

function scheduleRefresh() {
  clearRefreshTimer()
  if (!autoRefreshEnabled.value) {
    return
  }

  refreshTimer = window.setInterval(() => {
    void loadDashboard(true)
  }, 15000)
}

function clearRefreshTimer() {
  if (refreshTimer) {
    window.clearInterval(refreshTimer)
    refreshTimer = undefined
  }
}

function toggleAutoRefresh() {
  autoRefreshEnabled.value = !autoRefreshEnabled.value
  scheduleRefresh()
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('zh-CN').format(value)
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

function formatLatency(micros: number) {
  if (micros < 1000) {
    return `${micros} us`
  }

  if (micros < 1000 * 1000) {
    return `${(micros / 1000).toFixed(1)} ms`
  }

  return `${(micros / 1000 / 1000).toFixed(2)} s`
}

function formatTimestamp(timestamp: number | null) {
  if (!timestamp) {
    return '暂无'
  }

  return new Date(timestamp * 1000).toLocaleString('zh-CN', {
    hour12: false,
  })
}

function formatLastUpdated(value: number | null) {
  if (!value) {
    return '未刷新'
  }

  return new Date(value).toLocaleString('zh-CN', {
    hour12: false,
  })
}

onMounted(async () => {
  await loadDashboard()
  scheduleRefresh()
})

onBeforeUnmount(() => {
  clearRefreshTimer()
})
</script>

<template>
  <div class="shell">
    <header class="hero-panel">
      <div>
        <p class="eyebrow">Rust WAF Console</p>
        <h1>前置安全网关控制台</h1>
        <p class="hero-copy">
          面向 <code>CDN -> rust_waf -> 雷池 -> Nginx</code> 的联调与展示面板，重点呈现链路健康、代理指标、阻断事件与前后台协同设计。
        </p>
      </div>
      <div class="hero-actions">
        <button class="ghost-button" @click="toggleAutoRefresh">
          {{ autoRefreshEnabled ? '关闭自动刷新' : '开启自动刷新' }}
        </button>
        <button class="primary-button" :disabled="refreshing" @click="loadDashboard(true)">
          {{ refreshing ? '刷新中...' : '立即刷新' }}
        </button>
      </div>
    </header>

    <section class="status-strip" :data-tone="statusTone">
      <div>
        <span class="status-dot"></span>
        <strong>{{ headline }}</strong>
      </div>
      <div class="status-meta">
        <span>版本 {{ dashboard?.health.version ?? '--' }}</span>
        <span>上次刷新 {{ formatLastUpdated(lastUpdatedAt) }}</span>
      </div>
    </section>

    <section v-if="error" class="alert-panel">
      <strong>API 访问失败</strong>
      <p>{{ error }}</p>
      <p class="muted">请确认 Rust 服务已用 <code>--features api</code> 启动，且监听地址与 Vite 代理一致。</p>
    </section>

    <section v-if="actionError" class="alert-panel action-alert error-alert">
      <strong>操作失败</strong>
      <p>{{ actionError }}</p>
    </section>

    <section v-if="actionMessage" class="alert-panel action-alert success-alert">
      <strong>操作成功</strong>
      <p>{{ actionMessage }}</p>
    </section>

    <section v-if="loading" class="placeholder-grid">
      <article v-for="item in 4" :key="item" class="skeleton-card"></article>
    </section>

    <template v-else-if="dashboard">
      <section class="card-grid metrics-grid">
        <article v-for="card in summaryCards" :key="card.label" class="metric-card">
          <p class="card-label">{{ card.label }}</p>
          <strong class="card-value">{{ card.value }}</strong>
          <p class="card-hint">{{ card.hint }}</p>
        </article>
      </section>

      <section class="analysis-grid">
        <article class="analysis-panel">
          <div class="panel-header compact-header">
            <div>
              <p class="eyebrow">Architecture</p>
              <h2>系统链路视图</h2>
            </div>
            <span class="badge">答辩展示区</span>
          </div>
          <div class="chain-flow">
            <div v-for="layer in defenseLayers" :key="layer.title" class="chain-node">
              <span class="node-tag">{{ layer.tag }}</span>
              <strong>{{ layer.title }}</strong>
              <p>{{ layer.description }}</p>
            </div>
          </div>
        </article>

        <article class="analysis-panel score-panel">
          <div class="panel-header compact-header">
            <div>
              <p class="eyebrow">Research Value</p>
              <h2>实验指标摘要</h2>
            </div>
          </div>
          <div class="score-stack">
            <div class="score-item">
              <div class="score-head">
                <span>代理成功率</span>
                <strong>{{ proxyQuality }}%</strong>
              </div>
              <div class="progress-track"><span :style="{ width: `${proxyQuality}%` }"></span></div>
            </div>
            <div class="score-item">
              <div class="score-head">
                <span>健康探测稳定性</span>
                <strong>{{ healthQuality }}%</strong>
              </div>
              <div class="progress-track good"><span :style="{ width: `${healthQuality}%` }"></span></div>
            </div>
            <div class="score-item meta-score">
              <div v-for="item in researchHighlights" :key="item.title" class="insight-card">
                <p class="card-label">{{ item.title }}</p>
                <strong class="insight-value">{{ item.value }}</strong>
                <p class="card-hint">{{ item.detail }}</p>
              </div>
            </div>
          </div>
        </article>
      </section>

      <section class="principle-grid">
        <article v-for="item in designPrinciples" :key="item.title" class="principle-card">
          <p class="eyebrow">Design</p>
          <h3>{{ item.title }}</h3>
          <p>{{ item.body }}</p>
        </article>
      </section>

      <section class="card-grid route-grid">
        <article v-for="card in routeCards" :key="card.label" class="route-card">
          <p class="card-label">{{ card.label }}</p>
          <strong class="card-value compact">{{ card.value }}</strong>
          <p class="card-hint">{{ card.hint }}</p>
        </article>
      </section>

      <section class="management-grid">
        <article class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Rule Management</p>
              <h2>新增规则</h2>
            </div>
          </div>
          <form class="rule-form" @submit.prevent="submitRule">
            <label>
              <span>规则 ID</span>
              <input v-model="ruleForm.id" required placeholder="例如 rust-l7-block-1" />
            </label>
            <label>
              <span>规则名称</span>
              <input v-model="ruleForm.name" required placeholder="例如 阻断高危扫描" />
            </label>
            <label>
              <span>匹配模式</span>
              <textarea v-model="ruleForm.pattern" required rows="4" placeholder="例如 /admin|/phpmyadmin"></textarea>
            </label>
            <div class="form-row">
              <label>
                <span>层级</span>
                <select v-model="ruleForm.layer">
                  <option value="l4">L4</option>
                  <option value="l7">L7</option>
                </select>
              </label>
              <label>
                <span>动作</span>
                <select v-model="ruleForm.action">
                  <option value="block">Block</option>
                  <option value="alert">Alert</option>
                  <option value="allow">Allow</option>
                </select>
              </label>
              <label>
                <span>严重级别</span>
                <select v-model="ruleForm.severity">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
            </div>
            <label class="checkbox-row">
              <input v-model="ruleForm.enabled" type="checkbox" />
              <span>创建后立即启用</span>
            </label>
            <div class="form-actions">
              <button class="ghost-button" type="button" @click="resetRuleForm">重置</button>
              <button class="primary-button" type="submit">新增规则</button>
            </div>
          </form>
        </article>

        <article class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Active Controls</p>
              <h2>封禁与规则操作</h2>
            </div>
          </div>
          <div class="management-subsection">
            <h3>活跃封禁</h3>
            <ul class="list-stack compact-stack">
              <li v-for="item in dashboard.blockedIps.blocked_ips" :key="item.id" class="list-card action-card">
                <div>
                  <strong>{{ item.ip }}</strong>
                  <p>{{ item.reason }}</p>
                </div>
                <div class="action-column">
                  <small>失效 {{ formatTimestamp(item.expires_at) }}</small>
                  <button
                    class="ghost-button small-button"
                    :disabled="pendingBlockedIpId === item.id"
                    @click="removeBlockedIp(item.id)"
                  >
                    {{ pendingBlockedIpId === item.id ? '处理中...' : '解除封禁' }}
                  </button>
                </div>
              </li>
            </ul>
          </div>
          <div class="management-subsection">
            <h3>规则操作</h3>
            <ul class="list-stack compact-stack">
              <li v-for="rule in dashboard.rules.rules.slice(0, 8)" :key="rule.id" class="list-card action-card">
                <div>
                  <strong>{{ rule.name }}</strong>
                  <p>{{ rule.pattern }}</p>
                </div>
                <div class="action-column">
                  <small>{{ rule.layer.toUpperCase() }} · {{ rule.action }} · {{ rule.enabled ? '启用中' : '已停用' }}</small>
                  <div class="button-row">
                    <button
                      class="ghost-button small-button"
                      :disabled="pendingRuleId === rule.id"
                      @click="toggleRule(rule)"
                    >
                      {{ pendingRuleId === rule.id ? '处理中...' : rule.enabled ? '停用' : '启用' }}
                    </button>
                    <button
                      class="danger-button small-button"
                      :disabled="pendingRuleId === rule.id"
                      @click="removeRule(rule.id)"
                    >
                      删除
                    </button>
                  </div>
                </div>
              </li>
            </ul>
          </div>
        </article>
      </section>

      <section class="panel-grid">
        <article class="panel panel-wide">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Security Events</p>
              <h2>最新阻断事件</h2>
            </div>
            <span class="badge">{{ dashboard.events.total }} 条</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>来源</th>
                  <th>目标</th>
                  <th>层级</th>
                  <th>原因</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="event in dashboard.events.events" :key="event.id">
                  <td>{{ formatTimestamp(event.created_at) }}</td>
                  <td>
                    <div>{{ event.source_ip }}</div>
                    <small>{{ event.protocol }}:{{ event.source_port }}</small>
                  </td>
                  <td>
                    <div>{{ event.dest_ip }}</div>
                    <small>{{ event.dest_port }}</small>
                  </td>
                  <td>
                    <span class="badge subtle">{{ event.layer }}</span>
                  </td>
                  <td>
                    <div>{{ event.reason }}</div>
                    <small>{{ event.http_method ?? 'N/A' }} {{ event.uri ?? '' }}</small>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <article class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Blocked IPs</p>
              <h2>活跃封禁</h2>
            </div>
            <span class="badge">{{ dashboard.blockedIps.total }} 个</span>
          </div>
          <ul class="list-stack">
            <li v-for="item in dashboard.blockedIps.blocked_ips" :key="item.id" class="list-card">
              <div>
                <strong>{{ item.ip }}</strong>
                <p>{{ item.reason }}</p>
              </div>
              <small>失效 {{ formatTimestamp(item.expires_at) }}</small>
            </li>
          </ul>
        </article>

        <article class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Rules</p>
              <h2>规则概览</h2>
            </div>
            <span class="badge">{{ dashboard.rules.rules.length }} 条</span>
          </div>
          <ul class="list-stack">
            <li v-for="rule in dashboard.rules.rules.slice(0, 8)" :key="rule.id" class="list-card">
              <div>
                <strong>{{ rule.name }}</strong>
                <p>{{ rule.pattern }}</p>
              </div>
              <small>{{ rule.layer.toUpperCase() }} · {{ rule.action }}</small>
            </li>
          </ul>
        </article>
      </section>

      <section class="architecture-panel">
        <div>
          <p class="eyebrow">Frontend / Backend Design</p>
          <h2>前后台分层设计</h2>
        </div>
        <div class="architecture-grid">
          <article>
            <h3>前端 Vue 控制台</h3>
            <p>通过 Vite 代理访问 Rust API，承担答辩展示、联调观测与最小管理台操作入口。</p>
          </article>
          <article>
            <h3>Rust API 控制面</h3>
            <p>已支持规则新增、启停更新、删除和解除封禁 IP，可作为论文中的控制平面实现。</p>
          </article>
          <article>
            <h3>数据面网关</h3>
            <p>Rust WAF 负责真实 IP 识别、超时控制、健康探测、代理度量和前置流量治理，再将请求交给雷池。</p>
          </article>
        </div>
      </section>
    </template>
  </div>
</template>
