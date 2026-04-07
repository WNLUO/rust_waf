<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { createRule, deleteRule, fetchDashboardPayload, unblockIp, updateRule } from '../lib/api'
import type { DashboardPayload, RuleDraft, RuleItem } from '../lib/types'

type AdminView = 'overview' | 'rules' | 'events' | 'blocked'

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
const activeView = ref<AdminView>('overview')
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
    return '等待 Rust WAF API 返回运行状态'
  }

  return dashboard.value.health.upstream_healthy
    ? '上游可达，网关处于可转发状态'
    : '上游不可达或已降级，请优先检查代理目标与健康检查'
})

const summaryCards = computed(() => {
  if (!dashboard.value) {
    return []
  }

  const { metrics } = dashboard.value
  return [
    {
      label: '累计请求',
      value: formatNumber(metrics.total_packets),
      hint: `累计流量 ${formatBytes(metrics.total_bytes)}`,
    },
    {
      label: '代理请求',
      value: formatNumber(metrics.proxied_requests),
      hint: `成功 ${formatNumber(metrics.proxy_successes)} / 失败 ${formatNumber(metrics.proxy_failures)}`,
    },
    {
      label: '拦截总数',
      value: formatNumber(metrics.blocked_packets),
      hint: `L4 ${metrics.blocked_l4} / L7 ${metrics.blocked_l7}`,
    },
    {
      label: '平均代理耗时',
      value: formatLatency(metrics.average_proxy_latency_micros),
      hint: `fail-close ${formatNumber(metrics.proxy_fail_close_rejections)}`,
    },
  ]
})

const runtimeCards = computed(() => {
  if (!dashboard.value) {
    return []
  }

  const { health, metrics } = dashboard.value
  return [
    {
      label: '服务状态',
      value: health.upstream_healthy ? 'Healthy' : 'Degraded',
      hint: health.upstream_last_error ?? '最近一次探测通过',
    },
    {
      label: '健康检查',
      value: `${metrics.upstream_healthcheck_successes}/${metrics.upstream_healthcheck_failures}`,
      hint: '成功次数 / 失败次数',
    },
    {
      label: '规则总数',
      value: formatNumber(metrics.active_rules),
      hint: `SQLite 中共 ${formatNumber(metrics.persisted_rules)} 条`,
    },
    {
      label: '持久化事件',
      value: formatNumber(metrics.persisted_security_events),
      hint: `封禁 IP ${formatNumber(metrics.persisted_blocked_ips)}`,
    },
  ]
})

const proxySuccessRate = computed(() => {
  if (!dashboard.value || dashboard.value.metrics.proxied_requests === 0) {
    return 0
  }

  return Math.round(
    (dashboard.value.metrics.proxy_successes / dashboard.value.metrics.proxied_requests) * 100,
  )
})

const healthSuccessRate = computed(() => {
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

const deploymentAdvice = computed(() => {
  if (!dashboard.value) {
    return {
      title: '等待运行数据',
      level: 'muted',
      summary: '载入指标后可评估是否适合轻量节点部署。',
      points: [
        '当前前端只能基于运行指标给出建议，后端尚未提供配置读写 API。',
        '如果要做自适应配置，建议先补充配置查询、修改和能力探测接口。',
      ],
    }
  }

  const metrics = dashboard.value.metrics
  const highLatency = metrics.average_proxy_latency_micros >= 50_000
  const unstableProxy = metrics.proxied_requests >= 20 && proxySuccessRate.value < 95
  const unstableHealth = healthSuccessRate.value < 90
  const busyGateway = metrics.blocked_packets > 1000 || metrics.proxied_requests > 10_000

  if (highLatency || unstableProxy || unstableHealth || busyGateway) {
    return {
      title: '建议使用标准或高性能节点',
      level: 'bad',
      summary: '当前指标显示这台节点更适合保守限流或迁移到更高配置机器。',
      points: [
        '建议开放性能档位控制，例如 minimal / standard / custom。',
        '建议把 max_concurrent_tasks、请求大小限制、L4 跟踪表大小暴露给控制台。',
        '如果继续使用小机器，优先收紧并发上限并关闭高成本特性。',
      ],
    }
  }

  return {
    title: '适合轻量节点部署',
    level: 'good',
    summary: '当前指标平稳，适合放在低配机器上承担前置过滤和基础代理。',
    points: [
      '可以优先使用轻量档位，限制并发和状态表规模。',
      '如需提升吞吐，再切到标准档位并逐步放开高级特性。',
      '后续可将这套建议接成一键策略下发，而不是只做只读提示。',
    ],
  }
})

const adminNavItems: Array<{ key: AdminView; label: string; hint: string }> = [
  { key: 'overview', label: '运行概览', hint: '状态与指标' },
  { key: 'rules', label: '规则管理', hint: '新增与启停' },
  { key: 'events', label: '安全事件', hint: '阻断记录' },
  { key: 'blocked', label: '封禁列表', hint: 'IP 封禁管理' },
]

const adminSectionTitle = computed(() => {
  switch (activeView.value) {
    case 'rules':
      return '规则管理'
    case 'events':
      return '安全事件'
    case 'blocked':
      return '封禁列表'
    default:
      return '运行概览'
  }
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
    error.value = err instanceof Error ? err.message : '加载控制台失败'
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
  <main class="page admin-page">
    <section class="admin-layout">
      <aside class="admin-sidebar panel">
        <div class="admin-sidebar-head">
          <p class="eyebrow">Navigation</p>
          <h2>后台导航</h2>
        </div>
        <nav class="admin-sidebar-nav">
          <button
            v-for="item in adminNavItems"
            :key="item.key"
            class="admin-nav-button"
            :class="{ active: activeView === item.key }"
            @click="activeView = item.key"
          >
            <strong>{{ item.label }}</strong>
            <small>{{ item.hint }}</small>
          </button>
        </nav>
      </aside>

      <section class="admin-main">
        <header class="admin-toolbar panel">
          <div>
            <p class="eyebrow">Admin Console</p>
            <h1>后台控制台</h1>
            <p class="panel-copy">
              当前为无鉴权后台设计稿，已具备顶部栏、侧边栏和分页切换结构，后续可以继续补登录、权限和更多后台子页面。
            </p>
          </div>
          <div class="admin-toolbar-actions">
            <div class="admin-toolbar-meta">
              <span class="badge">{{ adminSectionTitle }}</span>
              <span class="admin-meta-item">版本 {{ dashboard?.health.version ?? '--' }}</span>
              <span class="admin-meta-item">上次刷新 {{ formatLastUpdated(lastUpdatedAt) }}</span>
            </div>
            <div class="hero-actions">
              <button class="ghost-button" @click="toggleAutoRefresh">
                {{ autoRefreshEnabled ? '关闭自动刷新' : '开启自动刷新' }}
              </button>
              <button class="primary-button" :disabled="refreshing" @click="loadDashboard(true)">
                {{ refreshing ? '刷新中...' : '立即刷新' }}
              </button>
            </div>
          </div>
        </header>

        <section class="status-strip" :data-tone="statusTone">
          <div>
            <span class="status-dot"></span>
            <strong>{{ headline }}</strong>
          </div>
          <div class="status-meta">
            <span>代理成功率 {{ proxySuccessRate }}%</span>
            <span>健康探测稳定性 {{ healthSuccessRate }}%</span>
          </div>
        </section>

        <section v-if="error" class="alert-panel">
          <strong>API 访问失败</strong>
          <p>{{ error }}</p>
          <p class="muted">请确认 Rust 服务已用 <code>--features api</code> 启动，且监听地址与前端代理一致。</p>
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
          <template v-if="activeView === 'overview'">
            <section class="card-grid metrics-grid">
              <article v-for="card in summaryCards" :key="card.label" class="metric-card">
                <p class="card-label">{{ card.label }}</p>
                <strong class="card-value">{{ card.value }}</strong>
                <p class="card-hint">{{ card.hint }}</p>
              </article>
            </section>

            <section class="card-grid route-grid">
              <article v-for="card in runtimeCards" :key="card.label" class="route-card">
                <p class="card-label">{{ card.label }}</p>
                <strong class="card-value compact">{{ card.value }}</strong>
                <p class="card-hint">{{ card.hint }}</p>
              </article>
            </section>

            <section class="ops-grid admin-overview-grid">
              <article class="panel advice-panel" :data-tone="deploymentAdvice.level">
                <div class="panel-header">
                  <div>
                    <p class="eyebrow">Deployment Advice</p>
                    <h2>{{ deploymentAdvice.title }}</h2>
                  </div>
                  <span class="badge">{{ proxySuccessRate }}% 代理成功率</span>
                </div>
                <p class="panel-copy">{{ deploymentAdvice.summary }}</p>
                <ul class="list-stack info-list">
                  <li v-for="point in deploymentAdvice.points" :key="point" class="list-card info-card">
                    <p>{{ point }}</p>
                  </li>
                </ul>
              </article>

              <article class="panel">
                <div class="panel-header">
                  <div>
                    <p class="eyebrow">Blocked Preview</p>
                    <h2>活跃封禁预览</h2>
                  </div>
                  <button class="ghost-button small-button" @click="activeView = 'blocked'">查看全部</button>
                </div>
                <ul class="list-stack compact-stack">
                  <li v-for="item in dashboard.blockedIps.blocked_ips.slice(0, 5)" :key="item.id" class="list-card">
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
                    <p class="eyebrow">Rules Preview</p>
                    <h2>规则预览</h2>
                  </div>
                  <button class="ghost-button small-button" @click="activeView = 'rules'">进入管理</button>
                </div>
                <ul class="list-stack compact-stack">
                  <li v-for="rule in dashboard.rules.rules.slice(0, 5)" :key="rule.id" class="list-card">
                    <div>
                      <strong>{{ rule.name }}</strong>
                      <p>{{ rule.pattern }}</p>
                    </div>
                    <small>{{ rule.layer.toUpperCase() }} · {{ rule.action }}</small>
                  </li>
                </ul>
              </article>
            </section>
          </template>

          <template v-else-if="activeView === 'rules'">
            <section class="admin-two-column">
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
                    <p class="eyebrow">Active Rules</p>
                    <h2>规则列表</h2>
                  </div>
                  <span class="badge">{{ dashboard.rules.rules.length }} 条</span>
                </div>
                <ul class="list-stack compact-stack">
                  <li v-for="rule in dashboard.rules.rules" :key="rule.id" class="list-card action-card">
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
              </article>
            </section>
          </template>

          <template v-else-if="activeView === 'events'">
            <section class="panel-grid admin-single-grid">
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
            </section>
          </template>

          <template v-else-if="activeView === 'blocked'">
            <section class="admin-two-column admin-blocked-grid">
              <article class="panel">
                <div class="panel-header">
                  <div>
                    <p class="eyebrow">Blocked IPs</p>
                    <h2>活跃封禁</h2>
                  </div>
                  <span class="badge">{{ dashboard.blockedIps.total }} 个</span>
                </div>
                <ul class="list-stack">
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
              </article>

              <article class="panel">
                <div class="panel-header">
                  <div>
                    <p class="eyebrow">Blocked Summary</p>
                    <h2>封禁说明</h2>
                  </div>
                </div>
                <ul class="list-stack info-list">
                  <li class="list-card info-card">
                    <p>当前后台已支持手动解除已记录的封禁 IP。</p>
                  </li>
                  <li class="list-card info-card">
                    <p>后续可以在这里增加按时间、来源、原因筛选和批量操作。</p>
                  </li>
                  <li class="list-card info-card">
                    <p>如果后端补全配置接口，这里也适合扩展封禁策略、TTL 和白名单设置。</p>
                  </li>
                </ul>
              </article>
            </section>
          </template>
        </template>
      </section>
    </section>
  </main>
</template>
