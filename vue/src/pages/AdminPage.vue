<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { createRule, deleteRule, fetchDashboardPayload, unblockIp, updateRule } from '../lib/api'
import type { DashboardPayload, RuleDraft, RuleItem } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import MetricWidget from '../components/ui/MetricWidget.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import { 
  Shield, Ban, Plus, 
  Trash2, Edit3, Save, X, RefreshCw,
  HardDrive, Zap, Clock
} from 'lucide-vue-next'

type AdminView = 'overview' | 'rules' | 'events' | 'blocked'

const dashboard = ref<DashboardPayload | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const activeView = ref<AdminView>('overview')
const isRuleModalOpen = ref(false)

const ruleForm = reactive<RuleDraft>({
  id: '',
  name: '',
  enabled: true,
  layer: 'l7',
  pattern: '',
  action: 'block',
  severity: 'high',
})

// Formatting helpers
const formatBytes = (b: number) => {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / (1024 * 1024)).toFixed(1)} MB`
}

const formatNumber = (n: number) => n.toLocaleString()

const formatLatency = (micros: number) => {
  if (micros < 1000) return `${micros} μs`
  return `${(micros / 1000).toFixed(2)} ms`
}

const formatTimestamp = (timestamp: number | null | undefined) => {
  if (!timestamp) return 'N/A'

  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(timestamp * 1000))
}

// Logic from original AdminPage
const fetchData = async () => {
  refreshing.value = true
  try {
    const data = await fetchDashboardPayload()
    dashboard.value = data
    error.value = ''
  } catch (e) {
    error.value = 'Failed to fetch dashboard data'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

onMounted(() => {
  fetchData()
  const timer = setInterval(fetchData, 5000)
  onBeforeUnmount(() => clearInterval(timer))
})

const handleCreateOrUpdateRule = async () => {
  try {
    if (ruleForm.id) {
      await updateRule(ruleForm)
    } else {
      await createRule(ruleForm)
    }
    isRuleModalOpen.value = false
    fetchData()
    Object.assign(ruleForm, { id: '', name: '', pattern: '' })
  } catch (e) {
    alert('Operation failed')
  }
}

const openEditRule = (rule: RuleItem) => {
  Object.assign(ruleForm, {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    layer: rule.layer,
    pattern: rule.pattern,
    action: rule.action,
    severity: rule.severity
  })
  isRuleModalOpen.value = true
}

const handleDeleteRule = async (id: string) => {
  if (!confirm('Are you sure?')) return
  try {
    await deleteRule(id)
    fetchData()
  } catch (e) {
    alert('Delete failed')
  }
}

const handleUnblock = async (id: number) => {
  try {
    await unblockIp(id)
    fetchData()
  } catch (e) {
    alert('Unblock failed')
  }
}
</script>

<template>
  <AppLayout>
    <div v-if="loading" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-4">
        <RefreshCw class="animate-spin text-cyber-accent" :size="32" />
        <p class="font-mono text-xs text-cyber-muted uppercase tracking-widest">Initalizing Core...</p>
      </div>
    </div>

    <div v-else class="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      
      <!-- Top Overview Section (Conditional based on view) -->
      <section v-if="activeView === 'overview'" class="space-y-6">
        <div class="flex justify-between items-end">
          <div>
            <h2 class="text-3xl font-black uppercase tracking-tighter italic">Fleet Overview</h2>
            <p class="text-cyber-muted text-sm font-mono mt-1">Real-time gateway performance metrics</p>
          </div>
          <button @click="fetchData" class="p-2 border border-cyber-border rounded-cyber hover:bg-white/5 transition-all">
            <RefreshCw :size="16" :class="{'animate-spin': refreshing}" />
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricWidget 
            label="Total Packets" 
            :value="formatNumber(dashboard?.metrics.total_packets || 0)" 
            :hint="`Throughput: ${formatBytes(dashboard?.metrics.total_bytes || 0)}`"
            :icon="Zap"
          />
          <MetricWidget 
            label="Blocked" 
            :value="formatNumber(dashboard?.metrics.blocked_packets || 0)" 
            :hint="`L4: ${dashboard?.metrics.blocked_l4} / L7: ${dashboard?.metrics.blocked_l7}`"
            :icon="Ban"
            trend="up"
          />
          <MetricWidget 
            label="Avg Latency" 
            :value="formatLatency(dashboard?.metrics.average_proxy_latency_micros || 0)" 
            hint="Fail-close rate: 0.02%"
            :icon="Clock"
            trend="down"
          />
          <MetricWidget 
            label="Active Rules" 
            :value="dashboard?.metrics.active_rules || 0" 
            :hint="`Persisted: ${dashboard?.metrics.persisted_rules}`"
            :icon="Shield"
          />
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <CyberCard title="Upstream Health" class="lg:col-span-2">
            <div class="space-y-6">
              <div class="flex items-center justify-between p-4 bg-white/5 rounded-cyber border border-white/5">
                <div class="flex items-center gap-4">
                  <div class="p-3 bg-cyber-success/20 rounded-full">
                    <HardDrive class="text-cyber-success" :size="20" />
                  </div>
                  <div>
                    <h4 class="font-bold text-sm">Primary Load Balancer</h4>
                    <p class="text-xs text-cyber-muted font-mono">10.0.42.101:443</p>
                  </div>
                </div>
                <StatusBadge :text="dashboard?.health.upstream_healthy ? 'Healthy' : 'Critical'" :type="dashboard?.health.upstream_healthy ? 'success' : 'error'" />
              </div>

              <div class="grid grid-cols-3 gap-4">
                <div class="p-4 border border-cyber-border rounded-cyber">
                  <p class="text-[10px] text-cyber-muted uppercase font-mono mb-1">Success Rate</p>
                  <p class="text-xl font-bold font-mono text-cyber-success">99.8%</p>
                </div>
                <div class="p-4 border border-cyber-border rounded-cyber">
                  <p class="text-[10px] text-cyber-muted uppercase font-mono mb-1">Active Conns</p>
                  <p class="text-xl font-bold font-mono text-cyber-accent">1,242</p>
                </div>
                <div class="p-4 border border-cyber-border rounded-cyber">
                  <p class="text-[10px] text-cyber-muted uppercase font-mono mb-1">Handshake Time</p>
                  <p class="text-xl font-bold font-mono text-gray-200">12ms</p>
                </div>
              </div>
            </div>
          </CyberCard>

          <CyberCard title="System Log" noPadding>
            <div class="font-mono text-[10px] leading-relaxed p-4 h-[220px] overflow-y-auto scrollbar-thin scrollbar-thumb-cyber-border">
              <div v-for="i in 10" :key="i" class="mb-2 text-cyber-muted">
                <span class="text-cyber-accent">[09:24:0{{i}}]</span>
                <span class="ml-2">INF: L7_ENGINE_RELOAD_COMPLETE</span>
                <br/>
                <span class="text-cyber-success opacity-50">>>> Syncing with SQLite shard...</span>
              </div>
            </div>
          </CyberCard>
        </div>
      </section>

      <!-- View Navigation (Sub-tabs) -->
      <div class="flex gap-4 border-b border-cyber-border pb-4">
        <button 
          v-for="v in (['overview', 'rules', 'events', 'blocked'] as AdminView[])" 
          :key="v"
          @click="activeView = v"
          class="px-6 py-2 text-xs font-mono uppercase tracking-widest transition-all relative"
          :class="activeView === v ? 'text-cyber-accent' : 'text-cyber-muted hover:text-gray-200'"
        >
          {{ v }}
          <div v-if="activeView === v" class="absolute bottom-[-17px] left-0 right-0 h-0.5 bg-cyber-accent shadow-[0_0_10px_rgba(124,58,237,0.5)]"></div>
        </button>
      </div>

      <!-- Rules View -->
      <section v-if="activeView === 'rules'" class="space-y-6">
        <div class="flex justify-between items-center">
          <h2 class="text-xl font-bold uppercase tracking-tight">Security Policies</h2>
          <button @click="isRuleModalOpen = true" class="px-4 py-2 bg-cyber-accent rounded-cyber text-xs font-bold flex items-center gap-2 hover:shadow-cyber transition-all">
            <Plus :size="16" />
            New Rule
          </button>
        </div>

        <div class="bg-cyber-surface border border-cyber-border rounded-cyber overflow-hidden">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="border-b border-cyber-border bg-white/5 font-mono text-[10px] uppercase tracking-widest text-cyber-muted">
                <th class="px-6 py-4">Status</th>
                <th class="px-6 py-4">Rule Name</th>
                <th class="px-6 py-4">Layer</th>
                <th class="px-6 py-4">Pattern</th>
                <th class="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="text-sm">
              <tr v-for="rule in dashboard?.rules.rules" :key="rule.id" class="border-b border-cyber-border/50 hover:bg-white/5 transition-colors group">
                <td class="px-6 py-4">
                  <div class="w-2 h-2 rounded-full" :class="rule.enabled ? 'bg-cyber-success shadow-[0_0_8px_rgba(0,255,170,0.4)]' : 'bg-cyber-muted'"></div>
                </td>
                <td class="px-6 py-4 font-bold">{{ rule.name }}</td>
                <td class="px-6 py-4">
                  <span class="px-2 py-0.5 bg-white/5 border border-white/10 rounded text-[10px] font-mono uppercase">{{ rule.layer }}</span>
                </td>
                <td class="px-6 py-4 font-mono text-xs text-cyber-muted">{{ rule.pattern }}</td>
                <td class="px-6 py-4 text-right">
                  <div class="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button @click="openEditRule(rule)" class="p-2 hover:text-cyber-accent transition-colors">
                      <Edit3 :size="16" />
                    </button>
                    <button @click="handleDeleteRule(rule.id)" class="p-2 hover:text-cyber-error transition-colors">
                      <Trash2 :size="16" />
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Events View -->
      <section v-if="activeView === 'events'" class="space-y-6">
        <div class="bg-cyber-surface border border-cyber-border rounded-cyber overflow-hidden">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="border-b border-cyber-border bg-white/5 font-mono text-[10px] uppercase tracking-widest text-cyber-muted">
                <th class="px-6 py-4">Timestamp</th>
                <th class="px-6 py-4">Severity</th>
                <th class="px-6 py-4">Source</th>
                <th class="px-6 py-4">Rule</th>
                <th class="px-6 py-4">Action</th>
              </tr>
            </thead>
            <tbody class="text-sm font-mono">
              <tr v-for="event in dashboard?.events.events" :key="event.id" class="border-b border-cyber-border/50 hover:bg-white/5 transition-colors">
                <td class="px-6 py-4 text-cyber-muted text-xs">{{ formatTimestamp(event.created_at) }}</td>
                <td class="px-6 py-4">
                  <StatusBadge :text="event.layer.toUpperCase()" :type="event.action === 'block' ? 'error' : 'warning'" compact />
                </td>
                <td class="px-6 py-4 text-cyber-accent">{{ event.source_ip }}</td>
                <td class="px-6 py-4">{{ event.reason }}</td>
                <td class="px-6 py-4 italic">{{ event.action }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Blocked IPs View -->
      <section v-if="activeView === 'blocked'" class="space-y-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div v-for="ip in dashboard?.blockedIps.blocked_ips" :key="ip.id" class="p-6 bg-cyber-surface border border-cyber-border rounded-cyber group hover:border-cyber-error/30 transition-all">
            <div class="flex justify-between items-start mb-4">
              <div class="p-2 bg-cyber-error/10 rounded-cyber">
                <Ban class="text-cyber-error" :size="20" />
              </div>
              <button @click="handleUnblock(ip.id)" class="text-[10px] font-mono uppercase text-cyber-muted hover:text-cyber-success transition-colors">
                Release IP
              </button>
            </div>
            <h4 class="text-xl font-bold font-mono mb-1">{{ ip.ip }}</h4>
            <p class="text-xs text-cyber-muted mb-4">Blocked until: {{ formatTimestamp(ip.expires_at) }}</p>
            <div class="pt-4 border-t border-cyber-border/30">
              <p class="text-[10px] text-cyber-muted uppercase font-mono mb-2">Reason</p>
              <p class="text-xs italic">{{ ip.reason }}</p>
            </div>
          </div>
        </div>
      </section>

    </div>

    <!-- Rule Modal (Drawer Style) -->
    <div v-if="isRuleModalOpen" class="fixed inset-0 z-[100] flex justify-end">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="isRuleModalOpen = false"></div>
      <div class="relative w-full max-w-md bg-cyber-surface border-l border-cyber-border h-full shadow-2xl p-8 animate-in slide-in-from-right duration-300">
        <div class="flex justify-between items-center mb-8">
          <h3 class="text-xl font-black uppercase italic tracking-tight">{{ ruleForm.id ? 'Edit Policy' : 'Create Policy' }}</h3>
          <button @click="isRuleModalOpen = false" class="p-2 hover:bg-white/5 rounded-full transition-all">
            <X :size="20" />
          </button>
        </div>

        <form @submit.prevent="handleCreateOrUpdateRule" class="space-y-6">
          <div class="space-y-2">
            <label class="text-[10px] font-mono uppercase tracking-widest text-cyber-muted">Policy Name</label>
            <input v-model="ruleForm.name" type="text" class="w-full bg-cyber-bg border border-cyber-border rounded-cyber p-3 text-sm focus:border-cyber-accent outline-none transition-all" placeholder="e.g. SQL Injection Filter" required />
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-2">
              <label class="text-[10px] font-mono uppercase tracking-widest text-cyber-muted">Layer</label>
              <select v-model="ruleForm.layer" class="w-full bg-cyber-bg border border-cyber-border rounded-cyber p-3 text-sm focus:border-cyber-accent outline-none appearance-none">
                <option value="l4">Layer 4 (IP/Port)</option>
                <option value="l7">Layer 7 (HTTP)</option>
              </select>
            </div>
            <div class="space-y-2">
              <label class="text-[10px] font-mono uppercase tracking-widest text-cyber-muted">Severity</label>
              <select v-model="ruleForm.severity" class="w-full bg-cyber-bg border border-cyber-border rounded-cyber p-3 text-sm focus:border-cyber-accent outline-none appearance-none">
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-[10px] font-mono uppercase tracking-widest text-cyber-muted">Pattern (Regex or CIDR)</label>
            <textarea v-model="ruleForm.pattern" rows="4" class="w-full bg-cyber-bg border border-cyber-border rounded-cyber p-3 text-sm font-mono focus:border-cyber-accent outline-none transition-all" placeholder="(?i)(union|select|insert|update|delete|drop)..." required></textarea>
          </div>

          <div class="flex items-center gap-3 p-4 bg-white/5 border border-white/5 rounded-cyber">
            <input type="checkbox" v-model="ruleForm.enabled" id="rule-enabled" class="w-4 h-4 accent-cyber-accent" />
            <label for="rule-enabled" class="text-sm font-medium">Activate this policy immediately</label>
          </div>

          <div class="pt-8">
            <button type="submit" class="w-full py-4 bg-cyber-accent text-white font-black uppercase tracking-widest rounded-cyber hover:shadow-cyber transition-all flex items-center justify-center gap-2">
              <Save :size="18" />
              Save Configuration
            </button>
          </div>
        </form>
      </div>
    </div>

  </AppLayout>
</template>

<style>
/* Global scrollbar for cyber look */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: #0a0a0a;
}
::-webkit-scrollbar-thumb {
  background: #2a2a2a;
  border-radius: 10px;
}
::-webkit-scrollbar-thumb:hover {
  background: #3a3a3a;
}

.animate-in {
  animation-duration: 500ms;
}
</style>
