<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import { useFormatters } from '../composables/useFormatters'
import { BellRing, Save, ServerCog, Settings, ShieldCheck } from 'lucide-vue-next'

type NotificationLevel = 'all' | 'critical' | 'blocked_only'

interface SystemSettingsForm {
  gatewayName: string
  autoRefreshSeconds: number
  upstreamEndpoint: string
  apiEndpoint: string
  emergencyMode: boolean
  sqlitePersistence: boolean
  notifyBySound: boolean
  notificationLevel: NotificationLevel
  retainDays: number
  notes: string
}

const { formatTimestamp } = useFormatters()
const settingsSavedAt = ref<number | null>(null)
const error = ref('')

const systemSettings = reactive<SystemSettingsForm>({
  gatewayName: '玄枢防护网关',
  autoRefreshSeconds: 5,
  upstreamEndpoint: '127.0.0.1:8081',
  apiEndpoint: '127.0.0.1:3000',
  emergencyMode: false,
  sqlitePersistence: true,
  notifyBySound: false,
  notificationLevel: 'critical',
  retainDays: 30,
  notes: '建议在变更规则前先观察近 15 分钟的事件趋势，再决定是否启用紧急模式。',
})

const settingsSummary = computed(() => [
  {
    title: '自动刷新',
    value: `${systemSettings.autoRefreshSeconds} 秒`,
    desc: '控制总览数据的轮询频率。',
    icon: BellRing,
  },
  {
    title: '上游目标',
    value: systemSettings.upstreamEndpoint,
    desc: systemSettings.emergencyMode ? '当前处于紧急防护模式。' : '当前按常规转发策略运行。',
    icon: ServerCog,
  },
  {
    title:
      systemSettings.notificationLevel === 'all'
        ? '全部事件'
        : systemSettings.notificationLevel === 'blocked_only'
          ? '仅拦截事件'
          : '仅高风险事件',
    value: systemSettings.gatewayName,
    desc: systemSettings.notifyBySound ? '声音提醒已启用。' : '声音提醒未启用。',
    icon: ShieldCheck,
  },
])

const saveSettings = () => {
  try {
    systemSettings.autoRefreshSeconds = Number.isFinite(systemSettings.autoRefreshSeconds)
      ? Math.min(Math.max(systemSettings.autoRefreshSeconds, 3), 60)
      : 5
    systemSettings.retainDays = Number.isFinite(systemSettings.retainDays)
      ? Math.min(Math.max(systemSettings.retainDays, 1), 365)
      : 30

    localStorage.setItem('waf-system-settings', JSON.stringify(systemSettings))
    settingsSavedAt.value = Math.floor(Date.now() / 1000)
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '系统设置保存失败'
  }
}

onMounted(() => {
  try {
    const stored = localStorage.getItem('waf-system-settings')
    if (stored) {
      Object.assign(systemSettings, JSON.parse(stored))
    }
  } catch {
    // ignore invalid local payload
  }
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="saveSettings"
        class="inline-flex items-center gap-2 rounded-full bg-cyber-accent px-4 py-2 text-xs font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
      >
        <Save :size="14" />
        保存设置
      </button>
    </template>

    <div class="space-y-6">
      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">系统设置</p>
        <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">控制台与运行侧基础参数</h2>
        <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
          设置页现在已经从总览中拆出来了，后续如果要接 Rust API，也会更自然，不会再和监控看板耦在一起。
        </p>
      </section>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <div
          v-for="item in settingsSummary"
          :key="item.title"
          class="rounded-[28px] border border-white/80 bg-white/76 p-5 shadow-[0_14px_38px_rgba(90,60,30,0.07)]"
        >
          <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong">
            <component :is="item.icon" :size="22" />
          </div>
          <p class="mt-4 text-xs tracking-[0.18em] text-cyber-muted">{{ item.title }}</p>
          <p class="mt-2 text-xl font-semibold text-stone-900">{{ item.value }}</p>
          <p class="mt-2 text-sm leading-6 text-stone-700">{{ item.desc }}</p>
        </div>
      </div>

      <div class="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
          <div class="flex items-center gap-3">
            <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong">
              <Settings :size="22" />
            </div>
            <div>
              <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">控制台参数</p>
              <h3 class="mt-1 text-xl font-semibold text-stone-900">基础运行配置</h3>
            </div>
          </div>

          <div class="mt-6 grid gap-5 md:grid-cols-2">
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">网关名称</span>
              <input v-model="systemSettings.gatewayName" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
            </label>
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">自动刷新频率（秒）</span>
              <input v-model.number="systemSettings.autoRefreshSeconds" type="number" min="3" max="60" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
            </label>
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">上游服务地址</span>
              <input v-model="systemSettings.upstreamEndpoint" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
            </label>
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">控制面 API 地址</span>
              <input v-model="systemSettings.apiEndpoint" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
            </label>
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">事件保留天数</span>
              <input v-model.number="systemSettings.retainDays" type="number" min="1" max="365" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
            </label>
            <label class="space-y-2">
              <span class="text-sm text-cyber-muted">通知级别</span>
              <select v-model="systemSettings.notificationLevel" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent">
                <option value="critical">仅高风险事件</option>
                <option value="blocked_only">仅拦截事件</option>
                <option value="all">全部事件</option>
              </select>
            </label>
          </div>

          <div class="mt-6 grid gap-4 md:grid-cols-3">
            <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
              <input v-model="systemSettings.emergencyMode" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
              <span>
                <span class="block text-sm font-medium text-stone-900">紧急模式</span>
                <span class="mt-1 block text-sm leading-6 text-cyber-muted">面向突发攻击时的高敏感运行状态。</span>
              </span>
            </label>
            <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
              <input v-model="systemSettings.sqlitePersistence" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
              <span>
                <span class="block text-sm font-medium text-stone-900">启用持久化</span>
                <span class="mt-1 block text-sm leading-6 text-cyber-muted">将事件、封禁和规则信息保存在本地数据库。</span>
              </span>
            </label>
            <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
              <input v-model="systemSettings.notifyBySound" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
              <span>
                <span class="block text-sm font-medium text-stone-900">声音提醒</span>
                <span class="mt-1 block text-sm leading-6 text-cyber-muted">在控制台打开期间对关键事件进行即时提示。</span>
              </span>
            </label>
          </div>
        </div>

        <div class="space-y-6">
          <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">设置说明</p>
            <h3 class="mt-2 text-xl font-semibold text-stone-900">当前页面先保存到浏览器本地</h3>
            <p class="mt-4 text-sm leading-7 text-stone-700">
              保存后会写入浏览器本地存储，适合先把交互和页面结构稳定下来。后续如果你要接真实后端配置接口，我们可以直接在这个独立页面上继续扩展。
            </p>
          </div>

          <div class="rounded-[32px] border border-white/80 bg-[linear-gradient(160deg,rgba(247,239,225,0.92),rgba(255,255,255,0.84))] p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">值守备注</p>
            <textarea
              v-model="systemSettings.notes"
              rows="8"
              class="mt-4 w-full rounded-[24px] border border-cyber-border bg-white px-4 py-4 outline-none transition focus:border-cyber-accent"
            ></textarea>
            <p class="mt-3 text-xs leading-6 text-cyber-muted">
              {{ settingsSavedAt ? `最近保存：${formatTimestamp(settingsSavedAt)}` : '尚未保存本地设置' }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
