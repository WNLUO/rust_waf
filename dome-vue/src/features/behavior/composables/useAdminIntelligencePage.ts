import { computed, onMounted, ref, watch } from 'vue'
import { fetchAiVisitorProfiles } from '@/shared/api/dashboard'
import {
  fetchBehaviorProfiles,
  fetchBehaviorSessions,
  fetchFingerprintProfiles,
} from '@/shared/api/events'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import { useAdminRealtimeState } from '@/shared/realtime/adminRealtime'
import {
  clampPage,
  pageItems,
  totalPages,
} from '@/features/behavior/utils/intelligenceDisplay'
import type {
  AiVisitorIntelligenceResponse,
  BehaviorProfileItem,
  BehaviorSessionItem,
  FingerprintProfileItem,
} from '@/shared/types'

export type IntelligenceTab = 'fingerprints' | 'sessions'

export function useAdminIntelligencePage() {
  const loading = ref(true)
  const refreshing = ref(false)
  const error = ref('')
  const tab = ref<IntelligenceTab>('fingerprints')
  const livePage = ref(1)
  const fingerprintPage = ref(1)
  const sessionPage = ref(1)
  const lastUpdated = ref<number | null>(null)
  const fingerprintProfiles = ref<FingerprintProfileItem[]>([])
  const behaviorSessions = ref<BehaviorSessionItem[]>([])
  const liveProfiles = ref<BehaviorProfileItem[]>([])
  const aiVisitorIntelligence =
    ref<AiVisitorIntelligenceResponse | null>(null)
  const realtimeState = useAdminRealtimeState()

  const { formatNumber, formatTimestamp } = useFormatters()

  useFlashMessages({
    error,
    errorTitle: '智能档案',
    errorDuration: 5600,
  })

  const liveProfilesByIdentity = computed(
    () =>
      new Map(liveProfiles.value.map((profile) => [profile.identity, profile])),
  )

  const currentRiskCount = computed(
    () =>
      liveProfiles.value.filter(
        (profile) => profile.blocked || profile.score >= 60,
      ).length,
  )

  const currentWatchingCount = computed(
    () =>
      liveProfiles.value.filter(
        (profile) =>
          !profile.blocked && profile.score >= 20 && profile.score < 60,
      ).length,
  )

  const currentHealthyCount = computed(
    () =>
      liveProfiles.value.filter(
        (profile) => !profile.blocked && profile.score < 20,
      ).length,
  )

  const aiVisitorProfiles = computed(
    () => aiVisitorIntelligence.value?.profiles ?? [],
  )

  const aiVisitorRecommendations = computed(
    () => aiVisitorIntelligence.value?.recommendations ?? [],
  )

  const aiPriorityVisitors = computed(() =>
    aiVisitorProfiles.value
      .filter(
        (profile) =>
          profile.tracking_priority !== 'low' ||
          profile.false_positive_risk !== 'low' ||
          profile.challenge_js_report_count > 0,
      )
      .slice(0, 6),
  )

  const aiChallengeJsReports = computed(() =>
    aiVisitorProfiles.value.reduce(
      (total, profile) => total + profile.challenge_js_report_count,
      0,
    ),
  )

  const aiAuthRejectedCount = computed(() =>
    aiVisitorProfiles.value.reduce(
      (total, profile) => total + profile.auth_rejected_count,
      0,
    ),
  )

  const aiBusinessTypeCount = computed(() => {
    const types = new Set<string>()
    for (const profile of aiVisitorProfiles.value) {
      for (const key of Object.keys(profile.business_route_types)) {
        types.add(key)
      }
    }
    return types.size
  })

  const liveTotalPages = computed(() => totalPages(liveProfiles.value.length))
  const fingerprintTotalPages = computed(() =>
    totalPages(fingerprintProfiles.value.length),
  )
  const sessionTotalPages = computed(() =>
    totalPages(behaviorSessions.value.length),
  )

  const pagedLiveProfiles = computed(() =>
    pageItems(liveProfiles.value, livePage.value),
  )
  const pagedFingerprintProfiles = computed(() =>
    pageItems(fingerprintProfiles.value, fingerprintPage.value),
  )
  const pagedBehaviorSessions = computed(() =>
    pageItems(behaviorSessions.value, sessionPage.value),
  )

  const statusLabel = computed(() => {
    if (refreshing.value) return '正在同步智能档案...'
    if (realtimeState.connected && lastUpdated.value) {
      return `实时通道已连接：${formatStatusTime(lastUpdated.value)}`
    }
    if (realtimeState.connecting) return '实时通道连接中...'
    if (lastUpdated.value) return `上次刷新：${formatStatusTime(lastUpdated.value)}`
    return '等待首次同步'
  })

  function goToLivePage(page: number) {
    livePage.value = clampPage(page, liveTotalPages.value)
  }

  function goToFingerprintPage(page: number) {
    fingerprintPage.value = clampPage(page, fingerprintTotalPages.value)
  }

  function goToSessionPage(page: number) {
    sessionPage.value = clampPage(page, sessionTotalPages.value)
  }

  function switchTab(nextTab: IntelligenceTab) {
    tab.value = nextTab
    if (nextTab === 'fingerprints') {
      fingerprintPage.value = 1
    } else {
      sessionPage.value = 1
    }
  }

  async function loadPage(showLoader = false) {
    if (showLoader) loading.value = true
    refreshing.value = true
    try {
      const [
        liveProfilesPayload,
        fingerprintsPayload,
        sessionsPayload,
        aiVisitorPayload,
      ] = await Promise.all([
        fetchBehaviorProfiles(),
        fetchFingerprintProfiles(),
        fetchBehaviorSessions(),
        fetchAiVisitorProfiles(),
      ])
      liveProfiles.value = liveProfilesPayload.profiles
      fingerprintProfiles.value = fingerprintsPayload.profiles
      behaviorSessions.value = sessionsPayload.sessions
      aiVisitorIntelligence.value = aiVisitorPayload
      lastUpdated.value = Date.now()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '加载智能档案失败'
    } finally {
      loading.value = false
      refreshing.value = false
    }
  }

  watch(
    () => liveProfiles.value.length,
    () => goToLivePage(livePage.value),
  )

  watch(
    () => fingerprintProfiles.value.length,
    () => goToFingerprintPage(fingerprintPage.value),
  )

  watch(
    () => behaviorSessions.value.length,
    () => goToSessionPage(sessionPage.value),
  )

  onMounted(() => {
    void loadPage(true)
  })

  return {
    loading,
    refreshing,
    tab,
    livePage,
    fingerprintPage,
    sessionPage,
    fingerprintProfiles,
    behaviorSessions,
    liveProfiles,
    aiVisitorIntelligence,
    realtimeState,
    formatNumber,
    formatTimestamp,
    liveProfilesByIdentity,
    currentRiskCount,
    currentWatchingCount,
    currentHealthyCount,
    aiVisitorProfiles,
    aiVisitorRecommendations,
    aiPriorityVisitors,
    aiChallengeJsReports,
    aiAuthRejectedCount,
    aiBusinessTypeCount,
    liveTotalPages,
    fingerprintTotalPages,
    sessionTotalPages,
    pagedLiveProfiles,
    pagedFingerprintProfiles,
    pagedBehaviorSessions,
    statusLabel,
    goToLivePage,
    goToFingerprintPage,
    goToSessionPage,
    switchTab,
    loadPage,
  }
}

function formatStatusTime(value: number) {
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value))
}
