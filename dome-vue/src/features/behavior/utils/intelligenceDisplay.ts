import type {
  AiVisitorProfileSignal,
  BehaviorProfileItem,
} from '@/shared/types'

export const PAGE_SIZE = 8

export function totalPages(total: number) {
  return Math.max(1, Math.ceil(total / PAGE_SIZE))
}

export function pageItems<T>(items: T[], page: number) {
  const start = (page - 1) * PAGE_SIZE
  return items.slice(start, start + PAGE_SIZE)
}

export function pageStart(page: number, total: number) {
  if (!total) return 0
  return (page - 1) * PAGE_SIZE + 1
}

export function pageEnd(page: number, total: number) {
  return Math.min(page * PAGE_SIZE, total)
}

export function clampPage(page: number, pages: number) {
  return Math.min(Math.max(page, 1), pages)
}

export function actionType(action: string | null) {
  if (action === 'block') return 'error' as const
  if (action === 'challenge') return 'warning' as const
  if (action?.startsWith('delay')) return 'info' as const
  return 'muted' as const
}

export function actionLabel(action: string | null) {
  if (action === 'block') return '已封禁'
  if (action === 'challenge') return '已挑战'
  if (action?.startsWith('delay')) return '已延迟'
  if (action) return action
  return '已记录'
}

export function currentStateType(profile: BehaviorProfileItem | undefined) {
  if (!profile) return 'muted' as const
  if (profile.blocked) return 'error' as const
  if (profile.score >= 60) return 'warning' as const
  if (profile.score >= 20) return 'info' as const
  return 'success' as const
}

export function currentStateLabel(profile: BehaviorProfileItem | undefined) {
  if (!profile) return '当前不活跃'
  if (profile.blocked) return '当前封禁中'
  if (profile.score >= 60) return '当前高风险'
  if (profile.score >= 20) return '当前观察中'
  return '当前正常'
}

export function aiVisitorStateType(profile: AiVisitorProfileSignal) {
  if (profile.tracking_priority === 'high') return 'warning' as const
  if (profile.false_positive_risk === 'high') return 'success' as const
  if (profile.human_confidence >= 75) return 'success' as const
  if (profile.automation_risk >= 50 || profile.probe_risk >= 45) {
    return 'warning' as const
  }
  return 'info' as const
}

export function aiVisitorStateLabel(profile: AiVisitorProfileSignal) {
  if (profile.state === 'trusted_session') return '可信会话'
  if (profile.state === 'admin_session') return '后台会话'
  if (profile.state === 'suspected_probe') return '疑似探测'
  if (profile.state === 'suspected_crawler') return '疑似自动化'
  if (profile.state === 'suspected_abuse') return '疑似滥用'
  if (profile.state === 'challenged') return '已挑战'
  return '观察中'
}

export function aiDecisionType(action: string) {
  if (action === 'increase_challenge') return 'warning' as const
  if (action === 'watch_visitor') return 'info' as const
  if (action === 'reduce_friction' || action === 'mark_trusted_temporarily') {
    return 'success' as const
  }
  return 'muted' as const
}

export function aiDecisionLabel(action: string) {
  if (action === 'increase_challenge') return '提高挑战'
  if (action === 'watch_visitor') return '持续跟踪'
  if (action === 'reduce_friction') return '降低摩擦'
  if (action === 'mark_trusted_temporarily') return '临时可信'
  return action
}

export function aiBusinessTypes(profile: AiVisitorProfileSignal) {
  return Object.entries(profile.business_route_types)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
}

export function aiTopRoutes(profile: AiVisitorProfileSignal) {
  return profile.route_summary.slice(0, 3)
}
