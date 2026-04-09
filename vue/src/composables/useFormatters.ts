const severityMap: Record<string, string> = {
  low: '低',
  medium: '中',
  high: '高',
  critical: '紧急',
}

const actionMap: Record<string, string> = {
  block: '拦截',
  allow: '放行',
  alert: '告警',
  log: '记录',
}

const layerMap: Record<string, string> = {
  l4: '四层',
  l7: '七层',
}

export function useFormatters() {
  const formatBytes = (bytes = 0) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  }

  const formatNumber = (value = 0) => value.toLocaleString('zh-CN')

  const formatLatency = (micros = 0) => {
    if (micros < 1000) return `${micros} 微秒`
    return `${(micros / 1000).toFixed(2)} 毫秒`
  }

  const formatTimestamp = (timestamp?: number | null) => {
    if (!timestamp) return '暂无'
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(timestamp * 1000))
  }

  const timeRemaining = (expiresAt?: number | null) => {
    if (!expiresAt) return '未知'
    const diff = expiresAt * 1000 - Date.now()
    if (diff <= 0) return '已过期'
    const minutes = Math.floor(diff / 60000)
    if (minutes < 60) return `${minutes} 分钟`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours} 小时`
    const days = Math.floor(hours / 24)
    return `${days} 天`
  }

  const severityLabel = (severity: string) => severityMap[severity] || severity
  const actionLabel = (action: string) => actionMap[action] || action
  const layerLabel = (layer: string) => layerMap[layer] || layer

  return {
    formatBytes,
    formatNumber,
    formatLatency,
    formatTimestamp,
    timeRemaining,
    severityLabel,
    actionLabel,
    layerLabel,
  }
}
