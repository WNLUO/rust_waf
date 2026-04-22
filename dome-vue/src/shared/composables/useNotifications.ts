import { reactive, watch, type Ref } from 'vue'

export type NotificationTone = 'success' | 'error' | 'info' | 'warning'

export interface NotificationItem {
  id: number
  title: string
  message: string
  tone: NotificationTone
  duration: number
}

interface NotifyOptions {
  title?: string
  tone?: NotificationTone
  duration?: number
}

interface FlashMessageOptions {
  error?: Ref<string>
  success?: Ref<string>
  errorDuration?: number
  successDuration?: number
  errorTitle?: string
  successTitle?: string
}

const notifications = reactive<NotificationItem[]>([])
let nextNotificationId = 1

function removeNotification(id: number) {
  const index = notifications.findIndex((item) => item.id === id)
  if (index >= 0) {
    notifications.splice(index, 1)
  }
}

function notify(message: string, options: NotifyOptions = {}) {
  const normalized = message.trim()
  if (!normalized) return

  const item: NotificationItem = {
    id: nextNotificationId += 1,
    title: options.title ?? defaultTitle(options.tone ?? 'info'),
    message: normalized,
    tone: options.tone ?? 'info',
    duration: options.duration ?? 3200,
  }

  notifications.push(item)
  window.setTimeout(() => removeNotification(item.id), item.duration)
}

function defaultTitle(tone: NotificationTone) {
  switch (tone) {
    case 'success':
      return '操作成功'
    case 'error':
      return '操作失败'
    case 'warning':
      return '需要注意'
    default:
      return '系统提示'
  }
}

export function useNotifications() {
  return {
    notifications,
    notify,
    notifySuccess: (message: string, options: Omit<NotifyOptions, 'tone'> = {}) =>
      notify(message, { ...options, tone: 'success' }),
    notifyError: (message: string, options: Omit<NotifyOptions, 'tone'> = {}) =>
      notify(message, { ...options, tone: 'error' }),
    notifyInfo: (message: string, options: Omit<NotifyOptions, 'tone'> = {}) =>
      notify(message, { ...options, tone: 'info' }),
    notifyWarning: (message: string, options: Omit<NotifyOptions, 'tone'> = {}) =>
      notify(message, { ...options, tone: 'warning' }),
    removeNotification,
  }
}

export function useFlashMessages(options: FlashMessageOptions) {
  const { notifyError, notifySuccess } = useNotifications()

  if (options.error) {
    watch(options.error, (value, previous) => {
      if (!value || value === previous) return
      notifyError(value, {
        title: options.errorTitle,
        duration: options.errorDuration ?? 5200,
      })
    })
  }

  if (options.success) {
    watch(options.success, (value, previous) => {
      if (!value || value === previous) return
      notifySuccess(value, {
        title: options.successTitle,
        duration: options.successDuration ?? 3000,
      })
    })
  }
}
