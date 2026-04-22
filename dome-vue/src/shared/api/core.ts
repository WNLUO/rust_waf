import type { ApiQueryValue } from '@/shared/types'

export const API_BASE = '/api'
export const ADMIN_TOKEN_STORAGE_KEY = 'waf-admin-api-token'

export type QueryParams = Record<string, ApiQueryValue>

export function getAuthHeaders() {
  if (typeof window === 'undefined') return {} as HeadersInit
  const token = window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY)?.trim()
  return token
    ? ({ Authorization: `Bearer ${token}` } satisfies HeadersInit)
    : ({} as HeadersInit)
}

async function readErrorMessage(response: Response) {
  let message = `请求失败：${response.status}`

  try {
    const payload = (await response.json()) as { error?: string }
    if (payload.error) {
      message = payload.error
    }
  } catch {
    // Keep fallback message.
  }

  return message
}

export async function apiRequest<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
      ...(init?.headers ?? {}),
    },
    ...init,
  })

  if (!response.ok) {
    throw new Error(await readErrorMessage(response))
  }

  return (await response.json()) as T
}

export async function formRequest<T>(
  path: string,
  formData: FormData,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: init?.method ?? 'POST',
    headers: {
      ...getAuthHeaders(),
      ...(init?.headers ?? {}),
    },
    body: formData,
    ...init,
  })

  if (!response.ok) {
    throw new Error(await readErrorMessage(response))
  }

  return (await response.json()) as T
}

export function buildQuery(params?: QueryParams) {
  if (!params) return ''
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (
      value === undefined ||
      value === null ||
      value === '' ||
      value === 'all'
    ) {
      return
    }
    search.append(key, String(value))
  })
  const query = search.toString()
  return query ? `?${query}` : ''
}

export const withDefaults = <T extends QueryParams>(
  defaults: T,
  overrides?: Partial<T>,
): T => ({
  ...defaults,
  ...(overrides || {}),
})
