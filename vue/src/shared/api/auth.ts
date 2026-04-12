import { ADMIN_TOKEN_STORAGE_KEY } from './core'

export function getAdminApiToken() {
  if (typeof window === 'undefined') return ''
  return window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) ?? ''
}

export function setAdminApiToken(token: string) {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token.trim())
}

export function clearAdminApiToken() {
  if (typeof window === 'undefined') return
  window.localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY)
}
