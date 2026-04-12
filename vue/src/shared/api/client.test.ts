import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  clearAdminApiToken,
  getAdminApiToken,
  setAdminApiToken,
} from './client'

type StorageMap = Map<string, string>

function createLocalStorage(store: StorageMap) {
  return {
    getItem(key: string) {
      return store.get(key) ?? null
    },
    setItem(key: string, value: string) {
      store.set(key, value)
    },
    removeItem(key: string) {
      store.delete(key)
    },
  }
}

describe('admin api token helpers', () => {
  const originalWindow = globalThis.window

  beforeEach(() => {
    const store = new Map<string, string>()
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: {
        localStorage: createLocalStorage(store),
      },
    })
  })

  afterEach(() => {
    Object.defineProperty(globalThis, 'window', {
      configurable: true,
      value: originalWindow,
    })
  })

  it('persists trimmed bearer tokens', () => {
    setAdminApiToken('  demo-token  ')
    expect(getAdminApiToken()).toBe('demo-token')
  })

  it('clears persisted bearer tokens', () => {
    setAdminApiToken('demo-token')
    clearAdminApiToken()
    expect(getAdminApiToken()).toBe('')
  })
})
