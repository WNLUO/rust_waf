import type { ActionIdeaPreset } from '@/shared/types'

export function isInlineJsIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'inline-js' || idea?.id === 'browser-fingerprint-js'
}

export function isRedirectIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'redirect-302'
}

export function isFakeSqlIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'fake-sql-echo'
}

export function isFakeXssIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'fake-xss-echo'
}

export function isTarpitIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'smart-tarpit'
}

export function isRandomErrorIdea(idea: ActionIdeaPreset | null | undefined) {
  return idea?.id === 'random-error-system'
}
