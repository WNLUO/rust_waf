import type {
  ActionIdeaPreset,
  ActionIdeaPresetsResponse,
  RuleActionPluginsResponse,
  RuleActionTemplatePreviewResponse,
  RuleActionTemplatesResponse,
  RuleDraft,
  RulesResponse,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest, formRequest } from './core'

export function createRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
}

export function updateRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>(
    `/rules/${encodeURIComponent(rule.id)}`,
    {
      method: 'PUT',
      body: JSON.stringify(rule),
    },
  )
}

export function deleteRule(id: string) {
  return apiRequest<WriteStatusResponse>(`/rules/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

export function fetchRulesList() {
  return apiRequest<RulesResponse>('/rules')
}

export function fetchRuleActionPlugins() {
  return apiRequest<RuleActionPluginsResponse>('/rule-action-plugins')
}

export function fetchRuleActionTemplates() {
  return apiRequest<RuleActionTemplatesResponse>('/rule-action-templates')
}

export function fetchRuleActionTemplatePreview(templateId: string) {
  return apiRequest<RuleActionTemplatePreviewResponse>(
    `/rule-action-templates/${encodeURIComponent(templateId)}/preview`,
  )
}

export function fetchActionIdeaPresets() {
  return apiRequest<ActionIdeaPresetsResponse>('/action-idea-presets')
}

export function updateActionIdeaPreset(
  ideaId: string,
  payload: Pick<
    ActionIdeaPreset,
    'title' | 'status_code' | 'content_type' | 'response_content'
  >,
) {
  return apiRequest<ActionIdeaPreset>(
    `/action-idea-presets/${encodeURIComponent(ideaId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
    },
  )
}

export async function uploadActionIdeaGzip(ideaId: string, file: File) {
  const formData = new FormData()
  formData.append('file', file)

  return formRequest<{ idea: ActionIdeaPreset }>(
    `/action-idea-presets/${encodeURIComponent(ideaId)}/upload-gzip`,
    formData,
  )
}

export function installRuleActionPlugin(packageUrl: string, sha256?: string) {
  return apiRequest<WriteStatusResponse>('/rule-action-plugins/install', {
    method: 'POST',
    body: JSON.stringify({ package_url: packageUrl, sha256 }),
  })
}

export async function uploadRuleActionPlugin(file: File, sha256?: string) {
  const formData = new FormData()
  formData.append('package', file)
  if (sha256?.trim()) {
    formData.append('sha256', sha256.trim())
  }

  return formRequest<WriteStatusResponse>('/rule-action-plugins/upload', formData)
}

export function updateRuleActionPlugin(pluginId: string, enabled: boolean) {
  return apiRequest<WriteStatusResponse>(
    `/rule-action-plugins/${encodeURIComponent(pluginId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    },
  )
}

export function deleteRuleActionPlugin(pluginId: string) {
  return apiRequest<WriteStatusResponse>(
    `/rule-action-plugins/${encodeURIComponent(pluginId)}`,
    {
      method: 'DELETE',
    },
  )
}
