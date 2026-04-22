export interface RuleItem {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
  plugin_template_id?: string | null
  response_template?: RuleResponseTemplate | null
}

export interface RuleDraft {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
  plugin_template_id?: string | null
  response_template?: RuleResponseTemplate | null
}

export interface RuleResponseHeader {
  key: string
  value: string
}

export interface RuleResponseTemplate {
  status_code: number
  content_type: string
  body_source: 'inline_text' | 'file' | string
  gzip: boolean
  body_text: string
  body_file_path: string
  headers: RuleResponseHeader[]
}

export interface RuleActionPluginItem {
  plugin_id: string
  name: string
  version: string
  description: string
  enabled: boolean
  installed_at: number
  updated_at: number
}

export interface RuleActionPluginsResponse {
  total: number
  plugins: RuleActionPluginItem[]
}

export interface RuleActionTemplateItem {
  template_id: string
  plugin_id: string
  name: string
  description: string
  layer: string
  action: string
  pattern: string
  severity: string
  response_template: RuleResponseTemplate
  updated_at: number
}

export interface RuleActionTemplatesResponse {
  total: number
  templates: RuleActionTemplateItem[]
}

export interface RuleActionTemplatePreviewResponse {
  template_id: string
  name: string
  content_type: string
  status_code: number
  gzip: boolean
  body_source: string
  body_preview: string
  truncated: boolean
}

export interface ActionIdeaPreset {
  id: string
  title: string
  mood: string
  summary: string
  mechanism: string
  performance: string
  fallback_path: string
  plugin_id: string
  file_name: string
  response_file_path: string
  plugin_name: string
  plugin_description: string
  template_local_id: string
  template_name: string
  template_description: string
  pattern: string
  severity: string
  content_type: string
  status_code: number
  gzip: boolean
  body_source: string
  runtime_body_file_path: string
  headers: RuleResponseHeader[]
  response_content: string
  requires_upload: boolean
  uploaded_file_name?: string | null
  uploaded_file_ready: boolean
  uploaded_body_preview?: string | null
  uploaded_body_preview_notice?: string | null
  uploaded_body_truncated: boolean
  has_overrides: boolean
  updated_at: number
}

export interface ActionIdeaPresetsResponse {
  total: number
  ideas: ActionIdeaPreset[]
}

export interface RulesResponse {
  rules: RuleItem[]
}
