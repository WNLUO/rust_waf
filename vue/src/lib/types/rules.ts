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

export interface RulesResponse {
  rules: RuleItem[]
}
