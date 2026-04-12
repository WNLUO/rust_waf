import type {
  RuleActionTemplateItem,
  RuleDraft,
  RuleItem,
  RuleResponseTemplate,
} from '@/features/rules/types/rules'

export function createDefaultResponseTemplate(): RuleResponseTemplate {
  return {
    status_code: 403,
    content_type: 'text/html; charset=utf-8',
    body_source: 'inline_text',
    gzip: true,
    body_text: '',
    body_file_path: '',
    headers: [],
  }
}

export function createDefaultRuleDraft(): RuleDraft {
  return {
    id: '',
    name: '',
    enabled: true,
    layer: 'l7',
    pattern: '',
    action: 'block',
    severity: 'high',
    plugin_template_id: null,
    response_template: createDefaultResponseTemplate(),
  }
}

export function isPluginActionValue(value: string) {
  return value.startsWith('plugin:')
}

export function toPluginActionValue(templateId: string) {
  return `plugin:${templateId}`
}

export function cloneResponseTemplate(
  template?: RuleResponseTemplate | null,
): RuleResponseTemplate {
  if (!template) return createDefaultResponseTemplate()

  return {
    ...template,
    headers: [...template.headers],
  }
}

export function createEditableRuleDraft(rule: RuleItem): RuleDraft {
  return {
    ...rule,
    action: rule.plugin_template_id
      ? toPluginActionValue(rule.plugin_template_id)
      : rule.action,
    plugin_template_id: rule.plugin_template_id ?? null,
    response_template: cloneResponseTemplate(rule.response_template),
  }
}

export function buildRulePayload(
  ruleForm: RuleDraft,
  pluginTemplates: RuleActionTemplateItem[],
): RuleDraft {
  const pluginTemplate = ruleForm.plugin_template_id
    ? (pluginTemplates.find(
        (item) => item.template_id === ruleForm.plugin_template_id,
      ) ?? null)
    : null
  const isPluginAction = isPluginActionValue(ruleForm.action)

  return {
    ...ruleForm,
    action: isPluginAction ? 'respond' : ruleForm.action,
    layer: pluginTemplate?.layer || ruleForm.layer,
    severity: pluginTemplate?.severity || ruleForm.severity,
    pattern: pluginTemplate?.pattern || ruleForm.pattern,
    plugin_template_id: pluginTemplate?.template_id || null,
    response_template:
      (pluginTemplate?.layer || ruleForm.layer) === 'l7' &&
      ((isPluginAction && pluginTemplate) || ruleForm.action === 'respond')
        ? {
            status_code: Number(
              pluginTemplate?.response_template.status_code ||
                ruleForm.response_template?.status_code ||
                403,
            ),
            content_type:
              pluginTemplate?.response_template.content_type ||
              ruleForm.response_template?.content_type ||
              'text/html; charset=utf-8',
            body_source:
              pluginTemplate?.response_template.body_source ||
              ruleForm.response_template?.body_source ||
              'inline_text',
            gzip: Boolean(
              pluginTemplate?.response_template.gzip ??
              ruleForm.response_template?.gzip,
            ),
            body_text:
              pluginTemplate?.response_template.body_text ||
              ruleForm.response_template?.body_text ||
              '',
            body_file_path:
              pluginTemplate?.response_template.body_file_path ||
              ruleForm.response_template?.body_file_path?.trim() ||
              '',
            headers: (
              pluginTemplate?.response_template.headers ||
              ruleForm.response_template?.headers ||
              []
            ).filter((item) => item.key.trim()),
          }
        : null,
  }
}

export function applyPluginTemplateToDraft(
  ruleForm: RuleDraft,
  template: RuleActionTemplateItem,
): RuleDraft {
  return {
    ...ruleForm,
    plugin_template_id: template.template_id,
    layer: template.layer,
    pattern: template.pattern,
    severity: template.severity,
    response_template: cloneResponseTemplate(template.response_template),
  }
}
