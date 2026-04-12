impl SqliteStore {
    pub async fn seed_rules(&self, rules: &[Rule]) -> Result<usize> {
        let mut inserted = 0usize;

        for rule in rules {
            let result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO rules (
                    id, name, enabled, layer, pattern, action, severity, plugin_template_id, response_template_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&rule.id)
            .bind(&rule.name)
            .bind(rule.enabled)
            .bind(rule.layer.as_str())
            .bind(&rule.pattern)
            .bind(rule.action.as_str())
            .bind(rule.severity.as_str())
            .bind(&rule.plugin_template_id)
            .bind(serialize_rule_response_template(rule.response_template.as_ref())?)
            .bind(unix_timestamp())
            .execute(&self.pool)
            .await?;

            inserted += result.rows_affected() as usize;
        }

        Ok(inserted)
    }

    pub async fn load_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, StoredRuleRow>(
            r#"
            SELECT id, name, enabled, layer, pattern, action, severity, plugin_template_id, response_template_json
            FROM rules
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_rule_action_plugins(&self) -> Result<Vec<RuleActionPluginEntry>> {
        sqlx::query_as::<_, RuleActionPluginEntry>(
            r#"
            SELECT plugin_id, name, version, description, enabled, installed_at, updated_at
            FROM rule_action_plugins
            ORDER BY plugin_id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_rule_action_templates(&self) -> Result<Vec<RuleActionTemplateEntry>> {
        sqlx::query_as::<_, RuleActionTemplateEntry>(
            r#"
            SELECT t.template_id, t.plugin_id, t.name, t.description, t.layer, t.action, t.pattern, t.severity, t.response_template_json, t.updated_at
            FROM rule_action_templates t
            INNER JOIN rule_action_plugins p ON p.plugin_id = t.plugin_id
            WHERE p.enabled = 1
            ORDER BY t.plugin_id ASC, t.template_id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn get_rule_action_template(
        &self,
        template_id: &str,
    ) -> Result<Option<RuleActionTemplateEntry>> {
        sqlx::query_as::<_, RuleActionTemplateEntry>(
            r#"
            SELECT t.template_id, t.plugin_id, t.name, t.description, t.layer, t.action, t.pattern, t.severity, t.response_template_json, t.updated_at
            FROM rule_action_templates t
            INNER JOIN rule_action_plugins p ON p.plugin_id = t.plugin_id
            WHERE p.enabled = 1 AND t.template_id = ?
            "#,
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_rule_action_plugin(&self, plugin: &RuleActionPluginUpsert) -> Result<()> {
        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO rule_action_plugins (plugin_id, name, version, description, enabled, installed_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(plugin_id) DO UPDATE SET
                name = excluded.name,
                version = excluded.version,
                description = excluded.description,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&plugin.plugin_id)
        .bind(&plugin.name)
        .bind(&plugin.version)
        .bind(&plugin.description)
        .bind(plugin.enabled)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn replace_rule_action_templates(
        &self,
        plugin_id: &str,
        templates: &[RuleActionTemplateUpsert],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM rule_action_templates WHERE plugin_id = ?")
            .bind(plugin_id)
            .execute(&mut *tx)
            .await?;

        let now = unix_timestamp();
        for template in templates {
            sqlx::query(
                r#"
                INSERT INTO rule_action_templates (
                    template_id, plugin_id, name, description, layer, action, pattern, severity, response_template_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&template.template_id)
            .bind(&template.plugin_id)
            .bind(&template.name)
            .bind(&template.description)
            .bind(&template.layer)
            .bind(&template.action)
            .bind(&template.pattern)
            .bind(&template.severity)
            .bind(serde_json::to_string(&template.response_template)?)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_action_idea_overrides(&self) -> Result<Vec<ActionIdeaOverrideEntry>> {
        sqlx::query_as::<_, ActionIdeaOverrideEntry>(
            r#"
            SELECT idea_id, title, status_code, content_type, response_content, body_file_path, uploaded_file_name, updated_at
            FROM action_idea_overrides
            ORDER BY idea_id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_action_idea_override(
        &self,
        override_entry: &ActionIdeaOverrideUpsert,
    ) -> Result<()> {
        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO action_idea_overrides (idea_id, title, status_code, content_type, response_content, body_file_path, uploaded_file_name, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(idea_id) DO UPDATE SET
                title = excluded.title,
                status_code = excluded.status_code,
                content_type = excluded.content_type,
                response_content = excluded.response_content,
                body_file_path = excluded.body_file_path,
                uploaded_file_name = excluded.uploaded_file_name,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&override_entry.idea_id)
        .bind(&override_entry.title)
        .bind(override_entry.status_code)
        .bind(&override_entry.content_type)
        .bind(&override_entry.response_content)
        .bind(&override_entry.body_file_path)
        .bind(&override_entry.uploaded_file_name)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn set_rule_action_plugin_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let now = unix_timestamp();
        let result = sqlx::query(
            r#"
            UPDATE rule_action_plugins
            SET enabled = ?, updated_at = ?
            WHERE plugin_id = ?
            "#,
        )
        .bind(enabled)
        .bind(now)
        .bind(plugin_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        if !enabled {
            sqlx::query(
                r#"
                UPDATE rules
                SET enabled = 0, updated_at = ?
                WHERE plugin_template_id LIKE ?
                "#,
            )
            .bind(now)
            .bind(format!("{}:%", plugin_id))
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_rule_action_plugin(&self, plugin_id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let now = unix_timestamp();
        sqlx::query(
            r#"
            UPDATE rules
            SET enabled = 0, plugin_template_id = NULL, updated_at = ?
            WHERE plugin_template_id LIKE ?
            "#,
        )
        .bind(now)
        .bind(format!("{}:%", plugin_id))
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query("DELETE FROM rule_action_plugins WHERE plugin_id = ?")
            .bind(plugin_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

}
