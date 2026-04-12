impl SqliteStore {
    pub async fn list_local_sites(&self) -> Result<Vec<LocalSiteEntry>> {
        let rows = sqlx::query_as::<_, LocalSiteEntry>(
            r#"
            SELECT id, name, primary_hostname, hostnames_json, listen_ports_json, upstreams_json,
                   safeline_intercept_json,
                   enabled, tls_enabled, local_certificate_id, source, sync_mode, notes,
                   last_synced_at, created_at, updated_at
            FROM local_sites
            ORDER BY updated_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_local_site(&self, id: i64) -> Result<Option<LocalSiteEntry>> {
        let row = sqlx::query_as::<_, LocalSiteEntry>(
            r#"
            SELECT id, name, primary_hostname, hostnames_json, listen_ports_json, upstreams_json,
                   safeline_intercept_json,
                   enabled, tls_enabled, local_certificate_id, source, sync_mode, notes,
                   last_synced_at, created_at, updated_at
            FROM local_sites
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn insert_local_site(&self, site: &LocalSiteUpsert) -> Result<i64> {
        let now = unix_timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO local_sites (
                name, primary_hostname, hostnames_json, listen_ports_json, upstreams_json,
                safeline_intercept_json,
                enabled, tls_enabled, local_certificate_id, source, sync_mode, notes,
                last_synced_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&site.name)
        .bind(&site.primary_hostname)
        .bind(serialize_string_vec(&site.hostnames)?)
        .bind(serialize_string_vec(&site.listen_ports)?)
        .bind(serialize_string_vec(&site.upstreams)?)
        .bind(
            site.safeline_intercept
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        )
        .bind(site.enabled)
        .bind(site.tls_enabled)
        .bind(site.local_certificate_id)
        .bind(&site.source)
        .bind(&site.sync_mode)
        .bind(&site.notes)
        .bind(site.last_synced_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn update_local_site(&self, id: i64, site: &LocalSiteUpsert) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE local_sites
            SET name = ?,
                primary_hostname = ?,
                hostnames_json = ?,
                listen_ports_json = ?,
                upstreams_json = ?,
                safeline_intercept_json = ?,
                enabled = ?,
                tls_enabled = ?,
                local_certificate_id = ?,
                source = ?,
                sync_mode = ?,
                notes = ?,
                last_synced_at = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&site.name)
        .bind(&site.primary_hostname)
        .bind(serialize_string_vec(&site.hostnames)?)
        .bind(serialize_string_vec(&site.listen_ports)?)
        .bind(serialize_string_vec(&site.upstreams)?)
        .bind(
            site.safeline_intercept
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        )
        .bind(site.enabled)
        .bind(site.tls_enabled)
        .bind(site.local_certificate_id)
        .bind(&site.source)
        .bind(&site.sync_mode)
        .bind(&site.notes)
        .bind(site.last_synced_at)
        .bind(unix_timestamp())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_local_site(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM local_sites WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn clear_site_data(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM safeline_site_mappings")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM site_sync_links")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM local_sites")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM safeline_cached_sites")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_local_certificates(&self) -> Result<Vec<LocalCertificateEntry>> {
        let rows = sqlx::query_as::<_, LocalCertificateEntry>(
            r#"
            SELECT id, name, domains_json, issuer, valid_from, valid_to, source_type,
                   provider_remote_id, provider_remote_domains_json, last_remote_fingerprint,
                   sync_status, sync_message, auto_sync_enabled,
                   trusted, expired, notes, last_synced_at, created_at, updated_at
            FROM local_certificates
            ORDER BY updated_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_local_certificate(&self, id: i64) -> Result<Option<LocalCertificateEntry>> {
        let row = sqlx::query_as::<_, LocalCertificateEntry>(
            r#"
            SELECT id, name, domains_json, issuer, valid_from, valid_to, source_type,
                   provider_remote_id, provider_remote_domains_json, last_remote_fingerprint,
                   sync_status, sync_message, auto_sync_enabled,
                   trusted, expired, notes, last_synced_at, created_at, updated_at
            FROM local_certificates
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn insert_local_certificate(
        &self,
        certificate: &LocalCertificateUpsert,
    ) -> Result<i64> {
        let now = unix_timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO local_certificates (
                name, domains_json, issuer, valid_from, valid_to, source_type,
                provider_remote_id, provider_remote_domains_json, last_remote_fingerprint,
                sync_status, sync_message, auto_sync_enabled,
                trusted, expired, notes, last_synced_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&certificate.name)
        .bind(serialize_string_vec(&certificate.domains)?)
        .bind(&certificate.issuer)
        .bind(certificate.valid_from)
        .bind(certificate.valid_to)
        .bind(&certificate.source_type)
        .bind(&certificate.provider_remote_id)
        .bind(serialize_string_vec(&certificate.provider_remote_domains)?)
        .bind(&certificate.last_remote_fingerprint)
        .bind(&certificate.sync_status)
        .bind(&certificate.sync_message)
        .bind(certificate.auto_sync_enabled)
        .bind(certificate.trusted)
        .bind(certificate.expired)
        .bind(&certificate.notes)
        .bind(certificate.last_synced_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn update_local_certificate(
        &self,
        id: i64,
        certificate: &LocalCertificateUpsert,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE local_certificates
            SET name = ?,
                domains_json = ?,
                issuer = ?,
                valid_from = ?,
                valid_to = ?,
                source_type = ?,
                provider_remote_id = ?,
                provider_remote_domains_json = ?,
                last_remote_fingerprint = ?,
                sync_status = ?,
                sync_message = ?,
                auto_sync_enabled = ?,
                trusted = ?,
                expired = ?,
                notes = ?,
                last_synced_at = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&certificate.name)
        .bind(serialize_string_vec(&certificate.domains)?)
        .bind(&certificate.issuer)
        .bind(certificate.valid_from)
        .bind(certificate.valid_to)
        .bind(&certificate.source_type)
        .bind(&certificate.provider_remote_id)
        .bind(serialize_string_vec(&certificate.provider_remote_domains)?)
        .bind(&certificate.last_remote_fingerprint)
        .bind(&certificate.sync_status)
        .bind(&certificate.sync_message)
        .bind(certificate.auto_sync_enabled)
        .bind(certificate.trusted)
        .bind(certificate.expired)
        .bind(&certificate.notes)
        .bind(certificate.last_synced_at)
        .bind(unix_timestamp())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_local_certificate(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM local_certificates WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_local_certificate_secret(
        &self,
        certificate_id: i64,
    ) -> Result<Option<LocalCertificateSecretEntry>> {
        let row = sqlx::query_as::<_, LocalCertificateSecretEntry>(
            r#"
            SELECT certificate_id, certificate_pem, private_key_pem, updated_at
            FROM local_certificate_secrets
            WHERE certificate_id = ?
            "#,
        )
        .bind(certificate_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_local_certificate_secret(
        &self,
        certificate_id: i64,
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO local_certificate_secrets (
                certificate_id, certificate_pem, private_key_pem, updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(certificate_id) DO UPDATE SET
                certificate_pem = excluded.certificate_pem,
                private_key_pem = excluded.private_key_pem,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(certificate_id)
        .bind(certificate_pem)
        .bind(private_key_pem)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    pub async fn delete_local_certificate_secret(&self, certificate_id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM local_certificate_secrets WHERE certificate_id = ?")
            .bind(certificate_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_site_sync_links(&self) -> Result<Vec<SiteSyncLinkEntry>> {
        let rows = sqlx::query_as::<_, SiteSyncLinkEntry>(
            r#"
            SELECT id, local_site_id, provider, remote_site_id, remote_site_name, remote_cert_id,
                   sync_mode, last_local_hash, last_remote_hash, last_error,
                   last_synced_at, created_at, updated_at
            FROM site_sync_links
            ORDER BY updated_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_site_sync_link(&self, link: &SiteSyncLinkUpsert) -> Result<()> {
        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO site_sync_links (
                local_site_id, provider, remote_site_id, remote_site_name, remote_cert_id,
                sync_mode, last_local_hash, last_remote_hash, last_error,
                last_synced_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, local_site_id) DO UPDATE SET
                remote_site_id = excluded.remote_site_id,
                remote_site_name = excluded.remote_site_name,
                remote_cert_id = excluded.remote_cert_id,
                sync_mode = excluded.sync_mode,
                last_local_hash = excluded.last_local_hash,
                last_remote_hash = excluded.last_remote_hash,
                last_error = excluded.last_error,
                last_synced_at = excluded.last_synced_at,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(link.local_site_id)
        .bind(&link.provider)
        .bind(&link.remote_site_id)
        .bind(&link.remote_site_name)
        .bind(&link.remote_cert_id)
        .bind(&link.sync_mode)
        .bind(&link.last_local_hash)
        .bind(&link.last_remote_hash)
        .bind(&link.last_error)
        .bind(link.last_synced_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_site_sync_link(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM site_sync_links WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_safeline_site_mappings(&self) -> Result<Vec<SafeLineSiteMappingEntry>> {
        let rows = sqlx::query_as::<_, SafeLineSiteMappingEntry>(
            r#"
            SELECT id, safeline_site_id, safeline_site_name, safeline_site_domain,
                   local_alias, enabled, is_primary, notes, updated_at
            FROM safeline_site_mappings
            ORDER BY is_primary DESC, updated_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn replace_safeline_site_mappings(
        &self,
        mappings: &[SafeLineSiteMappingUpsert],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM safeline_site_mappings")
            .execute(&mut *tx)
            .await?;

        for mapping in mappings {
            sqlx::query(
                r#"
                INSERT INTO safeline_site_mappings (
                    safeline_site_id, safeline_site_name, safeline_site_domain,
                    local_alias, enabled, is_primary, notes, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&mapping.safeline_site_id)
            .bind(&mapping.safeline_site_name)
            .bind(&mapping.safeline_site_domain)
            .bind(&mapping.local_alias)
            .bind(mapping.enabled)
            .bind(mapping.is_primary)
            .bind(&mapping.notes)
            .bind(unix_timestamp())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_safeline_cached_sites(&self) -> Result<Vec<SafeLineCachedSiteEntry>> {
        let rows = sqlx::query_as::<_, SafeLineCachedSiteEntry>(
            r#"
            SELECT remote_site_id, name, domain, status, enabled,
                   server_names_json, ports_json, ssl_ports_json, upstreams_json,
                   ssl_enabled, cert_id, cert_type, cert_filename, key_filename,
                   health_check, raw_json, updated_at
            FROM safeline_cached_sites
            ORDER BY updated_at DESC, remote_site_id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn replace_safeline_cached_sites(
        &self,
        sites: &[SafeLineCachedSiteUpsert],
    ) -> Result<Option<i64>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM safeline_cached_sites")
            .execute(&mut *tx)
            .await?;

        if sites.is_empty() {
            tx.commit().await?;
            return Ok(None);
        }

        let now = unix_timestamp();
        for site in sites {
            sqlx::query(
                r#"
                INSERT INTO safeline_cached_sites (
                    remote_site_id, name, domain, status, enabled,
                    server_names_json, ports_json, ssl_ports_json, upstreams_json,
                    ssl_enabled, cert_id, cert_type, cert_filename, key_filename,
                    health_check, raw_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&site.remote_site_id)
            .bind(&site.name)
            .bind(&site.domain)
            .bind(&site.status)
            .bind(site.enabled)
            .bind(serialize_string_vec(&site.server_names)?)
            .bind(serialize_string_vec(&site.ports)?)
            .bind(serialize_string_vec(&site.ssl_ports)?)
            .bind(serialize_string_vec(&site.upstreams)?)
            .bind(site.ssl_enabled)
            .bind(site.cert_id)
            .bind(site.cert_type)
            .bind(&site.cert_filename)
            .bind(&site.key_filename)
            .bind(site.health_check)
            .bind(&site.raw_json)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(Some(now))
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_safeline_sync_state(
        &self,
        resource: &str,
    ) -> Result<Option<SafeLineSyncStateEntry>> {
        let row = sqlx::query_as::<_, SafeLineSyncStateEntry>(
            r#"
            SELECT resource, last_cursor, last_success_at, last_imported_count, last_skipped_count, updated_at
            FROM safeline_sync_state
            WHERE resource = ?
            "#,
        )
        .bind(resource)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_safeline_sync_state(
        &self,
        resource: &str,
        last_cursor: Option<i64>,
        imported: usize,
        skipped: usize,
    ) -> Result<()> {
        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO safeline_sync_state (
                resource, last_cursor, last_success_at, last_imported_count, last_skipped_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource) DO UPDATE SET
                last_cursor = excluded.last_cursor,
                last_success_at = excluded.last_success_at,
                last_imported_count = excluded.last_imported_count,
                last_skipped_count = excluded.last_skipped_count,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(resource)
        .bind(last_cursor)
        .bind(now)
        .bind(imported as i64)
        .bind(skipped as i64)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
