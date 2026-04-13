use super::super::types::*;
use super::super::{non_empty_string, unix_timestamp};
use super::rules_and_events::{
    default_generated_certificate_name, ensure_local_certificate_exists, ensure_local_site_exists,
    normalize_string_list, parse_json_string_vec, parse_json_value, required_string,
};
use crate::integrations::safeline::{SafeLineProbeResult, SafeLineSiteSummary};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::collections::HashSet;

impl From<SafeLineProbeResult> for SafeLineTestResponse {
    fn from(value: SafeLineProbeResult) -> Self {
        Self {
            status: value.status,
            message: value.message,
            openapi_doc_reachable: value.openapi_doc_reachable,
            openapi_doc_status: value.openapi_doc_status,
            authenticated: value.authenticated,
            auth_probe_status: value.auth_probe_status,
        }
    }
}

impl From<SafeLineSiteSummary> for SafeLineSiteResponse {
    fn from(value: SafeLineSiteSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain,
            status: value.status,
            enabled: value.enabled,
            server_names: value.server_names,
            ports: value.ports,
            ssl_ports: value.ssl_ports,
            upstreams: value.upstreams,
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename,
            key_filename: value.key_filename,
            health_check: value.health_check,
            raw: value.raw,
        }
    }
}

impl TryFrom<crate::storage::SafeLineCachedSiteEntry> for SafeLineSiteResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::SafeLineCachedSiteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.remote_site_id,
            name: value.name,
            domain: value.domain,
            status: value.status,
            enabled: value.enabled,
            server_names: parse_json_string_vec(&value.server_names_json)?,
            ports: parse_json_string_vec(&value.ports_json)?,
            ssl_ports: parse_json_string_vec(&value.ssl_ports_json)?,
            upstreams: parse_json_string_vec(&value.upstreams_json)?,
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename,
            key_filename: value.key_filename,
            health_check: value.health_check,
            raw: parse_json_value(&value.raw_json)?,
        })
    }
}

impl crate::storage::SafeLineCachedSiteUpsert {
    pub(crate) fn from_summary(value: &SafeLineSiteSummary) -> Result<Self, anyhow::Error> {
        Ok(Self {
            remote_site_id: value.id.clone(),
            name: value.name.clone(),
            domain: value.domain.clone(),
            status: value.status.clone(),
            enabled: value.enabled,
            server_names: value.server_names.clone(),
            ports: value.ports.clone(),
            ssl_ports: value.ssl_ports.clone(),
            upstreams: value.upstreams.clone(),
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename.clone(),
            key_filename: value.key_filename.clone(),
            health_check: value.health_check,
            raw_json: serde_json::to_string(&value.raw)?,
        })
    }
}

impl From<crate::storage::SafeLineSiteMappingEntry> for SafeLineMappingResponse {
    fn from(value: crate::storage::SafeLineSiteMappingEntry) -> Self {
        Self {
            id: value.id,
            safeline_site_id: value.safeline_site_id,
            safeline_site_name: value.safeline_site_name,
            safeline_site_domain: value.safeline_site_domain,
            local_alias: value.local_alias,
            enabled: value.enabled,
            is_primary: value.is_primary,
            notes: value.notes,
            updated_at: value.updated_at,
        }
    }
}

impl SafeLineMappingsUpdateRequest {
    pub(crate) fn into_storage_mappings(
        self,
    ) -> Result<(Vec<crate::storage::SafeLineSiteMappingUpsert>, bool), String> {
        let mut primary_count = 0usize;
        let mut seen_site_ids = HashSet::new();
        let mut mappings = Vec::with_capacity(self.mappings.len());
        let allow_empty_replace = self.allow_empty_replace.unwrap_or(false);

        for item in self.mappings {
            let safeline_site_id = item.safeline_site_id.trim().to_string();
            let safeline_site_name = item.safeline_site_name.trim().to_string();
            let safeline_site_domain = item.safeline_site_domain.trim().to_string();
            let local_alias = item.local_alias.trim().to_string();
            let notes = item.notes.trim().to_string();

            if safeline_site_id.is_empty() {
                return Err("映射里的雷池站点 ID 不能为空".to_string());
            }
            if !seen_site_ids.insert(safeline_site_id.clone()) {
                return Err(format!("雷池站点 {} 存在重复映射", safeline_site_id));
            }
            if local_alias.is_empty() {
                return Err(format!("站点 {} 的本地别名不能为空", safeline_site_id));
            }
            if item.is_primary {
                primary_count += 1;
                if !item.enabled {
                    return Err(format!("主站点 {} 必须保持启用状态", safeline_site_id));
                }
            }

            mappings.push(crate::storage::SafeLineSiteMappingUpsert {
                safeline_site_id,
                safeline_site_name,
                safeline_site_domain,
                local_alias,
                enabled: item.enabled,
                is_primary: item.is_primary,
                notes,
            });
        }

        if primary_count > 1 {
            return Err("同一时间只能设置一个主站点映射".to_string());
        }

        Ok((mappings, allow_empty_replace))
    }
}

impl TryFrom<crate::storage::LocalSiteEntry> for LocalSiteResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::LocalSiteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            primary_hostname: value.primary_hostname,
            hostnames: parse_json_string_vec(&value.hostnames_json)?,
            listen_ports: parse_json_string_vec(&value.listen_ports_json)?,
            upstreams: parse_json_string_vec(&value.upstreams_json)?,
            safeline_intercept: value
                .safeline_intercept_json
                .as_deref()
                .map(serde_json::from_str::<crate::config::l7::SafeLineInterceptConfig>)
                .transpose()?
                .map(|config| SafeLineInterceptConfigResponse::from_config(&config)),
            enabled: value.enabled,
            tls_enabled: value.tls_enabled,
            local_certificate_id: value.local_certificate_id,
            source: value.source,
            sync_mode: value.sync_mode,
            notes: value.notes,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl LocalSiteUpsertRequest {
    pub(crate) async fn into_storage_site(
        self,
        store: &crate::storage::SqliteStore,
    ) -> Result<crate::storage::LocalSiteUpsert, String> {
        let name = required_string(self.name, "站点名称不能为空")?;
        let primary_hostname = required_string(self.primary_hostname, "主域名不能为空")?;
        let mut hostnames = normalize_string_list(self.hostnames);
        if !hostnames.iter().any(|item| item == &primary_hostname) {
            hostnames.insert(0, primary_hostname.clone());
        }
        let listen_ports = Vec::new();
        let upstreams = normalize_string_list(self.upstreams);
        let safeline_intercept = self
            .safeline_intercept
            .map(SafeLineInterceptConfigRequest::into_config)
            .transpose()?;
        let source = non_empty_string(self.source).unwrap_or_else(|| "manual".to_string());
        let sync_mode = non_empty_string(self.sync_mode).unwrap_or_else(|| "manual".to_string());
        let notes = self.notes.trim().to_string();

        for upstream in &upstreams {
            crate::core::gateway::normalize_upstream_endpoint(upstream)
                .map_err(|err| format!("上游地址 '{}' 无效: {}", upstream, err))?;
        }

        if let Some(local_certificate_id) = self.local_certificate_id {
            ensure_local_certificate_exists(store, local_certificate_id).await?;
        }

        Ok(crate::storage::LocalSiteUpsert {
            name,
            primary_hostname,
            hostnames,
            listen_ports,
            upstreams,
            safeline_intercept,
            enabled: self.enabled,
            tls_enabled: self.tls_enabled,
            local_certificate_id: self.local_certificate_id,
            source,
            sync_mode,
            notes,
            last_synced_at: self.last_synced_at,
        })
    }
}

impl TryFrom<crate::storage::LocalCertificateEntry> for LocalCertificateResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::LocalCertificateEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            domains: parse_json_string_vec(&value.domains_json)?,
            issuer: value.issuer,
            valid_from: value.valid_from,
            valid_to: value.valid_to,
            source_type: value.source_type,
            provider_remote_id: value.provider_remote_id,
            provider_remote_domains: parse_json_string_vec(&value.provider_remote_domains_json)?,
            last_remote_fingerprint: value.last_remote_fingerprint,
            sync_status: value.sync_status,
            sync_message: value.sync_message,
            auto_sync_enabled: value.auto_sync_enabled,
            trusted: value.trusted,
            expired: value.expired,
            notes: value.notes,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            certificate_pem: None,
            private_key_pem: None,
        })
    }
}

impl LocalCertificateUpsertRequest {
    pub(crate) fn into_storage_certificate(
        self,
    ) -> Result<
        (
            crate::storage::LocalCertificateUpsert,
            Option<Option<LocalCertificateSecretDraft>>,
        ),
        String,
    > {
        let name = required_string(self.name, "证书名称不能为空")?;
        let domains = normalize_string_list(self.domains);
        let issuer = self.issuer.trim().to_string();
        let source_type =
            non_empty_string(self.source_type).unwrap_or_else(|| "manual".to_string());
        let provider_remote_id = self.provider_remote_id.and_then(non_empty_string);
        let provider_remote_domains = normalize_string_list(self.provider_remote_domains);
        let last_remote_fingerprint = self.last_remote_fingerprint.and_then(non_empty_string);
        let sync_status = non_empty_string(self.sync_status).unwrap_or_else(|| "idle".to_string());
        let sync_message = self.sync_message.trim().to_string();
        let notes = self.notes.trim().to_string();
        let certificate_pem = self.certificate_pem.unwrap_or_default().trim().to_string();
        let private_key_pem = self.private_key_pem.unwrap_or_default().trim().to_string();

        if let (Some(valid_from), Some(valid_to)) = (self.valid_from, self.valid_to) {
            if valid_to < valid_from {
                return Err("证书有效期结束时间不能早于开始时间".to_string());
            }
        }

        let secret = match (certificate_pem.is_empty(), private_key_pem.is_empty()) {
            (true, true) if self.clear_secret.unwrap_or(false) => Some(None),
            (true, true) => None,
            (false, false) => Some(Some(LocalCertificateSecretDraft {
                certificate_pem,
                private_key_pem,
            })),
            _ => {
                return Err("证书 PEM 与私钥 PEM 需要同时填写，或同时留空".to_string());
            }
        };

        Ok((
            crate::storage::LocalCertificateUpsert {
                name,
                domains,
                issuer,
                valid_from: self.valid_from,
                valid_to: self.valid_to,
                source_type,
                provider_remote_id,
                provider_remote_domains,
                last_remote_fingerprint,
                sync_status,
                sync_message,
                auto_sync_enabled: self.auto_sync_enabled,
                trusted: self.trusted,
                expired: self.expired,
                notes,
                last_synced_at: self.last_synced_at,
            },
            secret,
        ))
    }
}

impl GeneratedLocalCertificateRequest {
    pub(crate) fn into_generated_certificate(
        self,
    ) -> Result<GeneratedLocalCertificateDraft, String> {
        let domains = normalize_string_list(self.domains);
        if domains.is_empty() {
            return Err("至少填写一个域名才能生成证书".to_string());
        }

        let primary_domain = domains[0].clone();
        let name = self
            .name
            .and_then(non_empty_string)
            .unwrap_or_else(|| default_generated_certificate_name(&primary_domain));
        let notes = self
            .notes
            .and_then(non_empty_string)
            .unwrap_or_else(|| "系统设置中生成的随机假证书".to_string());
        let now = unix_timestamp();
        let valid_to = now.saturating_add(3600 * 24 * 365);
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(domains.clone()).map_err(|err| err.to_string())?;

        Ok(GeneratedLocalCertificateDraft {
            certificate: crate::storage::LocalCertificateUpsert {
                name,
                domains,
                issuer: "WAF Auto Generated".to_string(),
                valid_from: Some(now),
                valid_to: Some(valid_to),
                source_type: "generated".to_string(),
                provider_remote_id: None,
                provider_remote_domains: Vec::new(),
                last_remote_fingerprint: None,
                sync_status: "idle".to_string(),
                sync_message: String::new(),
                auto_sync_enabled: false,
                trusted: false,
                expired: false,
                notes,
                last_synced_at: None,
            },
            secret: LocalCertificateSecretDraft {
                certificate_pem: cert.pem(),
                private_key_pem: key_pair.serialize_pem(),
            },
        })
    }
}

impl From<crate::storage::SiteSyncLinkEntry> for SiteSyncLinkResponse {
    fn from(value: crate::storage::SiteSyncLinkEntry) -> Self {
        Self {
            id: value.id,
            local_site_id: value.local_site_id,
            provider: value.provider,
            remote_site_id: value.remote_site_id,
            remote_site_name: value.remote_site_name,
            remote_cert_id: value.remote_cert_id,
            sync_mode: value.sync_mode,
            last_local_hash: value.last_local_hash,
            last_remote_hash: value.last_remote_hash,
            last_error: value.last_error,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl SiteSyncLinkUpsertRequest {
    pub(crate) async fn into_storage_link(
        self,
        store: &crate::storage::SqliteStore,
    ) -> Result<crate::storage::SiteSyncLinkUpsert, String> {
        if self.local_site_id <= 0 {
            return Err("local_site_id 必须大于 0".to_string());
        }
        ensure_local_site_exists(store, self.local_site_id).await?;

        let provider = required_string(self.provider, "provider 不能为空")?;
        let remote_site_id = required_string(self.remote_site_id, "remote_site_id 不能为空")?;
        let remote_site_name =
            non_empty_string(self.remote_site_name).unwrap_or_else(|| remote_site_id.clone());
        let sync_mode =
            non_empty_string(self.sync_mode).unwrap_or_else(|| "remote_to_local".to_string());

        Ok(crate::storage::SiteSyncLinkUpsert {
            local_site_id: self.local_site_id,
            provider,
            remote_site_id,
            remote_site_name,
            remote_cert_id: self.remote_cert_id.and_then(non_empty_string),
            sync_mode,
            last_local_hash: self.last_local_hash.and_then(non_empty_string),
            last_remote_hash: self.last_remote_hash.and_then(non_empty_string),
            last_error: self.last_error.and_then(non_empty_string),
            last_synced_at: self.last_synced_at,
        })
    }
}
