use super::*;

pub async fn pull_certificates(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineCertificatesPullResult> {
    ensure_enabled(config)?;

    let now = unix_timestamp();
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let mut local_certificates = store.list_local_certificates().await?;
    let mut result = SafeLineCertificatesPullResult::default();

    for certificate in &remote_certificates {
        let detail = crate::integrations::safeline::load_certificate(config, &certificate.id)
            .await
            .ok();
        let sync_state =
            sync_remote_certificate(store, &mut local_certificates, certificate, detail, now)
                .await?;
        if sync_state.inserted {
            result.imported_certificates += 1;
        } else {
            result.updated_certificates += 1;
        }
    }

    store
        .upsert_safeline_sync_state(
            "certificates_pull",
            Some(now),
            result.imported_certificates + result.updated_certificates,
            result.skipped_certificates,
        )
        .await?;

    Ok(result)
}

pub async fn pull_certificate(
    store: &SqliteStore,
    config: &SafeLineConfig,
    remote_cert_id: &str,
) -> Result<i64> {
    ensure_enabled(config)?;

    let remote_cert_id = remote_cert_id.trim();
    if remote_cert_id.is_empty() {
        bail!("remote_cert_id 不能为空");
    }

    let now = unix_timestamp();
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let certificate = remote_certificates
        .iter()
        .find(|item| item.id == remote_cert_id)
        .ok_or_else(|| anyhow!("雷池证书 '{}' 不存在或当前账号不可见", remote_cert_id))?;
    let detail = crate::integrations::safeline::load_certificate(config, remote_cert_id)
        .await
        .ok();
    let mut local_certificates = store.list_local_certificates().await?;
    let sync_state =
        sync_remote_certificate(store, &mut local_certificates, certificate, detail, now).await?;
    store
        .upsert_safeline_sync_state("certificates_pull", Some(now), 1, 0)
        .await?;
    Ok(sync_state.local_id)
}

pub async fn push_certificate(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_certificate_id: i64,
) -> Result<String> {
    ensure_enabled(config)?;

    if local_certificate_id <= 0 {
        bail!("local_certificate_id 必须大于 0");
    }

    let now = unix_timestamp();
    let local_certificate = store
        .load_local_certificate(local_certificate_id)
        .await?
        .ok_or_else(|| anyhow!("本地证书 '{}' 不存在", local_certificate_id))?;
    let secret = store
        .load_local_certificate_secret(local_certificate_id)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "本地证书 #{} 缺少证书内容，无法推送到雷池",
                local_certificate_id
            )
        })?;

    if secret.certificate_pem.trim().is_empty() || secret.private_key_pem.trim().is_empty() {
        update_certificate_sync_metadata(
            store,
            &local_certificate,
            CertificateSyncMetadataUpdate {
                provider_remote_id: local_certificate.provider_remote_id.clone(),
                provider_remote_domains: parse_json_vec(
                    &local_certificate.provider_remote_domains_json,
                )
                .unwrap_or_default(),
                last_remote_fingerprint: local_certificate.last_remote_fingerprint.clone(),
                sync_status: "blocked".to_string(),
                sync_message: "本地证书缺少完整私钥，无法推送到雷池".to_string(),
                last_synced_at: local_certificate.last_synced_at,
            },
        )
        .await?;
        bail!(
            "本地证书 #{} 缺少完整私钥，无法推送到雷池",
            local_certificate_id
        );
    }

    let local_domains = parse_json_vec(&local_certificate.domains_json)?;
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;
    let match_result =
        match_remote_certificate(&local_certificate, &local_domains, &remote_certificates)?;

    let payload = SafeLineCertificateUpsert {
        domains: local_domains.clone(),
        certificate_pem: secret.certificate_pem.clone(),
        private_key_pem: secret.private_key_pem.clone(),
    };

    let summary = if let Some(remote_id) = match_result.remote_id.as_deref() {
        crate::integrations::safeline::update_certificate(config, remote_id, &payload).await?
    } else {
        crate::integrations::safeline::create_certificate(config, &payload).await?
    };

    if !summary.accepted {
        update_certificate_sync_metadata(
            store,
            &local_certificate,
            CertificateSyncMetadataUpdate {
                provider_remote_id: local_certificate.provider_remote_id.clone(),
                provider_remote_domains: match_result.remote_domains,
                last_remote_fingerprint: local_certificate.last_remote_fingerprint.clone(),
                sync_status: "error".to_string(),
                sync_message: summary.message.clone(),
                last_synced_at: local_certificate.last_synced_at,
            },
        )
        .await?;
        bail!("{}", summary.message);
    }

    let remote_id = summary
        .remote_id
        .clone()
        .or_else(|| match_result.remote_id.clone())
        .ok_or_else(|| anyhow!("雷池证书写入成功，但未返回远端证书 ID"))?;

    update_certificate_sync_metadata(
        store,
        &local_certificate,
        CertificateSyncMetadataUpdate {
            provider_remote_id: Some(remote_id.clone()),
            provider_remote_domains: local_domains,
            last_remote_fingerprint: certificate_fingerprint(&secret.certificate_pem),
            sync_status: "synced".to_string(),
            sync_message: match_result.success_message(&remote_id),
            last_synced_at: Some(now),
        },
    )
    .await?;

    store
        .upsert_safeline_sync_state("certificates_push", Some(now), 1, 0)
        .await?;

    Ok(remote_id)
}

pub async fn preview_certificate_match(
    store: &SqliteStore,
    config: &SafeLineConfig,
    local_certificate_id: i64,
) -> Result<CertificateMatchPreview> {
    ensure_enabled(config)?;

    if local_certificate_id <= 0 {
        bail!("local_certificate_id 必须大于 0");
    }

    let local_certificate = store
        .load_local_certificate(local_certificate_id)
        .await?
        .ok_or_else(|| anyhow!("本地证书 '{}' 不存在", local_certificate_id))?;
    let local_domains = parse_json_vec(&local_certificate.domains_json)?;
    let normalized_local_domains = normalized_domain_set(&local_domains);
    let remote_certificates = crate::integrations::safeline::list_certificates(config).await?;

    if let Some(remote_id) = local_certificate.provider_remote_id.as_deref() {
        if let Some(remote) = remote_certificates.iter().find(|item| item.id == remote_id) {
            let normalized_remote_domains = normalized_domain_set(&remote.domains);
            if normalized_remote_domains == normalized_local_domains {
                return Ok(CertificateMatchPreview {
                    status: "ok".to_string(),
                    strategy: "remote_id".to_string(),
                    local_certificate_id,
                    local_domains,
                    linked_remote_id: local_certificate.provider_remote_id.clone(),
                    matched_remote_id: Some(remote.id.clone()),
                    message: format!("将按已绑定的雷池证书 ID {} 直接更新。", remote.id),
                    candidates: vec![remote.clone()],
                });
            }

            return Ok(CertificateMatchPreview {
                status: "conflict".to_string(),
                strategy: "drifted".to_string(),
                local_certificate_id,
                local_domains,
                linked_remote_id: local_certificate.provider_remote_id.clone(),
                matched_remote_id: Some(remote.id.clone()),
                message: format!(
                    "已绑定的雷池证书 {} 仍存在，但域名集合已漂移。本地：{}；远端：{}。",
                    remote.id,
                    normalized_local_domains.join(", "),
                    normalized_remote_domains.join(", ")
                ),
                candidates: vec![remote.clone()],
            });
        }
    }

    let domain_matches = remote_certificates
        .iter()
        .filter(|item| normalized_domain_set(&item.domains) == normalized_local_domains)
        .cloned()
        .collect::<Vec<_>>();

    if domain_matches.len() == 1 {
        let remote = domain_matches[0].clone();
        return Ok(CertificateMatchPreview {
            status: "ok".to_string(),
            strategy: "domains".to_string(),
            local_certificate_id,
            local_domains,
            linked_remote_id: local_certificate.provider_remote_id.clone(),
            matched_remote_id: Some(remote.id.clone()),
            message: format!(
                "未命中已绑定 ID，将按域名集合匹配并更新雷池证书 {}。",
                remote.id
            ),
            candidates: vec![remote],
        });
    }

    if domain_matches.len() > 1 {
        return Ok(CertificateMatchPreview {
            status: "conflict".to_string(),
            strategy: "domains".to_string(),
            local_certificate_id,
            local_domains,
            linked_remote_id: local_certificate.provider_remote_id.clone(),
            matched_remote_id: None,
            message: "雷池中存在多张域名集合相同的证书，当前不会自动覆盖，请先人工确认目标。"
                .to_string(),
            candidates: domain_matches,
        });
    }

    Ok(CertificateMatchPreview {
        status: "create".to_string(),
        strategy: "create".to_string(),
        local_certificate_id,
        local_domains,
        linked_remote_id: local_certificate.provider_remote_id.clone(),
        matched_remote_id: None,
        message: "未找到可复用的雷池证书，推送时将创建新证书。".to_string(),
        candidates: Vec::new(),
    })
}
