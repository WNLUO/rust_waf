use super::*;

pub async fn list_sites(config: &SafeLineConfig) -> Result<Vec<SafeLineSiteSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池站点列表"
        ));
    }

    let client = client::build_client(config)?;
    let payload = client::get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(
            &config.site_list_path,
            &[DEFAULT_SITE_LIST_PATH, LEGACY_SITE_LIST_PATH],
        ),
        "站点列表",
    )
    .await?;
    extract_sites(&payload)
}

pub async fn upsert_site(
    config: &SafeLineConfig,
    site: &SafeLineSiteUpsert,
) -> Result<SafeLineSiteWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法写入雷池站点"
        ));
    }

    let client = client::build_client(config)?;
    let path = normalized_or_default(&config.site_list_path, DEFAULT_SITE_LIST_PATH);
    let base_payload = build_site_upsert_payload(site);
    let mut attempts = Vec::new();

    if let Some(remote_id) = site.remote_id.as_deref() {
        let remote_id = remote_id.trim();
        if !remote_id.is_empty() {
            attempts.push(SiteWriteAttempt::Put(
                format!("{path}/{remote_id}"),
                base_payload.clone(),
            ));
            let mut payload_with_id = base_payload.clone();
            if let Some(object) = payload_with_id.as_object_mut() {
                object.insert("id".to_string(), Value::String(remote_id.to_string()));
            }
            attempts.push(SiteWriteAttempt::Put(path.clone(), payload_with_id.clone()));
            attempts.push(SiteWriteAttempt::Post(path.clone(), payload_with_id));
        }
    } else {
        attempts.push(SiteWriteAttempt::Post(path.clone(), base_payload.clone()));
    }

    if attempts.is_empty() {
        attempts.push(SiteWriteAttempt::Post(path.clone(), base_payload));
    }

    let mut last_failure = SafeLineSiteWriteSummary {
        remote_id: site.remote_id.clone(),
        accepted: false,
        status_code: StatusCode::BAD_GATEWAY.as_u16(),
        message: "未执行任何站点写入尝试".to_string(),
    };

    for attempt in attempts {
        let (status, body) = client::send_with_auth(&client, &base_url, config, |auth| {
            let url = format!("{base_url}{}", attempt.path());
            match &attempt {
                SiteWriteAttempt::Post(_, payload) => {
                    auth::with_auth_headers(client.post(&url).json(payload), auth)
                }
                SiteWriteAttempt::Put(_, payload) => {
                    auth::with_auth_headers(client.put(&url).json(payload), auth)
                }
            }
        })
        .await?;

        if status.is_success() {
            return Ok(SafeLineSiteWriteSummary {
                remote_id: extract_write_response_id_from_body(&body)
                    .or_else(|| site.remote_id.clone()),
                accepted: true,
                status_code: status.as_u16(),
                message: body_or_status(status, &body),
            });
        }

        last_failure = SafeLineSiteWriteSummary {
            remote_id: site.remote_id.clone(),
            accepted: false,
            status_code: status.as_u16(),
            message: format_failure(attempt.path(), status, &body),
        };
    }

    Ok(last_failure)
}
