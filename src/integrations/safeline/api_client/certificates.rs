use super::*;

pub async fn list_certificates(config: &SafeLineConfig) -> Result<Vec<SafeLineCertificateSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池证书列表"
        ));
    }

    let client = client::build_client(config)?;
    let payload = client::get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(DEFAULT_CERT_PATH, &[DEFAULT_CERT_PATH]),
        "证书列表",
    )
    .await?;
    extract_certificates(&payload)
}

pub async fn load_certificate(
    config: &SafeLineConfig,
    certificate_id: &str,
) -> Result<SafeLineCertificateDetail> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池证书详情"
        ));
    }

    let client = client::build_client(config)?;
    let url = format!(
        "{base_url}{}/{}",
        normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH),
        certificate_id.trim()
    );
    let (status, body) = client::send_with_auth(&client, &base_url, config, |auth| {
        auth::with_auth_headers(client.get(&url), auth)
    })
    .await?;

    if !status.is_success() {
        return Err(anyhow!(
            "雷池证书详情接口返回 HTTP {}：{}",
            status,
            body.trim()
        ));
    }

    let payload = serde_json::from_str::<Value>(&body)
        .map_err(|err| anyhow!("雷池证书详情返回了不可解析的 JSON：{}", err))?;
    parse_certificate_detail(&payload).ok_or_else(|| {
        anyhow!(
            "已拿到雷池证书详情响应，但未能识别证书内容。请检查 /api/open/cert/{{id}} 的返回结构。"
        )
    })
}

pub async fn create_certificate(
    config: &SafeLineConfig,
    certificate: &SafeLineCertificateUpsert,
) -> Result<SafeLineCertificateWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法创建雷池证书"
        ));
    }

    let client = client::build_client(config)?;
    let path = normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH);
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "type": 2,
        "domains": certificate.domains,
        "manual": {
            "crt": certificate.certificate_pem,
            "key": certificate.private_key_pem,
        }
    });

    let (status, body) = client::send_with_auth(&client, &base_url, config, |auth| {
        auth::with_auth_headers(client.post(&url).json(&payload), auth)
    })
    .await?;

    if status.is_success() {
        let remote_id = extract_write_response_id_from_body(&body);
        return Ok(SafeLineCertificateWriteSummary {
            remote_id,
            accepted: true,
            status_code: status.as_u16(),
            message: body_or_status(status, &body),
        });
    }

    Ok(SafeLineCertificateWriteSummary {
        remote_id: None,
        accepted: false,
        status_code: status.as_u16(),
        message: body_or_status(status, &body),
    })
}

pub async fn update_certificate(
    config: &SafeLineConfig,
    remote_id: &str,
    certificate: &SafeLineCertificateUpsert,
) -> Result<SafeLineCertificateWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法更新雷池证书"
        ));
    }

    let remote_id = remote_id.trim();
    if remote_id.is_empty() {
        return Err(anyhow!("remote_id 不能为空"));
    }

    let client = client::build_client(config)?;
    let path = normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH);
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "id": remote_id,
        "type": 2,
        "domains": certificate.domains,
        "manual": {
            "crt": certificate.certificate_pem,
            "key": certificate.private_key_pem,
        }
    });

    let attempts = [
        ("PUT", format!("{url}/{remote_id}"), payload.clone()),
        ("PUT", url.clone(), payload.clone()),
        ("POST", url, payload),
    ];

    let mut last_failure = SafeLineCertificateWriteSummary {
        remote_id: Some(remote_id.to_string()),
        accepted: false,
        status_code: StatusCode::BAD_GATEWAY.as_u16(),
        message: "未执行任何证书写入尝试".to_string(),
    };

    for (method, url, payload) in attempts {
        let (status, body) =
            client::send_with_auth(&client, &base_url, config, |auth| match method {
                "PUT" => auth::with_auth_headers(client.put(&url).json(&payload), auth),
                _ => auth::with_auth_headers(client.post(&url).json(&payload), auth),
            })
            .await?;

        if status.is_success() {
            return Ok(SafeLineCertificateWriteSummary {
                remote_id: extract_write_response_id_from_body(&body)
                    .or_else(|| Some(remote_id.to_string())),
                accepted: true,
                status_code: status.as_u16(),
                message: body_or_status(status, &body),
            });
        }

        last_failure = SafeLineCertificateWriteSummary {
            remote_id: Some(remote_id.to_string()),
            accepted: false,
            status_code: status.as_u16(),
            message: body_or_status(status, &body),
        };
    }

    Ok(last_failure)
}
