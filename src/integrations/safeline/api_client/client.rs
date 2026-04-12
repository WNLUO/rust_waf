use super::*;

pub(super) fn build_client(config: &SafeLineConfig) -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(!config.verify_tls)
        .timeout(Duration::from_secs(10))
        .build()?)
}

pub(super) async fn get_json_with_fallback(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    paths: &[String],
    resource_name: &str,
) -> Result<Value> {
    let mut failures = Vec::new();

    for path in paths {
        let url = format!("{base_url}{path}");
        let (status, body) = send_with_auth(client, base_url, config, |auth| {
            auth::with_auth_headers(client.get(&url), auth)
        })
        .await?;

        if status.is_success() {
            if looks_like_html(&body) {
                failures.push(format!(
                    "{path} -> HTTP {status}（返回了前端页面而不是 JSON）"
                ));
                continue;
            }

            let payload = serde_json::from_str::<Value>(&body).map_err(|err| {
                anyhow!(
                    "雷池{resource_name}接口 {} 返回了不可解析的 JSON：{}",
                    path,
                    err
                )
            })?;
            return Ok(payload);
        }

        if body.contains("login-required") || body.contains("Login required") {
            return Err(anyhow!(
                "雷池{}接口 {} 返回 login-required。当前 Token 可访问部分 OpenAPI，但该接口仍要求登录态 Bearer 授权，说明接入尚未完全完成。",
                resource_name,
                path
            ));
        }

        if body.contains("commerce license required") {
            return Err(anyhow!(
                "雷池{}接口 {} 返回 commerce license required，当前实例版本或授权不支持该能力。",
                resource_name,
                path
            ));
        }

        failures.push(format!("{path} -> HTTP {status}"));
    }

    Err(anyhow!(
        "雷池{}接口均未成功返回，请检查路径是否与实例版本匹配。已尝试：{}",
        resource_name,
        failures.join("，")
    ))
}

pub(super) async fn send_with_auth<F>(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    build_request: F,
) -> Result<(StatusCode, String)>
where
    F: Fn(&AuthContext) -> RequestBuilder,
{
    let auth_contexts = auth::resolve_auth_contexts(client, base_url, config).await?;
    let mut last_status = StatusCode::UNAUTHORIZED;
    let mut last_body = String::new();

    for auth in &auth_contexts {
        let response = build_request(auth).send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let login_required = body.contains("login-required") || body.contains("Login required");
        last_status = status;
        last_body = body.clone();
        if status.is_success() || !login_required {
            return Ok((status, body));
        }
    }

    Ok((last_status, last_body))
}
