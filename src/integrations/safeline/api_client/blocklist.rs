use super::*;

pub async fn push_blocked_ip(
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
) -> Result<SafeLineBlockedIpSyncSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法同步本地封禁到雷池"
        ));
    }

    let client = client::build_client(config)?;
    let path = normalized_or_default(&config.blocklist_sync_path, DEFAULT_BLOCKLIST_PATH);
    if path.contains("/open/ipgroup") {
        return push_blocked_ip_via_open_ipgroup(&client, &base_url, config, blocked_ip, &path)
            .await;
    }
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "ip": blocked_ip.ip,
        "reason": blocked_ip.reason,
        "blocked_at": blocked_ip.blocked_at,
        "expires_at": blocked_ip.expires_at,
        "source": "waf-local",
    });
    let (status, body) = client::send_with_auth(&client, &base_url, config, |auth| {
        auth::with_auth_headers(client.post(&url).json(&payload), auth)
    })
    .await?;
    let accepted = status.is_success() || status == StatusCode::CONFLICT;

    Ok(SafeLineBlockedIpSyncSummary {
        ip: blocked_ip.ip.clone(),
        accepted,
        status_code: status.as_u16(),
        message: if body.trim().is_empty() {
            status.to_string()
        } else {
            body
        },
    })
}

pub async fn list_blocked_ips(config: &SafeLineConfig) -> Result<Vec<SafeLineBlockedIpSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池封禁列表"
        ));
    }

    let client = client::build_client(config)?;
    let payload = client::get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(
            &config.blocklist_sync_path,
            &[DEFAULT_BLOCKLIST_PATH, LEGACY_BLOCKLIST_PATH],
        ),
        "封禁列表",
    )
    .await?;
    extract_blocked_ips(&payload)
}

pub async fn delete_blocked_ip(
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
) -> Result<SafeLineBlockedIpDeleteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法调用雷池远端解封"
        ));
    }

    let client = client::build_client(config)?;
    let path = if config.blocklist_delete_path.trim().is_empty() {
        &config.blocklist_sync_path
    } else {
        &config.blocklist_delete_path
    };
    let path = normalized_or_default(path, DEFAULT_BLOCKLIST_PATH);
    if path.contains("/open/ipgroup") {
        return delete_blocked_ip_via_open_ipgroup(&client, &base_url, config, blocked_ip, &path)
            .await;
    }
    let url = format!("{base_url}{path}");

    let payload = serde_json::json!({
        "id": blocked_ip.provider_remote_id.as_deref(),
        "remote_id": blocked_ip.provider_remote_id.as_deref(),
        "ip": &blocked_ip.ip,
        "address": &blocked_ip.ip,
        "reason": &blocked_ip.reason,
        "blocked_at": blocked_ip.blocked_at,
        "expires_at": blocked_ip.expires_at,
    });

    let mut last_status = StatusCode::BAD_GATEWAY;
    let mut last_message = String::new();

    let delete_action_payload = serde_json::json!({
        "action": "delete",
        "id": blocked_ip.provider_remote_id.as_deref(),
        "remote_id": blocked_ip.provider_remote_id.as_deref(),
        "ip": &blocked_ip.ip,
    });
    let mut request_kinds = Vec::new();
    if let Some(remote_id) = blocked_ip.provider_remote_id.as_deref() {
        request_kinds.push(DeleteAttempt::DeleteById(remote_id.to_string()));
    }
    request_kinds.push(DeleteAttempt::DeleteByBody(payload.clone()));
    request_kinds.push(DeleteAttempt::PostDelete(delete_action_payload));

    for attempt in request_kinds {
        let (status, body) =
            client::send_with_auth(&client, &base_url, config, |auth| match &attempt {
                DeleteAttempt::DeleteById(remote_id) => {
                    auth::with_auth_headers(client.delete(format!("{url}/{remote_id}")), auth)
                }
                DeleteAttempt::DeleteByBody(payload) => {
                    auth::with_auth_headers(client.delete(&url).json(payload), auth)
                }
                DeleteAttempt::PostDelete(payload) => {
                    auth::with_auth_headers(client.post(&url).json(payload), auth)
                }
            })
            .await?;

        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(SafeLineBlockedIpDeleteSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        last_status = status;
        last_message = if body.trim().is_empty() {
            status.to_string()
        } else {
            body
        };
    }

    Ok(SafeLineBlockedIpDeleteSummary {
        ip: blocked_ip.ip.clone(),
        accepted: false,
        status_code: last_status.as_u16(),
        message: last_message,
    })
}

async fn push_blocked_ip_via_open_ipgroup(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
    path: &str,
) -> Result<SafeLineBlockedIpSyncSummary> {
    let ip_group_ids = configured_ip_group_ids(config)?;
    let payload = serde_json::json!({
        "ip_group_ids": ip_group_ids,
        "ips": [blocked_ip.ip.clone()],
    });

    let mut failures = Vec::new();
    for action_path in open_ipgroup_action_paths(path, OPEN_BLOCKLIST_APPEND_SUFFIX) {
        let url = format!("{base_url}{action_path}");
        let (status, body) = client::send_with_auth(client, base_url, config, |auth| {
            auth::with_auth_headers(client.post(&url).json(&payload), auth)
        })
        .await?;

        if status.is_success() || status == StatusCode::CONFLICT {
            return Ok(SafeLineBlockedIpSyncSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        failures.push(format_failure(&action_path, status, &body));
    }

    Err(anyhow!(
        "调用新版雷池 IP 组追加接口失败。已尝试：{}",
        failures.join("；")
    ))
}

async fn delete_blocked_ip_via_open_ipgroup(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
    path: &str,
) -> Result<SafeLineBlockedIpDeleteSummary> {
    let ip_group_ids = configured_ip_group_ids(config)?;
    let payload = serde_json::json!({
        "ip_group_ids": ip_group_ids.clone(),
        "ips": [blocked_ip.ip.clone()],
    });

    let mut attempts = Vec::new();
    for action_path in open_ipgroup_action_paths(path, OPEN_BLOCKLIST_REMOVE_SUFFIX) {
        attempts.push(OpenIpGroupDeleteAttempt::PostRemove(
            action_path.clone(),
            payload.clone(),
        ));
        attempts.push(OpenIpGroupDeleteAttempt::DeleteRemove(
            action_path.clone(),
            payload.clone(),
        ));
    }

    let base_path = super::super::sync_helpers::open_ipgroup_base_path(path);
    attempts.push(OpenIpGroupDeleteAttempt::PostAction(
        base_path.clone(),
        serde_json::json!({
            "action": "remove",
            "ip_group_ids": ip_group_ids.clone(),
            "ips": [blocked_ip.ip.clone()],
        }),
    ));
    attempts.push(OpenIpGroupDeleteAttempt::PostAction(
        base_path,
        serde_json::json!({
            "action": "delete",
            "ip_group_ids": ip_group_ids,
            "ips": [blocked_ip.ip.clone()],
        }),
    ));

    let mut failures = Vec::new();
    for attempt in attempts {
        let path = attempt.path().to_string();
        let (status, body) = client::send_with_auth(client, base_url, config, |auth| {
            let url = format!("{base_url}{path}");
            match &attempt {
                OpenIpGroupDeleteAttempt::PostRemove(_, payload)
                | OpenIpGroupDeleteAttempt::PostAction(_, payload) => {
                    auth::with_auth_headers(client.post(&url).json(payload), auth)
                }
                OpenIpGroupDeleteAttempt::DeleteRemove(_, payload) => {
                    auth::with_auth_headers(client.delete(&url).json(payload), auth)
                }
            }
        })
        .await?;

        if status.is_success() || status == StatusCode::NOT_FOUND || status == StatusCode::CONFLICT
        {
            return Ok(SafeLineBlockedIpDeleteSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        failures.push(format_failure(&path, status, &body));
    }

    Err(anyhow!(
        "调用新版雷池 IP 组移除接口失败。已尝试：{}",
        failures.join("；")
    ))
}
