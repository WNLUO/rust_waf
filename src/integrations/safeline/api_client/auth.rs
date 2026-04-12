use super::*;
use rand::{distributions::Alphanumeric, Rng};

pub(super) async fn resolve_auth_contexts(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
) -> Result<Vec<AuthContext>> {
    let mut contexts = Vec::new();
    let token = config.api_token.trim();
    if !token.is_empty() {
        contexts.push(AuthContext {
            api_token: Some(token.to_string()),
            bearer_token: Some(token.to_string()),
        });
    }

    if has_username_password(config) {
        let jwt = login_with_password(client, base_url, config).await?;
        if !jwt.trim().is_empty() {
            contexts.push(AuthContext {
                api_token: None,
                bearer_token: Some(jwt),
            });
        }
    }

    if contexts.is_empty() {
        contexts.push(AuthContext {
            api_token: None,
            bearer_token: None,
        });
    }

    Ok(contexts)
}

pub(super) fn with_auth_headers(request: RequestBuilder, auth: &AuthContext) -> RequestBuilder {
    let request = if let Some(api_token) = auth.api_token.as_deref() {
        request.header("API-TOKEN", api_token)
    } else {
        request
    };

    if let Some(bearer_token) = auth.bearer_token.as_deref() {
        request.header("Authorization", format!("Bearer {bearer_token}"))
    } else {
        request
    }
}

pub(super) fn has_any_auth(config: &SafeLineConfig) -> bool {
    !config.api_token.trim().is_empty() || has_username_password(config)
}

pub(super) fn has_username_password(config: &SafeLineConfig) -> bool {
    !config.username.trim().is_empty() && !config.password.trim().is_empty()
}

async fn login_with_password(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
) -> Result<String> {
    let aes_key_url = format!("{base_url}{LOGIN_AES_KEY_PATH}");
    let csrf_url = format!("{base_url}{LOGIN_CSRF_PATH}");
    let login_url = format!("{base_url}{LOGIN_PATH}");

    let aes_key = client
        .get(&aes_key_url)
        .send()
        .await?
        .json::<SafeLineSystemKeyEnvelope>()
        .await?
        .data;
    if aes_key.len() != 16 {
        return Err(anyhow!(
            "雷池登录加密密钥长度异常，期望 16 字节，实际 {}",
            aes_key.len()
        ));
    }

    let csrf_token = client
        .get(&csrf_url)
        .send()
        .await?
        .json::<SafeLineCsrfEnvelope>()
        .await?
        .data
        .csrf_token;

    let iv = random_iv();
    let encrypted_password = encrypt_password(&aes_key, &iv, config.password.trim())?;
    let payload = serde_json::json!({
        "username": config.username.trim(),
        "password": encrypted_password,
        "csrf_token": csrf_token,
    });

    let response = client.post(&login_url).json(&payload).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("雷池登录失败，HTTP {}：{}", status, body));
    }

    let envelope = serde_json::from_str::<SafeLineLoginEnvelope>(&body)
        .map_err(|err| anyhow!("雷池登录返回了不可解析的 JSON：{}", err))?;
    if envelope.data.jwt.trim().is_empty() {
        return Err(anyhow!(
            "雷池登录未返回 JWT：{}",
            if envelope.msg.trim().is_empty() {
                "空响应".to_string()
            } else {
                envelope.msg
            }
        ));
    }

    Ok(envelope.data.jwt)
}

fn random_iv() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

pub(super) fn encrypt_password(aes_key: &str, iv: &str, password: &str) -> Result<String> {
    let encrypted = encrypt_password_with_openssl(aes_key, iv, password)?;
    let mut mixed = Vec::with_capacity(iv.len() + encrypted.len());
    mixed.extend_from_slice(iv.as_bytes());
    mixed.extend_from_slice(&encrypted);
    Ok(BASE64.encode(mixed))
}

fn encrypt_password_with_openssl(aes_key: &str, iv: &str, password: &str) -> Result<Vec<u8>> {
    let output = Command::new("/usr/bin/openssl")
        .arg("enc")
        .arg("-aes-128-cbc")
        .arg("-K")
        .arg(bytes_to_hex(aes_key.as_bytes()))
        .arg("-iv")
        .arg(bytes_to_hex(iv.as_bytes()))
        .arg("-nosalt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(password.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|err| anyhow!("调用 openssl 进行雷池密码加密失败：{}", err))?;

    if !output.status.success() {
        return Err(anyhow!(
            "openssl 加密失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(output.stdout)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
