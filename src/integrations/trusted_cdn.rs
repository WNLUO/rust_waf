use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::distributions::{Alphanumeric, DistString};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const EDGEONE_OVERSEAS_IPS_URL: &str = "https://api.edgeone.ai/ips?product=EO&area=overseas";
const EDGEONE_DOC_URL: &str = "https://edgeone.ai/document/zh/57237";
const ALIYUN_ESA_ACTION: &str = "GetOriginProtection";
const ALIYUN_ESA_VERSION: &str = "2024-09-10";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedCdnProviderKind {
    EdgeOneOverseas,
    AliyunEsa,
}

pub struct TrustedCdnProviderSyncResult {
    pub provider: TrustedCdnProviderKind,
    pub synced_cidrs: Option<Vec<String>>,
    pub status: crate::config::l4::TrustedCdnSyncStatus,
    pub message: String,
    pub synced_at: i64,
}

impl TrustedCdnProviderSyncResult {
    fn success(
        provider: TrustedCdnProviderKind,
        synced_cidrs: Vec<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            synced_cidrs: Some(synced_cidrs),
            status: crate::config::l4::TrustedCdnSyncStatus::Success,
            message: message.into(),
            synced_at: unix_timestamp(),
        }
    }

    fn error(provider: TrustedCdnProviderKind, message: impl Into<String>) -> Self {
        Self {
            provider,
            synced_cidrs: None,
            status: crate::config::l4::TrustedCdnSyncStatus::Error,
            message: message.into(),
            synced_at: unix_timestamp(),
        }
    }
}

pub fn build_sync_client() -> Result<Client> {
    Client::builder()
        .user_agent("rust-waf/trusted-cdn-sync")
        .http1_only()
        .build()
        .map_err(Into::into)
}

pub fn provider_due(last_synced_at: Option<i64>, interval_secs: u64, now: i64) -> bool {
    match last_synced_at {
        Some(last_synced_at) => now.saturating_sub(last_synced_at) >= interval_secs as i64,
        None => true,
    }
}

pub async fn sync_edgeone_overseas(client: &Client) -> TrustedCdnProviderSyncResult {
    match fetch_edgeone_overseas_cidrs(client).await {
        Ok(cidrs) => TrustedCdnProviderSyncResult::success(
            TrustedCdnProviderKind::EdgeOneOverseas,
            cidrs.clone(),
            format!(
                "EdgeOne 国际版开放数据同步成功，共 {} 条，来源 {}。",
                cidrs.len(),
                EDGEONE_DOC_URL
            ),
        ),
        Err(err) => TrustedCdnProviderSyncResult::error(
            TrustedCdnProviderKind::EdgeOneOverseas,
            format!("EdgeOne 国际版同步失败: {}", err),
        ),
    }
}

pub async fn sync_aliyun_esa(
    client: &Client,
    provider: &crate::config::l4::TrustedCdnAliyunEsaConfig,
) -> TrustedCdnProviderSyncResult {
    if provider.site_id.trim().is_empty() {
        return TrustedCdnProviderSyncResult::error(
            TrustedCdnProviderKind::AliyunEsa,
            "阿里云 ESA 已开启，但 Site ID 为空。",
        );
    }
    if provider.access_key_id.trim().is_empty() || provider.access_key_secret.trim().is_empty() {
        return TrustedCdnProviderSyncResult::error(
            TrustedCdnProviderKind::AliyunEsa,
            "阿里云 ESA 已开启，但 AccessKey ID / Secret 未填写。",
        );
    }

    match fetch_aliyun_esa_cidrs(client, provider).await {
        Ok(cidrs) => TrustedCdnProviderSyncResult::success(
            TrustedCdnProviderKind::AliyunEsa,
            cidrs.clone(),
            format!("阿里云 ESA 回源白名单同步成功，共 {} 条。", cidrs.len()),
        ),
        Err(err) => TrustedCdnProviderSyncResult::error(
            TrustedCdnProviderKind::AliyunEsa,
            format!("阿里云 ESA 同步失败: {}", err),
        ),
    }
}

async fn fetch_edgeone_overseas_cidrs(client: &Client) -> Result<Vec<String>> {
    let response = client
        .get(EDGEONE_OVERSEAS_IPS_URL)
        .send()
        .await
        .context("请求 EdgeOne 开放数据失败")?;
    let response = response
        .error_for_status()
        .context("EdgeOne 开放数据返回非 2xx 状态码")?;
    let body = response.text().await.context("读取 EdgeOne 数据失败")?;
    let cidrs = normalize_cidr_lines(&body);
    if cidrs.is_empty() {
        return Err(anyhow!("EdgeOne 开放数据为空"));
    }
    Ok(cidrs)
}

async fn fetch_aliyun_esa_cidrs(
    client: &Client,
    provider: &crate::config::l4::TrustedCdnAliyunEsaConfig,
) -> Result<Vec<String>> {
    let endpoint = provider.endpoint.trim();
    let host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if host.is_empty() {
        return Err(anyhow!("阿里云 ESA API Endpoint 为空"));
    }

    let query = format!("SiteId={}", provider.site_id.trim());
    let url = format!("https://{host}/?{query}");
    let payload_hash = hex_sha256(b"");
    let x_acs_date = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let nonce = random_nonce();
    let signed_headers =
        "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
    let canonical_headers = format!(
        "host:{host}\n\
x-acs-action:{ALIYUN_ESA_ACTION}\n\
x-acs-content-sha256:{payload_hash}\n\
x-acs-date:{x_acs_date}\n\
x-acs-signature-nonce:{nonce}\n\
x-acs-version:{ALIYUN_ESA_VERSION}\n"
    );
    let canonical_request =
        format!("GET\n/\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let string_to_sign = format!(
        "ACS3-HMAC-SHA256\n{}",
        hex_sha256(canonical_request.as_bytes())
    );
    let signature = sign_hmac_sha256(&provider.access_key_secret, &string_to_sign)?;
    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        provider.access_key_id.trim(),
        signed_headers,
        signature
    );

    let response = client
        .get(url)
        .header("host", host)
        .header("x-acs-action", ALIYUN_ESA_ACTION)
        .header("x-acs-version", ALIYUN_ESA_VERSION)
        .header("x-acs-date", x_acs_date)
        .header("x-acs-signature-nonce", nonce)
        .header("x-acs-content-sha256", payload_hash)
        .header("authorization", authorization)
        .send()
        .await
        .context("请求阿里云 ESA OpenAPI 失败")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!(
            "阿里云 ESA OpenAPI 返回 {}: {}",
            status,
            truncate_body(&body)
        ));
    }

    let payload = serde_json::from_str::<AliyunEsaOriginProtectionResponse>(&body)
        .context("解析阿里云 ESA 响应失败")?;
    let Some(whitelist) = payload.latest_ip_whitelist else {
        return Err(anyhow!("阿里云 ESA 响应中未包含 LatestIPWhitelist"));
    };

    let mut cidrs = whitelist.ipv4.unwrap_or_default();
    cidrs.extend(whitelist.ipv6.unwrap_or_default());
    let cidrs = normalize_cidrs(cidrs);
    if cidrs.is_empty() {
        return Err(anyhow!("阿里云 ESA 返回的白名单为空"));
    }
    Ok(cidrs)
}

fn normalize_cidr_lines(body: &str) -> Vec<String> {
    normalize_cidrs(
        body.lines()
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>(),
    )
}

fn normalize_cidrs(values: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        if !normalized.iter().any(|item| item == &value) {
            normalized.push(value);
        }
    }
    normalized
}

fn random_nonce() -> String {
    let suffix = Alphanumeric.sample_string(&mut rand::thread_rng(), 24);
    format!("rwaf-{}", suffix.to_ascii_lowercase())
}

fn sign_hmac_sha256(secret: &str, payload: &str) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(secret.trim().as_bytes()).context("构造阿里云签名器失败")?;
    mac.update(payload.as_bytes());
    Ok(hex_bytes(&mac.finalize().into_bytes()))
}

fn hex_sha256(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(payload);
    hex_bytes(&digest.finalize())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn truncate_body(body: &str) -> String {
    const LIMIT: usize = 240;
    if body.chars().count() <= LIMIT {
        body.to_string()
    } else {
        body.chars().take(LIMIT).collect::<String>() + "..."
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, Deserialize)]
struct AliyunEsaOriginProtectionResponse {
    #[serde(rename = "LatestIPWhitelist")]
    latest_ip_whitelist: Option<AliyunEsaIpWhitelist>,
}

#[derive(Debug, Deserialize)]
struct AliyunEsaIpWhitelist {
    #[serde(rename = "IPv4")]
    ipv4: Option<Vec<String>>,
    #[serde(rename = "IPv6")]
    ipv6: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_edgeone_text_body() {
        let cidrs = normalize_cidr_lines("203.0.113.0/24\n\n198.51.100.0/24\n203.0.113.0/24\n");
        assert_eq!(
            cidrs,
            vec!["203.0.113.0/24".to_string(), "198.51.100.0/24".to_string()]
        );
    }

    #[test]
    fn provider_due_when_missing_last_synced_at() {
        assert!(provider_due(None, 300, 1_700_000_000));
        assert!(!provider_due(Some(1_700_000_000), 300, 1_700_000_200));
        assert!(provider_due(Some(1_700_000_000), 300, 1_700_000_300));
    }
}
