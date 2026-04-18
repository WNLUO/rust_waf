use ipnet::IpNet;
use reqwest::Client;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

use crate::config::BotProviderConfig;
use crate::storage::{BotIpCacheEntry, SqliteStore};

const REFRESH_INTERVAL_SECS: u64 = 6 * 60 * 60;
const INITIAL_REFRESH_RETRY_SECS: u64 = 5 * 60;
const DNS_VERIFICATION_TTL_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BotVerificationStatus {
    Verified,
    VerifiedReverseDns,
    NotVerified,
    Unavailable,
}

#[derive(Debug, Clone)]
struct BotIpProvider {
    id: String,
    urls: Vec<String>,
}

#[derive(Debug, Default)]
struct BotIpCache {
    providers: BTreeMap<String, BotIpProviderCache>,
    dns_verifications: BTreeMap<String, BotDnsVerificationCache>,
    dns_pending: BTreeMap<String, i64>,
}

#[derive(Debug, Default)]
struct BotIpProviderCache {
    ranges: Vec<IpNet>,
    last_refresh_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
}

#[derive(Debug)]
struct BotDnsVerificationCache {
    verified: bool,
    expires_at: i64,
}

#[derive(Debug, Default)]
pub(crate) struct BotIpVerifier {
    cache: RwLock<BotIpCache>,
}

#[derive(Debug, Clone)]
pub struct BotVerifierSnapshot {
    pub generated_at: i64,
    pub providers: Vec<BotVerifierProviderSnapshot>,
}

#[derive(Debug, Clone)]
pub struct BotVerifierProviderSnapshot {
    pub provider: String,
    pub range_count: usize,
    pub last_refresh_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub status: String,
}

impl BotIpVerifier {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn verify(&self, provider: &str, ip: IpAddr) -> BotVerificationStatus {
        let now = unix_timestamp();
        let guard = self.cache.read().expect("bot verifier cache lock poisoned");
        let ip_cache = guard.providers.get(provider);
        if ip_cache
            .filter(|cache| cache.last_success_at.is_some())
            .is_some_and(|cache| cache.ranges.iter().any(|range| range.contains(&ip)))
        {
            BotVerificationStatus::Verified
        } else if let Some(dns_cache) = guard.dns_verifications.get(&dns_key(provider, ip)) {
            if dns_cache.expires_at < now {
                ip_cache_status(ip_cache)
            } else if dns_cache.verified {
                BotVerificationStatus::VerifiedReverseDns
            } else {
                BotVerificationStatus::NotVerified
            }
        } else {
            ip_cache_status(ip_cache)
        }
    }

    pub(crate) fn enqueue_dns_verification(
        self: &std::sync::Arc<Self>,
        provider: &str,
        ip: IpAddr,
        suffixes: &[String],
    ) {
        if suffixes.is_empty() {
            return;
        }
        let now = unix_timestamp();
        let key = dns_key(provider, ip);
        {
            let mut guard = self
                .cache
                .write()
                .expect("bot verifier cache lock poisoned");
            if guard
                .dns_verifications
                .get(&key)
                .is_some_and(|cached| cached.expires_at > now)
            {
                return;
            }
            if guard
                .dns_pending
                .get(&key)
                .is_some_and(|started_at| now.saturating_sub(*started_at) < 300)
            {
                return;
            }
            guard.dns_pending.insert(key.clone(), now);
        }

        let verifier = std::sync::Arc::clone(self);
        let provider = provider.to_string();
        let suffixes = suffixes.to_vec();
        tokio::spawn(async move {
            let result = verify_reverse_dns(ip, &suffixes).await;
            verifier.finish_dns_verification(&provider, ip, result);
        });
    }

    fn finish_dns_verification(&self, provider: &str, ip: IpAddr, result: anyhow::Result<bool>) {
        let key = dns_key(provider, ip);
        let now = unix_timestamp();
        let verified = match result {
            Ok(verified) => verified,
            Err(err) => {
                log::warn!(
                    "Bot reverse DNS verification failed provider={} ip={}: {}",
                    provider,
                    ip,
                    err
                );
                false
            }
        };
        let mut guard = self
            .cache
            .write()
            .expect("bot verifier cache lock poisoned");
        guard.dns_pending.remove(&key);
        guard.dns_verifications.insert(
            key,
            BotDnsVerificationCache {
                verified,
                expires_at: now.saturating_add(DNS_VERIFICATION_TTL_SECS),
            },
        );
    }

    pub(crate) fn hydrate_from_entries(&self, entries: Vec<BotIpCacheEntry>) {
        let mut guard = self
            .cache
            .write()
            .expect("bot verifier cache lock poisoned");
        for entry in entries {
            let ranges = serde_json::from_str::<Vec<String>>(&entry.ranges_json)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|item| item.parse::<IpNet>().ok())
                .collect::<Vec<_>>();
            guard.providers.insert(
                entry.provider,
                BotIpProviderCache {
                    ranges,
                    last_refresh_at: entry.last_refresh_at,
                    last_success_at: entry.last_success_at,
                    last_error: entry.last_error,
                },
            );
        }
    }

    pub(crate) fn snapshot(
        &self,
        configured_providers: &[BotProviderConfig],
    ) -> BotVerifierSnapshot {
        let guard = self.cache.read().expect("bot verifier cache lock poisoned");
        let mut providers = bot_ip_providers(configured_providers)
            .into_iter()
            .map(|provider| {
                let cache = guard.providers.get(&provider.id);
                let range_count = cache.map(|cache| cache.ranges.len()).unwrap_or(0);
                let last_refresh_at = cache.and_then(|cache| cache.last_refresh_at);
                let last_success_at = cache.and_then(|cache| cache.last_success_at);
                let last_error = cache.and_then(|cache| cache.last_error.clone());
                let status = if range_count > 0 && last_success_at.is_some() {
                    "ready"
                } else if last_error.is_some() {
                    "degraded"
                } else {
                    "empty"
                };
                BotVerifierProviderSnapshot {
                    provider: provider.id,
                    range_count,
                    last_refresh_at,
                    last_success_at,
                    last_error,
                    status: status.to_string(),
                }
            })
            .collect::<Vec<_>>();
        providers.sort_by(|left, right| left.provider.cmp(&right.provider));
        BotVerifierSnapshot {
            generated_at: unix_timestamp(),
            providers,
        }
    }

    pub(crate) async fn refresh_once(
        &self,
        configured_providers: &[BotProviderConfig],
        store: Option<&SqliteStore>,
    ) {
        let client = match Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(3))
            .user_agent("rust_waf bot verifier")
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                log::warn!("Failed to build bot verifier HTTP client: {}", err);
                return;
            }
        };

        for provider in bot_ip_providers(configured_providers) {
            let result = fetch_provider_ranges(&client, &provider).await;
            let refresh_result = {
                let mut guard = self
                    .cache
                    .write()
                    .expect("bot verifier cache lock poisoned");
                let cache = guard.providers.entry(provider.id.clone()).or_default();
                cache.last_refresh_at = Some(unix_timestamp());
                match result {
                    Ok(ranges) if !ranges.is_empty() => {
                        let ranges_json = serde_json::to_string(
                            &ranges.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        )
                        .unwrap_or_else(|_| "[]".to_string());
                        cache.ranges = ranges;
                        cache.last_success_at = cache.last_refresh_at;
                        cache.last_error = None;
                        log::info!(
                            "Bot verifier refreshed provider={} ranges={}",
                            provider.id,
                            cache.ranges.len()
                        );
                        ProviderRefreshPersistence {
                            ranges_json,
                            last_refresh_at: cache.last_refresh_at,
                            last_success_at: cache.last_success_at,
                            last_error: None,
                        }
                    }
                    Ok(_) => {
                        cache.last_error = Some("empty provider ranges".to_string());
                        log::warn!("Bot verifier provider={} returned no ranges", provider.id);
                        ProviderRefreshPersistence {
                            ranges_json: "[]".to_string(),
                            last_refresh_at: cache.last_refresh_at,
                            last_success_at: cache.last_success_at,
                            last_error: cache.last_error.clone(),
                        }
                    }
                    Err(err) => {
                        cache.last_error = Some(err.to_string());
                        let ranges_json = serde_json::to_string(
                            &cache
                                .ranges
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>(),
                        )
                        .unwrap_or_else(|_| "[]".to_string());
                        log::warn!(
                            "Bot verifier failed to refresh provider={}: {}",
                            provider.id,
                            err
                        );
                        ProviderRefreshPersistence {
                            ranges_json,
                            last_refresh_at: cache.last_refresh_at,
                            last_success_at: cache.last_success_at,
                            last_error: cache.last_error.clone(),
                        }
                    }
                }
            };

            if let Some(store) = store {
                if let Err(err) = store
                    .upsert_bot_ip_cache_entry(
                        &provider.id,
                        &refresh_result.ranges_json,
                        refresh_result.last_refresh_at,
                        refresh_result.last_success_at,
                        refresh_result.last_error.as_deref(),
                    )
                    .await
                {
                    log::warn!(
                        "Failed to persist bot verifier cache provider={}: {}",
                        provider.id,
                        err
                    );
                }
            }
        }
    }
}

struct ProviderRefreshPersistence {
    ranges_json: String,
    last_refresh_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
}

pub(crate) async fn run_bot_ip_refresh_loop(
    verifier: std::sync::Arc<BotIpVerifier>,
    configured_providers: std::sync::Arc<std::sync::RwLock<Vec<BotProviderConfig>>>,
    store: Option<std::sync::Arc<SqliteStore>>,
) {
    let providers = configured_providers
        .read()
        .expect("bot provider config lock poisoned")
        .clone();
    verifier.refresh_once(&providers, store.as_deref()).await;
    let mut interval = tokio::time::interval(Duration::from_secs(REFRESH_INTERVAL_SECS));
    loop {
        interval.tick().await;
        let providers = configured_providers
            .read()
            .expect("bot provider config lock poisoned")
            .clone();
        verifier.refresh_once(&providers, store.as_deref()).await;
        if !has_any_success(&verifier) {
            tokio::time::sleep(Duration::from_secs(INITIAL_REFRESH_RETRY_SECS)).await;
        }
    }
}

fn bot_ip_providers(configured: &[BotProviderConfig]) -> Vec<BotIpProvider> {
    configured
        .iter()
        .filter(|provider| provider.enabled)
        .filter(|provider| !provider.id.trim().is_empty() && !provider.urls.is_empty())
        .map(|provider| BotIpProvider {
            id: provider.id.trim().to_ascii_lowercase(),
            urls: provider.urls.clone(),
        })
        .collect()
}

pub(crate) fn bot_dns_provider<'a>(
    configured: &'a [BotProviderConfig],
    provider_id: &str,
) -> Option<Vec<String>> {
    configured
        .iter()
        .find(|provider| provider.enabled && provider.id.eq_ignore_ascii_case(provider_id))
        .filter(|provider| provider.reverse_dns_enabled)
        .map(|provider| provider.reverse_dns_suffixes.clone())
        .filter(|suffixes| !suffixes.is_empty())
}

fn ip_cache_status(cache: Option<&BotIpProviderCache>) -> BotVerificationStatus {
    match cache {
        Some(cache) if !cache.ranges.is_empty() && cache.last_success_at.is_some() => {
            BotVerificationStatus::NotVerified
        }
        _ => BotVerificationStatus::Unavailable,
    }
}

fn dns_key(provider: &str, ip: IpAddr) -> String {
    format!("{}|{}", provider.to_ascii_lowercase(), ip)
}

fn has_any_success(verifier: &BotIpVerifier) -> bool {
    verifier
        .cache
        .read()
        .expect("bot verifier cache lock poisoned")
        .providers
        .values()
        .any(|cache| cache.last_success_at.is_some())
}

async fn fetch_provider_ranges(
    client: &Client,
    provider: &BotIpProvider,
) -> anyhow::Result<Vec<IpNet>> {
    let mut ranges = Vec::new();
    let mut errors = Vec::new();
    for url in &provider.urls {
        match fetch_ranges_from_url(client, url).await {
            Ok(mut fetched) => ranges.append(&mut fetched),
            Err(err) => errors.push(format!("{url}: {err}")),
        }
    }
    ranges.sort_by_key(|range| range.to_string());
    ranges.dedup();
    if ranges.is_empty() && !errors.is_empty() {
        anyhow::bail!("{}", errors.join("; "));
    }
    Ok(ranges)
}

async fn verify_reverse_dns(ip: IpAddr, suffixes: &[String]) -> anyhow::Result<bool> {
    let resolver = hickory_resolver::Resolver::builder_tokio()?.build()?;
    let ptr_lookup =
        tokio::time::timeout(Duration::from_secs(3), resolver.reverse_lookup(ip)).await??;
    for record in ptr_lookup.answers() {
        let hostname = record
            .data
            .to_string()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !suffixes
            .iter()
            .any(|suffix| hostname.ends_with(suffix.trim_end_matches('.')))
        {
            continue;
        }
        let forward_lookup = tokio::time::timeout(
            Duration::from_secs(3),
            resolver.lookup_ip(hostname.as_str()),
        )
        .await??;
        if forward_lookup.iter().any(|resolved_ip| resolved_ip == ip) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn fetch_ranges_from_url(client: &Client, url: &str) -> anyhow::Result<Vec<IpNet>> {
    let response = client.get(url).send().await?.error_for_status()?;
    let payload = response.json::<Value>().await?;
    let mut ranges = Vec::new();
    collect_ip_ranges(&payload, &mut ranges);
    Ok(ranges)
}

fn collect_ip_ranges(value: &Value, ranges: &mut Vec<IpNet>) {
    match value {
        Value::String(text) => {
            if let Some(range) = parse_range(text) {
                ranges.push(range);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_ip_ranges(item, ranges);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if key.to_ascii_lowercase().contains("prefix")
                    || key.to_ascii_lowercase().contains("cidr")
                    || key.to_ascii_lowercase().contains("range")
                {
                    collect_ip_ranges(value, ranges);
                } else if matches!(value, Value::Array(_) | Value::Object(_)) {
                    collect_ip_ranges(value, ranges);
                }
            }
        }
        _ => {}
    }
}

fn parse_range(value: &str) -> Option<IpNet> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse::<IpNet>()
        .ok()
        .or_else(|| trimmed.parse::<IpAddr>().ok().map(IpNet::from))
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_ranges_from_google_style_payload() {
        let payload = serde_json::json!({
            "prefixes": [
                {"ipv4Prefix": "66.249.64.0/19"},
                {"ipv6Prefix": "2001:4860:4801::/48"}
            ]
        });
        let mut ranges = Vec::new();
        collect_ip_ranges(&payload, &mut ranges);
        let google_v4 = "66.249.66.1".parse::<IpAddr>().unwrap();
        let google_v6 = "2001:4860:4801::1".parse::<IpAddr>().unwrap();
        assert!(ranges.iter().any(|range| range.contains(&google_v4)));
        assert!(ranges.iter().any(|range| range.contains(&google_v6)));
    }
}
