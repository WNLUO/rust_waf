use ipnet::IpNet;
use reqwest::Client;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

use crate::storage::{BotIpCacheEntry, SqliteStore};

const REFRESH_INTERVAL_SECS: u64 = 6 * 60 * 60;
const INITIAL_REFRESH_RETRY_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BotVerificationStatus {
    Verified,
    NotVerified,
    Unavailable,
}

#[derive(Debug, Clone)]
struct BotIpProvider {
    id: &'static str,
    urls: &'static [&'static str],
}

#[derive(Debug, Default)]
struct BotIpCache {
    providers: BTreeMap<String, BotIpProviderCache>,
}

#[derive(Debug, Default)]
struct BotIpProviderCache {
    ranges: Vec<IpNet>,
    last_refresh_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
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

const PROVIDERS: &[BotIpProvider] = &[
    BotIpProvider {
        id: "google",
        urls: &[
            "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
            "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
            "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
            "https://developers.google.com/crawling/ipranges/common-crawlers.json",
            "https://developers.google.com/crawling/ipranges/special-crawlers.json",
            "https://developers.google.com/crawling/ipranges/user-triggered-fetchers.json",
        ],
    },
    BotIpProvider {
        id: "bing",
        urls: &["https://www.bing.com/toolbox/bingbot.json"],
    },
];

impl BotIpVerifier {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn verify(&self, provider: &str, ip: IpAddr) -> BotVerificationStatus {
        let guard = self.cache.read().expect("bot verifier cache lock poisoned");
        let Some(cache) = guard.providers.get(provider) else {
            return BotVerificationStatus::Unavailable;
        };
        if cache.ranges.is_empty() || cache.last_success_at.is_none() {
            return BotVerificationStatus::Unavailable;
        }
        if cache.ranges.iter().any(|range| range.contains(&ip)) {
            BotVerificationStatus::Verified
        } else {
            BotVerificationStatus::NotVerified
        }
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

    pub(crate) fn snapshot(&self) -> BotVerifierSnapshot {
        let guard = self.cache.read().expect("bot verifier cache lock poisoned");
        let mut providers = PROVIDERS
            .iter()
            .map(|provider| {
                let cache = guard.providers.get(provider.id);
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
                    provider: provider.id.to_string(),
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

    pub(crate) async fn refresh_once(&self, store: Option<&SqliteStore>) {
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

        for provider in PROVIDERS {
            let result = fetch_provider_ranges(&client, provider).await;
            let refresh_result = {
                let mut guard = self
                    .cache
                    .write()
                    .expect("bot verifier cache lock poisoned");
                let cache = guard.providers.entry(provider.id.to_string()).or_default();
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
                        provider.id,
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
    store: Option<std::sync::Arc<SqliteStore>>,
) {
    verifier.refresh_once(store.as_deref()).await;
    let mut interval = tokio::time::interval(Duration::from_secs(REFRESH_INTERVAL_SECS));
    loop {
        interval.tick().await;
        verifier.refresh_once(store.as_deref()).await;
        if !has_any_success(&verifier) {
            tokio::time::sleep(Duration::from_secs(INITIAL_REFRESH_RETRY_SECS)).await;
        }
    }
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
    for url in provider.urls {
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
