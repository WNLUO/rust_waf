use anyhow::Result;
use log::{info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{Duration, MissedTickBehavior};

use crate::config::Config;
use crate::core::WafContext;

#[derive(Clone, Copy)]
enum SafeLineAutoSyncTask {
    Events,
    BlockedIpsPush,
    BlockedIpsPull,
}

impl SafeLineAutoSyncTask {
    const ALL: [Self; 3] = [Self::Events, Self::BlockedIpsPush, Self::BlockedIpsPull];

    fn resource(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::BlockedIpsPush => "blocked_ips_push",
            Self::BlockedIpsPull => "blocked_ips_pull",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Events => "事件同步",
            Self::BlockedIpsPush => "封禁推送",
            Self::BlockedIpsPull => "封禁回流",
        }
    }

    fn enabled(self, config: &crate::config::SafeLineConfig) -> bool {
        match self {
            Self::Events => config.auto_sync_events,
            Self::BlockedIpsPush => config.auto_sync_blocked_ips_push,
            Self::BlockedIpsPull => config.auto_sync_blocked_ips_pull,
        }
    }
}

pub(super) async fn run_safeline_auto_sync_loop(
    store: Arc<crate::storage::SqliteStore>,
    fallback_config: Config,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_attempts: HashMap<&'static str, i64> = HashMap::new();

    loop {
        interval.tick().await;

        let config = match store.load_app_config().await {
            Ok(Some(config)) => config.normalized(),
            Ok(None) => fallback_config.clone().normalized(),
            Err(err) => {
                warn!(
                    "Failed to load persisted config for SafeLine auto sync: {}",
                    err
                );
                continue;
            }
        };
        let safeline = &config.integrations.safeline;

        if !safeline.enabled || !crate::integrations::safeline_sync::is_configured(safeline) {
            continue;
        }

        for task in SafeLineAutoSyncTask::ALL {
            if !task.enabled(safeline) {
                continue;
            }

            let last_persisted_run = match store.load_safeline_sync_state(task.resource()).await {
                Ok(state) => state.map(|item| item.updated_at).unwrap_or(0),
                Err(err) => {
                    warn!(
                        "Failed to read SafeLine sync state for {}: {}",
                        task.label(),
                        err
                    );
                    continue;
                }
            };
            let last_attempt = last_attempts.get(task.resource()).copied().unwrap_or(0);
            let now = unix_timestamp();
            let last_run_at = last_persisted_run.max(last_attempt);

            if last_run_at > 0
                && now.saturating_sub(last_run_at) < safeline.auto_sync_interval_secs as i64
            {
                continue;
            }

            last_attempts.insert(task.resource(), now);

            match task {
                SafeLineAutoSyncTask::Events => {
                    match crate::integrations::safeline_sync::sync_events(store.as_ref(), safeline)
                        .await
                    {
                        Ok(result) => info!(
                            "SafeLine 自动{}完成：新增 {} 条，跳过 {} 条。",
                            task.label(),
                            result.imported,
                            result.skipped
                        ),
                        Err(err) => warn!("SafeLine 自动{}失败: {}", task.label(), err),
                    }
                }
                SafeLineAutoSyncTask::BlockedIpsPush => {
                    match crate::integrations::safeline_sync::push_blocked_ips(
                        store.as_ref(),
                        safeline,
                    )
                    .await
                    {
                        Ok(result) => info!(
                            "SafeLine 自动{}完成：成功 {} 条，跳过 {} 条，失败 {} 条。",
                            task.label(),
                            result.synced,
                            result.skipped,
                            result.failed
                        ),
                        Err(err) => warn!("SafeLine 自动{}失败: {}", task.label(), err),
                    }
                }
                SafeLineAutoSyncTask::BlockedIpsPull => {
                    match crate::integrations::safeline_sync::pull_blocked_ips(
                        store.as_ref(),
                        safeline,
                    )
                    .await
                    {
                        Ok(result) => info!(
                            "SafeLine 自动{}完成：新增 {} 条，跳过 {} 条。",
                            task.label(),
                            result.imported,
                            result.skipped
                        ),
                        Err(err) => warn!("SafeLine 自动{}失败: {}", task.label(), err),
                    }
                }
            }
        }
    }
}

pub(super) async fn run_trusted_cdn_sync_loop(context: Arc<WafContext>) {
    let Some(store) = context.sqlite_store.as_ref().cloned() else {
        return;
    };
    let client = match crate::integrations::trusted_cdn::build_sync_client() {
        Ok(client) => client,
        Err(err) => {
            warn!("Failed to initialize trusted CDN sync client: {}", err);
            return;
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let snapshot = context.config_snapshot();
        let trusted_cdn = &snapshot.l4_config.trusted_cdn;
        let sync_interval_secs = trusted_cdn.sync_interval_secs();
        let now = unix_timestamp();
        let mut results = Vec::new();

        if trusted_cdn.edgeone_overseas.enabled
            && crate::integrations::trusted_cdn::provider_due(
                trusted_cdn.edgeone_overseas.last_synced_at,
                sync_interval_secs,
                now,
            )
        {
            results.push(crate::integrations::trusted_cdn::sync_edgeone_overseas(&client).await);
        }

        if trusted_cdn.aliyun_esa.enabled
            && crate::integrations::trusted_cdn::provider_due(
                trusted_cdn.aliyun_esa.last_synced_at,
                sync_interval_secs,
                now,
            )
        {
            results.push(
                crate::integrations::trusted_cdn::sync_aliyun_esa(&client, &trusted_cdn.aliyun_esa)
                    .await,
            );
        }

        if results.is_empty() {
            continue;
        }

        let mut latest = match store.load_app_config().await {
            Ok(Some(config)) => config.normalized(),
            Ok(None) => context.config_snapshot(),
            Err(err) => {
                warn!(
                    "Failed to load persisted config for trusted CDN sync: {}",
                    err
                );
                continue;
            }
        };

        for result in results {
            match result.provider {
                crate::integrations::trusted_cdn::TrustedCdnProviderKind::EdgeOneOverseas => {
                    latest.l4_config.trusted_cdn.edgeone_overseas.last_synced_at =
                        Some(result.synced_at);
                    latest
                        .l4_config
                        .trusted_cdn
                        .edgeone_overseas
                        .last_sync_status = result.status;
                    latest
                        .l4_config
                        .trusted_cdn
                        .edgeone_overseas
                        .last_sync_message = result.message.clone();
                    if let Some(cidrs) = result.synced_cidrs {
                        latest.l4_config.trusted_cdn.edgeone_overseas.synced_cidrs = cidrs;
                    }
                }
                crate::integrations::trusted_cdn::TrustedCdnProviderKind::AliyunEsa => {
                    latest.l4_config.trusted_cdn.aliyun_esa.last_synced_at = Some(result.synced_at);
                    latest.l4_config.trusted_cdn.aliyun_esa.last_sync_status = result.status;
                    latest.l4_config.trusted_cdn.aliyun_esa.last_sync_message =
                        result.message.clone();
                    if let Some(cidrs) = result.synced_cidrs {
                        latest.l4_config.trusted_cdn.aliyun_esa.synced_cidrs = cidrs;
                    }
                }
            }
        }

        latest = latest.normalized();
        if let Err(err) = store.upsert_app_config(&latest).await {
            warn!("Failed to persist trusted CDN sync result: {}", err);
            continue;
        }
        context.apply_runtime_config(latest);
    }
}

pub(super) async fn run_upstream_healthcheck_loop(context: Arc<WafContext>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    let mut last_probe_at: Option<i64> = None;

    loop {
        interval.tick().await;
        let config = context.config_snapshot();
        if !config.l7_config.upstream_healthcheck_enabled {
            continue;
        }
        let Some(upstream_addr) = config.tcp_upstream_addr.clone() else {
            continue;
        };
        let now = unix_timestamp();
        if !should_run_upstream_probe(
            last_probe_at,
            now,
            config.l7_config.upstream_healthcheck_interval_secs,
        ) {
            continue;
        }
        last_probe_at = Some(now);
        match probe_upstream_tcp(
            &upstream_addr,
            config.l7_config.upstream_healthcheck_timeout_ms,
        )
        .await
        {
            Ok(()) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_upstream_healthcheck(true);
                }
                context.set_upstream_health(true, None);
            }
            Err(err) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_upstream_healthcheck(false);
                }
                context.set_upstream_health(false, Some(err.to_string()));
            }
        }
    }
}

pub(super) async fn run_auto_tuning_loop(context: Arc<WafContext>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        if let Err(err) = context.run_auto_tuning_tick().await {
            warn!("Auto tuning tick failed: {}", err);
        }
    }
}

pub(super) async fn probe_upstream_tcp(upstream_addr: &str, timeout_ms: u64) -> Result<()> {
    let authority = crate::core::gateway::parse_upstream_endpoint(upstream_addr)?.authority;
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        TcpStream::connect(authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream health check timed out"))??;
    Ok(())
}

fn should_run_upstream_probe(last_probe_at: Option<i64>, now: i64, interval_secs: u64) -> bool {
    match last_probe_at {
        None => true,
        Some(last) => now.saturating_sub(last) >= interval_secs.max(1) as i64,
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::should_run_upstream_probe;

    #[test]
    fn upstream_probe_respects_configured_interval() {
        assert!(should_run_upstream_probe(None, 100, 5));
        assert!(!should_run_upstream_probe(Some(100), 104, 5));
        assert!(should_run_upstream_probe(Some(100), 105, 5));
        assert!(should_run_upstream_probe(Some(100), 101, 0));
    }
}
