use super::{unix_timestamp, WafContext};
use crate::locks::{read_lock, write_lock};
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use reqwest::Client;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const SERVER_PUBLIC_IP_REFRESH_SECS: i64 = 15 * 60;
const SERVER_PUBLIC_IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const SERVER_PUBLIC_IP_ENDPOINTS: [&str; 3] = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

#[derive(Debug, Clone, Default)]
pub struct ServerPublicIpSnapshot {
    pub ips: Vec<String>,
    pub last_refresh_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
pub(super) struct ServerPublicIpRuntime {
    ips: HashSet<IpAddr>,
    last_refresh_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: Option<String>,
}

impl WafContext {
    pub async fn refresh_server_public_ip_allowlist(&self, force: bool) -> Result<usize> {
        let now = unix_timestamp();
        if !force && !self.server_public_ip_refresh_due(now) {
            return Ok(self.server_public_ip_snapshot().ips.len());
        }

        self.set_server_public_ip_refresh_started(now);
        let detected = detect_server_public_ips(&self.config_snapshot()).await;
        match detected {
            Ok(ips) if !ips.is_empty() => {
                let count = ips.len();
                self.replace_server_public_ips(ips, now, None);
                self.remove_server_public_ips_from_local_blocks().await;
                info!(
                    "Server public IP allowlist refreshed with {} address(es): {:?}",
                    count,
                    self.server_public_ip_snapshot().ips
                );
                Ok(count)
            }
            Ok(_) => {
                let message = "no public IP detected from configured listeners or lookup endpoints";
                self.set_server_public_ip_error(now, message.to_string());
                debug!("Server public IP allowlist refresh skipped: {message}");
                Ok(0)
            }
            Err(err) => {
                self.set_server_public_ip_error(now, err.to_string());
                warn!("Failed to refresh server public IP allowlist: {}", err);
                Err(err)
            }
        }
    }

    pub fn server_public_ip_snapshot(&self) -> ServerPublicIpSnapshot {
        let guard = read_lock(&self.server_public_ips, "server_public_ips");
        let mut ips = guard
            .ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        ips.sort();
        ServerPublicIpSnapshot {
            ips,
            last_refresh_at: guard.last_refresh_at,
            last_success_at: guard.last_success_at,
            last_error: guard.last_error.clone(),
        }
    }

    pub fn is_server_public_ip(&self, ip: IpAddr) -> bool {
        read_lock(&self.server_public_ips, "server_public_ips")
            .ips
            .contains(&ip)
    }

    pub fn is_server_public_ip_str(&self, value: &str) -> bool {
        value
            .trim()
            .parse::<IpAddr>()
            .map(|ip| self.is_server_public_ip(ip))
            .unwrap_or(false)
    }

    pub(crate) fn learn_server_public_ip_candidate(&self, ip: IpAddr, reason: &str) -> bool {
        if !is_public_routable_ip(ip) {
            return false;
        }
        let mut guard = write_lock(&self.server_public_ips, "server_public_ips");
        if !guard.ips.insert(ip) {
            return true;
        }
        let now = unix_timestamp();
        guard.last_success_at = Some(now);
        guard.last_error = None;
        info!("Learned server public IP {} from {}", ip, reason);
        true
    }

    pub async fn remove_server_public_ip_from_local_blocks(&self, value: &str) {
        let Ok(ip) = value.trim().parse::<IpAddr>() else {
            return;
        };
        if !self.is_server_public_ip(ip) {
            return;
        }
        self.remove_server_public_ips_from_local_blocks().await;
    }

    #[cfg(test)]
    pub(crate) fn replace_server_public_ips_for_test(&self, ips: impl IntoIterator<Item = IpAddr>) {
        self.replace_server_public_ips(ips.into_iter().collect(), unix_timestamp(), None);
    }

    fn server_public_ip_refresh_due(&self, now: i64) -> bool {
        let guard = read_lock(&self.server_public_ips, "server_public_ips");
        guard
            .last_refresh_at
            .map(|last| now.saturating_sub(last) >= SERVER_PUBLIC_IP_REFRESH_SECS)
            .unwrap_or(true)
    }

    fn set_server_public_ip_refresh_started(&self, now: i64) {
        let mut guard = write_lock(&self.server_public_ips, "server_public_ips");
        guard.last_refresh_at = Some(now);
    }

    fn replace_server_public_ips(
        &self,
        ips: HashSet<IpAddr>,
        now: i64,
        last_error: Option<String>,
    ) {
        let mut guard = write_lock(&self.server_public_ips, "server_public_ips");
        guard.ips = ips;
        guard.last_refresh_at = Some(now);
        guard.last_success_at = Some(now);
        guard.last_error = last_error;
    }

    fn set_server_public_ip_error(&self, now: i64, error: String) {
        let mut guard = write_lock(&self.server_public_ips, "server_public_ips");
        guard.last_refresh_at = Some(now);
        guard.last_error = Some(error);
    }

    async fn remove_server_public_ips_from_local_blocks(&self) {
        let Some(store) = self.sqlite_store.as_ref() else {
            return;
        };
        let entries = match store.list_active_local_blocked_ips().await {
            Ok(entries) => entries,
            Err(err) => {
                warn!(
                    "Failed to inspect local blocked IPs for server public IP cleanup: {}",
                    err
                );
                return;
            }
        };
        let mut removed = 0_u64;
        for entry in entries {
            let Ok(ip) = entry.ip.parse::<IpAddr>() else {
                continue;
            };
            if !self.is_server_public_ip(ip) {
                continue;
            }
            if let Some(inspector) = self.l4_inspector() {
                inspector.unblock_ip(&ip);
            }
            match store.delete_blocked_ip(entry.id).await {
                Ok(true) => {
                    removed = removed.saturating_add(1);
                    store.emit_blocked_ip_deleted(entry.id);
                }
                Ok(false) => {}
                Err(err) => warn!(
                    "Failed to remove server public IP {} from local blocked IPs: {}",
                    entry.ip, err
                ),
            }
        }
        if removed > 0 {
            info!(
                "Removed {} active local blocked IP entrie(s) for server public IP allowlist",
                removed
            );
        }
    }
}

async fn detect_server_public_ips(config: &crate::config::Config) -> Result<HashSet<IpAddr>> {
    let mut ips = configured_public_listener_ips(config);
    let client = Client::builder()
        .timeout(SERVER_PUBLIC_IP_LOOKUP_TIMEOUT)
        .build()?;

    let mut errors = Vec::new();
    for endpoint in SERVER_PUBLIC_IP_ENDPOINTS {
        match lookup_public_ip(&client, endpoint).await {
            Ok(ip) => {
                ips.insert(ip);
                break;
            }
            Err(err) => errors.push(format!("{endpoint}: {err}")),
        }
    }

    if ips.is_empty() && !errors.is_empty() {
        return Err(anyhow!(errors.join("; ")));
    }

    Ok(ips)
}

fn configured_public_listener_ips(config: &crate::config::Config) -> HashSet<IpAddr> {
    config
        .listen_addrs
        .iter()
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| addr.ip())
        .filter(|ip| is_public_routable_ip(*ip))
        .collect()
}

async fn lookup_public_ip(client: &Client, endpoint: &str) -> Result<IpAddr> {
    let response = client.get(endpoint).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("status {}", response.status()));
    }
    let body = response.text().await?;
    let ip = body
        .trim()
        .trim_matches('"')
        .parse::<IpAddr>()
        .map_err(|err| anyhow!("invalid ip response {:?}: {}", body.trim(), err))?;
    if !is_public_routable_ip(ip) {
        return Err(anyhow!("non-public ip response {ip}"));
    }
    Ok(ip)
}

fn is_public_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}
