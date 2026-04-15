use crate::config::l7::SlowAttackDefenseConfig;
use crate::core::CustomHttpResponse;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SlowAttackGuard {
    config: RwLock<SlowAttackDefenseConfig>,
    event_buckets: DashMap<String, SlidingWindowCounter>,
}

#[derive(Debug)]
struct SlidingWindowCounter {
    events: Mutex<VecDeque<Instant>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowAttackKind {
    IdleConnection,
    SlowHeaders,
    SlowBody,
    SlowTlsHandshake,
}

#[derive(Debug, Clone)]
pub struct SlowAttackObservation {
    pub kind: SlowAttackKind,
    pub peer_ip: IpAddr,
    pub client_ip: Option<IpAddr>,
    pub trusted_proxy_peer: bool,
    pub identity_state: &'static str,
    pub client_identity_unresolved: bool,
    pub host: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SlowAttackAssessment {
    pub reason: String,
    pub event_count: u32,
    pub should_block_ip: bool,
    pub block_ip: Option<IpAddr>,
    pub block_duration_secs: u64,
}

impl SlowAttackGuard {
    pub fn new(config: &SlowAttackDefenseConfig) -> Self {
        Self {
            config: RwLock::new(config.clone()),
            event_buckets: DashMap::new(),
        }
    }

    pub fn update_config(&self, config: &SlowAttackDefenseConfig) {
        let mut guard = self
            .config
            .write()
            .expect("slow attack config lock poisoned");
        *guard = config.clone();
    }

    pub fn config(&self) -> SlowAttackDefenseConfig {
        self.config
            .read()
            .expect("slow attack config lock poisoned")
            .clone()
    }

    pub fn assess(&self, observation: SlowAttackObservation) -> SlowAttackAssessment {
        let config = self.config();
        let window_secs = slow_attack_window_secs(&config, observation.kind);
        let block_threshold = slow_attack_block_threshold(&config, observation.kind);
        let key = observation
            .client_ip
            .unwrap_or(observation.peer_ip)
            .to_string();
        let event_count = self.observe(key, Duration::from_secs(window_secs));
        let block_ip = self.block_target_ip(&observation);
        let should_block_ip =
            config.enabled && block_ip.is_some() && event_count >= block_threshold;
        let scope = observation
            .client_ip
            .map(|ip| format!("client_ip={ip}"))
            .unwrap_or_else(|| format!("peer_ip={}", observation.peer_ip));
        let host_suffix = observation
            .host
            .as_deref()
            .map(|host| format!(" host={host}"))
            .unwrap_or_default();

        SlowAttackAssessment {
            reason: format!(
                "slow attack detected: kind={} {} events_in_window={}{} detail={}",
                observation.kind.as_str(),
                scope,
                event_count,
                host_suffix,
                observation.detail,
            ),
            event_count,
            should_block_ip,
            block_ip,
            block_duration_secs: config.block_duration_secs,
        }
    }

    pub fn build_response(
        &self,
        assessment: &SlowAttackAssessment,
        kind: SlowAttackKind,
    ) -> CustomHttpResponse {
        let status_code = if assessment.should_block_ip { 429 } else { 408 };
        let action = if assessment.should_block_ip {
            "block"
        } else {
            "close"
        };
        let body = format!(
            "request terminated by rust_waf slow-attack defense: kind={} action={} detail={}",
            kind.as_str(),
            action,
            assessment.reason,
        );

        CustomHttpResponse {
            status_code,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("connection".to_string(), "close".to_string()),
                (
                    "x-rust-waf-slow-attack".to_string(),
                    kind.as_str().to_string(),
                ),
            ],
            body: body.into_bytes(),
            tarpit: None,
            random_status: None,
        }
    }

    fn observe(&self, key: String, window: Duration) -> u32 {
        let mut entry = self
            .event_buckets
            .entry(key)
            .or_insert_with(SlidingWindowCounter::new);
        entry.observe(window)
    }

    fn block_target_ip(&self, observation: &SlowAttackObservation) -> Option<IpAddr> {
        if matches!(observation.identity_state, "trusted_cdn_unresolved") {
            return None;
        }
        if matches!(observation.identity_state, "spoofed_forward_header") {
            return Some(observation.peer_ip);
        }
        if observation.client_identity_unresolved {
            return None;
        }
        if let Some(client_ip) = observation.client_ip {
            return Some(client_ip);
        }
        if observation.trusted_proxy_peer {
            None
        } else {
            Some(observation.peer_ip)
        }
    }
}

fn slow_attack_window_secs(config: &SlowAttackDefenseConfig, kind: SlowAttackKind) -> u64 {
    match kind {
        SlowAttackKind::SlowTlsHandshake => config.event_window_secs.min(180).max(30),
        _ => config.event_window_secs.max(1),
    }
}

fn slow_attack_block_threshold(config: &SlowAttackDefenseConfig, kind: SlowAttackKind) -> u32 {
    match kind {
        SlowAttackKind::SlowTlsHandshake => config.max_events_per_window.min(3).max(1),
        _ => config.max_events_per_window.max(1),
    }
}

impl SlidingWindowCounter {
    fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
        }
    }

    fn observe(&mut self, window: Duration) -> u32 {
        let now = Instant::now();
        let mut events = self
            .events
            .lock()
            .expect("slow attack bucket lock poisoned");
        while let Some(front) = events.front() {
            if now.duration_since(*front) > window {
                events.pop_front();
            } else {
                break;
            }
        }
        events.push_back(now);
        events.len().min(u32::MAX as usize) as u32
    }
}

impl SlowAttackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleConnection => "idle_connection",
            Self::SlowHeaders => "slow_headers",
            Self::SlowBody => "slow_body",
            Self::SlowTlsHandshake => "slow_tls_handshake",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_proxy_without_client_identity_does_not_escalate_to_block() {
        let guard = SlowAttackGuard::new(&SlowAttackDefenseConfig {
            max_events_per_window: 1,
            ..SlowAttackDefenseConfig::default()
        });

        let assessment = guard.assess(SlowAttackObservation {
            kind: SlowAttackKind::SlowHeaders,
            peer_ip: "203.0.113.10".parse().unwrap(),
            client_ip: None,
            trusted_proxy_peer: true,
            identity_state: "trusted_cdn_unresolved",
            client_identity_unresolved: true,
            host: None,
            detail: "headers stalled".to_string(),
        });

        assert!(!assessment.should_block_ip);
        assert!(assessment.block_ip.is_none());
    }

    #[test]
    fn spoofed_forward_header_slow_attack_blocks_peer_ip() {
        let guard = SlowAttackGuard::new(&SlowAttackDefenseConfig {
            max_events_per_window: 1,
            ..SlowAttackDefenseConfig::default()
        });

        let assessment = guard.assess(SlowAttackObservation {
            kind: SlowAttackKind::SlowHeaders,
            peer_ip: "203.0.113.15".parse().unwrap(),
            client_ip: None,
            trusted_proxy_peer: false,
            identity_state: "spoofed_forward_header",
            client_identity_unresolved: false,
            host: None,
            detail: "spoofed header slow attack".to_string(),
        });

        assert!(assessment.should_block_ip);
        assert_eq!(assessment.block_ip, Some("203.0.113.15".parse().unwrap()));
    }

    #[test]
    fn slow_tls_handshake_uses_tighter_thresholds() {
        let guard = SlowAttackGuard::new(&SlowAttackDefenseConfig {
            event_window_secs: 300,
            max_events_per_window: 4,
            ..SlowAttackDefenseConfig::default()
        });

        let make_observation = || SlowAttackObservation {
            kind: SlowAttackKind::SlowTlsHandshake,
            peer_ip: "203.0.113.20".parse().unwrap(),
            client_ip: None,
            trusted_proxy_peer: false,
            identity_state: "direct_client",
            client_identity_unresolved: false,
            host: None,
            detail: "listener=0.0.0.0:660 timeout_ms=3000".to_string(),
        };

        assert!(!guard.assess(make_observation()).should_block_ip);
        assert!(!guard.assess(make_observation()).should_block_ip);
        assert!(guard.assess(make_observation()).should_block_ip);
    }
}
