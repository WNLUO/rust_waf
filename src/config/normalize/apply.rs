use std::net::SocketAddr;

use super::super::*;
use super::{gateway_and_integrations, profile};

impl Config {
    pub fn normalized(mut self) -> Self {
        normalize_base_config(&mut self);
        profile::normalize_profile_settings(&mut self);
        profile::normalize_l4_behavior_thresholds(&mut self);
        gateway_and_integrations::normalize_l7_settings(&mut self);

        if !self.bloom_enabled {
            self.l4_bloom_false_positive_verification = false;
            self.l7_bloom_false_positive_verification = false;
        }

        if let Err(err) = self.http3_config.validate() {
            log::warn!(
                "HTTP/3.0 configuration validation failed: {}, using defaults",
                err
            );
            self.http3_config = Http3Config::default();
        }

        if self.runtime_profile.is_minimal() {
            self.maintenance_interval_secs = clamp_u64(self.maintenance_interval_secs, 30, 300, 60);
        } else {
            self.maintenance_interval_secs = clamp_u64(self.maintenance_interval_secs, 5, 180, 30);
        }

        if self.max_concurrent_tasks == 0 {
            self.max_concurrent_tasks = if self.runtime_profile.is_minimal() {
                128
            } else {
                512
            };
        }

        let (min_concurrency, max_concurrency) = if self.runtime_profile.is_minimal() {
            (32usize, 256usize)
        } else {
            (128usize, 1024usize)
        };
        self.max_concurrent_tasks = self
            .max_concurrent_tasks
            .clamp(min_concurrency, max_concurrency);

        gateway_and_integrations::normalize_console_and_gateway(&mut self);
        gateway_and_integrations::normalize_integrations_and_admin(&mut self);

        self
    }
}

fn normalize_base_config(config: &mut Config) {
    if config.sqlite_path.trim().is_empty() {
        config.sqlite_path = default_sqlite_path();
    }

    if !config.sqlite_enabled {
        config.sqlite_rules_enabled = false;
    } else {
        config.sqlite_auto_migrate = true;
    }

    config.sqlite_queue_capacity = if config.runtime_profile.is_minimal() {
        clamp_or_default(config.sqlite_queue_capacity, 512).clamp(128, 4_096)
    } else {
        clamp_or_default(config.sqlite_queue_capacity, 1024).clamp(256, 16_384)
    };

    if config.listen_addrs.is_empty() {
        config.listen_addrs = vec!["0.0.0.0:8080".to_string()];
    }

    config.udp_upstream_addr = config.udp_upstream_addr.take().and_then(|addr| {
        let trimmed = addr.trim();
        if trimmed.is_empty() {
            None
        } else {
            match trimmed.parse::<SocketAddr>() {
                Ok(_) => Some(trimmed.to_string()),
                Err(err) => {
                    log::warn!(
                        "Invalid udp_upstream_addr '{}': {}, disabling UDP forwarding",
                        trimmed,
                        err
                    );
                    None
                }
            }
        }
    });

    config.tcp_upstream_addr = config.tcp_upstream_addr.take().and_then(|addr| {
        let trimmed = addr.trim();
        if trimmed.is_empty() {
            None
        } else {
            match crate::core::gateway::normalize_upstream_endpoint(trimmed) {
                Ok(endpoint) => Some(endpoint),
                Err(err) => {
                    log::warn!(
                        "Invalid tcp_upstream_addr '{}': {}, disabling TCP forwarding",
                        trimmed,
                        err
                    );
                    None
                }
            }
        }
    });

    if config.listen_addrs.len() > 1 && config.runtime_profile.is_minimal() {
        log::info!("Multiple listen addresses detected, upgrading to Standard profile");
        config.runtime_profile = RuntimeProfile::Standard;
    }
}
