mod env;
pub mod gateway;
pub mod http3;
pub mod l4;
pub mod l7;
mod normalize;
mod rules;
mod types;

pub(crate) use self::env::default_sqlite_queue_capacity;
use self::env::*;
pub use self::env::{apply_env_overrides, resolve_sqlite_path};
pub(crate) use self::normalize::deserialize_boolish;
pub(crate) use self::rules::default_rule_response_content_type;
pub use self::rules::{
    Rule, RuleAction, RuleLayer, RuleResponseBodySource, RuleResponseHeader, RuleResponseTemplate,
    Severity,
};
pub use self::types::{
    AdaptiveProtectionConfig, AdaptiveProtectionGoal, AdaptiveProtectionMode, AdminApiAuthConfig,
    AiAuditConfig, AiAuditProviderConfig, AutoSloTargets, AutoTuningConfig, AutoTuningIntent,
    AutoTuningMode, Config, ConsoleSettings, IntegrationsConfig, RuntimeProfile, SafeLineConfig,
};
pub use gateway::{
    GatewayConfig, HeaderOperation, HeaderOperationAction, HeaderOperationScope, SourceIpStrategy,
};
pub use http3::Http3Config;
pub use l4::L4Config;
pub use l7::{L7Config, UpstreamProtocolPolicy};

impl Config {
    pub fn effective_trusted_proxy_cidrs(&self) -> Vec<String> {
        let mut cidrs = Vec::new();

        for cidr in &self.l7_config.trusted_proxy_cidrs {
            if !cidrs.iter().any(|item| item == cidr) {
                cidrs.push(cidr.clone());
            }
        }
        for cidr in self.l4_config.trusted_cdn.effective_cidrs() {
            if !cidrs.iter().any(|item| item == &cidr) {
                cidrs.push(cidr);
            }
        }

        cidrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_strips_empty_udp_upstream_addr() {
        let config = Config {
            udp_upstream_addr: Some("   ".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.udp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_drops_invalid_udp_upstream_addr() {
        let config = Config {
            udp_upstream_addr: Some("not-an-addr".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.udp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_drops_invalid_tcp_upstream_addr() {
        let config = Config {
            tcp_upstream_addr: Some("not-an-addr".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.tcp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_keeps_https_tcp_upstream_addr() {
        let config = Config {
            tcp_upstream_addr: Some("https://127.0.0.1:9443".to_string()),
            ..Config::default()
        }
        .normalized();

        assert_eq!(
            config.tcp_upstream_addr.as_deref(),
            Some("https://127.0.0.1:9443")
        );
    }

    #[test]
    fn normalized_expands_https_listen_port_to_global_bind() {
        let config = Config {
            gateway_config: GatewayConfig {
                https_listen_addr: "660".to_string(),
                ..GatewayConfig::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(config.gateway_config.https_listen_addr, "0.0.0.0:660");
    }

    #[test]
    fn normalized_cleans_real_ip_headers_and_trusted_proxy_cidrs() {
        let config = Config {
            l4_config: L4Config {
                trusted_cdn: l4::TrustedCdnConfig {
                    manual_cidrs: vec![
                        " 192.0.2.0/24 ".to_string(),
                        "".to_string(),
                        "192.0.2.0/24".to_string(),
                    ],
                    ..l4::TrustedCdnConfig::default()
                },
                ..L4Config::default()
            },
            l7_config: L7Config {
                real_ip_headers: vec![
                    " X-Forwarded-For ".to_string(),
                    "".to_string(),
                    "CF-Connecting-IP".to_string(),
                ],
                trusted_proxy_cidrs: vec![
                    " 203.0.113.0/24 ".to_string(),
                    "".to_string(),
                    "198.51.100.10/32".to_string(),
                ],
                ..L7Config::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(
            config.l7_config.real_ip_headers,
            vec![
                "x-forwarded-for".to_string(),
                "cf-connecting-ip".to_string()
            ]
        );
        assert_eq!(
            config.l7_config.trusted_proxy_cidrs,
            vec!["203.0.113.0/24".to_string(), "198.51.100.10/32".to_string()]
        );
        assert_eq!(
            config.l4_config.trusted_cdn.manual_cidrs,
            vec!["192.0.2.0/24".to_string()]
        );
    }

    #[test]
    fn effective_trusted_proxy_cidrs_merge_global_and_trusted_cdn() {
        let config = Config {
            l4_config: L4Config {
                trusted_cdn: l4::TrustedCdnConfig {
                    manual_cidrs: vec!["192.0.2.0/24".to_string()],
                    edgeone_overseas: l4::TrustedCdnEdgeOneConfig {
                        enabled: true,
                        synced_cidrs: vec!["198.51.100.0/24".to_string()],
                        ..l4::TrustedCdnEdgeOneConfig::default()
                    },
                    ..l4::TrustedCdnConfig::default()
                },
                ..L4Config::default()
            },
            l7_config: L7Config {
                trusted_proxy_cidrs: vec!["203.0.113.0/24".to_string()],
                ..L7Config::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(
            config.effective_trusted_proxy_cidrs(),
            vec![
                "203.0.113.0/24".to_string(),
                "192.0.2.0/24".to_string(),
                "198.51.100.0/24".to_string()
            ]
        );
    }

    #[test]
    fn legacy_source_ip_strategy_alias_deserializes_to_first() {
        let strategy: SourceIpStrategy = serde_json::from_str("\"x_forwarded_for_any\"").unwrap();
        assert_eq!(strategy, SourceIpStrategy::XForwardedForFirst);
    }

    #[test]
    fn normalized_keeps_only_supported_ssl_protocols() {
        let config = Config {
            gateway_config: GatewayConfig {
                ssl_protocols: vec![
                    "TLSv1".to_string(),
                    " tlsv1.2 ".to_string(),
                    "TLS13".to_string(),
                    "TLSv1.1".to_string(),
                ],
                ..GatewayConfig::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(
            config.gateway_config.ssl_protocols,
            vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()]
        );
    }

    #[test]
    fn default_config_enables_standard_profile_and_api() {
        let config = Config::default();

        assert_eq!(config.runtime_profile, RuntimeProfile::Standard);
        assert_eq!(config.listen_addrs, vec!["0.0.0.0:66".to_string()]);
        assert_eq!(config.gateway_config.https_listen_addr, "0.0.0.0:660");
        assert!(config.api_enabled);
        assert!(config.bloom_enabled);
        assert!(config.l4_bloom_false_positive_verification);
        assert!(config.l7_bloom_false_positive_verification);
        assert!(config.l4_config.advanced_ddos_enabled);
        assert!(config.l7_config.upstream_healthcheck_enabled);
        assert!(config.l7_config.http2_config.enabled);
        assert!(config.gateway_config.enable_http1_0);
        assert!(config.gateway_config.http_to_https_redirect);
        assert!(config.gateway_config.enable_hsts);
        assert!(config.gateway_config.rewrite_host_enabled);
        assert!(config.gateway_config.rewrite_x_forwarded_for);
        assert!(config.gateway_config.enable_ntlm);
        assert!(config.gateway_config.fallback_self_signed_certificate);
        assert!(config.integrations.safeline.auto_sync_events);
        assert!(!config.integrations.safeline.auto_sync_blocked_ips_push);
        assert!(config.integrations.safeline.auto_sync_blocked_ips_pull);
        assert_eq!(
            config.http3_config.listen_addr,
            config.gateway_config.https_listen_addr
        );
    }

    #[test]
    fn normalized_aligns_http3_listener_with_https_entry() {
        let config = Config {
            gateway_config: GatewayConfig {
                https_listen_addr: "9443".to_string(),
                ..GatewayConfig::default()
            },
            http3_config: Http3Config {
                listen_addr: "0.0.0.0:8443".to_string(),
                ..Http3Config::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(config.gateway_config.https_listen_addr, "0.0.0.0:9443");
        assert_eq!(config.http3_config.listen_addr, "0.0.0.0:9443");
    }

    #[test]
    fn normalized_keeps_cc_block_thresholds_safely_above_challenge_thresholds() {
        let config = Config {
            l7_config: L7Config {
                cc_defense: l7::CcDefenseConfig {
                    ip_challenge_threshold: 30,
                    ip_block_threshold: 31,
                    host_challenge_threshold: 18,
                    host_block_threshold: 19,
                    route_challenge_threshold: 9,
                    route_block_threshold: 10,
                    hot_path_challenge_threshold: 40,
                    hot_path_block_threshold: 41,
                    ..l7::CcDefenseConfig::default()
                },
                ..L7Config::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(config.l7_config.cc_defense.ip_block_threshold, 60);
        assert_eq!(config.l7_config.cc_defense.host_block_threshold, 36);
        assert_eq!(config.l7_config.cc_defense.route_block_threshold, 18);
        assert_eq!(config.l7_config.cc_defense.hot_path_block_threshold, 80);
    }
}
