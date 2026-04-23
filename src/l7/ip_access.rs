use crate::config::l7::{IpAccessAction, IpAccessConfig, IpAccessMode};
use crate::core::{InspectionLayer, InspectionResult, WafContext};
use crate::locks::{read_lock, write_lock};
use crate::protocol::UnifiedHttpRequest;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::RwLock;

#[derive(Debug)]
pub struct IpAccessGuard {
    state: RwLock<IpAccessState>,
}

#[derive(Debug, Clone)]
struct IpAccessState {
    config: IpAccessConfig,
    allow_cidrs: Vec<IpNet>,
    block_cidrs: Vec<IpNet>,
    domestic_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone)]
struct GeoSignal {
    country_code: Option<String>,
    source: &'static str,
    trusted: bool,
}

impl IpAccessGuard {
    pub fn new(config: &IpAccessConfig) -> Self {
        Self {
            state: RwLock::new(IpAccessState::new(config)),
        }
    }

    pub fn update_config(&self, config: &IpAccessConfig) {
        *write_lock(&self.state, "ip_access") = IpAccessState::new(config);
    }

    pub fn inspect_request(
        &self,
        context: &WafContext,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let state = read_lock(&self.state, "ip_access").clone();
        let config = &state.config;
        if !config.enabled {
            return None;
        }

        request.add_metadata("ip_access.enabled".to_string(), "true".to_string());
        request.add_metadata(
            "ip_access.mode".to_string(),
            ip_access_mode_label(config.mode).to_string(),
        );

        let client_ip = request
            .client_ip
            .as_deref()
            .and_then(|value| value.trim().parse::<IpAddr>().ok())?;
        request.add_metadata("ip_access.client_ip".to_string(), client_ip.to_string());

        if config.allow_server_public_ip
            && request
                .get_metadata("network.server_public_ip_exempt")
                .is_some_and(|value| value == "true")
        {
            return self.allow(request, "server_public_ip_allowed");
        }

        if config.allow_private_ips && is_private_or_local_ip(client_ip) {
            return self.allow(request, "private_ip_allowed");
        }

        if state
            .block_cidrs
            .iter()
            .any(|cidr| cidr.contains(&client_ip))
        {
            return self.enforce(
                context,
                request,
                IpAccessAction::Block,
                "block_cidr_matched",
                None,
            );
        }

        if state
            .allow_cidrs
            .iter()
            .any(|cidr| cidr.contains(&client_ip))
        {
            return self.allow(request, "allow_cidr_matched");
        }

        if let Some(result) = self.evaluate_bot_policy(context, request, config) {
            return result;
        }

        let geo = self.resolve_geo_signal(request, client_ip, &state);
        if let Some(country_code) = geo.country_code.as_deref() {
            request.add_metadata(
                "ip_access.country_code".to_string(),
                country_code.to_string(),
            );
        }
        request.add_metadata("ip_access.geo.source".to_string(), geo.source.to_string());
        request.add_metadata("ip_access.geo.trusted".to_string(), geo.trusted.to_string());

        if geo
            .country_code
            .as_deref()
            .is_some_and(|country| is_domestic_country(config, country))
        {
            return self.allow(request, "domestic_country_allowed");
        }

        if state
            .domestic_cidrs
            .iter()
            .any(|cidr| cidr.contains(&client_ip))
        {
            request.add_metadata(
                "ip_access.geo.source".to_string(),
                "domestic_cidr".to_string(),
            );
            return self.allow(request, "domestic_cidr_allowed");
        }

        let (action, reason) = if geo.country_code.is_some() {
            (
                match config.mode {
                    IpAccessMode::Monitor => IpAccessAction::Alert,
                    IpAccessMode::DomesticOnly => config.overseas_action,
                    IpAccessMode::Custom => config.default_action,
                },
                match config.overseas_action {
                    IpAccessAction::Block => "overseas_country_blocked",
                    IpAccessAction::Challenge => "overseas_country_challenged",
                    IpAccessAction::Alert => "overseas_country_alerted",
                    IpAccessAction::Allow => "overseas_country_allowed",
                },
            )
        } else {
            (
                match config.mode {
                    IpAccessMode::Monitor => IpAccessAction::Alert,
                    _ => config.unknown_geo_action,
                },
                match config.unknown_geo_action {
                    IpAccessAction::Block => "unknown_geo_blocked",
                    IpAccessAction::Challenge => "unknown_geo_challenged",
                    IpAccessAction::Alert => "unknown_geo_alerted",
                    IpAccessAction::Allow => "unknown_geo_allowed",
                },
            )
        };

        self.enforce(
            context,
            request,
            action,
            reason,
            geo.country_code.as_deref(),
        )
    }

    fn evaluate_bot_policy(
        &self,
        context: &WafContext,
        request: &mut UnifiedHttpRequest,
        config: &IpAccessConfig,
    ) -> Option<Option<InspectionResult>> {
        let trust_class = request
            .get_metadata("client.trust_class")
            .map(String::as_str)
            .unwrap_or("unknown")
            .to_string();
        let category = request
            .get_metadata("bot.category")
            .map(String::as_str)
            .unwrap_or("")
            .to_string();
        request.add_metadata(
            "ip_access.bot.trust_class".to_string(),
            trust_class.to_string(),
        );
        if !category.is_empty() {
            request.add_metadata("ip_access.bot.category".to_string(), category.to_string());
        }

        if trust_class == "verified_good_bot"
            && category == "search"
            && config.bot_policy.allow_verified_search_bots
        {
            return Some(self.allow(request, "verified_search_bot_allowed"));
        }
        if trust_class == "claimed_good_bot" && category == "search" {
            if config.bot_policy.allow_claimed_search_bots {
                return Some(self.allow(request, "claimed_search_bot_allowed"));
            }
            return Some(self.enforce(
                context,
                request,
                config.bot_policy.claimed_search_bot_action,
                "claimed_search_bot_challenged",
                None,
            ));
        }
        if trust_class == "suspect_bot" {
            return Some(self.enforce(
                context,
                request,
                config.bot_policy.suspect_bot_action,
                "suspect_bot_challenged",
                None,
            ));
        }
        if category == "ai" && config.bot_policy.allow_ai_bots {
            return Some(self.allow(request, "ai_bot_allowed"));
        }
        None
    }

    fn resolve_geo_signal(
        &self,
        request: &mut UnifiedHttpRequest,
        client_ip: IpAddr,
        state: &IpAccessState,
    ) -> GeoSignal {
        let config = &state.config;
        if config.geo_headers.enabled {
            let trusted_proxy = request
                .get_metadata("network.trusted_proxy_peer")
                .is_some_and(|value| value == "true");
            let header_allowed = trusted_proxy || !config.geo_headers.trust_only_from_proxy;
            for header in &config.geo_headers.country_headers {
                let Some(value) = request.get_header(header) else {
                    continue;
                };
                if !header_allowed {
                    request.add_metadata(
                        "ip_access.geo.header_ignored".to_string(),
                        "untrusted_peer".to_string(),
                    );
                    return GeoSignal {
                        country_code: None,
                        source: "cdn_header_untrusted",
                        trusted: false,
                    };
                }
                if let Some(country_code) = normalize_country_code(value) {
                    request.add_metadata("ip_access.geo.header".to_string(), header.clone());
                    add_optional_geo_header_metadata(
                        request,
                        "ip_access.region",
                        &config.geo_headers.region_headers,
                    );
                    add_optional_geo_header_metadata(
                        request,
                        "ip_access.city",
                        &config.geo_headers.city_headers,
                    );
                    return GeoSignal {
                        country_code: Some(country_code),
                        source: "cdn_header",
                        trusted: true,
                    };
                }
            }
        }

        if state
            .domestic_cidrs
            .iter()
            .any(|cidr| cidr.contains(&client_ip))
        {
            return GeoSignal {
                country_code: Some("CN".to_string()),
                source: "domestic_cidr",
                trusted: true,
            };
        }

        GeoSignal {
            country_code: None,
            source: "unknown",
            trusted: false,
        }
    }

    fn allow(
        &self,
        request: &mut UnifiedHttpRequest,
        reason: &'static str,
    ) -> Option<InspectionResult> {
        request.add_metadata("ip_access.action".to_string(), "allow".to_string());
        request.add_metadata("ip_access.reason".to_string(), reason.to_string());
        None
    }

    fn enforce(
        &self,
        context: &WafContext,
        request: &mut UnifiedHttpRequest,
        action: IpAccessAction,
        reason: &'static str,
        country_code: Option<&str>,
    ) -> Option<InspectionResult> {
        let reason_text = format!(
            "ip access policy {}: client_ip={} country={} source={}",
            reason,
            request.client_ip.as_deref().unwrap_or("unknown"),
            country_code.unwrap_or_else(|| {
                request
                    .get_metadata("ip_access.country_code")
                    .map(String::as_str)
                    .unwrap_or("unknown")
            }),
            request
                .get_metadata("ip_access.geo.source")
                .map(String::as_str)
                .unwrap_or("unknown")
        );
        request.add_metadata("ip_access.reason".to_string(), reason.to_string());

        match action {
            IpAccessAction::Allow => {
                request.add_metadata("ip_access.action".to_string(), "allow".to_string());
                None
            }
            IpAccessAction::Alert => {
                request.add_metadata("ip_access.action".to_string(), "alert".to_string());
                Some(InspectionResult::alert(InspectionLayer::L7, reason_text))
            }
            IpAccessAction::Block => {
                request.add_metadata("ip_access.action".to_string(), "block".to_string());
                Some(InspectionResult::block(InspectionLayer::L7, reason_text))
            }
            IpAccessAction::Challenge => {
                if context.l7_cc_guard().has_valid_request_challenge(request) {
                    request.add_metadata(
                        "ip_access.action".to_string(),
                        "challenge_verified".to_string(),
                    );
                    return None;
                }
                request.add_metadata("ip_access.action".to_string(), "challenge".to_string());
                context
                    .l7_cc_guard()
                    .build_request_challenge_result(request, reason_text)
            }
        }
    }
}

impl IpAccessState {
    fn new(config: &IpAccessConfig) -> Self {
        Self {
            config: config.clone(),
            allow_cidrs: parse_cidrs(&config.allow_cidrs, "allow_cidrs"),
            block_cidrs: parse_cidrs(&config.block_cidrs, "block_cidrs"),
            domestic_cidrs: parse_cidrs(&config.domestic_cidrs, "domestic_cidrs"),
        }
    }
}

fn parse_cidrs(values: &[String], label: &str) -> Vec<IpNet> {
    values
        .iter()
        .filter_map(|value| match value.parse::<IpNet>() {
            Ok(cidr) => Some(cidr),
            Err(err) => {
                log::warn!(
                    "Ignoring invalid ip_access {} entry '{}': {}",
                    label,
                    value,
                    err
                );
                None
            }
        })
        .collect()
}

fn normalize_country_code(value: &str) -> Option<String> {
    let code = value.trim().to_ascii_uppercase();
    if matches!(code.as_str(), "" | "XX" | "T1") {
        return None;
    }
    (code.len() == 2 && code.chars().all(|ch| ch.is_ascii_alphabetic())).then_some(code)
}

fn is_domestic_country(config: &IpAccessConfig, country_code: &str) -> bool {
    config
        .domestic_country_codes
        .iter()
        .any(|item| item.eq_ignore_ascii_case(country_code))
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

fn add_optional_geo_header_metadata(
    request: &mut UnifiedHttpRequest,
    metadata_key: &str,
    headers: &[String],
) {
    for header in headers {
        if let Some(value) = request.get_header(header) {
            let value = value.trim();
            if !value.is_empty() {
                request.add_metadata(metadata_key.to_string(), value.to_string());
                return;
            }
        }
    }
}

fn ip_access_mode_label(mode: IpAccessMode) -> &'static str {
    match mode {
        IpAccessMode::Monitor => "monitor",
        IpAccessMode::DomesticOnly => "domestic_only",
        IpAccessMode::Custom => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::l7::IpAccessGeoHeaderConfig;
    use crate::protocol::{HttpVersion, UnifiedHttpRequest};

    fn request(ip: &str) -> UnifiedHttpRequest {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.client_ip = Some(ip.to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request
    }

    #[test]
    fn untrusted_geo_header_is_ignored() {
        let config = IpAccessConfig {
            enabled: true,
            geo_headers: IpAccessGeoHeaderConfig {
                country_headers: vec!["cf-ipcountry".to_string()],
                ..IpAccessGeoHeaderConfig::default()
            },
            ..IpAccessConfig::default()
        };
        let guard = IpAccessGuard::new(&config);
        let mut request = request("203.0.113.10");
        request.add_header("cf-ipcountry".to_string(), "CN".to_string());
        let state = guard.state.read().unwrap().clone();
        let geo = guard.resolve_geo_signal(&mut request, "203.0.113.10".parse().unwrap(), &state);
        assert_eq!(geo.source, "cdn_header_untrusted");
        assert!(geo.country_code.is_none());
    }

    #[test]
    fn trusted_geo_header_supplies_country() {
        let config = IpAccessConfig {
            enabled: true,
            geo_headers: IpAccessGeoHeaderConfig {
                country_headers: vec!["cf-ipcountry".to_string()],
                ..IpAccessGeoHeaderConfig::default()
            },
            ..IpAccessConfig::default()
        };
        let guard = IpAccessGuard::new(&config);
        let mut request = request("203.0.113.10");
        request.add_header("cf-ipcountry".to_string(), "cn".to_string());
        request.add_metadata("network.trusted_proxy_peer".to_string(), "true".to_string());
        let state = guard.state.read().unwrap().clone();
        let geo = guard.resolve_geo_signal(&mut request, "203.0.113.10".parse().unwrap(), &state);
        assert_eq!(geo.source, "cdn_header");
        assert_eq!(geo.country_code.as_deref(), Some("CN"));
    }
}
