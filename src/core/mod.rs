pub mod engine;
pub mod packet;

use anyhow::Result;
use log::debug;
use crate::config::Config;
use crate::l4::L4Inspector;
use crate::l7::L7Inspector;
use crate::rules::RuleEngine;
use crate::metrics::MetricsCollector;

pub use engine::WafEngine;
pub use packet::{PacketInfo, InspectionResult, InspectionLayer, Protocol};

pub struct WafContext {
    pub config: Config,
    pub l4_inspector: Option<L4Inspector>,
    pub l7_inspector: Option<L7Inspector>,
    pub rule_engine: Option<RuleEngine>,
    pub metrics: Option<MetricsCollector>,
}

impl WafContext {
    pub async fn new(config: Config) -> Result<Self> {
        let l4_enabled = config.l4_config.ddos_protection_enabled
            || config.l4_config.connection_rate_limit > 0
            || config.l4_config.scan_enabled;
        let l7_enabled = config.l7_config.http_inspection_enabled;
        let bloom_enabled = config.bloom_enabled;
        let l4_bloom_verification = config.l4_bloom_false_positive_verification;
        let l7_bloom_verification = config.l7_bloom_false_positive_verification;
        let rules = if config.rules.is_empty() {
            None
        } else {
            Some(RuleEngine::new(config.rules.clone())?)
        };
        let metrics = if config.metrics_enabled {
            Some(MetricsCollector::new())
        } else {
            None
        };

        Ok(Self {
            l4_inspector: l4_enabled.then(|| {
                L4Inspector::new(
                    config.l4_config.clone(),
                    bloom_enabled,
                    l4_bloom_verification,
                )
            }),
            l7_inspector: l7_enabled.then(|| {
                L7Inspector::new(
                    config.l7_config.clone(),
                    bloom_enabled,
                    l7_bloom_verification,
                )
            }),
            rule_engine: rules,
            metrics,
            config,
        })
    }

    pub fn inspect_request(&self, packet: &PacketInfo, payload: &[u8]) -> InspectionResult {
        if let Some(metrics) = &self.metrics {
            metrics.record_packet(payload.len());
        }

        if let Some(l4_inspector) = &self.l4_inspector {
            let result = l4_inspector.inspect_packet(packet);
            if result.blocked {
                self.record_block(&result);
                return result;
            }
        }

        if let Some(l7_inspector) = &self.l7_inspector {
            let result = l7_inspector.inspect_http_request(packet, payload);
            if result.blocked {
                self.record_block(&result);
                return result;
            }
        }

        if let Some(rule_engine) = &self.rule_engine {
            let payload_str = String::from_utf8_lossy(payload);
            let rule_result = rule_engine.inspect(packet, Some(payload_str.as_ref()));
            if rule_result.blocked {
                self.record_block(&rule_result);
                return rule_result;
            }
            if rule_engine.has_rules() && !rule_result.reason.is_empty() {
                debug!("Non-blocking rule matched: {}", rule_result.reason);
            }
        }

        InspectionResult::allow(InspectionLayer::L7)
    }

    pub fn metrics_snapshot(&self) -> Option<crate::metrics::MetricsSnapshot> {
        self.metrics.as_ref().map(MetricsCollector::get_stats)
    }

    fn record_block(&self, result: &InspectionResult) {
        if let Some(metrics) = &self.metrics {
            metrics.record_block(result.layer.clone());
        }
    }
}
