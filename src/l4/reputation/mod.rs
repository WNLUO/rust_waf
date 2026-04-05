pub mod blacklist;
pub mod whitelist;
pub mod scoring;

use crate::config::L4Config;
use log::info;

pub use blacklist::BlacklistManager;
pub use whitelist::WhitelistManager;
pub use scoring::ReputationScorer;

pub struct ReputationManager {
    config: L4Config,
    blacklist: BlacklistManager,
    whitelist: WhitelistManager,
    scorer: ReputationScorer,
}

impl ReputationManager {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Reputation Manager");
        Self {
            config: config.clone(),
            blacklist: BlacklistManager::new(config.clone()),
            whitelist: WhitelistManager::new(config.clone()),
            scorer: ReputationScorer::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Reputation Manager started");
        self.blacklist.start().await?;
        self.whitelist.start().await?;
        self.scorer.start().await?;
        Ok(())
    }

    pub fn check(&self, packet: &crate::core::PacketInfo) -> Option<crate::core::InspectionResult> {
        // Check whitelist first
        if self.whitelist.is_allowed(&packet.source_ip) {
            return None; // Whitelisted, allow
        }

        // Check blacklist
        if self.blacklist.is_blocked(&packet.source_ip) {
            return Some(crate::core::InspectionResult {
                blocked: true,
                reason: format!("IP {} is blacklisted", packet.source_ip),
                layer: crate::core::InspectionLayer::L4,
            });
        }

        // Check reputation score
        if let Some(score) = self.scorer.get_score(&packet.source_ip) {
            if score < 50 { // Threshold for blocking
                return Some(crate::core::InspectionResult {
                    blocked: true,
                    reason: format!("Low reputation score for {}: {}", packet.source_ip, score),
                    layer: crate::core::InspectionLayer::L4,
                });
            }
        }

        None
    }
}
