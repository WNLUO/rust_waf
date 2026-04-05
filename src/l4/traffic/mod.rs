pub mod analyzer;
pub mod statistics;
pub mod pattern;

use crate::config::L4Config;
use log::info;

pub use analyzer::Analyzer;
pub use statistics::TrafficStatistics;
pub use pattern::PatternDetector;

pub struct MainTrafficAnalyzer {
    config: L4Config,
    statistics: TrafficStatistics,
    pattern_detector: PatternDetector,
}

impl MainTrafficAnalyzer {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Traffic Analyzer");
        Self {
            config: config.clone(),
            statistics: TrafficStatistics::new(config.clone()),
            pattern_detector: PatternDetector::new(config.clone()),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Traffic Analyzer started");
        self.statistics.start().await?;
        self.pattern_detector.start().await?;
        Ok(())
    }

    pub fn analyze(&self, _packet: &crate::core::PacketInfo) {
        // Simplified - in production would record statistics
    }

    pub fn get_stats(&self) -> TrafficStats {
        TrafficStats {
            statistics: self.statistics.get_stats(),
            patterns: self.pattern_detector.get_stats(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficStats {
    pub statistics: crate::l4::traffic::statistics::TrafficStatisticsStats,
    pub patterns: crate::l4::traffic::pattern::PatternStats,
}
