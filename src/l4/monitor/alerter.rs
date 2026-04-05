use crate::config::L4Config;
use crate::core::PacketInfo;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, warn};

pub struct Alerter {
    config: L4Config,
    alerts_sent: AtomicU64,
}

impl Alerter {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Alerter");
        Self {
            config,
            alerts_sent: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Alerter started");
        Ok(())
    }

    pub fn send_alert(&self, packet: &PacketInfo, reason: &str) {
        self.alerts_sent.fetch_add(1, Ordering::Relaxed);
        warn!("ALERT: Threat detected from {} - {}", packet.source_ip, reason);

        // In production, this would send to external monitoring systems
        // Such as Slack, PagerDuty, email, etc.
    }

    pub fn get_alert_count(&self) -> u64 {
        self.alerts_sent.load(Ordering::Relaxed)
    }
}
