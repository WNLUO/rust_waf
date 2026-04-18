pub mod behavior_guard;
pub mod bloom_filter;
pub mod cc_guard;
pub mod ip_access;
pub mod slow_attack_guard;

use crate::config::L7Config;
use crate::core::WafContext;
use log::{debug, info};

pub use behavior_guard::{BehaviorProfileSnapshot, L7BehaviorGuard};
pub use bloom_filter::L7BloomFilterManager;
pub use cc_guard::L7CcGuard;
pub use ip_access::IpAccessGuard;
pub use slow_attack_guard::{SlowAttackGuard, SlowAttackKind, SlowAttackObservation};

#[derive(Debug, Clone)]
pub struct HttpTrafficProcessor {
    max_request_size: usize,
    http2_enabled: bool,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::Http2Config;

    #[test]
    fn processor_tracks_request_limits_from_config() {
        let config = L7Config {
            max_request_size: 16_384,
            http2_config: Http2Config {
                enabled: true,
                ..Http2Config::default()
            },
            ..L7Config::default()
        };

        let processor = HttpTrafficProcessor::new(&config);
        assert_eq!(processor.max_request_size(), 16_384);
        assert!(processor.http2_enabled());
    }
}

impl HttpTrafficProcessor {
    pub fn new(config: &L7Config) -> Self {
        info!("Initializing HTTP gateway processor");
        Self {
            max_request_size: config.max_request_size,
            http2_enabled: config.http2_config.enabled,
        }
    }

    pub async fn start(&self, _context: &WafContext) -> anyhow::Result<()> {
        debug!(
            "HTTP gateway processor ready (max_request_size={}, http2_enabled={})",
            self.max_request_size, self.http2_enabled
        );
        Ok(())
    }

    pub fn max_request_size(&self) -> usize {
        self.max_request_size
    }

    pub fn http2_enabled(&self) -> bool {
        self.http2_enabled
    }
}
