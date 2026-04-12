pub mod cc_guard;

use crate::config::L7Config;
use crate::core::WafContext;
use log::{debug, info};

pub use cc_guard::L7CcGuard;

#[derive(Debug, Clone)]
pub struct HttpTrafficProcessor {
    max_request_size: usize,
    http2_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_tracks_request_limits_from_config() {
        let mut config = L7Config::default();
        config.max_request_size = 16_384;
        config.http2_config.enabled = true;

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
