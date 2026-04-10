use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub https_listen_addr: String,
    #[serde(default)]
    pub default_certificate_id: Option<i64>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            https_listen_addr: String::new(),
            default_certificate_id: None,
        }
    }
}
