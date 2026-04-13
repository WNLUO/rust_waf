use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    /// 是否启用HTTP/3.0支持
    pub enabled: bool,
    /// HTTP/3.0监听地址
    pub listen_addr: String,
    /// 最大并发流数
    pub max_concurrent_streams: usize,
    /// 连接空闲超时时间（秒）
    pub idle_timeout_secs: u64,
    /// MTU大小
    pub mtu: usize,
    /// 最大帧大小
    pub max_frame_size: usize,
    /// 是否启用连接迁移
    pub enable_connection_migration: bool,
    /// QPACK表大小
    pub qpack_table_size: usize,
    /// TLS证书路径（可选）
    pub certificate_path: Option<String>,
    /// TLS私钥路径（可选）
    pub private_key_path: Option<String>,
    /// 是否启用TLS 1.3
    pub enable_tls13: bool,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: true, // 默认启用HTTP/3.0
            listen_addr: "0.0.0.0:8443".to_string(),
            max_concurrent_streams: 100,
            idle_timeout_secs: 300,
            mtu: 1350,
            max_frame_size: 65536,
            enable_connection_migration: true,
            qpack_table_size: 4096,
            certificate_path: None,
            private_key_path: None,
            enable_tls13: true,
        }
    }
}

impl Http3Config {
    /// 验证配置的有效性
    pub fn validate(&self) -> Result<(), String> {
        // 验证MTU大小
        if self.mtu < 1200 || self.mtu > 1500 {
            return Err("MTU must be between 1200 and 1500".to_string());
        }

        // 验证最大帧大小
        if self.max_frame_size < 65536 || self.max_frame_size > 16777215 {
            return Err("Max frame size must be between 65536 and 16777215".to_string());
        }

        // 验证QPACK表大小
        if self.qpack_table_size < 1024 || self.qpack_table_size > 65536 {
            return Err("QPACK table size must be between 1024 and 65536".to_string());
        }

        // 验证并发流数
        if self.max_concurrent_streams < 1 || self.max_concurrent_streams > 1000 {
            return Err("Max concurrent streams must be between 1 and 1000".to_string());
        }

        // 如果启用TLS，验证证书和私钥
        if self.enable_tls13 {
            if self.certificate_path.is_some() && self.private_key_path.is_none() {
                return Err(
                    "If certificate path is provided, private key path is also required"
                        .to_string(),
                );
            }
            if self.certificate_path.is_none() && self.private_key_path.is_some() {
                return Err(
                    "If private key path is provided, certificate path is also required"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    /// 获取默认配置（用于生产环境）
    #[allow(dead_code)]
    pub fn production() -> Self {
        Self {
            enabled: true,
            listen_addr: "0.0.0.0:8443".to_string(),
            max_concurrent_streams: 100,
            idle_timeout_secs: 300,
            mtu: 1350,
            max_frame_size: 65536,
            enable_connection_migration: true,
            qpack_table_size: 4096,
            certificate_path: None,
            private_key_path: None,
            enable_tls13: true,
        }
    }

    /// 获取开发配置
    #[allow(dead_code)]
    pub fn development() -> Self {
        Self {
            enabled: true,
            listen_addr: "127.0.0.1:8443".to_string(),
            max_concurrent_streams: 50,
            idle_timeout_secs: 60,
            mtu: 1200,
            max_frame_size: 65536,
            enable_connection_migration: false,
            qpack_table_size: 2048,
            certificate_path: None,
            private_key_path: None,
            enable_tls13: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Http3Config::default();
        assert!(config.enabled);
        assert_eq!(config.listen_addr, "0.0.0.0:8443");
        assert_eq!(config.max_concurrent_streams, 100);
    }

    #[test]
    fn test_production_config() {
        let config = Http3Config::production();
        assert!(config.enabled);
        assert_eq!(config.listen_addr, "0.0.0.0:8443");
        assert_eq!(config.max_concurrent_streams, 100);
    }

    #[test]
    fn test_config_validation_valid() {
        let config = Http3Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_mtu() {
        let config = Http3Config {
            mtu: 1000,
            ..Http3Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_streams() {
        let config = Http3Config {
            max_concurrent_streams: 2000,
            ..Http3Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_tls_requirement() {
        let config = Http3Config {
            enable_tls13: true,
            certificate_path: Some("/path/to/cert.pem".to_string()),
            private_key_path: None,
            ..Http3Config::default()
        };
        assert!(config.validate().is_err());
    }
}
