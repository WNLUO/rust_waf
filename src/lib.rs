// WAF库文件
// 导出公共API用于测试

pub mod bloom_filter;
pub mod config;
pub mod core;
pub mod integrations;
pub mod l4;
pub mod l7;
pub mod metrics;
pub mod protocol;
pub mod rules;
pub mod storage;
pub mod tls;

#[cfg(feature = "api")]
pub mod api;

// 重新导出常用类型
pub use config::http3::Http3Config;
pub use config::l7::Http2Config;
pub use config::{Config, L7Config, RuntimeProfile};
pub use core::{InspectionLayer, InspectionResult, PacketInfo, Protocol, WafContext};
pub use l7::L7Inspector;
pub use protocol::{
    Http1Handler, Http2Handler, Http3Handler, Http3StreamManager, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
pub use storage::SqliteStore;
