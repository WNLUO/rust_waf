// WAF库文件
// 导出公共API用于测试

pub mod core;
pub mod bloom_filter;
pub mod l4;
pub mod l7;
pub mod rules;
pub mod config;
pub mod metrics;
pub mod protocol;

#[cfg(feature = "api")]
pub mod api;

// 重新导出常用类型
pub use core::{WafContext, PacketInfo, InspectionResult, InspectionLayer, Protocol};
pub use config::{Config, L7Config, RuntimeProfile};
pub use config::l7::Http2Config;
pub use config::http3::Http3Config;
pub use protocol::{HttpVersion, ProtocolDetector, UnifiedHttpRequest, Http1Handler, Http2Handler, Http3Handler, Http3StreamManager};
pub use l7::L7Inspector;