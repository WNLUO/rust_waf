pub mod detector;
pub mod http1;
pub mod http2;
pub mod http3;
pub mod unified;

use std::fmt;

/// HTTP协议版本枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http1_0,
    /// HTTP/1.1
    #[default]
    Http1_1,
    /// HTTP/2.0
    Http2_0,
    /// HTTP/3.0 (预留)
    Http3_0,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http1_0 => write!(f, "HTTP/1.0"),
            HttpVersion::Http1_1 => write!(f, "HTTP/1.1"),
            HttpVersion::Http2_0 => write!(f, "HTTP/2.0"),
            HttpVersion::Http3_0 => write!(f, "HTTP/3.0"),
        }
    }
}

/// HTTP协议检测错误
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol detection timeout")]
    #[allow(dead_code)]
    Timeout,
    #[error("HTTP/1 idle timeout after {elapsed_ms}ms")]
    IdleTimeout { elapsed_ms: u64 },
    #[error("HTTP/1 slow header read: {bytes_read} bytes in {elapsed_ms}ms")]
    SlowHeader { bytes_read: usize, elapsed_ms: u64 },
    #[error("HTTP/1 slow body read: {bytes_read}/{expected_bytes} bytes in {elapsed_ms}ms")]
    SlowBody {
        bytes_read: usize,
        expected_bytes: usize,
        elapsed_ms: u64,
    },
    #[error("Unsupported protocol version")]
    #[allow(dead_code)]
    UnsupportedVersion,
    #[error("Protocol parsing error: {0}")]
    ParseError(String),
}

pub use detector::ProtocolDetector;
pub use http1::Http1Handler;
pub use http2::{Http2Handler, Http2Response};
#[allow(unused_imports)]
pub use http3::{Http3Handler, Http3StreamManager, QuicPacketInfo};
pub use unified::UnifiedHttpRequest;
