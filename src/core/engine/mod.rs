use anyhow::Result;
use brotli::Decompressor;
use flate2::read::{GzDecoder, ZlibDecoder};
use ipnet::IpNet;
use log::{debug, info, warn};
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::pin::Pin;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[cfg(feature = "http3")]
use bytes::Buf;
#[cfg(feature = "http3")]
use bytes::Bytes;
#[cfg(feature = "http3")]
use h3::server::RequestStream;
#[cfg(feature = "http3")]
use h3_quinn::Connection as H3QuinnConnection;
#[cfg(feature = "http3")]
use quinn::Incoming as QuinnIncoming;

use super::WafContext;
use crate::config::l7::{
    SafeLineInterceptAction, SafeLineInterceptConfig, SafeLineInterceptMatchMode,
    UpstreamFailureMode,
};
use crate::config::{Config, RuntimeProfile};
use crate::core::gateway::{
    normalize_hostname, parse_upstream_endpoint, GatewaySiteRuntime, UpstreamScheme,
};
use crate::core::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo, Protocol,
};
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use crate::protocol::{
    Http1Handler, Http2Handler, Http2Response, Http3Handler, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
pub(crate) const BROWSER_FINGERPRINT_REPORT_PATH: &str =
    "/.well-known/waf/browser-fingerprint-report";
const MAX_BROWSER_FINGERPRINT_DETAILS_BYTES: usize = 128 * 1024;
static ENTRY_LISTENER_RUNTIME: OnceLock<Arc<EntryListenerRuntime>> = OnceLock::new();

include!("runtime.rs");
include!("network.rs");
include!("proxy.rs");
include!("policy.rs");
