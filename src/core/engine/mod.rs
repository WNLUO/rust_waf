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
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::pin::Pin;
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
    AiRouteResultObservation, CustomHttpResponse, InspectionAction, InspectionLayer,
    InspectionResult, PacketInfo, Protocol,
};
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use crate::protocol::{
    Http1Handler, Http2Handler, Http2Response, Http3Handler, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};

mod network;

#[cfg(feature = "http3")]
use self::network::handle_http3_quic_connection;
pub(crate) use self::network::peer_is_configured_trusted_proxy;
use self::network::{handle_connection, handle_tls_connection, handle_udp_datagram};
mod policy;
mod proxy;
mod runtime;

use self::policy::{
    apply_client_identity, apply_gateway_site_metadata, apply_response_policies,
    apply_server_public_ip_metadata, body_for_request, enforce_upstream_policy, http_status_text,
    inspect_application_layers, inspect_blocked_client_ip, inspect_l7_bloom_filter,
    inspect_transport_layers, persist_http_inspection_event, persist_l4_inspection_event,
    persist_safeline_intercept_blocked_ip, persist_safeline_intercept_event,
    prepare_request_for_proxy, prepare_request_for_routing, redirect_to_https_location,
    resolve_gateway_site, resolve_safeline_intercept_config, select_upstream_target,
    should_keep_client_connection_open, should_reject_unmatched_site,
    try_handle_browser_fingerprint_report,
};
use self::proxy::{
    apply_safeline_upstream_action, enforce_http1_request_safety, proxy_http_request,
    proxy_http_request_with_session_affinity, resolve_runtime_custom_response,
    write_http1_upstream_response, UpstreamClientConnection, UpstreamResponseDisposition,
};
#[cfg(feature = "http3")]
pub(crate) use self::runtime::sync_http3_listener_runtime;
use self::runtime::PrefixedStream;
pub use self::runtime::WafEngine;
pub(crate) use self::runtime::{sync_entry_listener_runtime, validate_entry_listener_config};
