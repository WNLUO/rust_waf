use super::*;

mod accept;
mod detect;
mod early_defense;
mod helpers;
mod http1;
mod http2;
mod http3;
mod udp;

pub(super) use self::accept::{handle_connection, handle_tls_connection};
pub(super) use self::detect::{detect_and_handle_protocol, parse_proxy_protocol_stream};
pub(crate) use self::early_defense::evaluate_early_defense;
pub(crate) use self::helpers::{
    maybe_delay_policy, maybe_delay_request, next_connection_id, peer_is_configured_trusted_proxy,
    proxy_metric_labels, proxy_traffic_kind, record_l7_behavior_metrics, record_l7_cc_metrics,
    record_l7_ip_access_metrics, request_in_critical_overload,
    should_skip_l4_connection_budget_for_trusted_proxy,
};
pub(super) use self::http1::handle_http1_connection;
pub(super) use self::http2::handle_http2_connection;
#[cfg(feature = "http3")]
pub(super) use self::http3::handle_http3_quic_connection;
pub(super) use self::udp::handle_udp_datagram;
