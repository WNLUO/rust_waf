use super::*;

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
pub(super) const BROWSER_FINGERPRINT_REPORT_PATH: &str =
    "/.well-known/waf/browser-fingerprint-report";
const MAX_BROWSER_FINGERPRINT_DETAILS_BYTES: usize = 128 * 1024;

mod browser_fingerprint;
mod inspection;
mod request;
mod routing;
#[cfg(test)]
mod tests;

pub(crate) use browser_fingerprint::try_handle_browser_fingerprint_report;
pub(crate) use inspection::{
    enforce_runtime_http_block_if_needed, inspect_application_layers, inspect_l7_bloom_filter,
    inspect_transport_layers, persist_http_identity_debug_event, persist_http_inspection_event,
    persist_l4_inspection_event, persist_safeline_intercept_blocked_ip,
    persist_safeline_intercept_event, persist_upstream_http2_debug_event,
};
#[cfg(test)]
pub(crate) use request::expand_request_template;
pub(crate) use request::{
    apply_client_identity, apply_response_policies, apply_server_public_ip_metadata,
    body_for_request, inspect_blocked_client_ip, prepare_request_for_proxy,
    prepare_request_for_routing, should_keep_client_connection_open,
};
pub(crate) use routing::{
    apply_gateway_site_metadata, enforce_upstream_policy, generate_request_id, http_status_text,
    infer_forwarded_proto, redirect_to_https_location, request_hostname, resolve_client_identity,
    resolve_gateway_site, resolve_safeline_intercept_config, select_upstream_target,
    should_reject_unmatched_site, unix_timestamp,
};
