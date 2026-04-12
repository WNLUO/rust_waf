use super::{
    SafeLineBlockedIpSummary, SafeLineCertificateDetail, SafeLineCertificateSummary,
    SafeLineSecurityEventSummary, SafeLineSiteSummary,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};
use anyhow::{anyhow, Result};
use serde_json::Value;

mod convert;
mod extract;
mod parse;
#[cfg(test)]
mod tests;
mod time;
mod value;

pub(super) use extract::{
    extract_blocked_ips, extract_certificates, extract_security_events, extract_sites,
    parse_certificate_detail,
};
use parse::{
    extract_host_from_uri, looks_like_blocked_ip_summary, parse_blocked_ip_summaries,
    parse_certificate_summary, parse_security_event_summary, parse_site_summary,
};
use time::{normalize_timestamp, parse_rfc3339_timestamp, unix_timestamp};
use value::{
    pick_array_strings, pick_bool, pick_first_array_string, pick_i64, pick_string, pick_timestamp,
};
