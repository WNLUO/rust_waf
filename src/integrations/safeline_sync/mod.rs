mod blocklist;
mod certificate_sync;
mod certificates;
mod events;
mod shared;
mod site_sync;
mod sites;

use crate::config::SafeLineConfig;
use crate::integrations::safeline::{
    SafeLineCertificateDetail, SafeLineCertificateSummary, SafeLineCertificateUpsert,
    SafeLineSiteSummary, SafeLineSiteUpsert,
};
use crate::storage::{
    BlockedIpQuery, BlockedIpRecord, LocalCertificateEntry, LocalCertificateUpsert, LocalSiteEntry,
    LocalSiteUpsert, SafeLineBlocklistPullResult, SafeLineBlocklistSyncResult,
    SafeLineImportResult, SecurityEventRecord, SiteSyncLinkUpsert, SqliteStore,
};
use anyhow::{anyhow, bail, Result};

use self::certificate_sync::{
    certificate_fingerprint, match_remote_certificate, normalized_domain_set,
    sync_remote_certificate, update_certificate_sync_metadata, CertificateSyncMetadataUpdate,
};
pub(crate) use self::shared::is_configured;
use self::shared::{apply_safeline_mapping, ensure_enabled, parse_json_vec, unix_timestamp};
use self::site_sync::{
    allows_push, find_matching_remote_site, hash_local_site_entry, hash_remote_site,
    local_site_to_remote, match_remote_site, record_site_link_error, resolve_remote_certificate_id,
    update_local_site_sync_metadata,
};

pub use blocklist::{pull_blocked_ips, push_blocked_ips};
pub use certificates::{
    preview_certificate_match, pull_certificate, pull_certificates, push_certificate,
};
pub use events::sync_events;
pub use sites::{pull_site, pull_sites, push_site, push_sites};

#[derive(Debug, Clone, Default)]
pub struct SafeLineSitesPullResult {
    pub imported_sites: usize,
    pub updated_sites: usize,
    pub imported_certificates: usize,
    pub updated_certificates: usize,
    pub linked_sites: usize,
    pub skipped_sites: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineSitesPushResult {
    pub created_sites: usize,
    pub updated_sites: usize,
    pub created_certificates: usize,
    pub reused_certificates: usize,
    pub skipped_sites: usize,
    pub failed_sites: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineCertificatesPullResult {
    pub imported_certificates: usize,
    pub updated_certificates: usize,
    pub skipped_certificates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSiteSyncAction {
    Created,
    Updated,
}

#[derive(Debug, Clone, Copy)]
pub struct SafeLineSitePullOptions {
    pub name: bool,
    pub primary_hostname: bool,
    pub hostnames: bool,
    pub listen_ports: bool,
    pub upstreams: bool,
    pub enabled: bool,
}

impl Default for SafeLineSitePullOptions {
    fn default() -> Self {
        Self {
            name: true,
            primary_hostname: true,
            hostnames: true,
            listen_ports: true,
            upstreams: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SafeLineSingleSitePullResult {
    pub action: SingleSiteSyncAction,
    pub remote_site_id: String,
}

#[derive(Debug, Clone)]
pub struct SafeLineSingleSitePushResult {
    pub action: SingleSiteSyncAction,
    pub local_site_id: i64,
    pub remote_site_id: String,
}

#[derive(Debug, Clone)]
pub struct CertificateMatchPreview {
    pub status: String,
    pub strategy: String,
    pub local_certificate_id: i64,
    pub local_domains: Vec<String>,
    pub linked_remote_id: Option<String>,
    pub matched_remote_id: Option<String>,
    pub message: String,
    pub candidates: Vec<SafeLineCertificateSummary>,
}
