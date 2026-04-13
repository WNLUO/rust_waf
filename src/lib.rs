// WAF库文件
// 导出公共API用于测试

use anyhow::Result;
use log::info;
use rand::distributions::{Alphanumeric, DistString};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
pub use core::{InspectionLayer, InspectionResult, PacketInfo, Protocol, WafContext, WafEngine};
pub use l7::HttpTrafficProcessor;
pub use protocol::{
    Http1Handler, Http2Handler, Http3Handler, Http3StreamManager, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
pub use storage::SqliteStore;

pub async fn load_runtime_config() -> Result<Config> {
    let sqlite_path = config::resolve_sqlite_path();
    let bootstrap_store = storage::SqliteStore::new(sqlite_path.clone(), true).await?;

    let mut config = if let Some(config) = bootstrap_store.load_app_config().await? {
        info!("Loaded configuration from SQLite: {}", sqlite_path);
        config
    } else {
        let mut config = config::Config::default();
        config.sqlite_enabled = true;
        config.sqlite_path = sqlite_path.clone();
        config.sqlite_auto_migrate = true;
        bootstrap_store.seed_app_config(&config).await?;
        info!("Seeded default configuration into SQLite: {}", sqlite_path);
        config
    };

    config = ensure_startup_default_certificate(&bootstrap_store, config).await?;

    config.sqlite_enabled = true;
    config.sqlite_path = sqlite_path;
    config.sqlite_auto_migrate = true;

    Ok(config::apply_env_overrides(config).normalized())
}

pub async fn build_engine() -> Result<WafEngine> {
    let config = load_runtime_config().await?;
    info!(
        "Loaded configuration: profile={:?}, api_enabled={}, bloom_enabled={}, l4_bloom_fp_verification={}, l7_bloom_fp_verification={}",
        config.runtime_profile,
        config.api_enabled,
        config.bloom_enabled,
        config.l4_bloom_false_positive_verification,
        config.l7_bloom_false_positive_verification
    );

    WafEngine::new(config).await
}

pub async fn run() -> Result<()> {
    let mut waf_engine = build_engine().await?;
    waf_engine.start().await
}

async fn ensure_startup_default_certificate(
    store: &SqliteStore,
    mut config: Config,
) -> Result<Config> {
    let mut selected_certificate_id = None;
    if let Some(default_certificate_id) = config.gateway_config.default_certificate_id {
        if has_usable_local_certificate(store, default_certificate_id).await? {
            selected_certificate_id = Some(default_certificate_id);
        }
    }

    if selected_certificate_id.is_none() {
        selected_certificate_id = find_first_usable_local_certificate(store).await?;
    }

    if let Some(certificate_id) = selected_certificate_id {
        let changed = config.gateway_config.default_certificate_id != Some(certificate_id);
        config.gateway_config.default_certificate_id = Some(certificate_id);
        let http3_changed =
            ensure_http3_certificate_paths(store, &mut config, certificate_id).await?;
        if changed || http3_changed {
            store.upsert_app_config(&config).await?;
            info!(
                "Reused local certificate {} as the startup default certificate",
                certificate_id
            );
        }
        return Ok(config);
    }

    let generated = generate_startup_self_signed_certificate();
    let certificate_id = store
        .insert_local_certificate(&generated.certificate)
        .await?;
    store
        .upsert_local_certificate_secret(
            certificate_id,
            &generated.certificate_pem,
            &generated.private_key_pem,
        )
        .await?;
    config.gateway_config.default_certificate_id = Some(certificate_id);
    ensure_http3_certificate_paths(store, &mut config, certificate_id).await?;
    store.upsert_app_config(&config).await?;
    info!(
        "Generated startup self-signed certificate {} for domain {}",
        certificate_id, generated.domain
    );

    Ok(config)
}

async fn has_usable_local_certificate(store: &SqliteStore, certificate_id: i64) -> Result<bool> {
    if store
        .load_local_certificate(certificate_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    let Some(secret) = store.load_local_certificate_secret(certificate_id).await? else {
        return Ok(false);
    };

    Ok(!secret.certificate_pem.trim().is_empty() && !secret.private_key_pem.trim().is_empty())
}

async fn find_first_usable_local_certificate(store: &SqliteStore) -> Result<Option<i64>> {
    for certificate in store.list_local_certificates().await? {
        if has_usable_local_certificate(store, certificate.id).await? {
            return Ok(Some(certificate.id));
        }
    }

    Ok(None)
}

async fn ensure_http3_certificate_paths(
    store: &SqliteStore,
    config: &mut Config,
    certificate_id: i64,
) -> Result<bool> {
    if !config.http3_config.enabled {
        return Ok(false);
    }

    if config.http3_config.certificate_path.is_some()
        && config.http3_config.private_key_path.is_some()
    {
        return Ok(false);
    }

    let Some(secret) = store.load_local_certificate_secret(certificate_id).await? else {
        return Ok(false);
    };

    let cert_path = managed_http3_certificate_path(certificate_id);
    let key_path = managed_http3_private_key_path(certificate_id);
    write_http3_pem_pair(
        &cert_path,
        &key_path,
        &secret.certificate_pem,
        &secret.private_key_pem,
    )?;

    config.http3_config.certificate_path = Some(cert_path.to_string_lossy().to_string());
    config.http3_config.private_key_path = Some(key_path.to_string_lossy().to_string());
    Ok(true)
}

fn managed_http3_certificate_path(certificate_id: i64) -> PathBuf {
    Path::new("data/http3/managed").join(format!("cert-{certificate_id}.pem"))
}

fn managed_http3_private_key_path(certificate_id: i64) -> PathBuf {
    Path::new("data/http3/managed").join(format!("key-{certificate_id}.pem"))
}

fn write_http3_pem_pair(
    cert_path: &Path,
    key_path: &Path,
    certificate_pem: &str,
    private_key_pem: &str,
) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, certificate_pem.as_bytes())?;
    std::fs::write(key_path, private_key_pem.as_bytes())?;
    Ok(())
}

fn generate_startup_self_signed_certificate() -> StartupGeneratedCertificate {
    let domain = random_startup_certificate_domain();
    let now = unix_timestamp();
    let valid_to = now.saturating_add(3600 * 24 * 365);
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![domain.clone()])
        .expect("failed to generate self-signed certificate");

    StartupGeneratedCertificate {
        domain: domain.clone(),
        certificate: storage::LocalCertificateUpsert {
            name: format!("Startup Self-Signed ({domain})"),
            domains: vec![domain],
            issuer: "WAF Auto Generated".to_string(),
            valid_from: Some(now),
            valid_to: Some(valid_to),
            source_type: "generated".to_string(),
            provider_remote_id: None,
            provider_remote_domains: Vec::new(),
            last_remote_fingerprint: None,
            sync_status: "idle".to_string(),
            sync_message: "系统启动时自动生成自签证书".to_string(),
            auto_sync_enabled: false,
            trusted: false,
            expired: false,
            notes: "系统启动时检测到缺少本地证书后自动生成".to_string(),
            last_synced_at: None,
        },
        certificate_pem: cert.pem(),
        private_key_pem: key_pair.serialize_pem(),
    }
}

fn random_startup_certificate_domain() -> String {
    let suffix = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    format!("{}.startup.local", suffix.to_ascii_lowercase())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

struct StartupGeneratedCertificate {
    domain: String,
    certificate: storage::LocalCertificateUpsert,
    certificate_pem: String,
    private_key_pem: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_test_db_path(label: &str) -> String {
        let unique = TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rust_waf_{label}_{unique}_{nanos}.db"));
        let _ = std::fs::remove_file(&path);
        path.to_string_lossy().to_string()
    }

    #[tokio::test]
    async fn startup_uses_existing_local_certificate_as_default() {
        let path = unique_test_db_path("startup_existing_cert");
        let store = SqliteStore::new(path, true).await.unwrap();
        let certificate_id = store
            .insert_local_certificate(&storage::LocalCertificateUpsert {
                name: "existing".to_string(),
                domains: vec!["example.com".to_string()],
                issuer: "test".to_string(),
                valid_from: Some(1),
                valid_to: Some(2),
                source_type: "manual".to_string(),
                provider_remote_id: None,
                provider_remote_domains: Vec::new(),
                last_remote_fingerprint: None,
                sync_status: "idle".to_string(),
                sync_message: String::new(),
                auto_sync_enabled: false,
                trusted: false,
                expired: false,
                notes: String::new(),
                last_synced_at: None,
            })
            .await
            .unwrap();
        store
            .upsert_local_certificate_secret(
                certificate_id,
                "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
                "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
            )
            .await
            .unwrap();

        let mut config = Config::default();
        config.gateway_config.default_certificate_id = None;

        let updated = ensure_startup_default_certificate(&store, config)
            .await
            .unwrap();

        assert_eq!(
            updated.gateway_config.default_certificate_id,
            Some(certificate_id)
        );
        assert_eq!(store.list_local_certificates().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn startup_generates_self_signed_certificate_when_missing() {
        let path = unique_test_db_path("startup_generate_cert");
        let store = SqliteStore::new(path, true).await.unwrap();
        let mut config = Config::default();
        config.gateway_config.default_certificate_id = None;

        let updated = ensure_startup_default_certificate(&store, config)
            .await
            .unwrap();

        let certificate_id = updated.gateway_config.default_certificate_id.unwrap();
        let certificate = store
            .load_local_certificate(certificate_id)
            .await
            .unwrap()
            .unwrap();
        let secret = store
            .load_local_certificate_secret(certificate_id)
            .await
            .unwrap()
            .unwrap();
        let domains: Vec<String> = serde_json::from_str(&certificate.domains_json).unwrap();

        assert_eq!(certificate.source_type, "generated");
        assert_eq!(domains.len(), 1);
        assert!(domains[0].ends_with(".startup.local"));
        assert!(secret.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(secret.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }
}
