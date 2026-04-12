use crate::config::l7::SafeLineInterceptConfig;
use crate::config::Config;
use crate::storage::{LocalCertificateSecretEntry, LocalSiteEntry, SqliteStore};
use anyhow::Result;
use log::warn;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{BufReader, Cursor};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct GatewaySiteRuntime {
    pub id: i64,
    pub name: String,
    pub primary_hostname: String,
    pub hostnames: Vec<String>,
    pub listen_ports: Vec<String>,
    pub tls_enabled: bool,
    pub certificate_id: Option<i64>,
    pub upstream_endpoint: Option<String>,
    pub safeline_intercept: Option<SafeLineInterceptConfig>,
}

#[derive(Debug, Clone)]
pub struct GatewayRuntime {
    inner: Arc<RwLock<GatewayRuntimeState>>,
    cert_resolver: Arc<GatewayCertResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEndpoint {
    pub scheme: UpstreamScheme,
    pub authority: String,
}

impl fmt::Display for UpstreamEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            UpstreamScheme::Http => f.write_str(&self.authority),
            UpstreamScheme::Https => write!(f, "https://{}", self.authority),
        }
    }
}

#[derive(Debug, Default)]
struct GatewayRuntimeState {
    sites: Vec<GatewaySiteRuntime>,
    host_index: HashMap<String, Vec<usize>>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default_cert: Option<Arc<CertifiedKey>>,
}

#[derive(Debug)]
struct GatewayCertResolver {
    inner: Arc<RwLock<GatewayRuntimeState>>,
}

impl ResolvesServerCert for GatewayCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let state = self.inner.read().expect("gateway_runtime lock poisoned");
        client_hello
            .server_name()
            .and_then(normalize_sni_hostname)
            .and_then(|name| state.by_name.get(&name).cloned())
            .or_else(|| state.default_cert.clone())
    }
}

impl Default for GatewayRuntime {
    fn default() -> Self {
        let inner = Arc::new(RwLock::new(GatewayRuntimeState::default()));
        Self {
            cert_resolver: Arc::new(GatewayCertResolver {
                inner: Arc::clone(&inner),
            }),
            inner,
        }
    }
}

impl GatewayRuntime {
    pub async fn load(config: &Config, store: Option<&SqliteStore>) -> Result<Self> {
        let runtime = Self::default();
        runtime.reload(config, store).await?;
        Ok(runtime)
    }

    pub async fn reload(&self, config: &Config, store: Option<&SqliteStore>) -> Result<()> {
        let next = build_runtime_state(config, store).await?;
        let mut guard = self.inner.write().expect("gateway_runtime lock poisoned");
        *guard = next;
        Ok(())
    }

    pub fn tls_resolver(&self) -> Option<Arc<dyn ResolvesServerCert>> {
        let state = self.inner.read().expect("gateway_runtime lock poisoned");
        if state.by_name.is_empty() && state.default_cert.is_none() {
            None
        } else {
            Some(self.cert_resolver.clone() as Arc<dyn ResolvesServerCert>)
        }
    }

    pub fn has_sites(&self) -> bool {
        !self
            .inner
            .read()
            .expect("gateway_runtime lock poisoned")
            .sites
            .is_empty()
    }

    pub fn resolve_site(
        &self,
        hostname: Option<&str>,
        listener_port: u16,
    ) -> Option<GatewaySiteRuntime> {
        let hostname = hostname.and_then(normalize_hostname)?;
        let state = self.inner.read().expect("gateway_runtime lock poisoned");
        let site_indexes = state.host_index.get(&hostname)?;

        site_indexes
            .iter()
            .filter_map(|index| state.sites.get(*index))
            .find(|site| site_matches_port(site, listener_port))
            .cloned()
    }
}

async fn build_runtime_state(
    config: &Config,
    store: Option<&SqliteStore>,
) -> Result<GatewayRuntimeState> {
    let Some(store) = store else {
        return Ok(GatewayRuntimeState::default());
    };

    let raw_sites = store.list_local_sites().await?;
    let enabled_sites = raw_sites
        .into_iter()
        .filter(|site| site.enabled)
        .collect::<Vec<_>>();

    let mut certificate_ids = enabled_sites
        .iter()
        .filter(|site| site.tls_enabled)
        .filter_map(|site| site.local_certificate_id)
        .collect::<HashSet<_>>();
    if let Some(default_certificate_id) = config.gateway_config.default_certificate_id {
        certificate_ids.insert(default_certificate_id);
    }

    let certified_keys = load_certified_keys(store, &certificate_ids).await?;
    let default_cert = config
        .gateway_config
        .default_certificate_id
        .and_then(|id| certified_keys.get(&id).cloned());

    let mut sites = Vec::with_capacity(enabled_sites.len());
    let mut host_index: HashMap<String, Vec<usize>> = HashMap::new();
    let mut certificates_by_name = HashMap::new();

    for site in enabled_sites {
        let runtime_site = runtime_site_from_entry(&site);
        let site_index = sites.len();

        for hostname in &runtime_site.hostnames {
            host_index
                .entry(hostname.clone())
                .or_default()
                .push(site_index);
        }

        if runtime_site.tls_enabled {
            if let Some(certificate_id) = runtime_site.certificate_id {
                if let Some(certified_key) = certified_keys.get(&certificate_id) {
                    for hostname in &runtime_site.hostnames {
                        certificates_by_name
                            .entry(hostname.clone())
                            .or_insert_with(|| Arc::clone(certified_key));
                    }
                } else {
                    warn!(
                        "Site '{}' references certificate {} but the certificate secret is unavailable",
                        runtime_site.name, certificate_id
                    );
                }
            }
        }

        sites.push(runtime_site);
    }

    Ok(GatewayRuntimeState {
        sites,
        host_index,
        by_name: certificates_by_name,
        default_cert,
    })
}

fn runtime_site_from_entry(site: &LocalSiteEntry) -> GatewaySiteRuntime {
    let primary_hostname =
        normalize_hostname(&site.primary_hostname).unwrap_or_else(|| site.primary_hostname.clone());
    let mut hostnames = parse_json_string_vec(&site.hostnames_json)
        .unwrap_or_else(|_| vec![site.primary_hostname.clone()])
        .into_iter()
        .filter_map(|hostname| normalize_hostname(&hostname))
        .collect::<Vec<_>>();

    if !hostnames
        .iter()
        .any(|hostname| hostname == &primary_hostname)
    {
        hostnames.insert(0, primary_hostname.clone());
    }
    hostnames.sort();
    hostnames.dedup();

    let listen_ports = parse_json_string_vec(&site.listen_ports_json).unwrap_or_default();
    let upstreams = parse_json_string_vec(&site.upstreams_json).unwrap_or_default();
    let upstream_endpoint =
        upstreams
            .iter()
            .find_map(|upstream| match normalize_upstream_endpoint(upstream) {
                Ok(endpoint) => Some(endpoint),
                Err(err) => {
                    warn!(
                        "Ignoring invalid upstream '{}' for site '{}': {}",
                        upstream, site.name, err
                    );
                    None
                }
            });
    let safeline_intercept = site.safeline_intercept_json.as_deref().and_then(|raw| {
        match serde_json::from_str::<SafeLineInterceptConfig>(raw) {
            Ok(config) => Some(config),
            Err(err) => {
                warn!(
                    "Ignoring invalid SafeLine intercept override for site '{}': {}",
                    site.name, err
                );
                None
            }
        }
    });

    GatewaySiteRuntime {
        id: site.id,
        name: site.name.clone(),
        primary_hostname,
        hostnames,
        listen_ports,
        tls_enabled: site.tls_enabled,
        certificate_id: site.local_certificate_id,
        upstream_endpoint,
        safeline_intercept,
    }
}

async fn load_certified_keys(
    store: &SqliteStore,
    certificate_ids: &HashSet<i64>,
) -> Result<HashMap<i64, Arc<CertifiedKey>>> {
    let mut certified_keys = HashMap::new();

    for certificate_id in certificate_ids {
        let Some(secret) = store.load_local_certificate_secret(*certificate_id).await? else {
            continue;
        };
        match certified_key_from_secret(&secret) {
            Ok(certified_key) => {
                certified_keys.insert(*certificate_id, Arc::new(certified_key));
            }
            Err(err) => {
                warn!(
                    "Failed to load certificate {} from SQLite secret storage: {}",
                    certificate_id, err
                );
            }
        }
    }

    Ok(certified_keys)
}

fn certified_key_from_secret(secret: &LocalCertificateSecretEntry) -> Result<CertifiedKey> {
    crate::tls::ensure_rustls_crypto_provider();

    let certs = load_pem_certificates(&secret.certificate_pem)?;
    let private_key = load_pem_private_key(&secret.private_key_pem)?;
    Ok(CertifiedKey::from_der(
        certs,
        private_key,
        &rustls::crypto::aws_lc_rs::default_provider(),
    )?)
}

fn load_pem_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(Cursor::new(pem.as_bytes()));
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("证书内容为空");
    }
    Ok(certs)
}

fn load_pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(Cursor::new(pem.as_bytes()));
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| anyhow::anyhow!("私钥内容为空"))
}

fn parse_json_string_vec(value: &str) -> Result<Vec<String>> {
    Ok(serde_json::from_str(value)?)
}

pub fn normalize_hostname(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn normalize_sni_hostname(value: &str) -> Option<String> {
    let normalized = normalize_hostname(value)?;
    if normalized.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(normalized)
    }
}

fn site_matches_port(site: &GatewaySiteRuntime, listener_port: u16) -> bool {
    let _ = site;
    let _ = listener_port;
    true
}

pub fn parse_upstream_endpoint(value: &str) -> Result<UpstreamEndpoint> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("上游地址不能为空");
    }

    if trimmed.starts_with("https://") {
        let uri = trimmed.parse::<http::Uri>()?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("HTTPS 回源地址缺少 authority"))?;
        return Ok(UpstreamEndpoint {
            scheme: UpstreamScheme::Https,
            authority: authority.as_str().to_string(),
        });
    }

    if trimmed.starts_with("http://") {
        let uri = trimmed.parse::<http::Uri>()?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow::anyhow!("HTTP 回源地址缺少 authority"))?;
        return Ok(UpstreamEndpoint {
            scheme: UpstreamScheme::Http,
            authority: authority.as_str().to_string(),
        });
    }

    if trimmed.contains(':') {
        return Ok(UpstreamEndpoint {
            scheme: UpstreamScheme::Http,
            authority: trimmed.to_string(),
        });
    }

    anyhow::bail!("上游地址 '{}' 缺少端口", trimmed)
}

pub fn normalize_upstream_endpoint(value: &str) -> Result<String> {
    parse_upstream_endpoint(value).map(|endpoint| endpoint.to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalize_upstream_endpoint, parse_upstream_endpoint, UpstreamScheme};

    #[test]
    fn normalize_upstream_endpoint_preserves_https_scheme() {
        assert_eq!(
            normalize_upstream_endpoint("https://127.0.0.1:9443").unwrap(),
            "https://127.0.0.1:9443"
        );
    }

    #[test]
    fn parse_upstream_endpoint_supports_plain_authority() {
        let endpoint = parse_upstream_endpoint("127.0.0.1:8080").unwrap();
        assert_eq!(endpoint.scheme, UpstreamScheme::Http);
        assert_eq!(endpoint.authority, "127.0.0.1:8080");
    }
}
