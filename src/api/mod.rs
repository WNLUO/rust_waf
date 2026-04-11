mod conversions;
mod events_handlers;
mod rules_handlers;
mod safeline_handlers;
mod settings_handlers;
mod sites_handlers;
mod system_handlers;
mod types;

use self::types::*;
use crate::config::{Config, Rule, RuleResponseBodySource, RuleResponseTemplate, RuntimeProfile};
use crate::core::WafContext;
use axum::{
    extract::Json as ExtractJson,
    extract::{Path, Query, State},
    http::StatusCode,
    http::{header, Method, Request},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch},
    Json, Router,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use zip::ZipArchive;

const MAX_PLUGIN_PACKAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLUGIN_ARCHIVE_ENTRIES: usize = 64;
const MAX_PLUGIN_TOTAL_UNCOMPRESSED_BYTES: usize = 8 * 1024 * 1024;

pub struct ApiServer {
    addr: SocketAddr,
    context: Arc<WafContext>,
}

#[derive(Clone)]
struct ApiState {
    context: Arc<WafContext>,
}

impl ApiServer {
    pub fn new(addr: SocketAddr, context: Arc<WafContext>) -> Self {
        Self { addr, context }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let state = ApiState {
            context: Arc::clone(&self.context),
        };
        let app = build_router(state);

        let listener = TcpListener::bind(self.addr).await?;
        log::info!("API server listening on {}", self.addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

fn build_router(state: ApiState) -> Router {
    let protected = Router::new()
        .route("/metrics", get(system_handlers::metrics_handler))
        .route(
            "/l4/config",
            get(settings_handlers::get_l4_config_handler)
                .put(settings_handlers::update_l4_config_handler),
        )
        .route("/l4/stats", get(settings_handlers::get_l4_stats_handler))
        .route(
            "/l7/config",
            get(settings_handlers::get_l7_config_handler)
                .put(settings_handlers::update_l7_config_handler),
        )
        .route("/l7/stats", get(settings_handlers::get_l7_stats_handler))
        .route(
            "/settings",
            get(settings_handlers::get_settings_handler)
                .put(settings_handlers::update_settings_handler),
        )
        .route(
            "/events",
            get(events_handlers::list_security_events_handler),
        )
        .route(
            "/events/:id",
            patch(events_handlers::update_security_event_handler),
        )
        .route(
            "/blocked-ips",
            get(events_handlers::list_blocked_ips_handler),
        )
        .route(
            "/blocked-ips/:id",
            delete(events_handlers::delete_blocked_ip_handler),
        )
        .route(
            "/rules",
            get(rules_handlers::list_rules_handler).post(rules_handlers::create_rule_handler),
        )
        .route(
            "/rule-action-plugins",
            get(rules_handlers::list_rule_action_plugins_handler),
        )
        .route(
            "/rule-action-plugins/install",
            axum::routing::post(rules_handlers::install_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-plugins/:plugin_id",
            axum::routing::patch(rules_handlers::update_rule_action_plugin_handler)
                .delete(rules_handlers::delete_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-plugins/upload",
            axum::routing::post(rules_handlers::upload_rule_action_plugin_handler),
        )
        .route(
            "/rule-action-templates",
            get(rules_handlers::list_rule_action_templates_handler),
        )
        .route(
            "/rule-action-templates/:template_id/preview",
            get(rules_handlers::preview_rule_action_template_handler),
        )
        .route(
            "/action-idea-presets",
            get(rules_handlers::list_action_idea_presets_handler),
        )
        .route(
            "/action-idea-presets/:idea_id",
            patch(rules_handlers::update_action_idea_preset_handler),
        )
        .route(
            "/action-idea-presets/:idea_id/upload-gzip",
            axum::routing::post(rules_handlers::upload_action_idea_gzip_handler),
        )
        .route(
            "/sites/local",
            get(sites_handlers::list_local_sites_handler)
                .post(sites_handlers::create_local_site_handler),
        )
        .route(
            "/sites/local/:id",
            get(sites_handlers::get_local_site_handler)
                .put(sites_handlers::update_local_site_handler)
                .delete(sites_handlers::delete_local_site_handler),
        )
        .route(
            "/certificates/local",
            get(sites_handlers::list_local_certificates_handler)
                .post(sites_handlers::create_local_certificate_handler),
        )
        .route(
            "/certificates/local/generate",
            axum::routing::post(sites_handlers::generate_local_certificate_handler),
        )
        .route(
            "/certificates/local/:id",
            get(sites_handlers::get_local_certificate_handler)
                .put(sites_handlers::update_local_certificate_handler)
                .delete(sites_handlers::delete_local_certificate_handler),
        )
        .route(
            "/integrations/safeline/test",
            axum::routing::post(safeline_handlers::test_safeline_handler),
        )
        .route(
            "/integrations/safeline/sites",
            axum::routing::post(safeline_handlers::list_safeline_sites_handler),
        )
        .route(
            "/integrations/safeline/sites/cached",
            get(safeline_handlers::list_cached_safeline_sites_handler),
        )
        .route(
            "/integrations/safeline/mappings",
            get(safeline_handlers::list_safeline_mappings_handler)
                .put(safeline_handlers::update_safeline_mappings_handler),
        )
        .route(
            "/integrations/safeline/pull/sites",
            axum::routing::post(safeline_handlers::pull_safeline_sites_handler),
        )
        .route(
            "/integrations/safeline/pull/sites/:remote_site_id",
            axum::routing::post(safeline_handlers::pull_safeline_site_handler),
        )
        .route(
            "/integrations/safeline/push/sites",
            axum::routing::post(safeline_handlers::push_safeline_sites_handler),
        )
        .route(
            "/integrations/safeline/push/sites/:local_site_id",
            axum::routing::post(safeline_handlers::push_safeline_site_handler),
        )
        .route(
            "/integrations/safeline/site-links",
            get(safeline_handlers::list_site_sync_links_handler)
                .put(safeline_handlers::upsert_site_sync_link_handler),
        )
        .route(
            "/integrations/safeline/site-links/:id",
            delete(safeline_handlers::delete_site_sync_link_handler),
        )
        .route(
            "/integrations/safeline/sync/events",
            axum::routing::post(safeline_handlers::sync_safeline_events_handler),
        )
        .route(
            "/integrations/safeline/sync/state",
            get(safeline_handlers::get_safeline_sync_state_handler),
        )
        .route(
            "/integrations/safeline/sync/blocked-ips",
            axum::routing::post(safeline_handlers::sync_safeline_blocked_ips_handler),
        )
        .route(
            "/integrations/safeline/pull/blocked-ips",
            axum::routing::post(safeline_handlers::pull_safeline_blocked_ips_handler),
        )
        .route(
            "/rules/:id",
            get(rules_handlers::get_rule_handler)
                .put(rules_handlers::update_rule_handler)
                .delete(rules_handlers::delete_rule_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ));

    Router::new()
        .route("/health", get(system_handlers::health_handler))
        .merge(protected)
        .with_state(state)
}

#[doc(hidden)]
pub fn build_test_router(context: Arc<WafContext>) -> Router {
    build_router(ApiState { context })
}

fn build_metrics_response(
    metrics: Option<crate::metrics::MetricsSnapshot>,
    active_rules: u64,
    storage_summary: Option<crate::storage::StorageMetricsSummary>,
) -> MetricsResponse {
    let snapshot = metrics.unwrap_or(crate::metrics::MetricsSnapshot {
        total_packets: 0,
        blocked_packets: 0,
        blocked_l4: 0,
        blocked_l7: 0,
        total_bytes: 0,
        proxied_requests: 0,
        proxy_successes: 0,
        proxy_failures: 0,
        proxy_fail_close_rejections: 0,
        upstream_healthcheck_successes: 0,
        upstream_healthcheck_failures: 0,
        proxy_latency_micros_total: 0,
        average_proxy_latency_micros: 0,
    });
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        total_bytes: snapshot.total_bytes,
        proxied_requests: snapshot.proxied_requests,
        proxy_successes: snapshot.proxy_successes,
        proxy_failures: snapshot.proxy_failures,
        proxy_fail_close_rejections: snapshot.proxy_fail_close_rejections,
        upstream_healthcheck_successes: snapshot.upstream_healthcheck_successes,
        upstream_healthcheck_failures: snapshot.upstream_healthcheck_failures,
        proxy_latency_micros_total: snapshot.proxy_latency_micros_total,
        average_proxy_latency_micros: snapshot.average_proxy_latency_micros,
        active_rules,
        sqlite_enabled,
        persisted_security_events: storage_summary.security_events,
        persisted_blocked_ips: storage_summary.blocked_ips,
        persisted_rules: storage_summary.rules,
        last_persisted_event_at: storage_summary.latest_event_at,
        last_rule_update_at: storage_summary.latest_rule_update_at,
    }
}

#[derive(Debug, Deserialize)]
struct RuleActionPluginManifest {
    plugin_id: String,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    templates: Vec<RuleActionPluginTemplateManifest>,
}

#[derive(Debug, Deserialize)]
struct RuleActionPluginTemplateManifest {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_rule_layer_l7")]
    layer: String,
    #[serde(default = "default_rule_action_respond")]
    action: String,
    #[serde(default)]
    pattern: String,
    #[serde(default = "default_rule_severity_high")]
    severity: String,
    response_template: RuleResponseTemplatePayload,
}

async fn install_rule_action_plugin_from_url(
    store: &crate::storage::SqliteStore,
    package_url: &str,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    let package_url = package_url.trim();
    if package_url.is_empty() {
        return Err("package_url 不能为空".to_string());
    }
    let url =
        reqwest::Url::parse(package_url).map_err(|err| format!("插件包 URL 不合法: {}", err))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(format!("插件包 URL 协议不受支持: {}", other)),
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|err| format!("创建下载客户端失败: {}", err))?;
    let response = client
        .get(package_url)
        .send()
        .await
        .map_err(|err| format!("下载插件包失败: {}", err))?;
    if !response.status().is_success() {
        return Err(format!("下载插件包失败: HTTP {}", response.status()));
    }
    if response.content_length().unwrap_or(0) > MAX_PLUGIN_PACKAGE_BYTES as u64 {
        return Err(format!(
            "插件包过大，限制为 {} 字节",
            MAX_PLUGIN_PACKAGE_BYTES
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("读取插件包失败: {}", err))?;
    install_rule_action_plugin_from_bytes(store, bytes.as_ref(), expected_sha256).await
}

async fn install_rule_action_plugin_from_bytes(
    store: &crate::storage::SqliteStore,
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    validate_plugin_package_bytes(bytes, expected_sha256)?;
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|err| format!("解析插件 zip 失败: {}", err))?;
    validate_plugin_archive_shape(&mut archive)?;
    let manifest = read_rule_action_plugin_manifest(&mut archive)?;
    validate_rule_action_plugin_manifest(&manifest)?;

    let plugin_assets_dir = PathBuf::from(crate::rules::RULE_RESPONSE_FILES_DIR)
        .join("plugins")
        .join(&manifest.plugin_id);
    if plugin_assets_dir.exists() {
        fs::remove_dir_all(&plugin_assets_dir)
            .map_err(|err| format!("清理旧插件资源失败: {}", err))?;
    }
    fs::create_dir_all(&plugin_assets_dir).map_err(|err| format!("创建插件目录失败: {}", err))?;

    let mut templates = Vec::with_capacity(manifest.templates.len());
    for template in &manifest.templates {
        let mut response_template: RuleResponseTemplate = template.response_template.clone().into();
        if matches!(response_template.body_source, RuleResponseBodySource::File) {
            let relative_asset_path =
                sanitize_relative_plugin_path(&response_template.body_file_path)?;
            let zip_entry_path = format!("responses/{}", relative_asset_path.display());
            extract_plugin_asset(
                &mut archive,
                &zip_entry_path,
                &plugin_assets_dir.join(&relative_asset_path),
            )?;
            response_template.body_file_path = format!(
                "plugins/{}/{}",
                manifest.plugin_id,
                relative_asset_path.to_string_lossy()
            );
        }

        let rule = Rule {
            id: format!("plugin:{}:{}", manifest.plugin_id, template.id),
            name: template.name.clone(),
            enabled: true,
            layer: crate::config::RuleLayer::parse(&template.layer)
                .map_err(|err| err.to_string())?,
            pattern: template.pattern.clone(),
            action: crate::config::RuleAction::parse(&template.action)
                .map_err(|err| err.to_string())?,
            severity: crate::config::Severity::parse(&template.severity)
                .map_err(|err| err.to_string())?,
            plugin_template_id: Some(format!("{}:{}", manifest.plugin_id, template.id)),
            response_template: Some(response_template.clone()),
        };
        crate::rules::validate_rule(&rule).map_err(|err| err.to_string())?;

        templates.push(crate::storage::RuleActionTemplateUpsert {
            template_id: format!("{}:{}", manifest.plugin_id, template.id),
            plugin_id: manifest.plugin_id.clone(),
            name: template.name.clone(),
            description: template.description.clone(),
            layer: template.layer.clone(),
            action: template.action.clone(),
            pattern: template.pattern.clone(),
            severity: template.severity.clone(),
            response_template,
        });
    }

    store
        .upsert_rule_action_plugin(&crate::storage::RuleActionPluginUpsert {
            plugin_id: manifest.plugin_id.clone(),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            description: manifest.description.clone(),
            enabled: true,
        })
        .await
        .map_err(|err| err.to_string())?;
    store
        .replace_rule_action_templates(&manifest.plugin_id, &templates)
        .await
        .map_err(|err| err.to_string())?;

    Ok(())
}

fn read_rule_action_plugin_manifest(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<RuleActionPluginManifest, String> {
    let mut manifest_file = archive
        .by_name("manifest.json")
        .map_err(|_| "插件包缺少 manifest.json".to_string())?;
    let mut manifest_json = String::new();
    manifest_file
        .read_to_string(&mut manifest_json)
        .map_err(|err| format!("读取 manifest.json 失败: {}", err))?;
    serde_json::from_str::<RuleActionPluginManifest>(&manifest_json)
        .map_err(|err| format!("解析 manifest.json 失败: {}", err))
}

fn validate_rule_action_plugin_manifest(manifest: &RuleActionPluginManifest) -> Result<(), String> {
    if !manifest
        .plugin_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("plugin_id 只能包含字母、数字、-、_".to_string());
    }
    if manifest.plugin_id.trim().is_empty() {
        return Err("plugin_id 不能为空".to_string());
    }
    if manifest.name.trim().is_empty() {
        return Err("插件名称不能为空".to_string());
    }
    if manifest.version.trim().is_empty() {
        return Err("插件版本不能为空".to_string());
    }
    if manifest.templates.is_empty() {
        return Err("插件包至少需要一个模板".to_string());
    }
    for template in &manifest.templates {
        if template.id.trim().is_empty() {
            return Err("模板 id 不能为空".to_string());
        }
        if template.name.trim().is_empty() {
            return Err("模板名称不能为空".to_string());
        }
    }
    Ok(())
}

fn validate_plugin_package_bytes(
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("插件包不能为空".to_string());
    }
    if bytes.len() > MAX_PLUGIN_PACKAGE_BYTES {
        return Err(format!(
            "插件包过大，限制为 {} 字节",
            MAX_PLUGIN_PACKAGE_BYTES
        ));
    }

    if let Some(expected) = expected_sha256 {
        let expected = expected.trim().to_ascii_lowercase();
        if !expected.is_empty() {
            if expected.len() != 64 || !expected.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err("sha256 必须是 64 位十六进制字符串".to_string());
            }
            let actual = format!("{:x}", Sha256::digest(bytes));
            if actual != expected {
                return Err("插件包 SHA-256 校验失败".to_string());
            }
        }
    }

    Ok(())
}

fn validate_plugin_archive_shape(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(), String> {
    if archive.len() > MAX_PLUGIN_ARCHIVE_ENTRIES {
        return Err(format!(
            "插件包文件数量过多，限制为 {} 个",
            MAX_PLUGIN_ARCHIVE_ENTRIES
        ));
    }

    let mut total_uncompressed = 0usize;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|err| format!("读取插件包文件列表失败: {}", err))?;
        total_uncompressed = total_uncompressed
            .checked_add(file.size() as usize)
            .ok_or_else(|| "插件包解压体积超限".to_string())?;
        if total_uncompressed > MAX_PLUGIN_TOTAL_UNCOMPRESSED_BYTES {
            return Err(format!(
                "插件包解压体积过大，限制为 {} 字节",
                MAX_PLUGIN_TOTAL_UNCOMPRESSED_BYTES
            ));
        }
    }

    Ok(())
}

fn sanitize_relative_plugin_path(value: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("文件模板的 body_file_path 不能为空".to_string());
    }
    let path = FsPath::new(trimmed);
    if path.is_absolute() {
        return Err("插件内文件路径必须使用相对路径".to_string());
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err("插件内文件路径不能包含越界路径".to_string());
        }
    }
    Ok(path.to_path_buf())
}

fn extract_plugin_asset(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    zip_entry_path: &str,
    output_path: &PathBuf,
) -> Result<(), String> {
    let mut file = archive
        .by_name(zip_entry_path)
        .map_err(|_| format!("插件包缺少资源文件 '{}'", zip_entry_path))?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("创建插件资源目录失败: {}", err))?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("读取插件资源失败: {}", err))?;
    fs::write(output_path, bytes).map_err(|err| format!("写入插件资源失败: {}", err))
}

fn default_rule_layer_l7() -> String {
    "l7".to_string()
}

fn default_rule_action_respond() -> String {
    "respond".to_string()
}

fn default_rule_severity_high() -> String {
    "high".to_string()
}

pub(super) fn parse_sort_direction(
    value: Option<&str>,
) -> Result<crate::storage::SortDirection, String> {
    match value.unwrap_or("desc").trim().to_ascii_lowercase().as_str() {
        "asc" => Ok(crate::storage::SortDirection::Asc),
        "desc" => Ok(crate::storage::SortDirection::Desc),
        other => Err(format!("Unsupported sort_direction '{}'", other)),
    }
}

pub(super) fn parse_event_sort_field(
    value: Option<&str>,
) -> Result<crate::storage::EventSortField, String> {
    match value
        .unwrap_or("created_at")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "created_at" => Ok(crate::storage::EventSortField::CreatedAt),
        "source_ip" => Ok(crate::storage::EventSortField::SourceIp),
        "dest_port" => Ok(crate::storage::EventSortField::DestPort),
        other => Err(format!("Unsupported event sort_by '{}'", other)),
    }
}

pub(super) fn parse_blocked_ip_sort_field(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSortField, String> {
    match value
        .unwrap_or("blocked_at")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "blocked_at" => Ok(crate::storage::BlockedIpSortField::BlockedAt),
        "expires_at" => Ok(crate::storage::BlockedIpSortField::ExpiresAt),
        "ip" => Ok(crate::storage::BlockedIpSortField::Ip),
        other => Err(format!("Unsupported blocked IP sort_by '{}'", other)),
    }
}

fn sqlite_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    if !state.context.config_snapshot().sqlite_enabled {
        return Err(ApiError::conflict(
            "SQLite storage is disabled in configuration".to_string(),
        ));
    }

    state
        .context
        .sqlite_store
        .as_deref()
        .ok_or_else(|| ApiError::conflict("SQLite store is unavailable".to_string()))
}

fn rules_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    let store = sqlite_store(state)?;
    if !state.context.config_snapshot().sqlite_rules_enabled {
        return Err(ApiError::conflict(
            "SQLite-backed rules are disabled in configuration".to_string(),
        ));
    }
    Ok(store)
}

async fn persisted_config(state: &ApiState) -> ApiResult<Config> {
    let store = sqlite_store(state)?;
    store
        .load_app_config()
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("数据库中未找到系统配置".to_string()))
}

pub(super) fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn runtime_profile_label(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Minimal => "minimal",
        RuntimeProfile::Standard => "standard",
    }
}

fn map_storage_write_error(error: anyhow::Error) -> ApiError {
    if let Some(sqlx_error) = error.downcast_ref::<sqlx::Error>() {
        if let Some(database_error) = sqlx_error.as_database_error() {
            if database_error.is_unique_violation() {
                return ApiError::conflict(database_error.message().to_string());
            }
            if database_error.is_foreign_key_violation() {
                return ApiError::bad_request(database_error.message().to_string());
            }
        }
    }

    ApiError::internal(error)
}

async fn admin_auth_middleware(
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let source_ip = request_source_ip(&request);
    let runtime_config = state.context.config_snapshot();
    let auth_config = runtime_config.admin_api_auth.clone();

    let principal = if auth_config.enabled {
        match extract_bearer_token(request.headers()) {
            Some(token) if token == auth_config.bearer_token => "bearer-token",
            _ => {
                audit_admin_request(
                    auth_config.audit_enabled,
                    method.as_str(),
                    &path,
                    source_ip.as_deref(),
                    "anonymous",
                    false,
                    StatusCode::UNAUTHORIZED,
                );
                return ApiError::unauthorized("管理接口需要 Bearer Token").into_response();
            }
        }
    } else {
        "anonymous"
    };

    let response = next.run(request).await;
    if auth_config.audit_enabled && is_audited_method(&method) {
        audit_admin_request(
            true,
            method.as_str(),
            &path,
            source_ip.as_deref(),
            principal,
            response.status().is_success(),
            response.status(),
        );
    }

    response
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn is_audited_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn request_source_ip(request: &Request<axum::body::Body>) -> Option<String> {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
}

fn audit_admin_request(
    enabled: bool,
    method: &str,
    path: &str,
    source_ip: Option<&str>,
    principal: &str,
    success: bool,
    status: StatusCode,
) {
    if !enabled {
        return;
    }
    log::info!(
        "admin_audit method={} path={} source_ip={} principal={} success={} status={}",
        method,
        path,
        source_ip.unwrap_or("unknown"),
        principal,
        success,
        status.as_u16()
    );
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleAction, RuleLayer, Severity};
    use crate::storage::{LocalCertificateEntry, LocalSiteEntry, SiteSyncLinkEntry, SqliteStore};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "{}_api_{}_{}.db",
                env!("CARGO_PKG_NAME"),
                name,
                nanos
            ))
            .display()
            .to_string()
    }

    #[test]
    fn test_build_metrics_response_without_sources() {
        let response = build_metrics_response(None, 0, None);

        assert_eq!(response.total_packets, 0);
        assert_eq!(response.blocked_packets, 0);
        assert_eq!(response.active_rules, 0);
        assert!(!response.sqlite_enabled);
        assert_eq!(response.persisted_security_events, 0);
        assert_eq!(response.persisted_blocked_ips, 0);
        assert_eq!(response.persisted_rules, 0);
        assert!(response.last_persisted_event_at.is_none());
        assert!(response.last_rule_update_at.is_none());
    }

    #[test]
    fn test_build_metrics_response_with_sources() {
        let response = build_metrics_response(
            Some(crate::metrics::MetricsSnapshot {
                total_packets: 12,
                blocked_packets: 3,
                blocked_l4: 1,
                blocked_l7: 2,
                total_bytes: 1024,
                proxied_requests: 10,
                proxy_successes: 8,
                proxy_failures: 2,
                proxy_fail_close_rejections: 1,
                upstream_healthcheck_successes: 5,
                upstream_healthcheck_failures: 1,
                proxy_latency_micros_total: 40_000,
                average_proxy_latency_micros: 5_000,
            }),
            4,
            Some(crate::storage::StorageMetricsSummary {
                security_events: 7,
                blocked_ips: 2,
                latest_event_at: Some(1234567890),
                rules: 5,
                latest_rule_update_at: Some(1234567899),
            }),
        );

        assert_eq!(response.total_packets, 12);
        assert_eq!(response.blocked_packets, 3);
        assert_eq!(response.blocked_l4, 1);
        assert_eq!(response.blocked_l7, 2);
        assert_eq!(response.total_bytes, 1024);
        assert_eq!(response.proxied_requests, 10);
        assert_eq!(response.proxy_successes, 8);
        assert_eq!(response.proxy_failures, 2);
        assert_eq!(response.proxy_fail_close_rejections, 1);
        assert_eq!(response.upstream_healthcheck_successes, 5);
        assert_eq!(response.upstream_healthcheck_failures, 1);
        assert_eq!(response.proxy_latency_micros_total, 40_000);
        assert_eq!(response.average_proxy_latency_micros, 5_000);
        assert_eq!(response.active_rules, 4);
        assert!(response.sqlite_enabled);
        assert_eq!(response.persisted_security_events, 7);
        assert_eq!(response.persisted_blocked_ips, 2);
        assert_eq!(response.persisted_rules, 5);
        assert_eq!(response.last_persisted_event_at, Some(1234567890));
        assert_eq!(response.last_rule_update_at, Some(1234567899));
    }

    #[test]
    fn test_rule_response_from_rule() {
        let response = RuleResponse::from(Rule {
            id: "rule-2".to_string(),
            name: "Alert Probe".to_string(),
            enabled: false,
            layer: RuleLayer::L4,
            pattern: "probe".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: None,
        });

        assert_eq!(response.id, "rule-2");
        assert_eq!(response.layer, "l4");
        assert_eq!(response.action, "alert");
        assert_eq!(response.severity, "medium");
    }

    #[test]
    fn test_events_query_params_into_query() {
        let query = EventsQueryParams {
            limit: Some(25),
            offset: Some(10),
            layer: Some("L7".to_string()),
            provider: Some("safeline".to_string()),
            provider_site_id: Some("site-1".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            action: Some("block".to_string()),
            blocked_only: Some(true),
            handled_only: Some(true),
            created_from: Some(100),
            created_to: Some(200),
            sort_by: Some("source_ip".to_string()),
            sort_direction: Some("asc".to_string()),
        }
        .into_query();

        let query = query.unwrap();
        assert_eq!(query.limit, 25);
        assert_eq!(query.offset, 10);
        assert_eq!(query.layer.as_deref(), Some("L7"));
        assert_eq!(query.provider.as_deref(), Some("safeline"));
        assert_eq!(query.provider_site_id.as_deref(), Some("site-1"));
        assert_eq!(query.source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(query.action.as_deref(), Some("block"));
        assert!(query.blocked_only);
        assert_eq!(query.created_from, Some(100));
        assert_eq!(query.created_to, Some(200));
        assert!(matches!(
            query.sort_by,
            crate::storage::EventSortField::SourceIp
        ));
        assert!(matches!(
            query.sort_direction,
            crate::storage::SortDirection::Asc
        ));
    }

    #[test]
    fn test_blocked_ips_query_params_into_query() {
        let query = BlockedIpsQueryParams {
            limit: Some(5),
            offset: Some(2),
            source_scope: Some("local".to_string()),
            provider: Some("safeline".to_string()),
            ip: Some("10.0.0.2".to_string()),
            keyword: Some(" rate ".to_string()),
            active_only: Some(true),
            blocked_from: Some(300),
            blocked_to: Some(400),
            sort_by: Some("ip".to_string()),
            sort_direction: Some("asc".to_string()),
        }
        .into_query();

        let query = query.unwrap();
        assert_eq!(query.limit, 5);
        assert_eq!(query.offset, 2);
        assert!(matches!(
            query.source_scope,
            crate::storage::BlockedIpSourceScope::Local
        ));
        assert_eq!(query.provider.as_deref(), Some("safeline"));
        assert_eq!(query.ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(query.keyword.as_deref(), Some("rate"));
        assert!(query.active_only);
        assert_eq!(query.blocked_from, Some(300));
        assert_eq!(query.blocked_to, Some(400));
        assert!(matches!(
            query.sort_by,
            crate::storage::BlockedIpSortField::Ip
        ));
    }

    #[test]
    fn test_blocked_ips_query_keyword_empty_becomes_none() {
        let query = BlockedIpsQueryParams {
            keyword: Some("   ".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query()
        .unwrap();

        assert_eq!(query.keyword, None);
    }

    #[test]
    fn test_invalid_sort_params_fail_validation() {
        let invalid_events = EventsQueryParams {
            sort_by: Some("unknown".to_string()),
            ..EventsQueryParams::default()
        }
        .into_query();
        assert!(invalid_events.is_err());

        let invalid_blocked = BlockedIpsQueryParams {
            source_scope: Some("sideways".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query();
        assert!(invalid_blocked.is_err());

        let invalid_blocked_sort = BlockedIpsQueryParams {
            sort_direction: Some("sideways".to_string()),
            ..BlockedIpsQueryParams::default()
        }
        .into_query();
        assert!(invalid_blocked_sort.is_err());
    }

    #[test]
    fn test_safeline_mapping_update_rejects_duplicate_site_ids() {
        let payload = SafeLineMappingsUpdateRequest {
            mappings: vec![
                SafeLineMappingUpsertRequest {
                    safeline_site_id: "site-1".to_string(),
                    safeline_site_name: "portal".to_string(),
                    safeline_site_domain: "portal.example.com".to_string(),
                    local_alias: "门户".to_string(),
                    enabled: true,
                    is_primary: false,
                    notes: "".to_string(),
                },
                SafeLineMappingUpsertRequest {
                    safeline_site_id: "site-1".to_string(),
                    safeline_site_name: "portal-dup".to_string(),
                    safeline_site_domain: "portal-dup.example.com".to_string(),
                    local_alias: "门户副本".to_string(),
                    enabled: true,
                    is_primary: false,
                    notes: "".to_string(),
                },
            ],
        };

        let error = payload.into_storage_mappings().unwrap_err();
        assert!(error.contains("重复映射"));
    }

    #[test]
    fn test_safeline_mapping_update_rejects_disabled_primary() {
        let payload = SafeLineMappingsUpdateRequest {
            mappings: vec![SafeLineMappingUpsertRequest {
                safeline_site_id: "site-1".to_string(),
                safeline_site_name: "portal".to_string(),
                safeline_site_domain: "portal.example.com".to_string(),
                local_alias: "门户".to_string(),
                enabled: false,
                is_primary: true,
                notes: "".to_string(),
            }],
        };

        let error = payload.into_storage_mappings().unwrap_err();
        assert!(error.contains("必须保持启用状态"));
    }

    #[tokio::test]
    async fn test_local_site_request_normalizes_primary_hostname() {
        let path = unique_test_db_path("local_site_request");
        let store = SqliteStore::new(path, true).await.unwrap();

        let site = LocalSiteUpsertRequest {
            name: " Portal ".to_string(),
            primary_hostname: " portal.example.com ".to_string(),
            hostnames: vec!["www.portal.example.com".to_string()],
            listen_ports: vec![" 443 ".to_string(), "443".to_string()],
            upstreams: vec![
                " http://127.0.0.1:8080 ".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ],
            safeline_intercept: None,
            enabled: true,
            tls_enabled: true,
            local_certificate_id: None,
            source: " ".to_string(),
            sync_mode: " ".to_string(),
            notes: " prod ".to_string(),
            last_synced_at: Some(123),
        }
        .into_storage_site(&store)
        .await
        .unwrap();

        assert_eq!(site.name, "Portal");
        assert_eq!(site.primary_hostname, "portal.example.com");
        assert_eq!(
            site.hostnames,
            vec![
                "portal.example.com".to_string(),
                "www.portal.example.com".to_string()
            ]
        );
        assert_eq!(site.listen_ports, vec!["443".to_string()]);
        assert_eq!(site.upstreams, vec!["http://127.0.0.1:8080".to_string()]);
        assert_eq!(site.source, "manual");
        assert_eq!(site.sync_mode, "manual");
        assert_eq!(site.notes, "prod");
    }

    #[tokio::test]
    async fn test_local_site_request_rejects_missing_certificate_reference() {
        let path = unique_test_db_path("local_site_missing_cert");
        let store = SqliteStore::new(path, true).await.unwrap();

        let error = LocalSiteUpsertRequest {
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames: Vec::new(),
            listen_ports: Vec::new(),
            upstreams: Vec::new(),
            safeline_intercept: None,
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(999),
            source: "manual".to_string(),
            sync_mode: "manual".to_string(),
            notes: String::new(),
            last_synced_at: None,
        }
        .into_storage_site(&store)
        .await
        .unwrap_err();

        assert!(error.contains("本地证书"));
    }

    #[test]
    fn test_local_certificate_request_validates_time_range() {
        let error = LocalCertificateUpsertRequest {
            name: "portal cert".to_string(),
            domains: vec!["portal.example.com".to_string()],
            issuer: "Acme".to_string(),
            valid_from: Some(200),
            valid_to: Some(100),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            trusted: true,
            expired: false,
            notes: String::new(),
            last_synced_at: None,
            certificate_pem: None,
            private_key_pem: None,
        }
        .into_storage_certificate()
        .unwrap_err();

        assert!(error.contains("有效期结束时间"));
    }

    #[tokio::test]
    async fn test_site_sync_link_request_requires_existing_local_site() {
        let path = unique_test_db_path("site_link_missing_site");
        let store = SqliteStore::new(path, true).await.unwrap();

        let error = SiteSyncLinkUpsertRequest {
            local_site_id: 404,
            provider: "safeline".to_string(),
            remote_site_id: "site-1".to_string(),
            remote_site_name: String::new(),
            remote_cert_id: None,
            sync_mode: String::new(),
            last_local_hash: None,
            last_remote_hash: None,
            last_error: None,
            last_synced_at: None,
        }
        .into_storage_link(&store)
        .await
        .unwrap_err();

        assert!(error.contains("本地站点"));
    }

    #[test]
    fn test_local_site_response_parses_json_fields() {
        let response = LocalSiteResponse::try_from(LocalSiteEntry {
            id: 1,
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames_json: r#"["portal.example.com","www.portal.example.com"]"#.to_string(),
            listen_ports_json: r#"["80","443"]"#.to_string(),
            upstreams_json: r#"["http://127.0.0.1:8080"]"#.to_string(),
            safeline_intercept_json: None,
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(3),
            source: "manual".to_string(),
            sync_mode: "manual".to_string(),
            notes: String::new(),
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        })
        .unwrap();

        assert_eq!(response.hostnames.len(), 2);
        assert_eq!(response.listen_ports, vec!["80", "443"]);
        assert_eq!(response.upstreams, vec!["http://127.0.0.1:8080"]);
    }

    #[test]
    fn test_local_certificate_response_parses_json_fields() {
        let response = LocalCertificateResponse::try_from(LocalCertificateEntry {
            id: 1,
            name: "Portal".to_string(),
            domains_json: r#"["portal.example.com","api.example.com"]"#.to_string(),
            issuer: "Acme".to_string(),
            valid_from: Some(100),
            valid_to: Some(200),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            trusted: true,
            expired: false,
            notes: String::new(),
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        })
        .unwrap();

        assert_eq!(
            response.domains,
            vec!["portal.example.com", "api.example.com"]
        );
        assert_eq!(response.provider_remote_id.as_deref(), Some("31"));
    }

    #[test]
    fn test_site_sync_link_response_from_storage() {
        let response = SiteSyncLinkResponse::from(SiteSyncLinkEntry {
            id: 1,
            local_site_id: 2,
            provider: "safeline".to_string(),
            remote_site_id: "site-1".to_string(),
            remote_site_name: "portal.example.com".to_string(),
            remote_cert_id: Some("31".to_string()),
            sync_mode: "bidirectional".to_string(),
            last_local_hash: Some("local".to_string()),
            last_remote_hash: Some("remote".to_string()),
            last_error: None,
            last_synced_at: Some(123),
            created_at: 100,
            updated_at: 200,
        });

        assert_eq!(response.provider, "safeline");
        assert_eq!(response.remote_site_id, "site-1");
        assert_eq!(response.remote_cert_id.as_deref(), Some("31"));
    }
}
