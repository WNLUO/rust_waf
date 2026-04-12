use super::types::RuleResponseTemplatePayload;
use crate::config::{Rule, RuleResponseBodySource, RuleResponseTemplate};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path as FsPath, PathBuf};
use std::time::Duration;
use zip::ZipArchive;

const MAX_PLUGIN_PACKAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLUGIN_ARCHIVE_ENTRIES: usize = 64;
const MAX_PLUGIN_TOTAL_UNCOMPRESSED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
struct RuleActionPluginManifest {
    plugin_id: String,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    templates: Vec<RuleActionPluginTemplateManifest>,
}

#[derive(Debug, serde::Deserialize)]
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

pub(super) async fn install_rule_action_plugin_from_url(
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

pub(super) async fn install_rule_action_plugin_from_bytes(
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
