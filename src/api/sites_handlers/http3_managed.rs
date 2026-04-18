use super::super::*;
use std::path::{Path as StdPath, PathBuf};

const MANAGED_HTTP3_CERT_DIR: &str = "data/http3/managed";

pub(super) async fn maybe_configure_http3_managed_certificate(
    state: &ApiState,
    store: &crate::storage::SqliteStore,
    certificate_id: i64,
) -> Result<Option<String>, ApiError> {
    let Some(secret) = store
        .load_local_certificate_secret(certificate_id)
        .await
        .map_err(ApiError::internal)?
    else {
        return Ok(None);
    };

    let cert_path = managed_http3_certificate_path(certificate_id);
    let key_path = managed_http3_private_key_path(certificate_id);
    write_managed_http3_pem_pair(&cert_path, &key_path, &secret).await?;

    let mut config = persisted_config(state).await?;
    let cert_path_string = cert_path.to_string_lossy().to_string();
    let key_path_string = key_path.to_string_lossy().to_string();

    let can_override = config
        .http3_config
        .certificate_path
        .as_deref()
        .map(is_managed_http3_path)
        .unwrap_or(true)
        && config
            .http3_config
            .private_key_path
            .as_deref()
            .map(is_managed_http3_path)
            .unwrap_or(true);

    if !can_override {
        return Ok(Some(
            "检测到 HTTP/3 正在使用自定义证书路径，已保留用户配置，未自动覆盖。".to_string(),
        ));
    }

    let changed = config.http3_config.certificate_path.as_deref()
        != Some(cert_path_string.as_str())
        || config.http3_config.private_key_path.as_deref() != Some(key_path_string.as_str())
        || !config.http3_config.enabled;

    if !changed {
        return Ok(Some(
            "已同步托管证书到 HTTP/3，当前配置无需变更。".to_string(),
        ));
    }

    config.http3_config.certificate_path = Some(cert_path_string);
    config.http3_config.private_key_path = Some(key_path_string);
    config.http3_config.enabled = true;
    let next = config.normalized();

    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next);
    #[cfg(feature = "http3")]
    crate::core::engine::sync_http3_listener_runtime(
        Arc::clone(&state.context),
        state
            .context
            .config_snapshot()
            .max_concurrent_tasks
            .saturating_mul(4)
            .clamp(128, 4096),
        state.context.config_snapshot().max_concurrent_tasks,
    )
    .await
    .map_err(ApiError::internal)?;

    Ok(Some(
        "已自动为 HTTP/3 写入证书文件并启用 HTTP/3；QUIC 监听已按当前配置热刷新。".to_string(),
    ))
}

pub(super) async fn maybe_clear_http3_managed_certificate(
    state: &ApiState,
    store: &crate::storage::SqliteStore,
    certificate_id: i64,
) -> Result<Option<String>, ApiError> {
    let cert_path = managed_http3_certificate_path(certificate_id);
    let key_path = managed_http3_private_key_path(certificate_id);
    remove_file_if_exists(&cert_path).await?;
    remove_file_if_exists(&key_path).await?;

    let mut config = persisted_config(state).await?;
    let cert_path_string = cert_path.to_string_lossy().to_string();
    let key_path_string = key_path.to_string_lossy().to_string();

    let used_by_http3 = config.http3_config.certificate_path.as_deref()
        == Some(cert_path_string.as_str())
        || config.http3_config.private_key_path.as_deref() == Some(key_path_string.as_str());
    if !used_by_http3 {
        return Ok(None);
    }

    config.http3_config.enabled = false;
    config.http3_config.certificate_path = None;
    config.http3_config.private_key_path = None;
    let next = config.normalized();
    store
        .upsert_app_config(&next)
        .await
        .map_err(ApiError::internal)?;
    state.context.apply_runtime_config(next);
    #[cfg(feature = "http3")]
    crate::core::engine::sync_http3_listener_runtime(
        Arc::clone(&state.context),
        state
            .context
            .config_snapshot()
            .max_concurrent_tasks
            .saturating_mul(4)
            .clamp(128, 4096),
        state.context.config_snapshot().max_concurrent_tasks,
    )
    .await
    .map_err(ApiError::internal)?;

    Ok(Some(
        "当前证书已从 HTTP/3 托管配置中移除，并已自动关闭 HTTP/3；如需继续启用，请重新指定证书。"
            .to_string(),
    ))
}

fn managed_http3_certificate_path(certificate_id: i64) -> PathBuf {
    StdPath::new(MANAGED_HTTP3_CERT_DIR).join(format!("cert-{certificate_id}.pem"))
}

fn managed_http3_private_key_path(certificate_id: i64) -> PathBuf {
    StdPath::new(MANAGED_HTTP3_CERT_DIR).join(format!("key-{certificate_id}.pem"))
}

fn is_managed_http3_path(path: &str) -> bool {
    path.starts_with(MANAGED_HTTP3_CERT_DIR)
}

async fn write_managed_http3_pem_pair(
    cert_path: &StdPath,
    key_path: &StdPath,
    secret: &crate::storage::LocalCertificateSecretEntry,
) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(MANAGED_HTTP3_CERT_DIR)
        .await
        .map_err(ApiError::internal)?;
    tokio::fs::write(cert_path, secret.certificate_pem.as_bytes())
        .await
        .map_err(ApiError::internal)?;
    tokio::fs::write(key_path, secret.private_key_pem.as_bytes())
        .await
        .map_err(ApiError::internal)?;
    Ok(())
}

async fn remove_file_if_exists(path: &StdPath) -> Result<(), ApiError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ApiError::internal(err)),
    }
}
