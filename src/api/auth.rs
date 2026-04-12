use super::error::ApiError;
use super::state::ApiState;
use axum::{
    extract::State,
    http::header,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

pub(super) async fn admin_auth_middleware(
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
