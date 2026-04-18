use super::*;
use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};

pub(crate) fn enforce_http1_request_safety(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> Result<()> {
    let config = &context.config_snapshot().l7_config;
    if !config.upstream_http1_strict_mode {
        return Ok(());
    }

    let content_length_count = request
        .get_metadata("http1.content_length_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| usize::from(request.get_header("content-length").is_some()));
    let has_transfer_encoding = request
        .get_metadata("http1.has_transfer_encoding")
        .map(|value| value == "true")
        .unwrap_or_else(|| request.get_header("transfer-encoding").is_some());
    let has_expect_100_continue = request
        .get_metadata("http1.has_expect_100_continue")
        .map(|value| value == "true")
        .unwrap_or_else(|| {
            request
                .get_header("expect")
                .map(|value| value.eq_ignore_ascii_case("100-continue"))
                .unwrap_or(false)
        });

    if config.reject_ambiguous_http1_requests && content_length_count > 1 {
        anyhow::bail!("rejected ambiguous HTTP/1 request: multiple Content-Length headers");
    }
    if config.reject_http1_transfer_encoding_requests && has_transfer_encoding {
        anyhow::bail!("rejected HTTP/1 request carrying Transfer-Encoding");
    }
    if config.reject_ambiguous_http1_requests && has_transfer_encoding && content_length_count > 0 {
        anyhow::bail!(
            "rejected ambiguous HTTP/1 request: both Content-Length and Transfer-Encoding present"
        );
    }
    if config.reject_expect_100_continue && has_expect_100_continue {
        anyhow::bail!("rejected HTTP/1 request carrying Expect: 100-continue");
    }
    let declared_body_len = request
        .get_header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if config.reject_body_on_safe_http_methods
        && (declared_body_len > 0 || !request.body.is_empty())
        && matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    {
        anyhow::bail!(
            "rejected HTTP/1 request carrying a body on safe method {}",
            request.method
        );
    }

    Ok(())
}

pub(super) fn build_http2_upstream_request(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<Request<Full<Bytes>>> {
    let upstream_authority = effective_http2_upstream_authority(request, upstream);
    let uri = format!(
        "https://{}{}",
        upstream_authority,
        normalize_http2_upstream_path(&request.uri)
    );
    let mut builder = Request::builder().method(request.method.as_str()).uri(uri);

    for (key, value) in &request.headers {
        if key.eq_ignore_ascii_case(CONNECTION.as_str())
            || key.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
            || key.eq_ignore_ascii_case(HOST.as_str())
            || should_strip_loop_detection_header(key)
            || key.starts_with(':')
        {
            continue;
        }
        if key.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            continue;
        }
        builder = builder.header(key.as_str(), value.as_str());
    }

    // In HTTP/2 the request authority is already carried by the URI/:authority.
    // Re-injecting a plain `Host` header here caused the local Tengine upstream
    // to reject otherwise valid requests with 400 Bad Request.
    builder
        .body(Full::new(Bytes::from(request.body.clone())))
        .map_err(Into::into)
}

pub(super) fn effective_http2_upstream_authority(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> String {
    // `upstream.authority` is only the connect target (for example 127.0.0.1:880).
    // The business host seen by the upstream virtual host must still come from the
    // original request host/authority so that SNI and routing stay on wnluo.com.
    request
        .get_header("host")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            request
                .metadata
                .get("authority")
                .cloned()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| upstream.authority.clone())
}

fn should_strip_loop_detection_header(header_name: &str) -> bool {
    header_name.eq_ignore_ascii_case("cdn-loop")
        || header_name.eq_ignore_ascii_case("via")
        || header_name.eq_ignore_ascii_case("eo-log-uuid")
}

fn normalize_http2_upstream_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}
