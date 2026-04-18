use super::*;

mod http1;
mod http2;
mod request;
#[cfg(test)]
mod tests;
mod tls;

use self::http1::{proxy_http1_request_strict, proxy_raw_http1_over_stream};
use self::http2::{proxy_http2_request, select_upstream_transport, UpstreamTransport};
pub(crate) use self::request::enforce_http1_request_safety;
use self::tls::{connect_upstream_client, resolve_upstream_tls_server_name};

#[allow(dead_code)]
async fn forward_http1_request<W>(
    client_stream: &mut W,
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let response = proxy_http_request(
        context,
        request,
        upstream_addr,
        connect_timeout_ms,
        write_timeout_ms,
        read_timeout_ms,
    )
    .await?;
    let approx_bytes = response.body.len() as u64;
    write_http1_upstream_response(context, client_stream, &response).await?;
    Ok(approx_bytes)
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum UpstreamClientConnection {
    Plain {
        authority: String,
        stream: TcpStream,
    },
    Tls {
        authority: String,
        server_name: String,
        stream: tokio_rustls::client::TlsStream<TcpStream>,
    },
}

pub(crate) fn resolve_runtime_custom_response(response: &CustomHttpResponse) -> CustomHttpResponse {
    let mut resolved = response.clone();
    if let Some(random_status) = response.random_status.as_ref() {
        let roll = rand::thread_rng().gen_range(0..100);
        if roll < u32::from(random_status.success_rate_percent) {
            resolved.status_code = 200;
            resolved.body = random_status.success_body.clone();
        } else if !random_status.failure_statuses.is_empty() {
            let index = rand::thread_rng().gen_range(0..random_status.failure_statuses.len());
            resolved.status_code = random_status.failure_statuses[index];
            resolved.body = random_status.failure_body.clone();
        }
    }
    resolved
}

pub(crate) async fn proxy_http_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    match select_upstream_transport(context, request, &upstream)? {
        UpstreamTransport::Http1 => {
            proxy_http1_request_strict(
                context,
                request,
                &upstream,
                connect_timeout_ms,
                write_timeout_ms,
                read_timeout_ms,
            )
            .await
        }
        UpstreamTransport::Http2 => {
            proxy_http2_request(
                context,
                request,
                &upstream,
                connect_timeout_ms,
                read_timeout_ms,
            )
            .await
        }
    }
}

pub(crate) async fn proxy_http_request_with_session_affinity(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    reusable_connection: &mut Option<UpstreamClientConnection>,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    if context
        .config_snapshot()
        .l7_config
        .upstream_http1_strict_mode
        || !context
            .config_snapshot()
            .l7_config
            .upstream_http1_allow_connection_reuse
        || !matches!(
            select_upstream_transport(context, request, &upstream)?,
            UpstreamTransport::Http1
        )
    {
        return proxy_http_request(
            context,
            request,
            upstream_addr,
            connect_timeout_ms,
            write_timeout_ms,
            read_timeout_ms,
        )
        .await;
    }

    enforce_http1_request_safety(context, request)?;
    let skip_verify = should_skip_upstream_tls_verification(context, &upstream);
    let effective_tls_server_name = if matches!(upstream.scheme, UpstreamScheme::Https) {
        resolve_upstream_tls_server_name(request, &upstream)?
    } else {
        None
    };
    let same_authority = reusable_connection
        .as_ref()
        .map(|connection| match connection {
            UpstreamClientConnection::Plain { authority, .. } => authority == &upstream.authority,
            UpstreamClientConnection::Tls {
                authority,
                server_name,
                ..
            } => {
                authority == &upstream.authority
                    && effective_tls_server_name
                        .as_deref()
                        .map(|expected| expected == server_name)
                        .unwrap_or(false)
            }
        })
        .unwrap_or(false);
    if !same_authority {
        *reusable_connection = None;
    }
    if reusable_connection.is_none() {
        *reusable_connection = Some(
            connect_upstream_client(
                request,
                &upstream,
                effective_tls_server_name.as_deref(),
                connect_timeout_ms,
                skip_verify,
            )
            .await?,
        );
    }

    let response = match reusable_connection.as_mut() {
        Some(UpstreamClientConnection::Plain { stream, .. }) => {
            proxy_raw_http1_over_stream(stream, request, write_timeout_ms, read_timeout_ms).await
        }
        Some(UpstreamClientConnection::Tls { stream, .. }) => {
            proxy_raw_http1_over_stream(stream, request, write_timeout_ms, read_timeout_ms).await
        }
        None => Err(anyhow::anyhow!("missing upstream connection after connect")),
    };

    match response {
        Ok(response) => {
            let should_close = response.headers.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("connection")
                    && value.to_ascii_lowercase().contains("close")
            });
            if should_close {
                *reusable_connection = None;
            }
            context.set_upstream_health(true, None);
            Ok(response)
        }
        Err(err) => {
            *reusable_connection = None;
            Err(err)
        }
    }
}
