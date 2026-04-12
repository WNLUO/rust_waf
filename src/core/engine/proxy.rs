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

#[derive(Debug, Clone)]
struct UpstreamHttpResponse {
    status_code: u16,
    status_text: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SafeLineInterceptMatch {
    event_id: Option<String>,
    evidence: &'static str,
}

#[derive(Debug, Clone)]
enum UpstreamResponseDisposition {
    Forward(UpstreamHttpResponse),
    Custom(CustomHttpResponse),
    Drop,
}

enum UpstreamClientConnection {
    Plain {
        authority: String,
        stream: TcpStream,
    },
    Tls {
        authority: String,
        stream: tokio_rustls::client::TlsStream<TcpStream>,
    },
}

fn resolve_runtime_custom_response(response: &CustomHttpResponse) -> CustomHttpResponse {
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

async fn proxy_http_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    let skip_verify = should_skip_upstream_tls_verification(context, &upstream);
    if matches!(upstream.scheme, UpstreamScheme::Http) {
        let upstream_stream = tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            TcpStream::connect(upstream.authority.as_str()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
        let parsed = proxy_raw_http1_over_stream(
            upstream_stream,
            request,
            write_timeout_ms,
            read_timeout_ms,
        )
        .await?;
        context.set_upstream_health(true, None);
        return Ok(parsed);
    }

    let upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream.authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
    let server_name = ServerName::try_from(
        authority_uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing host"))?
            .to_string(),
    )
    .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))?;
    let tls_connector = build_upstream_tls_connector(skip_verify)?;
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        tls_connector.connect(server_name, upstream_stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
    let parsed =
        proxy_raw_http1_over_stream(tls_stream, request, write_timeout_ms, read_timeout_ms).await?;
    context.set_upstream_health(true, None);
    Ok(parsed)
}

async fn proxy_http_request_with_session_affinity(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    reusable_connection: &mut Option<UpstreamClientConnection>,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    let skip_verify = should_skip_upstream_tls_verification(context, &upstream);
    let same_authority = reusable_connection
        .as_ref()
        .map(|connection| match connection {
            UpstreamClientConnection::Plain { authority, .. }
            | UpstreamClientConnection::Tls { authority, .. } => authority == &upstream.authority,
        })
        .unwrap_or(false);
    if !same_authority {
        *reusable_connection = None;
    }
    if reusable_connection.is_none() {
        *reusable_connection = Some(
            connect_upstream_client(&upstream, connect_timeout_ms, skip_verify).await?,
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
            let should_close = response
                .headers
                .iter()
                .any(|(key, value)| {
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

async fn connect_upstream_client(
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    skip_certificate_verification: bool,
) -> Result<UpstreamClientConnection> {
    match upstream.scheme {
        UpstreamScheme::Http => {
            let stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                TcpStream::connect(upstream.authority.as_str()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
            Ok(UpstreamClientConnection::Plain {
                authority: upstream.authority.clone(),
                stream,
            })
        }
        UpstreamScheme::Https => {
            let upstream_stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                TcpStream::connect(upstream.authority.as_str()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
            let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
            let server_name = ServerName::try_from(
                authority_uri
                    .host()
                    .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing host"))?
                    .to_string(),
            )
            .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))?;
            let tls_connector = build_upstream_tls_connector(skip_certificate_verification)?;
            let stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                tls_connector.connect(server_name, upstream_stream),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
            Ok(UpstreamClientConnection::Tls {
                authority: upstream.authority.clone(),
                stream,
            })
        }
    }
}

async fn proxy_raw_http1_over_stream<S>(
    mut upstream_stream: S,
    request: &UnifiedHttpRequest,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = request.to_http1_bytes();
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream write timed out"))??;

    let mut response_bytes = Vec::new();
    let mut buffer = vec![0u8; 8192];
    let mut expected_total_len: Option<usize> = None;
    let mut chunked = false;
    loop {
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(read_timeout_ms),
            upstream_stream.read(&mut buffer),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream read timed out"))?;
        match read_result {
            Ok(0) => break,
            Ok(n) => {
                response_bytes.extend_from_slice(&buffer[..n]);

                if let Some(headers_end) = response_bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    if expected_total_len.is_none() && !chunked {
                        let header_block = &response_bytes[..headers_end];
                        let header_text = String::from_utf8_lossy(header_block);
                        let mut content_length = None;
                        for line in header_text.lines() {
                            if let Some((name, value)) = line.split_once(':') {
                                if name.eq_ignore_ascii_case("content-length") {
                                    content_length = value.trim().parse::<usize>().ok();
                                }
                                if name.eq_ignore_ascii_case("transfer-encoding")
                                    && value.to_ascii_lowercase().contains("chunked")
                                {
                                    chunked = true;
                                }
                            }
                        }
                        if let Some(length) = content_length {
                            expected_total_len = Some(headers_end + 4 + length);
                        }
                    }

                    if let Some(expected) = expected_total_len {
                        if response_bytes.len() >= expected {
                            break;
                        }
                    } else if chunked
                        && response_bytes[headers_end + 4..]
                            .windows(5)
                            .any(|window| window == b"0\r\n\r\n")
                    {
                        break;
                    }
                }
            }
            Err(err) if !response_bytes.is_empty() => {
                debug!(
                    "Ignoring upstream read error after receiving response bytes: {}",
                    err
                );
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }

    parse_http1_response(&response_bytes)
}

fn build_upstream_tls_connector(skip_certificate_verification: bool) -> Result<TlsConnector> {
    if skip_certificate_verification {
        return Ok(build_insecure_upstream_tls_connector());
    }

    build_verified_upstream_tls_connector()
}

fn build_verified_upstream_tls_connector() -> Result<TlsConnector> {
    crate::tls::ensure_rustls_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn build_insecure_upstream_tls_connector() -> TlsConnector {
    crate::tls::ensure_rustls_crypto_provider();
    let config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn should_skip_upstream_tls_verification(
    context: &WafContext,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> bool {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        return false;
    }

    let config = context.config_snapshot();
    let safeline_base_url = config.integrations.safeline.base_url.trim();
    if safeline_base_url.is_empty() {
        return false;
    }

    let safeline_uri = match safeline_base_url.parse::<http::Uri>() {
        Ok(uri) => uri,
        Err(_) => return false,
    };
    if !safeline_uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        return false;
    }

    let Some(safeline_authority) = safeline_uri.authority().map(|value| value.as_str()) else {
        return false;
    };

    authorities_match_https(safeline_authority, &upstream.authority)
}

fn authorities_match_https(left: &str, right: &str) -> bool {
    let Some((left_host, left_port)) = parse_https_authority(left) else {
        return false;
    };
    let Some((right_host, right_port)) = parse_https_authority(right) else {
        return false;
    };

    left_host.eq_ignore_ascii_case(&right_host) && left_port == right_port
}

fn parse_https_authority(authority: &str) -> Option<(String, u16)> {
    let uri = format!("https://{}", authority).parse::<http::Uri>().ok()?;
    let host = uri.host()?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    Some((host, port))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn parse_http1_response(response: &[u8]) -> Result<UpstreamHttpResponse> {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            anyhow::anyhow!("Invalid upstream HTTP/1 response: missing header terminator")
        })?;
    let header_block = &response[..headers_end];
    let body_offset = headers_end + 4;
    let header_text = String::from_utf8_lossy(header_block);
    let mut lines = header_text.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _version = status_parts.next();
    let status_code = status_parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status code"))?
        .parse::<u16>()?;
    let status_text = status_parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
                continue;
            }
            headers.push((name, value));
        }
    }

    let body = if chunked {
        decode_chunked_body(&response[body_offset..])?
    } else {
        response[body_offset..].to_vec()
    };

    Ok(UpstreamHttpResponse {
        status_code,
        status_text,
        headers,
        body,
    })
}

async fn write_http1_upstream_response<W>(
    context: &WafContext,
    client_stream: &mut W,
    response: &UpstreamHttpResponse,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = response.headers.clone();
    apply_response_policies(context, &mut headers, response.status_code);
    Http1Handler::new()
        .write_response_with_headers(
            client_stream,
            response.status_code,
            response
                .status_text
                .as_deref()
                .unwrap_or(http_status_text(response.status_code)),
            &headers,
            &response.body,
        )
        .await?;
    Ok(())
}

fn apply_safeline_upstream_action(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    intercept_config: &SafeLineInterceptConfig,
    response: UpstreamHttpResponse,
) -> UpstreamResponseDisposition {
    if !intercept_config.enabled {
        return UpstreamResponseDisposition::Forward(response);
    }

    let Some(matched) = detect_safeline_block_response(
        &response,
        intercept_config.max_body_bytes,
        intercept_config.match_mode,
    ) else {
        return UpstreamResponseDisposition::Forward(response);
    };
    let response_status = response.status_code;

    let (local_action, disposition) = match intercept_config.action {
        SafeLineInterceptAction::Pass => ("pass", UpstreamResponseDisposition::Forward(response)),
        SafeLineInterceptAction::Replace => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => ("replace", UpstreamResponseDisposition::Custom(custom)),
                Err(err) => {
                    warn!(
                    "Failed to build SafeLine replacement response, falling back to upstream response: {}",
                    err
                );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
        SafeLineInterceptAction::Drop => ("drop", UpstreamResponseDisposition::Drop),
        SafeLineInterceptAction::ReplaceAndBlockIp => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => {
                    persist_safeline_intercept_blocked_ip(
                        context,
                        packet,
                        request,
                        intercept_config.block_duration_secs,
                        matched.event_id.as_deref(),
                    );
                    (
                        "replace_and_block_ip",
                        UpstreamResponseDisposition::Custom(custom),
                    )
                }
                Err(err) => {
                    warn!(
                        "Failed to build SafeLine replacement response for replace_and_block_ip, falling back to upstream response: {}",
                        err
                    );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
    };

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_block(InspectionLayer::L7);
    }
    if let Some(inspector) = context.l4_inspector() {
        inspector.record_l7_feedback(packet, request, crate::l4::behavior::FeedbackSource::SafeLine);
    }
    persist_safeline_intercept_event(
        context,
        packet,
        request,
        matched_site,
        &matched,
        response_status,
        local_action,
    );

    disposition
}

fn detect_safeline_block_response(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
    match_mode: SafeLineInterceptMatchMode,
) -> Option<SafeLineInterceptMatch> {
    let body = decode_response_body_for_matching(response, max_body_bytes)?;
    let has_body_signature = body_has_safeline_signature(&body);
    let has_header_signature = headers_have_safeline_signature(&response.headers);
    let has_signature = has_body_signature || has_header_signature;

    if let Some(event_id) = extract_html_comment_event_id(&body) {
        return Some(SafeLineInterceptMatch {
            event_id: Some(event_id),
            evidence: "html_event_comment",
        });
    }

    let json_event_id = extract_json_event_id(&body);
    if has_signature && json_event_id.is_some() {
        return Some(SafeLineInterceptMatch {
            event_id: json_event_id,
            evidence: "json_signature",
        });
    }

    if has_signature && matches!(response.status_code, 403 | 405) {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_and_signature",
        });
    }

    if matches!(match_mode, SafeLineInterceptMatchMode::Relaxed)
        && matches!(response.status_code, 403 | 405)
    {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_only_relaxed",
        });
    }

    None
}

fn decode_response_body_for_matching(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
) -> Option<String> {
    let limit = max_body_bytes.max(256);
    let mut decoded = Vec::new();

    match upstream_header_value(&response.headers, "content-encoding")
        .map(|value| value.to_ascii_lowercase())
    {
        Some(value) if value.contains("gzip") => {
            let decoder = GzDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(value) if value.contains("deflate") => {
            let decoder = ZlibDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(value) if value.contains("br") => {
            let decoder = Decompressor::new(response.body.as_slice(), 4096);
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(_) => {
            decoded.extend_from_slice(&response.body[..response.body.len().min(limit)]);
        }
        None => {
            decoded.extend_from_slice(&response.body[..response.body.len().min(limit)]);
        }
    }

    Some(String::from_utf8_lossy(&decoded).into_owned())
}

fn upstream_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn extract_json_event_id(body: &str) -> Option<String> {
    let payload = serde_json::from_str::<serde_json::Value>(body).ok()?;
    extract_json_string_by_keys(
        &payload,
        &["event_id", "eventId", "eventID", "log_id", "logId"],
    )
}

fn extract_html_comment_event_id(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    for marker in ["<!-- event_id:", "<!-- event-id:", "<!-- event id:"] {
        let Some(start) = lower.find(marker) else {
            continue;
        };
        let value_start = start + marker.len();
        let Some(remainder) = body.get(value_start..) else {
            continue;
        };
        let Some(end) = remainder.find("-->") else {
            continue;
        };
        let candidate = remainder.get(..end)?.trim();
        let event_id = candidate.split_whitespace().next()?.trim();
        if is_valid_safeline_event_id(event_id) {
            return Some(event_id.to_string());
        }
    }

    None
}

fn body_has_safeline_signature(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let mentions_safeline = lower.contains("safeline") || lower.contains("chaitin");
    let mentions_block = lower.contains("blocked")
        || lower.contains("forbidden")
        || lower.contains("intercept")
        || lower.contains("web application firewall")
        || lower.contains("\"code\":403")
        || lower.contains("\"status\":403");

    mentions_safeline && mentions_block
}

fn headers_have_safeline_signature(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        let value = value.to_ascii_lowercase();
        (matches!(
            key.as_str(),
            "server" | "x-powered-by" | "x-waf" | "x-safeline-event-id" | "x-request-id"
        ) && (value.contains("safeline") || value.contains("chaitin")))
            || (key == "set-cookie" && value.contains("sl-session="))
    })
}

fn extract_json_string_by_keys(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for key in keys {
                if let Some(candidate) = map
                    .get(*key)
                    .and_then(|item| item.as_str())
                    .filter(|item| is_valid_safeline_event_id(item))
                {
                    return Some(candidate.to_string());
                }
            }

            map.values()
                .find_map(|item| extract_json_string_by_keys(item, keys))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| extract_json_string_by_keys(item, keys)),
        _ => None,
    }
}

fn is_valid_safeline_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'))
}

fn request_expects_empty_body(request: &UnifiedHttpRequest) -> bool {
    request.method.eq_ignore_ascii_case("HEAD")
}

fn body_for_request(request: &UnifiedHttpRequest, body: &[u8]) -> Vec<u8> {
    if request_expects_empty_body(request) {
        Vec::new()
    } else {
        body.to_vec()
    }
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid chunked response: missing chunk size terminator")
            })?
            + cursor;
        let size_line = std::str::from_utf8(&body[cursor..line_end])?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = cursor + chunk_size;
        if chunk_end > body.len() {
            anyhow::bail!("Invalid chunked response: chunk exceeds body length");
        }
        decoded.extend_from_slice(&body[cursor..chunk_end]);
        cursor = chunk_end;

        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            anyhow::bail!("Invalid chunked response: missing CRLF after chunk");
        }
        cursor += 2;
    }

    Ok(decoded)
}
