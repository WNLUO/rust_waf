use super::*;

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn parse_proxy_protocol_stream(
    context: &WafContext,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<(PrefixedStream<TcpStream>, Vec<(String, String)>)> {
    if context.config_snapshot().gateway_config.source_ip_strategy
        != crate::config::SourceIpStrategy::ProxyProtocol
    {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    }

    let mut peeked = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(context.config_snapshot().l7_config.first_byte_timeout_ms),
        stream.peek(&mut peeked),
    )
    .await??;
    let preview = &peeked[..bytes_read];

    let Some(line_end) = preview.windows(2).position(|item| item == b"\r\n") else {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    };
    let line = &preview[..line_end + 2];
    let Some(source_ip) = parse_proxy_protocol_v1_source_ip(line) else {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    };

    let mut stream = stream;
    let mut consumed = vec![0u8; line.len()];
    stream.read_exact(&mut consumed).await?;
    debug!(
        "Parsed PROXY protocol source ip {} for peer {}",
        source_ip, peer_addr
    );

    Ok((
        PrefixedStream::new(Vec::new(), stream),
        vec![(
            "proxy_protocol_source_ip".to_string(),
            source_ip.to_string(),
        )],
    ))
}

fn parse_proxy_protocol_v1_source_ip(line: &[u8]) -> Option<std::net::IpAddr> {
    let text = std::str::from_utf8(line).ok()?.trim();
    let mut parts = text.split_whitespace();
    if parts.next()? != "PROXY" {
        return None;
    }

    match parts.next()? {
        "TCP4" | "TCP6" => parts.next()?.parse::<std::net::IpAddr>().ok(),
        "UNKNOWN" => None,
        _ => None,
    }
}

pub(crate) async fn detect_and_handle_protocol<S>(
    context: Arc<WafContext>,
    mut stream: S,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = context.config_snapshot();
    let detector = ProtocolDetector::default();

    let mut initial_buffer = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(config.l7_config.first_byte_timeout_ms),
        stream.read(&mut initial_buffer),
    )
    .await??;
    let stream = PrefixedStream::new(initial_buffer[..bytes_read].to_vec(), stream);

    let detected_version = if bytes_read > 0 {
        let preview = &initial_buffer[..bytes_read];
        if detector.is_http2_upgrade_request(preview) {
            debug!(
                "Detected h2c upgrade request from {}, inspecting first exchange as HTTP/1.1",
                peer_addr
            );
        }
        detector.detect_version(preview)
    } else {
        HttpVersion::Http1_1
    };

    debug!(
        "Detected protocol version: {} for connection from {}",
        detected_version, peer_addr
    );

    match detected_version {
        HttpVersion::Http2_0 if config.l7_config.http2_config.enabled => {
            handle_http2_connection(
                context,
                stream,
                peer_addr,
                packet,
                extra_metadata,
                connection_semaphore,
            )
            .await
        }
        _ => {
            handle_http1_connection(
                context,
                stream,
                peer_addr,
                packet,
                extra_metadata,
                connection_semaphore,
            )
            .await
        }
    }
}
