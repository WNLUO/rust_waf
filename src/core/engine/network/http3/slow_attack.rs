use super::response::send_http3_response;
use super::*;

pub(super) async fn handle_http3_slow_attack_error(
    context: &WafContext,
    packet: &PacketInfo,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    err: crate::protocol::ProtocolError,
) -> Result<()> {
    let (kind, detail) = match err {
        crate::protocol::ProtocolError::SlowBody {
            bytes_read,
            expected_bytes,
            elapsed_ms,
        } => (
            crate::l7::SlowAttackKind::SlowBody,
            format!(
                "http3 bytes_read={bytes_read} expected_bytes={expected_bytes} elapsed_ms={elapsed_ms}"
            ),
        ),
        crate::protocol::ProtocolError::IdleTimeout { elapsed_ms } => (
            crate::l7::SlowAttackKind::IdleConnection,
            format!("http3 elapsed_ms={elapsed_ms}"),
        ),
        other => return Err(other.into()),
    };

    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context, packet.source_ip);
    let assessment = context
        .slow_attack_guard()
        .assess(crate::l7::SlowAttackObservation {
            kind,
            peer_ip: packet.source_ip,
            client_ip: None,
            trusted_proxy_peer,
            identity_state: if trusted_proxy_peer {
                "trusted_cdn_unresolved"
            } else {
                "direct_client"
            },
            client_identity_unresolved: trusted_proxy_peer,
            host: None,
            detail,
        });
    if let Some(metrics) = context.metrics.as_ref() {
        match kind {
            crate::l7::SlowAttackKind::IdleConnection => metrics.record_slow_attack_idle_timeout(),
            crate::l7::SlowAttackKind::SlowHeaders => metrics.record_slow_attack_header_timeout(),
            crate::l7::SlowAttackKind::SlowBody => metrics.record_slow_attack_body_timeout(),
            crate::l7::SlowAttackKind::SlowTlsHandshake => {
                metrics.record_slow_attack_tls_handshake()
            }
        }
        if assessment.should_block_ip {
            metrics.record_slow_attack_block();
        }
        metrics.record_block(crate::core::InspectionLayer::L7);
    }
    if let Some(inspector) = context.l4_inspector() {
        let mut slow_request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http3_0,
            "SLOW".to_string(),
            format!("/slow-attack/{}", kind.as_str()),
        );
        slow_request.set_client_ip(packet.source_ip.to_string());
        inspector.record_l7_feedback(
            packet,
            &slow_request,
            crate::l4::behavior::FeedbackSource::SlowAttack,
        );
    }
    if assessment.should_block_ip {
        if let Some(ip) = assessment.block_ip {
            if let Some(inspector) = context.l4_inspector() {
                inspector.block_ip(
                    &ip,
                    &assessment.reason,
                    std::time::Duration::from_secs(assessment.block_duration_secs),
                );
            }
            if let Some(store) = context.sqlite_store.as_ref() {
                let blocked_at = current_unix_timestamp();
                store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
                    ip.to_string(),
                    assessment.reason.clone(),
                    blocked_at,
                    blocked_at + assessment.block_duration_secs as i64,
                ));
            }
        }
    }
    persist_http3_slow_attack_event(context, packet, kind, &assessment);

    let response = context
        .slow_attack_guard()
        .build_response(&assessment, kind);
    send_http3_response(
        stream,
        response.status_code,
        &response.headers,
        response.body,
        None,
    )
    .await?;
    Ok(())
}

fn persist_http3_slow_attack_event(
    context: &WafContext,
    packet: &PacketInfo,
    kind: crate::l7::SlowAttackKind,
    assessment: &crate::l7::slow_attack_guard::SlowAttackAssessment,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };
    let mut event = crate::storage::SecurityEventRecord::now(
        "L7",
        if assessment.should_block_ip {
            "block"
        } else {
            "respond"
        },
        assessment.reason.clone(),
        assessment.block_ip.unwrap_or(packet.source_ip).to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.http_version = Some("HTTP/3.0".to_string());
    event.details_json = serde_json::to_string_pretty(&serde_json::json!({
        "slow_attack": {
            "kind": kind.as_str(),
            "event_count": assessment.event_count,
            "block_ip": assessment.block_ip.map(|ip| ip.to_string()),
            "peer_ip": packet.source_ip.to_string(),
        }
    }))
    .ok();
    store.enqueue_security_event(event);
}

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
