use super::response::write_custom_http1_response;
use super::*;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(super) enum Http1RequestFlow {
    KeepAliveDecision,
    Close,
}

pub(super) async fn handle_http1_proxy_or_local_response<S>(
    context: &WafContext,
    http1_handler: &Http1Handler,
    stream: &mut S,
    packet: &PacketInfo,
    peer_addr: std::net::SocketAddr,
    config: &Config,
    matched_site: Option<&GatewaySiteRuntime>,
    request: &UnifiedHttpRequest,
    traffic_source_ip: &str,
    request_dump_len: usize,
    reusable_upstream_connection: &mut Option<UpstreamClientConnection>,
) -> Result<Http1RequestFlow>
where
    S: AsyncWrite + Unpin,
{
    let traffic_source_ip = traffic_source_ip.to_string();
    let upstream_addr = select_upstream_target(matched_site);
    if let Some(upstream_addr) = upstream_addr.as_deref() {
        let safeline_intercept = resolve_safeline_intercept_config(config, matched_site);
        if let Err(reason) = enforce_upstream_policy(context) {
            context
                .traffic_map
                .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_fail_close_rejection();
            }
            http1_handler
                .write_response(
                    stream,
                    503,
                    "Service Unavailable",
                    reason.to_string().as_bytes(),
                )
                .await?;
            return Ok(Http1RequestFlow::Close);
        }
        if let Some(metrics) = context.metrics.as_ref() {
            let labels = proxy_metric_labels(request);
            metrics.record_proxy_attempt_with_labels(proxy_traffic_kind(request), &labels);
        }
        if !safeline_intercept.enabled {
            let proxy_started_at = Instant::now();
            match stream_http_request_to_http1_client(
                context,
                request,
                upstream_addr,
                config.l7_config.proxy_connect_timeout_ms,
                config.l7_config.proxy_write_timeout_ms,
                config.l7_config.proxy_read_timeout_ms,
                stream,
            )
            .await
            {
                Ok(response) => {
                    if let Some(metrics) = context.metrics.as_ref() {
                        let labels = proxy_metric_labels(request);
                        metrics.record_proxy_success_with_labels(
                            proxy_traffic_kind(request),
                            proxy_started_at.elapsed(),
                            &labels,
                        );
                        metrics.record_streamed_proxy_response();
                    }
                    context.traffic_map.record_ingress(
                        traffic_source_ip.clone(),
                        request_dump_len,
                        false,
                    );
                    context.traffic_map.record_egress(
                        traffic_source_ip.clone(),
                        response.body_bytes_sent,
                        proxy_started_at.elapsed(),
                    );
                    context.note_ai_route_result(
                        request,
                        AiRouteResultObservation {
                            status_code: response.status_code,
                            latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                            upstream_error: response.status_code >= 500,
                            local_response: false,
                            blocked: false,
                        },
                    );
                    return Ok(Http1RequestFlow::Close);
                }
                Err(err) => {
                    context.traffic_map.record_ingress(
                        traffic_source_ip.clone(),
                        request_dump_len,
                        false,
                    );
                    if let Some(metrics) = context.metrics.as_ref() {
                        let labels = proxy_metric_labels(request);
                        metrics
                            .record_proxy_failure_with_labels(proxy_traffic_kind(request), &labels);
                    }
                    context.set_upstream_health(false, Some(err.to_string()));
                    warn!(
                        "Failed to stream HTTP/1.1 request from {} to {}: {}",
                        peer_addr, upstream_addr, err
                    );
                    http1_handler
                        .write_response(stream, 502, "Bad Gateway", b"upstream proxy failed")
                        .await?;
                    context.note_ai_route_result(
                        request,
                        AiRouteResultObservation {
                            status_code: 502,
                            latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                            upstream_error: true,
                            local_response: false,
                            blocked: false,
                        },
                    );
                    return Ok(Http1RequestFlow::Close);
                }
            }
        }
        let proxy_started_at = Instant::now();
        let proxy_result = if config.gateway_config.enable_ntlm
            && config.l7_config.upstream_http1_allow_connection_reuse
            && !config.l7_config.upstream_http1_strict_mode
        {
            proxy_http_request_with_session_affinity(
                context,
                &request,
                upstream_addr,
                config.l7_config.proxy_connect_timeout_ms,
                config.l7_config.proxy_write_timeout_ms,
                config.l7_config.proxy_read_timeout_ms,
                reusable_upstream_connection,
            )
            .await
        } else {
            proxy_http_request(
                context,
                &request,
                upstream_addr,
                config.l7_config.proxy_connect_timeout_ms,
                config.l7_config.proxy_write_timeout_ms,
                config.l7_config.proxy_read_timeout_ms,
            )
            .await
        };
        match proxy_result {
            Ok(response) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(request);
                    metrics.record_proxy_success_with_labels(
                        proxy_traffic_kind(request),
                        proxy_started_at.elapsed(),
                        &labels,
                    );
                }
                context.traffic_map.record_egress(
                    traffic_source_ip.clone(),
                    response.body.len(),
                    proxy_started_at.elapsed(),
                );
                match apply_safeline_upstream_action(
                    context,
                    packet,
                    &request,
                    matched_site,
                    safeline_intercept,
                    response,
                ) {
                    UpstreamResponseDisposition::Forward(response) => {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump_len,
                            false,
                        );
                        context.note_ai_route_result(
                            &request,
                            AiRouteResultObservation {
                                status_code: response.status_code,
                                latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                                upstream_error: response.status_code >= 500,
                                local_response: false,
                                blocked: false,
                            },
                        );
                        write_http1_upstream_response(context, stream, &response).await?;
                    }
                    UpstreamResponseDisposition::Custom(response) => {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump_len,
                            true,
                        );
                        let status_code = write_custom_http1_response(
                            context,
                            &http1_handler,
                            stream,
                            &request,
                            &response,
                            true,
                            true,
                        )
                        .await?;
                        context.note_ai_route_result(
                            &request,
                            AiRouteResultObservation {
                                status_code,
                                latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                                upstream_error: false,
                                local_response: true,
                                blocked: status_code >= 400,
                            },
                        );
                    }
                    UpstreamResponseDisposition::Drop => {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump_len,
                            true,
                        );
                        context.note_ai_route_result(
                            &request,
                            AiRouteResultObservation {
                                status_code: 499,
                                latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                                upstream_error: false,
                                local_response: true,
                                blocked: true,
                            },
                        );
                        let _ = stream.shutdown().await;
                        return Ok(Http1RequestFlow::Close);
                    }
                }
            }
            Err(err) => {
                context.traffic_map.record_ingress(
                    traffic_source_ip.clone(),
                    request_dump_len,
                    false,
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(request);
                    metrics.record_proxy_failure_with_labels(proxy_traffic_kind(request), &labels);
                }
                context.set_upstream_health(false, Some(err.to_string()));
                warn!(
                    "Failed to proxy HTTP/1.1 request from {} to {}: {}",
                    peer_addr, upstream_addr, err
                );
                http1_handler
                    .write_response(stream, 502, "Bad Gateway", b"upstream proxy failed")
                    .await?;
                context.note_ai_route_result(
                    &request,
                    AiRouteResultObservation {
                        status_code: 502,
                        latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                        upstream_error: true,
                        local_response: false,
                        blocked: false,
                    },
                );
            }
        }
    } else if matched_site.is_some() {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
        http1_handler
            .write_response(stream, 502, "Bad Gateway", b"site upstream not configured")
            .await?;
    } else if should_reject_unmatched_site(context, request) {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
        if config.console_settings.drop_unmatched_requests {
            let _ = stream.shutdown().await;
            return Ok(Http1RequestFlow::Close);
        }
        http1_handler
            .write_response(stream, 404, "Not Found", b"site not found")
            .await?;
    } else {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
        let metrics = context.metrics_snapshot();
        let metrics_line = metrics
            .map(|snapshot| {
                format!(
                    "packets={},blocked={},blocked_l4={},blocked_l7={},bytes={}",
                    snapshot.total_packets,
                    snapshot.blocked_packets,
                    snapshot.blocked_l4,
                    snapshot.blocked_l7,
                    snapshot.total_bytes
                )
            })
            .unwrap_or_else(|| "metrics=disabled".to_string());

        let body = format!("allowed\n{}\n", metrics_line);
        http1_handler
            .write_response(stream, 200, "OK", body.as_bytes())
            .await?;
    }

    Ok(Http1RequestFlow::KeepAliveDecision)
}
