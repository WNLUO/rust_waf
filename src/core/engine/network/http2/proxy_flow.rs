use super::response::{build_custom_http2_response, build_plain_http2_response};
use super::*;

pub(super) async fn handle_http2_proxy_or_local_response(
    context: &WafContext,
    packet: &PacketInfo,
    config: &Config,
    matched_site: Option<&GatewaySiteRuntime>,
    request: &UnifiedHttpRequest,
    traffic_source_ip: &str,
    request_dump_len: usize,
) -> Result<Http2Response, crate::protocol::ProtocolError> {
    let traffic_source_ip = traffic_source_ip.to_string();
    if let Some(reason) = site_proxy_shed_reason(request) {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, true);
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_fail_close_rejection();
        }
        return Ok(build_plain_http2_response(503, reason.as_bytes().to_vec()));
    }
    let upstream_addr = select_upstream_target(matched_site);
    if let Some(upstream_addr) = upstream_addr.as_deref() {
        if let Err(reason) = enforce_upstream_policy(context) {
            context
                .traffic_map
                .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_fail_close_rejection();
            }
            return Ok(build_plain_http2_response(
                503,
                reason.to_string().into_bytes(),
            ));
        }
        if let Some(metrics) = context.metrics.as_ref() {
            let labels = proxy_metric_labels(&request);
            metrics.record_proxy_attempt_with_labels(proxy_traffic_kind(&request), &labels);
        }
        let proxy_started_at = Instant::now();
        match proxy_http_request(
            context,
            &request,
            upstream_addr,
            config.l7_config.proxy_connect_timeout_ms,
            config.l7_config.proxy_write_timeout_ms,
            config.l7_config.proxy_read_timeout_ms,
        )
        .await
        {
            Ok(response) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(&request);
                    metrics.record_proxy_success_with_labels(
                        proxy_traffic_kind(&request),
                        proxy_started_at.elapsed(),
                        &labels,
                    );
                }
                context.traffic_map.record_egress(
                    traffic_source_ip.clone(),
                    response.body.len(),
                    proxy_started_at.elapsed(),
                );
                return match apply_safeline_upstream_action(
                    context,
                    &packet,
                    &request,
                    matched_site,
                    resolve_safeline_intercept_config(&config, matched_site),
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
                        let mut headers = response.headers.clone();
                        apply_response_policies(context, &mut headers, response.status_code);
                        Ok(Http2Response {
                            status_code: response.status_code,
                            headers,
                            body: response.body,
                        })
                    }
                    UpstreamResponseDisposition::Custom(response) => {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump_len,
                            true,
                        );
                        let response =
                            build_custom_http2_response(context, request, &response, true);
                        context.note_ai_route_result(
                            request,
                            AiRouteResultObservation {
                                status_code: response.status_code,
                                latency_ms: Some(proxy_started_at.elapsed().as_millis() as u64),
                                upstream_error: false,
                                local_response: true,
                                blocked: response.status_code >= 400,
                            },
                        );
                        Ok(response)
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
                        Err(crate::protocol::ProtocolError::ParseError(
                            "SafeLine blocked upstream response dropped".to_string(),
                        ))
                    }
                };
            }
            Err(err) => {
                context.traffic_map.record_ingress(
                    traffic_source_ip.clone(),
                    request_dump_len,
                    false,
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(&request);
                    metrics.record_proxy_failure_with_labels(proxy_traffic_kind(&request), &labels);
                }
                context.set_upstream_health(false, Some(err.to_string()));
                warn!(
                    "Failed to proxy HTTP/2 request from {} to {}: {}",
                    request.client_ip.as_deref().unwrap_or("unknown"),
                    upstream_addr,
                    err
                );
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
                return Ok(build_plain_http2_response(
                    502,
                    b"upstream proxy failed".to_vec(),
                ));
            }
        }
    } else if matched_site.is_some() {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
        return Ok(build_plain_http2_response(
            502,
            b"site upstream not configured".to_vec(),
        ));
    } else if should_reject_unmatched_site(context, &request) {
        context
            .traffic_map
            .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
        if config.console_settings.drop_unmatched_requests {
            return Err(crate::protocol::ProtocolError::ParseError(
                "unmatched site dropped".to_string(),
            ));
        }
        return Ok(build_plain_http2_response(404, b"site not found".to_vec()));
    }

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

    Ok(build_plain_http2_response(
        200,
        format!("allowed\n{}\n", metrics_line).into_bytes(),
    ))
}
