use super::response::send_http3_response;
use super::*;

pub(super) async fn handle_http3_proxy_or_local_response(
    context: &WafContext,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    config: &Config,
    matched_site: Option<&GatewaySiteRuntime>,
    request: &UnifiedHttpRequest,
    traffic_source_ip: &str,
    request_dump_len: usize,
) -> Result<()> {
    let traffic_source_ip = traffic_source_ip.to_string();
    let upstream_addr = select_upstream_target(matched_site);
    context
        .traffic_map
        .record_ingress(traffic_source_ip.clone(), request_dump_len, false);
    if let Some(upstream_addr) = upstream_addr.as_deref() {
        let safeline_intercept = resolve_safeline_intercept_config(config, matched_site);
        if let Err(reason) = enforce_upstream_policy(context) {
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_fail_close_rejection();
            }
            send_http3_response(stream, 503, &[], reason.to_string().into_bytes(), None).await?;
            return Ok(());
        }
        if let Some(metrics) = context.metrics.as_ref() {
            let labels = proxy_metric_labels(request);
            metrics.record_proxy_attempt_with_labels(proxy_traffic_kind(request), &labels);
        }
        let proxy_started_at = Instant::now();
        if !safeline_intercept.enabled {
            match stream_http_request_to_http3_client(
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
                    context.traffic_map.record_egress(
                        traffic_source_ip.clone(),
                        response.body_bytes_sent,
                        proxy_started_at.elapsed(),
                    );
                    return Ok(());
                }
                Err(err) => {
                    if let Some(metrics) = context.metrics.as_ref() {
                        let labels = proxy_metric_labels(request);
                        metrics
                            .record_proxy_failure_with_labels(proxy_traffic_kind(request), &labels);
                    }
                    context.set_upstream_health(false, Some(err.to_string()));
                    warn!(
                        "Failed to stream HTTP/3 request from {} to {}: {}",
                        request.client_ip.as_deref().unwrap_or("unknown"),
                        upstream_addr,
                        err
                    );
                    send_http3_response(stream, 502, &[], b"upstream proxy failed".to_vec(), None)
                        .await?;
                    return Ok(());
                }
            }
        }
        match proxy_http_request(
            context,
            request,
            upstream_addr,
            config.l7_config.proxy_connect_timeout_ms,
            config.l7_config.proxy_write_timeout_ms,
            config.l7_config.proxy_read_timeout_ms,
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
                }
                context.traffic_map.record_egress(
                    traffic_source_ip.clone(),
                    response.body.len(),
                    proxy_started_at.elapsed(),
                );
                send_http3_response(
                    stream,
                    response.status_code,
                    &response.headers,
                    response.body,
                    None,
                )
                .await?;
                return Ok(());
            }
            Err(err) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(request);
                    metrics.record_proxy_failure_with_labels(proxy_traffic_kind(request), &labels);
                }
                context.set_upstream_health(false, Some(err.to_string()));
                warn!(
                    "Failed to proxy HTTP/3 request from {} to {}: {}",
                    request.client_ip.as_deref().unwrap_or("unknown"),
                    upstream_addr,
                    err
                );
                send_http3_response(stream, 502, &[], b"upstream proxy failed".to_vec(), None)
                    .await?;
                return Ok(());
            }
        }
    } else if matched_site.is_some() {
        send_http3_response(
            stream,
            502,
            &[],
            b"site upstream not configured".to_vec(),
            None,
        )
        .await?;
        return Ok(());
    } else if should_reject_unmatched_site(context, request) {
        if config.console_settings.drop_unmatched_requests {
            return Ok(());
        }
        send_http3_response(stream, 404, &[], b"site not found".to_vec(), None).await?;
        return Ok(());
    }

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

    send_http3_response(
        stream,
        200,
        &[],
        format!("allowed\n{}\n", metrics_line).into_bytes(),
        None,
    )
    .await?;
    Ok(())
}
