use super::*;

pub(super) fn record_l7_block_feedback(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &crate::core::InspectionResult,
) {
    crate::core::engine::policy::enforce_runtime_http_block_if_needed(
        context, packet, request, result,
    );
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_block(result.layer.clone());
        if matches!(result.layer, crate::core::InspectionLayer::L7) {
            metrics.record_l7_drop_reason(
                request.get_metadata("l7.drop_reason").map(String::as_str),
                &result.reason,
            );
        }
        if request
            .get_metadata("early_defense.action")
            .map(String::as_str)
            == Some("drop")
        {
            metrics.record_early_defense_drop(
                request
                    .get_metadata("early_defense.reason")
                    .map(String::as_str),
            );
        }
    }
    if should_sample_runtime_l7_feedback(request, result).is_some_and(|sample| !sample) {
        return;
    }
    if let Some(inspector) = context.l4_inspector() {
        inspector.record_l7_feedback(
            packet,
            request,
            crate::l4::behavior::FeedbackSource::L7Block,
        );
    }
}

pub(super) fn enforce_and_record_l7_block_feedback(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &crate::core::InspectionResult,
) {
    record_l7_block_feedback(context, packet, request, result);
}

fn should_sample_runtime_l7_feedback(
    request: &UnifiedHttpRequest,
    result: &crate::core::InspectionResult,
) -> Option<bool> {
    if result.persist_blocked_ip {
        return None;
    }
    if request
        .get_metadata("runtime.defense.depth")
        .map(String::as_str)
        != Some("survival")
    {
        return None;
    }
    static SURVIVAL_L7_FEEDBACK_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let sequence = SURVIVAL_L7_FEEDBACK_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(sequence.is_multiple_of(64))
}
