use super::*;

pub(super) fn record_l7_block_feedback(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &crate::core::InspectionResult,
) {
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_block(result.layer.clone());
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
    crate::core::engine::policy::enforce_runtime_http_block_if_needed(
        context, packet, request, result,
    );
    record_l7_block_feedback(context, packet, request, result);
}
