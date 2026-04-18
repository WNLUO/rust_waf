use super::*;

pub(super) fn result_should_drop_http2(
    result: &crate::core::InspectionResult,
    request: &UnifiedHttpRequest,
) -> bool {
    matches!(result.action, crate::core::InspectionAction::Drop)
        || request
            .get_metadata("l7.enforcement")
            .map(|value| value == "drop")
            .unwrap_or(false)
}

pub(super) fn drop_http2_result(reason: &str) -> crate::protocol::ProtocolError {
    crate::protocol::ProtocolError::ParseError(format!("HTTP/2 request dropped: {reason}"))
}
