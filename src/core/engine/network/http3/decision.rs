use super::*;

pub(super) fn result_should_drop_http3(
    result: &crate::core::InspectionResult,
    request: &UnifiedHttpRequest,
) -> bool {
    matches!(result.action, crate::core::InspectionAction::Drop)
        || request
            .get_metadata("l7.enforcement")
            .map(|value| value == "drop")
            .unwrap_or(false)
}
