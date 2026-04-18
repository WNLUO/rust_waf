use super::*;

pub(super) fn runtime_defense_depth(request: &UnifiedHttpRequest) -> crate::core::DefenseDepth {
    request
        .get_metadata("runtime.defense.depth")
        .map(|value| crate::core::DefenseDepth::from_str(value))
        .unwrap_or(crate::core::DefenseDepth::Balanced)
}
pub(super) fn runtime_usize_metadata(
    request: &UnifiedHttpRequest,
    key: &str,
    default: usize,
) -> usize {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

pub(super) fn runtime_u64_metadata(request: &UnifiedHttpRequest, key: &str, default: u64) -> u64 {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}
