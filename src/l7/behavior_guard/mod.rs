use crate::core::{InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod aggregate;
mod assessment;
mod guard;
mod request_utils;
mod response;
mod route_burst;
mod runtime;
mod signals;
mod types;
mod window;

#[cfg(test)]
mod tests;

use aggregate::{
    aggregate_enforcement_key, assessment_allows_aggregate_enforcement, behavior_aggregate_keys,
    AggregateEnforcement, AggregateEnforcementAction,
};
use assessment::assess_samples;
pub use guard::L7BehaviorGuard;
use request_utils::{
    bounded_dashmap_key, compact_component, normalized_route_path, request_identity, request_kind,
    request_path, route_family, should_drop_delay_under_pressure, unix_timestamp,
};
use response::build_behavior_response;
use route_burst::{
    route_burst_exempt, route_burst_keys, RouteBurstAction, RouteBurstAssessment, RouteBurstSample,
    RouteBurstWindow,
};
use runtime::{runtime_defense_depth, runtime_u64_metadata, runtime_usize_metadata};
use signals::{
    behavior_header_signature, behavior_host, behavior_user_agent, request_is_script_like_document,
    select_behavior_assessment,
};
use types::{BehaviorAssessment, BehaviorWindow, RequestKind, RequestSample};

pub use types::BehaviorProfileSnapshot;

const BEHAVIOR_WINDOW_SECS: u64 = 300;
const ACTIVE_PROFILE_IDLE_SECS: i64 = 60;
const MAX_SAMPLES_PER_IDENTITY: usize = 96;
const CLEANUP_EVERY_REQUESTS: u64 = 512;
const CHALLENGE_SCORE: u32 = 60;
const BLOCK_SCORE: u32 = 90;
const DELAY_SCORE: u32 = 35;
const DELAY_MS: u64 = 250;
pub const AUTO_BLOCK_DURATION_SECS: u64 = 15 * 60;
const CHALLENGES_BEFORE_AUTO_BLOCK: usize = 2;
const MAX_BEHAVIOR_BUCKETS: usize = 32_768;
const MAX_BEHAVIOR_KEY_LEN: usize = 160;
const MAX_BEHAVIOR_ROUTE_LEN: usize = 160;
const OVERFLOW_SHARDS: u64 = 64;
const AGGREGATE_CHALLENGE_ENFORCEMENT_SECS: u64 = 30;
const AGGREGATE_BLOCK_ENFORCEMENT_SECS: u64 = 90;
const ROUTE_BURST_WINDOW_SECS: u64 = 3;
const ROUTE_BURST_CHALLENGE_TOTAL: usize = 6;
const ROUTE_BURST_CHALLENGE_DISTINCT_IPS: usize = 4;
const ROUTE_BURST_BLOCK_TOTAL: usize = 10;
const ROUTE_BURST_BLOCK_DISTINCT_IPS: usize = 8;
const MAX_BURST_SAMPLES_PER_ROUTE: usize = 64;
