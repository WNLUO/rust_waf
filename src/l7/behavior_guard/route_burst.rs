use super::*;
use crate::locks::mutex_lock;

#[derive(Debug)]
pub(super) struct RouteBurstWindow {
    pub(super) samples: Mutex<VecDeque<RouteBurstSample>>,
    pub(super) last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
pub(super) struct RouteBurstSample {
    pub(super) client_ip: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) header_signature: Option<String>,
    pub(super) script_like: bool,
    pub(super) at: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct RouteBurstAssessment {
    pub(super) identity: String,
    pub(super) action: RouteBurstAction,
    pub(super) score: u32,
    pub(super) total: usize,
    pub(super) distinct_client_ips: usize,
    pub(super) distinct_user_agents: usize,
    pub(super) distinct_header_signatures: usize,
    pub(super) script_like_ratio_percent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteBurstAction {
    None,
    Challenge,
    Block,
}

impl RouteBurstAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Challenge => "aggregate_challenge",
            Self::Block => "aggregate_block",
        }
    }
}

impl RouteBurstAssessment {
    pub(super) fn rank(&self) -> u8 {
        match self.action {
            RouteBurstAction::Block => 2,
            RouteBurstAction::Challenge => 1,
            RouteBurstAction::None => 0,
        }
    }
}

impl RouteBurstWindow {
    pub(super) fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe_and_assess(
        &mut self,
        sample: RouteBurstSample,
        unix_now: i64,
    ) -> RouteBurstAssessment {
        let now = sample.at;
        let mut samples = mutex_lock(&self.samples, "route burst");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > Duration::from_secs(ROUTE_BURST_WINDOW_SECS)
                || samples.len() > MAX_BURST_SAMPLES_PER_ROUTE
            {
                samples.pop_front();
            } else {
                break;
            }
        }
        samples.push_back(sample);
        while samples.len() > MAX_BURST_SAMPLES_PER_ROUTE {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        assess_route_burst(&samples)
    }
}

fn assess_route_burst(samples: &VecDeque<RouteBurstSample>) -> RouteBurstAssessment {
    let total = samples.len();
    let distinct_client_ips = samples
        .iter()
        .filter_map(|sample| sample.client_ip.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_user_agents = samples
        .iter()
        .filter_map(|sample| sample.user_agent.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_header_signatures = samples
        .iter()
        .filter_map(|sample| sample.header_signature.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let script_like_count = samples.iter().filter(|sample| sample.script_like).count();
    let script_like_ratio_percent = if total == 0 {
        0
    } else {
        ((script_like_count * 100) / total) as u32
    };
    let scripted_or_mechanical = script_like_ratio_percent >= 70
        || (distinct_header_signatures <= 2 && distinct_user_agents <= 4);
    let action = if total >= ROUTE_BURST_BLOCK_TOTAL
        && distinct_client_ips >= ROUTE_BURST_BLOCK_DISTINCT_IPS
        && scripted_or_mechanical
    {
        RouteBurstAction::Block
    } else if total >= ROUTE_BURST_CHALLENGE_TOTAL
        && distinct_client_ips >= ROUTE_BURST_CHALLENGE_DISTINCT_IPS
        && scripted_or_mechanical
    {
        RouteBurstAction::Challenge
    } else {
        RouteBurstAction::None
    };
    let score = match action {
        RouteBurstAction::Block => 100,
        RouteBurstAction::Challenge => CHALLENGE_SCORE,
        RouteBurstAction::None => 0,
    };
    RouteBurstAssessment {
        identity: "route_burst".to_string(),
        action,
        score,
        total,
        distinct_client_ips,
        distinct_user_agents,
        distinct_header_signatures,
        script_like_ratio_percent,
    }
}
pub(super) fn route_burst_keys(
    request: &UnifiedHttpRequest,
    route: &str,
    kind: RequestKind,
) -> Vec<String> {
    let host = behavior_host(request);
    let mut keys = vec![format!(
        "site:{host}|route:{route}|kind:{}|burst",
        kind.as_str()
    )];
    if let Some(family) = route_family(&request.uri, route) {
        keys.push(format!(
            "site:{host}|family:{family}|kind:{}|burst",
            kind.as_str()
        ));
    }
    keys
}

pub(super) fn route_burst_exempt(route: &str) -> bool {
    let route = route.to_ascii_lowercase();
    route == "/robots.txt"
        || route == "/sitemap.xml"
        || route.starts_with("/sitemap")
        || route == "/favicon.ico"
        || route.starts_with("/.well-known/")
}
