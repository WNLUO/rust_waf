use super::*;
use crate::locks::mutex_lock;

impl BehaviorWindow {
    pub(super) fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            challenge_hits: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    pub(super) fn observe_and_assess(
        &mut self,
        identity: String,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let mut samples = mutex_lock(&self.samples, "behavior window");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        samples.push_back(RequestSample {
            route: route.clone(),
            kind,
            client_ip,
            user_agent,
            header_signature,
            at: now,
        });
        while samples.len() > MAX_SAMPLES_PER_IDENTITY {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        let recent_challenges = self.recent_challenges(now, window);

        assess_samples(identity, &samples, now, recent_challenges)
    }

    pub(super) fn recent_challenges(&self, now: Instant, window: Duration) -> usize {
        let mut challenge_hits = mutex_lock(&self.challenge_hits, "behavior challenge");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.len()
    }

    pub(super) fn record_challenge(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = mutex_lock(&self.challenge_hits, "behavior challenge");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.push_back(now);
    }

    pub(super) fn record_block(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = mutex_lock(&self.challenge_hits, "behavior challenge");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.clear();
    }

    pub(super) fn snapshot(
        &self,
        identity: String,
        now: Instant,
        window: Duration,
    ) -> Option<BehaviorProfileSnapshot> {
        let mut samples = mutex_lock(&self.samples, "behavior window");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        if samples.is_empty() {
            return None;
        }
        let samples_snapshot = samples.iter().cloned().collect::<VecDeque<_>>();
        drop(samples);

        let assessment = assess_samples(
            identity.clone(),
            &samples_snapshot,
            now,
            self.recent_challenges(now, window),
        );
        let latest = samples_snapshot.back().cloned()?;
        Some(BehaviorProfileSnapshot {
            identity,
            source_ip: latest.client_ip,
            latest_seen_unix: self.last_seen_unix.load(Ordering::Relaxed),
            score: assessment.score,
            dominant_route: assessment.dominant_route,
            focused_document_route: assessment.focused_document_route,
            focused_api_route: assessment.focused_api_route,
            distinct_routes: assessment.distinct_routes,
            distinct_client_ips: assessment.distinct_client_ips,
            distinct_user_agents: assessment.distinct_user_agents,
            distinct_header_signatures: assessment.distinct_header_signatures,
            repeated_ratio_percent: assessment.repeated_ratio_percent,
            client_ip_repeated_ratio_percent: assessment.client_ip_repeated_ratio_percent,
            document_repeated_ratio_percent: assessment.document_repeated_ratio_percent,
            api_repeated_ratio_percent: assessment.api_repeated_ratio_percent,
            jitter_ms: assessment.jitter_ms,
            document_requests: assessment.document_requests,
            api_requests: assessment.api_requests,
            non_document_requests: assessment.non_document_requests,
            recent_challenges: assessment.recent_challenges,
            session_span_secs: assessment.session_span_secs,
            flags: assessment.flags.into_iter().map(str::to_string).collect(),
            latest_route: latest.route,
            latest_kind: latest.kind.as_str(),
        })
    }
}
