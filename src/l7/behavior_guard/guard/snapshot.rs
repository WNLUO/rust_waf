use super::*;

impl L7BehaviorGuard {
    pub fn snapshot_profiles(&self, limit: usize) -> Vec<BehaviorProfileSnapshot> {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let mut profiles = self
            .buckets
            .iter()
            .filter_map(|entry| {
                let last_seen_unix = entry.value().last_seen_unix.load(Ordering::Relaxed);
                if unix_now.saturating_sub(last_seen_unix) > ACTIVE_PROFILE_IDLE_SECS {
                    return None;
                }
                entry.value().snapshot(entry.key().clone(), now, window)
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.latest_seen_unix.cmp(&left.latest_seen_unix))
        });
        if limit > 0 && profiles.len() > limit {
            profiles.truncate(limit);
        }
        profiles
    }
}
