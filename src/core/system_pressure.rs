use std::fs;
use std::time::{Duration, Instant};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuPressureSnapshot {
    pub usage_percent: f64,
    pub score: u8,
    pub sample_available: bool,
}

#[derive(Debug)]
pub struct CpuPressureMonitor {
    cached: CpuPressureSnapshot,
    last_sample_at: Option<Instant>,
    last_cgroup_usage_micros: Option<u64>,
    quota_cores: f64,
}

impl CpuPressureMonitor {
    pub fn new() -> Self {
        Self {
            cached: CpuPressureSnapshot::default(),
            last_sample_at: None,
            last_cgroup_usage_micros: None,
            quota_cores: cgroup_v2_quota_cores().unwrap_or_else(detected_parallelism),
        }
    }

    pub fn snapshot(&mut self) -> CpuPressureSnapshot {
        let now = Instant::now();
        if self
            .last_sample_at
            .is_some_and(|last| now.duration_since(last) < SAMPLE_INTERVAL)
        {
            return self.cached;
        }

        let Some(current_usage) = cgroup_v2_cpu_usage_micros() else {
            self.last_sample_at = Some(now);
            self.cached = CpuPressureSnapshot {
                sample_available: false,
                ..self.cached
            };
            return self.cached;
        };

        let Some(last_usage) = self.last_cgroup_usage_micros else {
            self.last_sample_at = Some(now);
            self.last_cgroup_usage_micros = Some(current_usage);
            self.cached = CpuPressureSnapshot {
                usage_percent: 0.0,
                score: 0,
                sample_available: true,
            };
            return self.cached;
        };

        let elapsed_secs = self
            .last_sample_at
            .map(|last| now.duration_since(last).as_secs_f64())
            .unwrap_or(0.0)
            .max(0.001);
        let used_secs = current_usage.saturating_sub(last_usage) as f64 / 1_000_000.0;
        let quota_cores = self.quota_cores.max(1.0);
        let usage_percent = (used_secs / elapsed_secs / quota_cores * 100.0).clamp(0.0, 100.0);

        self.last_sample_at = Some(now);
        self.last_cgroup_usage_micros = Some(current_usage);
        self.cached = CpuPressureSnapshot {
            usage_percent,
            score: cpu_pressure_score(usage_percent),
            sample_available: true,
        };
        self.cached
    }
}

impl Default for CpuPressureMonitor {
    fn default() -> Self {
        Self::new()
    }
}

pub fn cpu_pressure_score(usage_percent: f64) -> u8 {
    if usage_percent >= 95.0 {
        3
    } else if usage_percent >= 85.0 {
        2
    } else if usage_percent >= 70.0 {
        1
    } else {
        0
    }
}

fn cgroup_v2_cpu_usage_micros() -> Option<u64> {
    let raw = fs::read_to_string("/sys/fs/cgroup/cpu.stat").ok()?;
    raw.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn cgroup_v2_quota_cores() -> Option<f64> {
    let raw = fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    let mut parts = raw.split_whitespace();
    let quota = parts.next()?;
    let period = parts.next()?.parse::<f64>().ok()?;
    if quota.eq_ignore_ascii_case("max") {
        return None;
    }
    let quota = quota.parse::<f64>().ok()?;
    if quota <= 0.0 || period <= 0.0 {
        return None;
    }
    Some((quota / period).max(1.0))
}

fn detected_parallelism() -> f64 {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1) as f64
}

#[cfg(test)]
mod tests {
    use super::cpu_pressure_score;

    #[test]
    fn cpu_pressure_score_uses_expected_thresholds() {
        assert_eq!(cpu_pressure_score(0.0), 0);
        assert_eq!(cpu_pressure_score(69.9), 0);
        assert_eq!(cpu_pressure_score(70.0), 1);
        assert_eq!(cpu_pressure_score(84.9), 1);
        assert_eq!(cpu_pressure_score(85.0), 2);
        assert_eq!(cpu_pressure_score(94.9), 2);
        assert_eq!(cpu_pressure_score(95.0), 3);
    }
}
