use super::system_profile::{detect_system_profile, SystemProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCapacityClass {
    Tiny,
    Small,
    Standard,
    Large,
}

impl RuntimeCapacityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Small => "small",
            Self::Standard => "standard",
            Self::Large => "large",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseDepth {
    Full,
    Balanced,
    Lean,
    Survival,
}

impl DefenseDepth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Balanced => "balanced",
            Self::Lean => "lean",
            Self::Survival => "survival",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "full" => Self::Full,
            "lean" => Self::Lean,
            "survival" => Self::Survival,
            _ => Self::Balanced,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeResourceBudget {
    pub capacity_class: RuntimeCapacityClass,
    pub defense_depth: DefenseDepth,
    pub l7_bucket_limit: usize,
    pub l7_page_window_limit: usize,
    pub behavior_bucket_limit: usize,
    pub behavior_sample_stride: u64,
    pub trusted_cdn_auto_learn_limit: usize,
    pub aggregate_events: bool,
    pub prefer_drop: bool,
}

impl RuntimeResourceBudget {
    pub fn from_system_and_pressure(
        system: &SystemProfile,
        pressure_level: &str,
        storage_queue_usage_percent: u64,
    ) -> Self {
        let capacity_class = classify_system(system);
        let defense_depth =
            defense_depth(capacity_class, pressure_level, storage_queue_usage_percent);
        let mut budget = match capacity_class {
            RuntimeCapacityClass::Tiny => Self {
                capacity_class,
                defense_depth,
                l7_bucket_limit: 8_192,
                l7_page_window_limit: 2_048,
                behavior_bucket_limit: 4_096,
                behavior_sample_stride: 2,
                trusted_cdn_auto_learn_limit: 64,
                aggregate_events: true,
                prefer_drop: true,
            },
            RuntimeCapacityClass::Small => Self {
                capacity_class,
                defense_depth,
                l7_bucket_limit: 16_384,
                l7_page_window_limit: 4_096,
                behavior_bucket_limit: 8_192,
                behavior_sample_stride: 1,
                trusted_cdn_auto_learn_limit: 128,
                aggregate_events: false,
                prefer_drop: false,
            },
            RuntimeCapacityClass::Standard => Self {
                capacity_class,
                defense_depth,
                l7_bucket_limit: 32_768,
                l7_page_window_limit: 12_288,
                behavior_bucket_limit: 16_384,
                behavior_sample_stride: 1,
                trusted_cdn_auto_learn_limit: 512,
                aggregate_events: false,
                prefer_drop: false,
            },
            RuntimeCapacityClass::Large => Self {
                capacity_class,
                defense_depth,
                l7_bucket_limit: 65_536,
                l7_page_window_limit: 32_768,
                behavior_bucket_limit: 32_768,
                behavior_sample_stride: 1,
                trusted_cdn_auto_learn_limit: 1024,
                aggregate_events: false,
                prefer_drop: false,
            },
        };

        match defense_depth {
            DefenseDepth::Full => {}
            DefenseDepth::Balanced => {
                budget.l7_bucket_limit = budget.l7_bucket_limit.min(32_768);
                budget.l7_page_window_limit = budget.l7_page_window_limit.min(12_288);
            }
            DefenseDepth::Lean => {
                budget.l7_bucket_limit = budget.l7_bucket_limit.min(8_192);
                budget.l7_page_window_limit = budget.l7_page_window_limit.min(2_048);
                budget.behavior_bucket_limit = budget.behavior_bucket_limit.min(4_096);
                budget.behavior_sample_stride = budget.behavior_sample_stride.max(2);
                budget.aggregate_events = true;
                budget.prefer_drop = true;
            }
            DefenseDepth::Survival => {
                budget.l7_bucket_limit = budget.l7_bucket_limit.min(2_048);
                budget.l7_page_window_limit = budget.l7_page_window_limit.min(512);
                budget.behavior_bucket_limit = budget.behavior_bucket_limit.min(1_024);
                budget.behavior_sample_stride = u64::MAX;
                budget.aggregate_events = true;
                budget.prefer_drop = true;
            }
        }

        budget
    }
}

pub fn current_runtime_resource_budget(
    pressure_level: &str,
    storage_queue_usage_percent: u64,
) -> RuntimeResourceBudget {
    RuntimeResourceBudget::from_system_and_pressure(
        &detect_system_profile(),
        pressure_level,
        storage_queue_usage_percent,
    )
}

fn classify_system(system: &SystemProfile) -> RuntimeCapacityClass {
    let memory_mb = system.memory_limit_bytes.map(|bytes| bytes / 1024 / 1024);
    let cpu = system.cpu_cores.max(1);
    match (cpu, memory_mb) {
        (1, Some(mem)) if mem <= 768 => RuntimeCapacityClass::Tiny,
        (_, Some(mem)) if mem <= 512 => RuntimeCapacityClass::Tiny,
        (1, _) => RuntimeCapacityClass::Small,
        (2, Some(mem)) if mem <= 2048 => RuntimeCapacityClass::Small,
        (_, Some(mem)) if mem <= 2048 => RuntimeCapacityClass::Small,
        (cpu, Some(mem)) if cpu >= 4 && mem >= 4096 => RuntimeCapacityClass::Large,
        (cpu, None) if cpu >= 4 => RuntimeCapacityClass::Large,
        _ => RuntimeCapacityClass::Standard,
    }
}

fn defense_depth(
    capacity_class: RuntimeCapacityClass,
    pressure_level: &str,
    storage_queue_usage_percent: u64,
) -> DefenseDepth {
    if pressure_level == "attack" || storage_queue_usage_percent >= 90 {
        return DefenseDepth::Survival;
    }
    if matches!(capacity_class, RuntimeCapacityClass::Tiny) && pressure_level != "normal" {
        return DefenseDepth::Survival;
    }
    if pressure_level == "high" || storage_queue_usage_percent >= 75 {
        return DefenseDepth::Lean;
    }
    if matches!(
        capacity_class,
        RuntimeCapacityClass::Tiny | RuntimeCapacityClass::Small
    ) || pressure_level == "elevated"
    {
        return DefenseDepth::Balanced;
    }
    DefenseDepth::Full
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(cpu: usize, memory_mb: Option<u64>) -> SystemProfile {
        SystemProfile {
            cpu_cores: cpu,
            memory_limit_bytes: memory_mb.map(|mb| mb * 1024 * 1024),
        }
    }

    #[test]
    fn tiny_system_starts_balanced_and_enters_survival_under_pressure() {
        let normal =
            RuntimeResourceBudget::from_system_and_pressure(&profile(1, Some(512)), "normal", 0);
        let elevated =
            RuntimeResourceBudget::from_system_and_pressure(&profile(1, Some(512)), "elevated", 0);

        assert_eq!(normal.capacity_class, RuntimeCapacityClass::Tiny);
        assert_eq!(normal.defense_depth, DefenseDepth::Balanced);
        assert_eq!(elevated.defense_depth, DefenseDepth::Survival);
        assert!(elevated.prefer_drop);
    }

    #[test]
    fn large_system_uses_full_until_runtime_pressure_rises() {
        let normal =
            RuntimeResourceBudget::from_system_and_pressure(&profile(8, Some(8192)), "normal", 0);
        let high =
            RuntimeResourceBudget::from_system_and_pressure(&profile(8, Some(8192)), "high", 0);

        assert_eq!(normal.capacity_class, RuntimeCapacityClass::Large);
        assert_eq!(normal.defense_depth, DefenseDepth::Full);
        assert_eq!(high.defense_depth, DefenseDepth::Lean);
        assert!(high.l7_bucket_limit < normal.l7_bucket_limit);
    }
}
