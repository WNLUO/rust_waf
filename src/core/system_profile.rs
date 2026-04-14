use std::fs;

#[derive(Debug, Clone)]
pub struct SystemProfile {
    pub cpu_cores: usize,
    pub memory_limit_bytes: Option<u64>,
}

pub fn detect_system_profile() -> SystemProfile {
    let cpu_cores = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1);

    let memory_limit_bytes = read_cgroup_memory_limit().or_else(read_proc_mem_total);

    SystemProfile {
        cpu_cores,
        memory_limit_bytes,
    }
}

fn read_cgroup_memory_limit() -> Option<u64> {
    read_cgroup_v2_memory_max().or_else(read_cgroup_v1_memory_limit)
}

fn read_cgroup_v2_memory_max() -> Option<u64> {
    let raw = fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    parse_memory_limit(raw.trim())
}

fn read_cgroup_v1_memory_limit() -> Option<u64> {
    let raw = fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes").ok()?;
    parse_memory_limit(raw.trim())
}

fn parse_memory_limit(value: &str) -> Option<u64> {
    if value.is_empty() || value.eq_ignore_ascii_case("max") {
        return None;
    }

    let parsed = value.parse::<u64>().ok()?;
    if parsed >= (1u64 << 60) {
        None
    } else {
        Some(parsed)
    }
}

fn read_proc_mem_total() -> Option<u64> {
    let raw = fs::read_to_string("/proc/meminfo").ok()?;
    let line = raw.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kb = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())?;
    Some(kb.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::parse_memory_limit;

    #[test]
    fn parse_memory_limit_ignores_max_and_large_values() {
        assert_eq!(parse_memory_limit("max"), None);
        assert_eq!(parse_memory_limit(""), None);
        assert_eq!(parse_memory_limit("1152921504606846976"), None);
    }

    #[test]
    fn parse_memory_limit_parses_normal_number() {
        assert_eq!(parse_memory_limit("536870912"), Some(536_870_912));
    }
}
