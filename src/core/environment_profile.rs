use std::fs;

use super::system_profile::{detect_system_profile, SystemProfile};

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct EnvironmentProfile {
    pub system: SystemProfile,
    pub memory_limit_mb: u64,
    pub cpu_cores: usize,
    pub fd_soft_limit: Option<u64>,
    pub containerized: bool,
}

impl EnvironmentProfile {
    pub fn detect() -> Self {
        let system = detect_system_profile();
        let memory_limit_mb = system
            .memory_limit_bytes
            .map(|value| value / 1024 / 1024)
            .unwrap_or(2048)
            .max(128);
        let cpu_cores = system.cpu_cores.max(1);

        Self {
            system,
            memory_limit_mb,
            cpu_cores,
            fd_soft_limit: detect_fd_soft_limit(),
            containerized: is_containerized(),
        }
    }
}

fn detect_fd_soft_limit() -> Option<u64> {
    let raw = fs::read_to_string("/proc/self/limits").ok()?;
    raw.lines().skip(1).find_map(|line| {
        if !line.starts_with("Max open files") {
            return None;
        }
        let mut parts = line.split_whitespace();
        let _ = parts.next()?;
        let _ = parts.next()?;
        let _ = parts.next()?;
        parts.next()?.parse::<u64>().ok()
    })
}

fn is_containerized() -> bool {
    fs::metadata("/.dockerenv").is_ok()
        || fs::read_to_string("/proc/1/cgroup")
            .ok()
            .is_some_and(|raw| raw.contains("docker") || raw.contains("kubepods"))
}
