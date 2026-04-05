use crate::config::L4Config;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use log::{info, debug};

pub struct ReputationScorer {
    config: L4Config,
    scores: HashMap<IpAddr, ScoreEntry>,
    total_scored: AtomicU64,
}

#[derive(Debug, Clone)]
struct ScoreEntry {
    score: i32,
    last_updated: std::time::Instant,
    reputation_history: Vec<i32>,
}

impl ReputationScorer {
    pub fn new(config: L4Config) -> Self {
        info!("Initializing Reputation Scorer");
        Self {
            config,
            scores: HashMap::new(),
            total_scored: AtomicU64::new(0),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Reputation Scorer started");
        Ok(())
    }

    pub fn get_score(&self, ip: &IpAddr) -> Option<i32> {
        self.scores.get(ip).map(|entry| entry.score)
    }

    pub fn update_score(&mut self, ip: IpAddr, delta: i32) {
        let entry = self.scores.entry(ip).or_insert_with(|| {
            self.total_scored.fetch_add(1, Ordering::Relaxed);
            ScoreEntry {
                score: 100, // Start with neutral score
                last_updated: std::time::Instant::now(),
                reputation_history: Vec::new(),
            }
        });

        entry.score = (entry.score + delta).max(0).min(100);
        entry.last_updated = std::time::Instant::now();

        debug!("Updated score for {}: {}", ip, entry.score);
    }

    pub fn penalize(&mut self, ip: IpAddr, severity: i32) {
        self.update_score(ip, -severity);
    }

    pub fn reward(&mut self, ip: IpAddr, amount: i32) {
        self.update_score(ip, amount);
    }
}
