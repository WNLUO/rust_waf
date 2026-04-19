#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceSentinelDefenseMemoryEntry {
    pub attack_type: String,
    pub preferred_action: String,
    pub effective_score: i64,
    pub ineffective_score: i64,
    pub weak_score: i64,
    pub harmful_score: i64,
    pub last_outcome: String,
    pub last_rejection_delta: i64,
    pub last_score_delta: i64,
    pub last_seen_ms: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceSentinelAttackSessionEntry {
    pub id: i64,
    pub session_id: i64,
    pub phase: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub duration_ms: i64,
    pub peak_severity: String,
    pub peak_attack_score: i64,
    pub primary_pressure: String,
    pub final_outcome: String,
    pub summary: String,
    pub report_json: Option<String>,
    pub updated_at: i64,
}
