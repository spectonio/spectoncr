//! Per-tenant LLM token spend cap (design 019 P4).

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SpendCap {
    pub tokens_per_day: u64,
}

impl Default for SpendCap {
    fn default() -> Self {
        Self {
            tokens_per_day: 200_000,
        }
    }
}

#[derive(Debug, Default)]
struct DayBucket {
    day: String,
    used: u64,
}

#[derive(Default)]
pub struct BudgetTracker {
    inner: Mutex<HashMap<String, DayBucket>>,
    cap: SpendCap,
}

impl BudgetTracker {
    pub fn new(cap: SpendCap) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            cap,
        }
    }

    fn today() -> String {
        Utc::now().format("%Y-%m-%d").to_string()
    }

    pub fn check_and_add(&self, tenant: &str, tokens: u64) -> Result<u64, String> {
        let mut guard = self.inner.lock().unwrap();
        let today = Self::today();
        let bucket = guard.entry(tenant.to_string()).or_insert(DayBucket {
            day: today.clone(),
            used: 0,
        });
        if bucket.day != today {
            bucket.day = today;
            bucket.used = 0;
        }
        if bucket.used.saturating_add(tokens) > self.cap.tokens_per_day {
            return Err(format!(
                "tenant {tenant} exceeded daily token budget ({} / {})",
                bucket.used, self.cap.tokens_per_day
            ));
        }
        bucket.used += tokens;
        Ok(bucket.used)
    }

    pub fn used_today(&self, tenant: &str) -> u64 {
        let guard = self.inner.lock().unwrap();
        let today = Self::today();
        guard
            .get(tenant)
            .filter(|b| b.day == today)
            .map(|b| b.used)
            .unwrap_or(0)
    }

    pub fn reset_at(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_cap() {
        let t = BudgetTracker::new(SpendCap {
            tokens_per_day: 100,
        });
        assert!(t.check_and_add("acme", 60).is_ok());
        assert!(t.check_and_add("acme", 50).is_err());
        assert_eq!(t.used_today("acme"), 60);
    }
}
