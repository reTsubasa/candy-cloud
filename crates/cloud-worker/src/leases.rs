use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub name: String,
    pub owner_id: String,
    pub lease_until: DateTime<Utc>,
}

pub fn can_acquire(current: Option<&Lease>, owner_id: &str, now: DateTime<Utc>) -> bool {
    current.is_none_or(|lease| lease.lease_until <= now || lease.owner_id == owner_id)
}

pub fn renew(name: impl Into<String>, owner_id: impl Into<String>, now: DateTime<Utc>, ttl: Duration) -> Lease {
    Lease { name: name.into(), owner_id: owner_id.into(), lease_until: now + ttl }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_or_same_owner_can_acquire() {
        let now = Utc::now();
        let expired = renew("grant-refresh", "a", now - Duration::minutes(2), Duration::minutes(1));
        let active = renew("grant-refresh", "a", now, Duration::minutes(1));
        assert!(can_acquire(Some(&expired), "b", now));
        assert!(can_acquire(Some(&active), "a", now));
        assert!(!can_acquire(Some(&active), "b", now));
    }
}
