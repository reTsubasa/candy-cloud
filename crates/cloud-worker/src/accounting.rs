use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct IdempotencyGuard { seen: HashSet<String> }

impl IdempotencyGuard {
    pub fn accept_once(&mut self, key: impl Into<String>) -> bool { self.seen.insert(key.into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_metering_event_is_ignored() {
        let mut guard = IdempotencyGuard::default();
        assert!(guard.accept_once("tenant/session/event-1"));
        assert!(!guard.accept_once("tenant/session/event-1"));
    }
}
