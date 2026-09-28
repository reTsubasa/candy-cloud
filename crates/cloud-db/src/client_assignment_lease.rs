//! Assignment-lease rules for terminal client node selection.
//!
//! A signed Client Grant names a node set and one `assignment_lease_until` for
//! all of them. The lease is what makes a node assignment *stable*: while it is
//! live Cloud must keep honouring the same node set, and only once it is over may
//! Cloud route the device somewhere else. Before this module the lease was only
//! ever written at signing time and never read back, so every refresh re-ran
//! selection and a healthy device could be bounced between equally valid nodes
//! for no reason.
//!
//! Everything here is pure: no database, no signing, no clock. The caller reads
//! the previous assignment and the currently active candidates, then asks this
//! module what to do. That keeps the one decision that matters -- "may I reuse the
//! assignment this device already holds?" -- testable without a live MySQL, and
//! keeps it in one place instead of spread across the issuance path.
//!
//! ## Boundary semantics
//!
//! The lease window is **half-open**: `[issued_at, assignment_lease_until)`. A
//! lease is live at `now` while `now < assignment_lease_until`, and it is *over*
//! the instant `now == assignment_lease_until`.
//!
//! This is not an arbitrary choice; it matches every other reader of the same
//! value in the frozen contracts:
//!
//! * `ClientGrantPayloadV1::validate` requires `assignment_lease_until > issued_at`
//!   (so the window is non-empty at signing time) and `<= expires_at`.
//! * The client/Core projection validator requires
//!   `node.assignment_lease_until > issued_at`, and the Core store's
//!   `has_live_node_lease_at(now)` asks `assignment_lease_until > now`.
//! * The projection assembler rejects a node whose lease is
//!   `<= issued_at`.
//!
//! All of those are "strictly greater than the current instant", i.e. the
//! endpoint belongs to the *next* window. Using `<=` here, or in the SQL that
//! feeds it, would let Cloud reuse an assignment for a window the client is
//! already obliged to stop using, so a device could be handed a Grant whose own
//! validator rejects it.

use uuid::Uuid;

use crate::client_routing::ClientNodeCandidate;

/// How close to the end of a lease Cloud starts calling it `Expiring`.
///
/// The state is observability, not a different decision: a live assignment is
/// reused whether it is `Live` or `Expiring` (see [`LeaseState::is_reusable`]).
/// What matters is that `Expiring` is *strictly* inside the window, so it can be
/// surfaced before the lease lapses rather than only afterwards.
pub const CLIENT_ASSIGNMENT_LEASE_REFRESH_MARGIN_SECS: u64 = 5 * 60;

/// Where one recorded assignment window stands relative to a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeaseState {
    /// More than the refresh margin of the window remains.
    Live,
    /// Still live, but within the refresh margin of `assignment_lease_until`.
    Expiring,
    /// The window is over: `now >= assignment_lease_until`.
    Expired,
}

impl LeaseState {
    /// Whether an assignment in this state may still be reused verbatim.
    ///
    /// `Expiring` is reusable on purpose. Cloud re-checks that every reused node
    /// is still an active candidate at this very instant, so reusing during the
    /// last minutes of a window cannot keep a node that left service -- and
    /// refusing to reuse there would reintroduce exactly the churn the lease
    /// exists to prevent.
    pub fn is_reusable(self) -> bool {
        matches!(self, Self::Live | Self::Expiring)
    }
}

/// Classifies `lease_until` at `now`.
///
/// The window is half-open, so `now == lease_until` is [`LeaseState::Expired`].
/// See the module docs for why that is the only self-consistent reading.
pub fn assignment_lease_state(now: u64, lease_until: u64) -> LeaseState {
    if now >= lease_until {
        return LeaseState::Expired;
    }
    // `now < lease_until` here, so the subtraction cannot underflow.
    if lease_until - now <= CLIENT_ASSIGNMENT_LEASE_REFRESH_MARGIN_SECS {
        LeaseState::Expiring
    } else {
        LeaseState::Live
    }
}

/// The lease instant a newly signed Grant must carry.
///
/// `issued_at + lease_secs`, clamped to `expires_at` because the frozen payload
/// validator rejects `assignment_lease_until > expires_at`. `None` when the
/// result would not be strictly after `issued_at`, which is the other half of the
/// same rule: a zero-width or inverted window is never signable.
pub fn assignment_lease_deadline(issued_at: u64, lease_secs: u64, expires_at: u64) -> Option<u64> {
    let deadline = issued_at.checked_add(lease_secs)?.min(expires_at);
    (deadline > issued_at).then_some(deadline)
}

/// A node identity from a previously signed assignment.
///
/// Deliberately *not* the wire `node_assignment` shape: the caller maps the
/// stored envelope into this minimal pair, so this module never needs to depend
/// on the wire contract (and therefore can never accidentally re-interpret it).
/// Only the two values that make the node a distinct transport identity are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedNode {
    pub node_id: Uuid,
    pub node_key_id: Uuid,
}

/// What Cloud should do about node selection for one issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentPlan {
    /// Reuse this node set, in this failover order, resolved against the nodes
    /// that are active *right now*.
    Reuse { nodes: Vec<ClientNodeCandidate> },
    /// Nothing was reusable. The caller runs normal selection.
    Reselect,
}

/// The assignment a device already holds, as read from its last Grant.
///
/// Owns its node list rather than borrowing one: the caller builds this from a
/// decoded envelope, and a borrowed view would tie the planner's lifetime to a
/// buffer the caller would then have to keep alive past the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousAssignment {
    /// The instant the stored envelope signs for. Taken from the *envelope*, not
    /// from the storage column: the column is a derived index (see migration
    /// `0047`) and the signature is the authority.
    pub lease_until: u64,
    /// Nodes in failover order, primary first.
    pub nodes: Vec<AssignedNode>,
}

/// Decides whether the assignment a device already holds may be reused.
///
/// Reuse is granted only when **all** of the following hold. Each condition is a
/// deliberate fail-closed choice; anything else falls back to fresh selection,
/// which is always safe (it re-reads Cloud's current view of the tenant).
///
/// 1. A previous assignment exists and its lease is not [`LeaseState::Expired`].
/// 2. It names at least one node.
/// 3. Every node it names is still an active candidate, matched on
///    `(node_id, node_key_id)`. A node that left service, that was removed from
///    its pool, or whose transport identity changed is *not* reusable, so a Grant
///    can never be signed naming a node Cloud is no longer offering. The fresh
///    candidate -- not the stored one -- supplies the endpoint, region, and
///    certificate, so a node that was repaired keeps working under the same
///    assignment.
/// 4. The stored order is a permutation of distinct nodes, so failover order is
///    unambiguous. The frozen envelope validator enforces this on everything
///    Cloud signs, but the planner does not take a blob's word for it.
///
/// The returned nodes are in the stored order, so priority 1 stays priority 1.
/// A surviving standby is never silently promoted: if the primary is gone the
/// whole assignment is re-selected, because choosing a new primary is a routing
/// decision, not a bookkeeping one.
pub fn plan_assignment(
    now: u64,
    previous: Option<&PreviousAssignment>,
    active: &[ClientNodeCandidate],
) -> AssignmentPlan {
    let Some(previous) = previous else {
        return AssignmentPlan::Reselect;
    };
    if !assignment_lease_state(now, previous.lease_until).is_reusable() {
        return AssignmentPlan::Reselect;
    }
    if previous.nodes.is_empty() {
        return AssignmentPlan::Reselect;
    }
    let mut reused = Vec::with_capacity(previous.nodes.len());
    let mut seen = std::collections::HashSet::with_capacity(previous.nodes.len());
    for assigned in &previous.nodes {
        if assigned.node_id.is_nil() || !seen.insert(assigned.node_id) {
            return AssignmentPlan::Reselect;
        }
        let Some(candidate) = active.iter().find(|candidate| {
            candidate.node_id == assigned.node_id && candidate.node_key_id == assigned.node_key_id
        }) else {
            return AssignmentPlan::Reselect;
        };
        reused.push(candidate.clone());
    }
    AssignmentPlan::Reuse { nodes: reused }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_900_000_000;

    fn candidate(node_id: u128, node_key_id: u128) -> ClientNodeCandidate {
        ClientNodeCandidate {
            node_id: Uuid::from_u128(node_id),
            node_key_id: Uuid::from_u128(node_key_id),
            endpoint_id: Uuid::from_u128(node_key_id + 100),
            endpoint: format!("edge-{node_id}.example.test:443"),
            region: "cn-east".into(),
            server_name: "edge.example.test".into(),
            server_cert_sha256: [7; 32],
        }
    }

    fn assigned(node_id: u128, node_key_id: u128) -> AssignedNode {
        AssignedNode {
            node_id: Uuid::from_u128(node_id),
            node_key_id: Uuid::from_u128(node_key_id),
        }
    }

    #[test]
    fn the_lease_is_over_exactly_at_its_deadline() {
        // The half-open reading is the whole point: at the deadline the client's
        // own validator already refuses the node (`assignment_lease_until >
        // issued_at`), so Cloud must not call it reusable.
        assert_eq!(assignment_lease_state(NOW, NOW + 1), LeaseState::Expiring);
        assert_eq!(assignment_lease_state(NOW, NOW), LeaseState::Expired);
        assert_eq!(assignment_lease_state(NOW + 1, NOW), LeaseState::Expired);
        assert_eq!(
            assignment_lease_state(NOW, NOW + CLIENT_ASSIGNMENT_LEASE_REFRESH_MARGIN_SECS + 1),
            LeaseState::Live
        );
    }

    #[test]
    fn the_expiring_band_ends_at_the_margin_and_starts_inside_the_window() {
        // Exactly at the margin the window is still live, so the band is closed
        // on the inside edge; one second further out it is plain `Live`.
        assert_eq!(
            assignment_lease_state(NOW, NOW + CLIENT_ASSIGNMENT_LEASE_REFRESH_MARGIN_SECS),
            LeaseState::Expiring
        );
        assert_eq!(
            assignment_lease_state(NOW, NOW + CLIENT_ASSIGNMENT_LEASE_REFRESH_MARGIN_SECS + 1),
            LeaseState::Live
        );
        // Only `Live` and `Expiring` may be reused; `Expired` never is.
        assert!(LeaseState::Live.is_reusable());
        assert!(LeaseState::Expiring.is_reusable());
        assert!(!LeaseState::Expired.is_reusable());
    }

    #[test]
    fn the_deadline_is_clamped_to_the_grant_and_never_zero_width() {
        assert_eq!(
            assignment_lease_deadline(NOW, 3_600, NOW + 86_400),
            Some(NOW + 3_600)
        );
        // A lease longer than the Grant is clamped, because the frozen validator
        // rejects `assignment_lease_until > expires_at`.
        assert_eq!(
            assignment_lease_deadline(NOW, 86_400, NOW + 60),
            Some(NOW + 60)
        );
        // A zero-width or inverted window is not signable at all.
        assert_eq!(assignment_lease_deadline(NOW, 0, NOW + 60), None);
        assert_eq!(assignment_lease_deadline(NOW, 60, NOW), None);
        assert_eq!(assignment_lease_deadline(NOW, 60, NOW - 1), None);
        assert_eq!(assignment_lease_deadline(u64::MAX, 1, u64::MAX), None);
    }

    fn previous(lease_until: u64, nodes: &[AssignedNode]) -> PreviousAssignment {
        PreviousAssignment {
            lease_until,
            nodes: nodes.to_vec(),
        }
    }

    #[test]
    fn a_live_lease_reuses_the_stored_order_against_fresh_candidates() {
        let active = vec![candidate(2, 22), candidate(1, 11), candidate(3, 33)];
        let stored = vec![assigned(1, 11), assigned(3, 33)];
        let plan = plan_assignment(NOW, Some(&previous(NOW + 3_600, &stored)), &active);
        let AssignmentPlan::Reuse { nodes } = plan else {
            panic!("a live assignment must be reused");
        };
        // Order is the stored failover order, not the candidate order.
        assert_eq!(
            nodes.iter().map(|node| node.node_id).collect::<Vec<_>>(),
            vec![Uuid::from_u128(1), Uuid::from_u128(3)]
        );
        // The node data itself comes from the *active* candidate, so a repaired
        // endpoint or rotated certificate is picked up on the next signature.
        assert_eq!(nodes[0].endpoint, active[1].endpoint);
        assert_eq!(nodes[1].endpoint, active[2].endpoint);
    }

    #[test]
    fn an_expired_or_absent_lease_reselects() {
        let active = vec![candidate(1, 11)];
        let stored = vec![assigned(1, 11)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW, &stored)), &active),
            AssignmentPlan::Reselect
        );
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW - 1, &stored)), &active),
            AssignmentPlan::Reselect
        );
        assert_eq!(
            plan_assignment(NOW, None, &active),
            AssignmentPlan::Reselect
        );
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &[])), &active),
            AssignmentPlan::Reselect
        );
    }

    #[test]
    fn a_node_that_left_service_is_never_reused() {
        // The stored primary is no longer offered, so the whole assignment is
        // re-selected rather than silently promoting the standby.
        let active = vec![candidate(2, 22), candidate(3, 33)];
        let stored = vec![assigned(1, 11), assigned(2, 22)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &stored)), &active),
            AssignmentPlan::Reselect
        );

        // Same node id, different transport key: the identity changed, so it is a
        // different node as far as the signature is concerned.
        let rotated = vec![candidate(1, 99)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &stored)), &rotated),
            AssignmentPlan::Reselect
        );

        // A missing standby is enough to reselect too: the failover list changed,
        // so Cloud re-runs the deterministic selection rather than trimming.
        let primary_only = vec![candidate(1, 11)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &stored)), &primary_only),
            AssignmentPlan::Reselect
        );
    }

    #[test]
    fn a_malformed_stored_order_is_refused_rather_than_trusted() {
        let active = vec![candidate(1, 11)];
        let duplicated = vec![assigned(1, 11), assigned(1, 11)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &duplicated)), &active),
            AssignmentPlan::Reselect
        );
        let nil = vec![assigned(0, 11)];
        assert_eq!(
            plan_assignment(NOW, Some(&previous(NOW + 3_600, &nil)), &active),
            AssignmentPlan::Reselect
        );
    }
}
