//! Tests of the `/faf` replay protection (`ttk_core::replay`).

use ttk_core::replay::{ReplayError, ReplayGuard, FAF_FRESHNESS_WINDOW, FAF_MAX_CLOCK_SKEW};

const NOW: u64 = 1_800_000_000;

#[test]
fn a_fresh_body_is_accepted_once() {
    let guard = ReplayGuard::new();
    assert_eq!(guard.accept([1; 16], NOW, NOW), Ok(()));
    assert_eq!(guard.accept([1; 16], NOW, NOW), Err(ReplayError::Replayed));
    assert_eq!(guard.accept([2; 16], NOW, NOW + 1), Ok(()));
    assert_eq!(guard.len(), 2);
}

#[test]
fn bodies_outside_the_freshness_window_are_stale() {
    let guard = ReplayGuard::new();
    let oldest = NOW - FAF_FRESHNESS_WINDOW;
    assert_eq!(guard.accept([1; 16], oldest, NOW), Ok(()));
    assert_eq!(
        guard.accept([2; 16], oldest - 1, NOW),
        Err(ReplayError::Stale)
    );
    let latest = NOW + FAF_MAX_CLOCK_SKEW;
    assert_eq!(guard.accept([3; 16], latest, NOW), Ok(()));
    assert_eq!(
        guard.accept([4; 16], latest + 1, NOW),
        Err(ReplayError::Stale)
    );
    assert_eq!(guard.accept([5; 16], 0, NOW), Err(ReplayError::Stale));
    assert_eq!(
        guard.accept([6; 16], u64::MAX, NOW),
        Err(ReplayError::Stale)
    );
}

#[test]
fn a_full_guard_refuses_until_ids_expire() {
    let guard = ReplayGuard::with_capacity(2);
    assert_eq!(guard.accept([1; 16], NOW, NOW), Ok(()));
    assert_eq!(guard.accept([2; 16], NOW + 10, NOW + 10), Ok(()));
    assert_eq!(
        guard.accept([3; 16], NOW + 10, NOW + 10),
        Err(ReplayError::Busy)
    );

    // Once the first id is stale, it is forgotten to make room; the second is still remembered.
    let later = NOW + FAF_FRESHNESS_WINDOW + 1;
    assert_eq!(guard.accept([3; 16], later, later), Ok(()));
    assert_eq!(
        guard.accept([2; 16], NOW + 10, later),
        Err(ReplayError::Replayed)
    );
    assert_eq!(guard.len(), 2);
}
