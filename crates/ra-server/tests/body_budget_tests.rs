//! Tests for the shared request body budget ([`ttk_ra_server::server::BodyBudget`]).

use ttk_ra_server::server::BodyBudget;

#[test]
fn reservations_grow_until_the_budget_is_exhausted() {
    let budget = BodyBudget::new(100);
    let mut first = budget.reservation();
    assert!(first.is_empty());
    assert!(first.grow(60));
    assert!(first.grow(20));
    assert_eq!(first.len(), 80);
    assert_eq!(budget.available(), 20);

    let mut second = budget.reservation();
    assert!(!second.grow(30), "only 20 bytes are left");
    assert!(second.is_empty(), "a refused grow reserves nothing");
    assert!(second.grow(20));
    assert_eq!(budget.available(), 0);
}

#[test]
fn dropping_a_reservation_returns_its_bytes() {
    let budget = BodyBudget::new(100);
    let mut reservation = budget.reservation();
    assert!(reservation.grow(100));
    assert_eq!(budget.available(), 0);
    drop(reservation);
    assert_eq!(budget.available(), 100);
}

#[test]
fn oversized_requests_are_refused() {
    let budget = BodyBudget::new(usize::MAX >> 4);
    assert!(!budget.reservation().grow(u32::MAX as usize + 1));
}
