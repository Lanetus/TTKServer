//! Replay protection for `POST /faf` bodies at their last node.
//!
//! Every sealed body carries its send time and a random message id inside the encryption (see
//! [`crate::seal`]), which no hop can change. The last node accepts a body only if it was sent
//! within [`FAF_FRESHNESS_WINDOW`] (allowing [`FAF_MAX_CLOCK_SKEW`] into the future) and its id
//! has not been seen in that window, so a hop that saw a request (or the parent, which sees the
//! traffic) can't have it evaluated twice. Ids only need remembering for the window: older
//! bodies are refused by their send time.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::seal::MESSAGE_ID_LEN;

/// How long after being sealed a body is still accepted, in seconds.
pub const FAF_FRESHNESS_WINDOW: u64 = 120;

/// How far ahead of the last node's clock a body's send time may be, in seconds.
pub const FAF_MAX_CLOCK_SKEW: u64 = 30;

/// Most message ids remembered at once. When full of unexpired ids, new bodies are refused
/// ([`ReplayError::Busy`]) rather than letting replays through or growing without bound.
pub const MAX_REMEMBERED_MESSAGES: usize = 262_144;

/// Why a body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// Sent more than [`FAF_FRESHNESS_WINDOW`] ago, or more than [`FAF_MAX_CLOCK_SKEW`] ahead.
    Stale,
    /// Its message id was already accepted.
    Replayed,
    /// [`MAX_REMEMBERED_MESSAGES`] unexpired ids are already remembered.
    Busy,
}

/// Describes the refusal.
impl std::fmt::Display for ReplayError {
    /// Writes a short reason.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stale => "message is outside the freshness window",
            Self::Replayed => "message was already received",
            Self::Busy => "too many recent messages",
        })
    }
}

impl std::error::Error for ReplayError {}

/// The message ids accepted within the freshness window, with when each expires.
#[derive(Debug)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<[u8; MESSAGE_ID_LEN], u64>>,
    capacity: usize,
}

/// An empty guard remembering at most [`MAX_REMEMBERED_MESSAGES`] ids.
impl Default for ReplayGuard {
    /// Same as [`ReplayGuard::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Acceptance of bodies.
impl ReplayGuard {
    /// An empty guard remembering at most [`MAX_REMEMBERED_MESSAGES`] ids.
    pub fn new() -> Self {
        Self::with_capacity(MAX_REMEMBERED_MESSAGES)
    }

    /// An empty guard remembering at most `capacity` ids.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: Mutex::default(),
            capacity,
        }
    }

    /// Accepts the body `message_id` sent at `sent_at` if it is fresh at `now` (all Unix
    /// seconds) and new, remembering its id until it would be stale anyway.
    pub fn accept(
        &self,
        message_id: [u8; MESSAGE_ID_LEN],
        sent_at: u64,
        now: u64,
    ) -> Result<(), ReplayError> {
        if sent_at > now.saturating_add(FAF_MAX_CLOCK_SKEW)
            || sent_at.saturating_add(FAF_FRESHNESS_WINDOW) < now
        {
            return Err(ReplayError::Stale);
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains_key(&message_id) {
            return Err(ReplayError::Replayed);
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, expires| *expires >= now);
            if seen.len() >= self.capacity {
                return Err(ReplayError::Busy);
            }
        }
        seen.insert(message_id, sent_at.saturating_add(FAF_FRESHNESS_WINDOW));
        Ok(())
    }

    /// Number of ids currently remembered (expired ones included until the next cleanup).
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no id is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
