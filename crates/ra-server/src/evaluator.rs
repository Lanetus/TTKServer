//! What a node does with a delivered message: the [`Evaluator`] trait and its [`EvalError`].
//!
//! The server itself evaluates nothing; nodes built on it (the terminal, with its file service)
//! turn the decrypted `/faf` message into their reply through an [`Evaluator`].

use std::future::Future;

/// Error of an [`Evaluator`] (or the storage behind it): unlike
/// [`BoxError`](crate::server::BoxError), `Send + Sync`, so it can be held across `.await` in
/// their `Send` futures.
pub type EvalError = Box<dyn std::error::Error + Send + Sync>;

/// What a node does with a delivered message: turns the decrypted message into the reply, which
/// the node then seals to the sender.
///
/// An error answers `500` without detail, so relays learn nothing about the message.
pub trait Evaluator: Send + Sync + 'static {
    /// Evaluates the decrypted `message` into the (plaintext) reply.
    fn eval(&self, message: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, EvalError>> + Send;
}
