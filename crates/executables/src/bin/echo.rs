//! `echo` binary: a terminal node whose `/faf` reply is the decrypted message itself, sealed back
//! to the sender like any reply. Useful to exercise the onion route end to end without a store.
//! Listens as configured by [`Listener::from_env`].

use ttk_ra_server::server::{BoxError, Listener, Server};
use ttk_ra_server::terminal::Terminal;
use ttk_ra_server::{EvalError, Evaluator};

/// [`Evaluator`] answering every message with the message unchanged.
pub struct Echo;

impl Evaluator for Echo {
    async fn eval(&self, message: Vec<u8>) -> Result<Vec<u8>, EvalError> {
        Ok(message)
    }
}

/// Starts logging and runs the terminal node with the [`Echo`] evaluator: attests, builds the
/// RA-TLS identity, then serves HTTP/3 until the endpoint closes.
#[tokio::main]
async fn main() -> Result<(), BoxError> {
    env_logger::init();
    Terminal::new(Server::listen(Listener::from_env()?)?, Echo)
        .serve()
        .await
}
