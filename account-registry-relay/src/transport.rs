//! How submissions reach the relay. A transport hands each submission it receives to the worker
//! with [`ask`](crate::relay::ask) and answers with the worker's verdict. The relay ships one,
//! [`P2p`](crate::p2p::P2p); another way in implements [`Transport`].

use std::sync::mpsc::SyncSender;

use crate::relay::Submission;

/// A way for submissions to reach the relay.
pub trait Transport: Send {
    /// A short name, for logs and metrics.
    fn name(&self) -> &'static str;

    /// Takes submissions and hands each to `jobs`, until it fails or the worker is gone.
    fn serve(self: Box<Self>, jobs: SyncSender<Submission>) -> Result<(), String>;
}
