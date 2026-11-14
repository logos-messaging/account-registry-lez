//! An account relay: publishes other accounts' signed logs to the registry and pays the fee, so an
//! account can be published before its owner holds any funds.
//!
//! Submissions arrive through a [`transport::Transport`]; the relay ships one, libp2p, as Logos
//! Core's `libp2p_module` sends them. Anyone can run a relay: a log authorizes its own write, so a
//! relay can only decline one, never forge or alter it.

pub mod auth;
pub mod ledger;
pub mod metrics;
pub mod p2p;
pub mod relay;
pub mod transport;
