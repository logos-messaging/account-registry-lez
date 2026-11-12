//! What `deploy` reports as it goes, on stderr: each transaction's hash, how long it waited for a
//! block, and what it cost the payer.

use std::{
    io::{IsTerminal, Write},
    thread,
    time::{Duration, Instant},
};

use account_registry_client::{AccountId, LezAccountRegError, Registry};

use crate::Error;

/// How often to look for a submitted transaction's effect.
const WAIT_INTERVAL: Duration = Duration::from_secs(2);

pub struct Progress<'registry> {
    registry: &'registry Registry,
    payer: AccountId,
    timeout: Duration,
    steps: usize,
    step: usize,
    sent: usize,
    started: Instant,
    opening_balance: u128,
}

impl<'registry> Progress<'registry> {
    /// Starts reporting a run of `steps` transactions paid by `payer`, each given `timeout` to
    /// land.
    pub fn new(
        registry: &'registry Registry,
        payer: AccountId,
        timeout: Duration,
        steps: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            registry,
            payer,
            timeout,
            steps,
            step: 0,
            sent: 0,
            started: Instant::now(),
            opening_balance: registry.balance(payer)?,
        })
    }

    /// Reports a step whose effect is already on chain.
    pub fn skip(&mut self, what: &str) {
        self.step += 1;
        eprintln!(
            "[{}/{}] {what}: already on chain, skipped",
            self.step, self.steps
        );
    }

    /// Sends one transaction with `send`, which returns its hash, and waits until `landed`
    /// reports its effect.
    pub fn submit(
        &mut self,
        what: &str,
        send: impl FnOnce() -> Result<String, LezAccountRegError>,
        mut landed: impl FnMut() -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.step += 1;
        eprintln!("[{}/{}] {what}", self.step, self.steps);
        let balance = self.registry.balance(self.payer)?;
        let height = self.registry.last_block()?;
        let tx = send()?;
        eprintln!("      tx {tx}");

        let sent = Instant::now();
        let live = std::io::stderr().is_terminal();
        loop {
            if landed()? {
                break;
            }
            let waited = sent.elapsed();
            if waited >= self.timeout {
                clear_line(live);
                return Err(self.not_landed(what, tx, waited, height));
            }
            if live {
                eprint!("\r      waiting for a block... {}", clock(waited));
                let _ = std::io::stderr().flush();
            }
            thread::sleep(WAIT_INTERVAL.min(self.timeout.saturating_sub(waited)));
        }
        clear_line(live);

        let cost = balance.saturating_sub(self.registry.balance(self.payer)?);
        let block = self
            .registry
            .transaction_block(&tx)?
            .map_or_else(String::new, |block| format!("in block {block} "));
        eprintln!(
            "      landed {block}after {}, cost {}",
            clock(sent.elapsed()),
            units(cost)
        );
        self.sent += 1;
        Ok(())
    }

    /// Reports the whole run.
    pub fn finish(&self) -> Result<(), Error> {
        let balance = self.registry.balance(self.payer)?;
        eprintln!(
            "Done: {} sent, {} skipped, {}, cost {}, balance {}",
            self.sent,
            self.steps - self.sent,
            clock(self.started.elapsed()),
            units(self.opening_balance.saturating_sub(balance)),
            units(balance)
        );
        Ok(())
    }

    fn not_landed(&self, what: &str, tx: String, waited: Duration, from: u64) -> Error {
        let what = what.to_owned();
        match self.registry.transaction_block(&tx) {
            Ok(Some(block)) => Error::Refused { what, tx, block },
            _ => Error::NotIncluded {
                what,
                tx,
                waited: clock(waited),
                from,
                to: self.registry.last_block().unwrap_or(from),
                done: self.step - 1,
                steps: self.steps,
            },
        }
    }
}

fn clear_line(live: bool) {
    if live {
        eprint!("\r{:60}\r", "");
    }
}

/// A duration as `42s` or `1m05s`.
pub fn clock(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    }
}

/// An amount in the zone's smallest unit, with thousands separators.
pub fn units(amount: u128) -> String {
    let digits = amount.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_and_durations_read_at_a_glance() {
        assert_eq!(units(0), "0");
        assert_eq!(units(999), "999");
        assert_eq!(units(1_000), "1,000");
        assert_eq!(units(142_684_648), "142,684,648");
        assert_eq!(clock(Duration::from_secs(42)), "42s");
        assert_eq!(clock(Duration::from_secs(65)), "1m05s");
    }
}
