//! What the relay has paid for, kept on disk so limits survive a restart.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Sponsored writes per account address.
    writes: BTreeMap<String, u32>,
    /// When each sponsored write was sent, in seconds since the epoch, for the past day.
    sent: Vec<u64>,
    /// Credentials already used.
    nullifiers: BTreeSet<String>,
    /// Units spent on fees, in total.
    spent: u128,
}

/// The relay's spending record.
pub struct Ledger {
    path: Option<PathBuf>,
    state: State,
}

impl Ledger {
    /// The ledger in `dir`, created if it does not exist.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join("ledger.json");
        let state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: Some(path),
            state,
        })
    }

    /// A ledger kept in memory only.
    #[cfg(test)]
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: State::default(),
        }
    }

    #[must_use]
    pub fn writes(&self, addr: &str) -> u32 {
        self.state.writes.get(addr).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn used(&self, nullifier: &str) -> bool {
        self.state.nullifiers.contains(nullifier)
    }

    /// Sponsored writes sent in the hour and in the day before `now`.
    #[must_use]
    pub fn recent(&self, now: u64) -> (usize, usize) {
        let since = |window: u64| {
            self.state
                .sent
                .iter()
                .filter(|&&at| at + window > now)
                .count()
        };
        (since(HOUR), since(DAY))
    }

    #[must_use]
    pub const fn spent(&self) -> u128 {
        self.state.spent
    }

    /// Records a sponsored write sent at `now`, before it lands: a write that is sent pays even
    /// if it then fails.
    pub fn record(&mut self, addr: &str, nullifier: Option<&str>, now: u64) -> io::Result<()> {
        *self.state.writes.entry(addr.to_owned()).or_default() += 1;
        if let Some(nullifier) = nullifier {
            self.state.nullifiers.insert(nullifier.to_owned());
        }
        self.state.sent.retain(|&at| at + DAY > now);
        self.state.sent.push(now);
        self.save()
    }

    /// Adds `units` to what the relay has spent.
    pub fn spend(&mut self, units: u128) -> io::Result<()> {
        self.state.spent += units;
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let staged = path.with_extension("json.new");
        fs::write(&staged, serde_json::to_vec_pretty(&self.state)?)?;
        fs::rename(staged, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("relay-ledger-{}", std::process::id()));
        let mut ledger = Ledger::open(&dir).unwrap();
        ledger.record("aa", Some("token:x"), 1_000).unwrap();
        ledger.spend(26).unwrap();

        let ledger = Ledger::open(&dir).unwrap();
        assert_eq!(ledger.writes("aa"), 1);
        assert!(ledger.used("token:x"));
        assert_eq!(ledger.spent(), 26);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recent_writes_age_out() {
        let mut ledger = Ledger::in_memory();
        ledger.record("aa", None, 0).unwrap();
        ledger.record("bb", None, 2 * HOUR).unwrap();
        assert_eq!(ledger.recent(2 * HOUR), (1, 2));
        assert_eq!(ledger.recent(DAY + 1), (0, 1));
    }
}
