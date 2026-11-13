//! The relay's one worker: checks each submission for free, then pays for the ones that pass.
//!
//! Everything a refused transaction would pay for is checked before sending: the log's
//! signature, that it extends the log on chain, the registry's size limit, the relay's own
//! limits and its balance. Submissions are handled one at a time, so two never race for the same
//! account or the payer's nonce.

use std::{
    sync::mpsc::{Receiver, Sender},
    time::{SystemTime, UNIX_EPOCH},
};

use account_log::{AccountAddr, SignedAccountLog};
use account_registry_client::{
    AccountId, LezAccountRegError, Registry,
    relay::{RelayReply, RelayRequest},
};

use crate::{auth::Auth, ledger::Ledger};

/// What the relay is willing to pay for.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Sponsored writes per account in any 24 hours, appends included.
    pub max_per_account_per_day: usize,
    /// Sponsor only accounts with nothing published yet.
    pub new_accounts_only: bool,
    /// The largest log payload sponsored, in bytes.
    pub max_log_bytes: usize,
    pub max_per_hour: usize,
    pub max_per_day: usize,
    /// Below this payer balance, refuse everything: a write must be able to reserve its fee.
    pub min_balance: u128,
}

/// Work for the relay's worker.
pub enum Job {
    Submit(Submission),
    /// Answer with the relay's state.
    Status(Sender<serde_json::Value>),
}

/// A submission, and where to answer it if the sender waits.
pub struct Submission {
    pub request: RelayRequest,
    pub reply: Option<Sender<RelayReply>>,
    /// Where it came from, for the log.
    pub source: &'static str,
}

/// A submission that passed every check.
struct Approved {
    addr: AccountAddr,
    log: SignedAccountLog,
    nullifier: Option<String>,
}

pub struct Relay {
    registry: Registry,
    payer: AccountId,
    auth: Auth,
    policy: Policy,
    ledger: Ledger,
}

impl Relay {
    #[must_use]
    pub const fn new(
        registry: Registry,
        payer: AccountId,
        auth: Auth,
        policy: Policy,
        ledger: Ledger,
    ) -> Self {
        Self {
            registry,
            payer,
            auth,
            policy,
            ledger,
        }
    }

    /// Handles jobs until every sender is gone.
    pub fn run(&mut self, jobs: &Receiver<Job>) {
        for job in jobs {
            match job {
                Job::Submit(submission) => self.handle(submission),
                Job::Status(reply) => {
                    let _gone = reply.send(self.status());
                }
            }
        }
    }

    fn handle(&mut self, submission: Submission) {
        let addr = submission.request.addr.clone();
        let checked = self.check(&submission.request);
        if let Some(reply) = submission.reply {
            let answer = match &checked {
                Ok(_) => RelayReply {
                    accepted: true,
                    reason: None,
                },
                Err(reason) => RelayReply {
                    accepted: false,
                    reason: Some(reason.clone()),
                },
            };
            let _gone = reply.send(answer);
        }
        match checked {
            Ok(approved) => match self.publish(&approved) {
                Ok(cost) => eprintln!("published {addr} (from {}), cost {cost}", submission.source),
                Err(error) => eprintln!("failed {addr} (from {}): {error}", submission.source),
            },
            Err(reason) => eprintln!("refused {addr} (from {}): {reason}", submission.source),
        }
    }

    /// Checks `request` against everything that would make the write fail or the relay
    /// unwilling, without spending anything.
    fn check(&self, request: &RelayRequest) -> Result<Approved, String> {
        let nullifier = self.auth.verify(request)?;
        if nullifier.as_deref().is_some_and(|n| self.ledger.used(n)) {
            return Err("these credentials were already used".into());
        }

        let (addr, log) = request.decode().map_err(|error| error.to_string())?;
        if log.payload.as_bytes().len() > self.policy.max_log_bytes {
            return Err(format!(
                "the relay sponsors logs up to {} bytes",
                self.policy.max_log_bytes
            ));
        }
        let stored = self
            .registry
            .fetch(&addr)
            .map_err(|error| error.to_string())?;
        if stored.as_ref() == Some(&log) {
            return Err("already published".into());
        }
        if self.ledger.writes_today(&addr.to_string(), now()) >= self.policy.max_per_account_per_day
        {
            return Err(format!(
                "the relay sponsors {} updates a day per account; try later, or pay yourself",
                self.policy.max_per_account_per_day
            ));
        }
        if stored.is_some() && self.policy.new_accounts_only {
            return Err("the relay sponsors new accounts only".into());
        }
        self.registry
            .prepare_append(&addr, &log)
            .map_err(|error| error.to_string())?;

        let (hour, day) = self.ledger.recent(now());
        if hour >= self.policy.max_per_hour || day >= self.policy.max_per_day {
            return Err("the relay is at its limit; try later, or pay yourself".into());
        }
        let balance = self
            .registry
            .balance(self.payer)
            .map_err(|error| error.to_string())?;
        if balance < self.policy.min_balance {
            return Err("the relay is out of funds; pay yourself".into());
        }

        Ok(Approved {
            addr,
            log,
            nullifier,
        })
    }

    /// Publishes `approved`, recording it before sending, and returns what it cost.
    fn publish(&mut self, approved: &Approved) -> Result<u128, LezAccountRegError> {
        let before = self.registry.balance(self.payer)?;
        let key = approved.addr.to_string();
        self.ledger
            .record(&key, approved.nullifier.as_deref(), now())
            .map_err(|error| LezAccountRegError::Relay(error.to_string()))?;
        let published = self.registry.publish(&approved.addr, &approved.log);
        let cost = before.saturating_sub(self.registry.balance(self.payer)?);
        self.ledger
            .spend(cost)
            .map_err(|error| LezAccountRegError::Relay(error.to_string()))?;
        published.map(|()| cost)
    }

    /// The relay's state, for `GET /v1/status`.
    #[must_use]
    pub fn status(&self) -> serde_json::Value {
        let (hour, day) = self.ledger.recent(now());
        serde_json::json!({
            "program": self.registry.program().to_string(),
            "payer": self.payer.to_string(),
            "balance": self.registry.balance(self.payer).ok().map(|b| b.to_string()),
            "auth": self.auth.kinds(),
            "sponsoredLastHour": hour,
            "sponsoredLastDay": day,
            "spent": self.ledger.spent().to_string(),
            "limits": {
                "maxPerAccountPerDay": self.policy.max_per_account_per_day,
                "newAccountsOnly": self.policy.new_accounts_only,
                "maxLogBytes": self.policy.max_log_bytes,
                "maxPerHour": self.policy.max_per_hour,
                "maxPerDay": self.policy.max_per_day,
            },
        })
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    //! Against a running sequencer with the registry deployed: `./run-local-sequencer`, then
    //! `account-registry deploy`, then this with `ACCOUNT_REGISTRY_PROGRAM` set and
    //! `--test-threads=1`: every test pays from the same payer, whose nonce they would share.

    use account_log::{AccountLogDraft, Context, Ed25519SigningKey, EntryData};
    use account_registry_client::{
        PrivateKey,
        relay::{RelayAuth, RelayRequest},
        sign,
    };

    use super::*;
    use crate::auth::{Open, SharedToken};

    const LOCAL_PAYER_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn policy() -> Policy {
        Policy {
            max_per_account_per_day: 2,
            new_accounts_only: false,
            max_log_bytes: 4096,
            max_per_hour: 2,
            max_per_day: 10,
            min_balance: 70_000_000,
        }
    }

    fn relay(auth: Auth, policy: Policy) -> Relay {
        let url = std::env::var("SEQUENCER_URL").unwrap_or("http://localhost:3040".into());
        let program: AccountId = std::env::var("ACCOUNT_REGISTRY_PROGRAM")
            .expect("ACCOUNT_REGISTRY_PROGRAM")
            .parse()
            .unwrap();
        let payer: PrivateKey = LOCAL_PAYER_KEY.parse().unwrap();
        let payer_id = account_registry_client::signer_id(&payer);
        let registry = Registry::connect(&url, program).unwrap().with_payer(payer);
        Relay::new(registry, payer_id, auth, policy, Ledger::in_memory())
    }

    fn new_account(name: &str, auth: RelayAuth) -> RelayRequest {
        let key = Ed25519SigningKey::generate();
        let mut draft = AccountLogDraft::new();
        let data = EntryData::Text(name.into());
        draft
            .add(Context::literal("profile.displayname"), data)
            .unwrap();
        let log = sign(&key, draft.log()).unwrap();
        RelayRequest::new(&AccountAddr::from(key.verifying_key()), &log, auth)
    }

    fn sponsor(relay: &mut Relay, request: &RelayRequest) -> Result<u128, String> {
        let approved = relay.check(request)?;
        relay.publish(&approved).map_err(|error| error.to_string())
    }

    #[test]
    #[ignore = "needs a running sequencer and a deployed registry"]
    fn sponsors_new_accounts_within_its_limits() {
        let mut relay = relay(Auth::new(vec![Box::new(Open)]), policy());

        let first = new_account("Saro", RelayAuth::default());
        assert!(sponsor(&mut relay, &first).unwrap() > 0);
        assert_eq!(relay.check(&first).err().unwrap(), "already published");

        let second = new_account("Ana", RelayAuth::default());
        assert!(sponsor(&mut relay, &second).is_ok());
        let third = new_account("Ben", RelayAuth::default());
        assert!(relay.check(&third).err().unwrap().contains("at its limit"));

        let mut forged = new_account("Eve", RelayAuth::default());
        forged.addr = new_account("Joe", RelayAuth::default()).addr;
        assert!(relay.check(&forged).is_err());
    }

    /// The log `key` signs after appending `names` to `draft`.
    fn grow(key: &Ed25519SigningKey, draft: &mut AccountLogDraft, name: &str) -> RelayRequest {
        let data = EntryData::Text(name.into());
        draft
            .add(Context::literal("profile.displayname"), data)
            .unwrap();
        let log = sign(key, draft.log()).unwrap();
        RelayRequest::new(
            &AccountAddr::from(key.verifying_key()),
            &log,
            RelayAuth::default(),
        )
    }

    #[test]
    #[ignore = "needs a running sequencer and a deployed registry"]
    fn sponsors_appends_up_to_its_daily_limit_per_account() {
        let roomy = Policy {
            max_per_hour: 10,
            ..policy()
        };
        let mut relay = relay(Auth::new(vec![Box::new(Open)]), roomy);
        let key = Ed25519SigningKey::generate();
        let mut draft = AccountLogDraft::new();

        assert!(sponsor(&mut relay, &grow(&key, &mut draft, "Saro")).is_ok());
        assert!(sponsor(&mut relay, &grow(&key, &mut draft, "Saro M.")).is_ok());
        let third = grow(&key, &mut draft, "Saro Marr");
        assert!(
            relay
                .check(&third)
                .err()
                .unwrap()
                .contains("2 updates a day")
        );

        let fresh = Policy {
            new_accounts_only: true,
            ..policy()
        };
        let relay = self::relay(Auth::new(vec![Box::new(Open)]), fresh);
        assert!(
            relay
                .check(&third)
                .err()
                .unwrap()
                .contains("new accounts only")
        );
    }

    #[test]
    #[ignore = "needs a running sequencer and a deployed registry"]
    fn refuses_what_it_cannot_or_will_not_pay_for() {
        let broke = Policy {
            min_balance: u128::MAX,
            ..policy()
        };
        let relay_broke = relay(Auth::new(vec![Box::new(Open)]), broke);
        let request = new_account("Saro", RelayAuth::default());
        assert!(
            relay_broke
                .check(&request)
                .err()
                .unwrap()
                .contains("out of funds")
        );

        let tight = Policy {
            max_log_bytes: 8,
            ..policy()
        };
        let relay_tight = relay(Auth::new(vec![Box::new(Open)]), tight);
        assert!(
            relay_tight
                .check(&request)
                .err()
                .unwrap()
                .contains("up to 8 bytes")
        );

        let gated = relay(
            Auth::new(vec![Box::new(SharedToken("s3cret".into()))]),
            policy(),
        );
        assert!(gated.check(&request).is_err());
        let wrong = RelayAuth {
            kind: "token".into(),
            payload: "guess".into(),
        };
        assert!(gated.check(&new_account("Ana", wrong)).is_err());
        let right = RelayAuth {
            kind: "token".into(),
            payload: "s3cret".into(),
        };
        assert!(gated.check(&new_account("Ben", right)).is_ok());
    }
}
