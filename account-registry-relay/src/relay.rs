//! The relay's one worker: checks each submission for free, then pays for the ones that pass.
//!
//! Everything a refused transaction would pay for is checked before sending: the log's
//! signature, that it extends the log on chain, the registry's size limit, the relay's own
//! limits and its balance. Submissions are checked one at a time and answered at once. The writes
//! that pass go out one at a time, each once the previous one has landed, so two never race for
//! the same account or the payer's nonce.

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use account_log::{AccountAddr, SignedAccountLog};
use account_registry_client::{
    AccountId, LezAccountRegError, PUBLISH_TIMEOUT, PreparedAppend, Registry,
    relay::{RelayReply, RelayRequest},
};

use crate::{auth::Auth, ledger::Ledger, metrics::Metrics};

/// What the relay is willing to pay for.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Sponsored appends per existing account in any 24 hours. A new account's first log is not
    /// counted; 0 sponsors new accounts only.
    pub max_appends_per_day: usize,
    /// The largest log payload sponsored, in bytes.
    pub max_log_bytes: usize,
    /// Sponsored writes in any hour, across all accounts.
    pub max_per_hour: usize,
    /// Sponsored writes in any 24 hours, across all accounts.
    pub max_per_day: usize,
    /// Below this payer balance, refuse everything: a write must be able to reserve its fee.
    pub min_balance: u128,
}

/// A submission, and where to answer it.
pub struct Submission {
    pub request: RelayRequest,
    pub reply: Sender<RelayReply>,
    /// The transport it came over, for logs and metrics.
    pub source: &'static str,
}

/// Why a submission was refused, as reported in metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Credentials,
    CredentialsUsed,
    Invalid,
    InProgress,
    TooLarge,
    AccountLimit,
    RelayLimit,
    AlreadyPublished,
    Rejected,
    Unavailable,
    OutOfFunds,
    Busy,
    Stopping,
}

impl Reason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::CredentialsUsed => "credentials_used",
            Self::Invalid => "invalid",
            Self::InProgress => "in_progress",
            Self::TooLarge => "too_large",
            Self::AccountLimit => "account_limit",
            Self::RelayLimit => "relay_limit",
            Self::AlreadyPublished => "already_published",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::OutOfFunds => "out_of_funds",
            Self::Busy => "busy",
            Self::Stopping => "stopping",
        }
    }
}

/// A refused submission: why, and what to tell the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    pub message: String,
}

impl Refusal {
    #[must_use]
    pub fn new(reason: Reason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn reply(&self) -> RelayReply {
        RelayReply {
            accepted: false,
            reason: Some(self.message.clone()),
        }
    }
}

/// How many submissions may wait for the worker; past that, they are refused as busy.
pub const QUEUE: usize = 64;

/// How often to look for the write in flight on chain.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How often to refresh the payer's balance while idle.
const BALANCE_INTERVAL: Duration = Duration::from_secs(60);

/// Hands `request`, received over `source`, to the worker and returns its verdict, or a refusal
/// if the relay is busy or stopping and never saw it.
pub fn ask(
    jobs: &SyncSender<Submission>,
    metrics: &Metrics,
    request: RelayRequest,
    source: &'static str,
) -> RelayReply {
    let (reply, answer) = mpsc::channel();
    let submission = Submission {
        request,
        reply,
        source,
    };
    let refusal = match jobs.try_send(submission) {
        Ok(()) => match answer.recv() {
            Ok(reply) => return reply,
            Err(_) => Refusal::new(Reason::Stopping, "the relay is stopping"),
        },
        Err(TrySendError::Full(_)) => Refusal::new(Reason::Busy, "the relay is busy; try later"),
        Err(TrySendError::Disconnected(_)) => {
            Refusal::new(Reason::Stopping, "the relay is stopping")
        }
    };
    metrics.refused(source, refusal.reason);
    refusal.reply()
}

/// A submission that passed every check.
struct Approved {
    addr: AccountAddr,
    log: SignedAccountLog,
    nullifier: Option<String>,
    /// Whether the account already has a log on chain.
    append: bool,
    source: &'static str,
}

/// The write sent and not yet landed.
struct InFlight {
    addr: AccountAddr,
    append: bool,
    source: &'static str,
    prepared: PreparedAppend,
    /// The payer's balance before sending.
    before: u128,
    sent: Instant,
}

pub struct Relay {
    registry: Registry,
    payer: AccountId,
    auth: Auth,
    policy: Policy,
    ledger: Ledger,
    metrics: Arc<Metrics>,
    approved: VecDeque<Approved>,
    in_flight: Option<InFlight>,
    next_poll: Instant,
}

impl Relay {
    #[must_use]
    pub fn new(
        registry: Registry,
        payer: AccountId,
        auth: Auth,
        policy: Policy,
        ledger: Ledger,
        metrics: Arc<Metrics>,
    ) -> Self {
        let relay = Self {
            registry,
            payer,
            auth,
            policy,
            ledger,
            metrics,
            approved: VecDeque::new(),
            in_flight: None,
            next_poll: Instant::now(),
        };
        relay.refresh();
        relay
    }

    /// Handles submissions until every sender is gone and every approved write is settled.
    pub fn run(&mut self, jobs: &Receiver<Submission>) {
        let mut open = true;
        while open || self.busy() {
            let wait = if self.busy() {
                POLL_INTERVAL
            } else {
                BALANCE_INTERVAL
            };
            let submission = if open {
                match jobs.recv_timeout(wait) {
                    Ok(submission) => Some(submission),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => {
                        open = false;
                        None
                    }
                }
            } else {
                thread::sleep(POLL_INTERVAL);
                None
            };
            match submission {
                Some(submission) => self.handle(submission),
                None if !self.busy() => self.refresh(),
                None => {}
            }
            self.advance();
        }
    }

    fn busy(&self) -> bool {
        self.in_flight.is_some() || !self.approved.is_empty()
    }

    /// Brings the balance and recent-write gauges up to date.
    fn refresh(&self) {
        if let Ok(balance) = self.registry.balance(self.payer) {
            self.metrics.set_balance(balance);
        }
        self.count();
    }

    /// Brings the gauges that need no sequencer up to date.
    fn count(&self) {
        let (hour, day) = self.ledger.recent(now());
        self.metrics.last_hour.set(gauge(hour));
        self.metrics.last_day.set(gauge(day));
        self.metrics.queued.set(gauge(self.approved.len()));
        self.metrics
            .in_flight
            .set(i64::from(self.in_flight.is_some()));
    }

    /// Settles the write in flight once it lands or fails, then sends the next approved one.
    fn advance(&mut self) {
        if let Some(flight) = &self.in_flight {
            if Instant::now() < self.next_poll {
                return;
            }
            self.next_poll = Instant::now() + POLL_INTERVAL;
            let outcome = self
                .registry
                .fetch(&flight.addr)
                .and_then(|stored| flight.prepared.landed(stored.as_ref()));
            let failure = match outcome {
                Ok(true) => None,
                Err(LezAccountRegError::Conflict) => Some(LezAccountRegError::Conflict),
                _ if flight.sent.elapsed() < PUBLISH_TIMEOUT => return,
                _ => Some(LezAccountRegError::Timeout),
            };
            let flight = self.in_flight.take().expect("a write is in flight");
            let cost = self.settle(flight.before);
            let (addr, source) = (&flight.addr, flight.source);
            match failure {
                None => {
                    let seconds = flight.sent.elapsed().as_secs_f64();
                    self.metrics.written(flight.append, Some(seconds), cost);
                    eprintln!("published {addr} (from {source}), cost {cost}");
                }
                Some(error) => {
                    self.metrics.written(flight.append, None, cost);
                    eprintln!("failed {addr} (from {source}): {error}");
                }
            }
        }
        while self.in_flight.is_none()
            && let Some(approved) = self.approved.pop_front()
        {
            let (addr, source, append) = (approved.addr.clone(), approved.source, approved.append);
            match self.send(approved) {
                Ok(flight) => {
                    self.next_poll = Instant::now() + POLL_INTERVAL;
                    self.in_flight = Some(flight);
                }
                Err(error) => {
                    self.metrics.written(append, None, 0);
                    eprintln!("failed {addr} (from {source}): {error}");
                }
            }
        }
        self.count();
    }

    fn handle(&mut self, submission: Submission) {
        let addr = submission.request.addr.clone();
        let source = submission.source;
        match self.check(&submission.request, source) {
            Ok(approved) => {
                let _gone = submission.reply.send(RelayReply {
                    accepted: true,
                    reason: None,
                });
                self.metrics.accepted(source);
                self.approved.push_back(approved);
            }
            Err(refusal) => {
                let _gone = submission.reply.send(refusal.reply());
                self.metrics.refused(source, refusal.reason);
                eprintln!("refused {addr} (from {source}): {}", refusal.message);
            }
        }
    }

    /// Checks `request` against everything that would make the write fail or the relay
    /// unwilling, without spending anything. The checks that need no sequencer come first.
    fn check(&self, request: &RelayRequest, source: &'static str) -> Result<Approved, Refusal> {
        let nullifier = self
            .auth
            .verify(request)
            .map_err(|message| Refusal::new(Reason::Credentials, message))?;
        if let Some(used) = nullifier.as_deref()
            && (self.ledger.used(used)
                || self
                    .approved
                    .iter()
                    .any(|approved| approved.nullifier.as_deref() == Some(used)))
        {
            return Err(Refusal::new(
                Reason::CredentialsUsed,
                "these credentials were already used",
            ));
        }

        let (addr, log) = request
            .decode()
            .map_err(|error| Refusal::new(Reason::Invalid, error.to_string()))?;
        if self
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.addr == addr)
            || self.approved.iter().any(|approved| approved.addr == addr)
        {
            return Err(Refusal::new(
                Reason::InProgress,
                "a write for this account is on its way; wait for it",
            ));
        }
        if log.payload.as_bytes().len() > self.policy.max_log_bytes {
            return Err(Refusal::new(
                Reason::TooLarge,
                format!(
                    "the relay sponsors logs up to {} bytes",
                    self.policy.max_log_bytes
                ),
            ));
        }
        let appends = self.ledger.appends_today(&addr.to_string(), now());
        if appends > 0 && appends >= self.policy.max_appends_per_day {
            return Err(self.account_limit());
        }
        let (hour, day) = self.ledger.recent(now());
        let waiting = self.approved.len();
        if hour + waiting >= self.policy.max_per_hour || day + waiting >= self.policy.max_per_day {
            return Err(Refusal::new(
                Reason::RelayLimit,
                "the relay is at its limit; try later, or pay yourself",
            ));
        }

        let stored = self.registry.fetch(&addr).map_err(unavailable)?;
        if stored.as_ref() == Some(&log) {
            return Err(Refusal::new(Reason::AlreadyPublished, "already published"));
        }
        let append = stored.is_some();
        if append && appends >= self.policy.max_appends_per_day {
            return Err(self.account_limit());
        }
        self.registry
            .prepare_append(&addr, &log)
            .map_err(|error| match error {
                LezAccountRegError::Transport(_)
                | LezAccountRegError::Rpc { .. }
                | LezAccountRegError::Response(_) => unavailable(error),
                error => Refusal::new(Reason::Rejected, error.to_string()),
            })?;

        let balance = self.registry.balance(self.payer).map_err(unavailable)?;
        self.metrics.set_balance(balance);
        if balance < self.policy.min_balance {
            return Err(Refusal::new(
                Reason::OutOfFunds,
                "the relay is out of funds; pay yourself",
            ));
        }

        Ok(Approved {
            addr,
            log,
            nullifier,
            append,
            source,
        })
    }

    fn account_limit(&self) -> Refusal {
        let message = match self.policy.max_appends_per_day {
            0 => "the relay sponsors new accounts only; pay yourself".to_owned(),
            max => format!(
                "the relay sponsors {max} updates a day to an existing account; try later, or pay \
                 yourself"
            ),
        };
        Refusal::new(Reason::AccountLimit, message)
    }

    /// Sends `approved`, recording it first: a write that is sent pays even if it then fails.
    fn send(&mut self, approved: Approved) -> Result<InFlight, LezAccountRegError> {
        let before = self.registry.balance(self.payer)?;
        let prepared = self
            .registry
            .prepare_append(&approved.addr, &approved.log)?;
        let key = approved.addr.to_string();
        self.ledger
            .record(
                approved.append.then_some(key.as_str()),
                approved.nullifier.as_deref(),
                now(),
            )
            .map_err(|error| LezAccountRegError::Relay(error.to_string()))?;
        if let Err(error) = self.registry.send_append(&prepared) {
            self.settle(before);
            return Err(error);
        }
        Ok(InFlight {
            addr: approved.addr,
            append: approved.append,
            source: approved.source,
            prepared,
            before,
            sent: Instant::now(),
        })
    }

    /// Adds what the payer spent since its balance was `before` to the ledger, and returns it.
    fn settle(&mut self, before: u128) -> u128 {
        let after = self.registry.balance(self.payer).unwrap_or(before);
        self.metrics.set_balance(after);
        let cost = before.saturating_sub(after);
        if let Err(error) = self.ledger.spend(cost) {
            eprintln!("ledger: {error}");
        }
        cost
    }

    /// Sends `approved` and waits for it to land, returning what it cost.
    #[cfg(test)]
    fn publish(&mut self, approved: Approved) -> Result<u128, LezAccountRegError> {
        let flight = self.send(approved)?;
        let landed = self
            .registry
            .await_append(&flight.prepared, PUBLISH_TIMEOUT);
        let cost = self.settle(flight.before);
        landed.map(|()| cost)
    }
}

fn unavailable(error: LezAccountRegError) -> Refusal {
    Refusal::new(
        Reason::Unavailable,
        format!("the relay cannot reach the chain: {error}"),
    )
}

fn gauge(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
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
            max_appends_per_day: 2,
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
        let metrics = Arc::new(Metrics::new(Vec::new()));
        Relay::new(
            registry,
            payer_id,
            auth,
            policy,
            Ledger::in_memory(),
            metrics,
        )
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
        let approved = relay
            .check(request, "test")
            .map_err(|refusal| refusal.message)?;
        relay.publish(approved).map_err(|error| error.to_string())
    }

    fn refusal(relay: &Relay, request: &RelayRequest) -> Refusal {
        relay
            .check(request, "test")
            .err()
            .expect("the relay refuses")
    }

    #[test]
    #[ignore = "needs a running sequencer and a deployed registry"]
    fn sponsors_new_accounts_within_its_limits() {
        let mut relay = relay(Auth::new(vec![Box::new(Open)]), policy());

        let first = new_account("Saro", RelayAuth::default());
        assert!(sponsor(&mut relay, &first).unwrap() > 0);
        assert_eq!(refusal(&relay, &first).reason, Reason::AlreadyPublished);

        let second = new_account("Ana", RelayAuth::default());
        assert!(sponsor(&mut relay, &second).is_ok());
        let third = new_account("Ben", RelayAuth::default());
        assert_eq!(refusal(&relay, &third).reason, Reason::RelayLimit);

        let mut forged = new_account("Eve", RelayAuth::default());
        forged.addr = new_account("Joe", RelayAuth::default()).addr;
        assert_eq!(refusal(&relay, &forged).reason, Reason::Invalid);
    }

    /// The log `key` signs after appending `name` to `draft`.
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
        assert!(sponsor(&mut relay, &grow(&key, &mut draft, "Saro Ma.")).is_ok());
        let third = grow(&key, &mut draft, "Saro Marr");
        let limited = refusal(&relay, &third);
        assert_eq!(limited.reason, Reason::AccountLimit);
        assert!(limited.message.contains("2 updates a day"));

        let fresh = Policy {
            max_appends_per_day: 0,
            ..policy()
        };
        let relay = self::relay(Auth::new(vec![Box::new(Open)]), fresh);
        assert!(
            refusal(&relay, &third)
                .message
                .contains("new accounts only")
        );
        assert!(
            relay
                .check(&new_account("Ana", RelayAuth::default()), "test")
                .is_ok()
        );
    }

    #[test]
    #[ignore = "needs a running sequencer and a deployed registry"]
    fn refuses_what_it_cannot_or_will_not_pay_for() {
        let broke = Policy {
            min_balance: u128::MAX,
            ..policy()
        };
        let request = new_account("Saro", RelayAuth::default());
        let relay_broke = relay(Auth::new(vec![Box::new(Open)]), broke);
        assert_eq!(refusal(&relay_broke, &request).reason, Reason::OutOfFunds);

        let tight = Policy {
            max_log_bytes: 8,
            ..policy()
        };
        let relay_tight = relay(Auth::new(vec![Box::new(Open)]), tight);
        let too_large = refusal(&relay_tight, &request);
        assert_eq!(too_large.reason, Reason::TooLarge);
        assert!(too_large.message.contains("up to 8 bytes"));

        let gated = relay(
            Auth::new(vec![Box::new(SharedToken("s3cret".into()))]),
            policy(),
        );
        assert_eq!(refusal(&gated, &request).reason, Reason::Credentials);
        let wrong = RelayAuth {
            kind: "token".into(),
            payload: "guess".into(),
        };
        assert_eq!(
            refusal(&gated, &new_account("Ana", wrong)).reason,
            Reason::Credentials
        );
        let right = RelayAuth {
            kind: "token".into(),
            payload: "s3cret".into(),
        };
        assert!(gated.check(&new_account("Ben", right), "test").is_ok());
    }
}
