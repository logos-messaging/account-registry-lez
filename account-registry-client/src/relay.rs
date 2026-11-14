//! What a client sends an account relay: a signed log for the relay to publish to the registry,
//! paying the fee itself.
//!
//! The log authorizes its own write, so a relay can neither forge nor alter one, only decline it.
//! A client therefore sends and forgets, then waits for the log on chain with
//! [`Registry::await_append`](crate::Registry::await_append), and falls back to paying itself if
//! it does not appear.
//!
//! A submission reaches a relay over libp2p, on `/logos/accounts/relay/1.0.0` as one
//! varint-framed message; `account-registry-relay` has the transport.

use account_log::{AccountAddr, SignedAccountLog};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::LezAccountRegError;

/// The submission format's version.
pub const RELAY_REQUEST_VERSION: u8 = 1;

/// One submission: the log the client wants published under `addr`, and its credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRequest {
    pub version: u8,
    /// The account's address, as its 64-character hex.
    pub addr: String,
    /// `SignedAccountLog::to_bytes()`, in standard base64.
    pub log: String,
    #[serde(default)]
    pub auth: RelayAuth,
}

/// Credentials for a relay that does not serve everyone. `kind` names how `payload` is checked;
/// an empty `kind` is no credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAuth {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub payload: String,
}

/// A relay's answer. Accepting a submission is no promise to publish it: only the chain
/// says whether it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReply {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RelayRequest {
    #[must_use]
    pub fn new(addr: &AccountAddr, log: &SignedAccountLog, auth: RelayAuth) -> Self {
        Self {
            version: RELAY_REQUEST_VERSION,
            addr: addr.to_string(),
            log: STANDARD.encode(log.to_bytes()),
            auth,
        }
    }

    /// The submission as it goes on the wire.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a request serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LezAccountRegError> {
        let request: Self = serde_json::from_slice(bytes)?;
        if request.version != RELAY_REQUEST_VERSION {
            return Err(LezAccountRegError::Relay(format!(
                "submission version {} is not {RELAY_REQUEST_VERSION}",
                request.version
            )));
        }
        Ok(request)
    }

    /// The address and log, after checking that the address signed the log.
    pub fn decode(&self) -> Result<(AccountAddr, SignedAccountLog), LezAccountRegError> {
        let addr: AccountAddr = self
            .addr
            .parse()
            .map_err(|_| LezAccountRegError::Relay(format!("{} is not an address", self.addr)))?;
        let bytes = STANDARD
            .decode(&self.log)
            .map_err(|_| LezAccountRegError::Relay("the log is not base64".into()))?;
        let log = SignedAccountLog::from_bytes(&bytes)?;
        log.verify(&addr).map_err(LezAccountRegError::Unverified)?;
        Ok((addr, log))
    }
}

#[cfg(test)]
mod tests {
    use account_log::{AccountLogDraft, Context, Ed25519SigningKey, EntryData};

    use super::*;
    use crate::sign;

    fn signed() -> (AccountAddr, SignedAccountLog) {
        let key = Ed25519SigningKey::generate();
        let mut draft = AccountLogDraft::new();
        let data = EntryData::Text("Saro".into());
        draft
            .add(Context::literal("profile.displayname"), data)
            .unwrap();
        let log = sign(&key, draft.log()).unwrap();
        (AccountAddr::from(key.verifying_key()), log)
    }

    #[test]
    fn a_submission_round_trips_and_verifies() {
        let (addr, log) = signed();
        let request = RelayRequest::new(&addr, &log, RelayAuth::default());
        let back = RelayRequest::from_bytes(&request.to_bytes()).unwrap();
        assert_eq!(back, request);
        assert_eq!(back.decode().unwrap(), (addr, log));
    }

    #[test]
    fn a_log_under_another_address_is_refused() {
        let (_, log) = signed();
        let (other, _) = signed();
        let request = RelayRequest::new(&other, &log, RelayAuth::default());
        assert!(matches!(
            request.decode(),
            Err(LezAccountRegError::Unverified(_))
        ));
    }

    #[test]
    fn another_version_is_refused() {
        let (addr, log) = signed();
        let mut request = RelayRequest::new(&addr, &log, RelayAuth::default());
        request.version = 2;
        assert!(matches!(
            RelayRequest::from_bytes(&request.to_bytes()),
            Err(LezAccountRegError::Relay(_))
        ));
    }

    #[test]
    fn missing_credentials_read_as_none() {
        let (addr, log) = signed();
        let request = RelayRequest::new(&addr, &log, RelayAuth::default());
        let json = format!(
            r#"{{"version":1,"addr":"{}","log":"{}"}}"#,
            request.addr, request.log
        );
        assert_eq!(
            RelayRequest::from_bytes(json.as_bytes()).unwrap().auth,
            RelayAuth::default()
        );
    }
}
