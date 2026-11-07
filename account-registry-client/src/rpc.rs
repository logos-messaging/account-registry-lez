//! The two sequencer calls the client makes, as blocking JSON-RPC 2.0 over HTTP.
//!
//! LEZ's own client (`sequencer_service_rpc`) is async and needs tokio, so this speaks its wire
//! format directly. The method names, positional parameters and encodings below must match its
//! `Rpc` trait at the pinned revision. Bump them together; the ignored `against_a_sequencer` test
//! checks them end to end.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use borsh::BorshSerialize;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction, ProgramDeploymentTransaction,
    PublicTransaction,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::LezAccountRegError;

/// How long one request may take before it fails.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A copy of LEZ's `common::transaction::LeeTransaction`, whose crate pulls in tokio. Same
/// variants in the same order, so the same borsh encoding: the variant's index, then its body.
#[derive(BorshSerialize)]
pub(crate) enum LeeTransaction {
    Public(PublicTransaction),
    #[allow(
        dead_code,
        reason = "never sent; listed so `ProgramDeployment` keeps index 2"
    )]
    PrivacyPreserving(PrivacyPreservingTransaction),
    ProgramDeployment(ProgramDeploymentTransaction),
}

impl LeeTransaction {
    /// The wire form `sendTransaction` takes: borsh, then standard base64.
    pub(crate) fn to_base64(&self) -> String {
        let bytes = borsh::to_vec(self).expect("borsh encoding into a Vec cannot fail");
        STANDARD.encode(bytes)
    }
}

/// A connection to one sequencer's RPC endpoint.
#[derive(Clone)]
pub(crate) struct Sequencer {
    agent: ureq::Agent,
    url: String,
}

impl Sequencer {
    pub(crate) fn new(url: String) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self { agent, url }
    }

    /// The account's current state; a default account if nothing was ever written to it.
    pub(crate) fn get_account(&self, account_id: AccountId) -> Result<Account, LezAccountRegError> {
        self.call("getAccount", (account_id,))
    }

    /// Returns once the sequencer has accepted `tx`, not once it is in a block.
    pub(crate) fn send_transaction(&self, tx: &LeeTransaction) -> Result<(), LezAccountRegError> {
        let _hash: Value = self.call("sendTransaction", (tx.to_base64(),))?;
        Ok(())
    }

    fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> Result<R, LezAccountRegError> {
        let request = json!({ "jsonrpc": "2.0", "id": 0, "method": method, "params": params });
        let response: Response = self
            .agent
            .post(&self.url)
            .send_json(request)?
            .body_mut()
            .read_json()?;
        if let Some(RpcError { code, message }) = response.error {
            return Err(LezAccountRegError::Rpc { code, message });
        }
        Ok(serde_json::from_value(
            response.result.unwrap_or(Value::Null),
        )?)
    }
}

#[derive(Deserialize)]
struct Response {
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}
