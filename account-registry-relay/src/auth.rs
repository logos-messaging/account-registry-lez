//! Who may have their log sponsored. Each scheme checks one `kind` of credentials; a submission
//! names its kind, and the relay accepts it only if a configured scheme of that kind does.
//!
//! The schemes here are placeholders for a test network. A real one, such as a Keycard
//! attestation or an RLN proof, implements [`Scheme`] and returns a nullifier, so one credential
//! sponsors one account however many keys its holder makes.

use account_registry_client::relay::RelayRequest;

/// One way of checking credentials.
pub trait Scheme: Send {
    /// The `auth.kind` this scheme checks.
    fn kind(&self) -> &'static str;

    /// Checks `request`'s credentials. On success, returns what identifies the credential
    /// itself, if anything: the relay sponsors each nullifier once.
    fn verify(&self, request: &RelayRequest) -> Result<Option<String>, String>;
}

/// Serves everyone: no credentials, kind `""`.
pub struct Open;

impl Scheme for Open {
    fn kind(&self) -> &'static str {
        ""
    }

    fn verify(&self, _request: &RelayRequest) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// Serves whoever knows one shared secret, e.g. a token built into an app: kind `token`.
pub struct SharedToken(pub String);

impl Scheme for SharedToken {
    fn kind(&self) -> &'static str {
        "token"
    }

    fn verify(&self, request: &RelayRequest) -> Result<Option<String>, String> {
        if same(request.auth.payload.as_bytes(), self.0.as_bytes()) {
            Ok(None)
        } else {
            Err("wrong token".into())
        }
    }
}

/// Whether `a` and `b` are equal, in time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// The schemes a relay accepts.
pub struct Auth(Vec<Box<dyn Scheme>>);

impl Auth {
    #[must_use]
    pub fn new(schemes: Vec<Box<dyn Scheme>>) -> Self {
        Self(schemes)
    }

    /// The nullifier of `request`'s credentials, if they pass.
    pub fn verify(&self, request: &RelayRequest) -> Result<Option<String>, String> {
        let kind = request.auth.kind.as_str();
        let scheme = self
            .0
            .iter()
            .find(|scheme| scheme.kind() == kind)
            .ok_or_else(|| match kind {
                "" => "this relay needs credentials".to_owned(),
                kind => format!("this relay does not accept {kind} credentials"),
            })?;
        let nullifier = scheme.verify(request)?;
        Ok(nullifier.map(|nullifier| format!("{kind}:{nullifier}")))
    }
}

#[cfg(test)]
mod tests {
    use account_registry_client::relay::RelayAuth;

    use super::*;

    fn request(kind: &str, payload: &str) -> RelayRequest {
        RelayRequest {
            version: 1,
            addr: String::new(),
            log: String::new(),
            auth: RelayAuth {
                kind: kind.into(),
                payload: payload.into(),
            },
        }
    }

    #[test]
    fn an_open_relay_takes_no_credentials() {
        let auth = Auth::new(vec![Box::new(Open)]);
        assert_eq!(auth.verify(&request("", "")), Ok(None));
        assert!(auth.verify(&request("token", "x")).is_err());
    }

    #[test]
    fn a_token_relay_takes_only_its_token() {
        let auth = Auth::new(vec![Box::new(SharedToken("s3cret".into()))]);
        assert_eq!(auth.verify(&request("token", "s3cret")), Ok(None));
        assert!(auth.verify(&request("token", "guess")).is_err());
        assert!(auth.verify(&request("", "")).is_err());
    }
}
