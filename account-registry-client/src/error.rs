use account_log::AccountLogError;

#[derive(Debug, thiserror::Error)]
pub enum LezAccountRegError {
    #[error("invalid sequencer URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("talking to the sequencer: {0}")]
    Transport(#[from] ureq::Error),
    #[error("the sequencer refused the call: {message} (code {code})")]
    Rpc { code: i32, message: String },
    #[error("unexpected response from the sequencer: {0}")]
    Response(#[from] serde_json::Error),
    #[error("building the transaction: {0}")]
    Transaction(#[from] lee::error::LeeError),
    #[error("invalid log: {0}")]
    Log(#[from] AccountLogError),
    #[error("the chain returned a log that does not verify for this address: {0}")]
    Unverified(AccountLogError),
    #[error("the log does not extend the one on chain; fetch and rebuild it")]
    NotAnExtension,
    #[error("another write landed first; fetch and rebuild the log")]
    Conflict,
    #[error("the transaction did not take effect in time")]
    Timeout,
}
