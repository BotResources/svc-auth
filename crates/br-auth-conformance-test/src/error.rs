use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConformanceError {
    #[error("go toolchain unavailable: {0}")]
    GoUnavailable(String),
    #[error("building the bearer-wire anchor failed: {0}")]
    Build(String),
    #[error("running the bearer-wire anchor failed: {0}")]
    Run(String),
    #[error("the anchor response did not parse as JSON: {0}")]
    AnchorResponse(String),
    #[error("the anchor reported an error: {0}")]
    AnchorError(String),
    #[error("encoding a bearer entry through the lib failed: {0}")]
    Encode(String),
    #[error("the bearer contract refused the input: {0}")]
    Contract(#[from] br_auth_contract::AuthContractError),
    #[error("the fabric refused a kv key/prefix: {0}")]
    Kv(String),
    #[error("the fabric published-language transport failed: {0}")]
    Fabric(String),
}

pub type Result<T> = std::result::Result<T, ConformanceError>;
