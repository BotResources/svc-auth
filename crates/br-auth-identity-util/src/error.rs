use thiserror::Error;

#[derive(Debug, Error)]
pub enum BearerPublishError {
    #[error("could not open the published-language bucket: {0}")]
    Bind(String),

    #[error("could not seal the bearer entry: {0}")]
    Seal(String),

    #[error("the bearer kv key is invalid: {0}")]
    Key(String),

    #[error("could not upsert the sealed bearer: {0}")]
    Put(String),

    #[error("could not retract the sealed bearer: {0}")]
    Delete(String),
}
