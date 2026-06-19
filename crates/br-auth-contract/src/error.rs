use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthContractError {
    #[error("seal key must be 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("sealed nonce is not valid base64")]
    NonceNotBase64,

    #[error("sealed ciphertext is not valid base64")]
    CiphertextNotBase64,

    #[error("sealed nonce must be 12 bytes, got {0}")]
    InvalidNonceLength(usize),

    #[error("serializing the bearer entry failed: {0}")]
    Serialize(String),

    #[error("the sealed bearer could not be opened (wrong key or tampered ciphertext)")]
    AeadFailed,

    #[error("the opened plaintext is not a valid bearer entry: {0}")]
    Deserialize(String),
}
