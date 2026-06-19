use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::AuthContractError;

pub const BEARER_SEAL_KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BearerSealKey([u8; BEARER_SEAL_KEY_LEN]);

impl BearerSealKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthContractError> {
        let array: [u8; BEARER_SEAL_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| AuthContractError::InvalidKeyLength(bytes.len()))?;
        Ok(Self(array))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; BEARER_SEAL_KEY_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_accepts_exactly_32_bytes() {
        assert!(BearerSealKey::from_bytes(&[7u8; 32]).is_ok());
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        let err = BearerSealKey::from_bytes(&[0u8; 16]).err().unwrap();
        assert!(matches!(err, AuthContractError::InvalidKeyLength(16)));
    }

    #[test]
    fn from_bytes_rejects_too_long() {
        let err = BearerSealKey::from_bytes(&[0u8; 48]).err().unwrap();
        assert!(matches!(err, AuthContractError::InvalidKeyLength(48)));
    }
}
