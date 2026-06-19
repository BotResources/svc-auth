use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::BearerEntry;
use crate::error::AuthContractError;
use crate::key::BearerSealKey;

const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBearer {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn seal(
    key: &BearerSealKey,
    token: &str,
    entry: &BearerEntry,
) -> Result<SealedBearer, AuthContractError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(entry).map_err(|e| AuthContractError::Serialize(e.to_string()))?,
    );
    let aad = br_core_auth::bearer_token_key(token);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| AuthContractError::AeadFailed)?;

    Ok(SealedBearer {
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn open(
    key: &BearerSealKey,
    token: &str,
    sealed: &SealedBearer,
) -> Result<BearerEntry, AuthContractError> {
    let nonce_bytes = STANDARD
        .decode(&sealed.nonce)
        .map_err(|_| AuthContractError::NonceNotBase64)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(AuthContractError::InvalidNonceLength(nonce_bytes.len()));
    }
    let ciphertext = STANDARD
        .decode(&sealed.ciphertext)
        .map_err(|_| AuthContractError::CiphertextNotBase64)?;
    let aad = br_core_auth::bearer_token_key(token);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AuthContractError::AeadFailed)?,
    );

    serde_json::from_slice(&plaintext).map_err(|e| AuthContractError::Deserialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use br_core_kernel::{Actor, ServiceAccountId, UserId};
    use uuid::Uuid;

    fn key_of(byte: u8) -> BearerSealKey {
        BearerSealKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn human_entry() -> BearerEntry {
        BearerEntry {
            actor: Actor::Human(UserId::from(Uuid::from_u128(0x42))),
            token_id: Uuid::from_u128(0x7),
        }
    }

    fn service_entry() -> BearerEntry {
        BearerEntry {
            actor: Actor::Service(ServiceAccountId::from(Uuid::from_u128(0x99))),
            token_id: Uuid::from_u128(0x1),
        }
    }

    const TOKEN_A: &str = "bearer-token-a";
    const TOKEN_B: &str = "bearer-token-b";

    #[test]
    fn seal_then_open_roundtrips_a_human_entry() {
        let key = key_of(1);
        let entry = human_entry();
        let sealed = seal(&key, TOKEN_A, &entry).unwrap();
        let opened = open(&key, TOKEN_A, &sealed).unwrap();
        assert_eq!(opened, entry);
    }

    #[test]
    fn seal_then_open_roundtrips_a_service_entry() {
        let key = key_of(2);
        let entry = service_entry();
        let sealed = seal(&key, TOKEN_A, &entry).unwrap();
        let opened = open(&key, TOKEN_A, &sealed).unwrap();
        assert_eq!(opened, entry);
    }

    #[test]
    fn open_with_a_different_key_fails() {
        let entry = human_entry();
        let sealed = seal(&key_of(3), TOKEN_A, &entry).unwrap();
        match open(&key_of(4), TOKEN_A, &sealed) {
            Err(AuthContractError::AeadFailed) => {}
            other => panic!("expected AeadFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_of_tampered_ciphertext_fails() {
        let key = key_of(5);
        let sealed = seal(&key, TOKEN_A, &human_entry()).unwrap();
        let mut raw = STANDARD.decode(&sealed.ciphertext).unwrap();
        raw[0] ^= 0xff;
        let tampered = SealedBearer {
            nonce: sealed.nonce,
            ciphertext: STANDARD.encode(raw),
        };
        match open(&key, TOKEN_A, &tampered) {
            Err(AuthContractError::AeadFailed) => {}
            other => panic!("expected AeadFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_under_a_different_token_fails() {
        let key = key_of(8);
        let sealed = seal(&key, TOKEN_A, &human_entry()).unwrap();
        match open(&key, TOKEN_B, &sealed) {
            Err(AuthContractError::AeadFailed) => {}
            other => panic!("expected AeadFailed, got {other:?}"),
        }
    }

    #[test]
    fn sealed_bearer_serde_json_roundtrips() {
        let sealed = seal(&key_of(6), TOKEN_A, &human_entry()).unwrap();
        let json = serde_json::to_string(&sealed).unwrap();
        let back: SealedBearer = serde_json::from_str(&json).unwrap();
        assert_eq!(sealed, back);
    }

    #[test]
    fn two_seals_of_the_same_payload_differ() {
        let key = key_of(7);
        let entry = human_entry();
        let a = seal(&key, TOKEN_A, &entry).unwrap();
        let b = seal(&key, TOKEN_A, &entry).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(
            open(&key, TOKEN_A, &a).unwrap(),
            open(&key, TOKEN_A, &b).unwrap()
        );
    }
}
