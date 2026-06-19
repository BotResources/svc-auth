# Changelog

All notable changes to `br-auth-contract` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## 0.1.0 - 2026-06-19

### Added

- Initial bearer-credential wire contract for publishing into `svc-auth`.
- `BEARER_TOKENS_KEY_PREFIX` and `bearer_token_kv_key` — the
  `identity/bearer_tokens/<sha256hex>` KV key in the shared `PUBLISHED_LANGUAGE`
  bucket, reusing `br_core_auth::bearer_token_key` for the one-way hash.
- `BearerEntry { actor, token_id }` — the cleartext payload (typed
  `br_core_kernel::Actor` identity plus the credential id).
- `SealedBearer { nonce, ciphertext }` — the base64/JSON AEAD envelope actually
  stored in KV, so it rides the generic published-language consumer.
- `BearerSealKey` — a length-validated 32-byte symmetric seal key.
- `seal(key, token, &BearerEntry)` / `open(key, token, &SealedBearer)` —
  ChaCha20-Poly1305 AEAD with a fresh random 96-bit nonce per seal. The token is
  passed in and its SHA-256 hash (the KV key suffix) is used as AEAD associated
  data internally, binding each sealed value to its KV key: a value relocated to
  a different key fails to open (`AeadFailed`), blocking ciphertext-substitution
  impersonation in the write-open shared bucket. `open` also fails on the wrong
  key or any tampering.
- `BearerSealKey` is zeroized on drop and exposes no `Debug`/`Serialize`; `seal`
  zeroizes the serialized cleartext plaintext after encryption.
- `AuthContractError` — the crate's own error type.
