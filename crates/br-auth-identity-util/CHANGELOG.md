# Changelog

All notable changes to `br-auth-identity-util` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## 0.1.0 - 2026-06-19

### Added

- `BearerPublisher` — the identity-side producer kit that seals a `BearerEntry`
  through `br-auth-contract` and writes it to the shared `PUBLISHED_LANGUAGE` KV
  bucket via the real `br-util-nats-fabric` `PublishedLanguagePublisher` (no raw
  `async-nats`).
- `BearerPublisher::open(fabric, key)` — binds the existing `PUBLISHED_LANGUAGE`
  bucket (fail-loud, never provisions) and holds the `BearerSealKey`.
- `put_bearer(token, &BearerEntry)` — the publish/upsert path: seals with
  `seal(key, token, entry)` and upserts the `SealedBearer` to
  `bearer_token_kv_key(token)` (`identity/bearer_tokens/<sha256hex>`); the token
  is the single source of both the KV key and the AEAD associated data.
- `delete_bearer(token)` — revocation: retracts the same KV key.
- `BearerPublishError` — the crate's own error type; the fabric's `FabricError`
  and the contract's `AuthContractError` never leak across the public API.
