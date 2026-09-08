# Changelog

All notable changes to `br-auth-identity-util` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## 0.3.0 - 2026-09-08

### Changed

- Bumped the `br-util-nats-fabric` pin from `br-rust-common` v1.2.0 to **v1.3.0**
  (and `br-auth-contract` to 0.3.0). Minor bump because `BearerPublisher::open`
  takes a `&br_util_nats_fabric::Fabric` in its public signature, so a consumer
  now agrees on the v1.3.0 fabric (shared-version coupling). No behavioral change.

## 0.2.0 - 2026-07-12

### Changed

- Bumped the `br-util-nats-fabric` pin (and `br-auth-contract` to 0.2.0) onto
  `br-rust-common` v1.1.0. Minor bump because `BearerPublisher::open` takes a
  `&br_util_nats_fabric::Fabric` in its public signature, so a consumer now
  agrees on the v1.1.0 fabric (shared-version coupling). No behavioral change.

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
