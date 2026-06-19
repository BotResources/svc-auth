# Changelog

All notable changes to `br-auth-conformance-test` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this crate keeps
its own version line (independent of `br-auth-contract`).

## 0.1.0 - 2026-06-19

### Added

- The independent-anchor conformance battery for the `br-auth-contract` bearer
  wire — **TEST FIXTURE ONLY** (dev-dependency).
- `anchor/` — an independent Go re-implementation of the bearer wire (SHA-256 KV
  key, `SealedBearer` JSON envelope, ChaCha20-Poly1305 with AAD = the token's
  SHA-256), sharing no source with the Rust lib. Exposed as a stdin/stdout JSON
  CLI (`key` / `seal` / `open`), built into a tempdir and invoked per check.
- Cross-language wire gate **x1–x4**: a Go-sealed bearer opens through the real
  `br_auth_contract::open` (oracle); a lib-sealed bearer opens in Go; the KV key
  agrees across languages **and** is the bearer prefix followed by a 64-char
  lowercase-hex token hash; the Go-frozen `SealedBearer` deserializes through the
  `deny_unknown_fields` lib type and rejects an added field.
- Negative gate **n1–n2** (both sides): a tampered ciphertext and a relocated
  (wrong-token / wrong-AAD) seal both fail to open on the lib and on Go.
- Real-fabric KV gate **k1–k3**, driving the **real `br-util-nats-fabric`
  v1.0.2** published-language read API over a real `nats-server` provisioned by the
  harness `FabricTestNats` (v1.0.1): a Go-sealed bearer (for **both** the human and
  service actor shapes) published to `identity/bearer_tokens/<hash>` through the
  real `PublishedLanguagePublisher` is read back by the real
  `PublishedLanguageReader` scoped to the bearer prefix and opened through the lib
  — proving the `SealedBearer` rides the generic fabric published-language read API
  (Reader) transparently; a `PublishedLanguageReader` scoped to the directory
  prefix (`identity/users/`) does not pick up the bearer key, and vice versa
  (cohabitation safety); and a non-`SealedBearer` value published under the bearer
  prefix makes the bearer-scoped reader **fail closed** with a `FabricError::Decode`
  naming the offending key (the scan does not silently skip it). `async-nats` stays
  confined to the harness; no hand-rolled KV scan.
- Public, reusable battery surface (`CheckOutcome` / `ConformanceReport`,
  per-check functions, `run_wire_battery`, `run_full_battery`) for black-box reuse
  against a live identity-service producer.
- Real-infra checks are `#[ignore]`-gated; default `cargo test` is green with no
  `go` / `nats-server` toolchain.
- Pins: `br-auth-contract` via path; `br-core-kernel` / `br-util-nats-fabric` at
  `br-rust-common` v1.0.2; `br-test-harness` v1.0.1 (`nats-fabric` +
  `spawned-nats`).
