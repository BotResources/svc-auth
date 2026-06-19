# br-auth-conformance-test

An **independent-anchor conformance battery** that guards the
[`br-auth-contract`](../br-auth-contract) **bearer wire** — the frozen format by
which a per-project identity service publishes encrypted bearer credentials to
`svc-auth` over the shared `PUBLISHED_LANGUAGE` KV bucket — against drift.

> ⚠️ **TEST FIXTURE ONLY.** A dev-dependency, never a runtime one. The real
> batteries build a real Go binary and stand up a real `nats-server` on a
> throwaway, isolated test instance.

## Three roles, never conflated

This crate follows the BotResources wire-conformance doctrine — **Go freezes the
wire · the conformance test imports the lib as oracle · the battery guards the
implementations**:

- **`anchor/`** (Go) — an **independent re-implementation** of the bearer wire,
  built from the contract spec, that **shares no source with the Rust lib**. It
  derives the SHA-256 KV key, builds the `SealedBearer` JSON envelope, and runs
  ChaCha20-Poly1305 (IETF, 96-bit nonce) with **associated data = the token's
  lowercase-hex SHA-256** — using only Go's stdlib `crypto/sha256` and
  `golang.org/x/crypto/chacha20poly1305`. Because it cannot drift *with* the Rust
  lib, it is the trustworthy freeze of the bytes.
- **the conformance checks (this crate)** — deserialize / `open` / `seal` the
  Go-frozen wire **through the real `br_auth_contract` types** (the lib is the
  **oracle**). A lib drift — a renamed/retyped field, a changed serde, a
  different AEAD algorithm, a different AAD, a different key format — makes the
  cross-language check **fail**. The types are imported, never mirrored; mirroring
  would blind the detector.
- **the battery (this crate)** — black-box check functions returning structured
  `CheckOutcome`s, reusable later against a live, conformant identity-service
  producer.

## The anchor invocation

The Go anchor is a tiny CLI that reads one JSON request on stdin and writes one
JSON response on stdout. The Rust `Anchor` (`src/anchor.rs`) `go build`s it once
into a tempdir (via the harness `run_once`) and then invokes it per check:

| `op` | request | response |
|---|---|---|
| `key` | `{ token }` | `{ kv_key, token_hash }` — the `identity/bearer_tokens/<sha256hex>` key + the raw hash |
| `seal` | `{ key_b64, token, plaintext_b64 }` | `{ sealed: { nonce, ciphertext }, kv_key, token_hash }` |
| `open` | `{ key_b64, token, sealed }` | `{ plaintext_b64 }` or `{ error }` on AEAD failure |

The anchor operates on **opaque plaintext bytes** — it never models the
`BearerEntry` shape. The Rust side serializes / deserializes the `BearerEntry`
through the **lib**, so the cleartext-payload shape is frozen by the lib oracle
and the envelope + crypto + key are frozen by the independent Go anchor.

## What it freezes

### Cross-language wire gate — x1–x4 (needs `go`)

| Id | Asserts |
|---|---|
| **x1** | a **Go-sealed** human + service bearer **opens through `br_auth_contract::open`** into the exact `BearerEntry` (the frozen wire opened through the oracle; drift → fail). |
| **x2** | a **lib-sealed** bearer **opens in the Go anchor** into the byte-identical entry JSON (interop the other direction). |
| **x3** | the KV key the Go anchor derives equals `bearer_token_kv_key` for the same token, **and** that key starts with `BEARER_TOKENS_KEY_PREFIX` with a **64-char lowercase-hex** hash portion (`identity/bearer_tokens/<sha256hex>`; key format + hashing agree *on the right shape*). |
| **x4** | the Go-frozen `SealedBearer` JSON deserializes through the real `SealedBearer` type, and its `deny_unknown_fields` **rejects** an added field (a renamed/added lib field would break the deser). |

### Negative gate — n1–n2, both sides (needs `go`)

| Id | Asserts |
|---|---|
| **n1** | a Go-sealed bearer with a **flipped ciphertext byte** fails to open on **both** the lib and Go (Poly1305 integrity). |
| **n2** | a bearer sealed under one token **fails to open under a different token** on both sides (AAD = the token hash → the sealed value is bound to its KV key; **anti-relocation**). |

### Real-fabric KV gate — k1–k3 (needs `nats-server` + `go`)

These run against a **real `nats-server`** provisioned by the harness
`FabricTestNats` (the house conformance pattern — every battery provisions NATS
through the fabric test harness, never a raw `async-nats` handle), and exercise
the **real `br-util-nats-fabric` published-language API** end to end.

| Id | Asserts |
|---|---|
| **k1** | a Go-sealed bearer **published** to `identity/bearer_tokens/<hash>` through the real `PublishedLanguagePublisher` is **read back** by the real `PublishedLanguageReader` scoped to the bearer prefix and **opened through the lib** into the original entry, for **both** the human and service actor shapes — the `SealedBearer` rides the **generic fabric published-language read API (Reader)** transparently (the inter-crate claim deferred to this crate). |
| **k3** | a non-`SealedBearer` (garbage JSON) value published under the bearer prefix makes the bearer-scoped `PublishedLanguageReader::<SealedBearer>().entries(prefix)` **fail closed** with a `FabricError::Decode` naming the offending key — the fabric scan does **not** silently skip an undecodable cohabiting value (shared-bucket contract against a buggy producer). |
| **k2** | a real `PublishedLanguageReader` scoped to the **directory** prefix `identity/users/` does **not** pick up a bearer key sharing the bucket, and a reader scoped to `identity/bearer_tokens/` does not pick up a directory key — **cohabitation safety** in the one shared `PUBLISHED_LANGUAGE` bucket. |

## Running it

The default `cargo test` is green with **no** toolchain (every real check is
`#[ignore]`-gated):

```sh
# the cross-language + negative wire gate (needs `go`)
cargo test -p br-auth-conformance-test --test conformance -- --ignored x
cargo test -p br-auth-conformance-test --test conformance -- --ignored n

# the full battery incl. the real-NATS KV round-trip (needs `go` + `nats-server`)
cargo test -p br-auth-conformance-test --test conformance -- --ignored --test-threads=1
```

The battery functions (`go_seal_opens_through_lib`, …, `run_wire_battery`,
`rides_published_language_consumer`, `directory_prefix_ignores_bearer`,
`undecodable_bearer_value_fails_closed`, `run_full_battery`) are public, so a
consuming service's e2e can call them directly.

## Reusing it against a live identity service

The KV checks publish through the real fabric `PublishedLanguagePublisher` to
prove the transport. The full **black-box run against a real producer** — a
conformant identity service that *itself* seals + publishes a real bearer — is
exercised once such a producer exists (the identity-side helper, crate 3, plus a
service). The reusable mechanism is `rides_published_language_consumer`: a real
`PublishedLanguageReader` scoped to `BEARER_TOKENS_KEY_PREFIX` reads the
producer's bucket and `open`s what it reads with the lib. This crate does **not**
fabricate a fake producer.

## Why — the non-obvious bits

| Thing | Why it is the way it is |
|---|---|
| The check `open`s / `seal`s / deserializes through the real `br_auth_contract` types | The owner's ruling (the scope / passport / directory precedent): success against the real type *is* the conformance check. Mirroring the expected types would be a second contract that drifts — exactly what this crate exists to prevent. |
| The Go anchor handles **opaque plaintext**, not `BearerEntry` | It freezes the **envelope + crypto + key** independently; the **payload shape** is frozen by the lib-oracle (de)serialization on the Rust side. Splitting the two keeps the Go anchor from re-encoding a shape it would have to keep in sync. |
| n1/n2 assert failure on **both** the lib and the Go anchor | A one-sided negative could pass by accident (e.g. the lib rejects but Go's AEAD is mis-scoped). Both-sided makes the anti-tamper / anti-relocation property a genuine cross-language fact. |
| k1/k2/k3 publish + read through the **real `br-util-nats-fabric`** `PublishedLanguagePublisher` / `PublishedLanguageReader` (v1.0.2) | The point of this crate is that a `SealedBearer` rides the **generic** fabric published-language read API (Reader) with no special-casing. Hand-rolling the scan (a `keys()` + prefix filter + decode) would re-implement the very API under test and prove nothing about the real reader — so the test drives the real one. The fabric exists at v1.0.2 (it did not at v0.11.0), which is why this is the rework. |
| k3 asserts `entries()` **fails closed** on an undecodable cohabiting value | The fabric scan path (`scan_entries`) decodes every prefix-matching value through `serde_json::from_slice::<V>` and propagates a `FabricError::Decode` on the first failure — it does **not** skip the bad key. k3 freezes that defined behavior so a buggy producer writing a non-`SealedBearer` under the bearer prefix surfaces loudly rather than being silently dropped. |
| The harness is `br-test-harness` **v1.0.1** with `FabricTestNats`, not a raw `SpawnedNats` | v1.0.1 is the harness release coupled to `br-rust-common` v1.0.2 (matches the contract's `br-core-*` pins). `FabricTestNats` is the house provisioner: it stands up the real `nats-server`, get-or-creates the fixed `PUBLISHED_LANGUAGE` bucket, and hands back the **real lib** publisher/reader — `async-nats` stays confined to the harness, never touched by this crate. |
| The whole real battery is `#[ignore]`-gated | It drives real infra (`go` + `nats-server`); the default `cargo test` must stay green on a machine without them, like the scope / directory conformance crates. |

## License

Apache-2.0. MSRV **1.88** (edition 2024).
