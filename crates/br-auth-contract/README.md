# br-auth-contract

The frozen wire contract for publishing **bearer credentials** to `svc-auth`.

`svc-auth` is the single, stable, never-duplicated authentication gatekeeper. Any
number of per-project identity services publish bearer credentials *into its
contract* (an N→1 fan: the consumer owns the contract). This crate freezes that
wire so an identity service and `svc-auth` agree on it without sharing code.

The crate is **pure**: types, constants, and pure crypto functions. It performs
no I/O — no NATS, no async, no fabric dependency. The identity-side publisher and
the `svc-auth`-side reader each own their own transport.

## Destination

- **Bucket:** `PUBLISHED_LANGUAGE` — the fabric's shared published-language KV
  bucket. This crate deliberately defines **no** bucket-name constant; the
  authoritative name is the fabric's `KV_PUBLISHED_LANGUAGE`. Bearers live as a
  key prefix inside the same bucket the directory uses. The directory freezes two
  prefixes as lib constants (`identity/users/`, `identity/groups/`); additional
  directory entities (e.g. service_accounts) ride the same bucket as open entities
  carried via the `_meta` manifest, not as a frozen constant.
- **Key:** `identity/bearer_tokens/<sha256hex>`, built by `bearer_token_kv_key`,
  where `<sha256hex>` is the lowercase-hex SHA-256 of the plaintext bearer token
  (reusing `br_core_auth::bearer_token_key`). The plaintext token never appears
  in the key — the key is a one-way hash.

## Cleartext payload — `BearerEntry`

What gets sealed. Serialized as JSON, then encrypted.

```text
pub struct BearerEntry {
    pub actor: br_core_kernel::Actor, // Human(UserId) | Service(ServiceAccountId)
    pub token_id: uuid::Uuid,
}
```

`actor` is the typed identity (who the credential authenticates as); `token_id`
identifies the credential itself (for audit / revocation). This shape serves both
the gate/audit use on the `svc-auth` side and the Passport-builder's "who is it"
need. It is intentionally minimal.

## Sealed envelope — `SealedBearer`

What is actually stored in the KV value. Plain JSON, so it rides the generic
published-language consumer transparently; the recipient opens it in its handler.

```text
pub struct SealedBearer {
    pub nonce: String,      // base64 (standard) of the 96-bit AEAD nonce
    pub ciphertext: String, // base64 (standard) of the AEAD ciphertext+tag
}
```

This envelope format is the must-not-drift part of the contract.

## AEAD scheme

- **Algorithm:** ChaCha20-Poly1305 (RustCrypto `chacha20poly1305`, AEAD).
- **Key:** a 32-byte symmetric key (`BearerSealKey`), shared between `svc-auth`
  and the identity service, provisioned out-of-band as a Kubernetes secret.
- **Nonce:** a fresh random 96-bit nonce per `seal`, drawn from the OS RNG.
- **Associated data (AAD):** the SHA-256 hash of the plaintext token (the same
  `<sha256hex>` that forms the KV key, via `br_core_auth::bearer_token_key`). The
  token is passed to both functions and the AAD is derived internally, so a
  sealed value is always bound to its KV key and cannot be produced unbound.
- `seal(key, token, &BearerEntry) -> Result<SealedBearer, AuthContractError>`
- `open(key, token, &SealedBearer) -> Result<BearerEntry, AuthContractError>`
  fails (`AeadFailed`) on the wrong key, on any tampering, or when the sealed
  value is opened under a different token than it was sealed with (AEAD
  integrity over both ciphertext and AAD).

## Security property (honest)

- **Confidential** — the value is AEAD-encrypted; a directory reader sharing the
  `PUBLISHED_LANGUAGE` bucket sees only ciphertext.
- **Integrity-protected** — Poly1305 authenticates the ciphertext; a tampered or
  truncated value fails to open.
- **Key-bound** — the sealed value is cryptographically bound to its KV key: the
  AAD is the token's SHA-256 hash, which is exactly the key suffix. A
  `SealedBearer` relocated to (or substituted under) a *different* key fails to
  open with `AeadFailed`. In the shared, write-open bucket model this blocks
  ciphertext substitution / relocation — an attacker who can write the bucket
  cannot copy a valid sealed value onto a key they control to impersonate a
  different token. (This guards against relocation of an *existing* sealed value;
  it does not, and cannot, authenticate *who* performed a legitimate write — that
  rests on bucket write access, which is the deployment's NATS-account boundary.)
- The KV **key** is a one-way SHA-256 hash of the token; the plaintext token is
  never stored or transported.
- **Confidentiality rests entirely on the shared symmetric key** (the
  `svc-auth`↔identity K8s secret), **not** on any NATS-level grant. There is no
  NATS-level auth between services within a project (one NATS account per project
  is the only boundary); anyone with bucket read access can read the bytes, so
  the bytes must be encrypted. Compromise of the shared key compromises
  confidentiality of every bearer entry.

## Why

| Thing | Why it is the way it is |
| --- | --- |
| Value is AEAD-encrypted, not plaintext | No NATS-level auth between services in a project; the directory and svc-auth share one bucket, so a reader sees the bytes — confidentiality must be application-level. |
| AAD = the token's SHA-256 hash (the KV key suffix); `seal`/`open` take the token | Binds the sealed value to its key. In the write-open shared bucket, a value relocated/substituted onto another key fails to open — blocks ciphertext-substitution impersonation. Deriving the AAD internally makes an unbound seal unrepresentable. |
| `BearerSealKey` is `ZeroizeOnDrop`, no `Debug`/`Serialize` | It is a long-lived secret; zeroizing on drop and refusing to print/serialize keep it out of logs and freed memory. |
| `seal` zeroizes the serialized plaintext | The `BearerEntry` JSON holds the cleartext actor + token id; it is wiped after encrypt so it does not linger in freed memory. |
| One bucket, key prefix (not a new bucket) | Buckets are GitOps-declared infra; reusing `PUBLISHED_LANGUAGE` with a key prefix avoids provisioning a new bucket and mirrors the directory's own prefixing. |
| No bucket-name constant in this crate | The authoritative name is the fabric's `KV_PUBLISHED_LANGUAGE`; a duplicate const here would drift. |
| Crate has no I/O / no fabric dep | It freezes a *wire*, not a transport; publisher and reader own their own NATS access through the fabric. |

## Usage in this contract family

This is the first of three crates. The conformance test
(`br-auth-conformance-test`) and the identity-side helper
(`br-auth-identity-util`) build on this frozen wire and are not part of this
crate.

## License

Apache-2.0.
