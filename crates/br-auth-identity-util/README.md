# br-auth-identity-util

The identity-side **producer kit** for bearer credentials.

`svc-auth` is the single, never-duplicated authentication gatekeeper; any number
of per-project identity services **publish** bearer credentials into its contract
(an N→1 fan). This crate is that publisher half: it seals a `BearerEntry` through
the frozen [`br-auth-contract`](../br-auth-contract) wire and writes it to the
shared `PUBLISHED_LANGUAGE` KV bucket through the **real**
[`br-util-nats-fabric`](https://github.com/BotResources/br-rust-common) publisher.
`svc-auth` reads the same keys via `br-auth-contract::open`.

There is **no raw `async-nats`** here: all NATS access goes through the fabric's
`PublishedLanguagePublisher`.

## Public API

```text
pub struct BearerPublisher { /* opaque: PL publisher + the held seal key */ }

impl BearerPublisher {
    pub async fn open(fabric: &Fabric, key: BearerSealKey)
        -> Result<Self, BearerPublishError>;

    pub async fn put_bearer(&self, token: &str, entry: &BearerEntry)
        -> Result<(), BearerPublishError>;

    pub async fn delete_bearer(&self, token: &str)
        -> Result<(), BearerPublishError>;
}

pub enum BearerPublishError { Bind, Seal, Key, Put, Delete }
```

- **`open`** binds the existing `PUBLISHED_LANGUAGE` bucket via the fabric (it
  never provisions it — an absent bucket fails loud) and holds the `BearerSealKey`
  (the long-lived `svc-auth`↔identity shared secret).
- **`put_bearer`** is the publish/upsert path: it seals `entry` with
  `br_auth_contract::seal(key, token, entry)` and upserts the `SealedBearer` to
  the KV key `br_auth_contract::bearer_token_kv_key(token)`
  (`identity/bearer_tokens/<sha256hex>`).
- **`delete_bearer`** is **revocation**: it retracts that same KV key.

The plaintext `token` is the **single source of both** the KV key
(`bearer_token_kv_key`) and the AEAD associated data (derived internally by
`seal`/`open`). The kit reuses the contract's helpers — it never re-derives the
hash or the AAD — so a published value is always bound to its key.

## Error boundary

`BearerPublishError` is this crate's own error type. The fabric's `FabricError`
and the contract's `AuthContractError` are captured as message strings and never
leak across the public API.

## Why

| Thing | Why it is the way it is |
| --- | --- |
| `BearerPublisher` holds the seal key | The seal key is the producer's long-lived secret; binding it to the handle makes every `put_bearer` use it without re-threading it per call. |
| `token` is the only key/AAD source; helpers are reused, not re-derived | Reusing `bearer_token_kv_key` + `seal` keeps the key and the AAD in lockstep with the frozen contract; re-deriving either would risk drift. |
| Own error type, no leaked `FabricError`/`AuthContractError` | Each crate owns its error type; a lower layer's error must not become part of this crate's public surface. |
| All NATS via `PublishedLanguagePublisher` | Raw `async-nats` is forbidden in service/producer code; the fabric renders + validates the transport. |
| `open` binds, never provisions | The bucket is GitOps-declared infra; the fabric binds-existing and fails loud, the kit does not create it. |

## Testing

- **Unit** (no infra): `put_bearer`'s seal recovers the original `BearerEntry`
  via `open` at the contract KV key, for both Human and Service actors.
- **Integration** (real NATS via `FabricTestNats`, `#[ignore]`-gated on a broker):
  `put_bearer` then read the key back through a real `PublishedLanguageReader` and
  `open` → matches; `delete_bearer` then read back → the key is absent.

## License

Apache-2.0.
