#![doc = include_str!("../README.md")]

pub mod anchor;
pub mod error;
pub mod fixture;
pub mod kv;
pub mod outcome;
pub mod wire;

pub use anchor::{Anchor, build_anchor, ensure_go_available};
pub use error::{ConformanceError, Result};
pub use kv::{
    directory_prefix_ignores_bearer, rides_published_language_consumer,
    undecodable_bearer_value_fails_closed,
};
pub use outcome::{CheckId, CheckOutcome, CheckStatus, ConformanceReport};
pub use wire::{
    go_seal_opens_through_lib, kv_key_agrees, relocated_seal_fails, run_wire_battery,
    rust_seal_opens_in_go, sealed_wire_deserializes, tampered_ciphertext_fails,
};

pub async fn run_full_battery() -> Result<ConformanceReport> {
    let anchor = Anchor::build().await?;
    let mut report = run_wire_battery(&anchor).await?;
    report.push(rides_published_language_consumer().await?);
    report.push(directory_prefix_ignores_bearer().await?);
    report.push(undecodable_bearer_value_fails_closed().await?);
    Ok(report)
}
