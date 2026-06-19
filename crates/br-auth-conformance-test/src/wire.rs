use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use br_auth_contract::{BEARER_TOKENS_KEY_PREFIX, SealedBearer, bearer_token_kv_key, open, seal};

use crate::anchor::Anchor;
use crate::error::Result;
use crate::fixture::{
    OTHER_TOKEN, SEAL_KEY_BYTES, TOKEN, encode_entry, human_entry, seal_key, service_entry,
};
use crate::outcome::{CheckId, CheckOutcome};

pub async fn go_seal_opens_through_lib(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::GoSealOpensThroughLib;
    let expected =
        "a Go-sealed bearer opens through br_auth_contract::open into the exact BearerEntry";
    let key = seal_key()?;

    for entry in [human_entry(), service_entry()] {
        let plaintext = encode_entry(&entry)?;
        let sealed = anchor.seal(&SEAL_KEY_BYTES, TOKEN, &plaintext).await?;
        match open(&key, TOKEN, &sealed) {
            Ok(opened) if opened == entry => {}
            Ok(opened) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("opened {opened:?}"),
                    "the lib opened the Go-sealed wire into a different BearerEntry (drift)",
                ));
            }
            Err(e) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("open errored: {e}"),
                    "the lib could not open the Go-sealed wire — the AEAD scheme or AAD drifted",
                ));
            }
        }
    }
    Ok(CheckOutcome::pass(
        id,
        expected,
        "Go-sealed human + service entries opened identically through the lib",
    ))
}

pub async fn rust_seal_opens_in_go(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::RustSealOpensInGo;
    let expected = "a lib-sealed bearer opens in the Go anchor into the byte-identical entry JSON";
    let key = seal_key()?;

    for entry in [human_entry(), service_entry()] {
        let sealed = seal(&key, TOKEN, &entry)?;
        let expected_plaintext = encode_entry(&entry)?;
        match anchor.open(&SEAL_KEY_BYTES, TOKEN, &sealed).await? {
            Ok(plaintext) if plaintext == expected_plaintext => {}
            Ok(plaintext) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("Go opened {} bytes", plaintext.len()),
                    format!(
                        "Go opened a different plaintext than the lib serialized: {:?}",
                        String::from_utf8_lossy(&plaintext)
                    ),
                ));
            }
            Err(e) => {
                return Ok(CheckOutcome::fail(
                    id,
                    expected,
                    format!("Go open failed: {e}"),
                    "the independent Go anchor could not open the lib-sealed wire — the envelope drifted",
                ));
            }
        }
    }
    Ok(CheckOutcome::pass(
        id,
        expected,
        "lib-sealed human + service entries opened in Go to the identical JSON",
    ))
}

pub async fn kv_key_agrees(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::KvKeyAgrees;
    let expected = "the KV key the Go anchor derives equals bearer_token_kv_key for the same token, and \
                    that key is the bearer prefix followed by a 64-char lowercase-hex token hash";
    let (go_key, _) = anchor.kv_key(TOKEN).await?;
    let lib_key = bearer_token_kv_key(TOKEN);
    if go_key != lib_key {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            format!("go={go_key}"),
            format!("lib derived {lib_key} — the key format or SHA-256 hashing drifted"),
        ));
    }

    let Some(hash) = lib_key.strip_prefix(BEARER_TOKENS_KEY_PREFIX) else {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            format!("lib_key={lib_key}"),
            format!("the agreed key does not start with the {BEARER_TOKENS_KEY_PREFIX} prefix"),
        ));
    };
    let well_shaped = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !well_shaped {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            format!("hash portion={hash:?}"),
            "the token hash is not 64 lowercase-hex chars — the agreed key is the wrong shape",
        ));
    }

    Ok(CheckOutcome::pass(id, expected, go_key))
}

pub async fn sealed_wire_deserializes(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::SealedWireDeserializes;
    let expected =
        "the Go-frozen SealedBearer JSON deserializes through the deny_unknown_fields lib type";
    let plaintext = encode_entry(&human_entry())?;
    let sealed = anchor.seal(&SEAL_KEY_BYTES, TOKEN, &plaintext).await?;

    let json = serde_json::to_string(&sealed)
        .map_err(|e| crate::error::ConformanceError::Encode(e.to_string()))?;
    match serde_json::from_str::<SealedBearer>(&json) {
        Ok(back) if back == sealed => {}
        Ok(_) => {
            return Ok(CheckOutcome::fail(
                id,
                expected,
                "round-tripped to a different value",
                "the SealedBearer serde is not stable",
            ));
        }
        Err(e) => {
            return Ok(CheckOutcome::fail(
                id,
                expected,
                format!("deser failed: {e}"),
                "the Go-frozen envelope no longer deserializes through SealedBearer (a renamed/added lib field)",
            ));
        }
    }

    let with_extra = format!(
        r#"{{"nonce":"{}","ciphertext":"{}","evil":true}}"#,
        sealed.nonce, sealed.ciphertext
    );
    if serde_json::from_str::<SealedBearer>(&with_extra).is_ok() {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "an unknown field was accepted",
            "SealedBearer must reject unknown fields (deny_unknown_fields) — the envelope is no longer closed",
        ));
    }

    Ok(CheckOutcome::pass(
        id,
        expected,
        "Go-frozen envelope deserializes through the closed lib type, unknown field rejected",
    ))
}

pub async fn tampered_ciphertext_fails(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::TamperedCiphertextFails;
    let expected =
        "a Go-sealed bearer whose ciphertext is flipped fails to open on both the lib and Go";
    let key = seal_key()?;
    let plaintext = encode_entry(&human_entry())?;
    let sealed = anchor.seal(&SEAL_KEY_BYTES, TOKEN, &plaintext).await?;

    let mut raw = STANDARD
        .decode(&sealed.ciphertext)
        .map_err(|e| crate::error::ConformanceError::AnchorResponse(format!("ciphertext: {e}")))?;
    raw[0] ^= 0xff;
    let tampered = SealedBearer {
        nonce: sealed.nonce.clone(),
        ciphertext: STANDARD.encode(raw),
    };

    if open(&key, TOKEN, &tampered).is_ok() {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "lib opened tampered ciphertext",
            "Poly1305 integrity is not enforced by the lib",
        ));
    }
    if anchor
        .open(&SEAL_KEY_BYTES, TOKEN, &tampered)
        .await?
        .is_ok()
    {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "Go opened tampered ciphertext",
            "the independent anchor accepted a tampered value",
        ));
    }
    Ok(CheckOutcome::pass(
        id,
        expected,
        "tampered ciphertext rejected by both the lib and the Go anchor",
    ))
}

pub async fn relocated_seal_fails(anchor: &Anchor) -> Result<CheckOutcome> {
    let id = CheckId::RelocatedSealFails;
    let expected = "a bearer sealed under TOKEN fails to open under a different token (AAD = key-bound, anti-relocation)";
    let key = seal_key()?;
    let plaintext = encode_entry(&human_entry())?;
    let sealed = anchor.seal(&SEAL_KEY_BYTES, TOKEN, &plaintext).await?;

    if open(&key, OTHER_TOKEN, &sealed).is_ok() {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "lib opened under the wrong token",
            "the AAD is not binding the sealed value to its key — relocation is possible",
        ));
    }
    if anchor
        .open(&SEAL_KEY_BYTES, OTHER_TOKEN, &sealed)
        .await?
        .is_ok()
    {
        return Ok(CheckOutcome::fail(
            id,
            expected,
            "Go opened under the wrong token",
            "the independent anchor does not bind the AAD to the key — relocation is possible",
        ));
    }
    Ok(CheckOutcome::pass(
        id,
        expected,
        "the cross-language seal refuses to open under a different token (AAD binding holds)",
    ))
}

pub async fn run_wire_battery(anchor: &Anchor) -> Result<crate::outcome::ConformanceReport> {
    let mut report = crate::outcome::ConformanceReport::default();
    report.push(go_seal_opens_through_lib(anchor).await?);
    report.push(rust_seal_opens_in_go(anchor).await?);
    report.push(kv_key_agrees(anchor).await?);
    report.push(sealed_wire_deserializes(anchor).await?);
    report.push(tampered_ciphertext_fails(anchor).await?);
    report.push(relocated_seal_fails(anchor).await?);
    Ok(report)
}
