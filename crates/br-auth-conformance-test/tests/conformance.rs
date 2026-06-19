use br_auth_conformance_test::{
    Anchor, CheckOutcome, directory_prefix_ignores_bearer, go_seal_opens_through_lib,
    kv_key_agrees, relocated_seal_fails, rides_published_language_consumer, rust_seal_opens_in_go,
    sealed_wire_deserializes, tampered_ciphertext_fails, undecodable_bearer_value_fails_closed,
};

fn assert_pass(outcome: &CheckOutcome) {
    assert!(
        outcome.is_pass(),
        "{} must pass: expected={:?} observed={:?} detail={:?}",
        outcome.id.code(),
        outcome.expected,
        outcome.observed,
        outcome.detail,
    );
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn x1_go_seal_opens_through_lib() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&go_seal_opens_through_lib(&anchor).await.expect("x1"));
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn x2_rust_seal_opens_in_go() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&rust_seal_opens_in_go(&anchor).await.expect("x2"));
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn x3_kv_key_agrees() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&kv_key_agrees(&anchor).await.expect("x3"));
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn x4_sealed_wire_deserializes() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&sealed_wire_deserializes(&anchor).await.expect("x4"));
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn n1_tampered_ciphertext_fails() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&tampered_ciphertext_fails(&anchor).await.expect("n1"));
}

#[tokio::test]
#[ignore = "wire gate: needs `go` on PATH to build the bearer-wire anchor"]
async fn n2_relocated_seal_fails() {
    let anchor = Anchor::build().await.expect("build anchor");
    assert_pass(&relocated_seal_fails(&anchor).await.expect("n2"));
}

#[tokio::test]
#[ignore = "real-infra: needs `nats-server` + `go` on PATH"]
async fn k1_rides_published_language_consumer() {
    assert_pass(&rides_published_language_consumer().await.expect("k1"));
}

#[tokio::test]
#[ignore = "real-infra: needs `nats-server` + `go` on PATH"]
async fn k2_directory_prefix_ignores_bearer() {
    assert_pass(&directory_prefix_ignores_bearer().await.expect("k2"));
}

#[tokio::test]
#[ignore = "real-infra: needs `nats-server` on PATH"]
async fn k3_undecodable_bearer_value_fails_closed() {
    assert_pass(&undecodable_bearer_value_fails_closed().await.expect("k3"));
}
