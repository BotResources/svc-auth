use br_test_harness::FabricTestNats;
use chrono::Utc;
use svc_auth::refresh_store::{RefreshToken, RefreshTokenStore};
use svc_auth::rotation::{RotationError, rotate};
use uuid::Uuid;

fn token(id: Uuid, family_id: Uuid) -> RefreshToken {
    RefreshToken {
        id,
        email: "cas@example.com".to_string(),
        family_id,
        used_at: None,
        replaced_by: None,
        created_at: Utc::now(),
    }
}

#[tokio::test]
async fn rotate_cas_conflict_revokes_family() {
    let nats = FabricTestNats::start().await.with_ephemeral_auth().await;
    let store = RefreshTokenStore::open(nats.fabric())
        .await
        .expect("open RefreshTokenStore on EPHEMERAL_AUTH");

    let family_id = Uuid::now_v7();
    let old = token(Uuid::now_v7(), family_id);
    store.store(&old).await.expect("store the original token");

    let (loaded, revision) = store
        .find_by_id(old.id)
        .await
        .expect("find the stored token")
        .expect("token present");

    let first_new = token(Uuid::now_v7(), family_id);
    rotate(&store, &loaded, revision, &first_new)
        .await
        .expect("first rotation wins the CAS");

    let second_new = token(Uuid::now_v7(), family_id);
    let outcome = rotate(&store, &loaded, revision, &second_new).await;
    assert!(
        matches!(outcome, Err(RotationError::Reuse(f)) if f == family_id),
        "a stale revision must lose the CAS and revoke the family, got {outcome:?}"
    );

    assert!(
        store.is_family_revoked(family_id).await,
        "the CAS-conflict branch must have revoked the family"
    );

    nats.shutdown().await;
}

#[tokio::test]
async fn rotate_used_at_guard_revokes_family() {
    let nats = FabricTestNats::start().await.with_ephemeral_auth().await;
    let store = RefreshTokenStore::open(nats.fabric())
        .await
        .expect("open RefreshTokenStore on EPHEMERAL_AUTH");

    let family_id = Uuid::now_v7();
    let mut already_used = token(Uuid::now_v7(), family_id);
    already_used.used_at = Some(Utc::now());

    let (_, revision) = {
        store
            .store(&already_used)
            .await
            .expect("store the already-used token");
        store
            .find_by_id(already_used.id)
            .await
            .expect("find the stored token")
            .expect("token present")
    };

    let new = token(Uuid::now_v7(), family_id);
    let outcome = rotate(&store, &already_used, revision, &new).await;
    assert!(
        matches!(outcome, Err(RotationError::Reuse(f)) if f == family_id),
        "replaying a used token must revoke the family, got {outcome:?}"
    );

    assert!(
        store.is_family_revoked(family_id).await,
        "the used_at-guard branch must have revoked the family"
    );

    nats.shutdown().await;
}
