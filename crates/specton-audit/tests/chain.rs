//! Chain integrity tests for InMemoryAudit (no Postgres required).

use specton_audit::{
    Actor, AuditEvent, AuditQuery, AuditSink, Category, InMemoryAudit, Outcome, Subject,
};

fn push_event(action: &str) -> AuditEvent {
    AuditEvent::success(Category::Push, action, Actor::system()).with_subject(Subject {
        tenant: Some("acme".into()),
        project: Some("api".into()),
        repo: Some("api".into()),
        reference: Some("v1".into()),
        digest: Some("sha256:abc".into()),
    })
}

#[tokio::test]
async fn append_query_and_verify_ok() {
    let sink = InMemoryAudit::for_tests();
    let a = sink.append(push_event("manifest.push")).await.unwrap();
    let b = sink.append(push_event("manifest.push")).await.unwrap();
    let c = sink.append(push_event("manifest.delete")).await.unwrap();
    assert_eq!(a, 1);
    assert_eq!(b, 2);
    assert_eq!(c, 3);

    let recent = sink.query(AuditQuery::recent(10)).await.unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].id, 3); // newest first

    let verdict = sink.verify_chain(1, 3).await.unwrap();
    assert!(verdict.ok, "{verdict:?}");
    assert_eq!(verdict.checked, 3);
}

#[tokio::test]
async fn tamper_breaks_chain() {
    let sink = InMemoryAudit::for_tests();
    sink.append(push_event("manifest.push")).await.unwrap();
    sink.append(push_event("manifest.push")).await.unwrap();
    sink.append(push_event("manifest.push")).await.unwrap();

    specton_audit::memory::tamper_row_hash_for_test(&sink, 2).await;

    let verdict = sink.verify_chain(1, 3).await.unwrap();
    assert!(!verdict.ok);
    assert_eq!(verdict.broken_at, Some(2));
}

#[tokio::test]
async fn key_rotation_still_verifies() {
    let mut sink = InMemoryAudit::for_tests();
    sink.append(push_event("manifest.push")).await.unwrap();
    sink.append(push_event("manifest.push")).await.unwrap();

    sink.register_and_activate("v2", b"second-hmac-key-32-bytes-long!!!!");
    sink.append(push_event("manifest.push")).await.unwrap();

    let verdict = sink.verify_chain(1, 3).await.unwrap();
    assert!(verdict.ok, "{verdict:?}");
    assert_eq!(verdict.checked, 3);

    let row3 = sink.get(3).await.unwrap();
    assert_eq!(row3.hmac_key_id, "v2");
}

#[tokio::test]
async fn filter_by_category_and_actor() {
    let sink = InMemoryAudit::for_tests();
    sink.append(push_event("manifest.push")).await.unwrap();
    sink.append(
        AuditEvent::success(
            Category::Delete,
            "manifest.delete",
            Actor {
                sub: "alice".into(),
                role: None,
                source_ip: None,
                ua: None,
            },
        )
        .with_subject(Subject {
            tenant: Some("acme".into()),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    let deletes = sink
        .query(AuditQuery {
            category: Some(Category::Delete),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].event.actor.sub, "alice");

    let by_actor = sink
        .query(AuditQuery {
            actor: Some("alice".into()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_actor.len(), 1);
}

#[tokio::test]
async fn failure_outcome_round_trips() {
    let sink = InMemoryAudit::for_tests();
    let mut event = AuditEvent::success(Category::Auth, "token.issue", Actor::system());
    event.outcome = Outcome::Failure {
        code: "rate_limited".into(),
    };
    let id = sink.append(event).await.unwrap();
    let row = sink.get(id).await.unwrap();
    assert_eq!(row.event.outcome.error_code(), Some("rate_limited"));
}
