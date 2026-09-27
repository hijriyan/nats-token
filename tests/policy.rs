use nats_token::policy::{Permission, RevocationList, StringList, Subject, TagList};
use nats_token::ValidationResults;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn subject_containment_matches_nats_wildcards() {
    assert!(Subject::from("foo.bar").is_contained_in(&Subject::from("foo.*")));
    assert!(Subject::from("foo.bar.baz").is_contained_in(&Subject::from("foo.>")));
    assert!(!Subject::from("foo.bar").is_contained_in(&Subject::from("bar.>")));
}

#[test]
fn lists_deduplicate_and_normalize_tags() {
    let mut strings = StringList::default();
    strings.add(["a", "a", ""]);
    assert_eq!(strings, vec!["a"]);
    let mut tags = TagList::default();
    tags.add([" Foo ", "foo"]);
    assert_eq!(tags, vec!["foo"]);
}

#[test]
fn permission_validation_rejects_queue_publish() {
    let mut permission = Permission::default();
    permission.allow.add(["subject queue"]);
    let mut results = ValidationResults::default();
    permission.validate(&mut results, false);
    assert!(results.is_blocking(false));
}

#[test]
fn revocation_is_inclusive_and_compacts() {
    let mut revocations = RevocationList::default();
    let when = UNIX_EPOCH + Duration::from_secs(100);
    revocations.revoke("UKEY", when);
    assert!(revocations.is_revoked("UKEY", when));
    revocations.revoke("*", when);
    let removed = revocations.maybe_compact();
    assert!(removed.iter().any(|entry| entry.public_key == "UKEY"));
}

#[test]
fn revocation_compaction_matches_v2_parity() {
    let mut revocations = RevocationList::default();
    revocations.revoke("UKEY1", UNIX_EPOCH + Duration::from_secs(100));
    revocations.revoke("UKEY2", UNIX_EPOCH + Duration::from_secs(200));
    revocations.revoke("UKEY3", UNIX_EPOCH + Duration::from_secs(300));

    assert_eq!(revocations.maybe_compact(), Vec::new());
    assert_eq!(
        serde_json::to_value(&revocations).unwrap(),
        serde_json::json!({"UKEY1": 100, "UKEY2": 200, "UKEY3": 300})
    );

    revocations.revoke("*", UNIX_EPOCH + Duration::from_secs(150));
    assert_eq!(
        revocations.maybe_compact(),
        vec![nats_token::policy::RevocationEntry {
            public_key: "UKEY1".into(),
            timestamp: 100,
        }]
    );
    assert_eq!(
        serde_json::to_value(&revocations).unwrap(),
        serde_json::json!({
            "*": 150,
            "UKEY2": 200,
            "UKEY3": 300,
        })
    );

    revocations.revoke("*", UNIX_EPOCH + Duration::from_secs(350));
    assert_eq!(
        revocations.maybe_compact(),
        vec![
            nats_token::policy::RevocationEntry {
                public_key: "UKEY2".into(),
                timestamp: 200,
            },
            nats_token::policy::RevocationEntry {
                public_key: "UKEY3".into(),
                timestamp: 300,
            },
        ]
    );
    assert_eq!(
        serde_json::to_value(&revocations).unwrap(),
        serde_json::json!({"*": 350})
    );
}

#[test]
fn revocation_floors_pre_epoch_fractional_seconds() {
    let mut revocations = RevocationList::default();
    revocations.revoke("UKEY", UNIX_EPOCH - Duration::from_millis(500));
    assert_eq!(serde_json::to_value(&revocations).unwrap()["UKEY"], -1);
    assert!(revocations.is_revoked("UKEY", UNIX_EPOCH - Duration::from_secs(1)));
    assert!(!revocations.is_revoked("UKEY", UNIX_EPOCH));
    let revocations: RevocationList = serde_json::from_str(r#"{"UKEY":-1}"#).unwrap();
    assert!(revocations.is_revoked("UKEY", UNIX_EPOCH - Duration::from_nanos(1)));
}
