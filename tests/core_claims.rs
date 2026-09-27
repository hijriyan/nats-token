use nats_token::{
    decode, decode_account_claims, decode_operator_claims, decode_user_claims, AccountClaims,
    ClusterTraffic, DecodedClaims, JetStreamTieredLimits, NatsLimits, OperatorClaims,
    OperatorLimits, UserClaims, CLUSTER_TRAFFIC_OWNER, CLUSTER_TRAFFIC_SYSTEM, NO_LIMIT,
};
use nkeys::KeyPair;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn public_nats_limits_match_upstream_wire_fields() {
    let empty = NatsLimits::default();
    assert_eq!((empty.subs, empty.data, empty.payload), (0, 0, 0));
    assert_eq!(serde_json::to_value(&empty).unwrap(), serde_json::json!({}));
    assert_eq!(serde_json::from_str::<NatsLimits>("{}").unwrap(), empty);

    let limits = NatsLimits {
        subs: NO_LIMIT,
        data: 1024,
        payload: 256,
    };
    let wire = serde_json::json!({"subs": -1, "data": 1024, "payload": 256});
    assert_eq!(serde_json::to_value(&limits).unwrap(), wire);
    assert_eq!(serde_json::from_value::<NatsLimits>(wire).unwrap(), limits);
}

#[test]
fn public_operator_limits_preserve_account_limits_api_and_wire() {
    let defaults = OperatorLimits::default();
    assert_eq!(defaults, OperatorLimits::default());
    assert_eq!(
        defaults.nats,
        NatsLimits {
            subs: -1,
            data: -1,
            payload: -1
        }
    );
    assert_eq!(defaults.account, nats_token::AccountLimits::default());
    assert_eq!(defaults.jetstream, nats_token::JetStreamLimits::default());
    assert!(defaults.tiered.is_empty());
    assert_eq!(
        serde_json::to_value(&defaults).unwrap(),
        serde_json::json!({
            "subs": -1, "data": -1, "payload": -1, "imports": -1,
            "exports": -1, "wildcards": true, "conn": -1, "leaf": -1
        })
    );

    let empty = OperatorLimits {
        nats: NatsLimits::default(),
        account: nats_token::AccountLimits {
            subscriptions: 0,
            data: 0,
            payload: 0,
            imports: 0,
            exports: 0,
            wildcard_exports: false,
            connections: 0,
            leaf_connections: 0,
            disallow_bearer: false,
            ..Default::default()
        },
        jetstream: nats_token::JetStreamLimits::default(),
        tiered: JetStreamTieredLimits::default(),
    };
    assert_eq!(serde_json::to_value(&empty).unwrap(), serde_json::json!({}));
    assert!(empty.tiered.is_empty());
    assert_eq!(
        serde_json::to_value(&empty.tiered).unwrap(),
        serde_json::json!({})
    );

    let limits = OperatorLimits {
        nats: NatsLimits {
            subs: 1,
            data: 2,
            payload: 3,
        },
        account: nats_token::AccountLimits {
            imports: 4,
            exports: 5,
            wildcard_exports: true,
            connections: 6,
            leaf_connections: 7,
            disallow_bearer: true,
            ..Default::default()
        },
        jetstream: nats_token::JetStreamLimits {
            memory_storage: 8,
            disk_storage: 9,
            streams: 10,
            consumers: 11,
            max_ack_pending: 12,
            memory_max_stream_bytes: 13,
            disk_max_stream_bytes: 14,
            max_bytes_required: true,
        },
        tiered: JetStreamTieredLimits::from([(
            "R3".into(),
            nats_token::JetStreamLimits {
                memory_storage: NO_LIMIT,
                ..Default::default()
            },
        )]),
    };
    let wire = serde_json::json!({
        "subs": 1, "data": 2, "payload": 3, "imports": 4, "exports": 5,
        "wildcards": true, "conn": 6, "leaf": 7, "disallow_bearer": true,
        "mem_storage": 8, "disk_storage": 9, "streams": 10, "consumer": 11,
        "max_ack_pending": 12, "mem_max_stream_bytes": 13,
        "disk_max_stream_bytes": 14, "max_bytes_required": true,
        "tiered_limits": {"R3": {"mem_storage": -1}}
    });
    assert_eq!(serde_json::to_value(&limits).unwrap(), wire);
    assert_eq!(
        serde_json::from_value::<OperatorLimits>(wire.clone()).unwrap(),
        limits
    );
    let mut claim = AccountClaims::new(KeyPair::new_account().public_key()).unwrap();
    claim.account.limits = limits.account.clone();
    claim.account.limits.jetstream = limits.jetstream.clone();
    let account_wire = serde_json::to_value(&claim).unwrap();
    assert_eq!(account_wire["nats"]["limits"]["imports"], 4);
    assert_eq!(account_wire["nats"]["limits"]["mem_storage"], 8);
    let decoded: AccountClaims = serde_json::from_value(account_wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), account_wire);
}

#[test]
fn typed_decoder_helpers_return_expected_claims() {
    let operator = KeyPair::new_operator();
    let mut operator_claim = OperatorClaims::new(operator.public_key()).unwrap();
    let operator_token = operator_claim.encode(&operator).unwrap();
    assert!(decode_operator_claims(&operator_token).is_ok());
    assert!(decode_account_claims(&operator_token).is_err());

    let account = KeyPair::new_account();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    let account_token = account_claim.encode(&operator).unwrap();
    assert!(decode_account_claims(&account_token).is_ok());

    let user = KeyPair::new_user();
    let mut user_claim = UserClaims::new(user.public_key()).unwrap();
    let user_token = user_claim.encode(&account).unwrap();
    assert!(decode_user_claims(&user_token).is_ok());
}

#[test]
fn operator_round_trip_requires_operator_signer() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim
        .operator
        .signing_keys
        .push(KeyPair::new_operator().public_key());

    let token = claim.encode(&operator).unwrap();
    assert!(matches!(
        decode(&token).unwrap(),
        DecodedClaims::Operator(_)
    ));
    assert!(claim.encode(&KeyPair::new_account()).is_err());
}

#[test]
fn account_jetstream_enablement_checks_tiered_limits() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.limits.tiered.insert(
        "gold".into(),
        nats_token::JetStreamLimits {
            memory_storage: 1024,
            ..Default::default()
        },
    );
    assert!(claim.account.limits.is_jetstream_enabled());
}

#[test]
fn account_jetstream_defaults_are_disabled_and_tiered_limits_enable_it() {
    let account = KeyPair::new_account();
    let claim = AccountClaims::new(account.public_key()).unwrap();
    assert!(!claim.account.limits.jetstream.is_enabled());
    let mut enabled = claim;
    enabled.account.limits.jetstream.memory_storage = 1024;
    assert!(enabled.account.limits.jetstream.is_enabled());
    enabled
        .account
        .limits
        .tiered
        .insert("gold".into(), nats_token::JetStreamLimits::default());
    assert!(enabled.account.limits.is_invalid_tiered_configuration());
}

#[test]
fn decoded_v2_account_with_tiered_limits_clears_ordinary_jetstream_limits() {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.limits.jetstream.memory_storage = 1;
    claim.account.limits.tiered.insert(
        "gold".into(),
        nats_token::JetStreamLimits {
            memory_storage: 2,
            ..Default::default()
        },
    );

    let token = claim.encode(&operator).unwrap();
    let decoded = decode_account_claims(&token).unwrap();

    assert_eq!(decoded.account.limits.jetstream, Default::default());
    assert_eq!(decoded.account.limits.tiered["gold"].memory_storage, 2);
}

#[test]
fn account_cluster_traffic_is_typed_and_matches_upstream_wire_values() {
    assert_eq!(CLUSTER_TRAFFIC_SYSTEM, ClusterTraffic::System);
    assert_eq!(CLUSTER_TRAFFIC_OWNER, ClusterTraffic::Owner);
    assert_eq!(ClusterTraffic::default().as_str(), "");
    assert_eq!(ClusterTraffic::System.as_str(), "system");
    assert_eq!(ClusterTraffic::Owner.as_str(), "owner");
    assert!(ClusterTraffic::default().is_valid());
    assert!(ClusterTraffic::System.is_valid());
    assert!(ClusterTraffic::Owner.is_valid());
    assert!(!ClusterTraffic::from("invalid").is_valid());

    let mut claim = AccountClaims::new(KeyPair::new_account().public_key()).unwrap();
    assert!(serde_json::to_value(&claim).unwrap()["nats"]
        .as_object()
        .unwrap()
        .get("cluster_traffic")
        .is_none());

    for (mode, wire) in [
        (ClusterTraffic::System, "system"),
        (ClusterTraffic::Owner, "owner"),
    ] {
        claim.account.cluster_traffic = wire.to_owned();
        let value = serde_json::to_value(&claim).unwrap();
        assert_eq!(value["nats"]["cluster_traffic"], wire);
        let decoded: AccountClaims = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.account.cluster_traffic, wire);
        assert_eq!(ClusterTraffic::from(decoded.account.cluster_traffic), mode);
    }
}

#[test]
fn account_cluster_traffic_rejects_unknown_wire_value() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.cluster_traffic = "invalid".into();
    let mut invalid = nats_token::ValidationResults::default();
    claim.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    for wire in ["invalid", "System", "OWNER", " system", "owner "] {
        let mut decoded: AccountClaims = serde_json::from_value(serde_json::json!({
            "nats": {"cluster_traffic": wire}
        }))
        .unwrap();
        assert_eq!(decoded.account.cluster_traffic, wire);
        assert_eq!(
            serde_json::to_value(&decoded).unwrap()["nats"]["cluster_traffic"],
            wire
        );
        let mut results = nats_token::ValidationResults::default();
        decoded.validate(&mut results);
        assert_eq!(results.issues, invalid.issues);
        assert_eq!(results.errors()[0].description, "invalid cluster traffic");
    }

    for wire in [
        serde_json::json!({}),
        serde_json::json!({"cluster_traffic": ""}),
        serde_json::json!({"cluster_traffic": "system"}),
        serde_json::json!({"cluster_traffic": "owner"}),
    ] {
        let mut decoded: AccountClaims =
            serde_json::from_value(serde_json::json!({"nats": wire})).unwrap();
        let mut results = nats_token::ValidationResults::default();
        decoded.validate(&mut results);
        assert!(results.is_empty());
        if decoded.account.cluster_traffic.is_empty() {
            assert_eq!(decoded.account.cluster_traffic, "");
            assert!(serde_json::to_value(decoded).unwrap()["nats"]
                .as_object()
                .unwrap()
                .get("cluster_traffic")
                .is_none());
        }
    }
    claim.account.cluster_traffic = String::from("owner");
    assert_eq!(
        ClusterTraffic::from(claim.account.cluster_traffic),
        ClusterTraffic::Owner
    );
    for wire in ["null", "1", "true", "{}", "[]"] {
        assert!(serde_json::from_str::<ClusterTraffic>(wire).is_err());
    }
}

#[test]
fn account_limits_distinguish_disabled_and_unlimited_jetstream() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    assert!(!claim.account.limits.is_unlimited());
    assert!(!claim.account.limits.jetstream.is_unlimited());
    claim.account.limits.jetstream.memory_storage = -1;
    claim.account.limits.jetstream.disk_storage = -1;
    claim.account.limits.jetstream.streams = -1;
    claim.account.limits.jetstream.consumers = -1;
    assert!(claim.account.limits.jetstream.is_unlimited());
    assert!(claim.account.limits.is_unlimited());
}

#[test]
fn account_wire_omits_zero_optional_fields() {
    let claim = AccountClaims::new(KeyPair::new_account().public_key()).unwrap();
    let nats = serde_json::to_value(claim).unwrap()["nats"].clone();
    let limits = &nats["limits"];

    for field in [
        "mem_storage",
        "disk_storage",
        "streams",
        "consumer",
        "max_ack_pending",
        "mem_max_stream_bytes",
        "disk_max_stream_bytes",
        "max_bytes_required",
        "disallow_bearer",
        "tiered_limits",
    ] {
        assert!(limits.get(field).is_none(), "{field}");
    }
    for field in [
        "imports",
        "exports",
        "wildcards",
        "conn",
        "leaf",
        "subs",
        "data",
        "payload",
    ] {
        assert!(limits.get(field).is_some(), "{field}");
    }
    assert_eq!(nats["default_permissions"]["pub"], serde_json::json!({}));
    assert_eq!(nats["default_permissions"]["sub"], serde_json::json!({}));
    assert!(nats["default_permissions"].get("resp").is_none());
    for field in [
        "description",
        "info_url",
        "signing_keys",
        "imports",
        "exports",
        "mappings",
        "authorization",
        "trace",
        "cluster_traffic",
        "tags",
    ] {
        assert!(nats.get(field).is_none(), "{field}");
    }
}

#[test]
fn account_connection_limits_use_upstream_wire_names() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.limits.connections = 10;
    claim.account.limits.leaf_connections = 2;
    claim.account.limits.disallow_bearer = true;
    let json = serde_json::to_value(&claim).unwrap();
    assert_eq!(json["nats"]["limits"]["conn"], 10);
    assert_eq!(json["nats"]["limits"]["leaf"], 2);
    assert_eq!(json["nats"]["limits"]["disallow_bearer"], true);
}

#[test]
fn account_defaults_are_unlimited_and_accept_operator_signer() {
    let account = KeyPair::new_account();
    let operator = KeyPair::new_operator();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();

    assert_eq!(claim.account.limits.subscriptions, NO_LIMIT);
    assert_eq!(claim.account.limits.data, NO_LIMIT);
    assert_eq!(claim.account.limits.payload, NO_LIMIT);
    assert_eq!(claim.account.limits.imports, NO_LIMIT);
    assert_eq!(claim.account.limits.exports, NO_LIMIT);
    assert!(claim.account.limits.wildcard_exports);

    let token = claim.encode(&operator).unwrap();
    assert!(matches!(decode(&token).unwrap(), DecodedClaims::Account(_)));
    assert!(claim.encode(&KeyPair::new_user()).is_err());
}

#[test]
fn user_round_trip_requires_account_signer() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.user.issuer_account = account.public_key();

    let token = claim.encode(&account).unwrap();
    assert!(matches!(decode(&token).unwrap(), DecodedClaims::User(_)));
    assert!(claim.encode(&KeyPair::new_operator()).is_err());
}

#[test]
fn user_revocation_round_trip_covers_specific_and_wildcard_users() {
    let account = KeyPair::new_account();
    let first = KeyPair::new_user();
    let second = KeyPair::new_user();
    let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
    let mut claim = AccountClaims::new(account.public_key()).unwrap();

    assert!(!claim
        .account
        .revocations
        .is_revoked(&first.public_key(), at(59)));
    claim.revoke_at(&first.public_key(), at(60));
    assert!(claim
        .account
        .revocations
        .is_revoked(&first.public_key(), at(60)));
    assert!(!claim
        .account
        .revocations
        .is_revoked(&second.public_key(), at(60)));
    claim.revoke_at("*", at(30));
    assert!(claim
        .account
        .revocations
        .is_revoked(&second.public_key(), at(30)));

    let wire = serde_json::to_value(&claim).unwrap();
    let decoded: AccountClaims = serde_json::from_value(wire).unwrap();
    assert!(decoded
        .account
        .revocations
        .is_revoked(&first.public_key(), at(60)));
    claim.clear_revocation("*");
    assert!(!claim
        .account
        .revocations
        .is_revoked(&second.public_key(), at(30)));
}

#[test]
fn account_revoke_uses_current_time() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    let before = SystemTime::now() - Duration::from_secs(2);
    claim.revoke(&user.public_key());
    let after = SystemTime::now() + Duration::from_secs(2);
    assert!(claim
        .account
        .revocations
        .is_revoked(&user.public_key(), before));
    assert!(!claim
        .account
        .revocations
        .is_revoked(&user.public_key(), after));
}

#[test]
fn account_revocation_is_inclusive_and_clearable() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    let mut user_claim = UserClaims::new(user.public_key()).unwrap();
    user_claim.claims.issued_at = 100;
    account_claim.revoke_at(&user.public_key(), UNIX_EPOCH + Duration::from_secs(100));
    assert!(account_claim.is_claim_revoked(&user_claim));
    account_claim.clear_revocation(&user.public_key());
    assert!(!account_claim.is_claim_revoked(&user_claim));
}

#[test]
fn account_revocations_survive_json_round_trip() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.revoke_at("UKEY", UNIX_EPOCH + Duration::from_secs(10));
    let json = serde_json::to_string(&claim).unwrap();
    assert!(json.contains("revocations"));
    let decoded: AccountClaims = serde_json::from_str(&json).unwrap();
    assert!(decoded
        .account
        .revocations
        .is_revoked("UKEY", UNIX_EPOCH + Duration::from_secs(10)));
}

#[test]
fn invalid_user_claim_is_considered_revoked() {
    let account = KeyPair::new_account();
    let account_claim = AccountClaims::new(account.public_key()).unwrap();
    let mut user_claim = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
    user_claim.claims.issued_at = 0;
    assert!(account_claim.is_claim_revoked(&user_claim));
}

#[test]
fn account_revocation_handles_negative_issued_at() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    let mut user_claim = UserClaims::new(user.public_key()).unwrap();
    for issued_at in [i64::MIN, -1, i64::MAX] {
        user_claim.claims.issued_at = issued_at;
        assert!(!account_claim.is_claim_revoked(&user_claim));
    }
    for key in [user.public_key(), "*".into()] {
        for cutoff in [i64::MIN, -1, i64::MAX] {
            account_claim.account.revocations =
                serde_json::from_value(serde_json::json!({key.clone(): cutoff})).unwrap();
            for issued_at in [i64::MIN, -1, 0, 1, i64::MAX] {
                user_claim.claims.issued_at = issued_at;
                assert_eq!(
                    account_claim.is_claim_revoked(&user_claim),
                    issued_at == 0 || cutoff >= issued_at
                );
            }
        }
    }
    account_claim.account.revocations = Default::default();
    user_claim.claims.issued_at = -1;
    assert!(!account_claim.is_claim_revoked(&user_claim));
    account_claim.revoke_at(&user.public_key(), UNIX_EPOCH - Duration::from_secs(1));
    assert!(account_claim.is_claim_revoked(&user_claim));
}

#[test]
fn typed_claims_reject_wrong_subject_prefix() {
    assert!(OperatorClaims::new(KeyPair::new_user().public_key())
        .unwrap()
        .encode(&KeyPair::new_operator())
        .is_err());
    assert!(AccountClaims::new(KeyPair::new_user().public_key())
        .unwrap()
        .encode(&KeyPair::new_account())
        .is_err());
    assert!(UserClaims::new(KeyPair::new_account().public_key())
        .unwrap()
        .encode(&KeyPair::new_account())
        .is_err());
}

#[test]
fn operator_validation_rejects_malformed_account_server_url() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim.operator.account_server_url = "https://[::1".into();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn operator_validation_rejects_negative_asserted_server_version() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim.operator.assert_server_version = "-1.2.3".into();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn account_validation_warns_on_self_signed_operator_limits() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.claims.issuer = account.public_key();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert_eq!(results.warnings().len(), 1);
    assert!(!results.is_blocking(true));
    claim.claims.issuer = KeyPair::new_operator().public_key();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_empty());
}

#[test]
fn account_validation_allows_account_signed_zero_limits() {
    let mut claim = AccountClaims::new(KeyPair::new_account().public_key()).unwrap();
    claim.claims.issuer = KeyPair::new_account().public_key();
    claim.account.limits = nats_token::AccountLimits {
        subscriptions: 0,
        data: 0,
        payload: 0,
        imports: 0,
        exports: 0,
        wildcard_exports: false,
        connections: 0,
        leaf_connections: 0,
        ..Default::default()
    };
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_empty(), "{:?}", results.issues);
}
