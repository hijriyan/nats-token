use nats_token::policy::{
    CIDRList, Permission, Permissions, TimeRange, UserLimits, UserPermissionLimits, UserScope,
};
use nats_token::{UserClaims, ValidationResults};
use nkeys::KeyPair;

#[test]
fn cidr_list_json_accepts_array_and_csv() {
    let array: CIDRList = serde_json::from_str("[\"10.0.0.0/8\",\"192.168.0.0/16\"]").unwrap();
    assert_eq!(array.len(), 2);
    let csv: CIDRList = serde_json::from_str("\"10.0.0.0/8, 192.168.0.0/16\"").unwrap();
    assert_eq!(csv.len(), 2);
}

#[test]
fn cidr_list_csv_normalizes_like_set() {
    let cidrs: CIDRList = serde_json::from_str("\" 10.0.0.0/8, 10.0.0.0/8, FD00::/8 \"").unwrap();
    assert_eq!(cidrs.len(), 2);
    assert!(cidrs.contains("fd00::/8"));
}

#[test]
fn cidr_list_collection_helpers_match_upstream() {
    let mut cidrs = CIDRList::default();
    cidrs.add([" 10.0.0.0/8 ", "10.0.0.0/8", "192.168.0.0/16"]);
    assert!(cidrs.contains("10.0.0.0/8"));
    assert_eq!(cidrs.len(), 2);
    cidrs.remove(["10.0.0.0/8"]);
    assert!(!cidrs.contains("10.0.0.0/8"));
    cidrs.set(" 172.16.0.0/12, 192.168.0.0/16 ");
    assert_eq!(cidrs.len(), 2);
    assert!(cidrs.contains("172.16.0.0/12"));
}

#[test]
fn cidr_list_parses_csv_and_rejects_invalid_network() {
    let cidrs = CIDRList::from_csv("10.0.0.0/8, 192.168.1.0/24");
    assert_eq!(cidrs.len(), 2);
    let mut invalid = CIDRList::from_csv("not-a-network");
    let mut results = ValidationResults::default();
    invalid.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn time_range_requires_valid_start_and_end() {
    let range = TimeRange {
        start: "25:00:00".into(),
        end: "12:00:00".into(),
    };
    let mut results = ValidationResults::default();
    range.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn permissions_reject_queue_publish_but_allow_queue_subscribe() {
    let mut publish = Permission::default();
    publish.allow.add(["orders workers"]);
    let mut subscribe = Permission::default();
    subscribe.allow.add(["orders workers"]);
    let permissions = Permissions {
        publish,
        subscribe,
        ..Default::default()
    };
    let mut results = ValidationResults::default();
    permissions.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn user_connection_types_survive_round_trip() {
    let user = nkeys::KeyPair::new_user();
    let account = nkeys::KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    let connection_types = [
        nats_token::CONNECTION_TYPE_STANDARD,
        nats_token::CONNECTION_TYPE_WEBSOCKET,
        nats_token::CONNECTION_TYPE_LEAFNODE,
        nats_token::CONNECTION_TYPE_LEAFNODE_WS,
        nats_token::CONNECTION_TYPE_MQTT,
        nats_token::CONNECTION_TYPE_MQTT_WS,
        nats_token::CONNECTION_TYPE_IN_PROCESS,
    ];
    assert_eq!(
        connection_types,
        [
            "STANDARD",
            "WEBSOCKET",
            "LEAFNODE",
            "LEAFNODE_WS",
            "MQTT",
            "MQTT_WS",
            "IN_PROCESS",
        ]
    );
    claim.user.allowed_connection_types =
        Some(connection_types.into_iter().map(String::from).collect());
    let wire = serde_json::to_value(&claim.user).unwrap();
    assert_eq!(
        wire["allowed_connection_types"],
        serde_json::json!(connection_types)
    );
    assert_eq!(
        serde_json::from_value::<nats_token::User>(wire).unwrap(),
        claim.user
    );
    let token = claim.encode(&account).unwrap();
    let decoded = nats_token::decode_user_claims(&token).unwrap();
    assert_eq!(
        decoded.user.allowed_connection_types,
        claim.user.allowed_connection_types
    );
}

#[test]
fn user_permission_template_omits_only_zero_fields() {
    let template = UserPermissionLimits::default();
    let value = serde_json::to_value(&template).unwrap();
    assert!(value.get("bearer_token").is_none());
    assert!(value.get("proxy_required").is_none());
    assert!(value.get("allowed_connection_types").is_none());

    let value = serde_json::to_value(UserPermissionLimits {
        bearer_token: true,
        proxy_required: true,
        allowed_connection_types: Some(vec!["STANDARD".into()]),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(value["bearer_token"], true);
    assert_eq!(value["proxy_required"], true);
    assert_eq!(
        value["allowed_connection_types"],
        serde_json::json!(["STANDARD"])
    );
}

#[test]
fn user_permission_template_omits_empty_connection_types() {
    let absent = serde_json::to_value(UserPermissionLimits::default()).unwrap();
    let empty = serde_json::to_value(UserPermissionLimits {
        allowed_connection_types: Some(vec![]),
        ..Default::default()
    })
    .unwrap();
    assert!(absent.get("allowed_connection_types").is_none());
    assert!(empty.get("allowed_connection_types").is_none());
}

#[test]
fn user_claim_empty_permissions_distinguishes_absent_and_empty_connection_types() {
    let user = KeyPair::new_user();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.set_scoped(true);
    assert!(claim.has_empty_permissions());
    claim.user.allowed_connection_types = Some(vec![]);
    assert!(!claim.has_empty_permissions());
    claim.set_scoped(true);
    assert!(claim.has_empty_permissions());
}

#[test]
fn user_proxy_required_decodes_from_wire() {
    let value = serde_json::json!({"nats": {"proxy_required": true}});
    let claim: UserClaims = serde_json::from_value(value).unwrap();
    assert!(claim.user.proxy_required);
}

#[test]
fn user_proxy_required_round_trips_true_and_omits_false() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.user.proxy_required = true;
    let token = claim.encode(&account).unwrap();
    assert!(
        nats_token::decode_user_claims(&token)
            .unwrap()
            .user
            .proxy_required
    );

    claim.user.proxy_required = false;
    let value = serde_json::to_value(&claim).unwrap();
    assert!(value["nats"].get("proxy_required").is_none());
}

#[test]
fn scoped_user_proxy_required_blocks_scope_and_reset_clears_it() {
    let signer = KeyPair::new_account();
    let user = KeyPair::new_user();
    let scope = UserScope {
        kind: "user_scope".into(),
        key: signer.public_key(),
        role: "reader".into(),
        ..Default::default()
    };
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.claims.issuer = signer.public_key();
    claim.set_scoped(true);
    assert!(claim.has_empty_permissions());
    claim.user.proxy_required = true;
    assert!(!claim.has_empty_permissions());
    assert!(scope.validate_user(&claim).is_err());
    claim.set_scoped(true);
    assert!(!claim.user.proxy_required);
    assert!(scope.validate_user(&claim).is_ok());
    claim.user.proxy_required = true;
    claim.set_scoped(false);
    assert!(claim.user.proxy_required);
}

#[test]
fn user_claim_convenience_helpers_expose_bearer_and_tags() {
    let user = nkeys::KeyPair::new_user();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.user.bearer_token = true;
    claim.user.tags.add(["ops"]);
    assert!(claim.is_bearer_token());
    assert!(claim.get_tags().contains("ops"));
}

#[test]
fn user_claim_nats_limits_default_unlimited_and_round_trip() {
    let user = nkeys::KeyPair::new_user();
    let account = nkeys::KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    assert_eq!(claim.user.limits.subscriptions, nats_token::NO_LIMIT);
    assert_eq!(claim.user.limits.data, nats_token::NO_LIMIT);
    assert_eq!(claim.user.limits.payload, nats_token::NO_LIMIT);
    claim.user.limits.payload = 10;
    let token = claim.encode(&account).unwrap();
    assert_eq!(
        nats_token::decode_user_claims(&token)
            .unwrap()
            .user
            .limits
            .payload,
        10
    );
}

#[test]
fn user_claim_validation_includes_permissions_and_limits() {
    let user = KeyPair::new_user();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.user.permissions.publish.allow.add(["orders workers"]);
    claim.user.limits.src = CIDRList::from_csv("not-a-network");
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn user_limits_validate_cidrs_times_and_timezone() {
    let limits = UserLimits {
        src: CIDRList::from_csv("10.0.0.0/8"),
        times: vec![TimeRange {
            start: "09:00:00".into(),
            end: "17:00:00".into(),
        }],
        locale: "Invalid/Timezone".into(),
        ..Default::default()
    };
    let mut results = ValidationResults::default();
    limits.validate(&mut results);
    assert!(results.is_blocking(false));
}
