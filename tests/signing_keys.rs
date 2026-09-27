use nats_token::policy::{SigningKey, SigningKeys, UserScope};
use nats_token::{AccountClaims, UserClaims, ValidationResults};
use nkeys::KeyPair;

#[test]
fn signing_keys_accept_account_keys_and_reject_other_prefixes() {
    let mut keys = SigningKeys::default();
    keys.add(SigningKey::Key(KeyPair::new_account().public_key()));
    keys.add(SigningKey::Key(KeyPair::new_user().public_key()));
    let mut results = ValidationResults::default();
    keys.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn new_user_scope_uses_unlimited_nats_limits() {
    let scope = UserScope::new();
    assert_eq!(scope.kind, "user_scope");
    assert_eq!(scope.template.limits.subscriptions, nats_token::NO_LIMIT);
    assert_eq!(scope.template.limits.data, nats_token::NO_LIMIT);
    assert_eq!(scope.template.limits.payload, nats_token::NO_LIMIT);
}

#[test]
fn user_scope_helpers_clear_and_detect_restrictions() {
    let user = KeyPair::new_user();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    assert!(!claim.has_empty_permissions());
    claim.user.permissions.publish.allow.add(["orders"]);
    assert!(!claim.has_empty_permissions());
    claim.set_scoped(true);
    assert!(claim.has_empty_permissions());
    assert_eq!(claim.user.limits.subscriptions, 0);
    claim.set_scoped(false);
    assert_eq!(claim.user.limits.subscriptions, nats_token::NO_LIMIT);
}

#[test]
fn user_scope_requires_matching_issuer_and_empty_permissions() {
    let signer = KeyPair::new_account();
    let user = KeyPair::new_user();
    let scope = UserScope {
        kind: "user_scope".into(),
        key: signer.public_key(),
        role: "reader".into(),
        ..Default::default()
    };
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    claim.set_scoped(true);
    claim.claims.issuer = signer.public_key();
    assert!(scope.validate_user(&claim).is_ok());
    claim.user.permissions.publish.allow.add(["orders"]);
    assert!(scope.validate_user(&claim).is_err());
}

#[test]
fn signing_scope_json_rejects_unknown_kind() {
    let value = serde_json::json!([{
        "kind": "unknown_scope",
        "key": KeyPair::new_account().public_key(),
        "role": "reader",
        "template": {}
    }]);
    assert!(serde_json::from_value::<SigningKeys>(value).is_err());
}

#[test]
fn signing_scope_json_uses_upstream_shape() {
    let account = KeyPair::new_account();
    let mut keys = SigningKeys::default();
    keys.add(SigningKey::UserScope(Box::new(UserScope {
        kind: "user_scope".into(),
        key: account.public_key(),
        role: "reader".into(),
        ..Default::default()
    })));
    let value = serde_json::to_value(&keys).unwrap();
    assert_eq!(value[0]["kind"], "user_scope");
    assert!(value[0].get("template").is_some());
    assert_eq!(serde_json::from_value::<SigningKeys>(value).unwrap(), keys);
}

#[test]
fn signing_keys_deserialization_replaces_duplicate_public_key() {
    let account = KeyPair::new_account().public_key();
    let value = serde_json::json!([
        account,
        {
            "kind": "user_scope",
            "key": account,
            "role": "reader",
            "template": {}
        }
    ]);
    let keys: SigningKeys = serde_json::from_value(value).unwrap();
    assert_eq!(keys.keys().len(), 1);
    assert!(keys.get_scope(&account).is_some());
}

#[test]
fn signing_keys_replace_existing_entry_for_same_public_key() {
    let account = KeyPair::new_account().public_key();
    let mut keys = SigningKeys::default();
    keys.add(SigningKey::Key(account.clone()));
    keys.add(SigningKey::UserScope(Box::new(UserScope {
        kind: "user_scope".into(),
        key: account.clone(),
        role: "reader".into(),
        ..Default::default()
    })));
    assert_eq!(keys.keys(), vec![account.clone()]);
    assert!(keys.get_scope(&account).is_some());
}

#[test]
fn signing_keys_json_is_sorted_by_public_key() {
    let first = KeyPair::new_account().public_key();
    let second = KeyPair::new_account().public_key();
    let mut keys = SigningKeys::default();
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    keys.add(SigningKey::Key(expected[1].clone()));
    keys.add(SigningKey::Key(expected[0].clone()));
    assert_eq!(
        serde_json::to_value(&keys).unwrap(),
        serde_json::json!(expected)
    );
}

#[test]
fn signing_keys_support_sorted_keys_scope_lookup_and_remove() {
    let first = KeyPair::new_account().public_key();
    let second = KeyPair::new_account().public_key();
    let mut keys = SigningKeys::default();
    keys.add(SigningKey::Key(second.clone()));
    keys.add(SigningKey::UserScope(Box::new(UserScope {
        kind: "user_scope".into(),
        key: first.clone(),
        role: "reader".into(),
        ..Default::default()
    })));
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    assert_eq!(keys.keys(), expected);
    assert!(keys.get_scope(&first).is_some());
    keys.remove(&first);
    assert!(!keys.contains(&first));
}

#[test]
fn account_directly_signs_user_without_issuer_account() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let account_claim = AccountClaims::new(account.public_key()).unwrap();
    let mut user_claim = UserClaims::new(user.public_key()).unwrap();
    user_claim.claims.issuer = account.public_key();
    assert!(account_claim.did_sign(&user_claim));
}

#[test]
fn account_did_sign_activation_with_direct_or_registered_account() {
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let other = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .signing_keys
        .add(SigningKey::Key(signer.public_key()));

    let mut direct = nats_token::ActivationClaims::new(account.public_key()).unwrap();
    direct.claims.issuer = account.public_key();
    assert!(claim.did_sign_activation(&direct));
    direct.activation.issuer_account = other.public_key();
    assert!(claim.did_sign_activation(&direct));
    direct.claims.issuer = other.public_key();
    assert!(!claim.did_sign_activation(&direct));

    let mut registered = nats_token::ActivationClaims::new(account.public_key()).unwrap();
    registered.claims.issuer = signer.public_key();
    registered.activation.issuer_account = account.public_key();
    assert!(claim.did_sign_activation(&registered));

    registered.activation.issuer_account = other.public_key();
    assert!(!claim.did_sign_activation(&registered));
    registered.activation.issuer_account = account.public_key();
    registered.claims.issuer = other.public_key();
    assert!(!claim.did_sign_activation(&registered));
}

#[test]
fn account_did_sign_user_with_registered_signing_key() {
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    account_claim
        .account
        .signing_keys
        .add(SigningKey::Key(signer.public_key()));
    let mut user_claim = UserClaims::new(user.public_key()).unwrap();
    user_claim.claims.issuer = signer.public_key();
    user_claim.user.issuer_account = account.public_key();
    assert!(account_claim.did_sign(&user_claim));
}

#[test]
fn account_signing_keys_validate_regular_and_scoped_account_keys_only() {
    let account = KeyPair::new_account();
    let regular = KeyPair::new_account();
    let scoped = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .signing_keys
        .add(SigningKey::Key(regular.public_key()));
    claim
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(UserScope {
            kind: "user_scope".into(),
            key: scoped.public_key(),
            role: "reader".into(),
            ..Default::default()
        })));
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(!results.is_blocking(false));

    claim
        .account
        .signing_keys
        .add(SigningKey::Key(user.public_key()));
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn account_signing_keys_add_remove_and_authorize_direct_self_and_registered_signers() {
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let other = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .signing_keys
        .add(SigningKey::Key(signer.public_key()));
    claim
        .account
        .signing_keys
        .add(SigningKey::Key(other.public_key()));
    claim
        .account
        .signing_keys
        .remove(&KeyPair::new_account().public_key());
    assert_eq!(claim.account.signing_keys.keys().len(), 2);
    claim.account.signing_keys.remove(&other.public_key());
    assert_eq!(claim.account.signing_keys.keys(), vec![signer.public_key()]);

    let mut direct = UserClaims::new(user.public_key()).unwrap();
    direct.claims.issuer = account.public_key();
    assert!(claim.did_sign(&direct));

    let mut registered = UserClaims::new(user.public_key()).unwrap();
    registered.claims.issuer = signer.public_key();
    registered.user.issuer_account = account.public_key();
    assert!(claim.did_sign(&registered));

    let mut wrong_account = registered.clone();
    wrong_account.user.issuer_account = other.public_key();
    assert!(!claim.did_sign(&wrong_account));

    let mut scoped = UserClaims::new(user.public_key()).unwrap();
    scoped.claims.issuer = signer.public_key();
    scoped.user.issuer_account = account.public_key();
    scoped.set_scoped(true);
    claim
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(UserScope {
            kind: "user_scope".into(),
            key: signer.public_key(),
            role: "reader".into(),
            ..Default::default()
        })));
    assert!(claim.did_sign(&scoped));
    scoped.user.permissions.publish.allow.add(["orders"]);
    assert!(claim.did_sign(&scoped));
    scoped.user.limits.subscriptions = 1;
    assert!(claim.did_sign(&scoped));
}

#[test]
fn signing_key_validation_requires_exact_account_prefix() {
    let mut keys = SigningKeys::default();
    keys.add(SigningKey::Key(KeyPair::new_operator().public_key()));
    let mut results = ValidationResults::default();
    keys.validate(&mut results);
    assert!(results.is_blocking(false));
}
