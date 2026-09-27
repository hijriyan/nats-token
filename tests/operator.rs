use nats_token::{
    parse_server_version, validate_operator_service_url, AccountClaims, OperatorClaims, TagList,
    ValidationResults,
};
use nkeys::KeyPair;

#[test]
fn operator_server_version_parser_accepts_semver_triplet() {
    assert_eq!(parse_server_version("2.10.3").unwrap(), (2, 10, 3));
    assert!(parse_server_version("2.1").is_err());
    assert!(parse_server_version("2.-1.0").is_err());
}

#[test]
fn operator_service_url_accepts_empty_value() {
    assert!(validate_operator_service_url("").is_ok());
}

#[test]
fn operator_service_url_accepts_supported_schemes_only() {
    for value in [
        "nats://host:4222",
        "tls://host:4222",
        "ws://host",
        "wss://host",
    ] {
        assert!(validate_operator_service_url(value).is_ok());
    }
    assert!(validate_operator_service_url("http://host").is_err());
    assert!(validate_operator_service_url("nats://user:pass@host").is_err());
    assert!(validate_operator_service_url("nats://host/path").is_err());
}

#[test]
fn operator_service_url_matches_upstream_validation_matrix() {
    let operator = KeyPair::new_operator();
    let mut combined = OperatorClaims::new(operator.public_key()).unwrap();
    let mut expected_errors = 0;
    for (value, should_fail) in [
        ("", false),
        ("HTTP://foo.bar.com", true),
        ("http://foo.bar.com/foo/bar", true),
        ("nats://user:pass@foo.bar.com", true),
        ("NATS://user:pass@foo.bar.com", true),
        ("NATS://user@foo.bar.com", true),
        ("nats://foo.bar.com/path", true),
        ("tls://foo.bar.com/path", true),
        ("/hello", true),
        ("NATS://foo.bar.com", false),
        ("TLS://foo.bar.com", false),
        ("nats://foo.bar.com", false),
        ("tls://foo.bar.com", false),
    ] {
        assert_eq!(
            validate_operator_service_url(value).is_err(),
            should_fail,
            "{value}"
        );
        combined.operator.operator_service_urls.push(value.into());
        expected_errors += usize::from(should_fail);
    }
    let mut results = ValidationResults::default();
    combined.validate(&mut results);
    assert_eq!(results.errors().len(), expected_errors);
}

#[test]
fn typed_claim_tags_round_trip() {
    let operator = KeyPair::new_operator();
    let mut operator_claim = OperatorClaims::new(operator.public_key()).unwrap();
    operator_claim.operator.tags.add(["foo", "bar"]);
    let token = operator_claim.encode(&operator).unwrap();
    let decoded = nats_token::decode_operator_claims(&token).unwrap();
    assert_eq!(
        &*decoded.operator.tags,
        &vec!["foo".to_string(), "bar".to_string()]
    );

    let account = KeyPair::new_account();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    account_claim.account.tags.add(["account"]);
    let account_token = account_claim.encode(&operator).unwrap();
    let decoded_account = nats_token::decode_account_claims(&account_token).unwrap();
    assert!(decoded_account.account.tags.contains("account"));

    let user = KeyPair::new_user();
    let mut user_claim = nats_token::UserClaims::new(user.public_key()).unwrap();
    user_claim.user.tags.add(["user"]);
    let token = user_claim.encode(&account).unwrap();
    let decoded = nats_token::decode_user_claims(&token).unwrap();
    assert!(decoded.user.tags.contains("user"));
}

#[test]
fn operator_and_account_claims_expose_tags() {
    let operator = KeyPair::new_operator();
    let mut operator_claim = OperatorClaims::new(operator.public_key()).unwrap();
    operator_claim.operator.tags.add(["operator"]);
    assert!(operator_claim.get_tags().contains("operator"));

    let account = KeyPair::new_account();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    account_claim.account.tags.add(["account"]);
    assert!(account_claim.get_tags().contains("account"));
}

#[test]
fn operator_tags_are_normalized_and_deduplicated() {
    let mut tags = TagList::default();
    tags.add([" NATS ", "nats", "Security"]);
    assert_eq!(&*tags, &vec!["nats".to_string(), "security".to_string()]);
}

#[test]
fn operator_did_sign_requires_self_or_registered_signing_key() {
    let operator = KeyPair::new_operator();
    let signing_key = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    account_claim.claims.issuer = signing_key.public_key();
    assert!(!claim.did_sign(&account_claim));
    claim.operator.signing_keys.push(signing_key.public_key());
    assert!(claim.did_sign(&account_claim));
}

#[test]
fn strict_operator_signing_requires_self_subject() {
    let operator = KeyPair::new_operator();
    let signing_key = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim.operator.strict_signing_key_usage = true;
    claim.operator.signing_keys.push(signing_key.public_key());
    let mut account_claim = AccountClaims::new(account.public_key()).unwrap();
    account_claim.claims.issuer = operator.public_key();
    assert!(!claim.did_sign(&account_claim));
}

#[test]
fn operator_encode_rejects_malformed_account_server_url() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim.operator.account_server_url = "https://[::1".into();
    assert!(claim.encode(&operator).is_err());
}

#[test]
fn operator_validation_rejects_invalid_keys_and_urls() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim
        .operator
        .signing_keys
        .push(KeyPair::new_user().public_key());
    claim.operator.system_account = KeyPair::new_user().public_key();
    claim.operator.account_server_url = "host-without-scheme".into();
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
    assert!(results.errors().len() >= 3);
}
