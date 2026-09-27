// Adapted from nats-io/jwt.js/tests/jwt_test.ts.
// Copyright 2021-2024 The NATS Authors. Licensed under Apache-2.0.

use nats_token::policy::{SigningKey, UserScope};
use nats_token::token::{decode_segment, encode_segment, split_token};
use nats_token::*;
use nkeys::KeyPair;
use serde_json::{json, Value};

fn payload(token: &str, kind: &str) -> Value {
    decode(token).expect("the encoded JWT must verify");
    let (header, body, _) = split_token(token).unwrap();
    let header: Value = serde_json::from_slice(&decode_segment(header).unwrap()).unwrap();
    assert_eq!(header, json!({"typ": "JWT", "alg": "ed25519-nkey"}));
    let body: Value = serde_json::from_slice(&decode_segment(body).unwrap()).unwrap();
    assert_eq!(body["nats"]["version"], 2);
    assert_eq!(body["nats"]["type"], kind);
    assert!(body.get("type").is_none());
    body
}

#[test]
fn rejects_bad_chunks() {
    assert!(
        matches!(decode("eyJhbGciOiJIUzI1NiIsInR"), Err(NjError::InvalidToken(message))
        if message == "expected 3 chunks")
    );
}

#[test]
fn rejects_bad_algorithm() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(matches!(decode(token), Err(NjError::InvalidToken(message))
        if message == "unexpected \"HS256\" algorithm"));
}

#[test]
fn rejects_bad_type() {
    let account = KeyPair::new_account();
    let token = AccountClaims::new(account.public_key())
        .unwrap()
        .encode(&account)
        .unwrap();
    let (_, body, _) = split_token(&token).unwrap();
    let header = encode_segment(br#"{"typ":"Foo","alg":"ed25519-nkey"}"#);
    // Re-sign so that only the header type is invalid.
    let signature = encode_segment(&account.sign(format!("{header}.{body}").as_bytes()).unwrap());
    assert!(
        matches!(decode(&format!("{header}.{body}.{signature}")), Err(NjError::InvalidToken(message))
        if message == "not supported type \"Foo\"")
    );
}

#[test]
fn rejects_bad_signature() {
    let account = KeyPair::new_account();
    let token = AccountClaims::new(account.public_key())
        .unwrap()
        .encode(&account)
        .unwrap();
    payload(&token, "account");
    let (header, body, sig) = split_token(&token).unwrap();
    // Mutate decoded bytes to keep Base64URL valid and exercise verification.
    let mut sig = decode_segment(sig).unwrap();
    sig[0] ^= 1;
    assert!(
        matches!(decode(&format!("{header}.{body}.{}", encode_segment(&sig))), Err(NjError::InvalidToken(message))
        if message == "claim failed V2 signature verification")
    );
}

#[test]
fn account_signingkeys_string() {
    let account = KeyPair::new_account();
    let signing_key = KeyPair::new_account().public_key();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .signing_keys
        .add(SigningKey::Key(signing_key.clone()));
    let token = claim.encode(&account).unwrap();
    assert_eq!(
        payload(&token, "account")["nats"]["signing_keys"],
        json!([signing_key])
    );
    assert_eq!(
        decode_account_claims(&token).unwrap().account.signing_keys,
        claim.account.signing_keys
    );
}

#[test]
fn account_signingkeys_scoped() {
    let account = KeyPair::new_account();
    let mut scope = UserScope::new();
    scope.key = KeyPair::new_account().public_key();
    scope.role = "anyrole".into();
    scope.template.permissions.subscribe.allow.add(["foo"]);
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(scope.clone())));
    let token = claim.encode(&account).unwrap();
    let wire = payload(&token, "account");
    assert_eq!(wire["nats"]["signing_keys"], json!([scope]));
    assert_eq!(
        wire["nats"]["signing_keys"][0]["template"]["sub"]["allow"],
        json!(["foo"])
    );
    assert_eq!(
        decode_account_claims(&token).unwrap().account.signing_keys,
        claim.account.signing_keys
    );
}

#[test]
fn check_key() {
    let account = KeyPair::new_account();
    let seed = account.seed().unwrap();
    let seed_bytes = seed.as_bytes();
    for key in [
        &account,
        &KeyPair::from_seed(&seed).unwrap(),
        &KeyPair::from_seed(std::str::from_utf8(seed_bytes).unwrap()).unwrap(),
    ] {
        let token = AccountClaims::new(account.public_key())
            .unwrap()
            .encode(key)
            .unwrap();
        assert_eq!(payload(&token, "account")["iss"], account.public_key());
    }
}

#[test]
fn account_signer_can_be_operator_or_account() {
    let subject = KeyPair::new_account().public_key();
    for (signer, allowed) in [
        (KeyPair::new_operator(), true),
        (KeyPair::new_account(), true),
        (KeyPair::new_user(), false),
    ] {
        let result = AccountClaims::new(&subject).unwrap().encode(&signer);
        assert_eq!(result.is_ok(), allowed);
        if let Ok(token) = result {
            let wire = payload(&token, "account");
            assert_eq!(wire["sub"], subject);
            assert_eq!(wire["iss"], signer.public_key());
        }
    }
}

#[test]
fn account_id_must_be_account() {
    let operator = KeyPair::new_operator();
    for (subject, allowed) in [
        (KeyPair::new_account(), true),
        (KeyPair::new_operator(), false),
        (KeyPair::new_user(), false),
    ] {
        assert_eq!(
            AccountClaims::new(subject.public_key())
                .unwrap()
                .encode(&operator)
                .is_ok(),
            allowed
        );
    }
}

#[test]
fn user_id_must_be_user() {
    let account = KeyPair::new_account();
    for (subject, allowed) in [
        (KeyPair::new_user(), true),
        (KeyPair::new_account(), false),
        (KeyPair::new_operator(), false),
    ] {
        assert_eq!(
            UserClaims::new(subject.public_key())
                .unwrap()
                .encode(&account)
                .is_ok(),
            allowed
        );
    }
}

#[test]
fn user_issuer_must_be_account() {
    let subject = KeyPair::new_user().public_key();
    for (signer, allowed) in [
        (KeyPair::new_account(), true),
        (KeyPair::new_user(), false),
        (KeyPair::new_operator(), false),
    ] {
        assert_eq!(
            UserClaims::new(&subject).unwrap().encode(&signer).is_ok(),
            allowed
        );
    }
}

#[test]
fn user_issuer_account_must_be_account() {
    let account = KeyPair::new_account();
    for (issuer, allowed) in [
        (KeyPair::new_account(), true),
        (KeyPair::new_user(), false),
        (KeyPair::new_operator(), false),
    ] {
        let mut claim = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
        claim.user.issuer_account = issuer.public_key();
        let decoded = decode_user_claims(&claim.encode(&account).unwrap()).unwrap();
        let mut results = ValidationResults::default();
        decoded.validate(&mut results);
        assert_eq!(!results.is_blocking(false), allowed);
    }
}

#[test]
fn ids_can_be_public_keys() {
    let account = KeyPair::new_account();
    let operator = KeyPair::new_operator();
    let user_public = KeyPair::new_user().public_key();
    let user = UserClaims::new(&user_public)
        .unwrap()
        .encode(&account)
        .unwrap();
    let ac = AccountClaims::new(account.public_key())
        .unwrap()
        .encode(&operator)
        .unwrap();
    assert_eq!(payload(&user, "user")["sub"], user_public);
    assert_eq!(payload(&ac, "account")["sub"], account.public_key());
}

fn four_claims() -> Vec<(&'static str, String)> {
    let account = KeyPair::new_account();
    let mut activation = ActivationClaims::new(account.public_key()).unwrap();
    activation.activation.import_type = "service".into();
    activation.activation.import_subject = "foo".into();
    let mut generic = GenericClaims::new(account.public_key()).unwrap();
    generic.data.insert("type".into(), json!("kind"));
    vec![
        (
            "account",
            AccountClaims::new(account.public_key())
                .unwrap()
                .encode(&account)
                .unwrap(),
        ),
        (
            "user",
            UserClaims::new(KeyPair::new_user().public_key())
                .unwrap()
                .encode(&account)
                .unwrap(),
        ),
        ("activation", activation.encode(&account).unwrap()),
        ("kind", generic.encode(&account).unwrap()),
    ]
}

#[test]
fn is_account_user_activation_generic() {
    // Full positive/negative matrix from the four upstream is* tests.
    for (kind, token) in four_claims() {
        let decoded = decode(&token).unwrap();
        assert_eq!(
            matches!(decoded, DecodedClaims::Account(_)),
            kind == "account"
        );
        assert_eq!(matches!(decoded, DecodedClaims::User(_)), kind == "user");
        assert_eq!(
            matches!(decoded, DecodedClaims::Activation(_)),
            kind == "activation"
        );
        assert_eq!(matches!(decoded, DecodedClaims::Generic(_)), kind == "kind");
    }
}

#[test]
fn version_is_v2_for_each_claim_family() {
    for (kind, token) in four_claims() {
        payload(&token, kind);
        assert_eq!(decode_generic(&token).unwrap().data["version"], 2);
    }
}

#[test]
fn verify_user_issuer_account() {
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let mut claim = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
    claim.user.issuer_account = account.public_key();
    let token = claim.encode(&signer).unwrap();
    let decoded = decode_user_claims(&token).unwrap();
    assert_eq!(decoded.claims.issuer, signer.public_key());
    assert_eq!(decoded.user.issuer_account, account.public_key());
    assert_eq!(
        payload(&token, "user")["nats"]["issuer_account"],
        account.public_key()
    );
}

#[test]
fn operator() {
    let operator = KeyPair::new_operator();
    let mut claim = OperatorClaims::new(operator.public_key()).unwrap();
    claim.claims.name = "O".into();
    claim.operator.tags.add(["a"]);
    let token = claim.encode(&operator).unwrap();
    let wire = payload(&token, "operator");
    assert_eq!(wire["name"], "O");
    assert_eq!(wire["nats"]["tags"], json!(["a"]));
    assert_eq!(decode_operator_claims(&token).unwrap(), claim);
}

#[test]
fn scoped_user() {
    let mut claim = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
    claim.set_scoped(true);
    let token = claim.encode(&KeyPair::new_account()).unwrap();
    let wire = payload(&token, "user");
    for field in ["data", "payload", "subs"] {
        // Rust follows the Go wire representation: explicit zero limits.
        assert_eq!(wire["nats"][field], 0, "{field}");
    }
    assert!(decode_user_claims(&token).unwrap().has_empty_permissions());
}

#[test]
fn tiered_limits() {
    let account = KeyPair::new_account();
    let tiers = json!({
        "R1": {"mem_storage": 1024, "disk_storage": 2048, "streams": 1, "consumer": 10, "max_bytes_required": true},
        "R3": {"mem_storage": 1, "disk_storage": 2, "streams": 3, "consumer": 4}
    });
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.limits.tiered = serde_json::from_value(tiers.clone()).unwrap();
    let token = claim.encode(&account).unwrap();
    let wire = payload(&token, "account");
    for tier in ["R1", "R3"] {
        for (field, value) in tiers[tier].as_object().unwrap() {
            assert_eq!(
                &wire["nats"]["limits"]["tiered_limits"][tier][field], value,
                "{tier}.{field}"
            );
        }
    }
    assert_eq!(
        decode_account_claims(&token).unwrap().account.limits.tiered,
        claim.account.limits.tiered
    );
}

fn activation_case(delegated: bool) {
    let subject = KeyPair::new_account();
    let issuer = KeyPair::new_account();
    let signing_key = KeyPair::new_account();
    let signer = if delegated { &signing_key } else { &issuer };
    let mut claim = ActivationClaims::new(subject.public_key()).unwrap();
    claim.claims.name = "test".into();
    claim.activation.import_subject = "foo".into();
    claim.activation.import_type = "service".into();
    if delegated {
        claim.activation.issuer_account = issuer.public_key();
    }
    let token = claim.encode(signer).unwrap();
    let wire = payload(&token, "activation");
    assert_eq!(wire["name"], "test");
    assert_eq!(wire["iss"], signer.public_key());
    assert_eq!(wire["sub"], subject.public_key());
    assert_eq!(wire["nats"]["subject"], "foo");
    assert_eq!(wire["nats"]["kind"], "service");
    assert_eq!(
        wire["nats"]["issuer_account"],
        if delegated {
            issuer.public_key()
        } else {
            String::new()
        }
    );
    assert_eq!(decode_activation_claims(&token).unwrap(), claim);
}

#[test]
fn activation_v2() {
    activation_case(false);
}

#[test]
fn activation_v2_issuer_and_verify_activation_issuer_account() {
    activation_case(true);
}

#[test]
fn account_disallow_bearer() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    for disallow in [false, true] {
        claim.account.limits.disallow_bearer = disallow;
        let token = claim.encode(&account).unwrap();
        let wire = payload(&token, "account");
        assert_eq!(
            decode_account_claims(&token)
                .unwrap()
                .account
                .limits
                .disallow_bearer,
            disallow
        );
        assert_eq!(
            wire["nats"]["limits"]["disallow_bearer"]
                .as_bool()
                .unwrap_or(false),
            disallow
        );
    }
}

#[test]
fn custom_aud() {
    let account = KeyPair::new_account();
    let mut ac = AccountClaims::new(account.public_key()).unwrap();
    let mut user = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
    let mut generic = GenericClaims::new(account.public_key()).unwrap();
    generic.data.insert("type".into(), json!("my-kind"));
    ac.claims.audience = "hello".into();
    user.claims.audience = "hello".into();
    generic.claims.audience = "hello".into();
    for (kind, token) in [
        ("account", ac.encode(&account).unwrap()),
        ("user", user.encode(&account).unwrap()),
        ("my-kind", generic.encode(&account).unwrap()),
    ] {
        assert_eq!(payload(&token, kind)["aud"], "hello");
        assert_eq!(decode_generic(&token).unwrap().claims.audience, "hello");
    }
}

#[test]
fn tags_round_trip_and_remain_editable() {
    let account = KeyPair::new_account();
    let mut ac = AccountClaims::new(account.public_key()).unwrap();
    ac.account.tags.add(["a", "b", "c"]);
    let mut ac = decode_account_claims(&ac.encode(&account).unwrap()).unwrap();
    assert_eq!(ac.account.tags, vec!["a", "b", "c"]);
    ac.account.tags.add(["d"]);
    assert_eq!(
        payload(&ac.encode(&account).unwrap(), "account")["nats"]["tags"],
        json!(["a", "b", "c", "d"])
    );
    let mut user = UserClaims::new(KeyPair::new_user().public_key()).unwrap();
    user.user.tags.add(["x", "y", "z"]);
    let mut user = decode_user_claims(&user.encode(&account).unwrap()).unwrap();
    assert_eq!(user.user.tags, vec!["x", "y", "z"]);
    user.user.tags.add(["zz"]);
    assert_eq!(
        payload(&user.encode(&account).unwrap(), "user")["nats"]["tags"],
        json!(["x", "y", "z", "zz"])
    );
}

#[test]
fn authorization_response() {
    let user = KeyPair::new_user();
    let server = KeyPair::new_server();
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let mut claim = AuthorizationResponseClaims::new(user.public_key()).unwrap();
    claim.claims.audience = server.public_key();
    claim.authorization.issuer_account = Some(account.public_key());
    claim.authorization.jwt = Some("hello".into());
    let token = claim.encode(&signer).unwrap();
    let wire = payload(&token, "authorization_response");
    assert_eq!(wire["sub"], user.public_key());
    assert_eq!(wire["aud"], server.public_key());
    assert_eq!(wire["iss"], signer.public_key());
    assert_eq!(wire["nats"]["issuer_account"], account.public_key());
    assert_eq!(wire["nats"]["jwt"], "hello");
    assert_eq!(decode_authorization_response_claims(&token).unwrap(), claim);
}
