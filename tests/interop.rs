use std::collections::BTreeMap;

use nats_token::*;
use nkeys::{KeyPair, KeyPairType};
use serde_json::{json, Value};

fn fixtures() -> BTreeMap<String, String> {
    serde_json::from_str(include_str!("fixtures/tokens.json")).unwrap()
}

fn key(kind: KeyPairType, byte: u8) -> KeyPair {
    KeyPair::new_from_raw(kind, [byte; 32]).unwrap()
}

#[test]
fn go_signed_fixtures_verify_and_preserve_payloads() {
    let tokens = fixtures();
    assert_eq!(tokens.len(), 7);
    let op = key(KeyPairType::Operator, 1).public_key();
    let ac = key(KeyPairType::Account, 2).public_key();
    let us = key(KeyPairType::User, 3).public_key();
    let sv = key(KeyPairType::Server, 4).public_key();
    for (kind, token) in &tokens {
        let (issuer, subject) = match kind.as_str() {
            "operator" => (&op, &op),
            "account" => (&op, &ac),
            "activation" => (&ac, &ac),
            "auth_request" => (&sv, &us),
            "generic" => (&us, &us),
            _ => (&ac, &us),
        };
        let common = decode_generic(token).unwrap().claims;
        assert_eq!(&common.issuer, issuer, "{kind}");
        assert_eq!(&common.subject, subject, "{kind}");
        assert!(common.issued_at > 0);
        assert!(!common.id.is_empty());
        let (header, payload, sig) = token::split_token(token).unwrap();
        let mut signature = token::decode_segment(sig).unwrap();
        signature[0] ^= 1;
        let tampered = format!("{header}.{payload}.{}", token::encode_segment(&signature));
        assert!(decode(&tampered).is_err(), "{kind}");
    }
    assert_eq!(
        decode_operator_claims(&tokens["operator"])
            .unwrap()
            .claims
            .name,
        "fixture-operator"
    );
    assert_eq!(
        decode_account_claims(&tokens["account"])
            .unwrap()
            .claims
            .name,
        "fixture-account"
    );
    let user = decode_user_claims(&tokens["user"]).unwrap();
    assert_eq!(user.claims.name, "fixture-user");
    assert_eq!(user.user.issuer_account, ac);
    let activation = decode_activation_claims(&tokens["activation"]).unwrap();
    assert_eq!(activation.activation.import_subject, "foo.*");
    assert_eq!(activation.activation.import_type, "stream");
    assert_eq!(activation.activation.issuer_account, ac);
    let request = decode_authorization_request_claims(&tokens["auth_request"]).unwrap();
    assert_eq!(request.request.server_id.name, "fixture-server");
    assert_eq!(request.request.user_nkey, us);
    assert_eq!(request.request.request_nonce, "nonce");
    let response = decode_authorization_response_claims(&tokens["auth_response"]).unwrap();
    assert_eq!(response.claims.audience, sv);
    assert_eq!(response.authorization.jwt.as_deref(), Some("fixture-jwt"));
    assert_eq!(
        response.authorization.issuer_account.as_deref(),
        Some(ac.as_str())
    );
    assert!(response.authorization.error.is_none());
    let DecodedClaims::Generic(generic) = decode(&tokens["generic"]).unwrap() else {
        panic!("generic dispatch")
    };
    assert_eq!(generic.data["type"], "fixture-generic");
    assert_eq!(generic.data["answer"], 42);
    let metadata: Value = serde_json::from_str(include_str!("fixtures/metadata.json")).unwrap();
    assert_eq!(
        metadata["upstream"]["commit"],
        "82017236da50e4a0173091105d82d46228b8dccf"
    );
}

#[test]
#[ignore = "requires Go; run cargo test --test interop go_verifies_rust_tokens -- --ignored"]
fn go_verifies_rust_tokens() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let op = key(KeyPairType::Operator, 1);
    let ac = key(KeyPairType::Account, 2);
    let us = key(KeyPairType::User, 3);
    let sv = key(KeyPairType::Server, 4);
    let mut tokens = BTreeMap::new();
    for (kind, token) in fixtures() {
        let value = match decode(&token).unwrap() {
            DecodedClaims::Operator(mut c) => c.encode(&op),
            DecodedClaims::Account(mut c) => c.encode(&op),
            DecodedClaims::User(mut c) => c.encode(&ac),
            DecodedClaims::Activation(mut c) => c.encode(&ac),
            DecodedClaims::AuthorizationRequest(mut c) => c.encode(&sv),
            DecodedClaims::AuthorizationResponse(mut c) => c.encode(&ac),
            DecodedClaims::Generic(mut c) => c.encode(&us),
        }
        .unwrap();
        tokens.insert(kind, value);
    }
    tokens.insert(
        "scoped_user".into(),
        issue_user_jwt(&ac, &ac.public_key(), &us.public_key(), None, 0, &[]).unwrap(),
    );
    let mut child = Command::new("go")
        .args(["run", ".", "verify"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/go"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&json!(tokens)).unwrap().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
