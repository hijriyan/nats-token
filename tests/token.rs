use nats_token::token::{
    decode_segment, encode_segment, split_token, v2_signing_input, Header, ALGORITHM_NKEY,
    MAX_TOKEN_SIZE, SUPPORTED_JWT_VERSION, TOKEN_TYPE_JWT, VERSION,
};
use nats_token::{decode, decode_user_claims, GenericClaims, NjError, ValidationResults};
use nkeys::KeyPair;
use serde_json::{json, Value};

fn token(key: &KeyPair, claims: Value) -> String {
    let header = encode_segment(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let payload = encode_segment(&serde_json::to_vec(&claims).unwrap());
    let signature = encode_segment(&key.sign(format!("{header}.{payload}").as_bytes()).unwrap());
    format!("{header}.{payload}.{signature}")
}

#[test]
fn header_constants_match_upstream() {
    assert_eq!(VERSION, "2.4.0");
    assert_eq!(SUPPORTED_JWT_VERSION, 2);
    assert_eq!(TOKEN_TYPE_JWT, "JWT");
    assert_eq!(ALGORITHM_NKEY, "ed25519-nkey");
}

#[test]
fn signing_input_includes_header_and_claims() {
    assert_eq!(v2_signing_input("h", "c"), b"h.c");
}

#[test]
fn v2_header_serializes_with_nkey_algorithm() {
    let header = Header::v2();
    assert_eq!(header.token_type, TOKEN_TYPE_JWT);
    assert_eq!(header.algorithm, ALGORITHM_NKEY);
    assert_eq!(
        header.encode().unwrap(),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ"
    );
}

#[test]
fn decode_rejects_old_nkey_algorithm() {
    assert!(Header::decode(r#"{"typ":"JWT","alg":"ed25519"}"#).is_err());
}

#[test]
fn token_size_limit_is_one_megabyte() {
    assert_eq!(MAX_TOKEN_SIZE, 1024 * 1024);
}

#[test]
fn v2_decoding_rejects_bad_type() {
    let key = KeyPair::new_account();
    let signed = token(
        &key,
        json!({"sub": KeyPair::new_user().public_key(), "iss": key.public_key(), "nats": {"version": 2, "foo": "bar"}}),
    );
    assert!(decode(&signed).is_ok());
    let (_, payload, _) = split_token(&signed).unwrap();
    let header = encode_segment(br#"{"typ":"JWS","alg":"ed25519-nkey"}"#);
    let input = v2_signing_input(&header, payload);
    let signature = key.sign(&input).unwrap();
    key.verify(&input, &signature).unwrap();
    let bad_token = format!("{header}.{payload}.{}", encode_segment(&signature));
    assert!(matches!(
        decode(&bad_token),
        Err(NjError::InvalidToken(message)) if message == "not supported type \"JWS\""
    ));
}

#[test]
fn v2_encoding_rejects_bad_type() {
    let header = Header {
        token_type: "JWS".into(),
        algorithm: ALGORITHM_NKEY.into(),
    };
    assert!(matches!(
        header.encode(),
        Err(NjError::InvalidToken(message)) if message == "not supported type \"JWS\""
    ));
}

#[test]
fn v2_encoding_rejects_old_algorithm() {
    let header = Header {
        token_type: TOKEN_TYPE_JWT.into(),
        algorithm: "ed25519".into(),
    };
    assert!(matches!(
        header.encode(),
        Err(NjError::InvalidToken(message)) if message == "unexpected \"ed25519\" algorithm"
    ));
}

#[test]
fn v2_decoding_rejects_unknown_algorithm() {
    assert!(matches!(
        Header::decode(r#"{"typ":"JWT","alg":"none"}"#),
        Err(NjError::InvalidToken(message)) if message == "unexpected \"none\" algorithm"
    ));
}

#[test]
fn v2_decoding_rejects_malformed_chunk_counts() {
    for token in ["a.b", "a.b.c.d"] {
        assert!(matches!(
            decode(token),
            Err(NjError::InvalidToken(message)) if message == "expected 3 chunks"
        ));
    }
}

#[test]
fn v2_decoding_rejects_tampered_signature() {
    let key = KeyPair::new_user();
    let claims = json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": 2}});
    let mut parts: Vec<_> = token(&key, claims).split('.').map(str::to_owned).collect();
    parts[2].push('A');
    assert!(matches!(
        decode(&parts.join(".")),
        Err(NjError::InvalidToken(message)) if message == "claim failed V2 signature verification"
    ));
}

#[test]
fn decode_rejects_valid_legacy_payload_only_signatures() {
    let key = KeyPair::new_account();
    let payload = encode_segment(
        &serde_json::to_vec(&json!({
            "sub": key.public_key(), "iss": key.public_key(), "type": "user"
        }))
        .unwrap(),
    );
    let signature = key.sign(payload.as_bytes()).unwrap();
    key.verify(payload.as_bytes(), &signature).unwrap();
    for algorithm in ["ed25519", ALGORITHM_NKEY] {
        let header = encode_segment(
            &serde_json::to_vec(&json!({
                "typ": "JWT", "alg": algorithm
            }))
            .unwrap(),
        );
        assert!(
            decode(&format!(
                "{header}.{payload}.{}",
                encode_segment(&signature)
            ))
            .is_err(),
            "{algorithm}"
        );
    }
}

#[test]
fn decode_rejects_malformed_segments_and_json() {
    for token in ["", "a.b", "a.b.c.d", ".a.b", "a..b", "a.b.", "=.e30.e30"] {
        assert!(decode(token).is_err(), "{token}");
    }
    assert!(decode("e30.e30.e30").is_err());
    assert!(decode("bm90LWpzb24.e30.e30").is_err());
    assert!(decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.bm90LWpzb24.e30").is_err());
    assert!(decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.e30.=hello=").is_err());
}

#[test]
fn decode_accepts_url_safe_segments() {
    assert_eq!(decode_segment("_-4").unwrap(), [255, 238]);
    assert!(decode_segment("=hello=").is_err());
    let key = KeyPair::new_user();
    let claims = json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": 2}});
    assert!(decode(&token(&key, claims)).is_ok());
}

#[test]
fn decode_rejects_nonempty_top_level_type() {
    let key = KeyPair::new_user();
    let signed = token(
        &key,
        json!({"sub": key.public_key(), "iss": key.public_key(), "type": "custom", "nats": {"version": 2, "type": "custom"}}),
    );
    assert!(decode(&signed).is_err());
}

#[test]
fn decode_requires_exact_integer_v2_version() {
    let key = KeyPair::new_user();
    for version in [
        json!(null),
        json!("2"),
        json!(0),
        json!(1),
        json!(3),
        json!(-1),
        json!(2.0),
    ] {
        let signed = token(
            &key,
            json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": version}}),
        );
        assert!(decode(&signed).is_err(), "{version}");
    }
    let missing = token(
        &key,
        json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {}}),
    );
    assert!(decode(&missing).is_err());
    let valid = token(
        &key,
        json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": 2}}),
    );
    assert!(decode(&valid).is_ok());
}

#[test]
fn empty_or_null_top_level_type_is_harmless() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    for top_level_type in [json!(""), Value::Null] {
        let signed = token(
            &account,
            json!({"sub": user.public_key(), "iss": account.public_key(), "type": top_level_type, "nats": {"version": 2, "type": "user"}}),
        );
        assert!(decode_user_claims(&signed).is_ok());
    }
}

#[test]
fn v2_custom_types_including_legacy_names_are_generic() {
    let key = KeyPair::new_user();
    for kind in ["custom", "cluster", "server"] {
        let signed = token(
            &key,
            json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": 2, "type": kind}}),
        );
        assert!(
            matches!(
                decode(&signed).unwrap(),
                nats_token::DecodedClaims::Generic(_)
            ),
            "{kind}"
        );
    }
}

#[test]
fn decode_accepts_case_insensitive_algorithm() {
    let key = KeyPair::new_user();
    let header = encode_segment(br#"{"typ":"JWT","alg":"Ed25519-NKey"}"#);
    let payload = encode_segment(
        &serde_json::to_vec(&json!({
            "sub": key.public_key(),
            "iss": key.public_key(),
            "nats": {"version": 2}
        }))
        .unwrap(),
    );
    let signature = encode_segment(&key.sign(format!("{header}.{payload}").as_bytes()).unwrap());
    assert!(decode(&format!("{header}.{payload}.{signature}")).is_ok());
}

#[test]
fn decode_rejects_invalid_typed_claims() {
    let key = KeyPair::new_user();
    let generic = token(
        &key,
        json!({"sub": key.public_key(), "iss": key.public_key(), "nats": {"version": 2}}),
    );
    assert!(decode(&generic).is_ok());
    assert!(decode_user_claims(&generic).is_err());
}

#[test]
fn decode_rejects_modified_signature_and_payload() {
    let key = KeyPair::new_user();
    let mut claim = GenericClaims::new(key.public_key()).unwrap();
    let token = claim.encode(&key).unwrap();
    let mut parts: Vec<_> = token.split('.').collect();
    parts[2] = "AAAA";
    assert!(decode(&parts.join(".")).is_err());
    parts[2] = token.split('.').nth(2).unwrap();
    let mut payload: Value = serde_json::from_slice(&decode_segment(parts[1]).unwrap()).unwrap();
    payload["name"] = json!("altered");
    let altered = encode_segment(&serde_json::to_vec(&payload).unwrap());
    parts[1] = &altered;
    assert!(matches!(
        decode(&parts.join(".")),
        Err(NjError::InvalidToken(message)) if message == "claim failed V2 signature verification"
    ));
    parts[1] = "=hello=";
    assert!(decode(&parts.join(".")).is_err());
}

#[test]
fn claim_time_validation_reports_expiry_and_not_before() {
    let mut claim = GenericClaims::new(KeyPair::new_user().public_key()).unwrap();
    claim.claims.expires = 1;
    claim.claims.not_before = i64::MAX;
    let mut results = ValidationResults::default();
    claim.claims.validate(&mut results);
    assert_eq!(results.warnings().len(), 2);
    assert!(results.is_blocking(true));
}

#[test]
fn decode_rejects_token_larger_than_limit() {
    let token = format!("a.b.{}", "c".repeat(MAX_TOKEN_SIZE - 4));
    assert_eq!(token.len(), MAX_TOKEN_SIZE);
    assert!(split_token(&token).is_ok());
    let oversized = format!("{token}c");
    assert_eq!(
        decode(&oversized).unwrap_err().to_string(),
        "invalid token: token too large"
    );
}

#[test]
fn validation_results_separate_time_checks_and_warnings() {
    let mut results = ValidationResults::default();
    results.add_time_check("late");
    results.add_warning("notice");
    assert!(!results.is_blocking(false));
    assert!(results.is_blocking(true));
    assert!(results.errors().is_empty());
    assert_eq!(results.warnings().len(), 2);

    results.add_error("bad");
    assert!(results.is_blocking(false));
    assert_eq!(results.errors().len(), 1);
}
