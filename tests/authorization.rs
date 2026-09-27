use data_encoding::BASE32;
use nats_token::{
    decode, decode_activation_claims, decode_authorization_response_claims, token::decode_segment,
    ActivationClaims, AuthorizationRequestClaims, AuthorizationResponseClaims, ClientTls,
    DecodedClaims, Signer,
};
use nkeys::KeyPair;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn activation_hash_id_matches_upstream_input_shape() {
    let issuer = KeyPair::new_account();
    let subject = KeyPair::new_account();
    let mut claim = ActivationClaims::new(subject.public_key()).unwrap();
    claim.claims.issuer = issuer.public_key();
    claim.activation.import_subject = "orders.*".into();
    let expected_input = format!("{}.{}.orders", claim.claims.issuer, claim.claims.subject);
    let expected = BASE32.encode(&Sha256::digest(expected_input.as_bytes()));
    assert_eq!(claim.hash_id().unwrap(), expected);
}

#[test]
fn activation_validation_checks_kind_subject_and_issuer_account() {
    let account = KeyPair::new_account();
    let mut claim = ActivationClaims::new(account.public_key()).unwrap();
    claim.activation.import_type = "invalid".into();
    claim.activation.import_subject = "bad subject".into();
    claim.activation.issuer_account = KeyPair::new_user().public_key();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
    assert!(results.errors().len() >= 3);
}

#[test]
fn activation_encode_rejects_invalid_full_keys_and_accepts_external_signers() {
    let subject = KeyPair::new_account();
    let mut claim = ActivationClaims::new(subject.public_key()).unwrap();
    assert!(claim.encode_with_signer(&InvalidAccountSigner).is_err());
    let mut claim = ActivationClaims::new("Ainvalid").unwrap();
    assert!(claim.encode(&KeyPair::new_account()).is_err());

    let signer = KeyPair::new_operator();
    let mut claim = ActivationClaims::new(subject.public_key()).unwrap();
    claim.activation.import_type = "stream".into();
    let called = Cell::new(false);
    let token = claim
        .encode_with_signer(&ExternalSigner {
            key: signer.public_key(),
            called: &called,
            signer: &signer,
        })
        .unwrap();
    assert!(called.get());
    assert!(decode_activation_claims(&token).is_ok());
}

#[test]
fn activation_predicates_match_exact_import_kind() {
    for (kind, service, stream) in [
        ("service", true, false),
        ("stream", false, true),
        ("", false, false),
        ("Service", false, false),
        ("invalid", false, false),
    ] {
        let activation = nats_token::Activation {
            import_type: kind.into(),
            ..Default::default()
        };
        assert_eq!(activation.is_service(), service);
        assert_eq!(activation.is_stream(), stream);
    }
}

#[test]
fn activation_export_revocation_rejects_missing_fields_and_is_inclusive() {
    let mut export = nats_token::policy::Export::new("foo", nats_token::policy::ExportType::Stream);
    let mut claim = ActivationClaims::new(KeyPair::new_account().public_key()).unwrap();
    assert!(export.is_claim_revoked(&claim));
    for issued_at in [i64::MIN, -1, i64::MAX] {
        claim.claims.issued_at = issued_at;
        assert!(!export.is_claim_revoked(&claim));
    }
    claim.claims.issued_at = -1;
    assert!(!export.is_claim_revoked(&claim));
    export.revoke_at(&claim.claims.subject, UNIX_EPOCH - Duration::from_secs(1));
    assert!(export.is_claim_revoked(&claim));
    claim.claims.issued_at = 0;
    assert!(export.is_claim_revoked(&claim));
    claim.claims.issued_at = 10;
    assert!(!export.is_claim_revoked(&claim));
    let subject = std::mem::take(&mut claim.claims.subject);
    assert!(export.is_claim_revoked(&claim));
    claim.claims.subject = subject;
    export.revoke_at(&claim.claims.subject, UNIX_EPOCH + Duration::from_secs(10));
    for (issued_at, expected) in [(9, true), (10, true), (11, false)] {
        claim.claims.issued_at = issued_at;
        assert_eq!(export.is_claim_revoked(&claim), expected);
    }
    export.clear_revocation(&claim.claims.subject);
    claim.claims.issued_at = 10;
    assert!(!export.is_claim_revoked(&claim));
    export.revoke_at("*", UNIX_EPOCH + Duration::from_secs(10));
    for (issued_at, expected) in [(9, true), (10, true), (11, false)] {
        claim.claims.issued_at = issued_at;
        assert_eq!(export.is_claim_revoked(&claim), expected);
    }
}

#[test]
fn activation_external_signer_matrix() {
    let subject = KeyPair::new_account().public_key();
    for (key, allowed) in [
        (KeyPair::new_account(), true),
        (KeyPair::new_operator(), true),
        (KeyPair::new_user(), false),
        (KeyPair::new_server(), false),
        (KeyPair::new_cluster(), false),
    ] {
        let called = Cell::new(false);
        let mut claim = ActivationClaims::new(&subject).unwrap();
        let result = claim.encode_with_signer(&ExternalSigner {
            key: key.public_key(),
            called: &called,
            signer: &key,
        });
        assert_eq!(result.is_ok(), allowed);
        assert_eq!(called.get(), allowed);
        if let Ok(token) = result {
            assert_eq!(decode_activation_claims(&token).unwrap(), claim);
        }
        let mut target = ActivationClaims::new(key.public_key()).unwrap();
        assert_eq!(
            target.encode(&KeyPair::new_account()).is_ok(),
            key.public_key().starts_with('A')
        );
    }
    let key = KeyPair::new_account();
    for public in ["Ainvalid".into(), "Oinvalid".into(), "".into(), {
        let mut corrupt = key.public_key();
        let last = corrupt.pop().unwrap();
        corrupt.push(if last == 'A' { 'B' } else { 'A' });
        corrupt
    }] {
        let called = Cell::new(false);
        let mut claim = ActivationClaims::new(&subject).unwrap();
        assert!(claim
            .encode_with_signer(&ExternalSigner {
                key: public.clone(),
                called: &called,
                signer: &key,
            })
            .is_err());
        assert!(!called.get());
        claim.claims.subject = public;
        assert!(claim.encode(&key).is_err());
    }
    let public_only = KeyPair::from_public_key(&key.public_key()).unwrap();
    let mut claim = ActivationClaims::new(&subject).unwrap();
    assert!(claim.encode(&public_only).is_err());
    let called = Cell::new(false);
    assert!(claim
        .encode_with_signer(&ExternalSigner {
            key: key.public_key(),
            called: &called,
            signer: &public_only,
        })
        .is_err());
    assert!(called.get());
}

struct ExternalSigner<'a> {
    key: String,
    called: &'a Cell<bool>,
    signer: &'a KeyPair,
}

impl Signer for ExternalSigner<'_> {
    fn public_key(&self) -> nats_token::Result<String> {
        Ok(self.key.clone())
    }
    fn sign(&self, data: &[u8]) -> nats_token::Result<Vec<u8>> {
        self.called.set(true);
        self.signer
            .sign(data)
            .map_err(|error| nats_token::NjError::Nkeys(error.to_string()))
    }
}

#[test]
fn activation_round_trip_uses_account_signer() {
    let subject = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let mut claim = ActivationClaims::new(subject.public_key()).unwrap();
    claim.activation.issuer_account = signer.public_key();
    claim.activation.import_subject = "orders.>".into();
    claim.activation.import_type = "stream".into();
    let token = claim.encode(&signer).unwrap();
    assert!(matches!(
        decode(&token).unwrap(),
        DecodedClaims::Activation(_)
    ));
    assert!(decode_activation_claims(&token).is_ok());
}

#[test]
fn authorization_request_round_trip_requires_server_signer() {
    let subject = KeyPair::new_user();
    let server = KeyPair::new_server();
    let mut claim = AuthorizationRequestClaims::new(subject.public_key()).unwrap();
    claim.request.user_nkey = subject.public_key();
    claim.request.request_nonce = "nonce".into();
    claim.request.client_tls = Some(ClientTls {
        version: "TLSv1.3".into(),
        ..Default::default()
    });
    let token = claim.encode(&server).unwrap();
    let payload =
        serde_json::from_slice::<Value>(&decode_segment(token.split('.').nth(1).unwrap()).unwrap())
            .unwrap();
    assert_eq!(payload["nats"]["client_tls"]["version"], "TLSv1.3");
    assert!(payload["nats"]["client_tls"].get("cipher").is_none());
    assert!(matches!(
        decode(&token).unwrap(),
        DecodedClaims::AuthorizationRequest(_)
    ));
    assert!(claim.encode(&KeyPair::new_account()).is_err());
}

#[test]
fn authorization_request_omits_empty_optional_fields() {
    let user = KeyPair::new_user();
    let mut claim = AuthorizationRequestClaims::new(user.public_key()).unwrap();
    claim.request.user_nkey = user.public_key();
    claim.request.client_tls = Some(ClientTls::default());
    let token = claim.encode(&KeyPair::new_server()).unwrap();
    let payload =
        serde_json::from_slice::<Value>(&decode_segment(token.split('.').nth(1).unwrap()).unwrap())
            .unwrap();
    let nats = &payload["nats"];

    assert_eq!(nats["server_id"]["name"], "");
    assert_eq!(nats["server_id"]["host"], "");
    assert_eq!(nats["server_id"]["id"], "");
    assert_eq!(nats["connect_opts"]["protocol"], 0);
    assert_eq!(nats["client_tls"], serde_json::json!({}));
    for field in ["version", "cluster", "tags", "xkey"] {
        assert!(nats["server_id"].get(field).is_none());
    }
    assert_eq!(nats["client_info"], serde_json::json!({}));
    assert_eq!(nats["connect_opts"], serde_json::json!({ "protocol": 0 }));
}

#[test]
fn authorization_response_omits_empty_optional_fields() {
    for value in [None, Some(String::new())] {
        let mut claim = AuthorizationResponseClaims::new("subject").unwrap();
        claim.authorization.jwt = value.clone();
        claim.authorization.error = value.clone();
        claim.authorization.issuer_account = value;
        let payload = serde_json::to_value(claim).unwrap();

        for field in ["jwt", "error", "issuer_account"] {
            assert!(payload["nats"].get(field).is_none(), "{field}");
        }
    }
}

#[test]
fn authorization_response_keeps_nonempty_optional_fields() {
    let mut claim = AuthorizationResponseClaims::new("subject").unwrap();
    claim.authorization.jwt = Some("jwt".into());
    claim.authorization.error = Some("error".into());
    claim.authorization.issuer_account = Some("account".into());
    let payload = serde_json::to_value(claim).unwrap();

    assert_eq!(payload["nats"]["jwt"], "jwt");
    assert_eq!(payload["nats"]["error"], "error");
    assert_eq!(payload["nats"]["issuer_account"], "account");
}

#[test]
fn authorization_request_requires_user_nkey() {
    let server = KeyPair::new_server();
    let mut claim = AuthorizationRequestClaims::new("subject").unwrap();
    assert!(claim.encode(&server).is_err());
}

struct InvalidAccountSigner;

impl Signer for InvalidAccountSigner {
    fn public_key(&self) -> nats_token::Result<String> {
        Ok("Ainvalid".into())
    }

    fn sign(&self, _data: &[u8]) -> nats_token::Result<Vec<u8>> {
        unreachable!()
    }
}

#[test]
fn authorization_response_rejects_unparseable_account_signer() {
    let user = KeyPair::new_user();
    let mut claim = AuthorizationResponseClaims::new(user.public_key()).unwrap();
    claim.authorization.error = Some("denied".into());
    assert!(claim.encode_with_signer(&InvalidAccountSigner).is_err());
}

#[test]
fn authorization_response_validation_requires_user_subject_and_server_audience() {
    let mut claim = AuthorizationResponseClaims::new("not-user").unwrap();
    claim.authorization.jwt = Some("token".into());
    claim.claims.audience = "not-server".into();
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
    assert!(results.errors().len() >= 2);
}

#[test]
fn authorization_response_requires_exactly_one_result() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let server = KeyPair::new_server();
    let mut claim = AuthorizationResponseClaims::new(user.public_key()).unwrap();
    claim.claims.audience = server.public_key();

    let mut empty_results = nats_token::ValidationResults::default();
    claim.validate(&mut empty_results);
    assert!(empty_results.is_blocking(false));
    assert!(claim.encode(&account).is_err());

    claim.authorization.jwt = Some(String::new());
    assert_eq!(
        claim.encode(&account).unwrap_err().to_string(),
        "invalid token: exactly one of jwt or error is required"
    );

    claim.authorization.jwt = None;
    claim.authorization.error = Some(String::new());
    assert_eq!(
        claim.encode(&account).unwrap_err().to_string(),
        "invalid token: exactly one of jwt or error is required"
    );

    claim.authorization.error = None;
    claim.authorization.jwt = Some("token".into());
    let mut valid_results = nats_token::ValidationResults::default();
    claim.validate(&mut valid_results);
    assert!(!valid_results.is_blocking(false));
    let token = claim.encode(&account).unwrap();
    assert!(decode_authorization_response_claims(&token).is_ok());
    assert!(decode_activation_claims(&token).is_err());

    claim.authorization.error = Some("bad".into());
    let mut both_results = nats_token::ValidationResults::default();
    claim.validate(&mut both_results);
    assert!(both_results.is_blocking(false));
    assert!(claim.encode(&account).is_err());
}

#[test]
fn authorization_response_validates_issuer_account() {
    let user = KeyPair::new_user();
    let server = KeyPair::new_server();
    let mut claim = AuthorizationResponseClaims::new(user.public_key()).unwrap();
    claim.claims.audience = server.public_key();
    claim.authorization.error = Some("denied".into());
    claim.authorization.issuer_account = Some(KeyPair::new_user().public_key());
    let mut invalid = nats_token::ValidationResults::default();
    claim.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    claim.authorization.issuer_account = Some(KeyPair::new_account().public_key());
    let mut valid = nats_token::ValidationResults::default();
    claim.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}
