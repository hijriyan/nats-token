use nats_token::{
    decode, is_generic_claim_type, ClaimType, DecodedClaims, GenericClaims, Signer, ACCOUNT_CLAIM,
    ACTIVATION_CLAIM, AUTHORIZATION_REQUEST_CLAIM, AUTHORIZATION_RESPONSE_CLAIM, GENERIC_CLAIM,
    OPERATOR_CLAIM, USER_CLAIM,
};

const OPERATOR_TYPE: &str = ClaimType::Operator.as_str();

#[test]
fn canonical_claim_names_match_upstream() {
    assert_eq!(OPERATOR_CLAIM, "operator");
    assert_eq!(ACCOUNT_CLAIM, "account");
    assert_eq!(USER_CLAIM, "user");
    assert_eq!(ACTIVATION_CLAIM, "activation");
    assert_eq!(AUTHORIZATION_REQUEST_CLAIM, "authorization_request");
    assert_eq!(AUTHORIZATION_RESPONSE_CLAIM, "authorization_response");
    assert_eq!(GENERIC_CLAIM, "generic");
    assert_eq!(OPERATOR_TYPE, OPERATOR_CLAIM);
    assert_eq!(ClaimType::Generic.as_str(), GENERIC_CLAIM);
}

#[test]
fn generic_claim_type_matches_upstream() {
    for claim_type in [
        OPERATOR_CLAIM,
        ACCOUNT_CLAIM,
        USER_CLAIM,
        ACTIVATION_CLAIM,
        AUTHORIZATION_REQUEST_CLAIM,
        AUTHORIZATION_RESPONSE_CLAIM,
    ] {
        assert!(!is_generic_claim_type(claim_type));
    }
    assert!(is_generic_claim_type(GENERIC_CLAIM));
    assert!(is_generic_claim_type("custom"));
    assert!(is_generic_claim_type(""));
}
use nkeys::KeyPair;
use serde_json::json;

#[test]
fn generic_claim_round_trip_preserves_custom_data() {
    let key = KeyPair::new_user();
    let subject = key.public_key();
    let mut claim = GenericClaims::new(subject.clone()).unwrap();
    claim.data.insert("type".into(), json!("custom"));
    claim.data.insert("answer".into(), json!(42));

    let token = claim.encode(&key).unwrap();
    let decoded = match decode(&token).unwrap() {
        DecodedClaims::Generic(decoded) => decoded,
        _ => panic!("expected generic claim"),
    };

    assert_eq!(decoded.claims.subject, subject);
    assert_eq!(decoded.claim_type(), ClaimType::Generic);
    assert_eq!(decoded.data["answer"], json!(42));
    assert_eq!(decoded.data["version"], json!(2));
    assert_eq!(decoded.claim_type_name(), "custom");
}

#[test]
fn generic_claim_validation_reports_time_checks() {
    let key = KeyPair::new_user();
    let mut claim = GenericClaims::new(key.public_key()).unwrap();
    claim.claims.expires = 1;
    let mut results = nats_token::ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(true));
}

#[test]
fn decode_generic_accepts_typed_claims() {
    let operator = KeyPair::new_operator();
    let mut claim = nats_token::OperatorClaims::new(operator.public_key()).unwrap();
    let token = claim.encode(&operator).unwrap();
    let decoded = nats_token::decode_generic(&token).unwrap();
    assert_eq!(decoded.claims.subject, operator.public_key());
    assert_eq!(decoded.data["type"], "operator");
}

#[test]
fn decode_rejects_tampered_claims() {
    let key = KeyPair::new_user();
    let mut claim = GenericClaims::new(key.public_key()).unwrap();
    let token = claim.encode(&key).unwrap();
    let mut parts: Vec<_> = token.split('.').collect();
    parts[1] = "e30";
    assert!(decode(&parts.join(".")).is_err());
}

#[test]
fn generic_claim_requires_subject() {
    assert!(GenericClaims::new("").is_none());
}

struct ExternalSigner(KeyPair);

impl Signer for ExternalSigner {
    fn public_key(&self) -> nats_token::Result<String> {
        Ok(self.0.public_key())
    }

    fn sign(&self, data: &[u8]) -> nats_token::Result<Vec<u8>> {
        self.0
            .sign(data)
            .map_err(|error| nats_token::NjError::Nkeys(error.to_string()))
    }
}

#[test]
fn generic_claim_supports_external_signer() {
    let key = KeyPair::new_user();
    let signer = ExternalSigner(key.clone());
    let mut claim = GenericClaims::new(key.public_key()).unwrap();
    let token = claim.encode_with_signer(&signer).unwrap();
    assert!(decode(&token).is_ok());
}
