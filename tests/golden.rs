use nats_token::{decode, token::encode_segment, GenericClaims};
use nkeys::KeyPair;
use serde_json::json;

const UPSTREAM_COMMIT: &str = "82017236da50e4a0173091105d82d46228b8dccf";
const GO_GENERIC_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJIWDdEVVYzMkVYQk5DSVVPRVdOQkFHM1hSS04zQUdOWVZFV0tYRzVCRjc1NEtHQ0pFWlVBIiwiaWF0IjoxNzkwMzQwNjY5LCJpc3MiOiJVRFZFVTNERDRLT0ZFQ1Y2NlZJSFdFWk9ZWDRaS1IzV1YyN0w0NjRTSUlQT1UySVVJM0pDWVNKRiIsInN1YiI6IlVEVkVVM0RENEtPRkVDVjY2VklIV0VaT1lYNFpLUjNXVjI3TDQ2NFNJSVBPVTJJVUkzSkNZU0pGIiwibmF0cyI6eyJ0eXBlIjoiZ29sZGVuIiwidmVyc2lvbiI6Mn19.QMpOlauvC7OCYGBJmqErm96T2TBDh_Yds9oddi9KToDYnacrbXN4io88Tk45REoVarrtOC7q0GPBnPkc1WbWBQ";

#[test]
fn decodes_go_generated_current_main_token() {
    assert_eq!(UPSTREAM_COMMIT.len(), 40);
    let decoded = decode(GO_GENERIC_TOKEN).unwrap();
    let nats_token::DecodedClaims::Generic(claim) = decoded else {
        panic!("expected generic claim");
    };
    assert_eq!(
        claim.claims.subject,
        "UDVEU3DD4KOFE CV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCYSJF".replace(' ', "")
    );
    assert_eq!(claim.data["type"], "golden");
}

#[test]
fn v2_golden_header_and_signature_shape() {
    let key = KeyPair::new_from_raw(nkeys::KeyPairType::User, [7; 32]).unwrap();
    let mut claim = GenericClaims::new(key.public_key()).unwrap();
    claim.data.insert("type".into(), json!("golden"));
    let token = claim.encode(&key).unwrap();
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        parts[0],
        encode_segment(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#)
    );
    assert!(decode(&token).is_ok());
}
