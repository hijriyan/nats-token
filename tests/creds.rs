use nats_token::{
    decode_user_claims, decorate_jwt, decorate_seed, format_user_config, issue_user_jwt,
    parse_decorated_jwt, parse_decorated_nkey, parse_decorated_user_nkey, UserClaims,
};
use nkeys::KeyPair;

#[test]
fn credentials_round_trip_decorated_values() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let seed = user.seed().unwrap();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    let jwt = claim.encode(&account).unwrap();
    let config = format_user_config(&jwt, &seed).unwrap();
    assert_eq!(parse_decorated_jwt(&config).unwrap(), jwt);
    assert_eq!(parse_decorated_user_nkey(&config).unwrap(), seed);
}

#[test]
fn credential_decorators_emit_nats_markers() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    let jwt = claim.encode(&account).unwrap();
    let decorated_jwt = decorate_jwt(&jwt).unwrap();
    let decorated_seed = decorate_seed(&user.seed().unwrap()).unwrap();
    assert!(decorated_jwt.contains("BEGIN NATS USER JWT"));
    assert!(decorated_seed.contains("BEGIN USER NKEY SEED"));
}

#[test]
fn credentials_parse_crlf_decorated_values() {
    let user = KeyPair::new_user();
    let account = KeyPair::new_account();
    let mut claim = UserClaims::new(user.public_key()).unwrap();
    let jwt = claim.encode(&account).unwrap();
    let config = format_user_config(&jwt, &user.seed().unwrap())
        .unwrap()
        .replace('\n', "\r\n");
    assert_eq!(parse_decorated_jwt(&config).unwrap(), jwt);
    assert_eq!(
        parse_decorated_user_nkey(&config).unwrap(),
        user.seed().unwrap()
    );
}

#[test]
fn parse_decorated_operator_jwt_handles_newlines_and_selected_blocks() {
    let operator = KeyPair::new_operator();
    let mut claim = nats_token::OperatorClaims::new(operator.public_key()).unwrap();
    let jwt = claim.encode(&operator).unwrap();
    let content =
        format!("-----BEGIN TEST OPERATOR JWT-----\n{jwt}\n------END TEST OPERATOR JWT------");
    for content in [content.clone(), content.replace('\n', "\r\n")] {
        assert_eq!(parse_decorated_jwt(&content).unwrap(), jwt);
        assert_eq!(parse_decorated_jwt(&format!("{content}\n")).unwrap(), jwt);
    }
}

#[test]
fn decorate_seed_rejects_short_inputs_with_upstream_error() {
    for seed in ["", " ", "S"] {
        assert_eq!(
            decorate_seed(seed).unwrap_err().to_string(),
            "nkeys error: seed is too short"
        );
    }
}

#[test]
fn decorated_nkey_parser_accepts_user_account_and_operator_seeds() {
    for key in [
        KeyPair::new_user(),
        KeyPair::new_account(),
        KeyPair::new_operator(),
    ] {
        let seed = key.seed().unwrap();
        assert_eq!(
            parse_decorated_nkey(&decorate_seed(&seed).unwrap()).unwrap(),
            seed
        );
    }
}

#[test]
fn credentials_reject_malformed_or_non_user_values() {
    let malformed = "  -----BEGIN NATS USER JWT-----\nnot-a-token\n";
    assert_eq!(parse_decorated_jwt(malformed).unwrap(), malformed);
    assert_eq!(parse_decorated_jwt("").unwrap(), "");
    let malformed = "-----BEGIN NATS USER JWT-----\nnot a token\n------END NATS USER JWT------";
    assert_eq!(parse_decorated_jwt(malformed).unwrap(), malformed);
    assert!(parse_decorated_user_nkey(
        "-----BEGIN USER NKEY SEED-----\nshort\n------END USER NKEY SEED------"
    )
    .is_err());
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claim = nats_token::OperatorClaims::new(operator.public_key()).unwrap();
    let jwt = claim.encode(&operator).unwrap();
    assert!(format_user_config(&jwt, &account.seed().unwrap()).is_err());
}

#[test]
fn credentials_parse_multiple_decorated_sections() {
    let operator = KeyPair::new_operator();
    let user = KeyPair::new_user();
    let jwt = "header.payload.signature";
    let contents =
        format!(
        "noise\r\n-----BEGIN NATS USER JWT-----\r\n{jwt}\r\n------END NATS USER JWT------\r\n{}",
        decorate_seed(&operator.seed().unwrap()).unwrap().replace('\n', "\r\n")
    );
    assert_eq!(parse_decorated_jwt(&contents).unwrap(), jwt);
    assert_eq!(
        parse_decorated_nkey(&contents).unwrap(),
        operator.seed().unwrap()
    );

    let mixed = format!(
        "{}{}",
        decorate_seed(&operator.seed().unwrap()).unwrap(),
        decorate_seed(&user.seed().unwrap()).unwrap()
    );
    assert_eq!(parse_decorated_nkey(&mixed).unwrap(), user.seed().unwrap());
    assert!(parse_decorated_user_nkey(&format!(
        "{}{}",
        decorate_seed(&user.seed().unwrap()).unwrap(),
        decorate_seed(&operator.seed().unwrap()).unwrap()
    ))
    .is_err());
}

#[test]
fn credentials_extract_raw_jwt_and_fallback_on_malformed_selected_block() {
    let raw = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJVIn0.signature";
    assert_eq!(parse_decorated_jwt(raw).unwrap(), raw);

    let contents = format!(
        "-----BEGIN NATS USER JWT-----\nnot a jwt\n------END NATS USER JWT------\n-----BEGIN NATS USER JWT-----\n{raw}\n------END NATS USER JWT------"
    );
    assert_eq!(parse_decorated_jwt(&contents).unwrap(), raw);
}

#[test]
fn issue_user_jwt_sets_user_claim_fields() {
    let account = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let user = KeyPair::new_user();
    let public_user = KeyPair::from_public_key(&user.public_key()).unwrap();
    let tags = vec!["Tag".to_owned(), "Tag".to_owned(), " second ".to_owned()];
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let jwt = issue_user_jwt(
        &signer,
        &account.public_key(),
        &public_user.public_key(),
        Some(""),
        60,
        &tags,
    )
    .unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claim = decode_user_claims(&jwt).unwrap();
    assert_eq!(claim.claims.subject, user.public_key());
    assert_eq!(claim.claims.name, user.public_key());
    assert_eq!(claim.claims.issuer, signer.public_key());
    assert_eq!(claim.user.issuer_account, account.public_key());
    assert!((before + 60..=after + 60).contains(&claim.claims.expires));
    assert_eq!(&*claim.user.tags, &tags);
    assert!(claim.has_empty_permissions());
}

#[test]
fn issue_user_jwt_supports_negative_and_zero_expiration() {
    let signer = KeyPair::new_account();
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let negative = decode_user_claims(
        &issue_user_jwt(
            &signer,
            &account.public_key(),
            &user.public_key(),
            None,
            -1,
            &[],
        )
        .unwrap(),
    )
    .unwrap();
    assert!(negative.claims.expires < negative.claims.issued_at);
    let zero = decode_user_claims(
        &issue_user_jwt(
            &signer,
            &account.public_key(),
            &user.public_key(),
            None,
            0,
            &[],
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(zero.claims.expires, 0);
    assert!(issue_user_jwt(
        &signer,
        &account.public_key(),
        &user.public_key(),
        None,
        i64::MAX,
        &[]
    )
    .is_err());
}

#[test]
fn issue_user_jwt_rejects_invalid_account_and_user_keys() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let operator = KeyPair::new_operator();
    assert!(issue_user_jwt(
        &operator,
        &account.public_key(),
        &user.public_key(),
        None,
        0,
        &[]
    )
    .is_err());
    assert!(issue_user_jwt(
        &account,
        &operator.public_key(),
        &user.public_key(),
        None,
        0,
        &[]
    )
    .is_err());
    assert!(issue_user_jwt(
        &account,
        &account.public_key(),
        &account.public_key(),
        None,
        0,
        &[]
    )
    .is_err());
}

#[test]
fn credentials_reject_seed_for_different_user() {
    let first = KeyPair::new_user();
    let second = KeyPair::new_user();
    assert!(format_user_config("eyJhbGciOiJub25lIn0.e30.sig", &second.seed().unwrap()).is_err());
    assert_ne!(first.public_key(), second.public_key());
}
