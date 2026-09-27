//! Create an operator-signed account JWT with the default limits.
use nats_token::{decode_account_claims, AccountClaims, KeyPair, ValidationResults};

fn main() -> nats_token::Result<()> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claims = AccountClaims::new(account.public_key()).unwrap();
    claims.claims.name = "example-account".into();

    // The account key identifies the account; the operator signs its policy.
    let jwt = claims.encode(&operator)?;
    let mut decoded = decode_account_claims(&jwt)?;
    let mut results = ValidationResults::default();
    decoded.validate(&mut results);
    assert!(!results.is_blocking(true), "{:?}", results.issues);
    assert_eq!(decoded.claims.subject, account.public_key());
    assert_eq!(decoded.claims.issuer, operator.public_key());
    assert_eq!(decoded.account.limits.connections, nats_token::NO_LIMIT);
    assert!(!decoded.account.limits.jetstream.is_enabled());

    println!("Account JWT: {jwt}");
    Ok(())
}
