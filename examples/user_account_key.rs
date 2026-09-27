//! Issue a user JWT with the main account keypair.
use nats_token::{
    decode_account_claims, decode_user_claims, format_user_config, AccountClaims, KeyPair,
    UserClaims, ValidationResults,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut account_claims = AccountClaims::new(account.public_key()).unwrap();
    let account_jwt = account_claims.encode(&operator)?;
    let mut trusted_account = decode_account_claims(&account_jwt)?;
    // This example trusts the operator it just created.
    assert_eq!(trusted_account.claims.issuer, operator.public_key());

    let mut claims = UserClaims::new(user.public_key()).unwrap();
    claims.claims.name = "orders-worker".into();
    claims.claims.expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64 + 3600;
    // Direct issuance leaves issuer_account empty: iss identifies the account.
    claims
        .user
        .permissions
        .publish
        .allow
        .add(["orders.created"]);
    claims
        .user
        .permissions
        .subscribe
        .allow
        .add(["orders.>", "_INBOX.>"]);
    claims.user.limits.subscriptions = 10;
    claims.user.limits.payload = 1024 * 1024;

    let jwt = claims.encode(&account)?;
    let decoded = decode_user_claims(&jwt)?;
    let mut results = ValidationResults::default();
    trusted_account.validate(&mut results);
    decoded.validate(&mut results);
    assert!(!results.is_blocking(true), "{:?}", results.issues);
    assert_eq!(decoded.claims.subject, user.public_key());
    assert_eq!(decoded.claims.issuer, account.public_key());
    assert!(decoded.user.issuer_account.is_empty());
    assert!(trusted_account.did_sign(&decoded));
    assert!(!trusted_account.is_claim_revoked(&decoded));

    // Credentials pair the user JWT with the USER seed, never the account seed.
    let credentials = format_user_config(&jwt, &user.seed()?)?;
    assert!(credentials.contains("BEGIN USER NKEY SEED"));
    // Keep credentials private; this example only prints the JWT.
    println!("User JWT: {jwt}");
    Ok(())
}
