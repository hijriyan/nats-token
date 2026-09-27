//! Issue a scoped user whose permissions come from the account's scope template.
use nats_token::policy::{SigningKey, UserScope};
use nats_token::{
    decode_account_claims, decode_user_claims, format_user_config, issue_user_jwt, AccountClaims,
    KeyPair, ValidationResults,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let signing_key = KeyPair::new_account();
    let user = KeyPair::new_user();

    let mut scope = UserScope::new();
    scope.key = signing_key.public_key();
    scope.role = "orders-reader".into();
    scope.template.permissions.publish.deny.add([">"]);
    scope.template.permissions.subscribe.allow.add(["orders.>"]);
    scope.template.limits.subscriptions = 10;

    let mut account_claims = AccountClaims::new(account.public_key()).unwrap();
    account_claims
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(scope)));
    let account_jwt = account_claims.encode(&operator)?;
    let mut trusted_account = decode_account_claims(&account_jwt)?;
    assert_eq!(trusted_account.claims.issuer, operator.public_key());

    // This helper sets issuer_account and clears user permissions/limits.
    // With UserClaims directly, call set_scoped(true), set issuer_account,
    // and encode with the scoped signing key. Do not copy the template into it.
    let jwt = issue_user_jwt(
        &signing_key,
        &account.public_key(),
        &user.public_key(),
        Some("orders-reader"),
        3600, // Lifetime in seconds; zero would mean no expiration.
        &["example".into()],
    )?;
    let decoded = decode_user_claims(&jwt)?;
    let mut results = ValidationResults::default();
    trusted_account.validate(&mut results);
    decoded.validate(&mut results);
    assert_eq!(decoded.claims.subject, user.public_key());
    assert_eq!(decoded.user.issuer_account, account.public_key());
    assert!(trusted_account.did_sign(&decoded));
    assert!(!trusted_account.is_claim_revoked(&decoded));
    assert!(decoded.has_empty_permissions());
    let registered_scope = trusted_account
        .account
        .signing_keys
        .get_scope(&decoded.claims.issuer)
        .expect("registered scoped signing key");
    registered_scope.template.permissions.validate(&mut results);
    registered_scope.template.limits.validate(&mut results);
    assert!(!results.is_blocking(true), "{:?}", results.issues);
    // did_sign alone does not check scoped-user constraints.
    registered_scope.validate_user(&decoded)?;

    let credentials = format_user_config(&jwt, &user.seed()?)?;
    assert!(credentials.contains("BEGIN USER NKEY SEED"));
    // The server needs the account JWT above to resolve and enforce the scope.
    // Keep credentials private; this example only prints the JWT.
    println!("User JWT: {jwt}");
    Ok(())
}
