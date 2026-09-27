//! Register distinct regular and scoped signing keys on one account.
use nats_token::policy::{SigningKey, UserScope};
use nats_token::{decode_account_claims, AccountClaims, KeyPair, ValidationResults};

fn main() -> nats_token::Result<()> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    // Both signing keys are account-type NKeys, independent of the main key.
    let regular = KeyPair::new_account();
    let scoped = KeyPair::new_account();
    let mut claims = AccountClaims::new(account.public_key()).unwrap();
    claims.claims.name = "delegated-account".into();
    claims
        .account
        .signing_keys
        .add(SigningKey::Key(regular.public_key()));

    let mut scope = UserScope::new();
    scope.key = scoped.public_key();
    scope.role = "orders-reader".into();
    // An empty publish allow list alone does not prohibit publishing.
    scope.template.permissions.publish.deny.add([">"]);
    scope.template.permissions.subscribe.allow.add(["orders.>"]);
    scope.template.limits.subscriptions = 10;
    claims
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(scope.clone())));

    let jwt = claims.encode(&operator)?;
    let mut decoded = decode_account_claims(&jwt)?;
    let mut results = ValidationResults::default();
    decoded.validate(&mut results);
    // Account validation checks key syntax; validate the scope template separately.
    scope.template.permissions.validate(&mut results);
    scope.template.limits.validate(&mut results);
    assert!(!results.is_blocking(true), "{:?}", results.issues);
    assert_eq!(decoded.claims.issuer, operator.public_key());
    assert_eq!(decoded.account.signing_keys.keys().len(), 2);
    assert!(decoded.account.signing_keys.contains(&regular.public_key()));
    assert_eq!(
        decoded.account.signing_keys.get_scope(&scoped.public_key()),
        Some(&scope)
    );

    println!("Account JWT: {jwt}");
    Ok(())
}
