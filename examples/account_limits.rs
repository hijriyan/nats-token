//! Configure core NATS and JetStream account limits before signing.
use nats_token::{
    decode_account_claims, AccountClaims, JetStreamLimits, KeyPair, ValidationResults,
};

fn main() -> nats_token::Result<()> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claims = AccountClaims::new(account.public_key()).unwrap();
    claims.claims.name = "limited-account".into();

    let limits = &mut claims.account.limits;
    limits.connections = 20;
    limits.subscriptions = 100;
    limits.payload = 1024 * 1024; // Bytes per message.
    limits.imports = 5;
    limits.exports = 5;
    limits.leaf_connections = 0;
    limits.disallow_bearer = true;
    // Defaults leave core resources unlimited and JetStream disabled.
    limits.jetstream = JetStreamLimits {
        memory_storage: 64 * 1024 * 1024,
        disk_storage: 1024 * 1024 * 1024,
        streams: 10,
        consumers: 20,
        ..Default::default()
    };

    let jwt = claims.encode(&operator)?;
    let mut decoded = decode_account_claims(&jwt)?;
    let mut results = ValidationResults::default();
    decoded.validate(&mut results);
    assert!(!results.is_blocking(true), "{:?}", results.issues);
    assert_eq!(decoded.claims.issuer, operator.public_key());
    assert_eq!(decoded.account.limits, claims.account.limits);

    // A configured server enforces these limits after receiving the account JWT.
    println!("Account JWT: {jwt}");
    Ok(())
}
