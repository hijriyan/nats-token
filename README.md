# nats-token

`nats-token` is a Rust implementation of NATS JWT v2 using [NKeys](https://docs.nats.io/using-nats/developer/connecting/nkey) for signing and verification.

The crate models NATS operators, accounts, users, activations, authorization messages, permissions, imports, exports, signing scopes, revocations, and decorated credentials. It is a JWT and policy library, not a NATS client.

## Status

- Crate version: `0.1.0`
- Rust edition: 2021
- License: Apache-2.0
- Token support: NATS JWT v2 only
- Signature algorithm: `ed25519-nkey`
- Go fixture dependency: `github.com/nats-io/jwt/v2 v2.8.2`
- Recorded upstream reference: `nats-io/jwt` commit `82017236da50e4a0173091105d82d46228b8dccf`

This project does not claim complete method-for-method or numerical test parity with upstream. The supported surface is documented below and covered by local tests and recorded Go fixtures.

## Installation

Maintainers: see [the release guide](RELEASE.md) for changelog generation and
automatic crates.io/GitHub releases.

Add the crate from crates.io:

```bash
cargo add nats-token@0.1.0
```

Or add the dependency to your `Cargo.toml`:

```toml
[dependencies]
nats-token = "0.1.0"
```

The package is named `nats-token` and its Rust import is `nats_token`.

Use `nats_token::KeyPair` to create and load keys for signing. No separate `nkeys` dependency is needed for the examples below.

## Quick start

Create an account claim, sign it with an operator, then decode and verify the token:

```rust
use nats_token::{decode_account_claims, AccountClaims, KeyPair, ValidationResults};

fn main() -> nats_token::Result<()> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();

    let mut claims = AccountClaims::new(account.public_key())
        .expect("account public key is non-empty");

    let token = claims.encode(&operator)?;
    let mut decoded = decode_account_claims(&token)?;
    let mut results = ValidationResults::default();
    decoded.validate(&mut results);
    assert!(!results.is_blocking(true));

    assert_eq!(decoded.claims.subject, account.public_key());
    Ok(())
}
```

Encoding refreshes `iat`, `iss`, and `jti`. Decoding checks token structure, header, claim version, signer prefix, and signature. Neither operation runs full semantic validation or establishes trust in the issuer; `validate()` and application trust checks are separate steps.

## Runnable examples

Run these from the repository root with `cargo run --example <name>`.
Each example creates fresh, temporary keys in memory, signs a JWT, then decodes
and validates it. The user examples also check account attribution and revocation.

| Example | What it demonstrates |
|---|---|
| [account_basic](examples/account_basic.rs) | An operator-signed account with default limits: unlimited core resources and JetStream disabled. |
| [account_limits](examples/account_limits.rs) | Connection, subscription, payload, import/export, and JetStream limits. |
| [account_signing_keys](examples/account_signing_keys.rs) | One account with distinct regular and scoped signing keys, including a reader scope template. |
| [user_account_key](examples/user_account_key.rs) | A user JWT signed by the main account keypair, with explicit permissions and limits. |
| [user_signing_key](examples/user_signing_key.rs) | A user JWT signed by a registered regular signing key, with `issuer_account` set. |
| [user_scoped_signing_key](examples/user_scoped_signing_key.rs) | A scoped user JWT with permissions and limits supplied by the registered scope. |

For example:

```bash
cargo run --example account_signing_keys
cargo run --example user_scoped_signing_key
```

Both regular and scoped account signing keys are created with
`KeyPair::new_account()`. Register their public keys in the account claim;
keep their seeds private. A regular signing key can choose user permissions,
while a scoped signing key uses the account's template. `issue_user_jwt()`
is specifically for scoped issuance; use `UserClaims::encode()` for direct
or regular signing-key issuance.

The user examples include a one-hour expiration and build decorated credentials
with `format_user_config()` using the **user** seed. They print only the JWT,
not the credentials. Keys and credentials are not saved, so separate runs do not
share an account. In an application, load existing keys with
`KeyPair::from_seed()` from your secret storage.

These examples run locally without a NATS server. Before connecting a client,
configure operator trust and publish the signed account JWT through your server's
account resolver workflow, including any signing keys, scopes, or updated limits.
This crate creates the tokens and credentials; it does not publish account claims
or enforce policy on connections.

Useful next examples beyond issuance are user renewal, revocation, signing-key
rotation, and a complete server/client setup. Revocation and signing-key changes
require re-signing and publishing the updated account claim.

## Migrating from Go `nats-io/jwt`

The table below maps common Go entry points to this crate. It is a navigation aid,
not a promise of complete API or behavioral parity. Policy types such as `Subject`
and `WeightedMapping` live under `nats_token::policy`; claim types and decoding
helpers are available at the crate root.

| Go `nats-io/jwt` | Rust `nats-token` | Usage notes |
|---|---|---|
| `NewOperatorClaims`, `NewAccountClaims`, `NewUserClaims` | `OperatorClaims::new`, `AccountClaims::new`, `UserClaims::new` | Return `Option`; an empty subject returns `None`. Key syntax is checked later. |
| `Encode` | `encode` / `encode_with_signer` | Require a mutable claim; refresh `iat`, `iss`, and `jti`. The custom `Signer` trait supports external signing. |
| `Decode` | `decode` | Returns `DecodedClaims`; verifies the signature without establishing trust or running semantic validation. |
| `DecodeAccountClaims`, `DecodeUserClaims` | `decode_account_claims`, `decode_user_claims` | Require the matching claim family and return `Result`. |
| `Validate` / `ValidationResults` | `validate` / `ValidationResults` | Append findings; use `is_blocking(true)` to include time checks. Account validation may normalize trace sampling. |
| `IssueUserJWT` | `issue_user_jwt` | Issues a scoped user token; expiration duration is in seconds, with zero meaning no expiry. |
| `FormatUserConfig` | `format_user_config` | Builds credentials after matching the user seed to the JWT subject. Output contains the private seed. |
| `Account.AddMapping` | `Account::add_mapping` | Replaces destinations for a source `Subject`; does not update a running server. |
| `WeightedMapping.GetWeight` | `WeightedMapping::effective_weight` | A stored weight of zero means 100 percent. |
| `NewUserScope` | `UserScope::new` | Sets the scope kind and unlimited template limits; `Default` is different. |
| `Revoke`, `RevokeAt`, `ClearRevocation` | `revoke`, `revoke_at`, `clear_revocation` | Available on account claims and exports; cutoffs are inclusive and changes must be published to the server. |
| `NoLimit`, `AnyAccount` | `NO_LIMIT`, `ANY_ACCOUNT` | Unlimited resource sentinel (`-1`) and external-authorization account wildcard (`*`). |

Build the public API reference with:

```bash
cargo doc --no-deps --open
```

## Supported features

### Tokens and signing

- JWT headers with type `JWT` and algorithm `ed25519-nkey`
- URL-safe Base64 encoding without padding
- V2 signature input: `header_segment.claims_segment`
- NKey signature verification from the claim issuer
- Maximum token size of 1 MiB
- Exactly three non-empty JWT segments
- Extensible `Signer` trait for external signing implementations
- Deterministic claim IDs using SHA-512/256 and Base32

### Claim types

| Claim type | Rust API | Main capabilities |
|---|---|---|
| Operator | `OperatorClaims` | Signing keys, system account, account server URL, service URLs, strict signing-key use, tags |
| Account | `AccountClaims` | Limits, imports, exports, mappings, permissions, signing keys, revocations, external authorization, message tracing |
| User | `UserClaims` | Publish/subscribe permissions, response permissions, limits, CIDRs, time ranges, connection types, scoped users |
| Activation | `ActivationClaims` | Stream/service activations, issuer account, subject and kind validation |
| Authorization request | `AuthorizationRequestClaims` | Server, user, client, connect, TLS, and nonce data |
| Authorization response | `AuthorizationResponseClaims` | User JWT or error response, server audience, issuer account |
| Generic | `GenericClaims` | Unknown/custom `nats.type` values and arbitrary `nats` JSON fields |

Use `decode()` when the claim type is not known in advance:

```rust
use nats_token::{decode, AccountClaims, DecodedClaims, KeyPair};

fn main() -> nats_token::Result<()> {
    let operator = KeyPair::new_operator();
    let account = KeyPair::new_account();
    let mut claims = AccountClaims::new(account.public_key()).unwrap();
    let token = claims.encode(&operator)?;

    match decode(&token)? {
        DecodedClaims::Operator(claim) => println!("operator: {}", claim.claims.subject),
        DecodedClaims::Account(claim) => println!("account: {}", claim.claims.subject),
        DecodedClaims::User(claim) => println!("user: {}", claim.claims.subject),
        DecodedClaims::Activation(claim) => println!("activation: {}", claim.claims.subject),
        DecodedClaims::AuthorizationRequest(_) => println!("authorization request"),
        DecodedClaims::AuthorizationResponse(_) => println!("authorization response"),
        DecodedClaims::Generic(claim) => println!("generic: {}", claim.claims.subject),
    }
    Ok(())
}
```

Typed helpers are available when the expected claim family is known:

- `decode_operator_claims`
- `decode_account_claims`
- `decode_user_claims`
- `decode_activation_claims`
- `decode_authorization_request_claims`
- `decode_authorization_response_claims`

`decode_generic()` accepts any supported claim family. For typed tokens it projects the modeled fields into `GenericClaims`; unknown fields in typed claims are not preserved. Unknown/custom claim families retain arbitrary fields inside the `nats` object.

### Account policy

The `nats_token::policy` module includes:

- NATS subjects and wildcard matching
- Publish and subscribe permissions
- Response permissions
- User subscription, data, and payload limits
- NATS and JetStream account limits, including tiered JetStream limits
- Stream and service imports/exports
- Service response modes: singleton, stream, and chunked
- Subject renaming and weighted mappings
- Account and user-scoped signing keys
- CIDR and time-range restrictions
- External authorization configuration
- Message tracing configuration
- Account and export revocation lists

### User connections

User claims support these connection types:

- Standard NATS
- WebSocket
- Leaf node
- Leaf node over WebSocket
- MQTT
- MQTT over WebSocket
- In-process

### Imports, exports, and mappings

Implemented behavior includes:

- Stream and service imports/exports
- Activation-token signature verification and import/account binding checks via `Import::validate_with_account` or `AccountClaims::validate`
- Import/export overlap checks
- Account-token positions
- Service latency sampling
- Subject wildcard renaming
- Weighted and cluster-specific mappings
- Mapping weight validation

`ResponseType` is public, while `Export::response_type` remains `Option<String>` for source compatibility.

### Signing scopes and revocations

- Regular account signing keys
- User-scope signing keys and scoped-user validation
- Sorted signing-key serialization and duplicate replacement
- Per-key and wildcard revocation
- Inclusive revocation timestamps
- Revocation clearing and compaction
- Account and export convenience `revoke()` methods using current time

### Credentials

The crate can issue and format user credentials:

```rust
use nats_token::{format_user_config, issue_user_jwt, AccountClaims, KeyPair};
use nats_token::policy::{SigningKey, UserScope};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let signing_key = KeyPair::new_account();
    let tags = vec!["engineering".to_owned()];

    let mut account_claims = AccountClaims::new(account.public_key()).unwrap();
    let mut scope = UserScope::new();
    scope.key = signing_key.public_key();
    scope.role = "engineering".to_owned();
    account_claims
        .account
        .signing_keys
        .add(SigningKey::UserScope(Box::new(scope)));

    let jwt = issue_user_jwt(
        &signing_key,
        &account.public_key(),
        &user.public_key(),
        Some("alice"),
        3600,
        &tags,
    )?;
    let credentials = format_user_config(&jwt, &user.seed()?)?;

    assert!(credentials.contains("BEGIN NATS USER JWT"));
    assert!(credentials.contains("BEGIN USER NKEY SEED"));
    Ok(())
}
```

`issue_user_jwt()` creates a scoped user with empty permissions and limits, supplied by the registered scope. Configure the scope template for your application, then sign and publish the account claim containing that signing key before using the credentials with a server. The example prepares the claims and credentials in memory; this crate does not publish them.

Credential helpers:

- `issue_user_jwt`
- `decorate_jwt`
- `decorate_seed`
- `parse_decorated_jwt`
- `parse_decorated_nkey`
- `parse_decorated_user_nkey`
- `format_user_config`

Decorated parsers accept LF and CRLF input. `parse_decorated_jwt` only extracts text; use a decoding helper to verify the JWT. `format_user_config` verifies that the user seed matches the JWT subject.

## Validation and trust

Cryptographic decoding and semantic validation are separate operations.

`decode()` verifies token shape, version, signer prefix, and signature. Claim-specific `validate()` methods report policy errors, warnings, and time checks through `ValidationResults`.

```rust
use nats_token::{GenericClaims, KeyPair, ValidationResults};

fn main() {
    let user = KeyPair::new_user();
    let mut claims = GenericClaims::new(user.public_key()).unwrap();
    claims.claims.expires = 1;

    let mut results = ValidationResults::default();
    claims.validate(&mut results);
    assert!(results.is_blocking(true));
}
```

A valid signature only proves that the issuer key signed the token. Applications must still apply their own trust policy, including operator/account relationships, allowed signing keys, activation constraints, and revocation checks.

## Compatibility rules

Accepted tokens must satisfy all these requirements:

- Header type is `JWT` (case-insensitive when decoding)
- Header algorithm is `ed25519-nkey` (case-insensitive when decoding)
- `nats.version` is the integer `2`
- Signature covers `header.claims`
- Claim type dispatch comes from `nats.type`
- Top-level `type` must not be a nonempty string; non-string values are ignored
- Token is no larger than 1 MiB

Encoding emits the canonical `JWT` / `ed25519-nkey` header. When decoding account claims, nonempty tiered limits take precedence and reset the untiered JetStream limits to their defaults.

Unknown v2 `nats.type` values decode as `GenericClaims`. This includes custom values named `cluster` or `server`; they do not receive legacy special handling.

## Not supported by design

These features are intentionally excluded:

- JWT v1 decoding or encoding
- The upstream `v1compat` API
- V1 field migration into v2 models
- Legacy `ed25519` JWT headers
- Payload-only signatures
- Legacy cluster/server claim forms
- A built-in NATS network client
- NKey generation or key storage beyond the delegated `nkeys` crate

## Not yet guaranteed

The following are not current compatibility promises:

- Complete method-for-method parity with every Go convenience API
- Complete numerical parity with every upstream Go test
- A single high-level API that validates a complete operator-account-user trust chain
- A declared minimum supported Rust version beyond Rust 2021 edition requirements

## Interoperability

Local tests include Go-generated v2 fixtures for typed and generic claims. They check modeled payload fields and tampered-signature rejection across seven claim families. Other local tests cover malformed tokens and policy validation; these fixtures do not establish complete upstream parity.

With Go 1.25 or later available (see `tests/fixtures/go/go.mod`), run the reverse interoperability test to generate Rust tokens and verify them with Go:

```bash
cargo test --test interop go_verifies_rust_tokens -- --ignored
```

## Development

Run the default Rust checks (external-tool interoperability tests are ignored):

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
```

Run optional interoperability checks separately with `go` and `nsc` on `PATH`:

```bash
cargo test --test interop go_verifies_rust_tokens -- --ignored
cargo test --test jwt_v2_nsc -- --ignored
```

The Go check may need network access to download its pinned modules. The three NSC tests create disposable isolated stores and clean them up afterward. Neither optional suite connects to a running NATS server.

## Security notes

- Treat NKey seeds as secrets.
- Do not log decorated credentials or seed material.
- Decode and signature verification do not replace application trust policy.
- Check semantic validation results before accepting claims.
- Apply revocation checks using the issued-at timestamp of the claim.

## Credits

Thanks to the maintainers and contributors of the [`nkeys`](https://crates.io/crates/nkeys) crate, which provides NKey generation, key loading, signing, and signature verification. `nats_token::KeyPair` is a re-export of `nkeys::KeyPair`.

## License

Licensed under the Apache License, Version 2.0.
