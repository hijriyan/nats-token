//! Scoped user issuance and decorated credentials parsing/formatting.
//!
//! Seed helpers return private key material; parsing decorated JWT text alone does not verify it.

use nkeys::KeyPair;

use crate::claims::{is_account, is_user};
use crate::{decode, DecodedClaims, NjError, Result, UserClaims};

/// Issue a scoped user JWT with empty permissions and an issuer account.
///
/// `expiration_duration` is in seconds relative to now; zero leaves expiry unset and negative values put it in the past. Empty names fall back to the user public key. Invalid key types, time overflow, or signing failures return an error. The account must register the signer separately.
pub fn issue_user_jwt(
    scoped_signing_key: &KeyPair,
    account_id: &str,
    public_user_key: &str,
    name: Option<&str>,
    expiration_duration: i64,
    tags: &[String],
) -> Result<String> {
    if !is_account(account_id) {
        return Err(NjError::Nkeys("account key required".into()));
    }
    if !is_user(public_user_key) {
        return Err(NjError::Nkeys("user key required".into()));
    }

    let mut claim = UserClaims::new(public_user_key)
        .ok_or_else(|| NjError::Nkeys("user key required".into()))?;
    claim.set_scoped(true);
    if expiration_duration != 0 {
        let now: i64 = crate::time::now_secs();
        claim.claims.expires = now
            .checked_add(expiration_duration)
            .ok_or_else(|| NjError::InvalidToken("expiration overflows i64".into()))?;
    }
    claim.user.issuer_account = account_id.to_owned();
    claim.claims.name = match name {
        Some("") | None => public_user_key.to_owned(),
        Some(name) => name.to_owned(),
    };
    claim.user.tags = serde_json::from_value(serde_json::to_value(tags)?)?;
    claim.encode(scoped_signing_key)
}

/// Verify and wrap a JWT in a NATS claim-type-specific text block; invalid tokens return an error.
pub fn decorate_jwt(jwt: &str) -> Result<String> {
    let kind = match decode(jwt)? {
        DecodedClaims::Operator(_) => "OPERATOR",
        DecodedClaims::Account(_) => "ACCOUNT",
        DecodedClaims::User(_) => "USER",
        DecodedClaims::Activation(_) => "ACTIVATION",
        DecodedClaims::AuthorizationRequest(_) => "AUTHORIZATION_REQUEST",
        DecodedClaims::AuthorizationResponse(_) => "AUTHORIZATION_RESPONSE",
        DecodedClaims::Generic(_) => "GENERIC",
    };
    Ok(format!(
        "-----BEGIN NATS {kind} JWT-----\n{jwt}\n------END NATS {kind} JWT------\n\n"
    ))
}

/// Validate an operator, account, or user seed and wrap it with NKey markers and a secret-material notice. The returned text contains the private seed.
pub fn decorate_seed(seed: &str) -> Result<String> {
    let seed = seed.trim();
    if seed.len() < 2 {
        return Err(NjError::Nkeys("seed is too short".into()));
    }
    let kind = match seed.get(..2) {
        Some("SU") => "USER",
        Some("SA") => "ACCOUNT",
        Some("SO") => "OPERATOR",
        _ => {
            return Err(NjError::Nkeys(
                "seed is not an operator, account or user seed".into(),
            ))
        }
    };
    KeyPair::from_seed(seed).map_err(|error| NjError::Nkeys(error.to_string()))?;
    Ok(format!("************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN {kind} NKEY SEED-----\n{seed}\n------END {kind} NKEY SEED------\n\n*************************************************************\n"))
}

/// Extract the first JWT block or return the original text unchanged. This does not decode or verify the JWT.
pub fn parse_decorated_jwt(contents: &str) -> Result<String> {
    Ok(extract_block(contents, "JWT").unwrap_or_else(|| contents.to_owned()))
}

/// Extract and validate an NKey seed, preferring the second seed block when present, then the first or a bare seed line. Missing or invalid seeds return an error.
pub fn parse_decorated_nkey(contents: &str) -> Result<String> {
    let blocks = extract_blocks(contents, "NKEY SEED");
    let seed = blocks
        .get(1)
        .or_else(|| blocks.first())
        .cloned()
        .or_else(|| {
            contents
                .lines()
                .map(str::trim)
                .find(|line| matches!(line.get(..2), Some("SU" | "SA" | "SO")))
                .map(str::to_owned)
        })
        .ok_or_else(|| NjError::Nkeys("no nkey seed found".into()))?;
    KeyPair::from_seed(&seed).map_err(|error| NjError::Nkeys(error.to_string()))?;
    Ok(seed)
}

/// Extract a validated seed and reject it unless it is a user seed. The returned string is secret material.
pub fn parse_decorated_user_nkey(contents: &str) -> Result<String> {
    let seed = parse_decorated_nkey(contents)?;
    if !seed.starts_with("SU") {
        return Err(NjError::Nkeys("does not contain a user seed".into()));
    }
    Ok(seed)
}

/// Build a credentials file after verifying a user JWT and matching its subject to the user seed. Returns an error for the wrong claim or key; output includes the private seed.
pub fn format_user_config(jwt: &str, seed: &str) -> Result<String> {
    let subject = match decode(jwt)? {
        DecodedClaims::User(claim) => claim.claims.subject,
        _ => return Err(NjError::InvalidToken("not a user claim".into())),
    };
    if !seed.trim().starts_with("SU") {
        return Err(NjError::Nkeys("seed is not a user seed".into()));
    }
    let key = KeyPair::from_seed(seed.trim()).map_err(|error| NjError::Nkeys(error.to_string()))?;
    if key.public_key() != subject {
        return Err(NjError::Nkeys("seed does not match JWT subject".into()));
    }
    Ok(format!("{}{}", decorate_jwt(jwt)?, decorate_seed(seed)?))
}

/// Return the first matching decorated block, if any.
fn extract_block(contents: &str, marker: &str) -> Option<String> {
    extract_blocks(contents, marker).into_iter().next()
}

/// Scan trimmed three-line blocks for the requested marker and a single-line token body; LF and CRLF are accepted.
fn extract_blocks(contents: &str, marker: &str) -> Vec<String> {
    let lines: Vec<_> = contents.lines().map(str::trim).collect();
    lines
        .windows(3)
        .filter(|window| {
            window[0].contains("BEGIN")
                && window[0].contains(marker)
                && window[1]
                    .chars()
                    .all(|character| character.is_alphanumeric() || "_-.=".contains(character))
                && window[2].contains("END")
        })
        .map(|window| window[1].to_owned())
        .collect()
}
