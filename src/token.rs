//! Compact JWT framing, Base64URL segments, and NATS v2 header handling.
//!
//! Use [`crate::decode`] for signature verification; segment and header helpers only parse framing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{NjError, Result};

/// Maximum accepted compact JWT size in bytes (1 MiB), enforced by [`split_token`].
pub const MAX_TOKEN_SIZE: usize = 1024 * 1024;
/// Upstream JWT library compatibility version string; distinct from the crate version and `nats.version`.
pub const VERSION: &str = "2.4.0";
/// The supported NATS JWT claim version (`nats.version`).
pub const SUPPORTED_JWT_VERSION: u8 = 2;
/// JWT header type emitted by this library.
pub const TOKEN_TYPE_JWT: &str = "JWT";
/// NATS v2 algorithm identifier for signing the encoded header and payload with an NKey.
pub const ALGORITHM_NKEY: &str = "ed25519-nkey";

/// JWT header with NATS v2 algorithm metadata; represented separately from the encoded segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Header `typ` value; canonical encoding uses `JWT`.
    #[serde(rename = "typ")]
    pub token_type: String,
    /// Header `alg` value; canonical encoding uses `ed25519-nkey`.
    #[serde(rename = "alg")]
    pub algorithm: String,
}

impl Header {
    /// Construct the canonical `JWT` and `ed25519-nkey` header.
    pub fn v2() -> Self {
        Self {
            token_type: TOKEN_TYPE_JWT.into(),
            algorithm: ALGORITHM_NKEY.into(),
        }
    }

    /// Validate the type case-insensitively and algorithm exactly, then return an encoded Base64URL JSON segment; invalid metadata returns an error.
    pub fn encode(&self) -> Result<String> {
        if !self.token_type.eq_ignore_ascii_case(TOKEN_TYPE_JWT) {
            return Err(NjError::InvalidToken(format!(
                "not supported type {:?}",
                self.token_type
            )));
        }
        if self.algorithm != ALGORITHM_NKEY {
            return Err(NjError::InvalidToken(format!(
                "unexpected {:?} algorithm",
                self.algorithm
            )));
        }
        Ok(encode_segment(&serde_json::to_vec(self)?))
    }

    /// Parse raw JSON text, not a Base64 segment, and validate type and algorithm case-insensitively; malformed or unsupported metadata returns an error.
    pub fn decode(value: &str) -> Result<Self> {
        let header: Self = serde_json::from_str(value)?;
        if !header.token_type.eq_ignore_ascii_case(TOKEN_TYPE_JWT) {
            return Err(NjError::InvalidToken(format!(
                "not supported type {:?}",
                header.token_type
            )));
        }
        if !header.algorithm.eq_ignore_ascii_case(ALGORITHM_NKEY) {
            return Err(NjError::InvalidToken(format!(
                "unexpected {:?} algorithm",
                header.algorithm
            )));
        }
        Ok(header)
    }
}

/// Encode bytes as URL-safe Base64 without padding for a JWT segment.
pub fn encode_segment(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode an unpadded URL-safe Base64 segment, reporting malformed input as a token error.
pub fn decode_segment(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| NjError::InvalidToken(error.to_string()))
}

/// Join already encoded header and claim segments with a dot; these exact bytes are signed in v2.
pub fn v2_signing_input(header: &str, claims: &str) -> Vec<u8> {
    format!("{header}.{claims}").into_bytes()
}

/// Borrow exactly three nonempty segments; reject tokens over 1 MiB or with a different segment count. No signature verification is performed here.
pub fn split_token(token: &str) -> Result<(&str, &str, &str)> {
    if token.len() > MAX_TOKEN_SIZE {
        return Err(NjError::InvalidToken("token too large".into()));
    }
    let mut parts = token.split('.');
    let result = (parts.next(), parts.next(), parts.next(), parts.next());
    match result {
        (Some(header), Some(claims), Some(signature), None)
            if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
        {
            Ok((header, claims, signature))
        }
        _ => Err(NjError::InvalidToken("expected 3 chunks".into())),
    }
}
