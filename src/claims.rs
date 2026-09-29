//! Claim models, signing boundaries, and signature-verified v2 dispatch.
//!
//! Constructors, encoding, semantic validation, and trust checks are separate operations.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::write::EncoderStringWriter;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha512_256};

use crate::authorization::{
    ActivationClaims, AuthorizationRequestClaims, AuthorizationResponseClaims,
};
use crate::token::{decode_segment, split_token, Header, SUPPORTED_JWT_VERSION};
use crate::{NjError, Result, ValidationResults};

/// Known NATS claim families used for dispatch through `nats.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimType {
    /// Operator identity and policy claim.
    Operator,
    /// Account identity and policy claim.
    Account,
    /// User identity and access policy claim.
    User,
    /// Export activation grant for an importing account.
    Activation,
    /// Server request to an external authorization service.
    AuthorizationRequest,
    /// External authorization decision for a user.
    AuthorizationResponse,
    /// Custom or otherwise unrecognized NATS claim family.
    Generic,
}

impl ClaimType {
    /// Borrow the stored or canonical wire string without allocating.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Account => "account",
            Self::User => "user",
            Self::Activation => "activation",
            Self::AuthorizationRequest => "authorization_request",
            Self::AuthorizationResponse => "authorization_response",
            Self::Generic => "generic",
        }
    }
}

/// Canonical `nats.type` string for operator claims.
pub const OPERATOR_CLAIM: &str = ClaimType::Operator.as_str();
/// Canonical `nats.type` string for account claims.
pub const ACCOUNT_CLAIM: &str = ClaimType::Account.as_str();
/// Canonical `nats.type` string for user claims.
pub const USER_CLAIM: &str = ClaimType::User.as_str();
/// Canonical `nats.type` string for activation claims.
pub const ACTIVATION_CLAIM: &str = ClaimType::Activation.as_str();
/// Canonical `nats.type` string for authorization request claims.
pub const AUTHORIZATION_REQUEST_CLAIM: &str = ClaimType::AuthorizationRequest.as_str();
/// Canonical `nats.type` string for authorization response claims.
pub const AUTHORIZATION_RESPONSE_CLAIM: &str = ClaimType::AuthorizationResponse.as_str();
/// Canonical `nats.type` string for generic claims.
pub const GENERIC_CLAIM: &str = ClaimType::Generic.as_str();

/// Return whether the name is outside the six typed claim families, including unknown and empty names.
pub fn is_generic_claim_type(value: &str) -> bool {
    !matches!(
        value,
        OPERATOR_CLAIM
            | ACCOUNT_CLAIM
            | USER_CLAIM
            | ACTIVATION_CLAIM
            | AUTHORIZATION_REQUEST_CLAIM
            | AUTHORIZATION_RESPONSE_CLAIM
    )
}

/// Common JWT metadata, flattened into the top-level JSON object. Times are Unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaimsData {
    /// Intended recipient (`aud`); authorization responses use the target server public key.
    #[serde(rename = "aud", skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// Expiration (`exp`) in Unix seconds; zero leaves expiration unset.
    #[serde(rename = "exp", skip_serializing_if = "is_zero")]
    pub expires: i64,
    /// Claim identifier (`jti`), regenerated from common metadata during encoding.
    #[serde(rename = "jti", skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Issue time (`iat`) in Unix seconds, refreshed during encoding.
    #[serde(rename = "iat", skip_serializing_if = "is_zero")]
    pub issued_at: i64,
    /// Signer public key (`iss`), refreshed during encoding.
    #[serde(rename = "iss", skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    /// Human-readable name carried as metadata.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Earliest validity time (`nbf`) in Unix seconds; zero leaves it unset.
    #[serde(rename = "nbf", skip_serializing_if = "is_zero")]
    pub not_before: i64,
    /// Claim identity (`sub`), typically an operator, account, or user public key.
    #[serde(rename = "sub", skip_serializing_if = "String::is_empty")]
    pub subject: String,
}

/// Serde omission predicate for zero-valued signed limits or timestamps.
fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// Serde omission predicate for a zero version or weight.
fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

impl ClaimsData {
    /// Append time findings for a positive expiry before now or a not-before time after now; no signature or trust checks are performed.
    pub fn validate(&self, results: &mut ValidationResults) {
        let now = unix_time();
        if self.expires > 0 && now > self.expires {
            results.add_time_check("claim is expired");
        }
        if self.not_before > now {
            results.add_time_check("claim is not yet valid");
        }
    }

    /// Compare issuer and subject strings only; this does not verify a signature or require nonempty keys.
    pub fn is_self_signed(&self) -> bool {
        self.issuer == self.subject
    }

    /// Replace issuer and issue time, then derive `jti` from SHA-512/256 of common metadata with an empty ID. Payload policy fields are not part of the ID hash.
    pub(crate) fn refresh(&mut self, issuer: String) -> Result<()> {
        self.issuer = issuer;
        self.issued_at = unix_time();
        self.id.clear();
        let bytes = serde_json::to_vec(self)?;
        self.id = BASE32_NOPAD.encode(&Sha512_256::digest(bytes));
        Ok(())
    }
}

/// Signing boundary for local keys or external signing services. Implementations return raw signature bytes.
pub trait Signer {
    /// Return the NKey public identity used as the claim issuer, or a provider error.
    fn public_key(&self) -> Result<String>;
    /// Sign the exact supplied bytes and return raw signature bytes, or a provider error; implementations must not re-encode the input.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// Borrowed NKey adapter implementing [`Signer`]; the key must contain signing material to sign.
pub struct KeyPairSigner<'a>(pub &'a KeyPair);

impl Signer for KeyPairSigner<'_> {
    /// Return the wrapped key's public NKey identity.
    fn public_key(&self) -> Result<String> {
        Ok(self.0.public_key())
    }

    /// Sign bytes with the wrapped key; map missing signing material or other NKey failures to the library error type.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0
            .sign(data)
            .map_err(|error| NjError::Nkeys(error.to_string()))
    }
}

/// Serialize a v2 header and payload, then sign the encoded `header.claims` bytes; propagate serialization or signer failures.
pub(crate) fn sign_claim<T: Serialize>(payload: &T, signer: &impl Signer) -> Result<String> {
    let mut token = Header::v2().encode()?;
    token.push('.');
    // Stream JSON directly into the token's Base64 segment, then append the signature.
    let mut writer = EncoderStringWriter::from_consumer(&mut token, &URL_SAFE_NO_PAD);
    serde_json::to_writer(&mut writer, payload)?;
    writer.into_inner();
    let signature = signer.sign(token.as_bytes())?;
    token.push('.');
    URL_SAFE_NO_PAD.encode_string(&signature, &mut token);
    Ok(token)
}

/// Check both NKey validity and the operator public-key prefix.
pub(crate) fn is_operator(key: &str) -> bool {
    nkeys::KeyPair::from_public_key(key).is_ok() && key.starts_with('O')
}

/// Check both NKey validity and the account public-key prefix.
pub(crate) fn is_account(key: &str) -> bool {
    nkeys::KeyPair::from_public_key(key).is_ok() && key.starts_with('A')
}

/// Check both NKey validity and the user public-key prefix.
pub(crate) fn is_user(key: &str) -> bool {
    nkeys::KeyPair::from_public_key(key).is_ok() && key.starts_with('U')
}

/// Parse three unsigned `major.minor.patch` components; an empty value means `(0, 0, 0)`. Malformed components return an error.
pub fn parse_server_version(value: &str) -> Result<(u32, u32, u32)> {
    if value.is_empty() {
        return Ok((0, 0, 0));
    }
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(NjError::InvalidToken(
            "server version must be major.minor.patch".into(),
        ));
    }
    let parsed: Result<Vec<u32>> = parts
        .iter()
        .map(|part| {
            part.parse()
                .map_err(|_| NjError::InvalidToken("invalid server version".into()))
        })
        .collect();
    let parsed = parsed?;
    Ok((parsed[0], parsed[1], parsed[2]))
}

/// Check supported NATS transport schemes and reject credentials or a nonempty first path segment. Empty values are accepted; this is not a full URL parser.
pub fn validate_operator_service_url(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(NjError::InvalidToken("service URL requires scheme".into()));
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "nats" | "tls" | "ws" | "wss"
    ) {
        return Err(NjError::InvalidToken(
            "unsupported service URL scheme".into(),
        ));
    }
    if rest.contains('@') || rest.split('/').nth(1).is_some_and(|path| !path.is_empty()) {
        return Err(NjError::InvalidToken(
            "service URL cannot contain credentials or path".into(),
        ));
    }
    Ok(())
}

/// Operator policy stored in the `nats` object of an operator JWT.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Operator {
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    #[serde(rename = "version", skip_serializing_if = "is_zero_u8")]
    pub version: u8,
    /// Application tags associated with this identity or policy.
    #[serde(
        rename = "tags",
        skip_serializing_if = "crate::policy::TagList::is_empty"
    )]
    pub tags: crate::policy::TagList,
    /// Operator public keys allowed to sign account claims on this operator's behalf.
    #[serde(rename = "signing_keys", skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
    /// Optional account JWT lookup service URL.
    #[serde(
        rename = "account_server_url",
        skip_serializing_if = "String::is_empty"
    )]
    pub account_server_url: String,
    /// NATS transport URLs advertised for this operator.
    #[serde(
        rename = "operator_service_urls",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub operator_service_urls: Vec<String>,
    /// Public key of the account used for system administration.
    #[serde(rename = "system_account", skip_serializing_if = "String::is_empty")]
    pub system_account: String,
    /// Required server version string in `major.minor.patch` form; empty disables this assertion.
    #[serde(
        rename = "assert_server_version",
        skip_serializing_if = "String::is_empty"
    )]
    pub assert_server_version: String,
    /// When true, issuer attribution requires a registered signing key rather than the operator identity key.
    #[serde(
        rename = "strict_signing_key_usage",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub strict_signing_key_usage: bool,
}

/// Operator identity and policy. Encoding checks key types; trust in the operator remains the caller's responsibility.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OperatorClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats", default)]
    pub operator: Operator,
}

impl OperatorClaims {
    /// Borrow tags associated with this claim without normalizing them.
    pub fn get_tags(&self) -> &crate::policy::TagList {
        &self.operator.tags
    }

    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject: subject.clone(),
                issuer: subject,
                ..Default::default()
            },
            operator: Operator::default(),
        })
    }

    /// Check whether the account's issuer is this operator or a registered signing key, respecting strict signing-key usage. This checks attribution, not the signature or account subject.
    pub fn did_sign(&self, claim: &AccountClaims) -> bool {
        let issuer = claim.claims.issuer.as_str();
        (issuer == self.claims.subject && !self.operator.strict_signing_key_usage)
            || self.operator.signing_keys.iter().any(|key| key == issuer)
    }

    /// Append time and operator-policy findings for signing keys, system account, service URLs, and asserted server version; does not establish trust.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.claims.validate(results);
        for key in &self.operator.signing_keys {
            if !is_operator(key) {
                results.add_error(format!("{key} is not an operator public key"));
            }
        }
        if !self.operator.system_account.is_empty() && !is_account(&self.operator.system_account) {
            results.add_error("system account is not an account public key");
        }
        if !self.operator.account_server_url.is_empty()
            && !matches!(
                url::Url::parse(&self.operator.account_server_url),
                Ok(url) if !url.scheme().is_empty()
            )
        {
            results.add_error("invalid account server URL");
        }
        for value in &self.operator.operator_service_urls {
            if let Err(error) = validate_operator_service_url(value) {
                results.add_error(error.to_string());
            }
        }
        if let Err(error) = parse_server_version(&self.operator.assert_server_version) {
            results.add_error(error.to_string());
        }
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }
    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Requires operator subject and signer keys and a valid nonempty account-server URL. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        if !is_operator(&self.claims.subject) || !is_operator(&signer.public_key()?) {
            return Err(NjError::InvalidToken("expected operator keys".into()));
        }
        if !self.operator.account_server_url.is_empty()
            && !matches!(
                url::Url::parse(&self.operator.account_server_url),
                Ok(url) if !url.scheme().is_empty()
            )
        {
            return Err(NjError::InvalidToken("invalid account server URL".into()));
        }
        self.claims.refresh(signer.public_key()?)?;
        self.operator.claim_type = "operator".into();
        self.operator.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}

/// Core NATS resource limits. Zero fields are omitted on serialization; use [`crate::NO_LIMIT`] where unlimited is intended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NatsLimits {
    /// Maximum subscription count; `-1` denotes unlimited where the server permits it.
    #[serde(
        rename = "subs",
        alias = "subscriptions",
        skip_serializing_if = "is_zero"
    )]
    pub subs: i64,
    /// Maximum data volume in bytes; `-1` denotes unlimited where the server permits it.
    #[serde(skip_serializing_if = "is_zero")]
    pub data: i64,
    /// Maximum individual message payload in bytes; `-1` denotes unlimited where the server permits it.
    #[serde(skip_serializing_if = "is_zero")]
    pub payload: i64,
}

/// JetStream storage and resource limits; default zero storage disables JetStream.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JetStreamLimits {
    /// Total JetStream memory storage allowance in bytes; zero disables this storage class.
    #[serde(rename = "mem_storage", skip_serializing_if = "is_zero")]
    pub memory_storage: i64,
    /// Total JetStream file storage allowance in bytes; zero disables this storage class.
    #[serde(skip_serializing_if = "is_zero")]
    pub disk_storage: i64,
    /// Maximum JetStream stream count; `-1` denotes unlimited.
    #[serde(skip_serializing_if = "is_zero")]
    pub streams: i64,
    /// Maximum JetStream consumer count; serialized as `consumer`.
    #[serde(rename = "consumer", skip_serializing_if = "is_zero")]
    pub consumers: i64,
    /// Maximum outstanding unacknowledged messages allowed by JetStream consumer limits.
    #[serde(skip_serializing_if = "is_zero")]
    pub max_ack_pending: i64,
    /// Per-stream memory storage cap in bytes.
    #[serde(rename = "mem_max_stream_bytes", skip_serializing_if = "is_zero")]
    pub memory_max_stream_bytes: i64,
    /// Per-stream file storage cap in bytes.
    #[serde(skip_serializing_if = "is_zero")]
    pub disk_max_stream_bytes: i64,
    /// Whether stream creation must specify a maximum byte count.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub max_bytes_required: bool,
}

impl JetStreamLimits {
    /// Check unlimited storage, stream, and consumer limits, with nonpositive auxiliary limits and no required max-bytes setting.
    pub fn is_unlimited(&self) -> bool {
        self.memory_storage == -1
            && self.disk_storage == -1
            && self.streams == -1
            && self.consumers == -1
            && self.max_ack_pending <= 0
            && self.memory_max_stream_bytes <= 0
            && self.disk_max_stream_bytes <= 0
            && !self.max_bytes_required
    }
    /// Return whether either storage limit is nonzero, including the unlimited sentinel.
    pub fn is_enabled(&self) -> bool {
        self.memory_storage != 0 || self.disk_storage != 0
    }
}

/// Combined account limits. `Default` allows unlimited core resources, while omitted JSON fields decode as zero; JetStream defaults to disabled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default = "AccountLimits::wire_default")]
pub struct AccountLimits {
    /// Maximum subscription count; `-1` denotes unlimited where the server permits it.
    #[serde(
        rename = "subs",
        alias = "subscriptions",
        skip_serializing_if = "is_zero"
    )]
    pub subscriptions: i64,
    /// Maximum data volume in bytes; `-1` denotes unlimited where the server permits it.
    #[serde(skip_serializing_if = "is_zero")]
    pub data: i64,
    /// Maximum individual message payload in bytes; `-1` denotes unlimited where the server permits it.
    #[serde(skip_serializing_if = "is_zero")]
    pub payload: i64,
    /// Maximum number of imports; `-1` means unlimited.
    #[serde(skip_serializing_if = "is_zero")]
    pub imports: i64,
    /// Maximum number of exports; `-1` means unlimited.
    #[serde(skip_serializing_if = "is_zero")]
    pub exports: i64,
    /// Whether exports may use wildcard subjects; serialized as `wildcards`.
    #[serde(
        rename = "wildcards",
        alias = "wildcard_exports",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub wildcard_exports: bool,
    /// Maximum ordinary client connections; serialized as `conn`.
    #[serde(rename = "conn", skip_serializing_if = "is_zero")]
    pub connections: i64,
    /// Maximum leaf-node connections; serialized as `leaf`.
    #[serde(rename = "leaf", skip_serializing_if = "is_zero")]
    pub leaf_connections: i64,
    /// Whether bearer user tokens are forbidden for this account.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub disallow_bearer: bool,
    /// Untiered JetStream limits, flattened into the account limit object.
    #[serde(flatten)]
    pub jetstream: JetStreamLimits,
    /// JetStream limits by tier name; serialized as `tiered_limits`.
    #[serde(
        rename = "tiered_limits",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub tiered: BTreeMap<String, JetStreamLimits>,
}

/// JetStream limits indexed by tier name, such as a replication tier understood by the server.
pub type JetStreamTieredLimits = BTreeMap<String, JetStreamLimits>;

/// Grouped view of operator-imposed account limits. Serialization merges `nats`, account-specific fields, JetStream, and tiered limits into one wire object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "AccountLimits", into = "AccountLimits")]
pub struct OperatorLimits {
    /// Core limits that override the corresponding fields of `account` during conversion to the wire representation.
    pub nats: NatsLimits,
    /// Account-specific limits; its embedded core and JetStream fields are replaced by the separate groups during serialization.
    pub account: AccountLimits,
    /// JetStream group replacing the embedded group of `account` during serialization.
    pub jetstream: JetStreamLimits,
    /// Tiered limits replacing the embedded tiers of `account` during serialization.
    pub tiered: JetStreamTieredLimits,
}

impl Default for OperatorLimits {
    /// Split the combined default account limits into their grouped representation.
    fn default() -> Self {
        AccountLimits::default().into()
    }
}

impl From<OperatorLimits> for AccountLimits {
    /// Merge grouped limits, taking core, JetStream, and tiered fields from the separate groups and account-specific fields from `account`.
    fn from(limits: OperatorLimits) -> Self {
        Self {
            subscriptions: limits.nats.subs,
            data: limits.nats.data,
            payload: limits.nats.payload,
            jetstream: limits.jetstream,
            tiered: limits.tiered,
            ..limits.account
        }
    }
}

impl From<AccountLimits> for OperatorLimits {
    /// Split combined limits into distinct groups; retain account-specific fields without duplicating the active core or JetStream groups.
    fn from(limits: AccountLimits) -> Self {
        Self {
            nats: NatsLimits {
                subs: limits.subscriptions,
                data: limits.data,
                payload: limits.payload,
            },
            account: AccountLimits {
                imports: limits.imports,
                exports: limits.exports,
                wildcard_exports: limits.wildcard_exports,
                connections: limits.connections,
                leaf_connections: limits.leaf_connections,
                disallow_bearer: limits.disallow_bearer,
                ..Default::default()
            },
            jetstream: limits.jetstream,
            tiered: limits.tiered,
        }
    }
}

impl AccountLimits {
    // Omitted wire limits are zero; constructors retain their unlimited defaults.
    /// Supply zero limits for omitted JSON fields, unlike the unlimited core limits used by `Default`.
    fn wire_default() -> Self {
        Self {
            subscriptions: 0,
            data: 0,
            payload: 0,
            imports: 0,
            exports: 0,
            wildcard_exports: false,
            connections: 0,
            leaf_connections: 0,
            ..Self::default()
        }
    }

    /// Check whether every serialized policy field has its zero/empty value.
    fn is_empty(&self) -> bool {
        self.subscriptions == 0
            && self.data == 0
            && self.payload == 0
            && self.imports == 0
            && self.exports == 0
            && !self.wildcard_exports
            && self.connections == 0
            && self.leaf_connections == 0
            && !self.disallow_bearer
            && self.jetstream == JetStreamLimits::default()
            && self.tiered.is_empty()
    }

    /// Check tiered storage limits when present, otherwise the untiered JetStream storage limits.
    pub fn is_jetstream_enabled(&self) -> bool {
        if self.tiered.is_empty() {
            self.jetstream.is_enabled()
        } else {
            self.tiered.values().any(JetStreamLimits::is_enabled)
        }
    }

    /// Require unlimited core and JetStream limits, wildcard exports, no bearer restriction, and no tiered limits.
    pub fn is_unlimited(&self) -> bool {
        self.subscriptions == -1
            && self.data == -1
            && self.payload == -1
            && self.imports == -1
            && self.exports == -1
            && self.wildcard_exports
            && self.connections == -1
            && self.leaf_connections == -1
            && !self.disallow_bearer
            && self.jetstream.is_unlimited()
            && self.tiered.is_empty()
    }

    /// Detect simultaneous nondefault tiered and untiered limits or an empty tier name.
    pub fn is_invalid_tiered_configuration(&self) -> bool {
        (!self.tiered.is_empty() && self.jetstream != JetStreamLimits::default())
            || self.tiered.contains_key("")
    }
}

impl Default for AccountLimits {
    /// Create unlimited core account limits with wildcard exports enabled, JetStream disabled, and no tiers.
    fn default() -> Self {
        Self {
            subscriptions: -1,
            data: -1,
            payload: -1,
            imports: -1,
            exports: -1,
            wildcard_exports: true,
            connections: -1,
            leaf_connections: -1,
            disallow_bearer: false,
            jetstream: JetStreamLimits::default(),
            tiered: BTreeMap::new(),
        }
    }
}

/// Route cluster traffic using the system-account ownership mode.
pub const CLUSTER_TRAFFIC_SYSTEM: ClusterTraffic = ClusterTraffic::System;
/// Route cluster traffic using the owning-account mode.
pub const CLUSTER_TRAFFIC_OWNER: ClusterTraffic = ClusterTraffic::Owner;

/// Cluster traffic ownership mode; unknown strings are preserved as `Other` for later validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClusterTraffic {
    /// Unspecified traffic ownership, serialized as an empty string.
    #[default]
    None,
    /// System-account cluster traffic ownership.
    System,
    /// Owning-account cluster traffic ownership.
    Owner,
    /// Unrecognized wire value retained for validation rather than silently discarded.
    Other(String),
}

impl ClusterTraffic {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Accept only empty, `system`, or `owner` wire values; preserved unknown strings are invalid.
    pub fn is_valid(&self) -> bool {
        matches!(self.as_str(), "" | "system" | "owner")
    }

    /// Borrow the stored or canonical wire string without allocating.
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "",
            Self::System => "system",
            Self::Owner => "owner",
            Self::Other(value) => value,
        }
    }
}

impl From<&str> for ClusterTraffic {
    /// Convert a wire string to a known ownership mode, preserving unknown values for validation.
    fn from(value: &str) -> Self {
        match value {
            "" => Self::None,
            "system" => Self::System,
            "owner" => Self::Owner,
            value => Self::Other(value.to_owned()),
        }
    }
}

impl From<String> for ClusterTraffic {
    /// Convert a wire string to a known ownership mode, preserving unknown values for validation.
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl Serialize for ClusterTraffic {
    /// Serialize the stored ownership mode as a string, preserving unknown values.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ClusterTraffic {
    /// Decode a string mode, preserving unknown values as `Other` for validation.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// Account policy: limits, signing keys, imports, exports, mappings, and authorization settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    /// Inclusive issue-time cutoffs for individual keys or the `*` wildcard.
    #[serde(
        default,
        skip_serializing_if = "crate::policy::RevocationList::is_empty"
    )]
    pub revocations: crate::policy::RevocationList,
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    #[serde(rename = "version", skip_serializing_if = "is_zero_u8")]
    pub version: u8,
    /// Resource and connection restrictions associated with this policy.
    #[serde(default = "AccountLimits::wire_default")]
    pub limits: AccountLimits,
    /// Registered account signing keys, optionally carrying user permission scopes.
    #[serde(default, skip_serializing_if = "crate::policy::SigningKeys::is_empty")]
    pub signing_keys: crate::policy::SigningKeys,
    /// Subjects and services this account imports from other accounts.
    #[serde(default, skip_serializing_if = "crate::policy::Imports::is_empty")]
    pub imports: crate::policy::Imports,
    /// Subjects and services this account makes available to other accounts.
    #[serde(default, skip_serializing_if = "crate::policy::Exports::is_empty")]
    pub exports: crate::policy::Exports,
    /// Fallback permissions for users without explicit permissions.
    #[serde(default)]
    pub default_permissions: crate::policy::Permissions,
    /// Account-local source subjects and their weighted destinations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mappings: crate::policy::Mapping,
    /// Optional external authorization configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<crate::policy::ExternalAuthorization>,
    /// Optional message trace destination and sampling policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<crate::policy::MsgTrace>,
    /// Traffic ownership wire string; validation accepts empty, `system`, or `owner`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster_traffic: String,
    /// Description and URL flattened into account policy.
    #[serde(flatten)]
    pub info: crate::policy::Info,
    /// Application tags associated with this identity or policy.
    #[serde(default, skip_serializing_if = "crate::policy::TagList::is_empty")]
    pub tags: crate::policy::TagList,
}

impl Account {
    /// Insert or replace all destinations for a source subject. No validation or server update is performed.
    pub fn add_mapping(
        &mut self,
        subject: crate::policy::Subject,
        mappings: Vec<crate::policy::WeightedMapping>,
    ) {
        self.mappings.insert(subject, mappings);
    }
}

/// Account identity and policy, signed by an account or operator key. Validation is separate from encoding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats", default)]
    pub account: Account,
}
impl AccountClaims {
    /// Borrow tags associated with this claim without normalizing them.
    pub fn get_tags(&self) -> &crate::policy::TagList {
        &self.account.tags
    }

    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..Default::default()
            },
            account: Account {
                limits: AccountLimits::default(),
                ..Default::default()
            },
        })
    }

    /// Return whether an external authorization configuration contains at least one auth user.
    pub fn has_external_authorization(&self) -> bool {
        self.account
            .authorization
            .as_ref()
            .is_some_and(crate::policy::ExternalAuthorization::is_enabled)
    }

    /// Create the configuration if needed and append auth users; does not deduplicate or validate supplied keys.
    pub fn enable_external_authorization<I, S>(&mut self, users: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let authorization = self
            .account
            .authorization
            .get_or_insert_with(Default::default);
        authorization
            .auth_users
            .extend(users.into_iter().map(Into::into));
    }

    /// Record an inclusive revocation cutoff at the current time; older cutoffs do not replace newer ones. The change remains local until the claim is published.
    pub fn revoke(&mut self, public_key: &str) {
        self.revoke_at(
            public_key,
            std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(crate::time::now_secs() as u64),
        );
    }

    /// Record an inclusive revocation cutoff at the supplied time; older cutoffs do not replace newer ones. The change remains local until the claim is published.
    pub fn revoke_at(&mut self, public_key: &str, timestamp: std::time::SystemTime) {
        self.account.revocations.revoke(public_key, timestamp);
    }

    /// Remove the cutoff for this key. A separate wildcard cutoff still applies.
    pub fn clear_revocation(&mut self, public_key: &str) {
        self.account.revocations.clear_revocation(public_key);
    }

    /// Check the claim's subject and issue time against revocations; missing subjects or zero issue times are treated as revoked.
    pub fn is_claim_revoked(&self, claim: &UserClaims) -> bool {
        if claim.claims.subject.is_empty() || claim.claims.issued_at == 0 {
            return true;
        }
        self.account
            .revocations
            .is_revoked_at(&claim.claims.subject, claim.claims.issued_at)
    }

    /// Check issuer attribution to this account or a registered signing key with matching issuer-account metadata; does not verify signature, scope, or revocation.
    pub fn did_sign(&self, claim: &UserClaims) -> bool {
        let issuer = claim.claims.issuer.as_str();
        issuer == self.claims.subject
            || (claim.user.issuer_account == self.claims.subject
                && self.account.signing_keys.contains(issuer))
    }

    /// Check activation issuer attribution to this account or its registered signing key; does not verify the signature or activation grant.
    pub fn did_sign_activation(&self, claim: &crate::authorization::ActivationClaims) -> bool {
        let issuer = claim.claims.issuer.as_str();
        issuer == self.claims.subject
            || (claim.activation.issuer_account == self.claims.subject
                && self.account.signing_keys.contains(issuer))
    }

    /// Append findings for account policy and time bounds, including import grants and resource counts. Normalizes a zero trace sampling rate to 100; does not verify the trust chain.
    pub fn validate(&mut self, results: &mut ValidationResults) {
        self.claims.validate(results);
        self.account.imports.validate(results);
        for import in &self.account.imports.0 {
            import.validate_token_with_account(&self.claims.subject, results);
        }
        self.account.exports.validate(results);
        self.account.default_permissions.validate(results);
        crate::policy::MappingValidation::validate(&self.account.mappings, results);
        self.account.info.validate(results);
        if let Some(trace) = &mut self.account.trace {
            trace.validate(results);
        }
        if !ClusterTraffic::from(self.account.cluster_traffic.as_str()).is_valid() {
            results.add_error("invalid cluster traffic");
        }
        if let Some(authorization) = &self.account.authorization {
            authorization.validate(results);
        }
        self.account.signing_keys.validate(results);
        if self.account.limits.is_invalid_tiered_configuration() {
            results.add_error("JetStream limits and tiered limits are invalid together");
        }
        if self.account.limits.imports >= 0
            && self.account.imports.0.len() as i64 > self.account.limits.imports
        {
            results.add_error("account contains more imports than allowed");
        }
        if self.account.limits.exports >= 0
            && self.account.exports.0.len() as i64 > self.account.limits.exports
        {
            results.add_error("account contains more exports than allowed");
        }
        if !self.account.limits.wildcard_exports
            && self
                .account
                .exports
                .0
                .iter()
                .any(|export| export.subject.has_wildcards())
        {
            results.add_error("wildcard exports are not allowed");
        }
        if is_account(&self.claims.issuer) && !self.account.limits.is_empty() {
            results.add_warning("self-signed account JWTs shouldn't contain operator limits");
        }
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }
    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Sorts imports and exports in place; requires an account subject and an account or operator signer. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        self.account.imports.sort_by_subject();
        self.account.exports.sort_by_subject();
        let issuer = signer.public_key()?;
        if !is_account(&self.claims.subject) || (!is_account(&issuer) && !is_operator(&issuer)) {
            return Err(NjError::InvalidToken(
                "expected account subject and account or operator signer".into(),
            ));
        }
        self.claims.refresh(issuer)?;
        self.account.claim_type = "account".into();
        self.account.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}

/// Allowed-connection-type wire value for standard NATS connections.
pub const CONNECTION_TYPE_STANDARD: &str = "STANDARD";
/// Allowed-connection-type wire value for NATS over WebSocket connections.
pub const CONNECTION_TYPE_WEBSOCKET: &str = "WEBSOCKET";
/// Allowed-connection-type wire value for leaf-node connections.
pub const CONNECTION_TYPE_LEAFNODE: &str = "LEAFNODE";
/// Allowed-connection-type wire value for leaf-node over WebSocket connections.
pub const CONNECTION_TYPE_LEAFNODE_WS: &str = "LEAFNODE_WS";
/// Allowed-connection-type wire value for MQTT connections.
pub const CONNECTION_TYPE_MQTT: &str = "MQTT";
/// Allowed-connection-type wire value for MQTT over WebSocket connections.
pub const CONNECTION_TYPE_MQTT_WS: &str = "MQTT_WS";
/// Allowed-connection-type wire value for in-process connections.
pub const CONNECTION_TYPE_IN_PROCESS: &str = "IN_PROCESS";

/// User policy carried under `nats`, including permissions, limits, and signing-account attribution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    /// Publish, subscribe, and reply permissions to be enforced by the server.
    #[serde(flatten)]
    pub permissions: crate::policy::Permissions,
    /// Resource and connection restrictions associated with this policy.
    #[serde(flatten)]
    pub limits: crate::policy::UserLimits,
    /// Optional list of accepted `CONNECTION_TYPE_*` wire values.
    #[serde(
        rename = "allowed_connection_types",
        default,
        skip_serializing_if = "crate::policy::is_none_or_empty"
    )]
    pub allowed_connection_types: Option<Vec<String>>,
    /// Application tags associated with this identity or policy.
    #[serde(default, skip_serializing_if = "crate::policy::TagList::is_empty")]
    pub tags: crate::policy::TagList,
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    #[serde(rename = "version", skip_serializing_if = "is_zero_u8")]
    pub version: u8,
    /// Parent account public key when a signing key issues the claim instead of the account key itself.
    pub issuer_account: String,
    /// Whether the token permits authentication without proving possession of the user key.
    pub bearer_token: bool,
    /// Whether the server should require a trusted proxy for this user.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_required: bool,
}

/// User identity and policy signed by an account key or its registered signing key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UserClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats", default)]
    pub user: User,
}
impl UserClaims {
    /// Return whether the claim requests authentication without nonce proof of key ownership.
    pub fn is_bearer_token(&self) -> bool {
        self.user.bearer_token
    }
    /// Borrow tags associated with this claim without normalizing them.
    pub fn get_tags(&self) -> &crate::policy::TagList {
        &self.user.tags
    }

    /// Check the zeroed permissions, limits, and flags required for scoped users; an explicitly present connection-type list is not empty for this check.
    pub fn has_empty_permissions(&self) -> bool {
        self.user.permissions.is_empty()
            && self.user.limits.src.is_empty()
            && self.user.limits.times.is_empty()
            && self.user.limits.locale.is_empty()
            && self.user.limits.subscriptions == 0
            && self.user.limits.data == 0
            && self.user.limits.payload == 0
            && !self.user.bearer_token
            && !self.user.proxy_required
            && self.user.allowed_connection_types.is_none()
    }

    /// Reset limits; when `scoped` is true also clear permissions, connection types, and bearer/proxy flags and set numeric limits to zero. Setting false restores default limits but does not reconstruct previous permissions.
    pub fn set_scoped(&mut self, scoped: bool) {
        self.user.limits = Default::default();
        if scoped {
            self.user.permissions = Default::default();
            self.user.limits.subscriptions = 0;
            self.user.limits.data = 0;
            self.user.limits.payload = 0;
            self.user.bearer_token = false;
            self.user.proxy_required = false;
            self.user.allowed_connection_types = None;
        }
    }

    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..Default::default()
            },
            user: User::default(),
        })
    }
    /// Append time, permission, connection-limit, and issuer-account findings; does not enforce these policies on a live connection.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.claims.validate(results);
        self.user.permissions.validate(results);
        self.user.limits.validate(results);
        if !self.user.issuer_account.is_empty() && !is_account(&self.user.issuer_account) {
            results.add_error("issuer account is not an account public key");
        }
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }
    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Requires a user subject and account signer. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        let issuer = signer.public_key()?;
        if !is_user(&self.claims.subject) || !is_account(&issuer) {
            return Err(NjError::InvalidToken(
                "expected user subject and account signer".into(),
            ));
        }
        self.claims.refresh(issuer)?;
        self.user.claim_type = "user".into();
        self.user.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}

/// Common JWT metadata plus arbitrary fields under `nats`; custom claim types retain their data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenericClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Arbitrary fields serialized inside `nats`, including optional custom `type`; encoding inserts version 2.
    #[serde(rename = "nats", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

impl GenericClaims {
    /// Append common time findings only; arbitrary `nats` data has no schema validation here.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.claims.validate(results);
    }

    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..ClaimsData::default()
            },
            data: BTreeMap::new(),
        })
    }

    /// Classify `nats.type` into a known family, falling back to `Generic`.
    pub fn claim_type(&self) -> ClaimType {
        match self.data.get("type").and_then(Value::as_str) {
            Some(OPERATOR_CLAIM) => ClaimType::Operator,
            Some(ACCOUNT_CLAIM) => ClaimType::Account,
            Some(USER_CLAIM) => ClaimType::User,
            Some(ACTIVATION_CLAIM) => ClaimType::Activation,
            Some(AUTHORIZATION_REQUEST_CLAIM) => ClaimType::AuthorizationRequest,
            Some(AUTHORIZATION_RESPONSE_CLAIM) => ClaimType::AuthorizationResponse,
            _ => ClaimType::Generic,
        }
    }

    /// Borrow the string `nats.type`, or return the generic name when absent or not a string.
    pub fn claim_type_name(&self) -> &str {
        self.data
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or(GENERIC_CLAIM)
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }

    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Sets `nats.version` to 2 without restricting subject or signer family. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        self.claims.refresh(signer.public_key()?)?;
        self.data
            .insert("version".into(), Value::from(SUPPORTED_JWT_VERSION));
        sign_claim(self, signer)
    }
}

/// Signature-verified claim selected by `nats.type`. Semantic validity and trust are not implied.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedClaims {
    /// Operator identity and policy claim.
    Operator(OperatorClaims),
    /// Account identity and policy claim.
    Account(Box<AccountClaims>),
    /// User identity and access policy claim.
    User(UserClaims),
    /// Export activation grant for an importing account.
    Activation(ActivationClaims),
    /// Server request to an external authorization service.
    AuthorizationRequest(Box<AuthorizationRequestClaims>),
    /// External authorization decision for a user.
    AuthorizationResponse(AuthorizationResponseClaims),
    /// Custom or otherwise unrecognized NATS claim family.
    Generic(GenericClaims),
}

/// Verify with [`decode`] and require a operator claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_operator_claims(token: &str) -> Result<OperatorClaims> {
    match decode(token)? {
        DecodedClaims::Operator(claim) => Ok(claim),
        _ => Err(NjError::InvalidToken("not an operator claim".into())),
    }
}

/// Verify with [`decode`] and require a account claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_account_claims(token: &str) -> Result<AccountClaims> {
    match decode(token)? {
        DecodedClaims::Account(claim) => Ok(*claim),
        _ => Err(NjError::InvalidToken("not an account claim".into())),
    }
}

/// Verify with [`decode`] and require a user claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_user_claims(token: &str) -> Result<UserClaims> {
    match decode(token)? {
        DecodedClaims::User(claim) => Ok(claim),
        _ => Err(NjError::InvalidToken("not a user claim".into())),
    }
}

/// Verify with [`decode`] and require a activation claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_activation_claims(token: &str) -> Result<ActivationClaims> {
    match decode(token)? {
        DecodedClaims::Activation(claim) => Ok(claim),
        _ => Err(NjError::InvalidToken("not an activation claim".into())),
    }
}

/// Verify with [`decode`] and require a authorization request claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_authorization_request_claims(token: &str) -> Result<AuthorizationRequestClaims> {
    match decode(token)? {
        DecodedClaims::AuthorizationRequest(claim) => Ok(*claim),
        _ => Err(NjError::InvalidToken(
            "not an authorization request claim".into(),
        )),
    }
}

/// Verify a token with [`decode`] and expose it as generic metadata. Typed tokens are projected through their modeled representation, so unknown typed fields are not preserved.
pub fn decode_generic(token: &str) -> Result<GenericClaims> {
    let decoded = decode(token)?;
    match decoded {
        DecodedClaims::Generic(claim) => Ok(claim),
        DecodedClaims::Operator(claim) => generic_projection(&claim, OPERATOR_CLAIM),
        DecodedClaims::Account(claim) => generic_projection(&*claim, ACCOUNT_CLAIM),
        DecodedClaims::User(claim) => generic_projection(&claim, USER_CLAIM),
        DecodedClaims::Activation(claim) => generic_projection(&claim, ACTIVATION_CLAIM),
        DecodedClaims::AuthorizationRequest(claim) => {
            generic_projection(&*claim, AUTHORIZATION_REQUEST_CLAIM)
        }
        DecodedClaims::AuthorizationResponse(claim) => {
            generic_projection(&claim, AUTHORIZATION_RESPONSE_CLAIM)
        }
    }
}

/// Project a typed claim through its serialized representation and restore its canonical `nats.type`; unmodeled fields are not recovered.
fn generic_projection<T: Serialize>(claim: &T, kind: &str) -> Result<GenericClaims> {
    let value = serde_json::to_value(claim)?;
    let claims: ClaimsData = serde_json::from_value(value.clone())?;
    let mut data = match value.get("nats") {
        Some(Value::Object(fields)) => fields.clone().into_iter().collect(),
        _ => BTreeMap::new(),
    };
    data.insert("type".into(), Value::String(kind.into()));
    Ok(GenericClaims { claims, data })
}

/// Verify with [`decode`] and require a authorization response claim; return an error for another claim family. Semantic validation and trust checks remain separate.
pub fn decode_authorization_response_claims(token: &str) -> Result<AuthorizationResponseClaims> {
    match decode(token)? {
        DecodedClaims::AuthorizationResponse(claim) => Ok(claim),
        _ => Err(NjError::InvalidToken(
            "not an authorization response claim".into(),
        )),
    }
}

/// Verify token structure, v2 metadata, issuer key type, and the signature over `header.claims`, then dispatch by `nats.type`.
///
/// Unknown types become generic claims. Tiered account limits take precedence over untiered JetStream limits. This does not call semantic validators, enforce expiration, or establish operator/account trust. Malformed tokens, invalid signatures, and unsupported typed signers return an error.
pub fn decode(token: &str) -> Result<DecodedClaims> {
    let (header_segment, claims_segment, signature_segment) = split_token(token)?;
    let header_bytes = decode_segment(header_segment)?;
    let _header = Header::decode(
        std::str::from_utf8(&header_bytes)
            .map_err(|error| NjError::InvalidToken(error.to_string()))?,
    )?;
    let claims_bytes = decode_segment(claims_segment)?;
    let raw: serde_json::Value = serde_json::from_slice(&claims_bytes)?;
    if raw
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        return Err(NjError::InvalidToken(
            "unsupported top-level claim type".into(),
        ));
    }
    if raw["nats"]["version"].as_u64() != Some(u64::from(SUPPORTED_JWT_VERSION)) {
        return Err(NjError::InvalidToken("unsupported claim version".into()));
    }
    let kind = raw["nats"]["type"].as_str().unwrap_or("");
    let signature = decode_segment(signature_segment)?;
    let common: ClaimsData = serde_json::from_slice(&claims_bytes)?;
    let key = KeyPair::from_public_key(&common.issuer)
        .map_err(|error| NjError::Nkeys(error.to_string()))?;
    // split_token validated the framing; the signed bytes are already contiguous.
    let signed = &token.as_bytes()[..header_segment.len() + 1 + claims_segment.len()];
    key.verify(signed, &signature)
        .map_err(|_| NjError::InvalidToken("claim failed V2 signature verification".into()))?;
    match kind {
        "operator" if is_operator(&common.issuer) => Ok(DecodedClaims::Operator(
            serde_json::from_slice(&claims_bytes)?,
        )),
        "account" if is_account(&common.issuer) || is_operator(&common.issuer) => {
            let mut claim: AccountClaims = serde_json::from_slice(&claims_bytes)?;
            if !claim.account.limits.tiered.is_empty() {
                claim.account.limits.jetstream = JetStreamLimits::default();
            }
            Ok(DecodedClaims::Account(Box::new(claim)))
        }
        "user" if is_account(&common.issuer) => {
            Ok(DecodedClaims::User(serde_json::from_slice(&claims_bytes)?))
        }
        "activation" if is_account(&common.issuer) || is_operator(&common.issuer) => Ok(
            DecodedClaims::Activation(serde_json::from_slice(&claims_bytes)?),
        ),
        "authorization_request" if common.issuer.starts_with('N') => Ok(
            DecodedClaims::AuthorizationRequest(Box::new(serde_json::from_slice(&claims_bytes)?)),
        ),
        "authorization_response" if is_account(&common.issuer) => Ok(
            DecodedClaims::AuthorizationResponse(serde_json::from_slice(&claims_bytes)?),
        ),
        "operator"
        | "account"
        | "user"
        | "activation"
        | "authorization_request"
        | "authorization_response" => Err(NjError::InvalidToken("unexpected signer prefix".into())),
        _ => Ok(DecodedClaims::Generic(serde_json::from_slice(
            &claims_bytes,
        )?)),
    }
}

/// Read whole Unix seconds, using zero when the system clock precedes the Unix epoch.
fn unix_time() -> i64 {
    crate::time::now_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_encoding_matches_compact_wire_bytes_at_chunk_boundaries() {
        let key = KeyPair::new_user();
        for size in [0, 1, 2, 3, 767, 768, 769, 1023, 1024, 1025, 128 * 1024] {
            let mut claim = GenericClaims::new(key.public_key()).unwrap();
            let text = format!("\"\\\n日本語{}", "x".repeat(size));
            claim
                .data
                .insert("blob".into(), Value::String(text.clone()));
            let token = claim.encode(&key).unwrap();
            // The non-streaming construction is the wire-format oracle.
            let header = Header::v2().encode().unwrap();
            let payload = crate::token::encode_segment(&serde_json::to_vec(&claim).unwrap());
            let input = format!("{header}.{payload}");
            let signature = crate::token::encode_segment(&key.sign(input.as_bytes()).unwrap());
            assert_eq!(token, format!("{input}.{signature}"), "size={size}");
            assert_eq!(decode_generic(&token).unwrap().data["blob"], text);
        }
    }

    /// Verify zero limits survive signing and decoding instead of becoming unlimited.
    #[test]
    fn restrictive_account_limits_survive_token_roundtrip() {
        let operator = KeyPair::new_operator();
        let account = KeyPair::new_account();
        let mut claim = AccountClaims::new(account.public_key()).unwrap();
        claim.account.limits = AccountLimits {
            subscriptions: 0,
            data: 0,
            payload: 0,
            imports: 0,
            exports: 0,
            wildcard_exports: false,
            connections: 0,
            leaf_connections: 0,
            ..Default::default()
        };
        let token = claim.encode(&operator).unwrap();
        let decoded = decode_account_claims(&token).unwrap();
        assert_eq!(decoded.account.limits, claim.account.limits);
    }
}
