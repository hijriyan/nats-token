//! Export activation grants and external authorization request/response claims.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claims::{
    is_account, is_operator, is_user, sign_claim, ClaimsData, KeyPairSigner, Signer,
};
use crate::token::SUPPORTED_JWT_VERSION;
use crate::{NjError, Result};
use nkeys::KeyPair;

/// Grant allowing an importing account to access a stream or service export.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Activation {
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    pub version: u8,
    /// Parent account public key when a signing key issues the claim instead of the account key itself.
    pub issuer_account: String,
    /// Exported subject covered by the grant; serialized as `subject`.
    #[serde(rename = "subject")]
    pub import_subject: String,
    /// Grant transport kind, `stream` or `service`; serialized as `kind`.
    #[serde(rename = "kind")]
    pub import_type: String,
}

impl Activation {
    /// Return whether this policy explicitly selects a service import or export.
    pub fn is_service(&self) -> bool {
        self.import_type == "service"
    }

    /// Return whether this policy explicitly selects a stream import or export.
    pub fn is_stream(&self) -> bool {
        self.import_type == "stream"
    }
}

/// Signed export activation whose JWT subject identifies the importing account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivationClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats")]
    pub activation: Activation,
}
/// Keep activation subject tokens before the first wildcard; a leading wildcard becomes `_` for hash generation.
fn clean_subject(subject: &str) -> String {
    let tokens: Vec<_> = subject.split('.').collect();
    for (index, token) in tokens.iter().enumerate() {
        if *token == "*" || *token == ">" {
            return if index == 0 {
                "_".into()
            } else {
                tokens[..index].join(".")
            };
        }
    }
    subject.into()
}

impl ActivationClaims {
    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..Default::default()
            },
            activation: Activation::default(),
        })
    }
    /// Append common time findings and check import kind, subject syntax, and optional issuer-account key.
    pub fn validate(&self, results: &mut crate::ValidationResults) {
        self.claims.validate(results);
        if !self.activation.is_stream() && !self.activation.is_service() {
            results.add_error("invalid activation import type");
        }
        crate::policy::Subject::from(self.activation.import_subject.as_str()).validate(results);
        if !self.activation.issuer_account.is_empty()
            && !is_account(&self.activation.issuer_account)
        {
            results.add_error("issuer account is not an account public key");
        }
    }

    /// Hash issuer, importing account, and the subject prefix before its first wildcard using SHA-256 and Base32. Missing identity or subject data returns an error.
    pub fn hash_id(&self) -> Result<String> {
        if self.claims.issuer.is_empty()
            || self.claims.subject.is_empty()
            || self.activation.import_subject.is_empty()
        {
            return Err(NjError::InvalidToken(
                "not enough activation data to create a hash".into(),
            ));
        }
        let clean = clean_subject(&self.activation.import_subject);
        let value = format!("{}.{}.{}", self.claims.issuer, self.claims.subject, clean);
        Ok(data_encoding::BASE32.encode(&Sha256::digest(value.as_bytes())))
    }
    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }
    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Requires an account subject and an account or operator signer. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        let issuer = signer.public_key()?;
        if !is_account(&self.claims.subject) || (!is_account(&issuer) && !is_operator(&issuer)) {
            return Err(NjError::InvalidToken(
                "expected account subject and account or operator signer".into(),
            ));
        }
        self.claims.refresh(issuer)?;
        self.activation.claim_type = "activation".into();
        self.activation.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}

/// Serde omission predicate for an absent numeric client identifier.
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Return whether an optional value is absent or empty, for omission from the wire object.
fn is_none_or_empty(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(str::is_empty)
}

/// Server identity and metadata included in an external authorization request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerId {
    /// Human-readable name carried as metadata.
    pub name: String,
    /// Host reported by the server requesting authorization.
    pub host: String,
    /// Server public identity reported in the request.
    pub id: String,
    /// NATS server software version, distinct from the JWT format version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Cluster name reported by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// Application tags associated with this identity or policy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Optional server public encryption key for authorization exchanges.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub xkey: String,
}

/// Server-observed client metadata included in an external authorization request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientInformation {
    /// Client host observed by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Server-assigned numeric client connection ID; zero is omitted.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub id: u64,
    /// User identity reported by the server for this connection.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// Human-readable name carried as metadata.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Application tags associated with this identity or policy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Client name tag reported by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name_tag: String,
    /// Connection kind reported by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Client type serialized as `type`.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub client_type: String,
    /// MQTT client identifier serialized as `mqtt_id`.
    #[serde(rename = "mqtt_id", skip_serializing_if = "String::is_empty")]
    pub mqtt: String,
    /// Server challenge associated with the client authentication attempt.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub nonce: String,
}

/// CONNECT payload metadata for authorization callouts; this is not a network client configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectOptions {
    /// JWT supplied by the client in CONNECT; empty values are omitted.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub jwt: String,
    /// Public NKey supplied by the client.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub nkey: String,
    /// Client signature over the server nonce, serialized as `sig`.
    #[serde(rename = "sig", skip_serializing_if = "String::is_empty")]
    pub signed_nonce: String,
    /// Client authentication token, serialized as `auth_token`.
    #[serde(rename = "auth_token", skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// Client username, serialized as `user`.
    #[serde(rename = "user", skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Client password, serialized as `pass`; treat this metadata as sensitive.
    #[serde(rename = "pass", skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Human-readable name carried as metadata.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Client implementation language reported in CONNECT.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub lang: String,
    /// Client library version reported in CONNECT.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// NATS protocol level reported in CONNECT, not the JWT format version.
    pub protocol: i32,
}

/// TLS details reported by the requesting server; this type does not verify certificates.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientTls {
    /// Negotiated TLS protocol version reported by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Negotiated TLS cipher suite reported by the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cipher: String,
    /// Client certificates supplied as strings in the authorization payload.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<String>,
    /// Certificate chains reported as verified by the server; this library performs no verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verified_chains: Vec<Vec<String>>,
}

/// External authorization request body sent by a NATS server.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthorizationRequest {
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    pub version: u8,
    /// Identity and metadata of the requesting server.
    pub server_id: ServerId,
    /// User public key to be authorized; validation requires a valid user NKey.
    pub user_nkey: String,
    /// Server-observed information about the connecting client.
    pub client_info: ClientInformation,
    /// Credentials and metadata from the client's CONNECT message.
    pub connect_opts: ConnectOptions,
    /// Optional TLS information supplied by the server.
    #[serde(rename = "client_tls", skip_serializing_if = "Option::is_none")]
    pub client_tls: Option<ClientTls>,
    /// Optional nonce binding the authorization exchange.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_nonce: String,
}

/// Server-signed authorization request with common JWT metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequestClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats")]
    pub request: AuthorizationRequest,
}

impl AuthorizationRequestClaims {
    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..Default::default()
            },
            request: AuthorizationRequest::default(),
        })
    }

    /// Append common time findings and require a valid user NKey in the request; this does not authenticate the requesting server.
    pub fn validate(&self, results: &mut crate::ValidationResults) {
        self.claims.validate(results);
        if !is_user(&self.request.user_nkey) {
            results.add_error("user nkey is required and must be a user public key");
        }
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }

    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Requires a valid request user key and server signer. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        if !is_user(&self.request.user_nkey) {
            return Err(NjError::InvalidToken("valid user nkey is required".into()));
        }
        let issuer = signer.public_key()?;
        if KeyPair::from_public_key(&issuer).is_err() || !issuer.starts_with('N') {
            return Err(NjError::InvalidToken("expected server signer".into()));
        }
        self.claims.refresh(issuer)?;
        self.request.claim_type = "authorization_request".into();
        self.request.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}

/// Authorization decision containing exactly one nonempty user JWT or error message.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthorizationResponse {
    /// NATS claim discriminator serialized as `type` within the `nats` object; set by typed encoding.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// NATS claim format version; typed encoding sets this to 2.
    pub version: u8,
    /// Issued user JWT on success; exactly one of this and `error` must be nonempty.
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub jwt: Option<String>,
    /// Reason for denying authorization; mutually exclusive with a nonempty `jwt`.
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub error: Option<String>,
    /// Optional account attribution when a signing key signs the response; nonempty values must be account public keys.
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub issuer_account: Option<String>,
}
/// Account-signed authorization decision; the subject is a user key and audience is the target server key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationResponseClaims {
    /// Common top-level JWT metadata, flattened during serialization.
    #[serde(flatten)]
    pub claims: ClaimsData,
    /// Type-specific policy serialized under the JWT `nats` object.
    #[serde(rename = "nats")]
    pub authorization: AuthorizationResponse,
}
impl AuthorizationResponseClaims {
    /// Create an unsigned claim for a nonempty subject; return `None` for an empty string. Key syntax is checked later, not by this constructor.
    pub fn new(subject: impl Into<String>) -> Option<Self> {
        let subject = subject.into();
        (!subject.is_empty()).then(|| Self {
            claims: ClaimsData {
                subject,
                ..Default::default()
            },
            authorization: AuthorizationResponse::default(),
        })
    }
    /// Append common time findings and check user subject, server audience, issuer account, and exactly one nonempty JWT or error. The embedded user JWT is not verified here.
    pub fn validate(&self, results: &mut crate::ValidationResults) {
        self.claims.validate(results);
        if !is_user(&self.claims.subject) {
            results.add_error("subject must be a user public key");
        }
        if KeyPair::from_public_key(&self.claims.audience).is_err()
            || !self.claims.audience.starts_with('N')
        {
            results.add_error("audience must be a server public key");
        }
        if is_none_or_empty(&self.authorization.jwt) == is_none_or_empty(&self.authorization.error)
        {
            results.add_error("exactly one of jwt or error is required");
        }
        if let Some(account) = &self.authorization.issuer_account {
            if !is_account(account) {
                results.add_error("issuer account must be an account public key");
            }
        }
    }

    /// Encode using a local NKey via `encode_with_signer`; updates issue time, issuer, ID, and v2 metadata. Signing and serialization failures are returned; full semantic validation is separate.
    pub fn encode(&mut self, key: &KeyPair) -> Result<String> {
        self.encode_with_signer(&KeyPairSigner(key))
    }
    /// Encode using a custom signer and refresh issue time, issuer, ID, and v2 metadata. Requires an account signer and exactly one nonempty JWT or error. Returns key, serialization, or signing errors; does not run full semantic validation.
    pub fn encode_with_signer(&mut self, signer: &impl Signer) -> Result<String> {
        if is_none_or_empty(&self.authorization.jwt) == is_none_or_empty(&self.authorization.error)
        {
            return Err(NjError::InvalidToken(
                "exactly one of jwt or error is required".into(),
            ));
        }
        let issuer = signer.public_key()?;
        if !is_account(&issuer) {
            return Err(NjError::InvalidToken("expected account signer".into()));
        }
        self.claims.refresh(issuer)?;
        self.authorization.claim_type = "authorization_response".into();
        self.authorization.version = SUPPORTED_JWT_VERSION;
        sign_claim(self, signer)
    }
}
