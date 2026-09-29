//! NATS account and user policies and their semantic validators.
//!
//! These types describe server-enforced behavior; they do not authorize network operations
//! on their own. Validation generally appends findings without changing values;
//! `MsgTrace::validate` also normalizes its sampling default.

use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::claims::{is_account, is_user};
use crate::ValidationResults;

/// Return whether an optional value is absent or empty, for omission from the wire object.
pub(crate) fn is_none_or_empty(value: &Option<Vec<String>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

/// String collection whose `add` method skips empty values and exact duplicates; direct mutation and deserialization do not normalize entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StringList(Vec<String>);

impl StringList {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check exact, case-sensitive membership.
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|item| item == value)
    }

    /// Remove the first exact match, leaving order and other entries unchanged.
    pub fn remove(&mut self, value: &str) {
        if let Some(index) = self.0.iter().position(|item| item == value) {
            self.0.remove(index);
        }
    }

    /// Append nonempty, case-sensitive unique strings while preserving insertion order.
    pub fn add<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let value = value.as_ref();
            if !value.is_empty() && !self.contains(value) {
                self.0.push(value.to_owned());
            }
        }
    }
}

impl Deref for StringList {
    /// Underlying collection exposed through dereferencing.
    type Target = Vec<String>;
    /// Borrow the underlying string vector; no normalization is performed.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StringList {
    /// Mutably borrow the underlying vector; direct writes bypass the collection's normalization rules.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq<Vec<&str>> for StringList {
    /// Compare stored strings and order exactly with the supplied string slice vector.
    fn eq(&self, other: &Vec<&str>) -> bool {
        self.0.iter().map(String::as_str).eq(other.iter().copied())
    }
}

/// Tag collection whose helpers trim and lowercase values; deserialization preserves the supplied strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TagList(Vec<String>);

impl TagList {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Trim and lowercase the query before checking stored entries.
    pub fn contains(&self, value: &str) -> bool {
        let value = value.trim().to_lowercase();
        self.0.contains(&value)
    }

    /// Remove the first match for the trimmed, lowercased query.
    pub fn remove(&mut self, value: &str) {
        let value = value.trim().to_lowercase();
        if let Some(index) = self.0.iter().position(|item| item == &value) {
            self.0.remove(index);
        }
    }

    /// Trim and lowercase incoming tags, skipping empty values and duplicates while preserving insertion order.
    pub fn add<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let value = value.as_ref().trim().to_lowercase();
            if !value.is_empty() && !self.0.contains(&value) {
                self.0.push(value);
            }
        }
    }
}

impl Deref for TagList {
    /// Underlying collection exposed through dereferencing.
    type Target = Vec<String>;
    /// Borrow the underlying string vector; no normalization is performed.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<Vec<&str>> for TagList {
    /// Compare stored strings and order exactly with the supplied string slice vector.
    fn eq(&self, other: &Vec<&str>) -> bool {
        self.0.iter().map(String::as_str).eq(other.iter().copied())
    }
}

/// Owned NATS subject or wildcard pattern. Construction does not validate syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject(String);

/// Import subject transformation with wildcard references; validation requires the source subject.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RenamingSubject(String);

impl From<&str> for RenamingSubject {
    /// Copy a subject transformation string without validating wildcard references.
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl RenamingSubject {
    /// Check destination syntax and matching wildcard tail/count against the source, including numeric reference bounds.
    pub fn validate(&self, from: &Subject, results: &mut ValidationResults) {
        Subject(self.0.clone()).validate(results);
        if from.is_empty() {
            results.add_error("subject cannot be empty");
            return;
        }
        let from_tail = from.as_str() == ">" || from.as_str().ends_with(".>");
        let to_tail = self.0 == ">" || self.0.ends_with(".>");
        if from_tail != to_tail {
            results.add_error("wildcard suffix mismatch");
        }
        let wildcards = from
            .as_str()
            .split('.')
            .filter(|token| *token == "*")
            .count();
        let mut references = 0;
        for token in self.0.split('.') {
            if token == "*" {
                references += 1;
            } else if let Some(index) = token
                .strip_prefix('$')
                .and_then(|value| value.parse::<usize>().ok())
            {
                references += 1;
                if index > wildcards {
                    results.add_error("wildcard reference is out of range");
                }
            }
        }
        if wildcards != references {
            results.add_error("wildcard reference count mismatch");
        }
    }

    /// Replace numeric `$n` references with `*` for namespace comparisons; no validation is performed.
    pub fn to_subject(&self) -> Subject {
        Subject(
            self.0
                .split('.')
                .map(|token| {
                    if token.starts_with('$') && token[1..].parse::<usize>().is_ok() {
                        "*"
                    } else {
                        token
                    }
                })
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

impl From<&str> for Subject {
    /// Copy a subject string without validating its syntax.
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Subject {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the stored or canonical wire string without allocating.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Detect tokens that are exactly `*` or `>`; embedded wildcard characters do not count.
    pub fn has_wildcards(&self) -> bool {
        self.0.split('.').any(|token| matches!(token, "*" | ">"))
    }

    /// Compare tokens against another pattern, allowing `*` and a trailing `>` in the containing pattern. Call on validated subjects; this is a token matcher, not a full symbolic pattern solver.
    pub fn is_contained_in(&self, other: &Self) -> bool {
        let mine: Vec<_> = self.0.split('.').collect();
        let theirs: Vec<_> = other.0.split('.').collect();
        if mine.len() < theirs.len() || (mine.len() > theirs.len() && theirs.last() != Some(&">")) {
            return false;
        }
        theirs.iter().enumerate().all(|(index, token)| {
            *token == ">" && index == theirs.len() - 1
                || *token == "*"
                || mine.get(index) == Some(token)
        })
    }

    /// Reject an empty subject, spaces, or empty dot-separated tokens. This does not enforce every server wildcard-position rule.
    pub fn validate(&self, results: &mut ValidationResults) {
        if self.0.is_empty() {
            results.add_error("subject cannot be empty");
        } else if self.0.contains(' ')
            || self.0.starts_with('.')
            || self.0.ends_with('.')
            || self.0.contains("..")
        {
            results.add_error(format!("invalid subject {:?}", self.0));
        }
    }
}

/// Account signing authority, either an unrestricted public key or a user-scoped key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SigningKey {
    /// Unrestricted account signing public key.
    Key(String),
    /// Account signing key with a user permission template.
    UserScope(Box<UserScope>),
}

/// Signing-key scope that supplies permissions and limits to otherwise empty user claims. Use `new` for the canonical kind and unlimited template limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UserScope {
    /// Scope discriminator; user-scope deserialization requires `user_scope`.
    pub kind: String,
    /// Account public signing key that owns this scope.
    pub key: String,
    /// Application-defined role label attached to the scope.
    pub role: String,
    /// Permissions and limits to apply to users issued by this scoped key.
    #[serde(default)]
    pub template: crate::policy::UserPermissionLimits,
    /// Human-readable description; validation may enforce an information-size limit.
    #[serde(default)]
    pub description: String,
}

/// Deserialization staging fields used to reject unsupported scope kinds before constructing a user scope.
#[derive(Deserialize)]
struct UserScopeWire {
    /// Scope discriminator; user-scope deserialization requires `user_scope`.
    kind: String,
    /// Account public signing key that owns this scope.
    key: String,
    /// Application-defined role label attached to the scope.
    role: String,
    /// Permissions and limits to apply to users issued by this scoped key.
    #[serde(default)]
    template: UserPermissionLimits,
    /// Human-readable description; validation may enforce an information-size limit.
    #[serde(default)]
    description: String,
}

impl<'de> Deserialize<'de> for UserScope {
    /// Decode scope fields and reject any kind other than `user_scope`.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = UserScopeWire::deserialize(deserializer)?;
        if wire.kind != "user_scope" {
            return Err(serde::de::Error::custom("unknown signing key scope"));
        }
        Ok(Self {
            kind: wire.kind,
            key: wire.key,
            role: wire.role,
            template: wire.template,
            description: wire.description,
        })
    }
}

/// Permissions and limits applied by a user scope. Default numeric limits are zero, unlike `UserLimits::default`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserPermissionLimits {
    /// Publish, subscribe, and reply permissions to be enforced by the server.
    #[serde(flatten)]
    pub permissions: Permissions,
    /// Resource and connection restrictions associated with this policy.
    #[serde(flatten)]
    pub limits: UserLimits,
    /// Whether the token permits authentication without proving possession of the user key.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub bearer_token: bool,
    /// Whether the server should require a trusted proxy for this user.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub proxy_required: bool,
    /// Optional list of accepted `CONNECTION_TYPE_*` wire values.
    #[serde(skip_serializing_if = "is_none_or_empty")]
    pub allowed_connection_types: Option<Vec<String>>,
}

impl Default for UserPermissionLimits {
    /// Create empty permissions with zero numeric limits for a scope template.
    fn default() -> Self {
        Self {
            permissions: Permissions::default(),
            limits: UserLimits {
                subscriptions: 0,
                data: 0,
                payload: 0,
                ..Default::default()
            },
            bearer_token: false,
            proxy_required: false,
            allowed_connection_types: None,
        }
    }
}

impl UserScope {
    /// Create a `user_scope` with unlimited numeric template limits; key and role remain empty for the caller to fill.
    pub fn new() -> Self {
        Self {
            kind: "user_scope".into(),
            template: UserPermissionLimits {
                limits: UserLimits {
                    subscriptions: crate::NO_LIMIT,
                    data: crate::NO_LIMIT,
                    payload: crate::NO_LIMIT,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Require matching signer identity and empty user permissions/limits; return an error on either mismatch. Does not verify the JWT signature.
    pub fn validate_user(&self, claim: &crate::UserClaims) -> crate::Result<()> {
        if claim.claims.issuer != self.key {
            return Err(crate::NjError::InvalidToken(
                "scoped signer issuer mismatch".into(),
            ));
        }
        if !claim.has_empty_permissions() {
            return Err(crate::NjError::InvalidToken(
                "scoped user permissions must be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Account signing-key collection; additions replace the same key, and serialization sorts entries by public key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigningKeys(Vec<SigningKey>);

impl<'de> Deserialize<'de> for SigningKeys {
    /// Decode signing keys and replace earlier entries when the same public key occurs again.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<SigningKey>::deserialize(deserializer)?;
        let mut keys = Self::default();
        for entry in entries {
            keys.add(entry);
        }
        Ok(keys)
    }
}

impl Serialize for SigningKeys {
    /// Serialize entries sorted by public key without changing their in-memory order.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut keys: Vec<_> = self.0.iter().collect();
        keys.sort_by_key(|key| match key {
            SigningKey::Key(key) => key.as_str(),
            SigningKey::UserScope(scope) => scope.key.as_str(),
        });
        keys.serialize(serializer)
    }
}

impl SigningKeys {
    /// Replace any existing entry with the same public key, then append the new key or scope.
    pub fn add(&mut self, key: SigningKey) {
        let public_key = match &key {
            SigningKey::Key(key) => key.clone(),
            SigningKey::UserScope(scope) => scope.key.clone(),
        };
        self.remove(&public_key);
        self.0.push(key);
    }

    /// Check whether a plain or scoped entry has the supplied public key.
    pub fn contains(&self, public_key: &str) -> bool {
        self.0.iter().any(|key| match key {
            SigningKey::Key(key) => key == public_key,
            SigningKey::UserScope(scope) => scope.key == public_key,
        })
    }

    /// Return owned public-key strings sorted lexicographically.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = self
            .0
            .iter()
            .map(|key| match key {
                SigningKey::Key(key) => key.clone(),
                SigningKey::UserScope(scope) => scope.key.clone(),
            })
            .collect();
        keys.sort();
        keys
    }

    /// Borrow the scope for this public key, or return `None` for a missing or unrestricted key.
    pub fn get_scope(&self, public_key: &str) -> Option<&UserScope> {
        self.0.iter().find_map(|key| match key {
            SigningKey::UserScope(scope) if scope.key == public_key => Some(scope.as_ref()),
            _ => None,
        })
    }

    /// Remove all entries for the supplied public key.
    pub fn remove(&mut self, public_key: &str) {
        self.0.retain(|key| match key {
            SigningKey::Key(key) => key != public_key,
            SigningKey::UserScope(scope) => scope.key != public_key,
        });
    }

    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Append findings for keys that are not valid account NKeys; scope templates are not validated here.
    pub fn validate(&self, results: &mut ValidationResults) {
        for key in &self.0 {
            let public_key = match key {
                SigningKey::Key(key) => key,
                SigningKey::UserScope(scope) => &scope.key,
            };
            if !matches!(
                nkeys::KeyPair::from_public_key(public_key),
                Ok(key) if key.key_pair_type() == nkeys::KeyPairType::Account
            ) {
                results.add_error(format!("{public_key} is not an account public key"));
            }
        }
    }
}

/// Whether an import or export transports messages or request/reply traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportType {
    /// Stream of messages shared between accounts.
    #[default]
    Stream,
    /// Request/reply service shared between accounts.
    Service,
}

/// Service response mode with the case-sensitive wire names used by NATS JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// One response per service request.
    Singleton,
    /// Multiple responses streamed for a service request.
    Stream,
    /// Chunked responses for a service request.
    Chunked,
}

impl ResponseType {
    /// Borrow the stored or canonical wire string without allocating.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Singleton => "Singleton",
            Self::Stream => "Stream",
            Self::Chunked => "Chunked",
        }
    }
}

impl From<ResponseType> for String {
    /// Allocate the canonical response-mode wire string.
    fn from(value: ResponseType) -> Self {
        value.as_str().into()
    }
}

impl std::fmt::Display for ResponseType {
    /// Write the canonical service response mode to the formatter.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Wire name for a service returning a single response.
pub const RESPONSE_TYPE_SINGLETON: &str = ResponseType::Singleton.as_str();
/// Wire name for a service returning streamed responses.
pub const RESPONSE_TYPE_STREAM: &str = ResponseType::Stream.as_str();
/// Wire name for a service returning chunked responses.
pub const RESPONSE_TYPE_CHUNKED: &str = ResponseType::Chunked.as_str();

/// Latency sampling percentage; zero serializes as `headers`, 1 through 100 as a number. Invalid numbers may decode but cannot serialize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct SamplingRate(pub i32);

/// Latency sampling mode controlled by request headers rather than a fixed percentage.
pub const HEADERS: SamplingRate = SamplingRate(0);

impl Serialize for SamplingRate {
    /// Serialize zero as `headers`, or 1 through 100 as a number; reject other values.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            0 => serializer.serialize_str("headers"),
            1..=100 => serializer.serialize_i32(self.0),
            _ => Err(serde::ser::Error::custom("unknown sampling rate")),
        }
    }
}

impl<'de> Deserialize<'de> for SamplingRate {
    /// Decode a numeric rate or case-insensitive `headers`; reject other strings. Numeric bounds are checked when validating or serializing.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Temporary wire representation for custom sampling deserialization.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            /// Numeric sampling value from the wire.
            Number(i32),
            /// Named sampling mode from the wire.
            Text(String),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Number(value) => Ok(Self(value)),
            Wire::Text(value) if value.eq_ignore_ascii_case("headers") => Ok(HEADERS),
            Wire::Text(_) => Err(serde::de::Error::custom("invalid sampling rate")),
        }
    }
}

/// Service latency measurement configuration and result subject.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceLatency {
    /// Latency sampling percentage; zero means request-header-controlled sampling.
    pub sampling: i32,
    /// Subject receiving service latency measurements; must not contain wildcards.
    pub results: Subject,
}

impl Serialize for ServiceLatency {
    /// Serialize the sampling mode and result subject; reject rates outside 0 through 100.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        if !(0..=100).contains(&self.sampling) {
            return Err(serde::ser::Error::custom("invalid sampling rate"));
        }
        let mut state = serializer.serialize_struct("ServiceLatency", 2)?;
        state.serialize_field("sampling", &SamplingRate(self.sampling))?;
        state.serialize_field("results", &self.results)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ServiceLatency {
    /// Decode result subject and numeric/header sampling; range validation is separate.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Temporary wire representation for custom sampling deserialization.
        #[derive(Deserialize)]
        struct Wire {
            /// Sampling value to decode using the custom rate representation.
            sampling: serde_json::Value,
            /// Subject to receive latency results.
            results: Subject,
        }
        let wire = Wire::deserialize(deserializer)?;
        let sampling = serde_json::from_value::<SamplingRate>(wire.sampling)
            .map_err(serde::de::Error::custom)?
            .0;
        Ok(Self {
            sampling,
            results: wire.results,
        })
    }
}

impl ServiceLatency {
    /// Accept sampling zero (headers) or 1 through 100, and require a valid non-wildcard result subject.
    pub fn validate(&self, results: &mut ValidationResults) {
        if !(0..=100).contains(&self.sampling) {
            results.add_error("sampling percentage must be between 1 and 100");
        }
        self.results.validate(results);
        if self.results.has_wildcards() {
            results.add_error("latency results subject cannot contain wildcards");
        }
    }
}

/// Stream or service made available to other accounts, optionally requiring an activation token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Export {
    /// Human-readable name carried as metadata.
    pub name: String,
    /// Subject pattern associated with this routing policy; construction alone does not validate it.
    pub subject: Subject,
    /// Explicit stream or service kind; missing values fail semantic validation.
    #[serde(rename = "type")]
    pub export_type: Option<ExportType>,
    /// Whether importing accounts must present activation tokens.
    pub token_req: bool,
    /// Whether this import/export permits tracing where its transport kind supports it.
    pub allow_trace: bool,
    /// Service response wire mode; absent or empty means single response.
    pub response_type: Option<String>,
    /// One-based position of the wildcard token carrying an account identifier; zero leaves it unset.
    pub account_token_position: Option<u32>,
    /// Service response threshold in Go duration wire units (nanoseconds); negative values are invalid.
    pub response_threshold: Option<i64>,
    /// Whether the export is advertised to interested accounts.
    pub advertise: bool,
    /// Human-readable description; validation may enforce an information-size limit.
    pub description: String,
    /// Optional URL with more information; validated separately from serialization.
    pub info_url: String,
    /// Optional service latency tracking configuration; not valid for stream exports.
    #[serde(rename = "service_latency")]
    pub latency: Option<ServiceLatency>,
    /// Inclusive issue-time cutoffs for individual keys or the `*` wildcard.
    #[serde(default, skip_serializing_if = "RevocationList::is_empty")]
    pub revocations: RevocationList,
}

impl Export {
    /// Return whether this policy explicitly selects a service import or export.
    pub fn is_service(&self) -> bool {
        self.export_type == Some(ExportType::Service)
    }
    /// Return whether this policy explicitly selects a stream import or export.
    pub fn is_stream(&self) -> bool {
        self.export_type == Some(ExportType::Stream)
    }
    /// Return whether this service uses the default/empty response mode or explicit `Singleton`.
    pub fn is_single_response(&self) -> bool {
        self.is_service()
            && matches!(
                self.response_type.as_deref(),
                None | Some("" | RESPONSE_TYPE_SINGLETON)
            )
    }
    /// Return whether this service explicitly uses `Stream` responses.
    pub fn is_stream_response(&self) -> bool {
        self.is_service() && self.response_type.as_deref() == Some(RESPONSE_TYPE_STREAM)
    }
    /// Return whether this service explicitly uses `Chunked` responses.
    pub fn is_chunked_response(&self) -> bool {
        self.is_service() && self.response_type.as_deref() == Some(RESPONSE_TYPE_CHUNKED)
    }

    /// Record an inclusive revocation cutoff at the current time; older cutoffs do not replace newer ones. The change remains local until the claim is published.
    pub fn revoke(&mut self, public_key: &str) {
        self.revoke_at(public_key, SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(crate::time::now_secs() as u64));
    }

    /// Record an inclusive revocation cutoff at the supplied time; older cutoffs do not replace newer ones. The change remains local until the claim is published.
    pub fn revoke_at(&mut self, public_key: &str, timestamp: SystemTime) {
        self.revocations.revoke(public_key, timestamp);
    }

    /// Remove the cutoff for this key. A separate wildcard cutoff still applies.
    pub fn clear_revocation(&mut self, public_key: &str) {
        self.revocations.clear_revocation(public_key);
    }

    /// Check the key and wildcard cutoffs against the claim's issue time, including equality.
    pub fn is_revoked(&self, public_key: &str, timestamp: SystemTime) -> bool {
        self.revocations.is_revoked(public_key, timestamp)
    }

    /// Check the claim's subject and issue time against revocations; missing subjects or zero issue times are treated as revoked.
    pub fn is_claim_revoked(&self, claim: &crate::authorization::ActivationClaims) -> bool {
        if claim.claims.subject.is_empty() || claim.claims.issued_at == 0 {
            return true;
        }
        self.revocations
            .is_revoked_at(&claim.claims.subject, claim.claims.issued_at)
    }

    /// Create an export with its subject and transport kind; remaining fields use defaults and syntax is not validated yet.
    pub fn new(subject: &str, export_type: ExportType) -> Self {
        Self {
            subject: Subject::from(subject),
            export_type: Some(export_type),
            ..Default::default()
        }
    }

    /// Append subject, transport, response, latency, account-token-position, and descriptive metadata findings; does not consult an importing account.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.subject.validate(results);
        if self.export_type.is_none() {
            results.add_error("invalid export type");
        }
        if self.is_stream()
            && self
                .response_type
                .as_deref()
                .is_some_and(|mode| !mode.is_empty())
        {
            results.add_error("stream export cannot have response type");
        }
        if self.is_stream() && self.allow_trace {
            results.add_error("allow trace only valid for service exports");
        }
        if self.is_service()
            && self.response_type.as_deref().is_some_and(|mode| {
                !matches!(
                    mode,
                    "" | RESPONSE_TYPE_SINGLETON | RESPONSE_TYPE_STREAM | RESPONSE_TYPE_CHUNKED
                )
            })
        {
            results.add_error("invalid service response type");
        }
        if let Some(threshold) = self.response_threshold {
            if threshold < 0 {
                results.add_error("negative response threshold is invalid");
            } else if threshold > 0 && !self.is_service() {
                results.add_error("response threshold only valid for services");
            }
        }
        if let Some(latency) = &self.latency {
            if !self.is_service() {
                results.add_error("latency tracking only permitted for services");
            }
            latency.validate(results);
        }
        if let Some(position) = self.account_token_position.filter(|position| *position > 0) {
            let tokens: Vec<_> = self.subject.as_str().split('.').collect();
            if position as usize > tokens.len() || tokens[position as usize - 1] != "*" {
                results.add_error("account token position must select a wildcard");
            }
        }
        Info {
            description: self.description.clone(),
            info_url: self.info_url.clone(),
        }
        .validate(results);
    }
}

/// Export collection with namespace-overlap validation and explicit subject sorting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exports(pub Vec<Export>);

impl Exports {
    /// Check whether any export contains this subject pattern, without filtering transport kind or checking activation authorization.
    pub fn has_export_containing_subject(&self, subject: &Subject) -> bool {
        self.0
            .iter()
            .any(|export| subject.is_contained_in(&export.subject))
    }

    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sort entries in place by source subject for deterministic claim encoding.
    pub fn sort_by_subject(&mut self) {
        self.0
            .sort_by(|left, right| left.subject.cmp(&right.subject));
    }
    /// Validate each export and reject overlapping subject namespaces of the same transport kind.
    pub fn validate(&self, results: &mut ValidationResults) {
        for export in &self.0 {
            export.validate(results);
        }
        for (index, export) in self.0.iter().enumerate() {
            for other in self.0.iter().skip(index + 1) {
                if export.export_type == other.export_type
                    && (export.subject.is_contained_in(&other.subject)
                        || other.subject.is_contained_in(&export.subject))
                {
                    results.add_error("overlapping export subject namespace");
                }
            }
        }
    }
}

/// Stream or service imported from another account, optionally renamed or authorized by an activation JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Import {
    /// Human-readable name carried as metadata.
    pub name: String,
    /// Subject pattern associated with this routing policy; construction alone does not validate it.
    pub subject: Subject,
    /// Public identity of the exporting account; base validation requires a nonempty value.
    pub account: String,
    /// Optional signed activation JWT authorizing access to a private export.
    pub token: String,
    /// Explicit stream or service kind; missing values fail semantic validation.
    #[serde(rename = "type")]
    pub import_type: Option<ExportType>,
    /// Legacy remapped subject; cannot be combined with a nonempty `local_subject`.
    pub to: Subject,
    /// Optional import subject transformation replacing `to`.
    pub local_subject: Option<RenamingSubject>,
    /// Whether service imports share requester information; invalid for stream imports.
    pub share: bool,
    /// Whether this import/export permits tracing where its transport kind supports it.
    pub allow_trace: bool,
}

impl Import {
    /// Return whether this policy explicitly selects a service import or export.
    pub fn is_service(&self) -> bool {
        self.import_type == Some(ExportType::Service)
    }
    /// Return whether this policy explicitly selects a stream import or export.
    pub fn is_stream(&self) -> bool {
        self.import_type == Some(ExportType::Stream)
    }

    /// Create an import with a subject and transport kind. The exporting account still needs to be set before validation.
    pub fn new(subject: &str, import_type: ExportType) -> Self {
        Self {
            subject: Subject::from(subject),
            import_type: Some(import_type),
            ..Default::default()
        }
    }

    /// Choose `to`, then a nonempty renamed local subject, then the original subject for overlap checks.
    fn effective_subject(&self) -> Subject {
        if !self.to.is_empty() {
            return self.to.clone();
        }
        self.local_subject
            .as_ref()
            .filter(|local| !local.0.is_empty())
            .map(RenamingSubject::to_subject)
            .unwrap_or_else(|| self.subject.clone())
    }

    /// Append findings for import configuration and activation-token decoding. A nonempty exporter string is required; its NKey syntax is not checked here.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.subject.validate(results);
        if self.account.is_empty() {
            results.add_error("account to import from is not specified");
        }
        if self.import_type.is_none() {
            results.add_error("invalid import type");
        }
        if self.is_service() && self.allow_trace {
            results.add_error("allow trace only valid for stream imports");
        }
        if self.share && !self.is_service() {
            results.add_error("sharing information is only valid for service imports");
        }
        if !self.to.is_empty()
            && self
                .local_subject
                .as_ref()
                .is_some_and(|local| !local.0.is_empty())
        {
            results.add_error("local subject replaces to");
        }
        if let Some(local) = &self.local_subject {
            if !local.0.is_empty() {
                local.validate(&self.subject, results);
            }
        }
        if !self.token.is_empty() && crate::decode_activation_claims(&self.token).is_err() {
            results.add_error("invalid import activation token");
        }
    }

    /// Validate the import and check activation subject, issuer attribution, kind, and subject coverage against the importing account. Does not establish exporter signing-key trust or check revocation.
    pub fn validate_with_account(
        &self,
        account_subject: impl AsRef<str>,
        results: &mut ValidationResults,
    ) {
        self.validate(results);
        self.validate_token_with_account(account_subject.as_ref(), results);
    }

    /// Check a decodable activation's binding to importer/exporter and subject coverage; absent or undecodable tokens are skipped here because base validation reports decoding failures.
    pub(crate) fn validate_token_with_account(
        &self,
        account_subject: &str,
        results: &mut ValidationResults,
    ) {
        if self.token.is_empty() {
            return;
        }
        let activation = match crate::decode_activation_claims(&self.token) {
            Ok(activation) => activation,
            Err(_) => return,
        };
        if !activation.activation.is_stream() && !activation.activation.is_service() {
            results.add_error("invalid activation import type");
        }
        Subject::from(activation.activation.import_subject.as_str()).validate(results);
        if !activation.activation.issuer_account.is_empty()
            && !is_account(&activation.activation.issuer_account)
        {
            results.add_error("invalid activation issuer account");
        }
        if activation.claims.subject != account_subject {
            results.add_error("activation subject does not match importing account");
        }
        if activation.claims.issuer != self.account
            && activation.activation.issuer_account != self.account
        {
            results.add_error("activation issuer does not match import account");
        }
        let import_type = match self.import_type {
            Some(ExportType::Stream) => "stream",
            Some(ExportType::Service) => "service",
            None => "",
        };
        if activation.activation.import_type != import_type {
            results.add_error("activation import type does not match import");
        }
        let import_subject = if self.is_service() && !self.to.is_empty() {
            &self.to
        } else {
            &self.subject
        };
        if !import_subject.is_contained_in(&Subject::from(
            activation.activation.import_subject.as_str(),
        )) {
            results.add_error("activation subject does not contain import subject");
        }
    }
}

/// Import collection with same-account service namespace-overlap validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imports(pub Vec<Import>);

impl Imports {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sort entries in place by source subject for deterministic claim encoding.
    pub fn sort_by_subject(&mut self) {
        self.0
            .sort_by(|left, right| left.subject.cmp(&right.subject));
    }
    /// Validate entries and reject overlapping effective service subjects imported from the same account.
    pub fn validate(&self, results: &mut ValidationResults) {
        for import in &self.0 {
            import.validate(results);
        }
        for (index, import) in self.0.iter().enumerate() {
            if !import.is_service() {
                continue;
            }
            let subject = import.effective_subject();
            for other in self.0.iter().skip(index + 1) {
                if other.is_service() && import.account == other.account {
                    let other_subject = other.effective_subject();
                    if subject.is_contained_in(&other_subject)
                        || other_subject.is_contained_in(&subject)
                    {
                        results.add_error("overlapping service import namespace");
                    }
                }
            }
        }
    }
}

/// One destination in an account subject mapping, optionally restricted to a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedMapping {
    /// Destination subject for this mapping branch.
    pub subject: Subject,
    /// Destination weight as a percentage; zero has an effective weight of 100.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub weight: u8,
    /// Optional cluster selecting this destination group; empty means unclustered.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
}

impl WeightedMapping {
    /// Create an unclustered mapping destination with the supplied weight; validation is deferred.
    pub fn new(subject: &str, weight: u8) -> Self {
        Self {
            subject: Subject::from(subject),
            weight,
            cluster: String::new(),
        }
    }

    /// Interpret an omitted/zero weight as 100 percent; otherwise return the stored percentage.
    pub fn effective_weight(&self) -> u8 {
        if self.weight == 0 {
            100
        } else {
            self.weight
        }
    }
}

/// Source subjects mapped to weighted destination lists.
pub type Mapping = std::collections::BTreeMap<Subject, Vec<WeightedMapping>>;

/// Semantic validation for the subject-mapping collection without changing its representation.
pub trait MappingValidation {
    /// Append findings for source/destination syntax and totals above 100 percent, separately for unclustered and per-cluster destinations.
    fn validate(&self, results: &mut ValidationResults);
}

impl MappingValidation for Mapping {
    /// Validate source/destination subjects and sum effective weights using wide counters; each cluster and the unclustered group must stay within 100 percent.
    fn validate(&self, results: &mut ValidationResults) {
        for (from, destinations) in self {
            from.validate(results);
            let mut total = 0_u32;
            let mut clusters = std::collections::BTreeMap::<&str, u32>::new();
            for destination in destinations {
                destination.subject.validate(results);
                let weight = u32::from(destination.effective_weight());
                if destination.cluster.is_empty() {
                    total += weight;
                } else {
                    *clusters.entry(&destination.cluster).or_default() += weight;
                }
            }
            if total > 100 || clusters.values().any(|weight| *weight > 100) {
                results.add_error(format!("mapping {:?} exceeds 100%", from.as_str()));
            }
        }
    }
}

/// Serde omission predicate for an unset sampling percentage.
fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

/// Serde omission predicate for a zero version or weight.
fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

/// Source-network list accepting a JSON array or comma-separated string; helper methods normalize strings, while array decoding preserves them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CIDRList(Vec<String>);

impl<'de> Deserialize<'de> for CIDRList {
    /// Decode an array of strings or a normalized comma-separated string; reject other shapes.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Array(values) => values
                .into_iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| serde::de::Error::custom("CIDR must be string"))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self),
            serde_json::Value::String(value) => Ok(Self::from_csv(&value)),
            _ => Err(serde::de::Error::custom(
                "CIDR list must be array or string",
            )),
        }
    }
}

impl CIDRList {
    /// Split a comma-separated list and normalize it through `add`; address syntax is validated separately.
    pub fn from_csv(value: &str) -> Self {
        let mut list = Self::default();
        list.add(value.split(','));
        list
    }

    /// Check normalized string membership; this does not test whether an IP address belongs to a network.
    pub fn contains(&self, value: &str) -> bool {
        self.0
            .iter()
            .any(|cidr| cidr == value.trim().to_ascii_lowercase().as_str())
    }

    /// Trim and ASCII-lowercase networks, skipping empty values and duplicates; no CIDR parsing occurs.
    pub fn add<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let value = value.as_ref().trim().to_ascii_lowercase();
            if !value.is_empty() && !self.0.contains(&value) {
                self.0.push(value);
            }
        }
    }

    /// Remove every exact normalized match for the supplied network strings.
    pub fn remove<I, S>(&mut self, values: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for value in values {
            let value = value.as_ref().trim().to_ascii_lowercase();
            self.0.retain(|cidr| cidr != &value);
        }
    }

    /// Replace the list with normalized comma-separated values.
    pub fn set(&mut self, values: &str) {
        self.0.clear();
        self.add(values.split(','));
    }

    /// Return the number of stored network strings.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Append findings for invalid IP addresses or prefixes outside IPv4/IPv6 bounds. Stored values are not changed.
    pub fn validate(&mut self, results: &mut ValidationResults) {
        for cidr in &self.0 {
            let Some((address, prefix)) = cidr.split_once('/') else {
                results.add_error(format!("invalid cidr {cidr:?}"));
                continue;
            };
            let valid = IpAddr::from_str(address).ok().is_some_and(|ip| {
                prefix
                    .parse::<u8>()
                    .ok()
                    .is_some_and(|bits| bits <= if ip.is_ipv4() { 32 } else { 128 })
            });
            if !valid {
                results.add_error(format!("invalid cidr {cidr:?}"));
            }
        }
    }
}

/// Daily connection-time window expressed as clock strings; interpreted with the user limit's time zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    /// Beginning of the daily window as an `hour:minute:second` clock string.
    pub start: String,
    /// End of the daily window as an `hour:minute:second` clock string.
    pub end: String,
}

impl TimeRange {
    /// Validate both clock endpoints independently; does not compare their ordering or evaluate the current time.
    pub fn validate(&self, results: &mut ValidationResults) {
        if !valid_time(&self.start) {
            results.add_error("invalid time range start");
        }
        if !valid_time(&self.end) {
            results.add_error("invalid time range end");
        }
    }
}

/// Check three colon-separated numeric clock components within hour/minute/second bounds; fixed two-digit widths are not required.
fn valid_time(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 3
        && parts[0].parse::<u8>().is_ok_and(|v| v < 24)
        && parts[1].parse::<u8>().is_ok_and(|v| v < 60)
        && parts[2].parse::<u8>().is_ok_and(|v| v < 60)
}

/// User connection restrictions and resource limits. Default core limits are unlimited (`-1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserLimits {
    /// Allowed source networks as CIDR strings.
    #[serde(skip_serializing_if = "CIDRList::is_empty")]
    pub src: CIDRList,
    /// Daily clock windows during which connections are allowed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub times: Vec<TimeRange>,
    /// IANA time zone for the windows, serialized as `times_location`; empty leaves it unspecified.
    #[serde(rename = "times_location")]
    pub locale: String,
    /// Maximum subscription count; `-1` denotes unlimited where the server permits it.
    #[serde(rename = "subs")]
    pub subscriptions: i64,
    /// Maximum data volume in bytes; `-1` denotes unlimited where the server permits it.
    pub data: i64,
    /// Maximum individual message payload in bytes; `-1` denotes unlimited where the server permits it.
    pub payload: i64,
}

impl Default for UserLimits {
    /// Create empty connection restrictions and unlimited core resource limits.
    fn default() -> Self {
        Self {
            src: CIDRList::default(),
            times: Vec::new(),
            locale: String::new(),
            subscriptions: -1,
            data: -1,
            payload: -1,
        }
    }
}

impl UserLimits {
    /// Check source CIDR syntax, time endpoints, and a nonempty IANA time-zone name. Does not enforce resource limits or connection eligibility.
    pub fn validate(&self, results: &mut ValidationResults) {
        let mut src = self.src.clone();
        src.validate(results);
        for range in &self.times {
            range.validate(results);
        }
        if !self.locale.is_empty() && self.locale.parse::<chrono_tz::Tz>().is_err() {
            results.add_error("invalid IANA time zone");
        }
    }
}

/// Temporary reply permission granted when a user receives a request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePermission {
    /// Maximum replies allowed by the temporary response permission.
    pub max: i32,
    /// Lifetime of response permission in Go duration wire units (nanoseconds).
    pub ttl: i64,
}

/// Publish, subscribe, and optional response permissions enforced by the NATS server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Permissions {
    /// Publish subject allow/deny rules, serialized as `pub`.
    #[serde(rename = "pub")]
    pub publish: Permission,
    /// Subscribe subject and optional queue allow/deny rules, serialized as `sub`.
    #[serde(rename = "sub")]
    pub subscribe: Permission,
    /// Optional temporary response permission, serialized as `resp`.
    #[serde(rename = "resp", skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponsePermission>,
}

impl Permissions {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.publish.allow.is_empty()
            && self.publish.deny.is_empty()
            && self.subscribe.allow.is_empty()
            && self.subscribe.deny.is_empty()
            && self.response.is_none()
    }

    /// Validate publish entries without queue names and subscribe entries with optional queue names; response limits are not checked here.
    pub fn validate(&self, results: &mut ValidationResults) {
        self.publish.validate(results, false);
        self.subscribe.validate(results, true);
    }
}

/// Maximum description or information-URL length in bytes (8 KiB).
pub const MAX_INFO_LENGTH: usize = 8 * 1024;

/// Human-readable description and optional information URL attached to account policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Info {
    /// Human-readable description; validation may enforce an information-size limit.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Optional URL with more information; validated separately from serialization.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub info_url: String,
}

impl Info {
    /// Enforce byte-length bounds and require a nonempty information URL to have a scheme and host.
    pub fn validate(&self, results: &mut ValidationResults) {
        if self.description.len() > MAX_INFO_LENGTH {
            results.add_error("description is too long");
        }
        if self.info_url.len() > MAX_INFO_LENGTH {
            results.add_error("info URL is too long");
        }
        if !self.info_url.is_empty() {
            match url::Url::parse(&self.info_url) {
                Ok(url) if !url.scheme().is_empty() && url.host().is_some() => {}
                _ => results.add_error("invalid info URL"),
            }
        }
    }
}

/// Account message-tracing destination and sampling percentage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MsgTrace {
    /// Trace event subject serialized as `dest`; validation forbids wildcards.
    #[serde(rename = "dest", skip_serializing_if = "Subject::is_empty")]
    pub destination: Subject,
    /// Trace sampling percentage; validation normalizes zero to 100.
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub sampling: i32,
}

impl MsgTrace {
    /// Check destination and sampling bounds, and normalize sampling zero to 100 in place.
    pub fn validate(&mut self, results: &mut ValidationResults) {
        self.destination.validate(results);
        if self.destination.has_wildcards() {
            results.add_error("trace destination cannot contain wildcards");
        }
        if !(0..=100).contains(&self.sampling) {
            results.add_error("trace sampling must be between 0 and 100");
        }
        if self.sampling == 0 {
            self.sampling = 100;
        }
    }
}

/// Wildcard permitting any account in external authorization; validation requires it to appear alone.
pub const ANY_ACCOUNT: &str = "*";

/// External authorization users, permitted target accounts, and optional encryption key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAuthorization {
    /// User public keys allowed to handle authorization; a nonempty list enables the feature.
    #[serde(rename = "auth_users", default)]
    pub auth_users: Vec<String>,
    /// Permitted account public keys, or [`ANY_ACCOUNT`] alone for unrestricted account selection.
    #[serde(rename = "allowed_accounts", default)]
    pub allowed_accounts: Vec<String>,
    /// Optional public XKey for encrypted authorization exchanges.
    #[serde(default)]
    pub xkey: String,
}

impl ExternalAuthorization {
    /// Return whether at least one authorization user is configured.
    pub fn is_enabled(&self) -> bool {
        !self.auth_users.is_empty()
    }

    /// Check user/account key types, exclusive wildcard-account use, and optional XKey validity; allowed accounts require at least one auth user.
    pub fn validate(&self, results: &mut ValidationResults) {
        if !self.allowed_accounts.is_empty() && !self.is_enabled() {
            results.add_error("external authorization requires auth users");
        }
        for key in &self.auth_users {
            if !is_user(key) {
                results.add_error("invalid auth user");
            }
        }
        if self.allowed_accounts.iter().any(|key| key == ANY_ACCOUNT)
            && self.allowed_accounts.len() > 1
        {
            results.add_error("allowed accounts must be either wildcard or specific accounts");
        }
        for key in &self.allowed_accounts {
            if key != ANY_ACCOUNT && !is_account(key) {
                results.add_error("invalid allowed account");
            }
        }
        if !self.xkey.is_empty()
            && (nkeys::KeyPair::from_public_key(&self.xkey).is_err() || !self.xkey.starts_with('X'))
        {
            results.add_error("invalid external authorization xkey");
        }
    }
}

/// Allow/deny subject lists; subscription entries may additionally specify a queue name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Permission {
    /// Subjects allowed by this rule, with optional queue tokens for subscriptions.
    #[serde(skip_serializing_if = "StringList::is_empty")]
    pub allow: StringList,
    /// Subjects denied by this rule; server policy determines precedence over allows.
    #[serde(skip_serializing_if = "StringList::is_empty")]
    pub deny: StringList,
}

impl Permission {
    /// Check subject entries and optional queue tokens; `permit_queue` controls whether a second space-separated token is allowed.
    pub fn validate(&self, results: &mut ValidationResults, permit_queue: bool) {
        for value in self.allow.iter().chain(self.deny.iter()) {
            let tokens: Vec<_> = value.split(' ').collect();
            if tokens.len() > 2 || (tokens.len() == 2 && !permit_queue) {
                results.add_error(format!("invalid permission subject {value:?}"));
                continue;
            }
            for token in tokens {
                Subject::from(token).validate(results);
            }
        }
    }
}

/// Public-key to inclusive Unix-second revocation cutoffs; `*` applies to all keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevocationList(std::collections::BTreeMap<String, i64>);

/// Removed revocation entry returned by compaction for auditing or inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Revoked public key whose redundant entry was removed.
    pub public_key: String,
    /// Inclusive issue-time cutoff in Unix seconds.
    pub timestamp: i64,
}

impl RevocationList {
    /// Return whether the collection or wire value has no entries or content.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Remove the cutoff for this key. A separate wildcard cutoff still applies.
    pub fn clear_revocation(&mut self, public_key: &str) {
        self.0.remove(public_key);
    }

    /// Insert or advance a key's inclusive issue-time cutoff; never move an existing cutoff backwards. Use `*` to revoke all keys through a timestamp.
    pub fn revoke(&mut self, public_key: impl Into<String>, timestamp: SystemTime) {
        let key = public_key.into();
        let timestamp = unix(timestamp);
        self.0
            .entry(key)
            .and_modify(|current| *current = (*current).max(timestamp))
            .or_insert(timestamp);
    }

    /// Check the key and wildcard cutoffs against the claim's issue time, including equality.
    pub fn is_revoked(&self, public_key: &str, timestamp: SystemTime) -> bool {
        self.is_revoked_at(public_key, unix(timestamp))
    }

    /// Check a Unix-second issue time against both per-key and wildcard cutoffs, including equality.
    pub(crate) fn is_revoked_at(&self, public_key: &str, timestamp: i64) -> bool {
        self.0.get("*").is_some_and(|value| *value >= timestamp)
            || self
                .0
                .get(public_key)
                .is_some_and(|value| *value >= timestamp)
    }

    /// Remove and return per-key entries already covered by the wildcard cutoff; leave later cutoffs and the wildcard itself intact.
    pub fn maybe_compact(&mut self) -> Vec<RevocationEntry> {
        let Some(all) = self.0.get("*").copied() else {
            return Vec::new();
        };
        let keys: Vec<_> = self
            .0
            .iter()
            .filter(|(key, timestamp)| key.as_str() != "*" && **timestamp <= all)
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                self.0.remove(&key).map(|timestamp| RevocationEntry {
                    public_key: key,
                    timestamp,
                })
            })
            .collect()
    }
}

/// Convert system time to signed Unix seconds, flooring pre-epoch fractions and saturating at the signed range.
fn unix(value: SystemTime) -> i64 {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
        Err(error) => {
            let duration = error.duration();
            let seconds = -(duration.as_secs() as i128) - i128::from(duration.subsec_nanos() > 0);
            seconds.max(i64::MIN as i128) as i64
        }
    }
}
