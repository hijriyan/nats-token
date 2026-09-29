//! NATS JWT v2 signing, decoding, credentials, and policy models.
//!
//! Encoding refreshes claim metadata. Decoding verifies signatures but does not establish
//! trust or run semantic validation. Use the claim validators and your own operator/account
//! trust policy before accepting a token. This crate does not connect to a NATS server.
//!
//! # Sign and verify an account claim
//!
//! ```
//! use nats_token::{AccountClaims, decode_account_claims, KeyPair, ValidationResults};
//!
//! let operator = KeyPair::new_operator();
//! let account = KeyPair::new_account();
//! let mut claim = AccountClaims::new(account.public_key()).unwrap();
//! let jwt = claim.encode(&operator)?;
//! let mut decoded = decode_account_claims(&jwt)?;
//! let mut findings = ValidationResults::default();
//! decoded.validate(&mut findings);
//! assert!(!findings.is_blocking(true));
//! assert_eq!(decoded.claims.subject, account.public_key());
//! // The application must additionally decide whether it trusts this operator.
//! # Ok::<(), nats_token::NjError>(())
//! ```

mod authorization;
mod claims;
mod creds;
mod error;
pub mod policy;
mod time;
pub mod token;
mod validation;

/// NATS key pairs for generating, loading, and signing with NKeys.
pub use nkeys::KeyPair;

pub use authorization::{
    Activation, ActivationClaims, AuthorizationRequest, AuthorizationRequestClaims,
    AuthorizationResponse, AuthorizationResponseClaims, ClientInformation, ClientTls,
    ConnectOptions, ServerId,
};
pub use claims::{
    decode, decode_account_claims, decode_activation_claims, decode_authorization_request_claims,
    decode_authorization_response_claims, decode_generic, decode_operator_claims,
    decode_user_claims, is_generic_claim_type, parse_server_version, validate_operator_service_url,
    Account, AccountClaims, AccountLimits, ClaimType, ClaimsData, ClusterTraffic, DecodedClaims,
    GenericClaims, JetStreamLimits, JetStreamTieredLimits, KeyPairSigner, NatsLimits, Operator,
    OperatorClaims, OperatorLimits, Signer, User, UserClaims, ACCOUNT_CLAIM, ACTIVATION_CLAIM,
    AUTHORIZATION_REQUEST_CLAIM, AUTHORIZATION_RESPONSE_CLAIM, CLUSTER_TRAFFIC_OWNER,
    CLUSTER_TRAFFIC_SYSTEM, CONNECTION_TYPE_IN_PROCESS, CONNECTION_TYPE_LEAFNODE,
    CONNECTION_TYPE_LEAFNODE_WS, CONNECTION_TYPE_MQTT, CONNECTION_TYPE_MQTT_WS,
    CONNECTION_TYPE_STANDARD, CONNECTION_TYPE_WEBSOCKET, GENERIC_CLAIM, OPERATOR_CLAIM, USER_CLAIM,
};
/// Unlimited-resource sentinel (`-1`) used by NATS limit fields that support it.
pub const NO_LIMIT: i64 = -1;
pub use creds::{
    decorate_jwt, decorate_seed, format_user_config, issue_user_jwt, parse_decorated_jwt,
    parse_decorated_nkey, parse_decorated_user_nkey,
};
pub use error::{NjError, Result};
pub use policy::{
    ExternalAuthorization, ResponseType, SamplingRate, TagList, ANY_ACCOUNT, HEADERS,
    RESPONSE_TYPE_CHUNKED, RESPONSE_TYPE_SINGLETON, RESPONSE_TYPE_STREAM,
};
pub use validation::{ValidationIssue, ValidationResults};
