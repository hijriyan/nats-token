use nats_token::policy::{Export, ExportType, Exports, Import, Imports, RenamingSubject, Subject};
use nats_token::{
    AccountClaims, ResponseType, SamplingRate, ValidationResults, HEADERS, RESPONSE_TYPE_CHUNKED,
    RESPONSE_TYPE_SINGLETON, RESPONSE_TYPE_STREAM,
};
use nkeys::KeyPair;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn export_validation_rejects_unknown_type_and_empty_subject() {
    let export = Export::default();
    let mut results = ValidationResults::default();
    export.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn exports_find_containing_subject() {
    let exports = Exports(vec![Export::new("orders.>", ExportType::Stream)]);
    assert!(exports.has_export_containing_subject(&Subject::from("orders.created")));
    assert!(!exports.has_export_containing_subject(&Subject::from("events.created")));
}

#[test]
fn stream_and_service_exports_sort_by_subject() {
    let mut exports = Exports(vec![
        Export::new("z", ExportType::Stream),
        Export::new("a", ExportType::Service),
    ]);
    exports.sort_by_subject();
    assert_eq!(exports.0[0].subject, Subject::from("a"));
}

#[test]
fn import_requires_account_and_valid_type() {
    let import = Import::new("orders", ExportType::Stream);
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(results.is_blocking(false));

    let invalid = Import {
        subject: Subject::from("orders"),
        ..Default::default()
    };
    let mut invalid_results = ValidationResults::default();
    invalid.validate(&mut invalid_results);
    assert!(invalid_results.is_blocking(false));
}

#[test]
fn response_type_constants_match_upstream_and_convert_to_export_strings() {
    assert_eq!(RESPONSE_TYPE_SINGLETON, "Singleton");
    assert_eq!(RESPONSE_TYPE_STREAM, "Stream");
    assert_eq!(RESPONSE_TYPE_CHUNKED, "Chunked");
    for (mode, expected) in [
        (ResponseType::Singleton, "Singleton"),
        (ResponseType::Stream, "Stream"),
        (ResponseType::Chunked, "Chunked"),
    ] {
        assert_eq!(mode.as_str(), expected);
        assert_eq!(mode.to_string(), expected);
        let export = Export {
            response_type: Some(mode.to_string()),
            ..Export::new("orders", ExportType::Service)
        };
        let mut results = ValidationResults::default();
        export.validate(&mut results);
        assert!(!results.is_blocking(false), "{expected}");
        assert_eq!(export.is_single_response(), expected == "Singleton");
        assert_eq!(export.is_stream_response(), expected == "Stream");
        assert_eq!(export.is_chunked_response(), expected == "Chunked");
        let wire = serde_json::to_value(&export).unwrap();
        assert_eq!(wire["response_type"], expected);
        assert_eq!(serde_json::from_value::<Export>(wire).unwrap(), export);
    }

    let mut export = Export::new("orders", ExportType::Service);
    export.response_type = Some("Invalid".into());
    let mut results = ValidationResults::default();
    export.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn export_response_mode_helpers_match_type_and_mode() {
    let stream = Export::new("orders", ExportType::Stream);
    assert!(!stream.is_service());
    assert!(stream.is_stream());
    assert!(!stream.is_stream_response());

    let mut service = Export::new("orders", ExportType::Service);
    service.response_type = Some("Singleton".into());
    assert!(service.is_service());
    assert!(!service.is_stream());
    assert!(service.is_single_response());
    service.response_type = Some("Stream".into());
    assert!(service.is_stream_response());
    service.response_type = Some("Chunked".into());
    assert!(service.is_chunked_response());
}

#[test]
fn export_upstream_branch_matrix() {
    for (subject, position, valid) in [
        ("*", 1, true),
        ("foo.*", 2, true),
        ("foo.*.bar.*", 2, true),
        ("foo.*.bar.>", 2, true),
        ("*.*.*.>", 2, true),
        ("*.*.>", 1, true),
        (">", 5, false),
        ("foo.>", 2, false),
        ("bar", 1, false),
        ("foo.*.bar", 3, false),
        ("foo.*x.bar", 2, false),
    ] {
        let mut export = Export::new(subject, ExportType::Stream);
        export.account_token_position = Some(position);
        let mut results = ValidationResults::default();
        export.validate(&mut results);
        assert_eq!(
            !results.is_blocking(false),
            valid,
            "{subject} position {position}"
        );
    }
}

#[test]
fn import_share_and_trace_branch_matrix() {
    let account = KeyPair::new_account().public_key();
    let mut stream_share = Import::new("orders", ExportType::Stream);
    stream_share.account = account.clone();
    stream_share.share = true;
    let mut results = ValidationResults::default();
    stream_share.validate(&mut results);
    assert!(results.is_blocking(false));

    let mut service_share = Import::new("orders", ExportType::Service);
    service_share.account = account.clone();
    service_share.share = true;
    let mut valid_share = ValidationResults::default();
    service_share.validate(&mut valid_share);
    assert!(!valid_share.is_blocking(false));

    let mut service_trace = Import::new("orders", ExportType::Service);
    service_trace.account = account.clone();
    service_trace.allow_trace = true;
    let mut invalid = ValidationResults::default();
    service_trace.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    let mut stream_trace = Import::new("orders", ExportType::Stream);
    stream_trace.account = account;
    stream_trace.allow_trace = true;
    let mut valid = ValidationResults::default();
    stream_trace.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}

#[test]
fn export_trace_and_response_threshold_branch_matrix() {
    for (kind, allow_trace, threshold, valid) in [
        (ExportType::Service, true, None, true),
        (ExportType::Stream, true, None, false),
        (ExportType::Service, false, Some(1), true),
        (ExportType::Stream, false, Some(1), false),
        (ExportType::Service, false, Some(-1), false),
        (ExportType::Stream, false, Some(0), true),
    ] {
        let mut export = Export::new("orders", kind);
        export.allow_trace = allow_trace;
        export.response_threshold = threshold;
        let mut results = ValidationResults::default();
        export.validate(&mut results);
        assert_eq!(
            !results.is_blocking(false),
            valid,
            "kind={kind:?} trace={allow_trace} threshold={threshold:?}"
        );
    }
}

#[test]
fn export_response_modes_match_service_rules() {
    let mut stream = Export::new("orders", ExportType::Stream);
    stream.response_type = Some("Stream".into());
    let mut stream_results = ValidationResults::default();
    stream.validate(&mut stream_results);
    assert!(stream_results.is_blocking(false));

    for mode in ["Singleton", "Stream", "Chunked"] {
        let mut service = Export::new("orders", ExportType::Service);
        service.response_type = Some(mode.into());
        let mut results = ValidationResults::default();
        service.validate(&mut results);
        assert!(!results.is_blocking(false), "{mode}");
    }
    let mut invalid = Export::new("orders", ExportType::Service);
    invalid.response_type = Some("Invalid".into());
    let mut invalid_results = ValidationResults::default();
    invalid.validate(&mut invalid_results);
    assert!(invalid_results.is_blocking(false));
}

#[test]
fn import_accepts_nonempty_account_without_nkey_validation_like_upstream() {
    let mut invalid = Import::new("orders", ExportType::Stream);
    invalid.account = "A123".into();
    let mut invalid_results = ValidationResults::default();
    invalid.validate(&mut invalid_results);
    assert!(!invalid_results.is_blocking(false));

    let mut valid = Import::new("orders", ExportType::Stream);
    valid.account = KeyPair::new_account().public_key();
    let mut valid_results = ValidationResults::default();
    valid.validate(&mut valid_results);
    assert!(!valid_results.is_blocking(false));
}

#[test]
fn import_type_helpers_match_type() {
    let stream = Import::new("orders", ExportType::Stream);
    assert!(stream.is_stream());
    assert!(!stream.is_service());
    let service = Import::new("orders", ExportType::Service);
    assert!(service.is_service());
    assert!(!service.is_stream());
}

#[test]
fn import_trace_permission_matches_import_type() {
    let account = KeyPair::new_account().public_key();
    let mut service = Import::new("orders", ExportType::Service);
    service.account = account.clone();
    service.allow_trace = true;
    let mut invalid = ValidationResults::default();
    service.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    let mut stream = Import::new("orders", ExportType::Stream);
    stream.account = account;
    stream.allow_trace = true;
    let mut valid = ValidationResults::default();
    stream.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}

#[test]
fn export_trace_permission_matches_export_type() {
    let mut stream = Export::new("orders", ExportType::Stream);
    stream.allow_trace = true;
    let mut invalid = ValidationResults::default();
    stream.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    let mut service = Export::new("orders", ExportType::Service);
    service.allow_trace = true;
    let mut valid = ValidationResults::default();
    service.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}

#[test]
fn export_revocation_is_inclusive_clearable_and_serializable() {
    let mut export = Export::new("orders", ExportType::Service);
    let before = SystemTime::now() - Duration::from_secs(2);
    export.revoke("CURRENT");
    let after = SystemTime::now() + Duration::from_secs(2);
    assert!(export.is_revoked("CURRENT", before));
    assert!(!export.is_revoked("CURRENT", after));
    export.revoke_at("UKEY", UNIX_EPOCH + Duration::from_secs(10));
    assert!(export.is_revoked("UKEY", UNIX_EPOCH + Duration::from_secs(10)));
    export.clear_revocation("UKEY");
    assert!(!export.is_revoked("UKEY", UNIX_EPOCH + Duration::from_secs(10)));
    export.revoke_at("UKEY", UNIX_EPOCH + Duration::from_secs(10));
    let json = serde_json::to_string(&export).unwrap();
    assert!(json.contains("revocations"));
}

#[test]
fn sampling_rate_public_api_matches_upstream_wire_format() {
    assert_eq!(HEADERS, SamplingRate(0));
    assert_eq!(nats_token::policy::HEADERS, HEADERS);
    for raw in [i32::MIN, -1, 0, 1, 50, 100, 101, i32::MAX] {
        let rate = SamplingRate(raw);
        assert_eq!(
            serde_json::from_str::<SamplingRate>(&raw.to_string()).unwrap(),
            rate
        );
        let latency = nats_token::policy::ServiceLatency {
            sampling: rate.0,
            results: Subject::from("metrics"),
        };
        let mut results = ValidationResults::default();
        latency.validate(&mut results);
        assert_eq!(results.is_blocking(false), !(0..=100).contains(&raw));
        if (0..=100).contains(&raw) {
            let expected = if raw == 0 {
                serde_json::json!("headers")
            } else {
                serde_json::json!(raw)
            };
            assert_eq!(serde_json::to_value(rate).unwrap(), expected);
            assert_eq!(
                serde_json::to_value(&latency).unwrap()["sampling"],
                expected
            );
            assert_eq!(
                serde_json::from_value::<SamplingRate>(expected.clone()).unwrap(),
                rate
            );
            let wire = serde_json::json!({"sampling": expected, "results": "metrics"});
            assert_eq!(
                serde_json::from_value::<nats_token::policy::ServiceLatency>(wire).unwrap(),
                latency
            );
        } else {
            assert!(serde_json::to_value(rate).is_err());
            assert!(serde_json::to_value(&latency).is_err());
        }
    }
    for text in ["headers", "HEADERS", "HeAdErS"] {
        assert_eq!(
            serde_json::from_value::<SamplingRate>(serde_json::json!(text)).unwrap(),
            HEADERS
        );
    }
    for invalid in [
        "null",
        "true",
        "1.5",
        "1.0",
        "2147483648",
        "-2147483649",
        "\"50\"",
        "\"other\"",
        "[]",
        "{}",
    ] {
        assert!(
            serde_json::from_str::<SamplingRate>(invalid).is_err(),
            "{invalid}"
        );
        let wire = format!("{{\"sampling\":{invalid},\"results\":\"metrics\"}}");
        assert!(
            serde_json::from_str::<nats_token::policy::ServiceLatency>(&wire).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn service_latency_rejects_invalid_sampling_on_serialize() {
    let latency = nats_token::policy::ServiceLatency {
        sampling: 101,
        results: Subject::from("metrics"),
    };
    assert!(serde_json::to_value(&latency).is_err());
}

#[test]
fn service_latency_sampling_uses_headers_or_percentage_wire_values() {
    let latency = nats_token::policy::ServiceLatency {
        sampling: 0,
        results: Subject::from("metrics"),
    };
    assert_eq!(
        serde_json::to_value(&latency).unwrap()["sampling"],
        "headers"
    );
    let latency = nats_token::policy::ServiceLatency {
        sampling: 50,
        results: Subject::from("metrics"),
    };
    assert_eq!(serde_json::to_value(&latency).unwrap()["sampling"], 50);
}

#[test]
fn export_latency_and_threshold_require_service() {
    let mut stream = Export::new("orders", ExportType::Stream);
    stream.response_threshold = Some(1);
    stream.latency = Some(nats_token::policy::ServiceLatency {
        sampling: 101,
        results: Subject::from("metrics.*"),
    });
    let mut results = ValidationResults::default();
    stream.validate(&mut results);
    assert!(results.is_blocking(false));

    let mut service = Export::new("orders", ExportType::Service);
    service.response_threshold = Some(-1);
    let mut service_results = ValidationResults::default();
    service.validate(&mut service_results);
    assert!(service_results.is_blocking(false));
}

#[test]
fn export_rejects_stream_response_and_invalid_account_token_position() {
    let mut export = Export::new("orders", ExportType::Stream);
    export.response_type = Some("Stream".into());
    export.account_token_position = Some(1);
    let mut results = ValidationResults::default();
    export.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn exports_reject_overlapping_same_type_namespaces() {
    let exports = Exports(vec![
        Export::new("orders.>", ExportType::Service),
        Export::new("orders.created", ExportType::Service),
    ]);
    let mut results = ValidationResults::default();
    exports.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn import_rejects_to_and_local_subject_together() {
    let import = Import {
        subject: Subject::from("orders.*"),
        account: "A".into(),
        import_type: Some(ExportType::Stream),
        to: Subject::from("local.*"),
        local_subject: Some(RenamingSubject::from("local.*")),
        ..Default::default()
    };
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn any_account_matches_upstream_wildcard_and_validation_rules() {
    assert_eq!(nats_token::ANY_ACCOUNT, "*");
    assert_eq!(nats_token::policy::ANY_ACCOUNT, nats_token::ANY_ACCOUNT);

    let authorization = nats_token::policy::ExternalAuthorization {
        auth_users: vec![KeyPair::new_user().public_key()],
        allowed_accounts: vec![nats_token::ANY_ACCOUNT.into()],
        ..Default::default()
    };
    let mut results = ValidationResults::default();
    authorization.validate(&mut results);
    assert!(!results.is_blocking(false));
}

#[test]
fn external_authorization_upstream_wildcard_and_no_user_matrix() {
    let account = KeyPair::new_account().public_key();
    let user = KeyPair::new_user().public_key();
    for (auth_users, allowed_accounts, valid) in [
        (
            vec![user.clone()],
            vec![nats_token::ANY_ACCOUNT.into()],
            true,
        ),
        (vec![user.clone()], vec![account.clone()], true),
        (vec![user.clone()], vec![], true),
        (
            vec![user.clone()],
            vec![nats_token::ANY_ACCOUNT.into(), account.clone()],
            false,
        ),
        (
            vec![user],
            vec![account.clone(), nats_token::ANY_ACCOUNT.into()],
            false,
        ),
        (Vec::new(), vec![], true),
        (Vec::new(), vec![account], false),
        (Vec::new(), vec![nats_token::ANY_ACCOUNT.into()], false),
    ] {
        let authorization = nats_token::policy::ExternalAuthorization {
            auth_users,
            allowed_accounts,
            ..Default::default()
        };
        let mut results = ValidationResults::default();
        authorization.validate(&mut results);
        assert_eq!(!results.is_blocking(false), valid);
    }
}

#[test]
fn external_authorization_reports_enabled_only_with_users() {
    let empty = nats_token::policy::ExternalAuthorization::default();
    assert!(!empty.is_enabled());
    let enabled = nats_token::policy::ExternalAuthorization {
        auth_users: vec![KeyPair::new_user().public_key()],
        ..Default::default()
    };
    assert!(enabled.is_enabled());
}

#[test]
fn account_external_authorization_helpers_and_wildcard_rules() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    assert!(!claim.has_external_authorization());
    claim.enable_external_authorization([user.public_key()]);
    assert!(claim.has_external_authorization());

    let authorization = claim.account.authorization.as_mut().unwrap();
    authorization.allowed_accounts = vec![nats_token::ANY_ACCOUNT.into(), account.public_key()];
    let mut invalid = ValidationResults::default();
    claim.validate(&mut invalid);
    assert!(invalid.is_blocking(false));
}

#[test]
fn account_external_authorization_accepts_valid_curve_xkey() {
    let account = KeyPair::new_account();
    let user = KeyPair::new_user();
    let curve = nkeys::KeyPair::new(nkeys::KeyPairType::Curve);
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.authorization = Some(nats_token::policy::ExternalAuthorization {
        auth_users: vec![user.public_key()],
        allowed_accounts: vec![nats_token::ANY_ACCOUNT.into()],
        xkey: curve.public_key(),
    });
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(!results.is_blocking(false));
}

#[test]
fn account_info_validation_requires_url_host() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    for value in ["https://[invalid", "relative/path"] {
        claim.account.info.info_url = value.into();
        let mut results = ValidationResults::default();
        claim.validate(&mut results);
        assert!(results.is_blocking(false), "{value}");
    }

    claim.account.info.info_url = "https://example.com/info".into();
    let mut valid = ValidationResults::default();
    claim.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}

#[test]
fn account_info_validation_rejects_long_description() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.info.description = "x".repeat(nats_token::policy::MAX_INFO_LENGTH + 1);
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));

    claim.account.info.description.clear();
    claim.account.info.info_url = format!(
        "https://example.com/{}",
        "x".repeat(nats_token::policy::MAX_INFO_LENGTH)
    );
    let mut url_results = ValidationResults::default();
    claim.validate(&mut url_results);
    assert!(url_results.is_blocking(false));
}

#[test]
fn account_trace_wire_uses_dest_and_omits_zero_sampling() {
    let mut trace = nats_token::policy::MsgTrace {
        destination: Subject::from("trace.events"),
        sampling: 0,
    };
    assert_eq!(
        serde_json::to_value(&trace).unwrap(),
        serde_json::json!({"dest": "trace.events"})
    );
    trace.sampling = 50;
    let value = serde_json::json!({"dest": "trace.events", "sampling": 50});
    assert_eq!(serde_json::to_value(&trace).unwrap(), value);
    assert_eq!(
        serde_json::from_value::<nats_token::policy::MsgTrace>(value).unwrap(),
        trace
    );
    let empty: nats_token::policy::MsgTrace = serde_json::from_str("{}").unwrap();
    assert_eq!(serde_json::to_value(empty).unwrap(), serde_json::json!({}));
}

#[test]
fn account_trace_sampling_defaults_and_validates_destination() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.trace = Some(nats_token::policy::MsgTrace {
        destination: Subject::from("trace.>"),
        sampling: 0,
    });
    let mut invalid = ValidationResults::default();
    claim.validate(&mut invalid);
    assert!(invalid.is_blocking(false));

    claim.account.trace = Some(nats_token::policy::MsgTrace {
        destination: Subject::from("trace.events"),
        sampling: 0,
    });
    claim.validate(&mut invalid);
    assert_eq!(claim.account.trace.as_ref().unwrap().sampling, 100);
}

#[test]
fn account_external_authorization_requires_valid_users_accounts_and_xkey() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.authorization = Some(nats_token::policy::ExternalAuthorization {
        auth_users: vec![nkeys::KeyPair::new_user().public_key()],
        allowed_accounts: vec![nats_token::ANY_ACCOUNT.into()],
        xkey: "invalid".into(),
    });
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn account_claim_validation_includes_mappings() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.mappings.insert(
        Subject::from("orders"),
        vec![
            nats_token::policy::WeightedMapping::new("east", 60),
            nats_token::policy::WeightedMapping::new("west", 50),
        ],
    );
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn account_claim_round_trip_preserves_imports_exports_and_mappings() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim
        .account
        .exports
        .0
        .push(Export::new("orders", ExportType::Stream));
    claim.account.imports.0.push(Import {
        account: "A123".into(),
        ..Import::new("events", ExportType::Stream)
    });
    claim.account.default_permissions = nats_token::policy::Permissions::default();
    claim.account.mappings.insert(
        Subject::from("source"),
        vec![nats_token::policy::WeightedMapping::new("target", 100)],
    );
    let token = claim.encode(&account).unwrap();
    let decoded = nats_token::decode(&token).unwrap();
    let nats_token::DecodedClaims::Account(decoded) = decoded else {
        panic!("expected account");
    };
    assert_eq!(
        decoded.account.exports.0[0].subject,
        Subject::from("orders")
    );
    assert_eq!(
        decoded.account.imports.0[0].subject,
        Subject::from("events")
    );
}

#[test]
fn service_import_conflicts_are_scoped_per_account() {
    let account_a = KeyPair::new_account().public_key();
    let account_b = KeyPair::new_account().public_key();
    let imports = Imports(vec![
        Import {
            account: account_a.clone(),
            ..Import::new("orders.>", ExportType::Service)
        },
        Import {
            account: account_a,
            ..Import::new("orders.create", ExportType::Service)
        },
    ]);
    let mut conflict = ValidationResults::default();
    imports.validate(&mut conflict);
    assert!(conflict.is_blocking(false));

    let separate = Imports(vec![
        Import {
            account: account_b.clone(),
            ..Import::new("orders", ExportType::Service)
        },
        Import {
            account: KeyPair::new_account().public_key(),
            ..Import::new("orders", ExportType::Service)
        },
    ]);
    let mut valid = ValidationResults::default();
    separate.validate(&mut valid);
    assert!(!valid.is_blocking(false));
}

#[test]
fn export_zero_values_match_unset_options() {
    for kind in [ExportType::Stream, ExportType::Service] {
        let mut export = Export::new("orders", kind);
        export.account_token_position = Some(0);
        export.response_type = Some(String::new());
        export.response_threshold = Some(0);
        let mut results = ValidationResults::default();
        export.validate(&mut results);
        assert!(!results.is_blocking(false), "{kind:?}: {results:?}");
        assert_eq!(export.is_single_response(), kind == ExportType::Service);
    }
}

#[test]
fn import_empty_local_subject_is_unset() {
    let import = Import {
        account: KeyPair::new_account().public_key(),
        local_subject: Some(RenamingSubject::from("")),
        to: Subject::from("local"),
        ..Import::new("orders", ExportType::Service)
    };
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(!results.is_blocking(false));
}

#[test]
fn import_and_export_preserve_upstream_wire_fields() {
    let import: Import = serde_json::from_value(serde_json::json!({
        "subject": "orders",
        "account": "A",
        "type": "service",
        "token": "activation-token",
        "share": true
    }))
    .unwrap();
    assert_eq!(import.token, "activation-token");
    assert!(import.share);
    let import_wire = serde_json::to_value(import).unwrap();
    assert_eq!(import_wire["token"], "activation-token");
    assert_eq!(import_wire["share"], true);

    let export: Export = serde_json::from_value(serde_json::json!({
        "subject": "orders",
        "type": "service",
        "advertise": true,
        "description": "Orders API",
        "info_url": "https://example.com/orders"
    }))
    .unwrap();
    assert!(export.advertise);
    assert_eq!(export.description, "Orders API");
    assert_eq!(export.info_url, "https://example.com/orders");
    let export_wire = serde_json::to_value(export).unwrap();
    assert_eq!(export_wire["advertise"], true);
    assert_eq!(export_wire["description"], "Orders API");
    assert_eq!(export_wire["info_url"], "https://example.com/orders");
}

fn activation_token(
    account: &KeyPair,
    issuer: &KeyPair,
    import_type: &str,
    subject: &str,
) -> String {
    let mut claim = nats_token::ActivationClaims::new(account.public_key()).unwrap();
    claim.activation.issuer_account = account.public_key();
    claim.activation.import_type = import_type.into();
    claim.activation.import_subject = subject.into();
    claim.encode(issuer).unwrap()
}

fn validated_import(account: &KeyPair, token: String) -> Import {
    Import {
        account: account.public_key(),
        token,
        ..Import::new("orders", ExportType::Stream)
    }
}

#[test]
fn import_context_validation_rejects_invalid_token() {
    let account = KeyPair::new_account();
    let import = validated_import(&account, "not-a-jwt".into());
    let mut results = ValidationResults::default();
    import.validate_with_account(account.public_key(), &mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn import_context_validation_rejects_wrong_account() {
    let account = KeyPair::new_account();
    let other = KeyPair::new_account();
    let token = activation_token(&account, &account, "stream", "orders");
    let import = validated_import(&account, token);
    let mut results = ValidationResults::default();
    import.validate_with_account(other.public_key(), &mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn import_context_validation_rejects_wrong_type_or_subject() {
    let account = KeyPair::new_account();
    let wrong_type = validated_import(
        &account,
        activation_token(&account, &account, "service", "orders"),
    );
    let mut type_results = ValidationResults::default();
    wrong_type.validate_with_account(account.public_key(), &mut type_results);
    assert!(type_results.is_blocking(false));

    let wrong_subject = validated_import(
        &account,
        activation_token(&account, &account, "stream", "events"),
    );
    let mut subject_results = ValidationResults::default();
    wrong_subject.validate_with_account(account.public_key(), &mut subject_results);
    assert!(subject_results.is_blocking(false));
}

#[test]
fn import_context_validation_ignores_activation_time_checks() {
    let account = KeyPair::new_account();
    let mut claim = nats_token::ActivationClaims::new(account.public_key()).unwrap();
    claim.activation.issuer_account = account.public_key();
    claim.activation.import_type = "stream".into();
    claim.activation.import_subject = "orders".into();
    claim.claims.expires = 1;
    let import = validated_import(&account, claim.encode(&account).unwrap());
    let mut results = ValidationResults::default();
    import.validate_with_account(account.public_key(), &mut results);
    assert!(results.is_empty());
}

#[test]
fn import_context_validation_accepts_valid_token() {
    let account = KeyPair::new_account();
    let import = validated_import(
        &account,
        activation_token(&account, &account, "stream", "orders"),
    );
    let mut results = ValidationResults::default();
    import.validate_with_account(account.public_key(), &mut results);
    assert!(results.is_empty());
}

#[test]
fn import_context_validation_accepts_direct_issuer_when_issuer_account_differs() {
    let exporter = KeyPair::new_account();
    let importer = KeyPair::new_account();
    let mut activation = nats_token::ActivationClaims::new(importer.public_key()).unwrap();
    activation.activation.issuer_account = KeyPair::new_account().public_key();
    activation.activation.import_type = "stream".into();
    activation.activation.import_subject = "orders".into();
    let import = validated_import(&exporter, activation.encode(&exporter).unwrap());
    let mut results = ValidationResults::default();
    import.validate_with_account(importer.public_key(), &mut results);
    assert!(results.is_empty());
}

#[test]
fn service_import_token_uses_to_for_subject_containment() {
    let exporter = KeyPair::new_account();
    let importer = KeyPair::new_account();
    let mut activation = nats_token::ActivationClaims::new(importer.public_key()).unwrap();
    activation.activation.import_type = "service".into();
    activation.activation.import_subject = "reply.>".into();
    let mut import = Import::new("request", ExportType::Service);
    import.account = exporter.public_key();
    import.to = Subject::from("reply.local");
    import.token = activation.encode(&exporter).unwrap();
    let mut results = ValidationResults::default();
    import.validate_with_account(importer.public_key(), &mut results);
    assert!(results.is_empty());
}

#[test]
fn import_context_validation_checks_issuer_relationship_and_time() {
    let exporter = KeyPair::new_account();
    let importer = KeyPair::new_account();
    let signer = KeyPair::new_account();
    let mut activation = nats_token::ActivationClaims::new(importer.public_key()).unwrap();
    activation.activation.import_type = "stream".into();
    activation.activation.import_subject = "orders".into();
    for (key, issuer_account, valid) in [
        (&exporter, String::new(), true),
        (&signer, String::new(), false),
        (&signer, exporter.public_key(), true),
        (&exporter, signer.public_key(), true),
    ] {
        activation.activation.issuer_account = issuer_account;
        let import = validated_import(&exporter, activation.encode(key).unwrap());
        let mut results = ValidationResults::default();
        import.validate_with_account(importer.public_key(), &mut results);
        assert_eq!(results.is_empty(), valid, "{results:?}");
    }
    activation.activation.issuer_account.clear();
    activation.claims.not_before = i64::MAX;
    let import = validated_import(&exporter, activation.encode(&exporter).unwrap());
    let mut account = AccountClaims::new(importer.public_key()).unwrap();
    account.account.imports.0.push(import);
    let mut results = ValidationResults::default();
    account.validate(&mut results);
    assert!(results.is_empty(), "{results:?}");
}

#[test]
fn account_validation_checks_import_tokens_and_preserves_wire_model() {
    let exporter = KeyPair::new_account();
    let importer = KeyPair::new_account();
    let mut claim = AccountClaims::new(importer.public_key()).unwrap();
    claim
        .account
        .imports
        .0
        .push(validated_import(&exporter, "not-a-jwt".into()));
    let before = serde_json::to_value(&claim).unwrap();
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_blocking(false));
    assert_eq!(before, serde_json::to_value(&claim).unwrap());
    claim.account.imports.0[0].token.clear();
    let mut results = ValidationResults::default();
    claim.validate(&mut results);
    assert!(results.is_empty(), "{results:?}");
}

#[test]
fn import_validation_rejects_invalid_token_and_preserves_wire_value() {
    let import = Import {
        account: "A".into(),
        token: "not-a-jwt".into(),
        ..Import::new("orders", ExportType::Stream)
    };
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(results.is_blocking(false));
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.imports.0.push(import.clone());
    let token = claim.encode(&account).unwrap();
    let decoded = nats_token::decode_account_claims(&token).unwrap();
    assert_eq!(decoded.account.imports.0[0], import);
}

#[test]
fn import_validation_rejects_url_looking_invalid_token() {
    let import = Import {
        account: "A".into(),
        token: "foo://bad-token-url".into(),
        ..Import::new("orders", ExportType::Stream)
    };
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn service_import_accepts_full_wildcard_with_to() {
    let import = Import {
        account: KeyPair::new_account().public_key(),
        to: Subject::from("foo.bar"),
        ..Import::new(">", ExportType::Service)
    };
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(!results.is_blocking(false), "{results:?}");
}

#[test]
fn import_export_omitted_fields_default_and_still_validate() {
    let import: Import = serde_json::from_str("{}").unwrap();
    let export: Export = serde_json::from_str("{}").unwrap();
    assert_eq!(import, Import::default());
    assert_eq!(export, Export::default());
    let mut results = ValidationResults::default();
    import.validate(&mut results);
    assert!(results.is_blocking(false));
    let mut results = ValidationResults::default();
    export.validate(&mut results);
    assert!(results.is_blocking(false));
}

#[test]
fn import_share_and_export_info_validate() {
    for kind in [ExportType::Stream, ExportType::Service] {
        let import = Import {
            account: "A".into(),
            share: true,
            ..Import::new("orders", kind)
        };
        let mut results = ValidationResults::default();
        import.validate(&mut results);
        assert_eq!(results.is_blocking(false), kind == ExportType::Stream);
    }
    for (description, info_url) in [
        (
            "x".repeat(nats_token::policy::MAX_INFO_LENGTH + 1),
            String::new(),
        ),
        (String::new(), "relative/path".into()),
    ] {
        let export = Export {
            description,
            info_url,
            ..Export::new("orders", ExportType::Service)
        };
        let mut results = ValidationResults::default();
        export.validate(&mut results);
        assert!(results.is_blocking(false));
    }
}

#[test]
fn import_rejects_empty_account_but_not_invalid_account_shape() {
    let empty = Import::new("orders", ExportType::Stream);
    let mut empty_results = ValidationResults::default();
    empty.validate(&mut empty_results);
    assert!(empty_results.is_blocking(false));

    let mut nonempty = Import::new("orders", ExportType::Stream);
    nonempty.account = "not-an-account-key".into();
    let mut nonempty_results = ValidationResults::default();
    nonempty.validate(&mut nonempty_results);
    assert!(!nonempty_results.is_blocking(false));
}

#[test]
fn import_empty_local_subject_falls_back_to_source_subject() {
    let import = Import {
        account: KeyPair::new_account().public_key(),
        local_subject: Some(RenamingSubject::from("")),
        ..Import::new("orders", ExportType::Service)
    };
    for (subject, overlaps) in [("orders", true), ("events", false)] {
        let imports = Imports(vec![
            import.clone(),
            Import {
                account: import.account.clone(),
                ..Import::new(subject, ExportType::Service)
            },
        ]);
        let mut results = ValidationResults::default();
        imports.validate(&mut results);
        assert_eq!(results.is_blocking(false), overlaps, "{subject}");
    }
}

#[test]
fn renaming_subject_accepts_zero_wildcard_reference() {
    let renaming = RenamingSubject::from("archive.$0");
    let mut results = ValidationResults::default();
    renaming.validate(&Subject::from("source.*"), &mut results);
    assert!(!results.is_blocking(false));
}

#[test]
fn export_latency_uses_upstream_wire_field() {
    let mut export = Export::new("orders", ExportType::Service);
    export.latency = Some(nats_token::policy::ServiceLatency {
        sampling: 0,
        results: Subject::from("metrics"),
    });
    let wire = serde_json::to_value(&export).unwrap();
    assert_eq!(wire["service_latency"]["sampling"], "headers");
    assert_eq!(serde_json::from_value::<Export>(wire).unwrap(), export);
}

#[test]
fn export_account_token_position_boundaries() {
    for (subject, position, valid) in [
        ("*", 1, true),
        ("foo.*", 2, true),
        ("foo.*.bar.*", 2, true),
        ("foo.*.bar.>", 2, true),
        ("*.*.*.>", 2, true),
        ("*.*.>", 1, true),
        (">", 5, false),
        ("foo.>", 2, false),
        ("bar.>", 1, false),
        ("*", 5, false),
        ("*.*", 5, false),
        ("bar", 1, false),
        ("foo.bar", 2, false),
        ("foo.*.bar", 3, false),
        ("*.>", 3, false),
        ("*.*.>", 3, false),
        ("foo.*x.bar", 2, false),
        ("foo.x*.bar", 2, false),
        ("*", u32::MAX, false),
    ] {
        for kind in [ExportType::Stream, ExportType::Service] {
            let mut export = Export::new(subject, kind);
            export.account_token_position = Some(position);
            let mut results = ValidationResults::default();
            export.validate(&mut results);
            assert_eq!(!results.is_blocking(false), valid, "{subject}:{position}");
        }
    }
}

#[test]
fn export_response_latency_and_trace_boundaries() {
    for kind in [ExportType::Stream, ExportType::Service] {
        for mode in ["", "Singleton", "Stream", "Chunked", "singleton", "bad"] {
            let mut export = Export::new("orders", kind);
            export.response_type = Some(mode.into());
            let mut results = ValidationResults::default();
            export.validate(&mut results);
            let valid = mode.is_empty()
                || (kind == ExportType::Service
                    && matches!(mode, "Singleton" | "Stream" | "Chunked"));
            assert_eq!(!results.is_blocking(false), valid, "{kind:?}:{mode}");
        }
        for threshold in [-1, 0, 1, i64::MAX] {
            let mut export = Export::new("orders", kind);
            export.response_threshold = Some(threshold);
            let mut results = ValidationResults::default();
            export.validate(&mut results);
            assert_eq!(
                !results.is_blocking(false),
                threshold == 0 || (threshold > 0 && kind == ExportType::Service)
            );
        }
        for sampling in [-1, 0, 1, 100, 101] {
            for subject in ["metrics", "", "metrics.*", "metrics.>", "metrics..x"] {
                let mut export = Export::new("orders", kind);
                export.latency = Some(nats_token::policy::ServiceLatency {
                    sampling,
                    results: Subject::from(subject),
                });
                let mut results = ValidationResults::default();
                export.validate(&mut results);
                assert_eq!(
                    !results.is_blocking(false),
                    kind == ExportType::Service
                        && (0..=100).contains(&sampling)
                        && subject == "metrics"
                );
            }
        }
        for allow_trace in [false, true] {
            let mut export = Export::new("orders", kind);
            export.allow_trace = allow_trace;
            let mut results = ValidationResults::default();
            export.validate(&mut results);
            assert_eq!(
                !results.is_blocking(false),
                !allow_trace || kind == ExportType::Service
            );
            let mut import = Import::new("orders", kind);
            import.account = KeyPair::new_account().public_key();
            import.allow_trace = allow_trace;
            let mut results = ValidationResults::default();
            import.validate(&mut results);
            assert_eq!(
                !results.is_blocking(false),
                !allow_trace || kind == ExportType::Stream
            );
        }
    }
}

#[test]
fn overlap_rules_use_type_account_and_effective_subject() {
    let account = KeyPair::new_account().public_key();
    for (left, right, overlaps) in [
        ("orders", "orders", true),
        ("orders.*", "orders.created", true),
        ("orders.>", "orders.created.more", true),
        ("orders.>", "orders", false),
        ("orders.*", "*.created", false),
        ("orders", "events", false),
    ] {
        for same_type in [false, true] {
            let exports = Exports(vec![
                Export::new(left, ExportType::Service),
                Export::new(
                    right,
                    if same_type {
                        ExportType::Service
                    } else {
                        ExportType::Stream
                    },
                ),
            ]);
            let mut results = ValidationResults::default();
            exports.validate(&mut results);
            assert_eq!(results.is_blocking(false), same_type && overlaps);
        }
        for same_account in [false, true] {
            let imports = Imports(vec![
                Import {
                    account: account.clone(),
                    to: Subject::from(left),
                    ..Import::new("source", ExportType::Service)
                },
                Import {
                    account: if same_account {
                        account.clone()
                    } else {
                        KeyPair::new_account().public_key()
                    },
                    to: Subject::from(right),
                    ..Import::new("other", ExportType::Service)
                },
            ]);
            let mut results = ValidationResults::default();
            imports.validate(&mut results);
            assert_eq!(results.is_blocking(false), same_account && overlaps);
        }
    }
    for kind in [ExportType::Stream, ExportType::Service] {
        let imports = Imports(vec![
            Import {
                account: account.clone(),
                local_subject: Some(RenamingSubject::from("local.$1")),
                ..Import::new("source.*", kind)
            },
            Import {
                account: account.clone(),
                local_subject: Some(RenamingSubject::from("local.created")),
                ..Import::new("other", kind)
            },
        ]);
        let mut results = ValidationResults::default();
        imports.validate(&mut results);
        assert_eq!(results.is_blocking(false), kind == ExportType::Service);
    }
}

#[test]
fn export_revocations_keep_latest_and_round_trip() {
    let mut export = Export::new("orders", ExportType::Service);
    let key = KeyPair::new_account().public_key();
    let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
    export.clear_revocation(&key);
    assert!(!export.is_revoked(&key, at(10)));
    export.revoke_at(&key, at(100));
    export.revoke_at(&key, at(50));
    assert!(export.is_revoked(&key, at(100)));
    assert!(!export.is_revoked(&key, at(101)));
    let wire = serde_json::to_value(&export).unwrap();
    let mut decoded: Export = serde_json::from_value(wire).unwrap();
    assert!(decoded.is_revoked(&key, at(60)));
    decoded.revoke_at("*", at(20));
    assert!(decoded.is_revoked("other", at(20)));
    assert!(!decoded.is_revoked("other", at(21)));
    decoded.clear_revocation(&key);
    assert!(!decoded.is_revoked(&key, at(60)));
    decoded.clear_revocation("*");
    assert!(!decoded.is_revoked(&key, at(10)));
}

#[test]
fn imports_sort_by_subject() {
    let mut imports = Imports(vec![
        Import::new("z", ExportType::Stream),
        Import::new("a", ExportType::Service),
    ]);
    imports.sort_by_subject();
    assert_eq!(imports.0[0].subject, Subject::from("a"));
}
