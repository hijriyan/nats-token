// NSC integration cases adapted from nats-io/jwt.js/tests/jwt_test.ts.
// Copyright 2021-2024 The NATS Authors. Licensed under Apache-2.0.
// Run: cargo test --test jwt_v2_nsc -- --ignored

use nats_token::{decode_account_claims, decode_user_claims, AccountClaims, OperatorClaims};
use nkeys::KeyPair;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Nsc(PathBuf);

impl Nsc {
    fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "nj-jwt-v2-nsc-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> String {
        let output = Command::new("nsc")
            .arg("--all-dirs")
            .arg(&self.0)
            .args(args)
            .env("NSC_NO_GIT", "true")
            .output()
            .expect("install nsc to run the JWT interoperability tests");
        assert!(
            output.status.success(),
            "nsc {args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.run(args)).unwrap()
    }
}

impl Drop for Nsc {
    fn drop(&mut self) {
        // Remove only the uniquely created test store, including disposable keys.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires nsc on PATH; uses a disposable isolated store"]
fn read_account() {
    let nsc = Nsc::new();
    nsc.run(&["add", "operator", "--name", "O"]);
    nsc.run(&["add", "account", "--name", "A"]);
    let operator = nsc.json(&["describe", "operator", "--json"]);
    let account = nsc.json(&["describe", "account", "A", "--json"]);
    let token = nsc.run(&["describe", "account", "A", "--raw"]);
    let claim = decode_account_claims(&token).unwrap();
    assert_eq!(claim.account.version, 2);
    assert_eq!(claim.claims.name, account["name"]);
    assert_eq!(claim.claims.subject, account["sub"]);
    assert_eq!(claim.claims.issuer, operator["sub"]);
    assert_eq!(claim.claims.issuer, account["iss"]);
}

#[test]
#[ignore = "requires nsc on PATH; uses a disposable isolated store"]
fn write_account() {
    let nsc = Nsc::new();
    let operator = KeyPair::new_operator();
    let mut op = OperatorClaims::new(operator.public_key()).unwrap();
    op.claims.name = "O".into();
    let operator_file = nsc.0.join("operator.jwt");
    fs::write(&operator_file, op.encode(&operator).unwrap()).unwrap();
    nsc.run(&["add", "operator", "--url", operator_file.to_str().unwrap()]);

    let mut account = AccountClaims::new(KeyPair::new_account().public_key()).unwrap();
    account.claims.name = "A".into();
    let token = account.encode(&operator).unwrap();
    let account_file = nsc.0.join("account.jwt");
    fs::write(&account_file, &token).unwrap();
    nsc.run(&[
        "import",
        "account",
        "--file",
        account_file.to_str().unwrap(),
    ]);
    let stored = nsc.json(&["describe", "account", "A", "--json"]);
    let decoded = decode_account_claims(&token).unwrap();
    assert_eq!(stored["name"], decoded.claims.name);
    assert_eq!(stored["sub"], decoded.claims.subject);
    assert_eq!(stored["iss"], decoded.claims.issuer);
    assert_eq!(stored["iss"], operator.public_key());
    assert_eq!(stored["nats"]["version"], 2);
    assert_eq!(nsc.run(&["describe", "account", "A", "--raw"]), token);
}

#[test]
#[ignore = "requires nsc on PATH; uses a disposable isolated store"]
fn tags() {
    let nsc = Nsc::new();
    nsc.run(&["add", "operator", "--name", "O"]);
    nsc.run(&["add", "account", "--name", "A"]);
    nsc.run(&["edit", "account", "--tag", "a", "--tag", "b", "--tag", "c"]);
    let token = nsc.run(&["describe", "account", "A", "--raw"]);
    let mut account = decode_account_claims(&token).unwrap();
    assert_eq!(account.account.version, 2);
    assert_eq!(account.account.tags, vec!["a", "b", "c"]);
    account.account.tags.add(["d"]);
    assert!(account.account.tags.contains("d"));

    nsc.run(&["add", "user", "--name", "u"]);
    nsc.run(&[
        "edit", "user", "--name", "u", "--tag", "x", "--tag", "y", "--tag", "z",
    ]);
    let token = nsc.run(&["describe", "user", "u", "--raw"]);
    let mut user = decode_user_claims(&token).unwrap();
    assert_eq!(user.user.version, 2);
    assert_eq!(user.user.tags, vec!["x", "y", "z"]);
    user.user.tags.add(["zz"]);
    assert!(user.user.tags.contains("zz"));
}
