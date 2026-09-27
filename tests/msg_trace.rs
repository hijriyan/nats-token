use nats_token::policy::{MsgTrace, Subject};
use nats_token::AccountClaims;
use nkeys::KeyPair;

#[test]
fn account_trace_matches_upstream_wire_shape() {
    let account = KeyPair::new_account();
    let mut claim = AccountClaims::new(account.public_key()).unwrap();
    claim.account.trace = Some(MsgTrace {
        destination: Subject::from("trace.events"),
        sampling: 0,
    });

    let zero = serde_json::to_value(&claim.account.trace).unwrap();
    assert_eq!(zero["dest"], "trace.events");
    assert!(zero.get("destination").is_none());
    assert!(zero.get("sampling").is_none());

    claim.account.trace.as_mut().unwrap().sampling = 25;
    let nonzero = serde_json::to_value(&claim.account.trace).unwrap();
    assert_eq!(nonzero["sampling"], 25);

    let upstream = serde_json::json!({"dest": "trace.events", "sampling": 25});
    let decoded: MsgTrace = serde_json::from_value(upstream).unwrap();
    assert_eq!(decoded.destination, Subject::from("trace.events"));
    assert_eq!(decoded.sampling, 25);
}
