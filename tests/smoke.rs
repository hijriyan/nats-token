#[test]
fn crate_is_loadable() {
    let result: nats_token::Result<()> = Ok(());
    assert!(result.is_ok());
}
