#![cfg(all(feature = "dev-unlock", debug_assertions, target_os = "macos"))]
//! The `dev-unlock` feature: a developer's password unlocks an existing vault once at
//! start, and never otherwise. Fake passwords only.

mod common;

use std::time::Duration;

use common::{OTHER_PASSWORD, PASSWORD, harness, make_vault, run_until, test_app, vault_path};
use holm_crypto::MasterPassword;
use holm_gui::app::ScreenKind;

const TIMEOUT: Duration = Duration::from_secs(30);

fn dev_password(text: &str) -> MasterPassword {
    MasterPassword::new(text.to_owned())
}

#[test]
fn right_password_reaches_the_vault_without_typing() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app.with_dev_password(dev_password(PASSWORD)));

    run_until(
        &mut harness,
        |app| app.screen_kind() == ScreenKind::Vault,
        TIMEOUT,
    );

    assert!(harness.state().is_unlocked());
}

#[test]
fn wrong_password_is_tried_once_and_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    make_vault(dir.path(), PASSWORD);
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app.with_dev_password(dev_password(OTHER_PASSWORD)));

    run_until(
        &mut harness,
        |app| {
            app.screen_kind() == ScreenKind::Unlock
                && app.throttle_status().consecutive_failures >= 1
        },
        TIMEOUT,
    );
    // More frames must not start another try.
    for _ in 0..10 {
        harness.step();
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(harness.state().screen_kind(), ScreenKind::Unlock);
    assert!(!harness.state().is_unlocked());
    assert_eq!(harness.state().throttle_status().consecutive_failures, 1);
}

#[test]
fn no_vault_keeps_the_create_screen() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _clock) = test_app(dir.path());
    let mut harness = harness(app.with_dev_password(dev_password(PASSWORD)));

    for _ in 0..10 {
        harness.step();
    }

    assert_eq!(harness.state().screen_kind(), ScreenKind::Create);
    assert!(!harness.state().is_unlocked());
    assert!(!vault_path(dir.path()).exists());
}
