//! Smoke test: the binary runs and announces itself.

use std::process::Command;

#[test]
fn prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .output()
        .expect("failed to run holm binary");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is not UTF-8");
    assert!(stdout.starts_with("holm "), "unexpected output: {stdout}");
}
