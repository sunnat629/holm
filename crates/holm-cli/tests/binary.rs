#![forbid(unsafe_code)]
//! The real `holm` binary refuses a password on the command line.

use std::process::Command;

#[test]
fn binary_rejects_password_flag() {
    for args in [
        &["--password", "x", "list"][..],
        &["list", "--password", "x"],
        &["-p", "x", "list"],
        &["--pass=x", "list"],
        &["--master", "x", "list"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_holm"))
            .args(args)
            .output()
            .expect("failed to run holm binary");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("only typed at the prompt"), "{stderr}");
        // No echo of the value: the fixed text has no letter x at all.
        assert!(!stderr.contains('x'), "{stderr}");
    }

    // A longer value is not echoed either.
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .args(["--password=EXAMPLE-argv-canary", "list"])
        .output()
        .expect("failed to run holm binary");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("EXAMPLE"), "{stderr}");
}

#[test]
fn binary_gen_help_and_unknown_command() {
    // `gen` needs no terminal and no vault.
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .args(["gen", "username"])
        .output()
        .expect("failed to run holm binary");
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());

    // Help goes to stdout and exits 0.
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .arg("help")
        .output()
        .expect("failed to run holm binary");
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("holm init")
    );

    // An unknown command is a usage error.
    let output = Command::new(env!("CARGO_BIN_EXE_holm"))
        .arg("frobnicate")
        .output()
        .expect("failed to run holm binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("frobnicate")
    );
}
