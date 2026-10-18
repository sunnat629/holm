//! Holm command-line app.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use holm_cli::Env;
use holm_cli::term::RealTerminal;
use holm_core::clock::SystemClock;
use holm_crypto::kdf::KdfParams;
use holm_platform::paths::default_vault_path;

fn main() -> ExitCode {
    // The arguments are the only thing read from the process environment.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let stderr = io::stderr();
    let mut err = stderr.lock();
    let inv = match holm_cli::args::parse(&args) {
        Ok(inv) => inv,
        Err(e) => return holm_cli::usage_error(&e, &mut err),
    };
    let env = Env {
        kdf: KdfParams::DEFAULT,
        clock: Box::new(|| Box::new(SystemClock::new())),
        default_vault: default_vault_path(),
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let code = holm_cli::run(inv, &env, &mut RealTerminal, &mut out, &mut err);
    if out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    code
}
