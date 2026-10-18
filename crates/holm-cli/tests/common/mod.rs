//! Shared helpers for holm-cli's integration tests: a fake terminal, a test `Env`,
//! and a way to run one command against a vault in a temporary folder.

#![allow(dead_code, reason = "each test file uses a different subset")]

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use holm_cli::Env;
use holm_cli::term::Terminal;
use holm_core::clock::SystemClock;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::FsStore;
use holm_platform::tty::TtyError;
use zeroize::Zeroizing;

/// A strong master password for test vaults.
pub const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";

/// Which kind of prompt the fake terminal was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Line,
}

/// A terminal that answers from a queue and records every prompt. An empty queue
/// answers [`TtyError::Cancelled`], as Ctrl-D would.
#[derive(Default)]
pub struct FakeTerminal {
    answers: VecDeque<String>,
    pub prompts: Vec<(Kind, String)>,
}

impl FakeTerminal {
    pub fn new(answers: &[&str]) -> FakeTerminal {
        FakeTerminal {
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            prompts: Vec::new(),
        }
    }

    pub fn unused(&self) -> usize {
        self.answers.len()
    }
}

impl Terminal for FakeTerminal {
    fn secret(&mut self, prompt: &str, _max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        self.prompts.push((Kind::Secret, prompt.to_owned()));
        self.answers
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(TtyError::Cancelled)
    }

    fn line(
        &mut self,
        prompt: &str,
        _max_bytes: usize,
        _deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.prompts.push((Kind::Line, prompt.to_owned()));
        self.answers
            .pop_front()
            .map(|a| Some(Zeroizing::new(a)))
            .ok_or(TtyError::Cancelled)
    }

    fn wait_for_key(&mut self, _until: Instant) -> Result<bool, TtyError> {
        Ok(false)
    }
}

/// An `Env` with the floor KDF costs (fast) and no default vault.
pub fn env() -> Env {
    Env {
        kdf: KdfParams::FLOOR,
        clock: Box::new(|| Box::new(SystemClock::new())),
        default_vault: None,
    }
}

/// A temporary folder and the vault path inside it.
pub fn vault_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.holm");
    (dir, path)
}

/// What one run printed.
pub struct Ran {
    pub code: ExitCode,
    pub out: String,
    pub err: String,
}

/// Parses `args` (after `holm --vault <path>`) and runs them with `term`.
pub fn run(path: &Path, args: &[&str], term: &mut FakeTerminal) -> Ran {
    let mut full: Vec<OsString> = vec!["--vault".into(), path.as_os_str().to_owned()];
    full.extend(args.iter().map(OsString::from));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = match holm_cli::args::parse(&full) {
        Ok(inv) => holm_cli::run(inv, &env(), term, &mut out, &mut err),
        Err(e) => holm_cli::usage_error(&e, &mut err),
    };
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// Makes a vault at `path` with [`PW`] through `holm init`.
pub fn init(path: &Path) {
    let mut term = FakeTerminal::new(&[PW, PW]);
    let ran = run(path, &["init"], &mut term);
    assert_eq!(ran.code, ExitCode::SUCCESS, "init failed: {}", ran.err);
}

/// Opens the vault at `path` directly, for adding fixtures.
pub fn session(path: &Path) -> Session<FsStore> {
    let mut s = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
    s.unlock(&MasterPassword::new(PW.to_owned())).unwrap();
    s
}

/// The exit code for a usage error.
pub fn usage() -> ExitCode {
    ExitCode::from(2)
}
