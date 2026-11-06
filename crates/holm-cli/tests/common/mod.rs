//! Shared helpers for holm-cli's integration tests: a fake terminal, a fake
//! clipboard, a test `Env`, and a way to run one command against a vault in a
//! temporary folder.

#![allow(dead_code, reason = "each test file uses a different subset")]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use holm_cli::term::{Interrupt, Terminal};
use holm_cli::{Clip, Env};
use holm_core::clock::{Clock, SystemClock};
use holm_core::item::Timestamp;
use holm_core::session::Session;
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::clipboard::{ClipCheck, ClipboardError};
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
    /// `wait_for_key`; the text is the wait in whole seconds.
    Wait,
}

/// A terminal that answers from a queue and records every prompt. An empty queue
/// answers [`TtyError::EndOfInput`], as Ctrl-D would. `wait_for_key` answers
/// `wait_answer` at once (true: Enter was pressed; false: the time ran out) after
/// running `on_wait`, unless `wait_stalls` is set.
#[derive(Default)]
pub struct FakeTerminal {
    answers: VecDeque<String>,
    pub prompts: Vec<(Kind, String)>,
    pub wait_answer: bool,
    pub on_wait: Option<Box<dyn FnMut()>>,
    /// Models a wait whose monotonic deadline never comes (the Mac slept, so
    /// `Instant` stood still): after `on_wait`, only the interrupt can end it, and a
    /// wait with no interrupt, or one that never fires, panics.
    pub wait_stalls: bool,
    /// How many waits ended because the interrupt fired.
    pub wait_interrupted: usize,
    /// If set, every prompt is also appended here, as `[prompt]`.
    pub transcript: Option<Rc<RefCell<String>>>,
}

impl FakeTerminal {
    pub fn new(answers: &[&str]) -> FakeTerminal {
        FakeTerminal {
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            ..FakeTerminal::default()
        }
    }

    fn record(&mut self, kind: Kind, prompt: &str) {
        if let Some(t) = &self.transcript {
            t.borrow_mut().push_str(&format!("[{prompt}]"));
        }
        self.prompts.push((kind, prompt.to_owned()));
    }

    /// The prompts' kinds, in order.
    pub fn kinds(&self) -> Vec<Kind> {
        self.prompts.iter().map(|p| p.0).collect()
    }

    pub fn unused(&self) -> usize {
        self.answers.len()
    }
}

impl Terminal for FakeTerminal {
    fn secret(&mut self, prompt: &str, _max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        self.record(Kind::Secret, prompt);
        self.answers
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(TtyError::EndOfInput)
    }

    fn line(
        &mut self,
        prompt: &str,
        _max_bytes: usize,
        _deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.record(Kind::Line, prompt);
        self.answers
            .pop_front()
            .map(|a| Some(Zeroizing::new(a)))
            .ok_or(TtyError::EndOfInput)
    }

    fn wait_for_key(&mut self, until: Instant) -> Result<bool, TtyError> {
        self.wait_for_key_interruptible(until, None)
    }

    fn wait_for_key_interruptible(
        &mut self,
        until: Instant,
        interrupt: Interrupt<'_>,
    ) -> Result<bool, TtyError> {
        let secs = until
            .saturating_duration_since(Instant::now())
            .as_secs_f64()
            .round();
        self.record(Kind::Wait, &format!("{secs}"));
        if let Some(f) = &mut self.on_wait {
            f();
        }
        if interrupt.is_some_and(|fired| fired()) {
            self.wait_interrupted += 1;
            return Ok(false);
        }
        assert!(
            !self.wait_stalls,
            "the wait never ended: no interrupt fired"
        );
        Ok(self.wait_answer)
    }
}

/// A clock the test moves by hand. Clones share the same time.
#[derive(Clone, Default)]
pub struct TestClock {
    mono_secs: Arc<AtomicU64>,
    unix: Arc<AtomicI64>,
}

impl TestClock {
    /// A clock at a plausible wall time.
    pub fn new() -> TestClock {
        let clock = TestClock::default();
        clock.unix.store(1_800_000_000, Ordering::SeqCst);
        clock
    }

    /// Moves only the wall clock, as a sleep does: the monotonic clock stops.
    pub fn sleep(&self, secs: i64) {
        self.unix.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp(self.unix.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.mono_secs.load(Ordering::SeqCst))
    }
}

/// What the fake clipboard saw.
#[derive(Default)]
pub struct ClipState {
    /// What is on the clipboard now.
    pub contents: Option<String>,
    /// How many times a value was set.
    pub sets: usize,
    /// How many times it was cleared.
    pub clears: usize,
    /// Another app's copy, put on the clipboard right after Holm's `set`.
    pub replaced_by: Option<String>,
    /// How many of the next reads of the clipboard fail.
    pub unreadable_checks: usize,
}

/// A clipboard over shared [`ClipState`].
pub struct FakeClip(pub Rc<RefCell<ClipState>>);

impl Clip for FakeClip {
    fn set(&mut self, text: &str) -> Result<(), ClipboardError> {
        let mut s = self.0.borrow_mut();
        s.sets += 1;
        s.contents = Some(s.replaced_by.clone().unwrap_or_else(|| text.to_owned()));
        Ok(())
    }

    fn check(&mut self, text: &str) -> ClipCheck {
        let mut s = self.0.borrow_mut();
        if s.unreadable_checks > 0 {
            s.unreadable_checks -= 1;
            return ClipCheck::Unreadable;
        }
        if s.contents.as_deref() == Some(text) {
            ClipCheck::Holds
        } else {
            ClipCheck::Other
        }
    }

    fn clear(&mut self) {
        let mut s = self.0.borrow_mut();
        s.clears += 1;
        s.contents = None;
    }
}

/// An `Env` with the floor KDF costs (fast), no default vault and no clipboard (as
/// on a system other than macOS).
pub fn env() -> Env {
    Env {
        kdf: KdfParams::FLOOR,
        clock: Box::new(|| Box::new(SystemClock::new())),
        default_vault: None,
        clip: Box::new(|| Err(ClipboardError::Unavailable)),
        // Unknown, as when `/dev/console` can't be read: never a change.
        console_owner: Rc::new(|| None),
    }
}

/// [`env`] with a fake clipboard over `state`.
pub fn env_with_clip(state: &Rc<RefCell<ClipState>>) -> Env {
    let state = Rc::clone(state);
    Env {
        clip: Box::new(move || Ok(Box::new(FakeClip(Rc::clone(&state))) as Box<dyn Clip>)),
        ..env()
    }
}

/// An output stream that keeps its own bytes and also appends them to a shared
/// transcript, if one is given.
struct Tee {
    own: Vec<u8>,
    transcript: Option<Rc<RefCell<String>>>,
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.own.extend_from_slice(buf);
        if let Some(t) = &self.transcript {
            t.borrow_mut().push_str(&String::from_utf8_lossy(buf));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    run_env(path, args, term, &env())
}

/// [`run`] with a given `Env`. Output also goes to the terminal's transcript, if it
/// has one.
pub fn run_env(path: &Path, args: &[&str], term: &mut FakeTerminal, env: &Env) -> Ran {
    let mut full: Vec<OsString> = vec!["--vault".into(), path.as_os_str().to_owned()];
    full.extend(args.iter().map(OsString::from));
    let mut out = Tee {
        own: Vec::new(),
        transcript: term.transcript.clone(),
    };
    let mut err = Tee {
        own: Vec::new(),
        transcript: term.transcript.clone(),
    };
    let code = match holm_cli::args::parse(&full) {
        Ok(inv) => holm_cli::run(inv, env, term, &mut out, &mut err),
        Err(e) => holm_cli::usage_error(&e, &mut err),
    };
    Ran {
        code,
        out: String::from_utf8(out.own).unwrap(),
        err: String::from_utf8(err.own).unwrap(),
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
