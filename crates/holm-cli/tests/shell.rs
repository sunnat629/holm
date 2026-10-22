//! `holm shell`: one unlocked session in one process, with idle auto-lock, one
//! throttle and a clipboard clear that runs from the prompt's deadline.
//!
//! The fake terminal answers from a queue of steps. A `Deadline` step moves the fake
//! clock forward and answers `Ok(None)`, as the real terminal does when the prompt's
//! deadline passes before Enter. A `Sleep` step moves only the wall clock (the Mac
//! slept, so the monotonic clock stood still), then asks the prompt's interrupt once,
//! as the real terminal does on its next 0.1 s poll.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::{ClipState, PW, Ran, env_with_clip, init, session, vault_dir};
use holm_cli::Env;
use holm_cli::shell::tokenize;
use holm_cli::term::{Interrupt, Terminal};
use holm_core::clock::Clock;
use holm_core::item::{ItemData, ItemId, ItemInput, Timestamp};
use holm_core::settings::Settings;
use holm_core::text::{GatedSecret, SecretText, Text};
use holm_crypto::MasterPassword;
use holm_platform::tty::TtyError;
use zeroize::Zeroizing;

const LOCKED: &str = "The vault is locked. Type unlock to open it.";
const IDLE_LOCKED: &str = "Locked after 5 minutes without use.";
const WRONG: &str = "That password didn't open this vault.";
const PROMPT: &str = "holm> ";
const LOCKED_PROMPT: &str = "holm (locked)> ";
const SLEEP_LOCKED: &str = "Locked because the computer slept.";
const USER_LOCKED: &str = "Locked because the Mac switched to another user or the login window.";

/// A clock the test moves by hand. Clones share the same time, so the shell and its
/// session see one clock.
#[derive(Clone, Default)]
struct TestClock {
    mono_secs: Arc<AtomicU64>,
    unix: Arc<AtomicI64>,
}

impl TestClock {
    fn advance(&self, secs: u64) {
        self.mono_secs.fetch_add(secs, Ordering::SeqCst);
        self.unix
            .fetch_add(i64::try_from(secs).unwrap(), Ordering::SeqCst);
    }

    /// Moves only the wall clock, as a sleep does: the monotonic clock stops.
    fn sleep(&self, secs: u64) {
        self.unix
            .fetch_add(i64::try_from(secs).unwrap(), Ordering::SeqCst);
    }

    /// Moves only the wall clock back, as a clock correction does.
    fn set_back(&self, secs: u64) {
        self.unix
            .fetch_sub(i64::try_from(secs).unwrap(), Ordering::SeqCst);
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

/// One answer from the fake terminal.
enum Step {
    /// A typed line or secret.
    Text(String),
    /// The clock moves on by this many seconds and the prompt's deadline passes.
    Deadline(u64),
    /// Runs, then the next step answers.
    Run(Box<dyn FnOnce()>),
    /// Ctrl-C at the prompt.
    CtrlC,
    /// The computer sleeps this many seconds while the prompt waits with nothing
    /// typed. If the prompt's interrupt fires, it answers `Ok(None)`; if not, the
    /// next step answers, typed after waking.
    Sleep(u64),
    /// This text is typed (no Enter yet), then the computer sleeps this many seconds.
    /// If the interrupt fires, the text is dropped and the prompt answers `Ok(None)`;
    /// if not, Enter is pressed after waking and the text is the line.
    TypedThenSleep(String, u64),
    /// The computer sleeps this many seconds at a prompt with nothing typed, the
    /// interrupt fires, and then the wall clock is set back by as much before the
    /// prompt returns `Ok(None)`. Panics if the interrupt does not fire.
    SleepThenSetBack(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Secret,
    Line,
    Wait,
}

/// A terminal that answers from `steps` and records every prompt and every line
/// deadline. An empty queue answers `EndOfInput`, as Ctrl-D does.
struct ShellTerm {
    steps: VecDeque<Step>,
    clock: TestClock,
    prompts: Vec<(Kind, String)>,
    deadlines: Vec<Option<Instant>>,
    /// The deadline of every hidden prompt that was given one.
    secret_deadlines: Vec<Option<Instant>>,
    /// How many prompts an interrupt stopped.
    interrupted: usize,
}

impl ShellTerm {
    fn new(clock: &TestClock, steps: Vec<Step>) -> ShellTerm {
        ShellTerm {
            steps: steps.into(),
            clock: clock.clone(),
            prompts: Vec::new(),
            deadlines: Vec::new(),
            secret_deadlines: Vec::new(),
            interrupted: 0,
        }
    }

    /// The answer to a prompt with this deadline and interrupt.
    fn answer(
        &mut self,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        loop {
            match self.next() {
                Some(Step::Text(t)) => return Ok(Some(Zeroizing::new(t))),
                Some(Step::Deadline(secs)) => {
                    assert!(deadline.is_some(), "a deadline step needs a deadline");
                    self.clock.advance(secs);
                    return Ok(None);
                }
                Some(Step::Sleep(secs)) => {
                    self.clock.sleep(secs);
                    if interrupt.is_some_and(|fired| fired()) {
                        self.interrupted += 1;
                        return Ok(None);
                    }
                }
                Some(Step::SleepThenSetBack(secs)) => {
                    self.clock.sleep(secs);
                    assert!(
                        interrupt.is_some_and(|fired| fired()),
                        "the interrupt did not fire"
                    );
                    self.interrupted += 1;
                    self.clock.set_back(secs);
                    return Ok(None);
                }
                Some(Step::TypedThenSleep(typed, secs)) => {
                    let typed = Zeroizing::new(typed);
                    self.clock.sleep(secs);
                    if interrupt.is_some_and(|fired| fired()) {
                        self.interrupted += 1;
                        return Ok(None);
                    }
                    return Ok(Some(typed));
                }
                Some(Step::CtrlC) => return Err(TtyError::Cancelled),
                Some(Step::Run(_)) | None => return Err(TtyError::EndOfInput),
            }
        }
    }

    fn next(&mut self) -> Option<Step> {
        loop {
            match self.steps.pop_front()? {
                Step::Run(f) => f(),
                other => return Some(other),
            }
        }
    }

    fn count(&self, kind: Kind) -> usize {
        self.prompts.iter().filter(|p| p.0 == kind).count()
    }

    /// The prompt texts of one kind, in order.
    fn texts(&self, kind: Kind) -> Vec<&str> {
        self.prompts
            .iter()
            .filter(|p| p.0 == kind)
            .map(|p| p.1.as_str())
            .collect()
    }

    fn all_prompts(&self) -> String {
        self.prompts.iter().map(|p| p.1.as_str()).collect()
    }
}

impl Terminal for ShellTerm {
    fn secret(&mut self, prompt: &str, _max_bytes: usize) -> Result<Zeroizing<String>, TtyError> {
        self.prompts.push((Kind::Secret, prompt.to_owned()));
        match self.next() {
            Some(Step::Text(t)) => Ok(Zeroizing::new(t)),
            Some(Step::Deadline(_)) => panic!("a secret prompt has no deadline"),
            Some(Step::Sleep(_) | Step::TypedThenSleep(..) | Step::SleepThenSetBack(_)) => {
                panic!("a plain secret prompt can't be interrupted")
            }
            Some(Step::CtrlC) => Err(TtyError::Cancelled),
            Some(Step::Run(_)) | None => Err(TtyError::EndOfInput),
        }
    }

    fn secret_until(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.secret_interruptible(prompt, max_bytes, deadline, None)
    }

    fn line(
        &mut self,
        prompt: &str,
        max_bytes: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.line_interruptible(prompt, max_bytes, deadline, None)
    }

    fn secret_interruptible(
        &mut self,
        prompt: &str,
        _max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.prompts.push((Kind::Secret, prompt.to_owned()));
        self.secret_deadlines.push(deadline);
        self.answer(deadline, interrupt)
    }

    fn line_interruptible(
        &mut self,
        prompt: &str,
        _max_bytes: usize,
        deadline: Option<Instant>,
        interrupt: Interrupt<'_>,
    ) -> Result<Option<Zeroizing<String>>, TtyError> {
        self.prompts.push((Kind::Line, prompt.to_owned()));
        self.deadlines.push(deadline);
        self.answer(deadline, interrupt)
    }

    fn wait_for_key(&mut self, _until: Instant) -> Result<bool, TtyError> {
        self.prompts.push((Kind::Wait, String::new()));
        Ok(false)
    }
}

/// Turns `lock_on_sleep` off in the vault at `path`. It is a weaker setting, so the
/// master password goes with it.
fn no_lock_on_sleep(path: &Path) {
    let mut s = session(path);
    let settings = Settings {
        lock_on_sleep: false,
        ..s.settings().unwrap().clone()
    };
    s.update_settings(settings, Some(&MasterPassword::new(PW.to_owned())))
        .unwrap();
}

fn t(s: &str) -> Step {
    Step::Text(s.to_owned())
}

fn clip_state() -> Rc<RefCell<ClipState>> {
    Rc::new(RefCell::new(ClipState::default()))
}

/// An `Env` with the fake clock and a fake clipboard.
fn shell_env(clock: &TestClock, clip: &Rc<RefCell<ClipState>>) -> Env {
    let clock = clock.clone();
    Env {
        clock: Box::new(move || Box::new(clock.clone())),
        ..env_with_clip(clip)
    }
}

/// [`shell_env`] whose `/dev/console` owner the test sets through `console`.
fn shell_env_console(
    clock: &TestClock,
    clip: &Rc<RefCell<ClipState>>,
    console: &Rc<Cell<Option<u32>>>,
) -> Env {
    let console = Rc::clone(console);
    Env {
        console_owner: Rc::new(move || console.get()),
        ..shell_env(clock, clip)
    }
}

/// A step that hands the Mac's screen to `uid` (None: the owner can't be read).
fn console_to(console: &Rc<Cell<Option<u32>>>, uid: Option<u32>) -> Step {
    let console = Rc::clone(console);
    Step::Run(Box::new(move || console.set(uid)))
}

/// Runs `holm --vault <path> shell` with `term`.
fn shell(path: &Path, term: &mut ShellTerm, env: &Env) -> Ran {
    let argv: Vec<OsString> = vec![
        "--vault".into(),
        path.as_os_str().to_owned(),
        "shell".into(),
    ];
    let inv = holm_cli::args::parse(&argv).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = holm_cli::run(inv, env, term, &mut out, &mut err);
    Ran {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

fn ok(ran: &Ran) {
    assert_eq!(
        ran.code,
        ExitCode::SUCCESS,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

/// Adds a login with `password` and returns its id.
fn add_login(path: &Path, title: &str, password: &str) -> ItemId {
    let mut s = session(path);
    s.add_item(ItemInput {
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("ada@example.com".to_owned()),
            password: SecretText::new(password.to_owned()),
            urls: vec![Text::new("https://mail.example.com".to_owned())],
            notes: SecretText::new(String::new()),
        },
    })
    .unwrap()
}

fn short(id: ItemId) -> String {
    id.to_hex()[..8].to_owned()
}

/// True if another Holm could take the vault folder's lock now.
fn folder_free(path: &Path) -> bool {
    holm_cli::vault::lock_folder(path).is_ok()
}

#[test]
fn tokenize_quotes_and_escapes() {
    let words = |line: &str| -> Vec<String> {
        tokenize(line)
            .unwrap()
            .iter()
            .map(|w| w.as_str().to_owned())
            .collect()
    };
    assert_eq!(words("list"), ["list"]);
    assert_eq!(words(""), Vec::<String>::new());
    assert_eq!(words("   \t "), Vec::<String>::new());
    assert_eq!(
        words("  add login   --title \"My Mail\" "),
        ["add", "login", "--title", "My Mail"]
    );
    assert_eq!(words("'a b'\"c d\"e"), ["a bc de"]);
    assert_eq!(words(r"a\ b c"), ["a b", "c"]);
    assert_eq!(words(r#""say \"hi\"""#), [r#"say "hi""#]);
    assert_eq!(words(r"'x\y'"), [r"x\y"]);
    assert_eq!(words(r#"it\'s "a\\b""#), ["it's", r"a\b"]);
    assert_eq!(words("--title \"\""), ["--title", ""]);
    assert_eq!(words("café 'naïve ü'"), ["café", "naïve ü"]);
    for bad in ["\"abc", "'abc", "a 'b c", r"abc\", r#""abc\"#] {
        assert!(tokenize(bad).is_err(), "{bad} should be refused");
    }
}

#[test]
fn unlock_list_lock_exit() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let check_path = path.clone();
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            // The shell holds the folder lock while it runs.
            Step::Run(Box::new(move || assert!(!folder_free(&check_path)))),
            t("list"),
            t("lock"),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.texts(Kind::Secret), ["Master password: "]);
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
    assert!(ran.err.contains("Locked."), "{}", ran.err);
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    // The folder lock is released on exit.
    assert!(folder_free(&path));
}

#[test]
fn shell_without_a_vault_stops_before_any_prompt() {
    let (_dir, path) = vault_dir();
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(&clock, vec![t(PW)]);
    let ran = shell(&path, &mut term, &env);
    assert_eq!(ran.code, ExitCode::FAILURE);
    assert!(ran.err.contains("Holm found no vault here."), "{}", ran.err);
    assert!(term.prompts.is_empty());
}

#[test]
fn locked_commands_refuse() {
    let (dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let csv = dir.path().join("in.csv");
    std::fs::write(&csv, "title,password\nA,b\n").unwrap();
    let csv = csv.to_str().unwrap().to_owned();
    let new_csv = dir.path().join("out.csv");
    let new_csv = new_csv.to_str().unwrap().to_owned();
    let refused = [
        "list".to_owned(),
        "get abcdef".to_owned(),
        "get abcdef --copy password".to_owned(),
        "add note --title T".to_owned(),
        "edit abcdef --title X".to_owned(),
        "rm abcdef".to_owned(),
        "passwd".to_owned(),
        format!("import {csv}"),
        format!("export {new_csv}"),
        format!("export --backup {new_csv}"),
    ];
    let mut steps = vec![t("not-the-password")];
    steps.extend(refused.iter().map(|l| t(l)));
    steps.extend([t("gen"), t("help"), t("version"), t("exit")]);
    let mut term = ShellTerm::new(&clock, steps);
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert!(ran.err.contains(WRONG), "{}", ran.err);
    assert_eq!(
        ran.err.matches(LOCKED).count(),
        refused.len(),
        "{}",
        ran.err
    );
    // Only the first unlock asked for a password; no refused command asked anything.
    assert_eq!(term.count(Kind::Secret), 1);
    assert_eq!(term.count(Kind::Line), refused.len() + 4);
    assert!(
        term.texts(Kind::Line).iter().all(|p| *p == LOCKED_PROMPT),
        "{:?}",
        term.prompts
    );
    assert_eq!(clip.borrow().sets, 0);
    assert!(!Path::new(&new_csv).exists());
    // gen, help and version need no vault.
    assert!(ran.out.contains("unlock"), "{}", ran.out);
    assert!(ran.out.contains(env!("CARGO_PKG_VERSION")), "{}", ran.out);
}

#[test]
fn idle_deadline_locks() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            // Before the auto-lock time: the deadline passes but nothing locks.
            Step::Deadline(100),
            t("list"),
            // The default auto-lock time is 300 seconds.
            Step::Deadline(300),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert!(
        term.deadlines[0].is_some(),
        "an open vault prompt has a deadline"
    );
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
    assert_eq!(ran.err.matches(IDLE_LOCKED).count(), 1, "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    // While locked with nothing to clear, the prompt waits with no deadline.
    assert_eq!(term.deadlines.last(), Some(&None));
}

#[test]
fn a_line_typed_after_the_idle_time_does_not_run() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let later = clock.clone();
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            // The idle time passes (for example while the Mac slept) and then a
            // command arrives before the deadline fired.
            Step::Run(Box::new(move || later.advance(301))),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert!(ran.err.contains(IDLE_LOCKED), "{}", ran.err);
    assert!(ran.err.contains(LOCKED), "{}", ran.err);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
}

#[test]
fn copy_schedules_clear_and_prompt_returns() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-copy-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let seen = Rc::clone(&clip);
    let still = Rc::clone(&clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("get {} --copy password", short(id))),
            // Back at the prompt with the value on the clipboard.
            Step::Run(Box::new(move || {
                assert_eq!(seen.borrow().contents.as_deref(), Some("EXAMPLE-copy-pw-1"));
            })),
            // 10 of the 30 seconds: not cleared yet.
            Step::Deadline(10),
            Step::Run(Box::new(move || {
                assert_eq!(still.borrow().clears, 0);
                assert!(still.borrow().contents.is_some());
            })),
            Step::Deadline(20),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    // No wait for Enter, and no master password asked again.
    assert_eq!(term.count(Kind::Wait), 0);
    assert_eq!(term.count(Kind::Secret), 1);
    assert_eq!(term.texts(Kind::Line), [PROMPT, PROMPT, PROMPT, PROMPT]);
    assert!(term.deadlines[1..].iter().all(Option::is_some));
    let state = clip.borrow();
    assert_eq!(state.sets, 1);
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
    assert!(
        ran.err
            .contains("Copied. Holm clears the clipboard in 30 seconds."),
        "{}",
        ran.err
    );
    assert_eq!(
        ran.err.matches("Clipboard cleared.").count(),
        1,
        "{}",
        ran.err
    );
    assert!(!ran.out.contains("EXAMPLE-copy-pw-1"));
    assert!(!ran.err.contains("EXAMPLE-copy-pw-1"));
}

#[test]
fn a_changed_clipboard_is_left_alone() {
    let (_dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    clip.borrow_mut().replaced_by = Some("someone else's text".to_owned());
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![t(PW), t("gen --copy"), Step::Deadline(30), t("exit")],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    let state = clip.borrow();
    assert_eq!(state.clears, 0);
    assert_eq!(state.contents.as_deref(), Some("someone else's text"));
    assert!(
        ran.err
            .contains("The clipboard changed since Holm copied to it, so Holm left it alone."),
        "{}",
        ran.err
    );
}

#[test]
fn an_unreadable_clipboard_is_cleared_anyway() {
    let (_dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    clip.borrow_mut().unreadable_checks = 1;
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![t(PW), t("gen --copy"), Step::Deadline(30), t("exit")],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    let state = clip.borrow();
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
    assert!(
        ran.err
            .contains("Holm couldn't read the clipboard to check it, so it cleared it anyway."),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("left it alone"), "{}", ran.err);
}

#[test]
fn exit_clears_clipboard_and_locks() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-copy-pw-2");
    for ending in [Some("exit"), Some("quit"), None] {
        let clock = TestClock::default();
        let clip = clip_state();
        let env = shell_env(&clock, &clip);
        let mut steps = vec![t(PW), t(&format!("get {} --copy password", short(id)))];
        // None: the queue runs out, which the fake reports as Ctrl-D.
        steps.extend(ending.map(t));
        let mut term = ShellTerm::new(&clock, steps);
        let ran = shell(&path, &mut term, &env);
        ok(&ran);
        let state = clip.borrow();
        assert_eq!(state.sets, 1, "{ending:?}");
        assert_eq!(state.clears, 1, "{ending:?}");
        assert_eq!(state.contents, None, "{ending:?}");
        assert!(ran.err.contains("Clipboard cleared."), "{}", ran.err);
        assert!(ran.err.contains("Locked."), "{}", ran.err);
        assert!(folder_free(&path), "{ending:?}");
    }
}

#[test]
fn lock_clears_the_clipboard_too() {
    let (_dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let seen = Rc::clone(&clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t("gen --copy"),
            t("lock"),
            Step::Run(Box::new(move || assert_eq!(seen.borrow().contents, None))),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(clip.borrow().clears, 1);
}

#[test]
fn throttle_survives_lock_and_unlock() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let later = clock.clone();
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t("wrong-password-1"),
            t("unlock"),
            t("wrong-password-2"),
            t("unlock"),
            t("wrong-password-3"),
            // The fourth unlock is refused before any prompt.
            t("unlock"),
            t("lock"),
            t("unlock"),
            // The 2-second wait passes on the session's clock.
            Step::Run(Box::new(move || later.advance(2))),
            t("unlock"),
            t(PW),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(ran.err.matches(WRONG).count(), 3, "{}", ran.err);
    assert_eq!(
        ran.err
            .matches("Too many wrong passwords. Wait 2 seconds and try again.")
            .count(),
        2,
        "{}",
        ran.err
    );
    assert_eq!(term.count(Kind::Secret), 4);
    assert!(ran.out.contains("Example Mail"), "{}", ran.out);
    // Opened once, at the last unlock: then `list` and `exit`.
    let lines = term.texts(Kind::Line);
    assert_eq!(lines.iter().filter(|p| **p == PROMPT).count(), 2);
}

#[test]
fn export_in_shell_asks_password_again() {
    let (dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-export-pw");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let file = dir.path().join("export.csv");
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("export \"{}\"", file.to_str().unwrap())),
            t("export"),
            t(PW),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(
        term.texts(Kind::Secret),
        ["Master password: ", "Master password again: "]
    );
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, "Type export to continue: ", PROMPT]
    );
    let csv = std::fs::read_to_string(&file).unwrap();
    assert!(csv.contains("EXAMPLE-export-pw"));
    assert!(ran.out.contains("Exported 1 item"), "{}", ran.out);
}

#[test]
fn passwd_and_phrase_copy_ask_again_and_others_do_not() {
    let (_dir, path) = vault_dir();
    init(&path);
    let phrase = {
        let mut s = session(&path);
        s.add_item(ItemInput {
            title: Text::new("Wallet".to_owned()),
            category: None,
            favourite: false,
            data: ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(SecretText::new("EXAMPLE seed words".to_owned())),
                notes: SecretText::new(String::new()),
            },
        })
        .unwrap()
    };
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t("add note --title Diary"),
            t("EXAMPLE note body"),
            t(&format!("get {} --copy phrase", short(phrase))),
            t(PW),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(
        term.texts(Kind::Secret),
        ["Master password: ", "Note: ", "Master password again: "]
    );
    assert!(ran.out.contains("Added "), "{}", ran.out);
    assert_eq!(
        clip.borrow().sets,
        1,
        "the phrase was copied after the password"
    );
}

#[test]
fn bad_lines_do_not_end_the_shell() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t("nonsense"),
            t("list --password hunter2"),
            t("list \"unclosed"),
            t("init"),
            t("shell"),
            t("unlock"),
            t(""),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert!(
        ran.err.contains("That is not a Holm command."),
        "{}",
        ran.err
    );
    assert!(
        ran.err.contains("Passwords are only typed at the prompt"),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("hunter2"));
    assert_eq!(
        ran.err
            .matches("That command doesn't run inside the shell.")
            .count(),
        2,
        "{}",
        ran.err
    );
    assert!(
        ran.err.contains("The vault is already open."),
        "{}",
        ran.err
    );
    assert!(ran.out.contains("Example Mail"), "{}", ran.out);
    assert_eq!(term.count(Kind::Secret), 1);
}

#[cfg(unix)]
#[test]
fn lock_with_an_unsaved_change_asks_first() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let folder = dir.path().to_owned();
    let mode = |m: u32| {
        let folder = folder.clone();
        move || std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(m)).unwrap()
    };
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            // No save can succeed in a read-only folder.
            Step::Run(Box::new(mode(0o500))),
            t("add note --title Kept"),
            t("EXAMPLE unsaved body"),
            t("lock"),
            t("no"),
            t("lock"),
            t("discard"),
            Step::Run(Box::new(mode(0o700))),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    ok(&ran);
    assert!(
        ran.err.contains("Holm couldn't confirm the save"),
        "{}",
        ran.err
    );
    assert_eq!(
        term.texts(Kind::Line),
        [
            PROMPT,
            PROMPT,
            "Type discard to lock without saving: ",
            PROMPT,
            "Type discard to lock without saving: ",
            LOCKED_PROMPT,
        ]
    );
    assert!(ran.err.contains("Not locked."), "{}", ran.err);
    assert!(
        ran.err.contains("Locked. Unsaved changes were discarded."),
        "{}",
        ran.err
    );
    // The change never reached the file.
    let s = session(&path);
    assert_eq!(s.active_items().unwrap().count(), 0);
}

#[test]
fn shell_output_holds_no_secret() {
    const CANARIES: [&str; 6] = [
        "CANARY-pw-7q",
        "CANARY-new-pw-8r",
        "CANARY-body-9s",
        "CANARY phrase words 1t",
        "CANARY-wrong-master-2u",
        "CANARY-new-Master-quiet-harbour-lamp-3v",
    ];
    let (dir, path) = vault_dir();
    init(&path);
    let login = add_login(&path, "L", CANARIES[0]);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let csv = dir.path().join("all.csv");
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(CANARIES[4]),
            t("unlock"),
            t(PW),
            t("list"),
            t(&format!("get {}", short(login))),
            t(&format!("get {} --copy password", short(login))),
            t(&format!("edit {} --new-password", short(login))),
            t(CANARIES[1]),
            t(CANARIES[1]),
            t("add note --title N"),
            t(CANARIES[2]),
            t("add phrase --title P"),
            t(CANARIES[3]),
            t(CANARIES[3]),
            t("passwd"),
            t(PW),
            t(CANARIES[5]),
            t(CANARIES[5]),
            t(&format!("export {}", csv.to_str().unwrap())),
            t("export"),
            t(CANARIES[5]),
            Step::Deadline(300),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    // Every step ran.
    assert!(ran.out.contains("Updated "), "{}", ran.out);
    assert_eq!(ran.out.matches("Added ").count(), 2, "{}", ran.out);
    assert!(
        ran.out.contains("Changed the master password."),
        "{}",
        ran.out
    );
    assert!(ran.out.contains("Exported 3 items"), "{}", ran.out);
    assert!(ran.err.contains("Locked after 5 minutes"), "{}", ran.err);
    assert_eq!(clip.borrow().sets, 1);
    assert!(csv.exists());
    let everything = format!("{}{}{}", ran.out, ran.err, term.all_prompts());
    for canary in CANARIES.iter().chain([&PW]) {
        assert!(
            !everything.contains(canary),
            "{canary} leaked: {everything}"
        );
    }
}

/// The idle time passes at a hidden prompt inside a command: the shell locks as an
/// idle lock, clears the clipboard, and the command changes nothing.
#[test]
fn idle_at_a_hidden_prompt_locks() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-copy-pw-3");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("get {} --copy password", short(id))),
            t("add note --title Walkaway"),
            // The user walks away at the hidden "Note: " prompt.
            Step::Deadline(300),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(ran.err.matches(IDLE_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains("Cancelled."), "{}", ran.err);
    // The hidden prompt waited with a deadline.
    assert_eq!(term.texts(Kind::Secret), ["Master password: ", "Note: "]);
    assert!(term.secret_deadlines.last().unwrap().is_some());
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    assert!(!ran.out.contains("Added "), "{}", ran.out);
    let state = clip.borrow();
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
    assert_eq!(session(&path).active_items().unwrap().count(), 1);
}

/// The idle time passes at a visible confirm prompt inside a command.
#[test]
fn idle_at_a_confirm_prompt_locks() {
    let (dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-export-pw-2");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let file = dir.path().join("export.csv");
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("export \"{}\"", file.to_str().unwrap())),
            // At "Type export to continue: ".
            Step::Deadline(300),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(ran.err.matches(IDLE_LOCKED).count(), 1, "{}", ran.err);
    assert_eq!(
        term.texts(Kind::Line),
        [
            PROMPT,
            "Type export to continue: ",
            LOCKED_PROMPT,
            LOCKED_PROMPT
        ]
    );
    // The confirm prompt waited with a deadline.
    assert!(term.deadlines[1].is_some());
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    assert!(!file.exists());
}

/// Ctrl-C at the discard prompt that Ctrl-C (or Ctrl-D) at the shell prompt led to
/// keeps the vault open with its change: Ctrl-C is a cancel, not a closed terminal.
#[cfg(unix)]
#[test]
fn ctrl_c_at_the_discard_prompt_keeps_the_change() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let folder = dir.path().to_owned();
    let mode = |m: u32| {
        let folder = folder.clone();
        move || std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(m)).unwrap()
    };
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            Step::Run(Box::new(mode(0o500))),
            t("add note --title Kept"),
            t("EXAMPLE unsaved body"),
            // At the shell prompt, then at "Type discard to lock without saving: ".
            Step::CtrlC,
            Step::CtrlC,
            Step::Run(Box::new(mode(0o700))),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    ok(&ran);
    assert!(ran.err.contains("Not locked."), "{}", ran.err);
    assert!(!ran.err.contains("discarded"), "{}", ran.err);
    assert_eq!(
        term.texts(Kind::Line),
        [
            PROMPT,
            PROMPT,
            "Type discard to lock without saving: ",
            PROMPT,
        ]
    );
    // `exit` saved the change once the folder was writable again.
    assert_eq!(session(&path).active_items().unwrap().count(), 1);
}

/// The input ends (Ctrl-D, or the terminal closes) at the shell prompt and again at
/// the discard prompt: nobody is left to ask, so the change is dropped and said so.
#[cfg(unix)]
#[test]
fn end_of_input_at_the_discard_prompt_discards() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let folder = dir.path().to_owned();
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            Step::Run(Box::new(move || {
                std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
            })),
            t("add note --title Dropped"),
            t("EXAMPLE unsaved body"),
            // The queue runs out: end of input at both prompts.
        ],
    );
    let ran = shell(&path, &mut term, &env);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    ok(&ran);
    assert!(
        ran.err.contains("Locked. Unsaved changes were discarded."),
        "{}",
        ran.err
    );
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, "Type discard to lock without saving: "]
    );
    assert_eq!(session(&path).active_items().unwrap().count(), 0);
}

/// The idle time passes at the discard prompt of `lock`: the idle lock discards, as
/// it does at the shell prompt.
#[cfg(unix)]
#[test]
fn idle_at_the_discard_prompt_locks() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let folder = dir.path().to_owned();
    let mode = |m: u32| {
        let folder = folder.clone();
        move || std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(m)).unwrap()
    };
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            Step::Run(Box::new(mode(0o500))),
            t("add note --title Kept"),
            t("EXAMPLE unsaved body"),
            t("lock"),
            // At "Type discard to lock without saving: ".
            Step::Deadline(300),
            Step::Run(Box::new(mode(0o700))),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    ok(&ran);
    assert!(
        ran.err
            .contains("Locked after 5 minutes without use. Unsaved changes were discarded."),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("Not locked."), "{}", ran.err);
    assert_eq!(
        term.texts(Kind::Line),
        [
            PROMPT,
            PROMPT,
            "Type discard to lock without saving: ",
            LOCKED_PROMPT,
            LOCKED_PROMPT,
        ]
    );
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    assert_eq!(session(&path).active_items().unwrap().count(), 0);
}

/// `lock` while already locked still clears a value `gen --copy` put on the
/// clipboard, as `exit` does.
#[test]
fn lock_while_locked_clears_the_clipboard() {
    let (_dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let seen = Rc::clone(&clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t("not-the-password"),
            t("gen --copy"),
            t("lock"),
            Step::Run(Box::new(move || assert_eq!(seen.borrow().contents, None))),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert!(
        ran.err.contains("The vault is already locked."),
        "{}",
        ran.err
    );
    assert_eq!(clip.borrow().clears, 1);
}

/// The computer sleeps while the shell waits at its prompt: the prompt stops, the
/// clipboard is cleared, and the vault locks before anything else runs.
#[test]
fn shell_locks_on_sleep_at_prompt() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("get {} --copy password", short(id))),
            // Two minutes asleep: under the auto-lock time, so only the sleep locks.
            Step::Sleep(120),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(ran.err.matches(SLEEP_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains(IDLE_LOCKED), "{}", ran.err);
    // The clipboard is cleared first, then the lock is reported.
    let cleared = ran.err.find("Clipboard cleared.").expect("cleared");
    assert!(cleared < ran.err.find(SLEEP_LOCKED).unwrap(), "{}", ran.err);
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
    assert_eq!(ran.err.matches(LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    let state = clip.borrow();
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
    assert!(!ran.err.contains("EXAMPLE-sleep-pw-1"));
}

/// The computer sleeps at a hidden prompt inside a command: the command stops
/// without its cancel message, and the vault locks.
#[test]
fn shell_locks_on_sleep_inside_inner_prompt() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-2");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("get {} --copy password", short(id))),
            t("add note --title Nap"),
            // The lid closes at the hidden "Note: " prompt.
            Step::Sleep(120),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(term.texts(Kind::Secret), ["Master password: ", "Note: "]);
    assert_eq!(ran.err.matches(SLEEP_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains("Cancelled."), "{}", ran.err);
    assert!(!ran.err.contains(IDLE_LOCKED), "{}", ran.err);
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
    assert!(!ran.out.contains("Added "), "{}", ran.out);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    let state = clip.borrow();
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
    assert_eq!(session(&path).active_items().unwrap().count(), 1);
}

/// A line typed before the sleep, with no Enter yet, is held only until the lock:
/// it is wiped and never runs.
#[test]
fn shell_keeps_typed_line_until_sleep_lock() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-3");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            Step::TypedThenSleep("list".to_owned(), 120),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(ran.err.matches(SLEEP_LOCKED).count(), 1, "{}", ran.err);
    // `list` never ran: not open (no titles) and not locked (no locked message).
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    assert!(!ran.err.contains(LOCKED), "{}", ran.err);
    assert_eq!(term.texts(Kind::Line), [PROMPT, LOCKED_PROMPT]);
}

/// With `lock_on_sleep` off, a sleep neither stops the prompt nor locks.
#[test]
fn shell_lock_on_sleep_false_stays_open() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-4");
    no_lock_on_sleep(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            Step::Sleep(120),
            t("list"),
            Step::TypedThenSleep("list".to_owned(), 120),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 0);
    assert!(!ran.err.contains(SLEEP_LOCKED), "{}", ran.err);
    assert!(!ran.err.contains(IDLE_LOCKED), "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 2, "{}", ran.out);
    assert_eq!(term.texts(Kind::Line), [PROMPT, PROMPT, PROMPT]);
}

/// A sleep while the vault is already locked (and nothing waits to be cleared) has
/// nothing to lock, and does not lock the vault again right after the next unlock.
#[test]
fn sleep_while_locked_then_unlock_stays_open() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-5");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t("lock"),
            // At the locked prompt there is nothing to protect, so no interrupt.
            Step::Sleep(120),
            t("unlock"),
            t(PW),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 0);
    assert!(!ran.err.contains(SLEEP_LOCKED), "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, LOCKED_PROMPT, PROMPT, PROMPT]
    );
}

/// A sleep longer than the auto-lock time is still reported as a sleep: the sleep
/// check runs before the idle check.
#[test]
fn shell_long_sleep_says_slept_not_idle() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-6");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            // Ten minutes asleep: past the five-minute auto-lock time too.
            Step::Sleep(600),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(ran.err.matches(SLEEP_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains(IDLE_LOCKED), "{}", ran.err);
    assert_eq!(term.texts(Kind::Line), [PROMPT, LOCKED_PROMPT]);
}

/// The interrupt's answer is what locks: a wall clock set back after it fired (so
/// the watch no longer sees a sleep) still locks.
#[test]
fn shell_locks_on_fired_interrupt_even_if_clock_set_back() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-sleep-pw-7");
    let clock = TestClock::default();
    let clip = clip_state();
    let env = shell_env(&clock, &clip);
    let mut term = ShellTerm::new(
        &clock,
        vec![t(PW), Step::SleepThenSetBack(120), t("list"), t("exit")],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(ran.err.matches(SLEEP_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.out.contains("Example Mail"), "{}", ran.out);
    assert_eq!(
        term.texts(Kind::Line),
        [PROMPT, LOCKED_PROMPT, LOCKED_PROMPT]
    );
}

/// Fast user switching or the login window hands `/dev/console` to another user:
/// the shell locks as for a sleep, clears the clipboard and drops the half-typed
/// line.
#[test]
fn shell_locks_when_console_user_changes() {
    let (_dir, path) = vault_dir();
    init(&path);
    let id = add_login(&path, "Example Mail", "EXAMPLE-switch-pw-1");
    let clock = TestClock::default();
    let clip = clip_state();
    let console = Rc::new(Cell::new(Some(501)));
    let env = shell_env_console(&clock, &clip, &console);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t(&format!("get {} --copy password", short(id))),
            // The login window takes the screen (root owns the console) while
            // "list" is half typed; no time passes, so no sleep is seen.
            console_to(&console, Some(0)),
            Step::TypedThenSleep("list".to_owned(), 0),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(ran.err.matches(USER_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains(SLEEP_LOCKED), "{}", ran.err);
    let cleared = ran.err.find("Clipboard cleared.").expect("cleared");
    assert!(cleared < ran.err.find(USER_LOCKED).unwrap(), "{}", ran.err);
    assert!(
        !ran.out.contains("Example Mail"),
        "the half-typed line never ran"
    );
    assert_eq!(term.texts(Kind::Line), [PROMPT, PROMPT, LOCKED_PROMPT]);
    let state = clip.borrow();
    assert_eq!(state.clears, 1);
    assert_eq!(state.contents, None);
}

/// A console owner change at a prompt inside a command stops the command and locks.
#[test]
fn shell_locks_on_console_change_inside_inner_prompt() {
    let (_dir, path) = vault_dir();
    init(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let console = Rc::new(Cell::new(Some(501)));
    let env = shell_env_console(&clock, &clip, &console);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            t("add note --title Switch"),
            // Another user takes the screen at the hidden "Note: " prompt.
            console_to(&console, Some(502)),
            Step::Sleep(0),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 1);
    assert_eq!(term.texts(Kind::Secret), ["Master password: ", "Note: "]);
    assert_eq!(ran.err.matches(USER_LOCKED).count(), 1, "{}", ran.err);
    assert!(!ran.err.contains("Cancelled."), "{}", ran.err);
    assert!(!ran.out.contains("Added "), "{}", ran.out);
    assert_eq!(term.texts(Kind::Line), [PROMPT, LOCKED_PROMPT]);
}

/// With `lock_on_sleep` off, a console owner change does not lock either.
#[test]
fn shell_console_change_ignored_when_lock_on_sleep_off() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-switch-pw-2");
    no_lock_on_sleep(&path);
    let clock = TestClock::default();
    let clip = clip_state();
    let console = Rc::new(Cell::new(Some(501)));
    let env = shell_env_console(&clock, &clip, &console);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            console_to(&console, Some(0)),
            Step::Sleep(0),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 0);
    assert!(!ran.err.contains(USER_LOCKED), "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
}

/// A console owner that can't be read (an error) is no change: no lock.
#[test]
fn shell_unreadable_console_is_no_change() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-switch-pw-3");
    let clock = TestClock::default();
    let clip = clip_state();
    let console = Rc::new(Cell::new(Some(501)));
    let env = shell_env_console(&clock, &clip, &console);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            t(PW),
            console_to(&console, None),
            Step::Sleep(0),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 0);
    assert!(!ran.err.contains(USER_LOCKED), "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
}

/// Unlocking counts the console's owner again: a user who unlocks with the password
/// while another user owns the console (say over SSH) is not locked out at once.
#[test]
fn shell_unlock_takes_the_console_owner_again() {
    let (_dir, path) = vault_dir();
    init(&path);
    add_login(&path, "Example Mail", "EXAMPLE-switch-pw-4");
    let clock = TestClock::default();
    let clip = clip_state();
    let console = Rc::new(Cell::new(Some(501)));
    let env = shell_env_console(&clock, &clip, &console);
    let mut term = ShellTerm::new(
        &clock,
        vec![
            console_to(&console, Some(502)),
            t(PW),
            Step::Sleep(0),
            t("list"),
            t("exit"),
        ],
    );
    let ran = shell(&path, &mut term, &env);
    ok(&ran);
    assert_eq!(term.interrupted, 0);
    assert!(!ran.err.contains(USER_LOCKED), "{}", ran.err);
    assert_eq!(ran.out.matches("Example Mail").count(), 1, "{}", ran.out);
}
