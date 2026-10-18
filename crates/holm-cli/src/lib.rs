//! Holm's command-line app, as a library so tests can run every command in-process
//! with a fake terminal.
//!
//! `main.rs` parses the arguments, builds an [`Env`] and a
//! [`term::RealTerminal`], and calls [`run`]. Passwords come only from the
//! [`term::Terminal`]: never from an argument (see [`args`]), the environment or a
//! pipe. Each command is one-shot: it asks for the master password, does its work,
//! and locks the vault before the process ends. There is no background agent.

#![forbid(unsafe_code)]

pub mod args;
pub mod commands;
pub mod output;
pub mod term;
pub mod vault;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use holm_core::clock::Clock;
use holm_crypto::kdf::KdfParams;

use crate::args::{Command, Invocation, UsageError};
use crate::commands::read;
pub use crate::output::CliError;
use crate::term::Terminal;

/// What a run needs from outside: the key-derivation costs for a new vault, a clock
/// for each session, and the default vault path.
pub struct Env {
    /// The costs `init` uses. `KdfParams::DEFAULT` in the app; tests use the floor.
    pub kdf: KdfParams,
    /// Makes the clock for a new session.
    pub clock: Box<dyn Fn() -> Box<dyn Clock>>,
    /// The vault used when `--vault` is not given.
    pub default_vault: Option<PathBuf>,
}

/// The help text.
pub const USAGE: &str = "\
Usage: holm [--vault PATH] <command>

Commands:
  holm init                 Make a new vault.
  holm list [options]       List items: id, type, title, detail.
      --search TEXT         Only items whose title, username, web address,
                            chain or category contains TEXT.
      --type TYPE           login, crypto, phrase or note.
      --category NAME       Only items in this category.
      --uncategorised       Only items with no category.
      --favourites          Only favourites.
      --trash               The Trash instead of the active items.
      --sort ORDER          title (default), updated or created.
  holm get ID               Show an item. Secret fields show as (hidden).
                            ID is the item's id, or its first 6 or more
                            characters, as holm list shows it.
  holm gen [KIND]           Make a new password (default), passphrase or
                            username. No vault needed.
  holm help                 Show this help.
  holm version              Show the version.

Coming next: add, edit, rm, import, export, passwd and shell.

Holm asks for the master password at a hidden prompt on the terminal. It never
takes a password from the command line, the environment or a pipe.
";

/// Runs one parsed command and returns the exit code: 0 on success, 1 on failure,
/// 2 for a usage error. Errors are printed to `err` as `holm: <fixed text>`.
pub fn run(
    inv: Invocation,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    match dispatch(inv, env, term, out, err) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(e)) => usage_error(&e, err),
        Err(e) => {
            // Nothing better to do if the error stream itself fails.
            let _ = writeln!(err, "holm: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

/// Prints a usage error and returns exit code 2.
pub fn usage_error(e: &UsageError, err: &mut dyn Write) -> ExitCode {
    let _ = writeln!(err, "holm: {e}\nRun holm help to see the commands.");
    ExitCode::from(2)
}

fn dispatch(
    inv: Invocation,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let Invocation { vault, command } = inv;
    match command {
        Command::Help => {
            write!(out, "holm {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"))?;
            Ok(())
        }
        Command::Version => {
            writeln!(out, "holm {}", env!("CARGO_PKG_VERSION"))?;
            Ok(())
        }
        Command::Gen(args) => read::gen_value(&args, out),
        Command::Init => read::init(&vault_path(vault, env)?, env, term, out, err),
        Command::List(args) => {
            let opened = vault::open(&vault_path(vault, env)?, env, term, err)?;
            read::list(&opened.session, &args, out)
        }
        Command::Get(args) => {
            let opened = vault::open(&vault_path(vault, env)?, env, term, err)?;
            read::get(&opened.session, &args, out)
        }
        Command::Pending(_) => Err(CliError::NotReady),
    }
}

/// The vault path: `--vault` if given, else the default, made absolute so a later
/// change of directory can't move it.
fn vault_path(given: Option<PathBuf>, env: &Env) -> Result<PathBuf, CliError> {
    let path = given
        .or_else(|| env.default_vault.clone())
        .ok_or(CliError::NoVaultPath)?;
    absolute(&path)
}

fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    std::path::absolute(path).map_err(|_| CliError::DirError)
}
