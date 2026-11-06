//! The `holm-gui` binary: opens Holm's window on macOS.
//!
//! `--vault <path>` picks another vault file (for manual testing); without it the
//! vault is at the default path (`holm_platform::paths::default_vault_path`). On
//! other operating systems it prints that the window is macOS-only for now.

use std::process::ExitCode;

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("Holm's window runs on macOS only for now.");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    if holm_platform::hardening::disable_core_dumps().is_err() {
        eprintln!("Holm could not disable core dumps.");
    }
    macos::run()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use eframe::egui;
    use holm_core::clock::SystemClock;
    use holm_crypto::kdf::KdfParams;
    use holm_gui::app::{AppConfig, HolmApp};
    use holm_gui::clipboard::SystemClipboard;

    /// Shown for any argument list other than none or `--vault <path>`.
    const USAGE: &str = "usage: holm-gui [--vault <path>]";

    /// Parses the arguments after the program name: none, or `--vault <path>` with a
    /// non-empty path. `Ok(None)` means "use the default path".
    pub(crate) fn parse_args(
        mut args: impl Iterator<Item = OsString>,
    ) -> Result<Option<PathBuf>, ()> {
        let Some(first) = args.next() else {
            return Ok(None);
        };
        if first != "--vault" {
            return Err(());
        }
        match (args.next(), args.next()) {
            (Some(path), None) if !path.is_empty() => Ok(Some(PathBuf::from(path))),
            _ => Err(()),
        }
    }

    /// The window options. `clipboard_shortcuts` stays off so egui never turns Cmd+C/X/V
    /// into copy or paste events (Security decision, clipboard in Phase 3).
    pub(crate) fn native_options() -> eframe::NativeOptions {
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("Holm")
                .with_inner_size([900.0, 600.0]),
            renderer: eframe::Renderer::Glow,
            clipboard_shortcuts: false,
            ..Default::default()
        }
    }

    /// Picks the vault path, then runs the window until it closes.
    pub(crate) fn run() -> ExitCode {
        let vault_path = match parse_args(std::env::args_os().skip(1)) {
            Ok(Some(path)) => path,
            Ok(None) => match holm_platform::paths::default_vault_path() {
                Some(path) => path,
                None => {
                    eprintln!(
                        "Holm could not find your home folder. Start it with --vault <path>."
                    );
                    return ExitCode::from(1);
                }
            },
            Err(()) => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        };
        let options = native_options();
        // On the main thread, before the window opens: the sleep, screen lock and
        // logout observers. `None` only off the main thread; the wall-clock check in
        // `tick` still catches a sleep then.
        let lock_events = holm_platform::window::LockEvents::install();
        let result = eframe::run_native(
            "Holm",
            options,
            Box::new(|cc| {
                holm_gui::fonts::install_fonts(&cc.egui_ctx);
                let app = HolmApp::new(AppConfig {
                    vault_path,
                    kdf: KdfParams::DEFAULT,
                    session_clock: Box::new(SystemClock::new()),
                    ui_clock: Box::new(SystemClock::new()),
                    // Opened on first copy or paste, not here.
                    clipboard: Box::new(SystemClipboard::new()),
                    file_dialog: Box::new(holm_gui::file_dialog::RfdDialog),
                    lock_events,
                    capture: Box::new(holm_gui::capture::SystemCapture),
                });
                #[cfg(all(feature = "dev-unlock", debug_assertions))]
                let app = match holm_gui::dev_unlock::password_from_env() {
                    Some(pw) => {
                        eprintln!("dev-unlock: unlocking from the environment (debug build only).");
                        app.with_dev_password(pw)
                    }
                    None => app,
                };
                Ok(Box::new(app))
            }),
        );
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                // Fixed text only: the library error's text could name a path.
                eprintln!("Holm could not open its window.");
                ExitCode::from(1)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn parse(args: &[&str]) -> Result<Option<PathBuf>, ()> {
            parse_args(args.iter().map(OsString::from))
        }

        #[test]
        fn egui_clipboard_shortcuts_stay_off() {
            assert!(!native_options().clipboard_shortcuts);
        }

        #[test]
        fn no_arguments_use_the_default_path() {
            assert_eq!(parse(&[]), Ok(None));
        }

        #[test]
        fn vault_flag_takes_one_path() {
            assert_eq!(
                parse(&["--vault", "/tmp/x/holm.vault"]),
                Ok(Some(PathBuf::from("/tmp/x/holm.vault")))
            );
        }

        #[test]
        fn anything_else_is_a_usage_error() {
            for args in [
                &["--vault"][..],
                &["--vault", ""],
                &["--vault", "a", "b"],
                &["--help"],
                &["holm.vault"],
                &["--vault=a"],
            ] {
                assert_eq!(parse(args), Err(()), "{args:?}");
            }
        }
    }
}
