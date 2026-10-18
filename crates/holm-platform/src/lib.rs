//! Holm platform code: everything that talks to the operating system.
//!
//! For now this is [`fs_store`], the vault file on disk with durable writes,
//! [`paths`], where the vault lives by default, [`lock`], one Holm at a time per
//! vault folder, and [`private_file`], the owner-only export file and the capped read
//! of an import file. All four use the standard library only. On macOS the optional
//! `gui-window` feature adds `window`, the window's minimised state from AppKit.

// No `unsafe` in the default build: everything there uses safe std APIs, and `unsafe`
// stays forbidden. The `gui-window` feature on macOS lowers this to `deny` so that the
// `window` module alone can allow it, each block with a `// SAFETY:` comment.
#![cfg_attr(
    not(all(feature = "gui-window", target_os = "macos")),
    forbid(unsafe_code)
)]
#![cfg_attr(all(feature = "gui-window", target_os = "macos"), deny(unsafe_code))]
#![deny(missing_docs)]

pub mod fs_store;
pub mod lock;
pub mod paths;
pub mod private_file;
#[cfg(all(feature = "gui-window", target_os = "macos"))]
pub mod window;

#[cfg(test)]
pub(crate) mod test_support {
    #![forbid(unsafe_code)]
    //! Helpers shared by this crate's unit tests.

    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Held while a test runs a child process, and by a test that needs a dropped
    /// lock to be free at once. A child process briefly holds copies of this
    /// process's open files (until its `exec` closes them), and a copy keeps a
    /// `File::try_lock` lock alive after the test drops its own handle.
    static CHILD_PROCESSES: Mutex<()> = Mutex::new(());

    /// Waits until no test is starting a child process, and blocks new ones until
    /// the guard drops.
    pub(crate) fn no_child_processes() -> MutexGuard<'static, ()> {
        CHILD_PROCESSES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Creates a FIFO at `path` with the `mkfifo` tool (std has no `mkfifo`).
    #[cfg(unix)]
    pub(crate) fn make_fifo(path: &std::path::Path) {
        let _guard = no_child_processes();
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(made.success());
    }
}
