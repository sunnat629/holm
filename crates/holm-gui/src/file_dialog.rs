//! The native file dialog behind a trait, so the app and its tests never call the OS.
//!
//! The real dialog blocks the main thread until the user answers. That is allowed here:
//! the app paints a placeholder frame first (see the vault view), so nothing sensitive
//! is on screen while the dialog is open. A path returned by a dialog is only ever
//! placed in the same path field the user can type in; it is checked like a typed path.
//! The path is never logged.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

/// Which dialog a "Choose..." button opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialogKind {
    /// Pick a file to import.
    Import,
    /// Pick a new file to write an export to.
    Export,
    /// Pick a new file to write a backup to.
    Backup,
}

/// A source of file paths chosen by the user.
pub trait FileDialog {
    /// Asks for an existing CSV or JSON file. `None` when the user cancels.
    fn pick_import(&mut self) -> Option<PathBuf>;

    /// Asks for a path to save to, starting with `suggested_name`. `None` when the
    /// user cancels.
    fn pick_save(&mut self, suggested_name: &str) -> Option<PathBuf>;
}

/// The system open and save sheets, through `rfd`. Blocks until the user answers.
#[derive(Debug, Default)]
pub struct RfdDialog;

impl FileDialog for RfdDialog {
    fn pick_import(&mut self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("CSV or JSON", &["csv", "json"])
            .pick_file()
    }

    fn pick_save(&mut self, suggested_name: &str) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_file_name(suggested_name)
            .save_file()
    }
}

/// A dialog that never opens. It answers with a queued path, and counts its calls.
/// Used by tests and by any build without a window system.
#[derive(Default)]
pub struct NoDialog {
    next: Option<PathBuf>,
    calls: Rc<Cell<usize>>,
    hook: Option<Box<dyn FnMut()>>,
}

impl NoDialog {
    /// A dialog that answers with `path` (every call).
    #[must_use]
    pub fn returning(path: PathBuf) -> NoDialog {
        NoDialog {
            next: Some(path),
            ..NoDialog::default()
        }
    }

    /// Runs `hook` inside each call, before the answer. A test uses it to move a
    /// fake clock while the "dialog" is open.
    #[must_use]
    pub fn with_hook(mut self, hook: impl FnMut() + 'static) -> NoDialog {
        self.hook = Some(Box::new(hook));
        self
    }

    /// A handle that reads how many times the dialog was called.
    #[must_use]
    pub fn counter(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.calls)
    }

    fn answer(&mut self) -> Option<PathBuf> {
        self.calls.set(self.calls.get() + 1);
        if let Some(hook) = &mut self.hook {
            hook();
        }
        self.next.clone()
    }
}

impl FileDialog for NoDialog {
    fn pick_import(&mut self) -> Option<PathBuf> {
        self.answer()
    }

    fn pick_save(&mut self, _suggested_name: &str) -> Option<PathBuf> {
        self.answer()
    }
}
