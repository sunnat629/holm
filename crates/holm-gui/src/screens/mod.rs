//! The app's screens. [`Screen`] is the state machine: exactly one screen is live, and
//! each variant owns only the data that screen needs. Leaving a screen drops its data,
//! and a form's [`SecretInput`](crate::secret_input::SecretInput) buffers wipe
//! themselves on drop.

pub(crate) mod create;
#[allow(
    dead_code,
    reason = "LoginForm and the vault view use it from part B1b"
)]
pub(crate) mod fields;
pub(crate) mod item_view;
pub(crate) mod login_form;
pub(crate) mod transfer;
pub(crate) mod unlock;
pub(crate) mod vault;

use std::sync::mpsc::Receiver;

use eframe::egui;
use zeroize::Zeroizing;

use crate::clipboard::{Paste, SecretClipboard, paste_into};
use crate::messages;
use crate::secret_input::SecretInput;
use crate::widgets::secret_field::{SecretFieldOutput, secret_area, secret_field};
use crate::worker::{JobKind, WorkDone};
use create::CreateForm;
use unlock::UnlockForm;
pub(crate) use vault::VaultView;

/// Which kind of field had keyboard focus when the frame ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum FieldFocus {
    /// No text field.
    #[default]
    None,
    /// A plain text field (title, username, web address).
    Plain,
    /// A secret field.
    Secret,
}

/// What a screen's fields need from the app for one frame: the clipboard (to paste and
/// copy), and a note of which kind of field has focus, for the next frame's
/// `raw_input_hook`.
pub(crate) struct FieldIo<'a> {
    /// The app's clipboard.
    pub(crate) clipboard: &'a mut dyn SecretClipboard,
    /// The focus seen so far this frame.
    pub(crate) focus: FieldFocus,
    /// The vault's clipboard time in seconds, for the line after a copy.
    pub(crate) clear_secs: u32,
    /// A password copied this frame, for the app to schedule its clear. Wiped on drop.
    pub(crate) copied: Option<Zeroizing<String>>,
}

impl FieldIo<'_> {
    /// Draws a [`secret_field`] and pastes into `buf` when it asks for a paste (Cmd+V
    /// while focused). A paste counts as a change. A paste too long for `buf` adds
    /// nothing and sets `error` to a fixed line instead.
    pub(crate) fn secret_field(
        &mut self,
        ui: &mut egui::Ui,
        id_salt: &str,
        label: &'static str,
        buf: &mut SecretInput,
        error: &mut Option<&'static str>,
    ) -> SecretFieldOutput {
        let out = secret_field(ui, id_salt, label, buf);
        self.after_secret(ui, buf, out, error)
    }

    /// Draws a multiline [`secret_area`], with the same paste rules as
    /// [`FieldIo::secret_field`]. A pasted text keeps its newlines when `buf` is
    /// multiline.
    #[allow(dead_code, reason = "the field editor's rows use it from part B1b")]
    pub(crate) fn secret_area(
        &mut self,
        ui: &mut egui::Ui,
        id_salt: &str,
        label: &'static str,
        buf: &mut SecretInput,
        error: &mut Option<&'static str>,
    ) -> SecretFieldOutput {
        let out = secret_area(ui, id_salt, label, buf);
        self.after_secret(ui, buf, out, error)
    }

    /// Notes the focus and runs a requested paste for a secret field drawn this frame.
    fn after_secret(
        &mut self,
        ui: &egui::Ui,
        buf: &mut SecretInput,
        mut out: SecretFieldOutput,
        error: &mut Option<&'static str>,
    ) -> SecretFieldOutput {
        if out.has_focus {
            self.focus = FieldFocus::Secret;
        }
        if out.paste_requested {
            match paste_into(self.clipboard, buf) {
                Paste::Pasted => out.changed = true,
                Paste::TooLong => *error = Some(messages::PASTE_TOO_LONG),
                Paste::Nothing => {}
            }
            // The field drew itself before the paste; draw it again with the new text.
            ui.ctx().request_repaint();
        }
        out
    }

    /// Notes that a plain text field has focus, when `focused`.
    pub(crate) fn note_plain(&mut self, focused: bool) {
        if focused {
            self.focus = FieldFocus::Plain;
        }
    }
}

/// The screen the app shows now.
pub(crate) enum Screen {
    /// First run: choose a master password.
    Create(CreateForm),
    /// A vault exists: type the master password.
    Unlock(UnlockForm),
    /// The worker owns the session and runs Argon2. No form and no secret exist here.
    Working {
        /// What the worker is doing, for the status line.
        job: JobKind,
        /// Where the worker's answer arrives.
        rx: Receiver<WorkDone>,
        /// The open vault's view, kept across item jobs (none for create and unlock).
        keep: Option<VaultView>,
    },
    /// The vault is open.
    Vault(VaultView),
    /// Holm can't go on. Fixed text only.
    Fatal(&'static str),
}
