//! The app's screens. [`Screen`] is the state machine: exactly one screen is live, and
//! each variant owns only the data that screen needs. Leaving a screen drops its data,
//! and a form's [`SecretInput`](crate::secret_input::SecretInput) buffers wipe
//! themselves on drop.

pub(crate) mod create;
pub(crate) mod unlock;

use std::sync::mpsc::Receiver;

use crate::worker::{JobKind, WorkDone};
use create::CreateForm;
use unlock::UnlockForm;

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
    },
    /// The vault is open.
    Vault(VaultView),
    /// Holm can't go on. Fixed text only.
    Fatal(&'static str),
}

/// The open vault. An empty placeholder until the item list (Task 4).
pub(crate) struct VaultView;
