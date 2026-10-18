//! The unlock screen: one password field, the Unlock button and the throttle line.

use eframe::egui;
use holm_core::throttle::ThrottleStatus;
use holm_crypto::MasterPassword;

use crate::messages;
use crate::secret_input::{MASTER_CAP, SecretInput};
use crate::widgets::secret_field::secret_field;

/// Label of the password field (the same words as on the create screen).
pub(crate) const PASSWORD_LABEL: &str = "Master password";
/// Label of the unlock button. No other node on this screen has exactly this label.
pub(crate) const UNLOCK_LABEL: &str = "Unlock";

/// The unlock form. The buffer wipes itself when the form drops.
pub(crate) struct UnlockForm {
    /// The master password being typed.
    pub(crate) password: SecretInput,
    /// The fixed line for the last failed try.
    pub(crate) error: Option<&'static str>,
}

impl UnlockForm {
    /// An empty form.
    pub(crate) fn new() -> UnlockForm {
        UnlockForm {
            password: SecretInput::with_capacity(MASTER_CAP),
            error: None,
        }
    }

    /// An empty form showing `error` (after a failed try).
    pub(crate) fn with_error(error: Option<&'static str>) -> UnlockForm {
        UnlockForm {
            error,
            ..UnlockForm::new()
        }
    }

    /// Whether a try may start: something is typed and no throttle wait is due.
    pub(crate) fn can_submit(&self, throttle: &ThrottleStatus) -> bool {
        throttle.retry_after.is_none() && !self.password.is_empty()
    }

    /// A submit attempt. While a wait is due or the field is empty it does nothing;
    /// otherwise the password moves out (no copy) and the field is left empty.
    pub(crate) fn submit(&mut self, throttle: &ThrottleStatus) -> Option<MasterPassword> {
        self.can_submit(throttle)
            .then(|| self.password.take_master_password())
    }

    /// Draws the form. Returns the password when a try should start.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        throttle: &ThrottleStatus,
    ) -> Option<MasterPassword> {
        ui.heading("Unlock your vault");
        ui.add_space(8.0);
        let field = secret_field(ui, "unlock-password", PASSWORD_LABEL, &mut self.password);
        if field.changed {
            self.error = None;
        }
        ui.add_space(8.0);
        let clicked = ui
            .add_enabled(self.can_submit(throttle), egui::Button::new(UNLOCK_LABEL))
            .clicked();
        if let Some(error) = self.error {
            ui.label(error);
        }
        if let Some(line) = messages::throttle_line(throttle) {
            ui.label(line);
        }
        if clicked || field.submitted {
            self.submit(throttle)
        } else {
            None
        }
    }

    /// Whether the buffer is empty.
    pub(crate) fn buffers_empty(&self) -> bool {
        self.password.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const FREE: ThrottleStatus = ThrottleStatus {
        consecutive_failures: 0,
        retry_after: None,
    };
    const WAITING: ThrottleStatus = ThrottleStatus {
        consecutive_failures: 3,
        retry_after: Some(Duration::from_secs(2)),
    };

    fn typed() -> UnlockForm {
        let mut form = UnlockForm::new();
        form.password.push_str("EXAMPLE-pw");
        form
    }

    #[test]
    fn waiting_or_empty_gives_no_submit() {
        let mut form = typed();
        assert!(form.submit(&WAITING).is_none());
        assert!(!form.buffers_empty(), "a refused try keeps the field");
        assert!(UnlockForm::new().submit(&FREE).is_none());
    }

    #[test]
    fn submit_takes_the_field() {
        let mut form = typed();
        let password = form.submit(&FREE).expect("a free form submits");
        assert_eq!(password.to_kdf_bytes().expose(), b"EXAMPLE-pw");
        assert!(form.buffers_empty());
    }
}
