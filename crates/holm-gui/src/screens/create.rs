//! The create screen: a new master password, typed twice, and the "I understand" box.

use eframe::egui;
use holm_core::strength::{self, StrengthReport};
use holm_crypto::MasterPassword;

use super::FieldIo;
use crate::messages;
use crate::secret_input::{MASTER_CAP, SecretInput};
use crate::widgets::strength_meter::strength_meter;

/// Label of the first password field.
pub(crate) const PASSWORD_LABEL: &str = "Master password";
/// Label of the second password field.
pub(crate) const CONFIRM_LABEL: &str = "Confirm master password";
/// Label of the "I understand" box.
pub(crate) const UNDERSTOOD_LABEL: &str = "I understand Holm can't recover my vault";
/// Label of the create button.
pub(crate) const CREATE_LABEL: &str = "Create vault";

/// The create form. Both buffers wipe themselves when the form drops.
pub(crate) struct CreateForm {
    /// The new master password.
    pub(crate) password: SecretInput,
    /// The same password again.
    pub(crate) confirm: SecretInput,
    /// The "I understand Holm can't recover my vault" box.
    pub(crate) understood: bool,
    /// Core's verdict on `password`, recomputed only when it changes. `None` while empty.
    pub(crate) report: Option<StrengthReport>,
    /// The fixed line shown after a refused submit or a failed create.
    pub(crate) error: Option<&'static str>,
}

impl CreateForm {
    /// An empty form.
    pub(crate) fn new() -> CreateForm {
        CreateForm {
            password: SecretInput::with_capacity(MASTER_CAP),
            confirm: SecretInput::with_capacity(MASTER_CAP),
            understood: false,
            report: None,
            error: None,
        }
    }

    /// An empty form showing `error` (after a failed create).
    pub(crate) fn with_error(error: &'static str) -> CreateForm {
        CreateForm {
            error: Some(error),
            ..CreateForm::new()
        }
    }

    /// Whether core accepts the password.
    fn strong(&self) -> bool {
        self.report.as_ref().is_some_and(|r| r.verdict.acceptable)
    }

    /// Why a submit would be refused now, in the order the user should fix it: too weak,
    /// then the two fields differ, then the box is not ticked. `None` means it can go.
    pub(crate) fn refusal(&self) -> Option<&'static str> {
        if !self.strong() {
            Some(messages::WEAK_PASSWORD)
        } else if !self.password.eq_secret(&self.confirm) {
            Some(messages::PASSWORDS_DIFFER)
        } else if !self.understood {
            Some(messages::TICK_TO_CONTINUE)
        } else {
            None
        }
    }

    /// A submit attempt (Enter in a field, or the button). On success both fields are
    /// emptied: the password moves out with no copy, and the confirm field is wiped.
    pub(crate) fn submit(&mut self) -> Option<MasterPassword> {
        if let Some(why) = self.refusal() {
            self.error = Some(why);
            return None;
        }
        self.confirm.clear();
        self.report = None;
        Some(self.password.take_master_password())
    }

    /// Recomputes the strength report from the password field.
    fn update_report(&mut self) {
        self.report = if self.password.is_empty() {
            None
        } else {
            // A wiping copy, dropped at the end of this statement.
            Some(strength::check(&self.password.to_master_password()))
        };
    }

    /// Draws the form. Returns the password when a submit went through.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        io: &mut FieldIo<'_>,
    ) -> Option<MasterPassword> {
        ui.heading("Create your vault");
        ui.label("Choose a master password. It is the only key to your vault.");
        ui.add_space(8.0);

        let mut refused = None;
        let first = io.secret_field(
            ui,
            "create-password",
            PASSWORD_LABEL,
            &mut self.password,
            &mut refused,
        );
        if first.changed {
            self.update_report();
        }
        if let Some(report) = &self.report {
            strength_meter(ui, report);
        }
        ui.add_space(4.0);
        let second = io.secret_field(
            ui,
            "create-confirm",
            CONFIRM_LABEL,
            &mut self.confirm,
            &mut refused,
        );
        if first.changed || second.changed {
            self.error = None;
        }
        if refused.is_some() {
            self.error = refused;
        }
        ui.add_space(4.0);
        if ui
            .checkbox(&mut self.understood, UNDERSTOOD_LABEL)
            .changed()
        {
            self.error = None;
        }
        ui.add_space(8.0);
        let ready = self.refusal().is_none();
        let clicked = ui
            .add_enabled(ready, egui::Button::new(CREATE_LABEL))
            .clicked();
        if let Some(error) = self.error {
            ui.label(error);
        }
        if clicked || first.submitted || second.submitted {
            self.submit()
        } else {
            None
        }
    }

    /// Whether both buffers are empty.
    pub(crate) fn buffers_empty(&self) -> bool {
        self.password.is_empty() && self.confirm.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRONG: &str = "correct-Horse-battery-staple-EXAMPLE-9";

    fn form(password: &str, confirm: &str, understood: bool) -> CreateForm {
        let mut form = CreateForm::new();
        form.password.push_str(password);
        form.confirm.push_str(confirm);
        form.understood = understood;
        form.update_report();
        form
    }

    #[test]
    fn refusals_come_in_order() {
        assert_eq!(form("", "", true).refusal(), Some(messages::WEAK_PASSWORD));
        assert_eq!(
            form("password1234", "password1234", true).refusal(),
            Some(messages::WEAK_PASSWORD)
        );
        assert_eq!(
            form(STRONG, "other", true).refusal(),
            Some(messages::PASSWORDS_DIFFER)
        );
        assert_eq!(
            form(STRONG, STRONG, false).refusal(),
            Some(messages::TICK_TO_CONTINUE)
        );
        assert_eq!(form(STRONG, STRONG, true).refusal(), None);
    }

    #[test]
    fn submit_takes_both_fields() {
        let mut ready = form(STRONG, STRONG, true);
        let password = ready.submit().expect("a ready form submits");
        assert_eq!(password.to_kdf_bytes().expose(), STRONG.as_bytes());
        assert!(ready.buffers_empty());
        assert!(ready.report.is_none());
        assert_eq!(ready.error, None);
    }

    #[test]
    fn refused_submit_keeps_fields_and_sets_error() {
        let mut unticked = form(STRONG, STRONG, false);
        assert!(unticked.submit().is_none());
        assert_eq!(unticked.error, Some(messages::TICK_TO_CONTINUE));
        assert!(!unticked.buffers_empty());
    }
}
