//! The migration backup prompt (spec 4.3, Q2). After the move to file format 2 Holm
//! keeps a copy of the old file. This banner asks the owner whether to delete it. Holm
//! never deletes it without a click on the delete button, and the text says what a
//! delete does not remove.

use eframe::egui;
use holm_core::index::BackupPrompt;

use crate::messages;

/// What the owner chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackupChoice {
    /// Delete the old copy now.
    Delete,
    /// Ask again after the next unlock.
    Later,
}

/// The two lines of the prompt: why the copy exists, and what deleting does not do.
pub(crate) fn lines(prompt: BackupPrompt) -> [&'static str; 2] {
    let why = match prompt {
        BackupPrompt::AfterPasswordChange => messages::BACKUP_PROMPT_PASSWORD,
        BackupPrompt::AfterUnlock | BackupPrompt::Done => messages::BACKUP_PROMPT_UNLOCK,
    };
    [why, messages::BACKUP_PROMPT_LIMIT]
}

/// Draws the prompt and returns the owner's choice. `error` is the line for a failed
/// delete.
pub(crate) fn show_backup_prompt(
    ui: &mut egui::Ui,
    prompt: BackupPrompt,
    error: Option<&'static str>,
) -> Option<BackupChoice> {
    let mut choice = None;
    let [why, limit] = lines(prompt);
    ui.add_space(4.0);
    ui.label(why);
    ui.label(limit);
    if let Some(error) = error {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
    ui.horizontal(|ui| {
        if ui.button(messages::BACKUP_DELETE_LABEL).clicked() {
            choice = Some(BackupChoice::Delete);
        }
        if ui.button(messages::BACKUP_LATER_LABEL).clicked() {
            choice = Some(BackupChoice::Later);
        }
    });
    ui.add_space(4.0);
    choice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_prompt_mentions_snapshots() {
        for prompt in [BackupPrompt::AfterUnlock, BackupPrompt::AfterPasswordChange] {
            let text = lines(prompt).join(" ");
            assert!(text.contains("Time Machine"), "{prompt:?}");
            assert!(text.contains("SSD"), "{prompt:?}");
            assert!(text.contains("delete"), "{prompt:?}");
        }
    }

    #[test]
    fn password_prompt_names_the_old_password() {
        assert!(lines(BackupPrompt::AfterPasswordChange)[0].contains("old password"));
        assert!(!lines(BackupPrompt::AfterUnlock)[0].contains("old password"));
    }
}
