//! The import and export screens. Both take a typed file path (no file dialog: a
//! dialog would hand path handling to the OS and add a dependency).
//!
//! Import runs in three steps: type a path, read a preview (counts, and skipped rows
//! by row number only), then a report with the delete-the-source warning. Export asks
//! for the master password again and a tick on "this file is not encrypted".
//!
//! No screen text ever holds a value from the file or the typed path; every line is a
//! fixed message or a count.

use eframe::egui;
use egui::TextBuffer as _;
use holm_core::export::EXPORT_WARNING;
use holm_core::import::{
    Dialect, IMPORT_DELETE_SOURCE_WARNING, ImportPreview, ImportReport, RowIssue, RowProblem,
};
use holm_core::throttle::ThrottleStatus;

use super::FieldIo;
use super::login_form::{LineBuf, line_field};
use crate::messages;
use crate::secret_input::{MASTER_CAP, SecretInput};
use crate::worker::{Job, TransferResult};
use holm_platform::transfer::{TransferError, typed_path};

/// Label of the path field.
pub(crate) const PATH_LABEL: &str = "File path";
/// Label of the export password field.
pub(crate) const EXPORT_PASSWORD_LABEL: &str = "Master password to export";
/// Label of the box the user ticks before an export.
pub(crate) const EXPORT_CONFIRM_LABEL: &str = "I understand this file is not encrypted";
/// Label of the read-the-file button.
pub(crate) const READ_LABEL: &str = "Read file";
/// Label of the import button on the preview.
pub(crate) const IMPORT_LABEL: &str = "Import these rows";
/// Label of the export button.
pub(crate) const EXPORT_LABEL: &str = "Export";
/// Label of the close button.
pub(crate) const CLOSE_LABEL: &str = "Close";
/// Label of the cancel button.
pub(crate) const CANCEL_LABEL: &str = "Cancel";

/// How many skipped rows are listed before "and more".
const ISSUE_LIST_MAX: usize = 20;

/// What a transfer screen asks the vault view to do.
pub(crate) enum TransferAction {
    /// Start a worker job.
    Job(Job),
    /// Close the transfer screen.
    Close,
}

/// The path step of an import.
pub(crate) struct ImportForm {
    path: LineBuf,
    error: Option<&'static str>,
}

/// The export form.
pub(crate) struct ExportForm {
    path: LineBuf,
    password: SecretInput,
    confirmed: bool,
    error: Option<&'static str>,
}

/// The preview of a read file. The batch itself waits in `batch` until the user goes ahead.
pub(crate) struct PreviewState {
    batch: Option<Box<holm_core::import::ImportBatch>>,
    preview: ImportPreview,
    issues: Vec<RowIssue>,
}

/// Which transfer screen is open.
pub(crate) enum Transfer {
    /// Typing the import path.
    Pick(ImportForm),
    /// Showing what the file holds.
    Preview(PreviewState),
    /// The import finished.
    Report(ImportReport),
    /// The export form.
    Export(ExportForm),
    /// The export finished.
    Exported,
    /// A job holds the data; the answer decides the next screen.
    Busy,
}

impl Transfer {
    /// A fresh import screen.
    pub(crate) fn import() -> Transfer {
        Transfer::Pick(ImportForm {
            path: LineBuf::new(),
            error: None,
        })
    }

    /// A fresh export screen.
    pub(crate) fn export() -> Transfer {
        Transfer::Export(ExportForm {
            path: LineBuf::new(),
            password: SecretInput::with_capacity(MASTER_CAP),
            confirmed: false,
            error: None,
        })
    }

    /// Whether every secret buffer is empty.
    pub(crate) fn buffers_empty(&self) -> bool {
        match self {
            Transfer::Export(form) => form.password.is_empty(),
            _ => true,
        }
    }

    /// Characters typed in secret buffers.
    pub(crate) fn secret_char_count(&self) -> usize {
        match self {
            Transfer::Export(form) => form.password.char_count(),
            _ => 0,
        }
    }

    /// Takes the answer of a transfer job and moves to the next screen. `self` is the
    /// screen that was open when the job started.
    pub(crate) fn on_result(&mut self, result: TransferResult, items_added: bool) {
        let was_export = matches!(self, Transfer::Export(_));
        match result {
            TransferResult::Previewed(batch, preview) => {
                let issues = batch.issues().to_vec();
                *self = Transfer::Preview(PreviewState {
                    batch: Some(batch),
                    preview,
                    issues,
                });
            }
            TransferResult::Imported(report) => *self = Transfer::Report(report),
            TransferResult::Exported => *self = Transfer::Exported,
            TransferResult::Failed(fail) => {
                let text = fail_text(&fail, was_export, items_added);
                match self {
                    Transfer::Export(form) => form.error = Some(text),
                    Transfer::Pick(form) => form.error = Some(text),
                    _ => {
                        *self = Transfer::Pick(ImportForm {
                            path: LineBuf::new(),
                            error: Some(text),
                        });
                    }
                }
            }
        }
    }

    /// Draws the screen. Returns what the user asked for.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        throttle: &ThrottleStatus,
        io: &mut FieldIo<'_>,
    ) -> Option<TransferAction> {
        match self {
            Transfer::Pick(form) => form.show(ui, io),
            Transfer::Preview(state) => {
                let action = state.show(ui);
                if matches!(action, Some(TransferAction::Job(_))) {
                    *self = Transfer::Busy;
                }
                action
            }
            Transfer::Report(report) => {
                ui.heading("Import finished");
                ui.label(format!("{} added.", report.imported));
                ui.label(format!("{} skipped as duplicates.", report.duplicates));
                ui.label(format!("{} skipped with problems.", report.skipped));
                ui.label(format!("{} without a category.", report.uncategorised));
                ui.add_space(8.0);
                ui.label(IMPORT_DELETE_SOURCE_WARNING);
                close_button(ui)
            }
            Transfer::Export(form) => form.show(ui, throttle, io),
            Transfer::Exported => {
                ui.heading("Export finished");
                ui.label(
                    "The file is written. It is not encrypted. Delete it as soon as you are done.",
                );
                close_button(ui)
            }
            Transfer::Busy => None,
        }
    }
}

fn close_button(ui: &mut egui::Ui) -> Option<TransferAction> {
    ui.add_space(8.0);
    ui.button(CLOSE_LABEL)
        .clicked()
        .then_some(TransferAction::Close)
}

/// The fixed line for a failed transfer.
fn fail_text(fail: &TransferError, export: bool, items_added: bool) -> &'static str {
    match fail {
        TransferError::NotFound => messages::IMPORT_NOT_FOUND,
        TransferError::NotAbsolute => messages::PATH_NOT_ABSOLUTE,
        TransferError::Exists => messages::EXPORT_EXISTS,
        TransferError::NotAFile => messages::IMPORT_NOT_A_FILE,
        TransferError::NoAccess => messages::IMPORT_NO_ACCESS,
        TransferError::ReadFailed => messages::IMPORT_READ_FAILED,
        TransferError::WriteFailed => messages::EXPORT_WRITE_FAILED,
        TransferError::TooLarge => messages::IMPORT_TOO_BIG,
        TransferError::Import(e) => messages::import_parse_error(e),
        TransferError::Core(e) if export => messages::export_error(e),
        TransferError::Core(e) => messages::import_apply_error(e, items_added),
    }
}

/// The fixed line for a skipped row.
fn problem_text(problem: &RowProblem) -> &'static str {
    match problem {
        RowProblem::Field(_) => "a field breaks a rule",
        RowProblem::UnknownType => "unknown type",
        RowProblem::MissingAddress => "a crypto row has no address",
        RowProblem::MissingPhrase => "a recovery row has no phrase",
        RowProblem::EmptyRow => "nothing to import",
        RowProblem::ExtraFields => "more cells than the header",
        RowProblem::UnusedField => "a secret cell on a row that does not use it",
        RowProblem::BadFavourite => "favourite is not true or false",
        RowProblem::BadTimestamp => "a date is not valid",
    }
}

fn dialect_text(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Holm => "Holm",
        Dialect::Chrome => "Chrome",
        Dialect::Firefox => "Firefox",
        Dialect::Safari => "Safari",
    }
}

impl ImportForm {
    fn show(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) -> Option<TransferAction> {
        ui.heading("Import");
        ui.label("Type the path of a CSV or JSON file. Holm reads it and shows a preview before it adds anything.");
        ui.add_space(8.0);
        if line_field(ui, io, PATH_LABEL, &mut self.path) {
            self.error = None;
        }
        ui.add_space(8.0);
        let can_read = !self.path.as_str().is_empty();
        let mut action = None;
        let mut refused = false;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(can_read, egui::Button::new(READ_LABEL))
                .clicked()
            {
                match typed_path(self.path.as_str()) {
                    Ok(path) => action = Some(TransferAction::Job(Job::PreviewImport(path))),
                    Err(_) => refused = true,
                }
            }
            if ui.button(CANCEL_LABEL).clicked() {
                action = Some(TransferAction::Close);
            }
        });
        if refused {
            self.error = Some(messages::PATH_NOT_ABSOLUTE);
        }
        if let Some(error) = self.error {
            ui.label(error);
        }
        if matches!(action, Some(TransferAction::Job(_))) {
            self.error = None;
        }
        action
    }
}

impl PreviewState {
    fn show(&mut self, ui: &mut egui::Ui) -> Option<TransferAction> {
        let p = &self.preview;
        ui.heading("Preview");
        ui.label(format!("Written by: {}.", dialect_text(p.dialect)));
        ui.label(format!(
            "{} rows are ready: {} logins, {} crypto, {} recovery phrases, {} notes.",
            p.ready, p.logins, p.crypto, p.phrases, p.notes
        ));
        ui.label(format!("{} duplicates will be skipped.", p.duplicates));
        ui.label(format!(
            "{} rows land in Uncategorised.",
            p.unmatched_category_rows
        ));
        if p.otp_ignored > 0 {
            ui.label(format!(
                "{} one-time-password secrets will not be stored.",
                p.otp_ignored
            ));
        }
        ui.label(format!("{} rows will be skipped with a problem.", p.issues));
        for issue in self.issues.iter().take(ISSUE_LIST_MAX) {
            ui.label(format!(
                "Row {}: {}.",
                issue.row,
                problem_text(&issue.problem)
            ));
        }
        if self.issues.len() > ISSUE_LIST_MAX {
            ui.label("And more.");
        }
        ui.add_space(8.0);
        let mut action = None;
        ui.horizontal(|ui| {
            let can = p.logins + p.crypto + p.phrases + p.notes > 0;
            if ui
                .add_enabled(can, egui::Button::new(IMPORT_LABEL))
                .clicked()
                && let Some(batch) = self.batch.take()
            {
                action = Some(TransferAction::Job(Job::Import(batch)));
            }
            if ui.button(CANCEL_LABEL).clicked() {
                action = Some(TransferAction::Close);
            }
        });
        action
    }
}

impl ExportForm {
    fn can_submit(&self, throttle: &ThrottleStatus) -> bool {
        !self.path.is_empty()
            && !self.password.is_empty()
            && self.confirmed
            && throttle.retry_after.is_none()
    }

    fn show(
        &mut self,
        ui: &mut egui::Ui,
        throttle: &ThrottleStatus,
        io: &mut FieldIo<'_>,
    ) -> Option<TransferAction> {
        ui.heading("Export");
        ui.label(EXPORT_WARNING);
        ui.add_space(8.0);
        if line_field(ui, io, PATH_LABEL, &mut self.path) {
            self.error = None;
        }
        ui.checkbox(&mut self.confirmed, EXPORT_CONFIRM_LABEL);
        let field = io.secret_field(
            ui,
            "export-password",
            EXPORT_PASSWORD_LABEL,
            &mut self.password,
            &mut self.error,
        );
        if field.changed {
            self.error = None;
        }
        ui.add_space(8.0);
        let mut action = None;
        ui.horizontal(|ui| {
            let clicked = ui
                .add_enabled(self.can_submit(throttle), egui::Button::new(EXPORT_LABEL))
                .clicked();
            if (clicked || field.submitted) && self.can_submit(throttle) {
                // Check the path first: the password stays typed if it is refused.
                match typed_path(self.path.as_str()) {
                    Ok(path) => {
                        action = Some(TransferAction::Job(Job::Export {
                            path,
                            password: self.password.take_master_password(),
                        }));
                    }
                    Err(_) => self.error = Some(messages::PATH_NOT_ABSOLUTE),
                }
            }
            if ui.button(CANCEL_LABEL).clicked() {
                action = Some(TransferAction::Close);
            }
        });
        // While throttled the live wait replaces the fixed text.
        if let Some(wait) = throttle.retry_after.and(messages::throttle_line(throttle)) {
            ui.label(wait);
        } else if let Some(error) = self.error {
            ui.label(error);
        }
        action
    }
}
