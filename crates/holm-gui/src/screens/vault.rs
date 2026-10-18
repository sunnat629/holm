//! The open vault: the item list on the left, the selected login (or the form) on the
//! right.
//!
//! The rows are built once from the session and owned here, so a frame never walks the
//! vault. All vault work (add, update, save) leaves as a [`Job`] for the worker thread,
//! and a lock request leaves as a [`VaultAction`] for the app. Locking drops this view,
//! so its rows, any open form (whose secret buffer wipes on drop) and the reveal state
//! all go with it.

use core::fmt;
use std::time::Duration;

use eframe::egui;
use egui::TextBuffer as _;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::item::{ItemData, ItemId, ItemInput, ItemType};
use holm_core::search::Query;
use holm_core::session::Session;
use holm_core::settings::REHIDE_PASSWORD_SECS;
use holm_core::text::{SecretText, Text};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use super::FieldIo;
use super::login_form::{FormAction, LineBuf, LoginForm, line_field};
use super::transfer::{Transfer, TransferAction};
use crate::clipboard::SecretClipboard;
use crate::messages;
use crate::rows::{ItemRow, build_rows};
use crate::worker::{Job, JobKind, TransferResult};

/// Label of the new-login button.
pub(crate) const NEW_LABEL: &str = "New login";
/// Label of the edit button.
pub(crate) const EDIT_LABEL: &str = "Edit";
/// Label of the reveal button.
pub(crate) const REVEAL_LABEL: &str = "Reveal";
/// Label of the hide button.
pub(crate) const HIDE_LABEL: &str = "Hide";
/// Label of the copy-password button.
pub(crate) const COPY_LABEL: &str = "Copy";
/// Label of the retry-save button.
pub(crate) const RETRY_LABEL: &str = "Try again";
/// Label of the lock button.
pub(crate) const LOCK_LABEL: &str = "Lock";
/// Label of the lock dialog's save button.
pub(crate) const SAVE_AND_LOCK_LABEL: &str = "Save and lock";
/// Label of the lock dialog's discard button.
pub(crate) const LOCK_ANYWAY_LABEL: &str = "Lock anyway";
/// Label of the lock dialog's cancel button.
pub(crate) const LOCK_CANCEL_LABEL: &str = "Cancel";
/// Label of the search box.
pub(crate) const SEARCH_LABEL: &str = "Search";
/// Label of the import button.
pub(crate) const IMPORT_OPEN_LABEL: &str = "Import...";
/// Label of the export button.
pub(crate) const EXPORT_OPEN_LABEL: &str = "Export...";
/// Shown under the list when items of other types exist.
pub(crate) const OTHER_TYPES_PREFIX: &str = "Other items not shown here:";
/// Shown with the count above. The command line lists every type.
pub(crate) const OTHER_TYPES_HINT: &str = "Use `holm get` on the command line to see them.";
/// How a hidden password looks.
pub(crate) const DOTS: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// What the open vault asks the app to do.
pub(crate) enum VaultAction {
    /// Vault work for the worker.
    Job(Job),
    /// The Lock button: lock, or ask first when there are unsaved changes.
    Lock,
    /// The lock dialog's "Save and lock".
    SaveAndLock,
    /// The lock dialog's "Lock anyway": lock and discard unsaved changes.
    LockAnyway,
}

/// What the right-hand side shows.
enum DetailMode {
    /// Nothing selected.
    Empty,
    /// The selected login, read-only.
    View,
    /// The form.
    Edit(LoginForm),
}

/// The open vault's screen state.
pub(crate) struct VaultView {
    /// The list rows.
    rows: Vec<ItemRow>,
    /// Whether `rows` must be rebuilt from the session before the next draw.
    rows_stale: bool,
    /// The selected item.
    selected: Option<ItemId>,
    /// The right-hand side.
    mode: DetailMode,
    /// When the revealed password hides again (UI clock time), if it is revealed.
    reveal_until: Option<Duration>,
    /// The fixed line shown above the detail, if any.
    status: Option<&'static str>,
    /// Whether the last write failed and left changes unsaved in memory.
    save_failed: bool,
    /// The fixed line for that failed write. Kept apart from `status` so navigation and
    /// other messages never hide it while the session is dirty.
    save_error: Option<&'static str>,
    /// The fixed line under the password after the Copy button, if any.
    copy_note: Option<&'static str>,
    /// Whether the unsaved-changes dialog of a manual lock is open.
    lock_dialog: bool,
    /// The search box. Wiped when the view drops on lock.
    search: LineBuf,
    /// The search text the rows were built with.
    searched: Zeroizing<String>,
    /// How many matching items are not logins.
    other_types: usize,
    /// The open import or export screen, if any.
    transfer: Option<Transfer>,
}

impl fmt::Debug for VaultView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultView")
            .field("rows", &self.rows.len())
            .field("revealed", &self.reveal_until.is_some())
            .finish_non_exhaustive()
    }
}

impl VaultView {
    /// A view whose rows are built on the first draw.
    pub(crate) fn new() -> VaultView {
        VaultView {
            rows: Vec::new(),
            rows_stale: true,
            selected: None,
            mode: DetailMode::Empty,
            reveal_until: None,
            status: None,
            save_failed: false,
            save_error: None,
            copy_note: None,
            lock_dialog: false,
            search: LineBuf::new(),
            searched: Zeroizing::new(String::new()),
            other_types: 0,
            transfer: None,
        }
    }

    /// Takes the answer of a transfer job. Called after `on_done`.
    pub(crate) fn on_transfer_done(&mut self, kind: JobKind, result: Option<TransferResult>) {
        if !kind.is_transfer() {
            return;
        }
        if matches!(result, Some(TransferResult::Imported(_))) {
            self.rows_stale = true;
        }
        if let Some(result) = result
            && let Some(transfer) = &mut self.transfer
        {
            transfer.on_result(result);
        }
    }

    /// Opens the dialog that asks before a manual lock discards unsaved changes.
    pub(crate) fn ask_before_lock(&mut self) {
        self.lock_dialog = true;
    }

    /// The dialog's "Save and lock" failed: closes the dialog and shows the
    /// failed-save banner, with its retry button. The vault stays open.
    pub(crate) fn on_lock_save_failed(&mut self, e: &CoreError) {
        self.lock_dialog = false;
        self.save_error = Some(messages::save_error(e));
        self.save_failed = true;
    }

    /// Whether the form holds no characters. True when no form is open.
    pub(crate) fn buffers_empty(&self) -> bool {
        let form = match &self.mode {
            DetailMode::Edit(form) => form.buffers_empty(),
            DetailMode::Empty | DetailMode::View => true,
        };
        form && self.transfer.as_ref().is_none_or(Transfer::buffers_empty)
    }

    /// Characters held by the form's secret buffer (0 when no form is open).
    pub(crate) fn secret_char_count(&self) -> usize {
        let form = match &self.mode {
            DetailMode::Edit(form) => form.password.char_count(),
            DetailMode::Empty | DetailMode::View => 0,
        };
        form + self
            .transfer
            .as_ref()
            .map_or(0, Transfer::secret_char_count)
    }

    /// Hides a revealed password when its time is up or the window lost focus.
    pub(crate) fn tick(&mut self, now: Duration, focused: bool) {
        if let Some(until) = self.reveal_until
            && (now >= until || !focused)
        {
            self.reveal_until = None;
        }
    }

    /// Takes the worker's answer for an item job.
    pub(crate) fn on_done(
        &mut self,
        kind: JobKind,
        result: &Result<(), CoreError>,
        added: Option<ItemId>,
        returned: Option<ItemInput>,
        session: &Session<FsStore>,
    ) {
        self.rows_stale = true;
        self.reveal_until = None;
        self.status = None;
        self.copy_note = None;
        match (kind, result) {
            (JobKind::Add, Ok(())) | (JobKind::Update, Ok(())) => {
                self.save_failed = false;
                self.save_error = None;
                if let Some(id) = added.or(self.selected) {
                    self.selected = Some(id);
                    self.mode = DetailMode::View;
                } else {
                    self.mode = DetailMode::Empty;
                }
            }
            (JobKind::Save, Ok(())) => {
                self.save_failed = false;
                self.save_error = None;
            }
            (JobKind::Add, Err(CoreError::Vault(VaultError::TooLargeToSave))) => {
                let form = match returned {
                    Some(input) => LoginForm::from_input(None, input, messages::TOO_LARGE_TO_SAVE),
                    None => {
                        let mut form = LoginForm::new_blank();
                        form.error = Some(messages::TOO_LARGE_TO_SAVE);
                        form
                    }
                };
                self.selected = None;
                self.mode = DetailMode::Edit(form);
            }
            (JobKind::Update, Err(CoreError::Vault(VaultError::TooLargeToSave))) => {
                self.mode = match (returned, self.selected) {
                    (Some(input), id @ Some(_)) => DetailMode::Edit(LoginForm::from_input(
                        id,
                        input,
                        messages::TOO_LARGE_TO_SAVE,
                    )),
                    (None, Some(id)) => {
                        match session.item(id).ok().and_then(LoginForm::from_item) {
                            Some(mut f) => {
                                f.error = Some(messages::TOO_LARGE_TO_SAVE);
                                DetailMode::Edit(f)
                            }
                            None => DetailMode::View,
                        }
                    }
                    (_, None) => DetailMode::Empty,
                };
            }
            (JobKind::Add | JobKind::Update | JobKind::Save, Err(e)) => {
                self.save_error = Some(messages::save_error(e));
                self.save_failed = true;
                if kind == JobKind::Add {
                    self.selected = None;
                    self.mode = DetailMode::Empty;
                } else if self.selected.is_some() {
                    self.mode = DetailMode::View;
                }
            }
            (
                JobKind::Create
                | JobKind::Unlock
                | JobKind::PreviewImport
                | JobKind::Import
                | JobKind::Export,
                _,
            ) => {}
        }
    }

    /// Draws the panels and returns what the user asked for. `idle_left` is the time
    /// until the idle lock when it is close enough to warn about.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
        now: Duration,
        idle_left: Option<Duration>,
        io: &mut FieldIo<'_>,
    ) -> Option<VaultAction> {
        if self.search.as_str() != self.searched.as_str() {
            self.rows_stale = true;
        }
        if self.rows_stale
            && let Some(session) = session
        {
            self.searched = Zeroizing::new(self.search.as_str().to_owned());
            let query = Query {
                text: Zeroizing::new(self.searched.as_str().to_owned()),
                ..Query::default()
            };
            match session.search(&query) {
                Ok(found) => {
                    self.rows = build_rows(&found);
                    self.other_types = found
                        .iter()
                        .filter(|s| s.item_type != ItemType::Login)
                        .count();
                }
                Err(_) => {
                    self.rows = Vec::new();
                    self.other_types = 0;
                }
            }
            self.rows_stale = false;
        }
        let mut action = None;
        egui::Panel::top("vault-top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Holm");
                if ui.button(LOCK_LABEL).clicked() {
                    action = Some(VaultAction::Lock);
                }
                let idle = self.transfer.is_none();
                if ui
                    .add_enabled(idle, egui::Button::new(IMPORT_OPEN_LABEL))
                    .clicked()
                {
                    self.transfer = Some(Transfer::import());
                }
                if ui
                    .add_enabled(idle, egui::Button::new(EXPORT_OPEN_LABEL))
                    .clicked()
                {
                    self.transfer = Some(Transfer::export());
                }
            });
        });
        if let Some(left) = idle_left {
            egui::Panel::bottom("vault-status").show(ui, |ui| {
                let amber = ui.visuals().warn_fg_color;
                ui.colored_label(amber, messages::idle_warning(left));
            });
        }
        egui::Panel::left("vault-list")
            .resizable(false)
            .exact_size(260.0)
            .show(ui, |ui| self.show_list(ui, io));
        let job = egui::CentralPanel::default()
            .show(ui, |ui| {
                if self.transfer.is_some() {
                    self.show_transfer(ui, io)
                } else {
                    self.show_detail(ui, session, now, io)
                }
            })
            .inner;
        if self.lock_dialog {
            action = self.show_lock_dialog(ui.ctx()).or(action);
        }
        action.or(job.map(VaultAction::Job))
    }

    /// The import or export screen in place of the detail pane.
    fn show_transfer(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) -> Option<Job> {
        let transfer = self.transfer.as_mut()?;
        match transfer.show(ui, io)? {
            TransferAction::Job(job) => Some(job),
            TransferAction::Close => {
                self.transfer = None;
                None
            }
        }
    }

    /// The dialog a manual lock opens when there are unsaved changes. Nothing is lost
    /// without a choice: "Save and lock", "Lock anyway" or "Cancel".
    fn show_lock_dialog(&mut self, ctx: &egui::Context) -> Option<VaultAction> {
        let mut action = None;
        let modal = egui::Modal::new(egui::Id::unique("vault-lock-dialog")).show(ctx, |ui| {
            ui.label(messages::UNSAVED_ON_LOCK);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(SAVE_AND_LOCK_LABEL).clicked() {
                    action = Some(VaultAction::SaveAndLock);
                }
                if ui.button(LOCK_ANYWAY_LABEL).clicked() {
                    action = Some(VaultAction::LockAnyway);
                }
                if ui.button(LOCK_CANCEL_LABEL).clicked() {
                    self.lock_dialog = false;
                }
            });
        });
        // Escape and a click on the backdrop count as Cancel.
        if modal.should_close() {
            self.lock_dialog = false;
        }
        action
    }

    /// The left panel: the new-login button and the rows.
    fn show_list(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) {
        if ui.button(NEW_LABEL).clicked() {
            self.selected = None;
            self.reveal_until = None;
            self.status = None;
            self.copy_note = None;
            self.mode = DetailMode::Edit(LoginForm::new_blank());
        }
        if line_field(ui, io, SEARCH_LABEL, &mut self.search) {
            self.rows_stale = true;
        }
        ui.separator();
        let mut clicked = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in &self.rows {
                let on = self.selected == Some(row.id);
                if ui.selectable_label(on, row.title.as_str()).clicked() {
                    clicked = Some(row.id);
                }
                if !row.subtitle.as_str().is_empty() {
                    ui.small(row.subtitle.as_str());
                }
            }
            if self.other_types > 0 {
                ui.separator();
                ui.small(format!("{} {}", OTHER_TYPES_PREFIX, self.other_types));
                ui.small(OTHER_TYPES_HINT);
            }
        });
        if let Some(id) = clicked
            && self.selected != Some(id)
        {
            self.selected = Some(id);
            self.mode = DetailMode::View;
            self.reveal_until = None;
            self.status = None;
            self.copy_note = None;
        }
    }

    /// The central panel.
    fn show_detail(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
        now: Duration,
        io: &mut FieldIo<'_>,
    ) -> Option<Job> {
        let mut job = None;
        if self.save_failed
            && session.is_some_and(Session::is_dirty)
            && let Some(error) = self.save_error
        {
            ui.label(error);
            if ui.button(RETRY_LABEL).clicked() {
                job = Some(Job::Save);
            }
            ui.separator();
        } else if !session.is_some_and(Session::is_dirty) {
            self.save_failed = false;
            self.save_error = None;
        }
        if let Some(status) = self.status {
            ui.label(status);
            ui.separator();
        }
        match &mut self.mode {
            DetailMode::Empty => {
                ui.label(messages::SELECT_OR_ADD);
            }
            DetailMode::Edit(form) => match form.show(ui, io) {
                FormAction::None => {}
                FormAction::Cancel => {
                    self.mode = match self.selected {
                        Some(_) => DetailMode::View,
                        None => DetailMode::Empty,
                    };
                }
                FormAction::Save => job = self.save_form(session),
            },
            DetailMode::View => job = job.or(self.show_item(ui, session, now, io.clipboard)),
        }
        job
    }

    /// Checks the form and turns it into an add or update job. A failed check puts the
    /// values back in the form with its message.
    fn save_form(&mut self, session: Option<&Session<FsStore>>) -> Option<Job> {
        let DetailMode::Edit(mut form) = core::mem::replace(&mut self.mode, DetailMode::Empty)
        else {
            return None;
        };
        let id = form.id;
        let (notes, urls) = id
            .and_then(|id| session.and_then(|s| s.item(id).ok()))
            .and_then(|item| match item.data() {
                ItemData::Login { urls, notes, .. } => Some((
                    SecretText::new(notes.expose().to_owned()),
                    urls.iter()
                        .skip(1)
                        .map(|u| Text::new(u.as_str().to_owned()))
                        .collect::<Vec<_>>(),
                )),
                _ => None,
            })
            .unwrap_or_else(|| (SecretText::new(String::new()), Vec::new()));
        let input = form.take_input(notes, urls);
        drop(form);
        match input.validate() {
            Ok(()) => Some(match id {
                Some(id) => Job::Update(id, input),
                None => Job::Add(input),
            }),
            Err(e) => {
                self.mode =
                    DetailMode::Edit(LoginForm::from_input(id, input, messages::field_error(&e)));
                None
            }
        }
    }

    /// The selected login, read-only, with the Copy button for its password.
    fn show_item(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
        now: Duration,
        clipboard: &mut dyn SecretClipboard,
    ) -> Option<Job> {
        let item = self
            .selected
            .and_then(|id| session.and_then(|s| s.item(id).ok()));
        let Some(item) = item else {
            ui.label(messages::SELECT_OR_ADD);
            return None;
        };
        let ItemData::Login {
            username,
            password,
            urls,
            ..
        } = item.data()
        else {
            ui.label(messages::SELECT_OR_ADD);
            return None;
        };
        ui.heading(item.title());
        ui.add_space(8.0);
        ui.label(format!("Username: {}", username.as_str()));
        if let Some(url) = urls.first() {
            ui.label(format!("Web address: {}", url.as_str()));
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Password:");
            match self.reveal_until {
                Some(until) => {
                    ui.add(
                        egui::Label::new(egui::RichText::new(password.expose()).monospace())
                            .selectable(false),
                    );
                    let left = until.saturating_sub(now);
                    let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
                    ui.label(format!("Visible \u{b7} hides in {secs} s"));
                    if ui.button(HIDE_LABEL).clicked() {
                        self.reveal_until = None;
                    }
                }
                None => {
                    ui.label(DOTS);
                    if ui.button(REVEAL_LABEL).clicked() {
                        self.reveal_until =
                            Some(now + Duration::from_secs(u64::from(REHIDE_PASSWORD_SECS)));
                    }
                }
            }
            // Only through Holm's clipboard (concealed), never egui's `copy_text`.
            if ui.button(COPY_LABEL).clicked() {
                self.copy_note = Some(match clipboard.set_secret(password.expose()) {
                    Ok(()) => messages::COPIED,
                    Err(_) => messages::COPY_FAILED,
                });
            }
        });
        if let Some(note) = self.copy_note {
            ui.label(note);
        }
        ui.add_space(8.0);
        if ui.button(EDIT_LABEL).clicked() {
            self.reveal_until = None;
            self.copy_note = None;
            match LoginForm::from_item(item) {
                Some(form) => {
                    self.status = None;
                    self.mode = DetailMode::Edit(form);
                }
                None => self.status = Some(messages::SECRET_TOO_LONG),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holm_core::clock::SystemClock;

    fn locked_session() -> Session<FsStore> {
        let dir = tempfile::tempdir().unwrap();
        Session::new(
            FsStore::new(dir.path().join("holm.vault")),
            Box::new(SystemClock::new()),
        )
    }

    fn typed() -> ItemInput {
        ItemInput {
            title: Text::new("Example Mail".to_owned()),
            category: None,
            favourite: false,
            data: ItemData::Login {
                username: Text::new("ada@example.com".to_owned()),
                password: SecretText::new("EXAMPLE-new-pass".to_owned()),
                urls: Vec::new(),
                notes: SecretText::new(String::new()),
            },
        }
    }

    fn too_large() -> Result<(), CoreError> {
        Err(CoreError::Vault(VaultError::TooLargeToSave))
    }

    #[test]
    fn too_large_add_keeps_the_typed_form_and_the_message() {
        let session = locked_session();
        let mut view = VaultView::new();
        view.on_done(JobKind::Add, &too_large(), None, Some(typed()), &session);
        assert!(!view.buffers_empty(), "typed values are back in the form");
        assert_eq!(view.secret_char_count(), "EXAMPLE-new-pass".chars().count());
        let DetailMode::Edit(form) = &view.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.error, Some(messages::TOO_LARGE_TO_SAVE));
        assert_eq!(form.id, None);
        assert!(!view.save_failed, "nothing is dirty after an undone change");
    }

    #[test]
    fn too_large_update_keeps_the_typed_form_for_that_item() {
        let session = locked_session();
        let mut view = VaultView::new();
        let id = ItemId::random().unwrap();
        view.selected = Some(id);
        view.on_done(JobKind::Update, &too_large(), None, Some(typed()), &session);
        let DetailMode::Edit(form) = &view.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.id, Some(id));
        assert_eq!(form.error, Some(messages::TOO_LARGE_TO_SAVE));
        assert_eq!(view.secret_char_count(), "EXAMPLE-new-pass".chars().count());
    }
}
