//! The open vault: the item list on the left, the selected item (or the login form) on
//! the right.
//!
//! The rows are built once from the session and owned here, so a frame never walks the
//! vault. All vault work (add, update, save) leaves as a [`Job`] for the worker thread,
//! and a lock request leaves as a [`VaultAction`] for the app. Locking drops this view,
//! so its rows, any open form (whose secret buffer wipes on drop) and the item view
//! (its reveal state, phrase gate and revealed phrase) all go with it.

use core::fmt;
use std::time::Duration;

use eframe::egui;
use egui::TextBuffer as _;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::item::{ItemData, ItemId, ItemInput, ItemType};
use holm_core::search::Query;
use holm_core::session::Session;
use holm_core::text::{SecretText, Text};
use holm_core::throttle::ThrottleStatus;
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use super::FieldIo;
use super::item_view::{ItemAction, ItemView, show_item};
use super::login_form::{FormAction, LineBuf, LoginForm, line_field};
use super::transfer::{CHOOSING_FILE, Transfer, TransferAction};
use crate::file_dialog::DialogKind;
use crate::messages;
use crate::rows::{ItemRow, build_rows};
use crate::worker::{Job, JobKind, TransferResult};
use holm_platform::transfer::TransferError;

/// Label of the new-login button.
pub(crate) const NEW_LABEL: &str = "New login";
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
    /// Open the native file dialog now: the placeholder frame has been painted.
    ChooseFile(DialogKind),
}

/// What the right-hand side shows.
enum DetailMode {
    /// Nothing selected.
    Empty,
    /// The selected item, read-only.
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
    /// Logins and other items in the whole active vault, whatever the search says.
    totals: (usize, usize),
    /// The selected item.
    selected: Option<ItemId>,
    /// The right-hand side.
    mode: DetailMode,
    /// The selected item's reveal state. Replaced (and so wiped) on every selection,
    /// on Edit and on New login.
    item: ItemView,
    /// The fixed line shown above the detail, if any.
    status: Option<&'static str>,
    /// Whether the last write failed and left changes unsaved in memory.
    save_failed: bool,
    /// The fixed line for that failed write. Kept apart from `status` so navigation and
    /// other messages never hide it while the session is dirty.
    save_error: Option<&'static str>,
    /// Whether the unsaved-changes dialog of a manual lock is open.
    lock_dialog: bool,
    /// The search box. Wiped when the view drops on lock.
    search: LineBuf,
    /// The search text the rows were built with.
    searched: Zeroizing<String>,
    /// The open import or export screen, if any.
    transfer: Option<Transfer>,
    /// Whether the session had unsaved changes when the running job started. A dirty
    /// session after an import only means rows went in if it was clean before.
    dirty_before_job: bool,
}

/// Whether a failed import left nothing added: the vault was too big to save, or the
/// batch had too many items.
fn import_rolled_back(e: &CoreError) -> bool {
    matches!(
        e,
        CoreError::Vault(VaultError::TooLargeToSave) | CoreError::TooManyItems
    )
}

impl fmt::Debug for VaultView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultView")
            .field("rows", &self.rows.len())
            .field("revealed", &self.item.is_revealed())
            .finish_non_exhaustive()
    }
}

impl VaultView {
    /// A view whose rows are built on the first draw.
    pub(crate) fn new() -> VaultView {
        VaultView {
            rows: Vec::new(),
            rows_stale: true,
            totals: (0, 0),
            selected: None,
            mode: DetailMode::Empty,
            item: ItemView::new(),
            status: None,
            save_failed: false,
            save_error: None,
            lock_dialog: false,
            search: LineBuf::new(),
            searched: Zeroizing::new(String::new()),
            transfer: None,
            dirty_before_job: false,
        }
    }

    /// Remembers whether the session was dirty as a job started.
    pub(crate) fn note_job_start(&mut self, dirty: bool) {
        self.dirty_before_job = dirty;
    }

    /// Takes the answer of a transfer job. Called after `on_done`. `session` is the
    /// session the job gave back: a dirty one after a failed import means the rows went
    /// in and only the save failed.
    pub(crate) fn on_transfer_done(
        &mut self,
        kind: JobKind,
        result: Option<TransferResult>,
        session: &Session<FsStore>,
    ) {
        if !kind.is_transfer() {
            return;
        }
        // Dirty now but not before: this job put changes in memory.
        let dirty = session.is_dirty() && !self.dirty_before_job;
        if result.is_none() {
            // The worker came back without an answer: do not leave the screen busy.
            self.transfer = None;
            self.status = Some(messages::WORKER_LOST);
            return;
        }
        match &result {
            Some(TransferResult::Imported(_)) => self.rows_stale = true,
            Some(TransferResult::Failed(TransferError::Core(e)))
                if kind == JobKind::Import && dirty && !import_rolled_back(e) =>
            {
                // The rows are in memory: list them and show the failed-save banner.
                self.rows_stale = true;
                self.save_error = Some(messages::save_error(e));
                self.save_failed = true;
            }
            _ => {}
        }
        if let Some(result) = result
            && let Some(transfer) = &mut self.transfer
        {
            transfer.on_result(result, dirty);
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
        form && self.item.buffers_empty()
            && self.transfer.as_ref().is_none_or(Transfer::buffers_empty)
    }

    /// Characters held by the form's secret buffer (0 when no form is open).
    pub(crate) fn secret_char_count(&self) -> usize {
        let form = match &self.mode {
            DetailMode::Edit(form) => form.password.char_count(),
            DetailMode::Empty | DetailMode::View => 0,
        };
        form + self.item.secret_char_count()
            + self
                .transfer
                .as_ref()
                .map_or(0, Transfer::secret_char_count)
    }

    /// Hides a revealed field when its time is up or the window lost focus.
    pub(crate) fn tick(&mut self, now: Duration, focused: bool) {
        self.item.tick(now, focused);
    }

    /// Takes the worker's answer to a phrase check. The item view stays; `now` is the
    /// UI clock, for the phrase's timer.
    pub(crate) fn on_phrase_done(
        &mut self,
        result: &Result<(), CoreError>,
        phrase: Option<SecretText>,
        now: Duration,
    ) {
        self.item.on_phrase_done(result, phrase, now);
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
        if kind == JobKind::RevealPhrase {
            return;
        }
        self.rows_stale = true;
        self.item = ItemView::new();
        self.status = None;
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
                | JobKind::Export
                | JobKind::Backup
                | JobKind::RevealPhrase,
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
        throttle: &ThrottleStatus,
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
            self.rows = match session.search(&query) {
                Ok(found) => build_rows(&found),
                Err(_) => Vec::new(),
            };
            self.totals = if self.searched.is_empty() {
                tally(&self.rows)
            } else {
                match session.search(&Query::default()) {
                    Ok(all) => tally(&build_rows(&all)),
                    Err(_) => (0, 0),
                }
            };
            self.rows_stale = false;
        }
        let mut action = None;
        egui::Panel::top("vault-top").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button(LOCK_LABEL).clicked() {
                    action = Some(VaultAction::Lock);
                }
                let idle = self.transfer.is_none();
                if ui
                    .add_enabled(idle, egui::Button::new(IMPORT_OPEN_LABEL))
                    .clicked()
                {
                    // The detail pane goes away: hide what it showed.
                    self.item = ItemView::new();
                    self.transfer = Some(Transfer::import());
                }
                if ui
                    .add_enabled(idle, egui::Button::new(EXPORT_OPEN_LABEL))
                    .clicked()
                {
                    // The detail pane goes away: hide what it showed.
                    self.item = ItemView::new();
                    self.transfer = Some(Transfer::export());
                }
                if ui
                    .add_enabled(idle, egui::Button::new(messages::BACKUP_BUTTON))
                    .clicked()
                {
                    // The detail pane goes away: hide what it showed.
                    self.item = ItemView::new();
                    self.transfer = Some(Transfer::backup());
                }
                if ui.button(NEW_LABEL).clicked() {
                    self.start_new_login();
                }
            });
        });
        if let Some(left) = idle_left {
            egui::Panel::bottom("vault-status").show(ui, |ui| {
                let amber = ui.visuals().warn_fg_color;
                ui.colored_label(amber, messages::idle_warning(left));
            });
        }
        let choosing = self.transfer.as_ref().is_some_and(Transfer::is_choosing);
        egui::Panel::left("vault-list")
            .resizable(false)
            .exact_size(260.0)
            .show(ui, |ui| {
                if choosing {
                    ui.label(CHOOSING_FILE);
                } else {
                    self.show_list(ui, io);
                }
            });
        let job = egui::CentralPanel::default()
            .show(ui, |ui| {
                if choosing {
                    ui.label(CHOOSING_FILE);
                    None
                } else if self.transfer.is_some() {
                    let retry = self.show_save_banner(ui, session);
                    self.show_transfer(ui, throttle, io).or(retry)
                } else {
                    self.show_detail(ui, session, now, throttle, io)
                }
            })
            .inner;
        if self.lock_dialog {
            action = self.show_lock_dialog(ui.ctx()).or(action);
        }
        // The placeholder is on screen; a later frame opens the dialog.
        let dialog = self
            .transfer
            .as_ref()
            .and_then(|t| t.dialog_due(ui.ctx().cumulative_frame_nr()))
            .map(VaultAction::ChooseFile);
        action.or(dialog).or(job.map(VaultAction::Job))
    }

    /// Takes the file dialog's answer (`None` when cancelled).
    pub(crate) fn finish_choice(&mut self, path: Option<std::path::PathBuf>) {
        if let Some(transfer) = &mut self.transfer {
            transfer.finish_choice(path);
        }
    }

    /// The import or export screen in place of the detail pane.
    fn show_transfer(
        &mut self,
        ui: &mut egui::Ui,
        throttle: &ThrottleStatus,
        io: &mut FieldIo<'_>,
    ) -> Option<Job> {
        let transfer = self.transfer.as_mut()?;
        match transfer.show(ui, throttle, io)? {
            TransferAction::Job(job) => Some(job),
            TransferAction::Close => {
                self.transfer = None;
                None
            }
            TransferAction::Choose(_) => None,
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

    /// Opens a blank login form in the detail pane.
    fn start_new_login(&mut self) {
        self.selected = None;
        self.item = ItemView::new();
        self.status = None;
        self.mode = DetailMode::Edit(LoginForm::new_blank());
    }

    fn show_list(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) {
        if line_field(ui, io, SEARCH_LABEL, &mut self.search) {
            self.rows_stale = true;
        }
        ui.separator();
        // The footer sits below the list, outside the scroll area, so the area is
        // bounded by the panel and scrolls instead of growing with its rows.
        let shown = (!self.searched.is_empty()).then_some(self.rows.len());
        egui::Panel::bottom("vault-list-footer")
            .show_separator_line(true)
            .show(ui, |ui| {
                ui.label(count_line(self.totals.0, self.totals.1, shown));
            });
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .id_salt("item-list")
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .show(ui, |ui| {
                for row in &self.rows {
                    let on = self.selected == Some(row.id);
                    if ui.selectable_label(on, row.title.as_str()).clicked() {
                        clicked = Some(row.id);
                    }
                    if !row.subtitle.as_str().is_empty() {
                        ui.small(row.subtitle.as_str());
                    }
                }
            });
        if let Some(id) = clicked
            && self.selected != Some(id)
        {
            self.selected = Some(id);
            self.mode = DetailMode::View;
            // Leaving an item hides and wipes whatever it showed, and closes its gate.
            self.item = ItemView::new();
            self.status = None;
        }
    }

    /// The central panel.
    /// The failed-save banner with its retry button, above whatever the central panel
    /// shows. Visible while the session is dirty, so no pane hides unsaved changes. Clears
    /// itself once the session is clean. While a job holds the session it stays as it is.
    fn show_save_banner(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
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
        } else if session.is_some_and(|s| !s.is_dirty()) {
            self.save_failed = false;
            self.save_error = None;
        }
        job
    }

    fn show_detail(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
        now: Duration,
        throttle: &ThrottleStatus,
        io: &mut FieldIo<'_>,
    ) -> Option<Job> {
        let mut job = None;
        if let Some(save) = self.show_save_banner(ui, session) {
            job = Some(save);
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
            DetailMode::View => job = job.or(self.show_item(ui, session, now, throttle, io)),
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

    /// Sets or clears the line under the Copy buttons (the app's clipboard clear
    /// reports through it).
    pub(crate) fn set_copy_note(&mut self, note: Option<String>) {
        self.item.set_copy_note(note);
    }

    /// The selected item, read-only (see [`show_item`]). Edit opens the login form and
    /// drops the item view, so whatever showed hides and wipes.
    fn show_item(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session<FsStore>>,
        now: Duration,
        throttle: &ThrottleStatus,
        io: &mut FieldIo<'_>,
    ) -> Option<Job> {
        let item = self
            .selected
            .and_then(|id| session.and_then(|s| s.item(id).ok()));
        let Some(item) = item else {
            ui.label(messages::SELECT_OR_ADD);
            return None;
        };
        match show_item(ui, item, &mut self.item, now, throttle, io) {
            ItemAction::None => None,
            ItemAction::Job(job) => Some(job),
            ItemAction::Edit => {
                self.item = ItemView::new();
                match LoginForm::from_item(item) {
                    Some(form) => {
                        self.status = None;
                        self.mode = DetailMode::Edit(form);
                    }
                    None => self.status = Some(messages::SECRET_TOO_LONG),
                }
                None
            }
        }
    }
}

/// Logins and all other items among `rows`.
fn tally(rows: &[ItemRow]) -> (usize, usize) {
    let logins = rows.iter().filter(|r| r.kind == ItemType::Login).count();
    (logins, rows.len() - logins)
}

/// The list footer: `12 logins, 3 other items`, plus `, 4 shown` while a search is on.
/// The counts are the whole vault's; only `shown` follows the search.
#[must_use]
pub(crate) fn count_line(logins: usize, others: usize, shown: Option<usize>) -> String {
    let mut line = format!(
        "{}, {}",
        messages::login_count(logins),
        messages::other_count(others)
    );
    if let Some(n) = shown {
        line.push_str(&messages::shown_count(n));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_line_plurals_and_shown() {
        assert_eq!(count_line(12, 3, None), "12 logins, 3 other items");
        assert_eq!(count_line(1, 1, None), "1 login, 1 other item");
        assert_eq!(
            count_line(0, 0, Some(0)),
            "0 logins, 0 other items, 0 shown"
        );
        assert_eq!(
            count_line(2, 2, Some(4)),
            "2 logins, 2 other items, 4 shown"
        );
    }
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
