//! `import` and `export`.
//!
//! Import reads the whole file (at most [`MAX_IMPORT_BYTES`]) and parses it before
//! the vault is opened, so a file Holm can't use is refused before any prompt. Rows
//! that can't be imported are reported by number and a fixed reason only, never by
//! their content.
//!
//! Export never writes over anything: an existing path is refused before any prompt,
//! and the file is created new with owner-only permissions.

use std::io::Write;
use std::path::{Path, PathBuf};

use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::export::EXPORT_WARNING;
use holm_core::import::{
    IMPORT_DELETE_SOURCE_WARNING, ImportBatch, ImportFormat, ImportPreview, RowIssue, RowProblem,
};
use holm_core::rules::FieldError;
use holm_core::session::Session;
use holm_core::store::StoreError;
use holm_crypto::MasterPassword;
use holm_platform::fs_store::FsStore;
use holm_platform::private_file::write_new_private_file;
use holm_platform::transfer::{self, TransferError, export_backup, export_plain, refuse_existing};

use crate::Env;
use crate::args::{CONFLICT, ExportArgs, ImportArgs};
use crate::commands::copy::AGAIN_PROMPT;
use crate::commands::write::confirm;
use crate::output::{CliError, read_error as core_read_error};
use crate::term::Terminal;
use crate::vault::{self, MAX_PASSWORD_BYTES};

/// The most row issues `import` lists one by one.
const MAX_LISTED_ISSUES: usize = 20;

/// `n` and the noun, with an `s` unless `n` is 1.
fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn absolute(path: &Path) -> Result<PathBuf, CliError> {
    std::path::absolute(path).map_err(|_| CliError::DirError)
}

/// A read error for an import file. The shared reader's own text talks about the
/// vault file and its limit, so it is never shown.
fn read_error(e: TransferError) -> CliError {
    match e {
        TransferError::NotFound => CliError::ImportFileMissing,
        TransferError::TooLarge => CliError::ImportTooLarge,
        TransferError::NotAFile => CliError::ImportNotAFile,
        TransferError::NoAccess => CliError::ImportNoAccess,
        TransferError::Import(e) => CliError::Import(e),
        _ => CliError::ImportReadFailed,
    }
}

/// The error for a failed [`Session::import`]. Only a save error leaves the items
/// added in memory, so only that is [`CliError::ImportNotSaved`]; an error before
/// any row went in is [`CliError::Failed`].
#[must_use]
pub fn import_error(e: &CoreError) -> CliError {
    match e {
        CoreError::TooManyItems => CliError::ImportTooManyItems,
        CoreError::Vault(VaultError::TooLargeToSave) => CliError::ImportTooLargeToSave,
        CoreError::Store(_) | CoreError::Body(_) | CoreError::Vault(_) => CliError::ImportNotSaved,
        _ => CliError::Failed,
    }
}

/// Why a row was skipped, as fixed text.
fn problem_text(p: RowProblem) -> &'static str {
    match p {
        RowProblem::Field(FieldError::Empty(_)) => "a field that must be filled is empty",
        RowProblem::Field(FieldError::TooLong(_)) => "a field is too long",
        RowProblem::Field(FieldError::ForbiddenChar(_)) => {
            "a field has a character Holm doesn't allow"
        }
        RowProblem::Field(FieldError::TooManyUrls) => "more than 32 web addresses",
        RowProblem::Field(FieldError::Reserved(_)) => "a field holds a reserved value",
        RowProblem::Field(FieldError::TooManyFields) => "An item can have at most 10 custom fields",
        RowProblem::Field(FieldError::BadDate) => "That date is not a real calendar day",
        RowProblem::Field(FieldError::NoSuchIndex) => "That field is not on the item",
        RowProblem::Field(FieldError::BadCodeCount) => "a recovery code list holds 1 to 20 codes",
        RowProblem::UnknownType => "the type isn't one Holm knows",
        RowProblem::MissingAddress => "a crypto address with no address",
        RowProblem::MissingPhrase => "a recovery phrase with no phrase",
        RowProblem::EmptyRow => "the row is empty",
        RowProblem::ExtraFields => "the row has more cells than the header",
        RowProblem::UnusedField => "a secret is in a column this type doesn't use",
        RowProblem::BadFavourite => "the favourite cell isn't true or false",
        RowProblem::BadTimestamp => "a created or updated time Holm can't read",
        RowProblem::BadFieldKind => {
            "The field kind must be text, secret, multiline, date or codes."
        }
        RowProblem::BadDate => "The date must be YYYY-MM-DD.",
        RowProblem::FieldGap => "A custom field skips an earlier slot.",
    }
}

fn print_preview(
    p: &ImportPreview,
    issues: &[RowIssue],
    out: &mut dyn Write,
) -> Result<(), CliError> {
    for (n, one, many) in [
        (p.logins, "login", "logins"),
        (p.crypto, "crypto address", "crypto addresses"),
        (p.phrases, "recovery phrase", "recovery phrases"),
        (p.notes, "secure note", "secure notes"),
    ] {
        if n > 0 {
            writeln!(out, "To add: {}", count(n, one, many))?;
        }
    }
    if p.unmatched_category_rows > 0 {
        let rows = count(p.unmatched_category_rows, "row names", "rows name");
        writeln!(
            out,
            "{rows} a category this vault doesn't have. Those items will have no category."
        )?;
    }
    if p.duplicates > 0 {
        writeln!(
            out,
            "Skipped: {} of items already in the vault or earlier in the file.",
            count(p.duplicates, "duplicate", "duplicates")
        )?;
    }
    if p.otp_ignored > 0 {
        writeln!(
            out,
            "{} won't be stored. Holm doesn't keep one-time-password secrets.",
            count(
                p.otp_ignored,
                "one-time-password secret",
                "one-time-password secrets"
            )
        )?;
    }
    if !issues.is_empty() {
        writeln!(
            out,
            "{} can't be imported:",
            count(issues.len(), "row", "rows")
        )?;
        for issue in issues.iter().take(MAX_LISTED_ISSUES) {
            writeln!(out, "  row {}: {}", issue.row, problem_text(issue.problem))?;
        }
        if issues.len() > MAX_LISTED_ISSUES {
            writeln!(out, "  and {} more", issues.len() - MAX_LISTED_ISSUES)?;
        }
    }
    Ok(())
}

/// `holm import FILE [--format csv|json]`.
///
/// Order: read and parse the file (no prompt yet), open the vault, show what would be
/// added and every row that can't be, ask for `import` at a visible prompt, import,
/// report, and warn that the source file is still in plain text.
///
/// # Errors
/// The `Import…` errors of [`CliError`], [`CliError::NotConfirmed`], the errors of
/// [`vault::open`], or a terminal error. [`CliError::ImportNotSaved`] means the items
/// were added in memory but may not be in the vault file.
pub fn import(
    path: &Path,
    args: &ImportArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let batch = read_import(args)?;
    let mut opened = vault::open(path, env, term, err)?;
    import_into(&mut opened.session, batch, term, out, err)
}

/// Reads and parses an import file. No prompt and no vault yet.
///
/// # Errors
/// The `Import…` read and parse errors of [`CliError`].
pub(crate) fn read_import(args: &ImportArgs) -> Result<ImportBatch, CliError> {
    let file = absolute(&args.file).map_err(|_| CliError::ImportReadFailed)?;
    transfer::read_import(&file, args.format).map_err(read_error)
}

/// The body of [`import`] on an open session, for `holm shell` too: the preview,
/// the `import` prompt, the import and the report.
pub(crate) fn import_into(
    session: &mut Session<FsStore>,
    batch: ImportBatch,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let preview = session
        .preview_import(&batch)
        .map_err(|_| CliError::Failed)?;
    print_preview(&preview, batch.issues(), out)?;
    let to_add = preview.logins + preview.crypto + preview.phrases + preview.notes;
    if to_add == 0 {
        writeln!(out, "Nothing to import.")?;
        return Ok(());
    }
    confirm(
        term,
        &format!("Type import to add {}: ", count(to_add, "item", "items")),
        "import",
    )?;
    let report = session.import(batch).map_err(|e| import_error(&e))?;
    writeln!(out, "Imported {}.", count(report.imported, "item", "items"))?;
    if report.uncategorised > 0 {
        writeln!(
            out,
            "{} no category.",
            count(report.uncategorised, "item has", "items have")
        )?;
    }
    writeln!(err, "{IMPORT_DELETE_SOURCE_WARNING}")?;
    Ok(())
}

/// `holm export FILE` (plain CSV) or `holm export --backup FILE` (an encrypted copy).
///
/// Plain order: refuse an existing path, open, show [`EXPORT_WARNING`], ask for
/// `export` at a visible prompt, ask for the master password again, then write a new
/// owner-only file.
///
/// # Errors
/// [`CliError::FileExists`] before any prompt, [`CliError::NotConfirmed`],
/// [`CliError::WrongPassword`], [`CliError::ExportWriteFailed`],
/// [`CliError::BackupFailed`], the errors of [`vault::open`], or a terminal error.
pub fn export(
    path: &Path,
    args: &ExportArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    if args.backup && args.format.is_some() {
        return Err(CliError::Usage(CONFLICT));
    }
    let file = export_target(args)?;
    let mut opened = vault::open(path, env, term, err)?;
    export_to(
        &mut opened.session,
        &file,
        args.backup,
        args.format,
        term,
        out,
        err,
    )
}

/// The export file as an absolute path. Nothing may be there yet.
///
/// # Errors
/// [`CliError::DirError`] or [`CliError::FileExists`].
pub(crate) fn export_target(args: &ExportArgs) -> Result<PathBuf, CliError> {
    let file = absolute(&args.file)?;
    refuse_existing(&file).map_err(|e| match e {
        TransferError::Exists => CliError::FileExists,
        _ => CliError::ExportWriteFailed,
    })?;
    Ok(file)
}

/// The body of [`export`] on an open session, for `holm shell` too. A plain export
/// still asks for `export` and for the master password again.
pub(crate) fn export_to(
    session: &mut Session<FsStore>,
    file: &Path,
    backup: bool,
    format: Option<ImportFormat>,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    if backup && format.is_some() {
        return Err(CliError::Usage(CONFLICT));
    }
    if backup {
        export_backup(session, file).map_err(|e| match e {
            TransferError::Exists => CliError::FileExists,
            _ => CliError::BackupFailed,
        })?;
        writeln!(
            out,
            "Saved an encrypted backup. It opens with the same master password."
        )?;
        return Ok(());
    }
    writeln!(err, "{EXPORT_WARNING}")?;
    confirm(term, "Type export to continue: ", "export")?;
    let password = vault::master(term.secret(AGAIN_PROMPT, MAX_PASSWORD_BYTES)?);
    let items = match format {
        Some(ImportFormat::Json) => export_json_file(session, &password, file),
        Some(ImportFormat::Csv) | None => export_plain(session, &password, file),
    }
    .map_err(|e| match e {
        TransferError::Core(e) => core_read_error(&e),
        TransferError::Exists => CliError::FileExists,
        _ => CliError::ExportWriteFailed,
    })?;
    drop(password);
    writeln!(
        out,
        "Exported {} to the file. Delete it as soon as you are done.",
        count(items, "item", "items")
    )?;
    Ok(())
}

/// Writes every active item as JSON. The GUI stays on [`export_plain`].
fn export_json_file(
    session: &mut Session<FsStore>,
    password: &MasterPassword,
    dest: &Path,
) -> Result<usize, TransferError> {
    refuse_existing(dest)?;
    let json = session.export_json(password).map_err(TransferError::Core)?;
    let count = session.active_items().map_err(TransferError::Core)?.count();
    write_new_private_file(dest, json.expose()).map_err(|error| match error {
        StoreError::AlreadyExists => TransferError::Exists,
        _ => TransferError::WriteFailed,
    })?;
    Ok(count)
}
