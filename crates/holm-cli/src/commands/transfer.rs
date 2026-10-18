//! `import` and `export`.
//!
//! Import reads the whole file (at most [`MAX_IMPORT_BYTES`]) and parses it before
//! the vault is opened, so a file Holm can't use is refused before any prompt. Rows
//! that can't be imported are reported by number and a fixed reason only, never by
//! their content.
//!
//! Export never writes over anything: an existing path is refused before any prompt,
//! and the file is created new with owner-only permissions.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::export::EXPORT_WARNING;
use holm_core::import::{
    IMPORT_DELETE_SOURCE_WARNING, ImportFormat, ImportPreview, MAX_IMPORT_BYTES, RowIssue,
    RowProblem, parse,
};
use holm_core::rules::FieldError;
use holm_core::store::StoreError;
use holm_platform::fs_store::FsStore;
use holm_platform::private_file::{read_capped, write_new_private_file};

use crate::Env;
use crate::args::{ExportArgs, ImportArgs};
use crate::commands::copy::AGAIN_PROMPT;
use crate::commands::write::confirm;
use crate::output::{CliError, write_error};
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

/// A read error for an import file. `read_capped`'s own text talks about the vault
/// file and its limit, so it is never shown.
fn read_error(e: &StoreError) -> CliError {
    match e {
        StoreError::Io(ErrorKind::NotFound) => CliError::ImportFileMissing,
        StoreError::NotARegularFile => CliError::ImportNotAFile,
        StoreError::TooLarge => CliError::ImportTooLarge,
        StoreError::Io(ErrorKind::PermissionDenied) => CliError::ImportNoAccess,
        _ => CliError::ImportReadFailed,
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
        RowProblem::UnknownType => "the type isn't one Holm knows",
        RowProblem::MissingAddress => "a crypto address with no address",
        RowProblem::MissingPhrase => "a recovery phrase with no phrase",
        RowProblem::EmptyRow => "the row is empty",
        RowProblem::ExtraFields => "the row has more cells than the header",
        RowProblem::UnusedField => "a secret is in a column this type doesn't use",
        RowProblem::BadFavourite => "the favourite cell isn't true or false",
        RowProblem::BadTimestamp => "a created or updated time Holm can't read",
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
    let file = absolute(&args.file).map_err(|_| CliError::ImportReadFailed)?;
    let format = args.format.unwrap_or_else(|| {
        let json = file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        if json {
            ImportFormat::Json
        } else {
            ImportFormat::Csv
        }
    });
    let bytes = read_capped(&file, MAX_IMPORT_BYTES).map_err(|e| read_error(&e))?;
    let batch = parse(&bytes, format).map_err(CliError::Import)?;
    drop(bytes);

    let mut opened = vault::open(path, env, term, err)?;
    let session = &mut opened.session;
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
    let report = match session.import(batch) {
        Ok(r) => r,
        Err(CoreError::TooManyItems) => return Err(CliError::ImportTooManyItems),
        Err(CoreError::Vault(VaultError::TooLargeToSave)) => {
            return Err(CliError::ImportTooLargeToSave);
        }
        // Any other save error leaves the items in memory, unsaved.
        Err(_) => return Err(CliError::ImportNotSaved),
    };
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
    let file = absolute(&args.file)?;
    if vault::exists(&file) {
        return Err(CliError::FileExists);
    }
    let mut opened = vault::open(path, env, term, err)?;
    let session = &mut opened.session;
    if args.backup {
        session
            .save_backup(&mut FsStore::new(&file))
            .map_err(|e| match e {
                CoreError::VaultExists | CoreError::Store(StoreError::AlreadyExists) => {
                    CliError::FileExists
                }
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
    let csv = session.export_csv(&password).map_err(|e| write_error(&e))?;
    drop(password);
    let items = session
        .active_items()
        .map_err(|_| CliError::Failed)?
        .count();
    write_new_private_file(&file, csv.expose()).map_err(|e| match e {
        StoreError::AlreadyExists => CliError::FileExists,
        _ => CliError::ExportWriteFailed,
    })?;
    drop(csv);
    writeln!(
        out,
        "Exported {} to the file. Delete it as soon as you are done.",
        count(items, "item", "items")
    )?;
    Ok(())
}
