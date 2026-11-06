//! `init`, `list`, `get` and `gen`.

use std::borrow::Cow;
use std::io::Write;
use std::path::Path;

use holm_core::category::name_key;
use holm_core::fields::{FieldKind, FieldValue, codes_left};
use holm_core::generator::{
    PassphraseSpec, PasswordSpec, UsernameSpec, generate_passphrase, generate_password,
    generate_username,
};
use holm_core::item::{ItemData, ItemType};
use holm_core::search::{CategoryFilter, Query, View};
use holm_core::session::Session;
use holm_core::strength;
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use crate::Env;
use crate::args::{CategoryArg, GenArgs, GenKind, GetArgs, ListArgs};
use crate::output::{CliError, clean, create_error, date_text, utc};
use crate::term::Terminal;
use crate::vault::{self, MAX_PASSWORD_BYTES};

/// What every secret field prints as. Never the value, never its length.
pub const HIDDEN: &str = "(hidden)";

/// The short name of an item type, as `list` prints it and `--type` takes it.
#[must_use]
pub fn type_name(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::CryptoAddress => "crypto",
        ItemType::RecoveryPhrase => "phrase",
        ItemType::SecureNote => "note",
    }
}

/// `holm init`: makes a new vault at `path`.
///
/// Order: folder check and instance lock, then refuse an existing vault (before any
/// prompt), then the new password, the strength check (a weak one is refused before
/// the second prompt), the repeat, and [`Session::create`].
///
/// # Errors
/// [`CliError::VaultExists`], [`CliError::WeakPassword`],
/// [`CliError::PasswordsDiffer`], a terminal error, or a create error as fixed text.
pub fn init(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let _lock = vault::lock_folder_for_init(path)?;
    if vault::exists(path) {
        return Err(CliError::VaultExists);
    }
    writeln!(
        out,
        "Choose a master password. Holm can't recover the vault if you forget it."
    )?;
    let password = vault::master(term.secret("New master password: ", MAX_PASSWORD_BYTES)?);
    let report = strength::check(&password);
    if !report.verdict.acceptable {
        // zxcvbn's feedback is fixed text from its tables; it never quotes the input.
        if let Some(warning) = &report.warning {
            writeln!(err, "{}", clean(warning))?;
        }
        for tip in &report.suggestions {
            writeln!(err, "Tip: {}", clean(tip))?;
        }
        return Err(CliError::WeakPassword);
    }
    let repeat = vault::master(term.secret("Repeat the master password: ", MAX_PASSWORD_BYTES)?);
    // Compared in NFC form, as the key derivation sees them.
    if password.to_kdf_bytes().expose() != repeat.to_kdf_bytes().expose() {
        return Err(CliError::PasswordsDiffer);
    }
    drop(repeat);
    let mut session = Session::new(FsStore::new(path), (env.clock)());
    if let Err(e) = session.create(&password, &env.kdf) {
        return Err(create_error(&e, vault::exists(path)));
    }
    session.lock();
    writeln!(out, "Made a new vault.")?;
    Ok(())
}

/// `holm list`: one tab-separated line per item: the first 8 characters of the id,
/// the type, the title and the subtitle (a login's username or first web address, or
/// a crypto address's chain).
///
/// # Errors
/// [`CliError::UnknownCategory`], or [`CliError::Output`].
pub fn list(
    session: &Session<FsStore>,
    args: &ListArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let category = match &args.category {
        None => CategoryFilter::All,
        Some(CategoryArg::Uncategorised) => CategoryFilter::Uncategorised,
        Some(CategoryArg::Named(name)) => {
            let key = name_key(name);
            let categories = session.categories().map_err(|_| CliError::Failed)?;
            let found = categories.iter().find(|c| name_key(c.name()) == key);
            CategoryFilter::Only(found.ok_or(CliError::UnknownCategory)?.id())
        }
    };
    let query = Query {
        text: args
            .search
            .clone()
            .unwrap_or_else(|| Zeroizing::new(String::new())),
        item_type: args.item_type,
        category,
        favourites_only: args.favourites,
        view: if args.trash {
            View::Trash
        } else {
            View::Active
        },
        sort: args.sort,
        expiring_only: args.expiring,
    };
    let hits = session.search(&query).map_err(|_| CliError::Failed)?;
    for hit in hits {
        let hex = hit.id.to_hex();
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            &hex[..8],
            type_name(hit.item_type),
            clean(hit.title),
            clean(hit.subtitle.unwrap_or_default())
        )?;
    }
    Ok(())
}

/// `holm get REF`: the item's public fields, and [`HIDDEN`] for every secret field.
///
/// # Errors
/// [`CliError::Usage`], [`CliError::NotFound`], [`CliError::Ambiguous`], or
/// [`CliError::Output`].
pub fn get(
    session: &Session<FsStore>,
    args: &GetArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let id = vault::resolve_any(session, &args.reference)?;
    let item = session.item(id).map_err(|_| CliError::NotFound)?;
    let category = match item.category() {
        None => None,
        Some(c) => session
            .categories()
            .map_err(|_| CliError::Failed)?
            .iter()
            .find(|cat| cat.id() == c)
            .map(|cat| cat.name()),
    };
    let yes_no = |b: bool| if b { "yes" } else { "no" };

    writeln!(out, "id: {}", id.to_hex())?;
    writeln!(out, "title: {}", clean(item.title()))?;
    writeln!(out, "type: {}", type_name(item.item_type()))?;
    match item.data() {
        ItemData::Login { username, urls, .. } => {
            writeln!(out, "username: {}", clean(username.as_str()))?;
            for url in urls {
                writeln!(out, "url: {}", clean(url.as_str()))?;
            }
            writeln!(out, "password: {HIDDEN}")?;
            writeln!(out, "notes: {HIDDEN}")?;
        }
        ItemData::CryptoAddress { chain, .. } => {
            writeln!(out, "chain: {}", clean(chain.as_str()))?;
            writeln!(out, "address: {HIDDEN}")?;
            writeln!(out, "memo: {HIDDEN}")?;
            writeln!(out, "notes: {HIDDEN}")?;
        }
        ItemData::RecoveryPhrase { .. } => {
            writeln!(out, "phrase: {HIDDEN}")?;
            writeln!(out, "notes: {HIDDEN}")?;
        }
        ItemData::SecureNote { .. } => {
            writeln!(out, "body: {HIDDEN}")?;
        }
    }
    for (index, field) in item.fields().iter().enumerate() {
        let n = index + 1;
        let kind = kind_name(field.kind());
        let shown = shown_field(field.value());
        writeln!(
            out,
            "field {n}: {} ({kind}) = {shown}",
            clean(field.label())
        )?;
        if let Some(date) = field.expiry() {
            writeln!(out, "field {n} expiry: {}", date_text(date))?;
        }
    }
    writeln!(
        out,
        "category: {}",
        category.map_or(Cow::Borrowed("(none)"), clean)
    )?;
    writeln!(out, "favourite: {}", yes_no(item.favourite()))?;
    writeln!(out, "created: {}", utc(item.created()))?;
    writeln!(out, "updated: {}", utc(item.updated()))?;
    match item.trashed() {
        Some(when) => writeln!(out, "in trash: yes, since {}", utc(when))?,
        None => writeln!(out, "in trash: no")?,
    }
    Ok(())
}

fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Text => "text",
        FieldKind::Secret => "secret",
        FieldKind::MultilineSecret => "multiline",
        FieldKind::Date => "date",
        FieldKind::RecoveryCodes => "codes",
    }
}

/// Text and dates are shown. A secret or multiline value stays [`HIDDEN`].
fn shown_field(value: &FieldValue) -> Cow<'_, str> {
    match value {
        FieldValue::Text(text) => clean(text.as_str()),
        FieldValue::Date(date) => Cow::Owned(date_text(*date)),
        FieldValue::RecoveryCodes(codes) => {
            let (left, total) = codes_left(codes);
            Cow::Owned(format!("{HIDDEN} ({left} of {total} left)"))
        }
        FieldValue::Secret(_) | FieldValue::MultilineSecret(_) => Cow::Borrowed(HIDDEN),
    }
}

/// `holm gen [password|passphrase|username]`: one new value from the default spec,
/// on stdout. No vault is opened.
///
/// # Errors
/// [`CliError::GenerateFailed`], or [`CliError::Output`].
pub fn gen_value(args: &GenArgs, out: &mut dyn Write) -> Result<(), CliError> {
    match args.kind {
        GenKind::Password => {
            let value =
                generate_password(&PasswordSpec::DEFAULT).map_err(|_| CliError::GenerateFailed)?;
            write_generated(out, value.expose())?;
        }
        GenKind::Passphrase => {
            let value = generate_passphrase(&PassphraseSpec::DEFAULT)
                .map_err(|_| CliError::GenerateFailed)?;
            write_generated(out, value.expose())?;
        }
        GenKind::Username => {
            let value =
                generate_username(&UsernameSpec::DEFAULT).map_err(|_| CliError::GenerateFailed)?;
            write_generated(out, value.as_str())?;
        }
    }
    Ok(())
}

/// Writes the value and newline from one wiping allocation, then flushes stdout.
fn write_generated(out: &mut dyn Write, value: &str) -> Result<(), CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'\n');
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}
