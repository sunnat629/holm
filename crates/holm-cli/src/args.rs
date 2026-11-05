//! The command line, parsed by hand: `holm [--vault PATH] <command> [flags]`.
//!
//! No framework: the arguments are a slice of `OsString`s, matched as slices. Every
//! error is a [`UsageError`] with fixed text, so an argument (which could be a
//! secret typed in the wrong place) is never echoed back.
//!
//! Passwords are never taken from the command line (spec section 8, item 10). Before
//! anything else, [`parse`] refuses any flag that looks like a password flag, such as
//! `--password`, `--pass=…`, `--master` or `-p`, wherever it appears.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

use holm_core::fields::{CalendarDate, FieldKind, FieldPreset, parse_date};
use holm_core::import::ImportFormat;
use holm_core::item::ItemType;
use holm_core::rules::MAX_CUSTOM_FIELDS;
use holm_core::search::Sort;
use zeroize::Zeroizing;

/// A command line Holm can't use. The text is fixed and never holds an argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageError(pub &'static str);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A password flag was given.
pub const PASSWORD_FLAG: UsageError = UsageError(
    "Passwords are only typed at the prompt, never given on the command line. Holm asks for them when it needs them.",
);
/// The first word is not a command.
pub const UNKNOWN_COMMAND: UsageError = UsageError("That is not a Holm command.");
/// A flag the command does not know.
pub const UNKNOWN_FLAG: UsageError = UsageError("That command has no such option.");
/// A flag that needs a value came last.
pub const MISSING_VALUE: UsageError = UsageError("An option is missing its value.");
/// A flag given twice.
pub const REPEATED_FLAG: UsageError = UsageError("An option is given more than once.");
/// More words than the command takes.
pub const TOO_MANY: UsageError = UsageError("That command got more words than it takes.");
/// An argument that is not valid Unicode.
pub const NOT_TEXT: UsageError = UsageError("An argument is not valid text.");
/// `get` without a reference.
pub const MISSING_REF: UsageError =
    UsageError("Give the item's id, or its first 6 or more characters.");
/// A reference that is not 6 to 32 lowercase hex digits.
pub const BAD_REF: UsageError =
    UsageError("An item id is 6 to 32 characters from 0-9 and a-f, as `holm list` shows it.");
/// `--type` with an unknown value.
pub const BAD_TYPE: UsageError = UsageError("The type must be login, crypto, phrase or note.");
/// `--sort` with an unknown value.
pub const BAD_SORT: UsageError = UsageError("The sort must be title, updated or created.");
/// `gen` with an unknown kind.
pub const BAD_GEN: UsageError = UsageError("Generate a password, a passphrase or a username.");
/// `--category` together with `--uncategorised`.
pub const CATEGORY_CONFLICT: UsageError =
    UsageError("Choose either --category or --uncategorised, not both.");
/// `--vault` with an empty path.
pub const EMPTY_VAULT: UsageError = UsageError("The vault path is empty.");
/// `add` without a type.
pub const MISSING_ADD_TYPE: UsageError =
    UsageError("Say what to add: login, crypto, phrase or note.");
/// `add` without `--title`.
pub const MISSING_TITLE: UsageError = UsageError("Give the item a title with --title.");
/// An `add` option that the chosen type does not take.
pub const WRONG_TYPE_OPTION: UsageError = UsageError("That option doesn't fit this type of item.");
/// `edit` with nothing to change.
pub const NOTHING_TO_CHANGE: UsageError = UsageError("Say what to change.");
/// Two options that contradict each other.
pub const CONFLICT: UsageError = UsageError("Two of those options contradict each other.");
/// `--copy` with an unknown field.
pub const BAD_FIELD: UsageError = UsageError(
    "Copy one of: password, username, url, address, memo, notes, body, phrase or field=N (N from 1 to 10).",
);
/// `import` or `export` without a file.
pub const MISSING_FILE: UsageError = UsageError("Give the file's path.");
/// `--format` with an unknown value.
pub const BAD_FORMAT: UsageError = UsageError("The format must be csv or json.");
/// A secret or multiline `--value` was given on the command line.
pub const SECRET_ON_COMMAND_LINE: UsageError =
    UsageError("A secret is typed at the prompt, not on the command line.");
/// `--preset` with an unknown name.
pub const BAD_PRESET: UsageError = UsageError(
    "The preset must be email, cloudflare, github, server, database, aws, api-key, wifi, bank-card or custom.",
);
/// `--kind` with an unknown value.
pub const BAD_KIND: UsageError = UsageError("The kind must be text, secret, multiline or date.");
/// A date that is not `YYYY-MM-DD`.
pub const BAD_DATE: UsageError = UsageError("The date must be YYYY-MM-DD.");
/// A custom-field position that is not 1 through 10.
pub const BAD_POSITION: UsageError = UsageError("The field number must be from 1 to 10.");

/// A parsed command line.
pub struct Invocation {
    /// The vault file from `--vault`, if given.
    pub vault: Option<PathBuf>,
    /// What to do.
    pub command: Command,
}

impl fmt::Debug for Invocation {
    // Hand-written: names only, never a path or a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invocation")
            .field("vault_given", &self.vault.is_some())
            .field("command", &self.command)
            .finish()
    }
}

/// One of the commands in spec section 8, item 10, plus help and version.
pub enum Command {
    /// `holm help`, `--help`, `-h`, or no command at all.
    Help,
    /// `holm version`, `--version`, `-V`.
    Version,
    /// `holm init`: make a new vault.
    Init,
    /// `holm list`: one line per item.
    List(ListArgs),
    /// `holm get REF`: one item's public fields.
    Get(GetArgs),
    /// `holm gen [KIND] [--copy]`: a new random value; no vault.
    Gen(GenArgs),
    /// `holm add TYPE --title T …`: a new item.
    Add(AddArgs),
    /// `holm edit REF …`: change an item.
    Edit(EditArgs),
    /// `holm rm [--forever] REF`: to the Trash, or out of it for good.
    Rm(RmArgs),
    /// `holm restore REF`: take a trashed item out of the Trash.
    Restore(RefArgs),
    /// `holm empty-trash`: delete everything in the Trash for good.
    EmptyTrash,
    /// `holm passwd`: change the master password.
    Passwd,
    /// `holm import FILE [--format csv|json]`.
    Import(ImportArgs),
    /// `holm export [--backup] FILE`.
    Export(ExportArgs),
    /// `holm shell`: one unlocked session for many commands.
    Shell,
}

impl fmt::Debug for Command {
    // Hand-written: the command's name only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Command::Help => "help",
            Command::Version => "version",
            Command::Init => "init",
            Command::List(_) => "list",
            Command::Get(_) => "get",
            Command::Gen(_) => "gen",
            Command::Add(_) => "add",
            Command::Edit(_) => "edit",
            Command::Rm(_) => "rm",
            Command::Restore(_) => "restore",
            Command::EmptyTrash => "empty-trash",
            Command::Passwd => "passwd",
            Command::Import(_) => "import",
            Command::Export(_) => "export",
            Command::Shell => "shell",
        };
        f.write_str(name)
    }
}

/// Which items `list` shows.
#[derive(Clone, Default)]
pub struct ListArgs {
    /// `--search TEXT`.
    pub search: Option<Zeroizing<String>>,
    /// `--type`.
    pub item_type: Option<ItemType>,
    /// `--category NAME` or `--uncategorised`.
    pub category: Option<CategoryArg>,
    /// `--favourites`.
    pub favourites: bool,
    /// `--trash`: the Trash instead of the active items.
    pub trash: bool,
    /// `--expiring`: only items whose soonest reminder is inside the window.
    pub expiring: bool,
    /// `--sort`; title order when not given.
    pub sort: Sort,
}

/// The category filter as typed.
#[derive(Clone, PartialEq, Eq)]
pub enum CategoryArg {
    /// `--category NAME`, matched by the category's name key.
    Named(Zeroizing<String>),
    /// `--uncategorised`.
    Uncategorised,
}

/// `get`'s reference, and the field to copy instead of printing the item.
#[derive(Clone)]
pub struct GetArgs {
    /// 6 to 32 lowercase hex digits, checked by [`parse`].
    pub reference: String,
    /// `--copy FIELD`.
    pub copy: Option<CopyField>,
}

/// The field `--copy` puts on the clipboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyField {
    /// A login's password.
    Password,
    /// A login's username.
    Username,
    /// A login's first web address.
    Url,
    /// A crypto item's address.
    Address,
    /// A crypto item's memo.
    Memo,
    /// The notes of a login, crypto item or recovery phrase.
    Notes,
    /// A secure note's body.
    Body,
    /// A recovery phrase (asks for the master password again).
    Phrase,
    /// A custom field. The `u8` is a 0-based index: `field=1` is `Custom(0)`.
    Custom(u8),
}

/// What `gen` makes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GenKind {
    /// A random password (the default).
    #[default]
    Password,
    /// A word passphrase.
    Passphrase,
    /// A username.
    Username,
}

/// `gen`'s arguments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenArgs {
    /// What to make.
    pub kind: GenKind,
    /// `--copy`: copy the value instead of printing it.
    pub copy: bool,
}

/// `add`'s arguments. Only public fields come from the command line; every secret is
/// asked for at a hidden prompt.
pub struct AddArgs {
    /// The item type.
    pub item_type: ItemType,
    /// `--title`.
    pub title: Zeroizing<String>,
    /// `--username` (login).
    pub username: Option<Zeroizing<String>>,
    /// `--url`, in order (login).
    pub urls: Vec<Zeroizing<String>>,
    /// `--chain` (crypto).
    pub chain: Option<Zeroizing<String>>,
    /// `--category NAME`.
    pub category: Option<Zeroizing<String>>,
    /// `--favourite`.
    pub favourite: bool,
    /// `--generate`: a password from the vault's generator settings (login).
    pub generate: bool,
    /// `--with-notes`: ask for notes too (not a secure note).
    pub with_notes: bool,
    /// `--preset`: labels and kinds only. Values stay empty. Date rows are omitted.
    pub preset: Option<FieldPreset>,
}

impl fmt::Debug for AddArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddArgs")
            .field("item_type", &self.item_type)
            .field("title_len", &self.title.len())
            .field("username_len", &self.username.as_ref().map(|s| s.len()))
            .field("url_count", &self.urls.len())
            .field("chain_len", &self.chain.as_ref().map(|s| s.len()))
            .field("category_len", &self.category.as_ref().map(|s| s.len()))
            .field("favourite", &self.favourite)
            .field("generate", &self.generate)
            .field("with_notes", &self.with_notes)
            .field("preset", &self.preset)
            .finish()
    }
}

/// What one `edit` does to the custom-field list. No variant holds a secret.
#[derive(Clone, PartialEq, Eq)]
pub enum FieldEdit {
    /// No custom-field change.
    None,
    /// `--field-add`. The value is not here: a secret is prompted, and a text or
    /// date value lives in [`EditArgs::field_value`].
    Add {
        /// The label, as typed. `Debug` prints its length only.
        label: String,
        /// `--kind`.
        kind: FieldKind,
        /// `--expiry`, if given.
        expiry: Option<CalendarDate>,
    },
    /// `--field-remove`. `position` is 1-based.
    Remove {
        /// The field number as typed, from 1.
        position: u8,
    },
    /// `--field-move` / `--to`. Both numbers are 1-based.
    Move {
        /// The field number to move.
        from: u8,
        /// Where it should land.
        to: u8,
    },
    /// `--field-set`. The value rule matches [`FieldEdit::Add`].
    Set {
        /// The field number as typed, from 1.
        position: u8,
        /// What to do with the reminder.
        expiry: ExpiryEdit,
    },
}

impl fmt::Debug for FieldEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldEdit::None => f.write_str("None"),
            FieldEdit::Add {
                label,
                kind,
                expiry,
            } => f
                .debug_struct("Add")
                .field("label_len", &label.len())
                .field("kind", kind)
                .field("expiry", expiry)
                .finish(),
            FieldEdit::Remove { position } => f
                .debug_struct("Remove")
                .field("position", position)
                .finish(),
            FieldEdit::Move { from, to } => f
                .debug_struct("Move")
                .field("from", from)
                .field("to", to)
                .finish(),
            FieldEdit::Set { position, expiry } => f
                .debug_struct("Set")
                .field("position", position)
                .field("expiry", expiry)
                .finish(),
        }
    }
}

/// How `--field-set` treats the reminder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryEdit {
    /// No `--expiry` and no `--clear-expiry`.
    Unchanged,
    /// `--clear-expiry`.
    Clear,
    /// `--expiry YYYY-MM-DD`.
    Set(CalendarDate),
}

/// A new login password for `edit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewPassword {
    /// `--new-password`: typed twice at hidden prompts.
    Typed,
    /// `--generate`: from the vault's generator settings.
    Generate,
}

/// `edit`'s arguments. Anything not given stays as it is.
pub struct EditArgs {
    /// The item's reference.
    pub reference: Zeroizing<String>,
    /// `--title`.
    pub title: Option<Zeroizing<String>>,
    /// `--username` (login).
    pub username: Option<Zeroizing<String>>,
    /// `--url`, appended (login).
    pub urls: Vec<Zeroizing<String>>,
    /// `--clear-urls`: drop the stored web addresses first (login).
    pub clear_urls: bool,
    /// `--category NAME` or `--uncategorised`.
    pub category: Option<CategoryArg>,
    /// `--favourite` or `--no-favourite`.
    pub favourite: Option<bool>,
    /// `--new-password` or `--generate` (login).
    pub new_password: Option<NewPassword>,
    /// `--new-notes`: ask for new notes (a secure note: a new body).
    pub new_notes: bool,
    /// The custom-field change, if any.
    pub fields: FieldEdit,
    /// `--value` for a text or date field. A secret never lands here: that flag
    /// is refused while parsing when the kind is already secret, and a
    /// `--field-set` value is wiped unused when the stored kind is secret.
    pub field_value: Option<Zeroizing<String>>,
}

impl fmt::Debug for EditArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let named_len = match &self.category {
            Some(CategoryArg::Named(name)) => Some(name.len()),
            _ => None,
        };
        f.debug_struct("EditArgs")
            .field("reference_len", &self.reference.len())
            .field("title_len", &self.title.as_ref().map(|s| s.len()))
            .field("username_len", &self.username.as_ref().map(|s| s.len()))
            .field("url_count", &self.urls.len())
            .field("clear_urls", &self.clear_urls)
            .field("category_len", &named_len)
            .field(
                "uncategorised",
                &matches!(self.category, Some(CategoryArg::Uncategorised)),
            )
            .field("favourite", &self.favourite)
            .field("new_password", &self.new_password)
            .field("new_notes", &self.new_notes)
            .field("fields", &self.fields)
            .field("value_len", &self.field_value.as_ref().map(|s| s.len()))
            .finish()
    }
}

/// The arguments of a command that takes one item reference.
pub struct RefArgs {
    /// The item's reference.
    pub reference: String,
}

/// `rm`'s arguments.
pub struct RmArgs {
    /// The item's reference.
    pub reference: String,
    /// `--forever`: delete a trashed item for good.
    pub forever: bool,
}

/// `import`'s arguments.
pub struct ImportArgs {
    /// The file to read.
    pub file: PathBuf,
    /// `--format`; otherwise `.json` means JSON and anything else CSV.
    pub format: Option<ImportFormat>,
}

/// `export`'s arguments.
pub struct ExportArgs {
    /// The new file to write.
    pub file: PathBuf,
    /// `--backup`: an encrypted copy of the vault instead of a plain export.
    pub backup: bool,
    /// `--format`. Absent means CSV. Together with `--backup` is [`CONFLICT`].
    pub format: Option<ImportFormat>,
}

/// Parses the arguments after the program name.
///
/// # Errors
/// A [`UsageError`] with fixed text: a password flag anywhere ([`PASSWORD_FLAG`]),
/// an unknown command or flag, a missing value, and so on.
pub fn parse(args: &[OsString]) -> Result<Invocation, UsageError> {
    if args.iter().any(|a| is_password_flag(a)) {
        return Err(PASSWORD_FLAG);
    }
    let (vault, rest) = match args {
        [flag, path, rest @ ..] if flag == "--vault" => {
            if path.is_empty() {
                return Err(EMPTY_VAULT);
            }
            (Some(PathBuf::from(path)), rest)
        }
        [flag] if flag == "--vault" => return Err(MISSING_VALUE),
        rest => (None, rest),
    };
    let command = parse_command(rest)?;
    Ok(Invocation { vault, command })
}

/// Parses a command and its flags, without `--vault`. `holm shell` uses this for
/// each line.
///
/// # Errors
/// As [`parse`].
pub fn parse_command(args: &[OsString]) -> Result<Command, UsageError> {
    if args.iter().any(|a| is_password_flag(a)) {
        return Err(PASSWORD_FLAG);
    }
    let Some((first, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    let name = text(first)?;
    match name {
        "help" | "--help" | "-h" => no_more(rest).map(|()| Command::Help),
        "version" | "--version" | "-V" => no_more(rest).map(|()| Command::Version),
        "init" => no_more(rest).map(|()| Command::Init),
        "list" => parse_list(rest).map(Command::List),
        "get" => parse_get(rest).map(Command::Get),
        "gen" => parse_gen(rest).map(Command::Gen),
        "add" => parse_add(rest).map(Command::Add),
        "edit" => parse_edit(rest).map(Command::Edit),
        "rm" => parse_rm(rest).map(Command::Rm),
        "import" => parse_import(rest).map(Command::Import),
        "export" => parse_export(rest).map(Command::Export),
        "restore" => parse_ref(rest).map(Command::Restore),
        "empty-trash" => no_more(rest).map(|()| Command::EmptyTrash),
        "passwd" => no_more(rest).map(|()| Command::Passwd),
        "shell" => no_more(rest).map(|()| Command::Shell),
        _ => Err(UNKNOWN_COMMAND),
    }
}

/// True for a flag that would carry a password: `-p` (alone or with a value stuck to
/// it), and any long flag whose name starts with `pass` or `master`, or is `pw` or
/// `pwd`, with or without `=value`. Prompt-only flags accept no attached value.
fn is_password_flag(arg: &OsStr) -> bool {
    let bytes = arg.as_encoded_bytes();
    if let Some(long) = bytes.strip_prefix(b"--") {
        let name = long.split(|b| *b == b'=').next().unwrap_or_default();
        let name = name.to_ascii_lowercase();
        return name.starts_with(b"pass")
            || name.starts_with(b"master")
            || name == b"pw"
            || name == b"pwd"
            || (long.contains(&b'=')
                && matches!(
                    name.as_slice(),
                    b"new-password" | b"new-notes" | b"with-notes"
                ));
    }
    bytes.starts_with(b"-p") || bytes.starts_with(b"-P")
}

/// The argument as UTF-8 text.
fn text(arg: &OsStr) -> Result<&str, UsageError> {
    arg.to_str().ok_or(NOT_TEXT)
}

fn no_more(rest: &[OsString]) -> Result<(), UsageError> {
    match rest {
        [] => Ok(()),
        [first, ..] => Err(unexpected(first)),
    }
}

/// The error for an argument a command did not expect: an unknown flag, or one word
/// too many.
fn unexpected(arg: &OsStr) -> UsageError {
    if arg.as_encoded_bytes().starts_with(b"-") {
        UNKNOWN_FLAG
    } else {
        TOO_MANY
    }
}

/// Sets the category filter once. A second `--category` is [`REPEATED_FLAG`]; mixing
/// it with `--uncategorised` is [`CATEGORY_CONFLICT`].
fn set_category(slot: &mut Option<CategoryArg>, value: CategoryArg) -> Result<(), UsageError> {
    match slot {
        None => {
            *slot = Some(value);
            Ok(())
        }
        Some(old) if std::mem::discriminant(old) == std::mem::discriminant(&value) => {
            Err(REPEATED_FLAG)
        }
        Some(_) => Err(CATEGORY_CONFLICT),
    }
}

/// Sets `slot` once; a second time is [`REPEATED_FLAG`].
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(REPEATED_FLAG);
    }
    *slot = Some(value);
    Ok(())
}

fn set_flag(slot: &mut bool) -> Result<(), UsageError> {
    if *slot {
        return Err(REPEATED_FLAG);
    }
    *slot = true;
    Ok(())
}

fn parse_list(mut rest: &[OsString]) -> Result<ListArgs, UsageError> {
    let mut search = None;
    let mut item_type = None;
    let mut category = None;
    let mut sort = None;
    let mut favourites = false;
    let mut trash = false;
    let mut expiring = false;
    loop {
        rest = match rest {
            [] => break,
            [flag, value, tail @ ..] if flag == "--search" => {
                set_once(&mut search, Zeroizing::new(text(value)?.to_owned()))?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--type" => {
                set_once(&mut item_type, item_type_of(text(value)?)?)?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--category" => {
                set_category(
                    &mut category,
                    CategoryArg::Named(Zeroizing::new(text(value)?.to_owned())),
                )?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--sort" => {
                set_once(&mut sort, sort_of(text(value)?)?)?;
                tail
            }
            [flag, tail @ ..] if flag == "--uncategorised" || flag == "--uncategorized" => {
                set_category(&mut category, CategoryArg::Uncategorised)?;
                tail
            }
            [flag, tail @ ..] if flag == "--favourites" || flag == "--favorites" => {
                set_flag(&mut favourites)?;
                tail
            }
            [flag, tail @ ..] if flag == "--trash" => {
                set_flag(&mut trash)?;
                tail
            }
            [flag, tail @ ..] if flag == "--expiring" => {
                set_flag(&mut expiring)?;
                tail
            }
            [flag]
                if ["--search", "--type", "--category", "--sort"]
                    .iter()
                    .any(|f| flag == *f) =>
            {
                return Err(MISSING_VALUE);
            }
            [first, ..] => return Err(unexpected(first)),
        };
    }
    Ok(ListArgs {
        search,
        item_type,
        category,
        favourites,
        trash,
        expiring,
        sort: sort.unwrap_or_default(),
    })
}

fn item_type_of(value: &str) -> Result<ItemType, UsageError> {
    match value {
        "login" => Ok(ItemType::Login),
        "crypto" => Ok(ItemType::CryptoAddress),
        "phrase" => Ok(ItemType::RecoveryPhrase),
        "note" => Ok(ItemType::SecureNote),
        _ => Err(BAD_TYPE),
    }
}

fn sort_of(value: &str) -> Result<Sort, UsageError> {
    match value {
        "title" => Ok(Sort::TitleAsc),
        "updated" => Ok(Sort::UpdatedDesc),
        "created" => Ok(Sort::CreatedDesc),
        _ => Err(BAD_SORT),
    }
}

fn parse_get(mut rest: &[OsString]) -> Result<GetArgs, UsageError> {
    let mut reference = None;
    let mut copy = None;
    loop {
        rest = match rest {
            [] => break,
            [flag, value, tail @ ..] if flag == "--copy" => {
                set_once(&mut copy, copy_field_of(text(value)?)?)?;
                tail
            }
            [flag] if flag == "--copy" => return Err(MISSING_VALUE),
            [word, tail @ ..] => {
                set_reference(&mut reference, word)?;
                tail
            }
        };
    }
    Ok(GetArgs {
        reference: reference.ok_or(MISSING_REF)?,
        copy,
    })
}

/// Takes `word` as the one reference: a flag is [`UNKNOWN_FLAG`], a second word
/// [`TOO_MANY`], a malformed one [`BAD_REF`].
fn set_reference(slot: &mut Option<String>, word: &OsStr) -> Result<(), UsageError> {
    if word.as_encoded_bytes().starts_with(b"-") {
        return Err(UNKNOWN_FLAG);
    }
    if slot.is_some() {
        return Err(TOO_MANY);
    }
    let reference = text(word)?;
    check_reference(reference)?;
    *slot = Some(reference.to_owned());
    Ok(())
}

fn copy_field_of(value: &str) -> Result<CopyField, UsageError> {
    if let Some(raw) = value.strip_prefix("field=") {
        let position = field_position(raw).map_err(|_| BAD_FIELD)?;
        return Ok(CopyField::Custom(position - 1));
    }
    match value {
        "password" => Ok(CopyField::Password),
        "username" => Ok(CopyField::Username),
        "url" => Ok(CopyField::Url),
        "address" => Ok(CopyField::Address),
        "memo" => Ok(CopyField::Memo),
        "notes" => Ok(CopyField::Notes),
        "body" => Ok(CopyField::Body),
        "phrase" => Ok(CopyField::Phrase),
        _ => Err(BAD_FIELD),
    }
}

/// `1` through [`MAX_CUSTOM_FIELDS`], as typed. Anything else is [`BAD_POSITION`].
fn field_position(value: &str) -> Result<u8, UsageError> {
    let Ok(n) = value.parse::<usize>() else {
        return Err(BAD_POSITION);
    };
    if (1..=MAX_CUSTOM_FIELDS).contains(&n) {
        u8::try_from(n).map_err(|_| BAD_POSITION)
    } else {
        Err(BAD_POSITION)
    }
}

fn kind_of(value: &str) -> Result<FieldKind, UsageError> {
    if value.eq_ignore_ascii_case("text") {
        Ok(FieldKind::Text)
    } else if value.eq_ignore_ascii_case("secret") {
        Ok(FieldKind::Secret)
    } else if value.eq_ignore_ascii_case("multiline") {
        Ok(FieldKind::MultilineSecret)
    } else if value.eq_ignore_ascii_case("date") {
        Ok(FieldKind::Date)
    } else {
        Err(BAD_KIND)
    }
}

fn secret_kind(kind: FieldKind) -> bool {
    matches!(kind, FieldKind::Secret | FieldKind::MultilineSecret)
}

fn preset_of(value: &str) -> Result<FieldPreset, UsageError> {
    if value.eq_ignore_ascii_case("email") {
        Ok(FieldPreset::Email)
    } else if value.eq_ignore_ascii_case("cloudflare") {
        Ok(FieldPreset::Cloudflare)
    } else if value.eq_ignore_ascii_case("github") {
        Ok(FieldPreset::GitHub)
    } else if value.eq_ignore_ascii_case("server") {
        Ok(FieldPreset::Server)
    } else if value.eq_ignore_ascii_case("database") {
        Ok(FieldPreset::Database)
    } else if value.eq_ignore_ascii_case("aws") {
        Ok(FieldPreset::Aws)
    } else if value.eq_ignore_ascii_case("api-key") {
        Ok(FieldPreset::ApiKey)
    } else if value.eq_ignore_ascii_case("wifi") {
        Ok(FieldPreset::WiFi)
    } else if value.eq_ignore_ascii_case("bank-card") {
        Ok(FieldPreset::BankCard)
    } else if value.eq_ignore_ascii_case("custom") {
        Ok(FieldPreset::Custom)
    } else {
        Err(BAD_PRESET)
    }
}

fn format_of(value: &str) -> Result<ImportFormat, UsageError> {
    match value {
        "csv" => Ok(ImportFormat::Csv),
        "json" => Ok(ImportFormat::Json),
        _ => Err(BAD_FORMAT),
    }
}

/// The flags `add` and `edit` share, as typed.
#[derive(Default)]
struct ItemFlags {
    title: Option<Zeroizing<String>>,
    username: Option<Zeroizing<String>>,
    urls: Vec<Zeroizing<String>>,
    chain: Option<Zeroizing<String>>,
    category: Option<CategoryArg>,
    favourite: Option<bool>,
    generate: bool,
    new_password: bool,
    with_notes: bool,
    new_notes: bool,
    clear_urls: bool,
    preset: Option<FieldPreset>,
    field_label: Option<String>,
    field_kind: Option<FieldKind>,
    field_expiry: Option<CalendarDate>,
    clear_expiry: bool,
    field_value: Option<Zeroizing<String>>,
    field_remove: Option<u8>,
    field_move: Option<u8>,
    field_to: Option<u8>,
    field_set: Option<u8>,
}

/// Which flags a command takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemCommand {
    Add,
    Edit,
}

/// Parses the flags of `add` or `edit`; any other word is handed to `word`.
fn parse_item_flags(
    mut rest: &[OsString],
    command: ItemCommand,
    word: &mut dyn FnMut(&OsStr) -> Result<(), UsageError>,
) -> Result<ItemFlags, UsageError> {
    let edit = command == ItemCommand::Edit;
    let mut f = ItemFlags::default();
    loop {
        if let Some(tail) = extra_item_flags(&mut f, rest, edit)? {
            rest = tail;
            continue;
        }
        rest = match rest {
            [] => break,
            [flag, value, tail @ ..] if flag == "--title" => {
                set_once(&mut f.title, Zeroizing::new(text(value)?.to_owned()))?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--username" => {
                set_once(&mut f.username, Zeroizing::new(text(value)?.to_owned()))?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--url" => {
                f.urls.push(Zeroizing::new(text(value)?.to_owned()));
                tail
            }
            [flag, value, tail @ ..] if flag == "--chain" && !edit => {
                set_once(&mut f.chain, Zeroizing::new(text(value)?.to_owned()))?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--category" => {
                set_category(
                    &mut f.category,
                    CategoryArg::Named(Zeroizing::new(text(value)?.to_owned())),
                )?;
                tail
            }
            [flag, tail @ ..]
                if edit && (flag == "--uncategorised" || flag == "--uncategorized") =>
            {
                set_category(&mut f.category, CategoryArg::Uncategorised)?;
                tail
            }
            [flag, tail @ ..] if flag == "--favourite" || flag == "--favorite" => {
                set_favourite(&mut f.favourite, true)?;
                tail
            }
            [flag, tail @ ..] if edit && (flag == "--no-favourite" || flag == "--no-favorite") => {
                set_favourite(&mut f.favourite, false)?;
                tail
            }
            [flag, tail @ ..] if flag == "--generate" => {
                set_flag(&mut f.generate)?;
                tail
            }
            [flag, tail @ ..] if edit && flag == "--new-password" => {
                set_flag(&mut f.new_password)?;
                tail
            }
            [flag, tail @ ..] if !edit && flag == "--with-notes" => {
                set_flag(&mut f.with_notes)?;
                tail
            }
            [flag, tail @ ..] if edit && flag == "--new-notes" => {
                set_flag(&mut f.new_notes)?;
                tail
            }
            [flag, tail @ ..] if edit && flag == "--clear-urls" => {
                set_flag(&mut f.clear_urls)?;
                tail
            }
            [flag]
                if ["--title", "--username", "--url", "--chain", "--category"]
                    .iter()
                    .any(|n| flag == *n) =>
            {
                return Err(MISSING_VALUE);
            }
            [first, tail @ ..] => {
                word(first)?;
                tail
            }
        };
    }
    Ok(f)
}

/// `--preset` on `add`, and the custom-field flags on `edit`. `None` means the
/// word belongs to the shared parser.
fn extra_item_flags<'a>(
    f: &mut ItemFlags,
    rest: &'a [OsString],
    edit: bool,
) -> Result<Option<&'a [OsString]>, UsageError> {
    if !edit {
        return preset_flag(f, rest);
    }
    match rest {
        [flag, value, tail @ ..] if flag == "--field-add" => {
            set_once(&mut f.field_label, text(value)?.to_owned())?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--kind" => {
            let kind = kind_of(text(value)?)?;
            if secret_kind(kind) && f.field_value.is_some() {
                // The bytes were stored before the kind was known. Drop them.
                f.field_value = None;
                return Err(SECRET_ON_COMMAND_LINE);
            }
            set_once(&mut f.field_kind, kind)?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--expiry" => {
            let date = parse_date(text(value)?).ok_or(BAD_DATE)?;
            set_once(&mut f.field_expiry, date)?;
            Ok(Some(tail))
        }
        [flag, _, ..] if flag == "--value" && f.field_kind.is_some_and(secret_kind) => {
            Err(SECRET_ON_COMMAND_LINE)
        }
        [flag, value, tail @ ..] if flag == "--value" => {
            set_once(&mut f.field_value, Zeroizing::new(text(value)?.to_owned()))?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--field-remove" => {
            set_once(&mut f.field_remove, field_position(text(value)?)?)?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--field-move" => {
            set_once(&mut f.field_move, field_position(text(value)?)?)?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--to" => {
            set_once(&mut f.field_to, field_position(text(value)?)?)?;
            Ok(Some(tail))
        }
        [flag, value, tail @ ..] if flag == "--field-set" => {
            set_once(&mut f.field_set, field_position(text(value)?)?)?;
            Ok(Some(tail))
        }
        [flag, tail @ ..] if flag == "--clear-expiry" => {
            set_flag(&mut f.clear_expiry)?;
            Ok(Some(tail))
        }
        [flag] if edit_flag_needs_value(flag) => Err(MISSING_VALUE),
        _ => Ok(None),
    }
}

fn preset_flag<'a>(
    f: &mut ItemFlags,
    rest: &'a [OsString],
) -> Result<Option<&'a [OsString]>, UsageError> {
    match rest {
        [flag, value, tail @ ..] if flag == "--preset" => {
            set_once(&mut f.preset, preset_of(text(value)?)?)?;
            Ok(Some(tail))
        }
        [flag] if flag == "--preset" => Err(MISSING_VALUE),
        _ => Ok(None),
    }
}

fn edit_flag_needs_value(flag: &OsStr) -> bool {
    [
        "--field-add",
        "--kind",
        "--expiry",
        "--value",
        "--field-remove",
        "--field-move",
        "--to",
        "--field-set",
    ]
    .iter()
    .any(|name| flag == *name)
}

/// One custom-field change, or [`FieldEdit::None`]. A secret `--value` is wiped
/// here and never returned.
fn take_field_edit(f: &mut ItemFlags) -> Result<FieldEdit, UsageError> {
    check_field_flags(f)?;
    if let Some(position) = f.field_remove.take() {
        return Ok(FieldEdit::Remove { position });
    }
    if let Some(from) = f.field_move.take() {
        let to = f.field_to.take().ok_or(MISSING_VALUE)?;
        return Ok(FieldEdit::Move { from, to });
    }
    if let Some(position) = f.field_set.take() {
        return Ok(FieldEdit::Set {
            position,
            expiry: expiry_edit(f),
        });
    }
    if f.field_label.is_some() {
        return take_field_add(f);
    }
    Ok(FieldEdit::None)
}

fn check_field_flags(f: &mut ItemFlags) -> Result<(), UsageError> {
    let chosen = u8::from(f.field_label.is_some())
        + u8::from(f.field_remove.is_some())
        + u8::from(f.field_move.is_some())
        + u8::from(f.field_set.is_some());
    if chosen > 1 {
        return Err(CONFLICT);
    }
    if f.field_to.is_some() && f.field_move.is_none() {
        return Err(CONFLICT);
    }
    if f.field_kind.is_some() && f.field_label.is_none() {
        return Err(CONFLICT);
    }
    if f.field_expiry.is_some() && f.field_label.is_none() && f.field_set.is_none() {
        return Err(CONFLICT);
    }
    if f.clear_expiry && (f.field_set.is_none() || f.field_expiry.is_some()) {
        return Err(CONFLICT);
    }
    if f.field_value.is_some() && f.field_label.is_none() && f.field_set.is_none() {
        f.field_value = None;
        return Err(CONFLICT);
    }
    Ok(())
}

fn expiry_edit(f: &mut ItemFlags) -> ExpiryEdit {
    if f.clear_expiry {
        ExpiryEdit::Clear
    } else if let Some(date) = f.field_expiry.take() {
        ExpiryEdit::Set(date)
    } else {
        ExpiryEdit::Unchanged
    }
}

fn take_field_add(f: &mut ItemFlags) -> Result<FieldEdit, UsageError> {
    let label = f.field_label.take().ok_or(MISSING_VALUE)?;
    let kind = f.field_kind.take().ok_or(MISSING_VALUE)?;
    if secret_kind(kind) {
        if f.field_value.is_some() {
            f.field_value = None;
            return Err(SECRET_ON_COMMAND_LINE);
        }
    } else if f.field_value.is_none() {
        return Err(MISSING_VALUE);
    } else if kind == FieldKind::Date && !date_value_ok(f) {
        f.field_value = None;
        return Err(BAD_DATE);
    }
    Ok(FieldEdit::Add {
        label,
        kind,
        expiry: f.field_expiry.take(),
    })
}

fn date_value_ok(f: &ItemFlags) -> bool {
    f.field_value
        .as_ref()
        .is_some_and(|value| parse_date(value.as_str()).is_some())
}

/// `--favourite` and `--no-favourite`: once, and not both.
fn set_favourite(slot: &mut Option<bool>, value: bool) -> Result<(), UsageError> {
    match slot {
        None => {
            *slot = Some(value);
            Ok(())
        }
        Some(old) if *old == value => Err(REPEATED_FLAG),
        Some(_) => Err(CONFLICT),
    }
}

fn parse_add(rest: &[OsString]) -> Result<AddArgs, UsageError> {
    let Some((kind, rest)) = rest.split_first() else {
        return Err(MISSING_ADD_TYPE);
    };
    let item_type = match text(kind)? {
        "login" => ItemType::Login,
        "crypto" => ItemType::CryptoAddress,
        "phrase" => ItemType::RecoveryPhrase,
        "note" => ItemType::SecureNote,
        k if k.starts_with('-') => return Err(MISSING_ADD_TYPE),
        _ => return Err(BAD_TYPE),
    };
    let f = parse_item_flags(rest, ItemCommand::Add, &mut |w| Err(unexpected(w)))?;
    let login = item_type == ItemType::Login;
    let fits = (login || (f.username.is_none() && f.urls.is_empty() && !f.generate))
        && (item_type == ItemType::CryptoAddress || f.chain.is_none())
        && (item_type != ItemType::SecureNote || !f.with_notes);
    if !fits {
        return Err(WRONG_TYPE_OPTION);
    }
    let category = match f.category {
        None => None,
        Some(CategoryArg::Named(name)) => Some(name),
        // Not accepted by `add`'s flag parser.
        Some(CategoryArg::Uncategorised) => return Err(UNKNOWN_FLAG),
    };
    Ok(AddArgs {
        item_type,
        title: f.title.ok_or(MISSING_TITLE)?,
        username: f.username,
        urls: f.urls,
        chain: f.chain,
        category,
        favourite: f.favourite.unwrap_or(false),
        generate: f.generate,
        with_notes: f.with_notes,
        preset: f.preset,
    })
}

fn parse_edit(rest: &[OsString]) -> Result<EditArgs, UsageError> {
    let mut reference = None;
    let mut f = parse_item_flags(rest, ItemCommand::Edit, &mut |w| {
        set_reference(&mut reference, w)
    })?;
    let new_password = match (f.new_password, f.generate) {
        (false, false) => None,
        (true, false) => Some(NewPassword::Typed),
        (false, true) => Some(NewPassword::Generate),
        (true, true) => return Err(CONFLICT),
    };
    let fields = take_field_edit(&mut f)?;
    let args = EditArgs {
        reference: Zeroizing::new(reference.ok_or(MISSING_REF)?),
        title: f.title,
        username: f.username,
        urls: f.urls,
        clear_urls: f.clear_urls,
        category: f.category,
        favourite: f.favourite,
        new_password,
        new_notes: f.new_notes,
        fields,
        field_value: f.field_value.take(),
    };
    let nothing = args.title.is_none()
        && args.username.is_none()
        && args.urls.is_empty()
        && !args.clear_urls
        && args.category.is_none()
        && args.favourite.is_none()
        && args.new_password.is_none()
        && !args.new_notes
        && matches!(args.fields, FieldEdit::None);
    if nothing {
        return Err(NOTHING_TO_CHANGE);
    }
    Ok(args)
}

fn parse_ref(rest: &[OsString]) -> Result<RefArgs, UsageError> {
    let mut reference = None;
    for word in rest {
        set_reference(&mut reference, word)?;
    }
    Ok(RefArgs {
        reference: reference.ok_or(MISSING_REF)?,
    })
}

fn parse_rm(mut rest: &[OsString]) -> Result<RmArgs, UsageError> {
    let mut reference = None;
    let mut forever = false;
    loop {
        rest = match rest {
            [] => break,
            [flag, tail @ ..] if flag == "--forever" => {
                set_flag(&mut forever)?;
                tail
            }
            [word, tail @ ..] => {
                set_reference(&mut reference, word)?;
                tail
            }
        };
    }
    Ok(RmArgs {
        reference: reference.ok_or(MISSING_REF)?,
        forever,
    })
}

/// Takes `word` as the one file path. Any word starting with `-` is a flag.
fn set_file(slot: &mut Option<PathBuf>, word: &OsStr) -> Result<(), UsageError> {
    if word.as_encoded_bytes().starts_with(b"-") {
        return Err(UNKNOWN_FLAG);
    }
    if word.is_empty() {
        return Err(MISSING_FILE);
    }
    set_once(slot, PathBuf::from(word)).map_err(|_| TOO_MANY)
}

fn parse_import(mut rest: &[OsString]) -> Result<ImportArgs, UsageError> {
    let mut file = None;
    let mut format = None;
    loop {
        rest = match rest {
            [] => break,
            [flag, value, tail @ ..] if flag == "--format" => {
                set_once(&mut format, format_of(text(value)?)?)?;
                tail
            }
            [flag] if flag == "--format" => return Err(MISSING_VALUE),
            [word, tail @ ..] => {
                set_file(&mut file, word)?;
                tail
            }
        };
    }
    Ok(ImportArgs {
        file: file.ok_or(MISSING_FILE)?,
        format,
    })
}

fn parse_export(mut rest: &[OsString]) -> Result<ExportArgs, UsageError> {
    let mut file = None;
    let mut backup = false;
    let mut format = None;
    loop {
        rest = match rest {
            [] => break,
            [flag, tail @ ..] if flag == "--backup" => {
                set_flag(&mut backup)?;
                tail
            }
            [flag, value, tail @ ..] if flag == "--format" => {
                set_once(&mut format, format_of(text(value)?)?)?;
                tail
            }
            [flag] if flag == "--format" => return Err(MISSING_VALUE),
            [word, tail @ ..] => {
                set_file(&mut file, word)?;
                tail
            }
        };
    }
    if backup && format.is_some() {
        return Err(CONFLICT);
    }
    Ok(ExportArgs {
        file: file.ok_or(MISSING_FILE)?,
        backup,
        format,
    })
}

/// Checks a reference's form: 6 to 32 lowercase hex digits.
///
/// # Errors
/// [`BAD_REF`] otherwise.
pub fn check_reference(reference: &str) -> Result<(), UsageError> {
    let ok = (6..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok { Ok(()) } else { Err(BAD_REF) }
}

fn parse_gen(mut rest: &[OsString]) -> Result<GenArgs, UsageError> {
    let mut kind = None;
    let mut copy = false;
    loop {
        rest = match rest {
            [] => break,
            [flag, tail @ ..] if flag == "--copy" => {
                set_flag(&mut copy)?;
                tail
            }
            [word, tail @ ..] => {
                let k = match text(word)? {
                    "password" => GenKind::Password,
                    "passphrase" => GenKind::Passphrase,
                    "username" => GenKind::Username,
                    k if k.starts_with('-') => return Err(UNKNOWN_FLAG),
                    _ if kind.is_some() => return Err(TOO_MANY),
                    _ => return Err(BAD_GEN),
                };
                set_once(&mut kind, k).map_err(|_| TOO_MANY)?;
                tail
            }
        };
    }
    Ok(GenArgs {
        kind: kind.unwrap_or_default(),
        copy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn parse_strs(list: &[&str]) -> Result<Invocation, UsageError> {
        parse(&args(list))
    }

    #[test]
    fn no_flag_takes_a_password() {
        for line in [
            &["--password", "x"][..],
            &["-p", "x"],
            &["--pass=x"],
            &["--master", "x"],
            &["list", "--password", "x"],
            &["--vault", "v.holm", "get", "abcdef", "-px"],
            &["--Password=x", "list"],
            &["--passphrase", "x", "list"],
            &["--master-password", "x", "init"],
            &["--pw", "x", "list"],
            &["init", "-P"],
        ] {
            let e = parse_strs(line).unwrap_err();
            assert_eq!(e, PASSWORD_FLAG, "{line:?}");
            assert!(e.0.contains("only typed at the prompt"));
            assert!(!e.0.contains('x'));
        }
        // A positional word "password" is fine (it is what `gen` makes).
        assert!(matches!(
            parse_strs(&["gen", "password"]).unwrap().command,
            Command::Gen(GenArgs {
                kind: GenKind::Password,
                copy: false,
            })
        ));
    }

    #[test]
    fn password_flag_with_value_named() {
        for flag in [
            "--new-password=EXAMPLE",
            "--new-notes=EXAMPLE",
            "--with-notes=EXAMPLE",
        ] {
            let error = parse_strs(&["edit", "abcdef", flag]).unwrap_err();
            assert_eq!(error, PASSWORD_FLAG);
            assert!(!error.to_string().contains("EXAMPLE"));
        }
    }

    #[test]
    fn args_text_fields_are_zeroizing() {
        let Command::Add(add) = parse_strs(&[
            "add",
            "crypto",
            "--title",
            "T",
            "--chain",
            "C",
            "--category",
            "Work",
        ])
        .unwrap()
        .command
        else {
            panic!("not add");
        };
        let _: &Zeroizing<String> = &add.title;
        let _: &Option<Zeroizing<String>> = &add.username;
        let _: &Vec<Zeroizing<String>> = &add.urls;
        let _: &Option<Zeroizing<String>> = &add.chain;
        let _: &Option<Zeroizing<String>> = &add.category;

        let Command::Edit(edit) =
            parse_strs(&["edit", "abcdef", "--title", "T", "--category", "Work"])
                .unwrap()
                .command
        else {
            panic!("not edit");
        };
        let _: &Zeroizing<String> = &edit.reference;
        let _: &Option<Zeroizing<String>> = &edit.title;
        let _: &Option<Zeroizing<String>> = &edit.username;
        let _: &Vec<Zeroizing<String>> = &edit.urls;
        let Some(CategoryArg::Named(name)) = &edit.category else {
            panic!("not named");
        };
        let _: &Zeroizing<String> = name;
    }

    #[test]
    fn every_spec_command_parses() {
        for (line, name) in [
            (&["init"][..], "init"),
            (&["list"], "list"),
            (&["get", "abcdef"], "get"),
            (&["add", "login", "--title", "T"], "add"),
            (&["edit", "abcdef", "--title", "T"], "edit"),
            (&["rm", "abcdef"], "rm"),
            (&["gen"], "gen"),
            (&["import", "file.csv"], "import"),
            (&["export", "file.csv"], "export"),
            (&["passwd"], "passwd"),
            (&["restore", "abcdef"], "restore"),
            (&["empty-trash"], "empty-trash"),
            (&["shell"], "shell"),
            (&["help"], "help"),
            (&["--version"], "version"),
            (&[], "help"),
        ] {
            let inv = parse_strs(line).unwrap();
            assert_eq!(format!("{:?}", inv.command), name, "{line:?}");
            assert!(inv.vault.is_none());
        }
        let inv = parse_strs(&["--vault", "/v/vault.holm", "list"]).unwrap();
        assert_eq!(inv.vault, Some(PathBuf::from("/v/vault.holm")));
        // Debug never shows the path.
        assert!(!format!("{inv:?}").contains("/v/"));

        let Command::List(list) = parse_strs(&[
            "list",
            "--search",
            "mail",
            "--type",
            "crypto",
            "--category",
            "Work",
            "--favourites",
            "--trash",
            "--sort",
            "updated",
        ])
        .unwrap()
        .command
        else {
            panic!("not list");
        };
        assert_eq!(list.search.as_deref().map(String::as_str), Some("mail"));
        assert_eq!(list.item_type, Some(ItemType::CryptoAddress));
        assert!(list.category == Some(CategoryArg::Named(Zeroizing::new("Work".to_owned()))));
        assert!(list.favourites && list.trash);
        assert_eq!(list.sort, Sort::UpdatedDesc);

        let Command::List(list) = parse_strs(&["list", "--uncategorised"]).unwrap().command else {
            panic!("not list");
        };
        assert!(list.category == Some(CategoryArg::Uncategorised));
        assert_eq!(list.sort, Sort::TitleAsc);

        for (kind, want) in [
            ("password", GenKind::Password),
            ("passphrase", GenKind::Passphrase),
            ("username", GenKind::Username),
        ] {
            let Command::Gen(g) = parse_strs(&["gen", kind]).unwrap().command else {
                panic!("not gen");
            };
            assert_eq!(g.kind, want);
        }
    }

    #[test]
    fn unknown_or_missing_values_are_usage_errors() {
        for (line, want) in [
            (&["frobnicate"][..], UNKNOWN_COMMAND),
            (&["list", "--colour"], UNKNOWN_FLAG),
            (&["list", "extra"], TOO_MANY),
            (&["list", "--search"], MISSING_VALUE),
            (&["list", "--type"], MISSING_VALUE),
            (&["list", "--type", "car"], BAD_TYPE),
            (&["list", "--sort", "size"], BAD_SORT),
            (&["list", "--trash", "--trash"], REPEATED_FLAG),
            (&["list", "--search", "a", "--search", "b"], REPEATED_FLAG),
            (
                &["list", "--category", "A", "--category", "B"],
                REPEATED_FLAG,
            ),
            (
                &["list", "--category", "A", "--uncategorised"],
                CATEGORY_CONFLICT,
            ),
            (&["get"], MISSING_REF),
            (&["get", "abcde"], BAD_REF),
            (&["get", "ABCDEF"], BAD_REF),
            (&["get", "abcdeg"], BAD_REF),
            (&["get", "abcdef", "more"], TOO_MANY),
            (&["gen", "pin"], BAD_GEN),
            (&["gen", "--copy", "--copy"], REPEATED_FLAG),
            (&["gen", "--colour"], UNKNOWN_FLAG),
            (&["gen", "password", "username"], TOO_MANY),
            (&["init", "now"], TOO_MANY),
            (&["--vault"], MISSING_VALUE),
            (&["--vault", ""], EMPTY_VAULT),
            (&["list", "--vault", "v.holm"], UNKNOWN_FLAG),
        ] {
            assert_eq!(parse_strs(line).map(|_| ()).unwrap_err(), want, "{line:?}");
        }
        assert_eq!(check_reference(&"a".repeat(33)).unwrap_err(), BAD_REF);
        assert!(check_reference(&"a".repeat(32)).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = OsString::from_vec(vec![b'l', 0xff]);
            assert_eq!(parse(&[bad]).map(|_| ()).unwrap_err(), NOT_TEXT);
        }
    }

    #[test]
    fn write_command_flags() {
        // `--copy` before or after the reference.
        for line in [
            &["get", "abcdef", "--copy", "phrase"][..],
            &["get", "--copy", "phrase", "abcdef"],
        ] {
            let Command::Get(g) = parse_strs(line).unwrap().command else {
                panic!("not get");
            };
            assert_eq!(
                (g.reference.as_str(), g.copy),
                ("abcdef", Some(CopyField::Phrase))
            );
        }
        let Command::Gen(g) = parse_strs(&["gen", "--copy", "username"]).unwrap().command else {
            panic!("not gen");
        };
        assert_eq!(
            g,
            GenArgs {
                kind: GenKind::Username,
                copy: true
            }
        );

        let Command::Add(a) = parse_strs(&[
            "add",
            "login",
            "--title",
            "T",
            "--url",
            "u1",
            "--url",
            "u2",
            "--favourite",
            "--generate",
            "--category",
            "Work",
        ])
        .unwrap()
        .command
        else {
            panic!("not add");
        };
        assert_eq!(a.item_type, ItemType::Login);
        assert_eq!(
            a.urls.iter().map(|url| url.as_str()).collect::<Vec<_>>(),
            ["u1", "u2"]
        );
        assert!(a.favourite && a.generate && !a.with_notes);
        assert_eq!(a.category.as_deref().map(String::as_str), Some("Work"));

        let Command::Edit(e) = parse_strs(&[
            "edit",
            "--clear-urls",
            "abcdef",
            "--no-favourite",
            "--uncategorised",
            "--new-notes",
        ])
        .unwrap()
        .command
        else {
            panic!("not edit");
        };
        assert!(e.clear_urls && e.new_notes && e.favourite == Some(false));
        assert!(e.category == Some(CategoryArg::Uncategorised));

        let Command::Import(i) = parse_strs(&["import", "--format", "json", "x.txt"])
            .unwrap()
            .command
        else {
            panic!("not import");
        };
        assert_eq!(i.format, Some(ImportFormat::Json));
        let Command::Export(x) = parse_strs(&["export", "b.holm", "--backup"])
            .unwrap()
            .command
        else {
            panic!("not export");
        };
        assert!(x.backup && x.file == std::path::Path::new("b.holm"));
        let Command::Rm(r) = parse_strs(&["rm", "--forever", "abcdef"]).unwrap().command else {
            panic!("not rm");
        };
        assert!(r.forever);

        for (line, want) in [
            (&["get", "abcdef", "--copy", "pin"][..], BAD_FIELD),
            (&["get", "abcdef", "--copy"], MISSING_VALUE),
            (&["add"], MISSING_ADD_TYPE),
            (&["add", "--title", "T"], MISSING_ADD_TYPE),
            (&["add", "login"], MISSING_TITLE),
            (&["add", "login", "--title"], MISSING_VALUE),
            (&["add", "login", "--title", "T", "extra"], TOO_MANY),
            (
                &["add", "login", "--title", "T", "--clear-urls"],
                UNKNOWN_FLAG,
            ),
            (
                &["add", "login", "--title", "T", "--new-password"],
                UNKNOWN_FLAG,
            ),
            (
                &["add", "login", "--title", "T", "--chain", "C"],
                WRONG_TYPE_OPTION,
            ),
            (
                &["add", "crypto", "--title", "T", "--username", "u"],
                WRONG_TYPE_OPTION,
            ),
            (&["edit", "abcdef"], NOTHING_TO_CHANGE),
            (&["edit", "--title", "T"], MISSING_REF),
            (&["edit", "abcdef", "--chain", "C"], UNKNOWN_FLAG),
            (
                &["edit", "abcdef", "--new-password", "--generate"],
                CONFLICT,
            ),
            (
                &["edit", "abcdef", "--favourite", "--no-favourite"],
                CONFLICT,
            ),
            (
                &["edit", "abcdef", "--favourite", "--favourite"],
                REPEATED_FLAG,
            ),
            (
                &["edit", "abcdef", "--category", "W", "--uncategorised"],
                CATEGORY_CONFLICT,
            ),
            (&["rm"], MISSING_REF),
            (&["rm", "abcdef", "abcdee"], TOO_MANY),
            (&["rm", "--force", "abcdef"], UNKNOWN_FLAG),
            (&["import"], MISSING_FILE),
            (&["import", ""], MISSING_FILE),
            (&["import", "a.csv", "b.csv"], TOO_MANY),
            (&["import", "a.csv", "--format", "xml"], BAD_FORMAT),
            (&["export"], MISSING_FILE),
            (&["export", "a.csv", "--backup", "--backup"], REPEATED_FLAG),
            (&["passwd", "now"], TOO_MANY),
            (&["restore"], MISSING_REF),
            (&["restore", "abcdef", "abcdee"], TOO_MANY),
            (&["empty-trash", "now"], TOO_MANY),
        ] {
            assert_eq!(parse_strs(line).map(|_| ()).unwrap_err(), want, "{line:?}");
        }
        // A password is never a flag, on any command.
        for line in [
            &["add", "login", "--title", "T", "--password", "x"][..],
            &["edit", "abcdef", "--pass=x"],
            &["import", "a.csv", "-p", "x"],
        ] {
            assert_eq!(
                parse_strs(line).map(|_| ()).unwrap_err(),
                PASSWORD_FLAG,
                "{line:?}"
            );
        }
    }

    #[test]
    fn custom_field_command_flags() {
        for (field, want) in [("field=1", 0_u8), ("field=10", 9)] {
            let Command::Get(g) = parse_strs(&["get", "abcdef", "--copy", field])
                .unwrap()
                .command
            else {
                panic!("not get");
            };
            assert_eq!(g.copy, Some(CopyField::Custom(want)));
        }
        for field in ["field=0", "field=11", "field=n"] {
            assert_eq!(
                parse_strs(&["get", "abcdef", "--copy", field]).unwrap_err(),
                BAD_FIELD,
                "{field}"
            );
        }

        let Command::List(list) = parse_strs(&["list", "--expiring"]).unwrap().command else {
            panic!("not list");
        };
        assert!(list.expiring);
        assert_eq!(
            parse_strs(&["list", "--expiring", "--expiring"]).unwrap_err(),
            REPEATED_FLAG
        );

        let Command::Add(add) = parse_strs(&["add", "login", "--title", "T", "--preset", "server"])
            .unwrap()
            .command
        else {
            panic!("not add");
        };
        assert_eq!(add.preset, Some(FieldPreset::Server));
        assert_eq!(
            parse_strs(&["add", "login", "--title", "T", "--preset", "nope"]).unwrap_err(),
            BAD_PRESET
        );
        assert_eq!(
            parse_strs(&["edit", "abcdef", "--preset", "server"]).unwrap_err(),
            UNKNOWN_FLAG
        );

        let Command::Edit(edit) = parse_strs(&[
            "edit",
            "abcdef",
            "--field-add",
            "Host",
            "--kind",
            "text",
            "--value",
            "localhost",
            "--expiry",
            "2026-11-05",
        ])
        .unwrap()
        .command
        else {
            panic!("not edit");
        };
        let FieldEdit::Add { kind, expiry, .. } = edit.fields else {
            panic!("not add");
        };
        assert_eq!(kind, FieldKind::Text);
        assert!(expiry.is_some());
        assert_eq!(
            edit.field_value.as_ref().map(|value| value.as_str()),
            Some("localhost")
        );

        let Command::Edit(edit) = parse_strs(&["edit", "abcdef", "--field-move", "3", "--to", "1"])
            .unwrap()
            .command
        else {
            panic!("not edit");
        };
        assert_eq!(edit.fields, FieldEdit::Move { from: 3, to: 1 });

        let Command::Export(export) = parse_strs(&["export", "a.json", "--format", "json"])
            .unwrap()
            .command
        else {
            panic!("not export");
        };
        assert_eq!(export.format, Some(ImportFormat::Json));
        assert!(!export.backup);

        for (line, want) in [
            (
                &[
                    "edit",
                    "abcdef",
                    "--field-add",
                    "Token",
                    "--kind",
                    "secret",
                    "--value",
                    "EXAMPLE",
                ][..],
                SECRET_ON_COMMAND_LINE,
            ),
            (
                &[
                    "edit",
                    "abcdef",
                    "--field-add",
                    "Token",
                    "--value",
                    "EXAMPLE",
                    "--kind",
                    "secret",
                ],
                SECRET_ON_COMMAND_LINE,
            ),
            (
                &[
                    "edit",
                    "abcdef",
                    "--field-add",
                    "Token",
                    "--kind",
                    "multiline",
                    "--value",
                    "EXAMPLE",
                ],
                SECRET_ON_COMMAND_LINE,
            ),
            (
                &[
                    "edit",
                    "abcdef",
                    "--field-add",
                    "L",
                    "--kind",
                    "nope",
                    "--value",
                    "x",
                ],
                BAD_KIND,
            ),
            (
                &[
                    "edit",
                    "abcdef",
                    "--field-add",
                    "L",
                    "--kind",
                    "date",
                    "--value",
                    "2026-13-01",
                ],
                BAD_DATE,
            ),
            (&["edit", "abcdef", "--field-remove", "0"], BAD_POSITION),
            (&["edit", "abcdef", "--field-remove", "11"], BAD_POSITION),
            (&["edit", "abcdef", "--field-move", "1"], MISSING_VALUE),
            (&["edit", "abcdef", "--to", "1"], CONFLICT),
            (&["edit", "abcdef", "--field-add", "L"], MISSING_VALUE),
            (
                &["add", "login", "--title", "T", "--field-add", "L"],
                UNKNOWN_FLAG,
            ),
            (
                &["export", "a.json", "--format", "json", "--backup"],
                CONFLICT,
            ),
            (&["export", "a.json", "--format", "CSV"], BAD_FORMAT),
            (&["export", "--format"], MISSING_VALUE),
        ] {
            let error = parse_strs(line).unwrap_err();
            assert_eq!(error, want, "{line:?}");
            assert!(!error.to_string().contains("EXAMPLE"));
        }
    }
}
