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

use holm_core::item::ItemType;
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
    /// `holm gen [KIND]`: a new random value; no vault.
    Gen(GenArgs),
    /// A command whose handler comes in a later task. Its flags are not parsed yet.
    Pending(Pending),
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
            Command::Pending(p) => p.name(),
        };
        f.write_str(name)
    }
}

/// The commands parsed but not run yet (Tasks 6 and 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    /// `holm add`.
    Add,
    /// `holm edit`.
    Edit,
    /// `holm rm`.
    Rm,
    /// `holm import`.
    Import,
    /// `holm export`.
    Export,
    /// `holm passwd`.
    Passwd,
    /// `holm shell`.
    Shell,
}

impl Pending {
    /// The command's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Pending::Add => "add",
            Pending::Edit => "edit",
            Pending::Rm => "rm",
            Pending::Import => "import",
            Pending::Export => "export",
            Pending::Passwd => "passwd",
            Pending::Shell => "shell",
        }
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
    /// `--sort`; title order when not given.
    pub sort: Sort,
}

/// The category filter as typed.
#[derive(Clone, PartialEq, Eq)]
pub enum CategoryArg {
    /// `--category NAME`, matched by the category's name key.
    Named(String),
    /// `--uncategorised`.
    Uncategorised,
}

/// `get`'s reference.
#[derive(Clone)]
pub struct GetArgs {
    /// 6 to 32 lowercase hex digits, checked by [`parse`].
    pub reference: String,
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

/// Parses a command and its flags, without `--vault`. `holm shell` (Task 7) uses this
/// for each line.
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
    let pending = |p: Pending| Ok(Command::Pending(p));
    match name {
        "help" | "--help" | "-h" => no_more(rest).map(|()| Command::Help),
        "version" | "--version" | "-V" => no_more(rest).map(|()| Command::Version),
        "init" => no_more(rest).map(|()| Command::Init),
        "list" => parse_list(rest).map(Command::List),
        "get" => parse_get(rest).map(Command::Get),
        "gen" => parse_gen(rest).map(Command::Gen),
        "add" => pending(Pending::Add),
        "edit" => pending(Pending::Edit),
        "rm" => pending(Pending::Rm),
        "import" => pending(Pending::Import),
        "export" => pending(Pending::Export),
        "passwd" => no_more(rest).and_then(|()| pending(Pending::Passwd)),
        "shell" => no_more(rest).and_then(|()| pending(Pending::Shell)),
        _ => Err(UNKNOWN_COMMAND),
    }
}

/// True for a flag that would carry a password: `-p` (alone or with a value stuck to
/// it), and any long flag whose name starts with `pass` or `master`, or is `pw` or
/// `pwd`, with or without `=value`. `--new-password` (Task 6, takes no value) is not
/// one: it asks for a prompt.
fn is_password_flag(arg: &OsStr) -> bool {
    let bytes = arg.as_encoded_bytes();
    if let Some(long) = bytes.strip_prefix(b"--") {
        let name = long.split(|b| *b == b'=').next().unwrap_or_default();
        let name = name.to_ascii_lowercase();
        return name.starts_with(b"pass")
            || name.starts_with(b"master")
            || name == b"pw"
            || name == b"pwd";
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
                set_category(&mut category, CategoryArg::Named(text(value)?.to_owned()))?;
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

fn parse_get(rest: &[OsString]) -> Result<GetArgs, UsageError> {
    match rest {
        [] => Err(MISSING_REF),
        [reference] => {
            let reference = text(reference)?;
            check_reference(reference)?;
            Ok(GetArgs {
                reference: reference.to_owned(),
            })
        }
        [_, extra, ..] => Err(unexpected(extra)),
    }
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

fn parse_gen(rest: &[OsString]) -> Result<GenArgs, UsageError> {
    let kind = match rest {
        [] => GenKind::Password,
        [kind] => match text(kind)? {
            "password" => GenKind::Password,
            "passphrase" => GenKind::Passphrase,
            "username" => GenKind::Username,
            k if k.starts_with('-') => return Err(UNKNOWN_FLAG),
            _ => return Err(BAD_GEN),
        },
        [_, extra, ..] => return Err(unexpected(extra)),
    };
    Ok(GenArgs { kind })
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
                kind: GenKind::Password
            })
        ));
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
        assert!(list.category == Some(CategoryArg::Named("Work".to_owned())));
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
            (&["gen", "--copy"], UNKNOWN_FLAG),
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
}
