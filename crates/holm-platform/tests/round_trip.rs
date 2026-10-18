//! The whole Phase 2a path end to end, through the public API only: create, add,
//! lock, unlock, edit, change the password, back up, open the backup. On disk it then
//! exports to an owner-only CSV file, reads it back and imports it into a new vault.
//!
//! Runs twice: on `FsStore` in a temporary directory (real files, durable writes)
//! and on an in-memory store, so a failure points at either the store or the core.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use holm_core::category::{BUILT_IN_CATEGORIES, CategoryId};
use holm_core::clock::SystemClock;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::format::Header;
use holm_core::generator::{PasswordSpec, generate_password};
use holm_core::import::{ImportFormat, MAX_IMPORT_BYTES, parse};
use holm_core::item::{ItemData, ItemId, ItemInput, Timestamp};
use holm_core::session::Session;
use holm_core::settings::Settings;
use holm_core::store::{StoreError, VaultStore};
use holm_core::text::{GatedSecret, SecretText, Text};
use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;
use holm_platform::fs_store::FsStore;
use holm_platform::private_file::{read_capped, write_new_private_file};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const NEW_PW: &str = "Quokka-Sextant-velvet-EXAMPLE-ember-71";
/// The cost the password change moves to: twice the floor's memory.
const RAISED: KdfParams = KdfParams {
    memory_kib: 131_072,
    iterations: 3,
    parallelism: 1,
};

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_owned())
}
fn t(s: &str) -> Text {
    Text::new(s.to_owned())
}
fn st(s: &str) -> SecretText {
    SecretText::new(s.to_owned())
}

/// Every field of one item as plain values. The phrase comes from `reveal_phrase`.
#[derive(Debug, PartialEq)]
struct Snap {
    title: String,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    kind: &'static str,
    fields: Vec<String>,
}

/// Everything the session shows: items (all active), categories and settings.
#[derive(Debug, PartialEq)]
struct View {
    items: BTreeMap<ItemId, Snap>,
    categories: Vec<(CategoryId, String)>,
    settings: Settings,
}

fn view<S: VaultStore>(s: &mut Session<S>, password: &MasterPassword) -> View {
    let ids: Vec<ItemId> = s.active_items().unwrap().map(|i| i.id()).collect();
    let mut items = BTreeMap::new();
    for id in ids {
        let item = s.item(id).unwrap();
        let (kind, fields): (&'static str, Vec<String>) = match item.data() {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => (
                "login",
                [username.as_str(), password.expose(), notes.expose()]
                    .into_iter()
                    .chain(urls.iter().map(Text::as_str))
                    .map(str::to_owned)
                    .collect(),
            ),
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => (
                "address",
                [
                    chain.as_str(),
                    address.expose(),
                    memo.expose(),
                    notes.expose(),
                ]
                .map(str::to_owned)
                .to_vec(),
            ),
            ItemData::RecoveryPhrase { notes, .. } => ("phrase", vec![notes.expose().to_owned()]),
            ItemData::SecureNote { body } => ("note", vec![body.expose().to_owned()]),
        };
        let mut snap = Snap {
            title: item.title().to_owned(),
            category: item.category(),
            favourite: item.favourite(),
            created: item.created(),
            updated: item.updated(),
            trashed: item.trashed(),
            kind,
            fields,
        };
        if kind == "phrase" {
            snap.fields
                .push(s.reveal_phrase(id, password).unwrap().to_owned());
        }
        items.insert(id, snap);
    }
    let categories = s
        .categories()
        .unwrap()
        .iter()
        .map(|c| (c.id(), c.name().to_owned()))
        .collect();
    let settings = s.settings().unwrap().clone();
    View {
        items,
        categories,
        settings,
    }
}

fn input(title: &str, category: Option<CategoryId>, favourite: bool, data: ItemData) -> ItemInput {
    ItemInput {
        title: t(title),
        category,
        favourite,
        data,
    }
}

/// The scenario. Returns both sessions so the caller can check its own store.
fn round_trip<S: VaultStore, B: VaultStore>(store: S, mut backup: B) -> (Session<S>, Session<B>) {
    let mut s = Session::new(store, Box::new(SystemClock::new()));
    s.create(&pw(PW), &KdfParams::FLOOR).unwrap();

    // One item of each type, a user category and a favourite.
    let work = s.add_category("Wörk ✉").unwrap();
    let built_in = s.categories().unwrap()[0].id();
    let login = s
        .add_item(input(
            "Exämple Mail",
            Some(work),
            true,
            ItemData::Login {
                username: t("ådå@example.com"),
                password: st("EXAMPLE-pw-ünï\t"),
                urls: vec![t("https://mail.example.com"), t("https://example.com/a b")],
                notes: st("line one\nline two"),
            },
        ))
        .unwrap();
    s.add_item(input(
        "Cold wallet",
        None,
        false,
        ItemData::CryptoAddress {
            chain: t("EXAMPLE-chain"),
            address: st("EXAMPLE-addr-0x00"),
            memo: st("mémo"),
            notes: st(""),
        },
    ))
    .unwrap();
    s.add_item(input(
        "Seed",
        Some(built_in),
        false,
        ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(st("example words only never real ones")),
            notes: st("in the drawer"),
        },
    ))
    .unwrap();
    let note = s
        .add_item(input(
            "Nötë",
            None,
            false,
            ItemData::SecureNote {
                body: st("Body ✓\n"),
            },
        ))
        .unwrap();
    // A login whose password comes from the generator.
    let generated = generate_password(&PasswordSpec::DEFAULT).unwrap();
    assert_eq!(generated.expose().chars().count(), 20);
    s.add_item(input(
        "Generated",
        None,
        false,
        ItemData::Login {
            username: t("someone"),
            password: generated,
            urls: vec![],
            notes: st(""),
        },
    ))
    .unwrap();
    assert!(!s.is_dirty(), "every change is saved at once");

    // Lock, unlock: every field equal.
    let created = view(&mut s, &pw(PW));
    assert_eq!(created.items.len(), 5);
    assert!(!s.lock().discarded_unsaved);
    s.unlock(&pw(PW)).unwrap();
    assert_eq!(view(&mut s, &pw(PW)), created);

    // Edit; trash and restore; weaken a setting (needs the password).
    s.update_item(
        note,
        input(
            "Nötë, edited",
            Some(work),
            true,
            ItemData::SecureNote {
                body: st("New body\n"),
            },
        ),
    )
    .unwrap();
    s.trash(login).unwrap();
    assert!(s.active_items().unwrap().all(|i| i.id() != login));
    s.restore(login).unwrap();
    let mut weaker = s.settings().unwrap().clone();
    weaker.auto_lock_secs += 600;
    weaker.lock_on_sleep = false;
    assert!(matches!(
        s.update_settings(weaker.clone(), None),
        Err(CoreError::PasswordRequired)
    ));
    s.update_settings(weaker.clone(), Some(&pw(PW))).unwrap();
    assert_eq!(s.item(note).unwrap().title(), "Nötë, edited");
    // Left in the trash across the password change and the backup.
    s.trash(note).unwrap();
    let edited = view(&mut s, &pw(PW));
    assert_eq!(edited.settings, weaker);
    assert_eq!(edited.items[&login].trashed, None);
    assert!(!edited.items.contains_key(&note));

    // Change the password and raise the cost; the old password no longer opens.
    s.change_password(&pw(PW), &pw(NEW_PW), &RAISED).unwrap();
    s.lock();
    assert!(matches!(
        s.unlock(&pw(PW)),
        Err(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
    ));
    s.unlock(&pw(NEW_PW)).unwrap();
    assert_eq!(view(&mut s, &pw(NEW_PW)), edited);
    assert!(s.item(note).unwrap().trashed().is_some());

    // A backup opens in a new session with the same items.
    s.save_backup(&mut backup).unwrap();
    let mut b = Session::new(backup, Box::new(SystemClock::new()));
    b.unlock(&pw(NEW_PW)).unwrap();
    assert_eq!(view(&mut b, &pw(NEW_PW)), edited);
    assert!(b.item(note).unwrap().trashed().is_some());
    (s, b)
}

/// The items of `v` by title, as an import into another vault sees them: a built-in
/// category by its name, a user category as none (import never creates one).
fn portable(v: View) -> Vec<(Option<String>, Snap)> {
    let mut out: Vec<(Option<String>, Snap)> = v
        .items
        .into_values()
        .map(|mut snap| {
            let name = snap.category.take().and_then(|id| {
                v.categories
                    .iter()
                    .find(|(c, n)| *c == id && BUILT_IN_CATEGORIES.contains(&n.as_str()))
                    .map(|(_, n)| n.clone())
            });
            (name, snap)
        })
        .collect();
    out.sort_by(|a, b| a.1.title.cmp(&b.1.title));
    out
}

/// Exports the unlocked `s` to an owner-only file in `dir`, reads it back through the
/// import cap and imports it into a new vault there. Every active item comes back.
fn export_and_reimport(s: &mut Session<FsStore>, dir: &Path) {
    let csv = s.export_csv(&pw(NEW_PW)).unwrap();
    let export = dir.join("holm-export.csv");
    write_new_private_file(&export, csv.expose()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&export).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(
        write_new_private_file(&export, b"EXAMPLE"),
        Err(StoreError::AlreadyExists)
    );
    let bytes = read_capped(&export, MAX_IMPORT_BYTES).unwrap();
    assert_eq!(bytes.as_slice(), csv.expose());

    let batch = parse(&bytes, ImportFormat::Csv).unwrap();
    assert!(batch.issues().is_empty());
    let mut other = Session::new(
        FsStore::new(dir.join("imported.vault")),
        Box::new(SystemClock::new()),
    );
    other.create(&pw(PW), &KdfParams::FLOOR).unwrap();
    let report = other.import(batch).unwrap();
    assert_eq!(report.imported, 4, "the trashed note stays out");
    assert_eq!(report.duplicates, 0);

    let expected = portable(view(s, &pw(NEW_PW)));
    let got = portable(view(&mut other, &pw(PW)));
    assert_eq!(got, expected);
    assert!(
        got.iter()
            .any(|(c, snap)| c.is_some() && snap.title == "Seed")
    );
    assert!(got.iter().any(|(_, snap)| snap.favourite));
}

/// Names in `dir` that look like a temp file (`*.tmp-*`).
fn temps(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp-"))
        .collect()
}

#[test]
fn full_round_trip_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("holm.vault");
    let backup = dir.path().join("holm-backup.vault");
    let (mut s, b) = round_trip(FsStore::new(&vault), FsStore::new(&backup));
    export_and_reimport(&mut s, dir.path());
    drop((s, b));
    for path in [&vault, &backup] {
        let bytes = fs::read(path).unwrap();
        let (header, _) = Header::parse(&bytes).unwrap();
        assert_eq!(header.kdf, RAISED);
    }
    assert!(
        temps(dir.path()).is_empty(),
        "temps left: {:?}",
        temps(dir.path())
    );
}

/// A plain in-memory store, for the same scenario without the file system.
/// (`holm-core`'s own `MemStore` is test-only and crate-private.)
#[derive(Default)]
struct MemStore {
    file: Option<Vec<u8>>,
}

impl VaultStore for MemStore {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        self.file.clone().ok_or(StoreError::NotFound)
    }
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.file = Some(bytes.to_vec());
        Ok(())
    }
    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if self.file.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        self.file = Some(bytes.to_vec());
        Ok(())
    }
    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        Ok(0)
    }
}

#[test]
fn full_round_trip_in_memory() {
    let (s, b) = round_trip(MemStore::default(), MemStore::default());
    let main = s.store().file.as_deref().unwrap();
    let copy = b.store().file.as_deref().unwrap();
    assert_eq!(Header::parse(main).unwrap().0.kdf, RAISED);
    assert_eq!(Header::parse(copy).unwrap().0.kdf, RAISED);
}
