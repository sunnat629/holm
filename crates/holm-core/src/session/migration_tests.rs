//! Session tests for format v2 (spec 3, 4, 7): which records a change seals, the write
//! gate, the v1 migration and the password change.

use super::tests::{FLOOR, NEW_PW, PW, WRONG, created, failures, open_file, pw, session, stored};
use super::{FAIL_SELF_CHECK, Session};
use crate::body::{VaultData, encode_v1_for_test, encode_v2_for_test};
use crate::envelope::{self, VaultError};
use crate::envelope_v2::{self, SealedRecord};
use crate::error::CoreError;
use crate::fields::FieldValue;
use crate::format::{Header, HeaderV2, ParsedHeader, parse_any};
use crate::fuzzing::fixture_items;
use crate::import::{ImportFormat, parse};
use crate::index::BackupPrompt;
use crate::item::{Item, ItemData, ItemId, ItemInput, SecretSlot};
use crate::migrate;
use crate::record::split;
use crate::store::{MemStore, StoreError};
use crate::text::{SecretText, Text};
use holm_crypto::kdf::derive_kek;
use std::io::ErrorKind;

type S = Session<MemStore>;

fn login(title: &str, password: &str) -> ItemInput {
    ItemInput {
        fields: Vec::new(),
        title: Text::new(title.to_owned()),
        category: None,
        favourite: false,
        data: ItemData::Login {
            username: Text::new("user".to_owned()),
            password: SecretText::new(password.to_owned()),
            urls: vec![Text::new("https://example.com".to_owned())],
            notes: SecretText::new("n".to_owned()),
        },
    }
}

fn full() -> StoreError {
    StoreError::Io(ErrorKind::StorageFull)
}

/// The sealed records of the open vault, copied.
fn records(s: &S) -> Vec<SealedRecord> {
    s.unlocked().unwrap().state.records.clone()
}

fn ids(s: &S) -> Vec<ItemId> {
    s.unlocked()
        .unwrap()
        .state
        .index
        .entries
        .iter()
        .map(|e| e.id)
        .collect()
}

/// A vault with three logins.
fn with_three() -> (S, Vec<ItemId>) {
    let (mut s, _) = created();
    let ids = ["a", "b", "c"]
        .iter()
        .map(|t| s.add_item(login(t, &format!("pw-EXAMPLE-{t}"))).unwrap())
        .collect();
    (s, ids)
}

fn password_of(s: &S, id: ItemId) -> String {
    match s.open_item(id).unwrap().data() {
        ItemData::Login { password, .. } => password.expose().to_owned(),
        _ => panic!("not a login"),
    }
}

fn corrupt_record(s: &mut S, pos: usize) {
    s.unlocked_mut().unwrap().state.records[pos].ct[0] ^= 1;
}

// ------------------------------------------------------------------ v1 fixtures

/// Items a v1 body can hold: no custom fields.
fn plain_items() -> Vec<Item> {
    let mut items = fixture_items();
    for i in &mut items {
        i.fields.clear();
    }
    items
}

/// Items a schema 2 body can hold: custom fields, but no recovery codes.
fn items_without_codes() -> Vec<Item> {
    let mut items = fixture_items();
    for i in &mut items {
        i.fields
            .retain(|f| !matches!(f.value(), FieldValue::RecoveryCodes(_)));
    }
    items
}

pub(super) fn data_with(items: Vec<Item>) -> VaultData {
    let mut d = VaultData::new_default();
    d.items = items;
    d
}

/// A v1 file holding `body`, locked with `PW` at the floor costs.
pub(super) fn v1_file(body: &[u8]) -> Vec<u8> {
    envelope::create(&pw(PW), &FLOOR, body).unwrap().1
}

fn v1_current(items: Vec<Item>) -> Vec<u8> {
    v1_file(data_with(items).encode().unwrap().expose())
}

/// An unlocked session over the v1 `file`; nothing written yet.
fn v1_session(file: Vec<u8>) -> S {
    let (mut s, _) = session();
    s.store.bytes = Some(file);
    s.unlock(&pw(PW)).unwrap();
    assert!(s.migration_pending());
    s
}

fn tag_of(file: &[u8]) -> String {
    let ParsedHeader::V1(h, _) = parse_any(file).unwrap() else {
        panic!("not v1")
    };
    migrate::backup_tag(&h)
}

/// What a record holds, as bytes, to compare items without `PartialEq`.
fn secrets_bytes(item: Item) -> Vec<u8> {
    split(item).1.encode().unwrap().expose().to_vec()
}

fn assert_holds(s: &S, expected: Vec<Item>) {
    let got = ids(s);
    assert_eq!(got.len(), expected.len());
    for (id, want) in got.into_iter().zip(expected) {
        assert_eq!(want.id, id);
        let have = s.open_item(id).unwrap();
        assert_eq!(have.title(), want.title());
        assert_eq!(secrets_bytes(have), secrets_bytes(want));
    }
}

// ------------------------------------------------------------- what a change seals

#[test]
fn edit_reseals_only_that_record() {
    let (mut s, ids) = with_three();
    let before = records(&s);
    let mut input = login("b", "pw-EXAMPLE-changed");
    input.favourite = true;
    s.update_item(ids[1], input).unwrap();
    let after = records(&s);
    assert_eq!(after[0], before[0]);
    assert_eq!(after[2], before[2]);
    assert_ne!(after[1].ct, before[1].ct);
    assert_ne!(after[1].nonce, before[1].nonce);
    assert_eq!(after[1].generation, before[1].generation + 1);
    // The index pins the new record.
    let entry = &s.unlocked().unwrap().state.index.entries[1];
    assert_eq!(entry.record.generation, after[1].generation);
    assert_eq!(entry.record.nonce, after[1].nonce);
    assert_eq!(password_of(&s, ids[1]), "pw-EXAMPLE-changed");
    assert_eq!(password_of(&s, ids[0]), "pw-EXAMPLE-a");
}

#[test]
fn public_change_reseals_no_record() {
    let (mut s, ids) = with_three();
    let before = records(&s);
    s.set_favourite(ids[0], true).unwrap();
    s.trash(ids[1]).unwrap();
    s.restore(ids[1]).unwrap();
    assert_eq!(records(&s), before);
    assert!(s.entry(ids[0]).unwrap().favourite());
    // The saved file holds the same record bytes.
    let file = open_file(&stored(&s), PW);
    assert_eq!(file.records, before);
}

#[test]
fn oversize_change_restores_old_record() {
    let (mut s, _) = created();
    let make = |i: usize| {
        let mut item = crate::fuzzing::fixture_item(
            0,
            ItemData::SecureNote {
                body: SecretText::new("x".repeat(30_000)),
            },
            Vec::new(),
        );
        item.id = ItemId::random().unwrap();
        item.title = Text::new(format!("n{i}"));
        item
    };
    let (_, ids) = s.seed_to_the_brim(make);
    let before = records(&s);
    let target = ids[0];
    let grow = ItemInput {
        fields: Vec::new(),
        title: Text::new("n0".to_owned()),
        category: None,
        favourite: false,
        data: ItemData::SecureNote {
            body: SecretText::new("y".repeat(65_536)),
        },
    };
    assert_eq!(
        s.update_item(target, grow),
        Err(CoreError::Vault(VaultError::TooLargeToSave))
    );
    assert_eq!(records(&s), before);
    let entry = &s.unlocked().unwrap().state.index.entries[0];
    assert_eq!(entry.record.generation, before[0].generation);
    assert_eq!(entry.record.nonce, before[0].nonce);
    match s.open_item(target).unwrap().data() {
        ItemData::SecureNote { body } => assert_eq!(body.expose(), "x".repeat(30_000)),
        _ => panic!("not a note"),
    }
}

#[test]
fn change_password_reseals_all_new_key_block() {
    let (mut s, ids) = with_three();
    let before = records(&s);
    let old_block = s.unlocked().unwrap().state.keys.key_block();
    s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap();
    let after = records(&s);
    assert_ne!(s.unlocked().unwrap().state.keys.key_block(), old_block);
    for (a, b) in after.iter().zip(&before) {
        assert_ne!(a.ct, b.ct);
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.generation, b.generation + 1);
    }
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(
            password_of(&s, *id),
            format!("pw-EXAMPLE-{}", ["a", "b", "c"][i])
        );
    }
    // On disk: the new password opens it and the old one does not.
    let file = stored(&s);
    assert!(envelope_v2::open_v2(&file, &pw(PW)).is_err());
    assert_eq!(open_file(&file, NEW_PW).records, after);
}

#[test]
fn change_password_write_fails_keeps_old() {
    let (mut s, ids) = with_three();
    let before = records(&s);
    let file_before = stored(&s);
    let block = s.unlocked().unwrap().state.keys.key_block();
    s.store.fail_next_write = Some(full());
    assert_eq!(
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
        Err(CoreError::Store(full()))
    );
    assert_eq!(records(&s), before);
    assert_eq!(s.unlocked().unwrap().state.keys.key_block(), block);
    assert_eq!(stored(&s), file_before);
    assert_eq!(password_of(&s, ids[2]), "pw-EXAMPLE-c");
    assert_eq!(s.check_password(&pw(PW)), Ok(()));
    // Saving still works under the old password.
    s.save().unwrap();
    assert!(envelope_v2::open_v2(&stored(&s), &pw(PW)).is_ok());
}

#[test]
fn change_password_uncertain_adopts_records() {
    let (mut s, ids) = with_three();
    s.store.fail_after_write = Some(full());
    assert_eq!(
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
        Err(CoreError::PasswordChangeUncertain(full()))
    );
    assert!(s.is_dirty());
    // Memory holds the new records and keys, and they match the file that was stored.
    let file = open_file(&stored(&s), NEW_PW);
    assert_eq!(file.records, records(&s));
    for id in &ids {
        assert!(password_of(&s, *id).starts_with("pw-EXAMPLE-"));
    }
    s.save().unwrap();
    s.lock();
    s.unlock(&pw(NEW_PW)).unwrap();
}

#[test]
fn change_password_damaged_record_stops() {
    let (mut s, ids) = with_three();
    corrupt_record(&mut s, 1);
    let file_before = stored(&s);
    let before = records(&s);
    assert_eq!(
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
        Err(CoreError::DamagedItem(ids[1]))
    );
    assert_eq!(stored(&s), file_before);
    assert_eq!(records(&s), before);
    assert_eq!(s.check_password(&pw(PW)), Ok(()));
    assert_eq!(s.check_password(&pw(NEW_PW)), Err(CoreError::WrongPassword));
}

#[test]
fn export_damaged_record_stops() {
    let (mut s, ids) = with_three();
    corrupt_record(&mut s, 2);
    assert_eq!(
        s.export_json(&pw(PW)).map(|_| ()),
        Err(CoreError::DamagedItem(ids[2]))
    );
    assert_eq!(
        s.export_csv(&pw(PW)).map(|_| ()),
        Err(CoreError::DamagedItem(ids[2]))
    );
}

#[test]
fn damaged_record_reveal_is_damaged_item() {
    let (mut s, ids) = with_three();
    corrupt_record(&mut s, 0);
    assert_eq!(
        s.reveal(ids[0], SecretSlot::Password).map(|_| ()),
        Err(CoreError::DamagedItem(ids[0]))
    );
    assert!(matches!(
        s.open_item(ids[0]),
        Err(CoreError::DamagedItem(id)) if id == ids[0]
    ));
    // The public part and the other items stay readable.
    assert_eq!(s.entry(ids[0]).unwrap().title(), "a");
    assert_eq!(password_of(&s, ids[1]), "pw-EXAMPLE-b");
}

#[test]
fn edit_at_max_generation_refused() {
    let (mut s, ids) = with_three();
    {
        let st = &mut s.unlocked_mut().unwrap().state;
        st.index.entries[0].record.generation = u64::MAX;
        st.records[0].generation = u64::MAX;
    }
    let before = records(&s);
    assert_eq!(
        s.update_item(ids[0], login("a", "other")),
        Err(CoreError::GenerationExhausted(ids[0]))
    );
    assert_eq!(records(&s), before);
}

#[test]
fn backup_reuses_record_bytes() {
    let (mut s, _) = with_three();
    let mut dest = MemStore::default();
    s.save_backup(&mut dest).unwrap();
    let copy = open_file(&dest.bytes.clone().unwrap(), PW);
    assert_eq!(copy.records, records(&s));
    assert_ne!(
        dest.bytes.unwrap(),
        stored(&s),
        "the index has a fresh nonce"
    );
}

// ------------------------------------------------------------------- migration

fn migrate_and_check(body: Vec<u8>, expected: Vec<Item>) {
    let file = v1_file(&body);
    let mut s = v1_session(file.clone());
    assert_holds(&s, expected);
    assert!(!s.is_dirty());
    assert_eq!(stored(&s), file, "nothing written before the first save");
    // The first save writes v2; a fresh session opens it with no migration.
    s.save().unwrap();
    assert!(!s.migration_pending());
    let v2 = stored(&s);
    assert!(matches!(parse_any(&v2).unwrap(), ParsedHeader::V2(..)));
    let (mut again, _) = session();
    again.store.bytes = Some(v2);
    again.unlock(&pw(PW)).unwrap();
    assert!(!again.migration_pending());
}

#[test]
fn migration_v3_to_v4_any() {
    // Body schema 3 (custom fields and recovery codes) becomes index schema 4.
    let body = data_with(fixture_items()).encode().unwrap();
    migrate_and_check(body.expose().to_vec(), fixture_items());
}

#[test]
fn migration_from_v1_and_v2_bodies() {
    let v1 = encode_v1_for_test(&data_with(plain_items()));
    migrate_and_check(v1.expose().to_vec(), plain_items());
    let v2 = encode_v2_for_test(&data_with(items_without_codes()));
    migrate_and_check(v2, items_without_codes());
}

#[test]
fn migration_rewraps_under_v2_aad() {
    let file = v1_current(plain_items());
    let ParsedHeader::V1(h, _) = parse_any(&file).unwrap() else {
        panic!("not v1")
    };
    let kek = derive_kek(&pw(PW), &h.salt, &h.kdf).unwrap();
    let (old_keys, plain) = envelope::open_with_kek(&file, &kek).unwrap();
    let data = VaultData::decode(plain.expose()).unwrap();
    let m = migrate::v1_to_v2(derive_kek(&pw(PW), &h.salt, &h.kdf).unwrap(), &h, data).unwrap();
    let new = m.keys.header();
    // A new data key, a new wrap nonce and a new wrap; the salt and costs carry over.
    assert_ne!(old_keys.dek().expose(), m.keys.dek().expose());
    assert_ne!(new.wrap_nonce, h.wrap_nonce);
    assert_ne!(new.wrapped_dek, h.wrapped_dek);
    assert_eq!(new.salt, h.salt);
    assert_eq!(new.kdf, h.kdf);
    assert!(envelope_v2::wrap_opens_to(&m.keys, &kek));
    assert_eq!(m.tag, tag_of(&file));
    assert!(m.records.iter().all(|r| r.generation == 1));
}

#[test]
fn v1_wrap_in_v2_header_fails() {
    // Same password, salt, costs, wrap nonce and wrap as a v1 file, in a v2 header: the
    // wrap was made under the v1 associated data, so it must not open.
    let (s, _) = created();
    let v2 = stored(&s);
    let ParsedHeader::V2(mut h, _, _) = parse_any(&v2).unwrap() else {
        panic!("not v2")
    };
    let v1 = v1_current(Vec::new());
    let ParsedHeader::V1(old, _) = parse_any(&v1).unwrap() else {
        panic!("not v1")
    };
    h.salt = old.salt;
    h.kdf = old.kdf;
    h.wrap_nonce = old.wrap_nonce;
    h.wrapped_dek = old.wrapped_dek;
    let mut forged = v2.clone();
    forged[..HeaderV2::encode(&h).len()].copy_from_slice(&h.encode());
    assert!(matches!(
        envelope_v2::open_v2(&forged, &pw(PW)),
        Err(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
    ));
}

#[test]
fn migration_lock_before_save_writes_nothing() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    assert!(!s.lock().discarded_unsaved);
    assert_eq!(stored(&s), file);
    assert!(s.store.backups.is_empty());
    assert_eq!(s.store.backup_calls, 0);
    // The v1 file still opens.
    s.unlock(&pw(PW)).unwrap();
    assert!(s.migration_pending());
}

#[test]
fn migration_backup_write_fails_vault_untouched() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    s.store.fail_backup_copy = Some(full());
    assert_eq!(s.add_item(login("n", "p")), Err(CoreError::MigrationFailed));
    assert_eq!(stored(&s), file);
    assert!(s.store.backups.is_empty());
    assert!(s.migration_pending());
    assert!(s.is_dirty());
    // Retry works once the backup can be written.
    s.save().unwrap();
    assert!(!s.migration_pending());
    assert_eq!(s.store.backups.get(&tag_of(&file)), Some(&file));
}

#[test]
fn migration_replace_fails_then_retry() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    s.store.fail_next_write = Some(full());
    assert_eq!(s.add_item(login("n", "p")), Err(CoreError::Store(full())));
    assert_eq!(stored(&s), file, "the v1 file is intact");
    assert!(s.migration_pending());
    assert_eq!(
        s.store.backups.len(),
        1,
        "the backup was kept before the replace"
    );
    s.save().unwrap();
    assert!(!s.migration_pending());
    assert_eq!(s.store.backups.len(), 1);
    assert_eq!(s.store.backup_calls, 2);
    assert!(matches!(
        parse_any(&stored(&s)).unwrap(),
        ParsedHeader::V2(..)
    ));
}

#[test]
fn migration_backup_exists_same_bytes() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    s.store.backups.insert(tag_of(&file), file.clone());
    s.save().unwrap();
    assert!(!s.migration_pending());
    assert_eq!(s.store.backups.get(&tag_of(&file)), Some(&file));
}

#[test]
fn migration_backup_exists_other_bytes_refuses() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    s.store
        .backups
        .insert(tag_of(&file), b"someone else".to_vec());
    assert_eq!(s.save(), Err(CoreError::MigrationFailed));
    assert_eq!(stored(&s), file);
    assert!(s.migration_pending());
    assert_eq!(
        s.store.backups.get(&tag_of(&file)).map(Vec::as_slice),
        Some(&b"someone else"[..])
    );
}

#[test]
fn migration_self_check_fails_writes_nothing() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    FAIL_SELF_CHECK.with(|f| f.set(true));
    assert_eq!(s.save(), Err(CoreError::MigrationFailed));
    assert_eq!(stored(&s), file);
    assert_eq!(s.store.backup_calls, 0, "no backup before the check passes");
    assert!(s.migration_pending());
    s.save().unwrap();
    assert!(!s.migration_pending());
}

#[test]
fn migration_note_persisted_in_first_v2_file() {
    let file = v1_current(plain_items());
    let tag = tag_of(&file);
    let mut s = v1_session(file);
    // A failed replace and a retry: the note is in the file that finally lands.
    s.store.fail_next_write = Some(full());
    assert!(s.save().is_err());
    s.save().unwrap();
    let state = open_file(&stored(&s), PW);
    let note = state.index.migration_backup.as_ref().unwrap();
    assert_eq!(note.tag, tag);
    assert_eq!(note.prompt, BackupPrompt::AfterUnlock);
    // And it is the same after a fresh unlock.
    s.lock();
    s.unlock(&pw(PW)).unwrap();
    let note = s.unlocked().unwrap().state.index.migration_backup.as_ref();
    assert_eq!(note.map(|n| n.tag.clone()), Some(tag));
}

#[test]
fn change_password_while_migration_pending() {
    let file = v1_current(plain_items());
    let tag = tag_of(&file);
    let mut s = v1_session(file.clone());
    s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap();
    assert!(!s.migration_pending());
    assert_eq!(s.store.backups.get(&tag), Some(&file));
    let state = open_file(&stored(&s), NEW_PW);
    let note = state.index.migration_backup.as_ref().unwrap();
    assert_eq!(note.tag, tag);
    assert_eq!(note.prompt, BackupPrompt::AfterPasswordChange);
    assert!(envelope_v2::open_v2(&stored(&s), &pw(PW)).is_err());
    assert_holds(&s, plain_items());
}

#[test]
fn uncertain_password_change_retry_keeps_stronger_note() {
    let file = v1_current(plain_items());
    let tag = tag_of(&file);
    let mut s = v1_session(file);
    s.store.fail_after_write = Some(full());
    assert_eq!(
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
        Err(CoreError::PasswordChangeUncertain(full()))
    );
    assert!(s.migration_pending());
    // The retry must not fall back to the weaker `AfterUnlock` prompt.
    s.save().unwrap();
    let state = open_file(&stored(&s), NEW_PW);
    let note = state.index.migration_backup.as_ref().unwrap();
    assert_eq!(note.tag, tag);
    assert_eq!(note.prompt, BackupPrompt::AfterPasswordChange);
}

#[test]
fn failed_password_change_puts_back_the_old_note() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file);
    // The first save lands the `AfterUnlock` note in memory, but the replace fails.
    s.store.fail_next_write = Some(full());
    assert!(s.save().is_err());
    // The password change fails at the backup copy: the note must not change.
    s.store.fail_backup_copy = Some(full());
    assert!(s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).is_err());
    let note = s.unlocked().unwrap().state.index.migration_backup.as_ref();
    assert_eq!(note.map(|n| n.prompt), Some(BackupPrompt::AfterUnlock));
}

#[test]
fn change_password_backup_fails_keeps_v1() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file.clone());
    s.store.fail_backup_copy = Some(full());
    assert_eq!(
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
        Err(CoreError::MigrationFailed)
    );
    assert_eq!(stored(&s), file);
    assert!(s.migration_pending());
    assert_eq!(s.check_password(&pw(PW)), Ok(()));
    assert_holds(&s, plain_items());
}

#[test]
fn import_while_migration_pending_takes_backup() {
    let file = v1_current(plain_items());
    let tag = tag_of(&file);
    let mut s = v1_session(file.clone());
    let csv = b"title,username,password,url,notes\nImported,me,EXAMPLE-imp-1,https://a.example,\n";
    let batch = parse(csv, ImportFormat::Csv).unwrap();
    let report = s.import(batch).unwrap();
    assert_eq!(report.imported, 1);
    assert!(!s.migration_pending());
    assert_eq!(s.store.backups.get(&tag), Some(&file));
    assert!(matches!(
        parse_any(&stored(&s)).unwrap(),
        ParsedHeader::V2(..)
    ));
    assert_eq!(s.stored_count(), 5);
}

#[test]
fn kdf_policy_precheck_v2_uncounted() {
    let (mut s, _) = created();
    s.lock();
    let mut file = stored(&s);
    let ParsedHeader::V2(mut h, _, _) = parse_any(&file).unwrap() else {
        panic!("not v2")
    };
    h.kdf.memory_kib = 2_097_152;
    file[..172].copy_from_slice(&h.encode());
    s.store.bytes = Some(file);
    assert!(matches!(
        s.unlock(&pw(PW)),
        Err(CoreError::Vault(VaultError::KdfPolicy(_)))
    ));
    assert_eq!(failures(&s), 0);
    assert!(!s.is_unlocked());
}

#[test]
fn newer_format_version_refused_untouched() {
    let (mut s, _) = created();
    s.lock();
    let mut file = stored(&s);
    file[8..10].copy_from_slice(&3u16.to_le_bytes());
    s.store.bytes = Some(file.clone());
    assert!(matches!(
        s.unlock(&pw(PW)),
        Err(CoreError::Vault(VaultError::Format(_)))
    ));
    assert!(!s.is_unlocked());
    assert_eq!(stored(&s), file, "the file is not touched");
    assert_eq!(s.store.backup_calls, 0);
}

#[test]
fn wrong_password_on_v1_is_not_a_migration_failure() {
    let mut s = {
        let (mut s, _) = session();
        s.store.bytes = Some(v1_current(plain_items()));
        s
    };
    assert_eq!(
        s.unlock(&pw(WRONG)),
        Err(CoreError::Vault(VaultError::WrongPasswordOrCorrupt))
    );
    assert_eq!(failures(&s), 1);
}

// ------------------------------------------------------------------ source checks

#[test]
fn only_write_gate_replaces() {
    // The only caller of `VaultStore::replace` in the session, import and export code.
    let session_src = include_str!("mod.rs");
    let live = session_src
        .split("#[cfg(test)]\nmod migration_tests;")
        .next()
        .unwrap();
    let needle = ["store", ".replace("].concat();
    assert_eq!(live.matches(&needle).count(), 1, "session/mod.rs");
    for (name, src) in [
        ("items.rs", include_str!("items.rs")),
        ("categories.rs", include_str!("categories.rs")),
        ("import/mod.rs", include_str!("../import/mod.rs")),
        ("export.rs", include_str!("../export.rs")),
        ("migrate.rs", include_str!("../migrate.rs")),
    ] {
        let live = src.split("#[cfg(test)]").next().unwrap();
        assert!(!live.contains(&needle), "{name} writes the store directly");
        assert!(
            !live.contains(".replace(&"),
            "{name} writes the store directly"
        );
    }
}

#[test]
fn resident_state_has_no_secret_marker() {
    let (mut s, _) = created();
    let marker = "EXAMPLE-RESIDENT-MARKER-zq9";
    let id = s.add_item(login("m", marker)).unwrap();
    let mut note = ItemInput {
        fields: Vec::new(),
        title: Text::new("note".to_owned()),
        category: None,
        favourite: false,
        data: ItemData::SecureNote {
            body: SecretText::new(format!("{marker}-body")),
        },
    };
    note.favourite = true;
    s.add_item(note).unwrap();
    // Open an item and drop it, then look at every resident buffer.
    drop(s.open_item(id).unwrap());
    assert_eq!(password_of(&s, id), marker);
    let resident = s.resident_bytes();
    assert!(!resident.is_empty());
    assert!(
        !resident
            .windows(marker.len())
            .any(|w| w == marker.as_bytes())
    );
    assert!(!format!("{s:?}").contains(marker));
}

#[test]
fn old_header_type_is_still_v1() {
    // `Header::encode` writes v1 (the version a v1 vault carries).
    let file = v1_current(Vec::new());
    let ParsedHeader::V1(h, _) = parse_any(&file).unwrap() else {
        panic!("not v1")
    };
    assert_eq!(Header::encode(&h)[8..10], 1u16.to_le_bytes());
}

// Backup prompts (spec 4.3, Q2).

fn saved_after_migration() -> (S, String) {
    let file = v1_current(plain_items());
    let tag = tag_of(&file);
    let mut s = v1_session(file);
    s.save().unwrap();
    (s, tag)
}

#[test]
fn backup_note_prompts() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file);
    // Nothing to ask while the migration is only in memory: no copy exists yet.
    assert_eq!(s.backup_prompt(), None);
    s.save().unwrap();
    assert_eq!(s.backup_prompt(), Some(BackupPrompt::AfterUnlock));
    // A vault that never migrated has no prompt.
    let (mut fresh, _) = session();
    fresh.create(&pw(PW), &FLOOR).unwrap();
    assert_eq!(fresh.backup_prompt(), None);
}

#[test]
fn backup_prompt_after_unlock() {
    let (mut s, tag) = saved_after_migration();
    s.dismiss_backup_prompt();
    assert_eq!(s.backup_prompt(), None);
    // Dismissing keeps the file and the note at the same step.
    assert!(s.store.backups.contains_key(&tag));
    s.lock();
    s.unlock(&pw(PW)).unwrap();
    assert_eq!(s.backup_prompt(), Some(BackupPrompt::AfterUnlock));
}

#[test]
fn backup_prompt_stronger_after_password_change() {
    let (mut s, tag) = saved_after_migration();
    s.dismiss_backup_prompt();
    s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap();
    // The stronger prompt shows at once, even after a dismissal, and the copy stays.
    assert_eq!(s.backup_prompt(), Some(BackupPrompt::AfterPasswordChange));
    assert!(s.store.backups.contains_key(&tag));
    s.lock();
    s.unlock(&pw(NEW_PW)).unwrap();
    assert_eq!(s.backup_prompt(), Some(BackupPrompt::AfterPasswordChange));
}

#[test]
fn backup_delete_clears_note() {
    let (mut s, tag) = saved_after_migration();
    s.delete_migration_backup().unwrap();
    assert!(!s.store.backups.contains_key(&tag));
    assert_eq!(s.backup_prompt(), None);
    // The note is `Done` in the file, so no later unlock asks again.
    let state = open_file(&stored(&s), PW);
    let note = state.index.migration_backup.as_ref().unwrap();
    assert_eq!(note.prompt, BackupPrompt::Done);
    s.lock();
    s.unlock(&pw(PW)).unwrap();
    assert_eq!(s.backup_prompt(), None);
}

#[test]
fn backup_missing_file_clears_note() {
    let (mut s, tag) = saved_after_migration();
    s.store.backups.remove(&tag);
    s.lock();
    s.unlock(&pw(PW)).unwrap();
    assert_eq!(s.backup_prompt(), None);
    assert!(s.unlocked().unwrap().state.index.migration_backup.is_none());
    // Deleting a copy that is already gone is not an error.
    s.delete_migration_backup().unwrap();
}

#[test]
fn backup_note_kept_unless_really_gone() {
    // The store cannot tell (or finds a symlink or folder, which it reports as
    // present): the note and the prompt stay.
    let (mut s, tag) = saved_after_migration();
    s.store.fail_backup_exists = Some(StoreError::Io(std::io::ErrorKind::PermissionDenied));
    s.lock();
    s.unlock(&pw(PW)).unwrap();
    assert_eq!(s.backup_prompt(), Some(BackupPrompt::AfterUnlock));
    assert!(s.unlocked().unwrap().state.index.migration_backup.is_some());
    assert!(s.store.backups.contains_key(&tag));
}

#[test]
fn backup_delete_then_save_fails_keeps_done_in_memory() {
    let (mut s, tag) = saved_after_migration();
    s.store.fail_next_write = Some(full());
    assert_eq!(s.delete_migration_backup(), Err(CoreError::Store(full())));
    // The copy is gone, the note says Done, and the save is still owed.
    assert!(!s.store.backups.contains_key(&tag));
    assert_eq!(s.backup_prompt(), None);
    assert!(s.is_dirty());
    s.save().unwrap();
    let state = open_file(&stored(&s), PW);
    assert_eq!(
        state.index.migration_backup.as_ref().unwrap().prompt,
        BackupPrompt::Done
    );
}

#[test]
fn backup_never_deleted_without_yes() {
    let (mut s, tag) = saved_after_migration();
    let calls = |s: &S| s.store.backups.contains_key(&tag);
    // Unlock, lock, edits, dismiss, password change and save never remove the copy.
    s.dismiss_backup_prompt();
    s.save().unwrap();
    s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap();
    s.lock();
    s.unlock(&pw(NEW_PW)).unwrap();
    assert!(calls(&s));
    // Only the explicit yes removes it.
    s.delete_migration_backup().unwrap();
    assert!(!calls(&s));
}

#[test]
fn backup_delete_while_migration_pending_does_nothing() {
    let file = v1_current(plain_items());
    let mut s = v1_session(file);
    s.delete_migration_backup().unwrap();
    assert!(s.migration_pending());
    assert!(s.store.backups.is_empty());
}
