//! The vault session: create, unlock, save, lock and change the password.
//!
//! [`Session`] holds the store, the clock, the unlock throttle and, while unlocked, the
//! keys and the vault state. It is the only place those meet. The state is the sealed
//! form: the index (public data and presence flags) and one sealed record per item. No
//! secret is resident; a secret is opened from its record for one call and wiped after.
//! Locking drops the unlocked state, which wipes the data key.
//!
//! Item, search, import and export operations live in sibling modules as further
//! `impl Session` blocks. They reach the unlocked state only through the `pub(crate)`
//! helpers here (`unlocked`, `unlocked_mut`, `commit`, `check_password` and
//! `now_unix`).
//!
//! # The write gate
//!
//! [`Session::write_gate`] is the one function that calls [`VaultStore::replace`]. While
//! a version 1 vault has been migrated in memory but not yet saved, the gate first keeps
//! a backup copy of the v1 bytes; if that fails, nothing is replaced (spec 4).

use core::fmt;
use std::time::Duration;

use holm_crypto::kdf::{KdfParams, derive_kek};
use holm_crypto::{MasterPassword, SecretKey};

use crate::body::VaultData;
use crate::clock::{Clock, IdleTimer};
use crate::envelope::{self, VaultError};
use crate::envelope_v2::{self, KeysV2, SealedRecord};
use crate::error::CoreError;
use crate::format::{FormatError, Header, ParsedHeader, parse_any};
use crate::index::{BackupNote, BackupPrompt, Index, RecordRef};
use crate::item::Timestamp;
use crate::migrate;
use crate::store::{StoreError, VaultStore};
use crate::strength;
use crate::throttle::{Throttle, ThrottleStatus, Throttled};

mod categories;
pub(crate) mod items;

#[cfg(test)]
thread_local! {
    /// Test hook: make the migration self-check fail once.
    pub(crate) static FAIL_SELF_CHECK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// The sealed form of an open vault: keys, index and one sealed record per index entry,
/// in the same order. Dropping it wipes the data key.
pub(crate) struct VaultState {
    /// The data key and current header.
    pub(crate) keys: KeysV2,
    /// Public data and presence flags.
    pub(crate) index: Index,
    /// `records[i]` is the sealed record of `index.entries[i]`.
    pub(crate) records: Vec<SealedRecord>,
}

impl VaultState {
    /// Builds the file for the current state. See [`envelope_v2::assemble`].
    fn assemble(&mut self) -> Result<Vec<u8>, VaultError> {
        let refs: Vec<&SealedRecord> = self.records.iter().collect();
        envelope_v2::assemble(&mut self.keys, &self.index, &refs)
    }
}

/// The version 1 file a migration started from, kept until the first v2 write is safe.
pub(crate) struct V1Origin {
    /// The v1 file bytes (ciphertext), for the backup copy.
    pub(crate) bytes: Vec<u8>,
    /// The backup tag.
    pub(crate) tag: String,
}

/// The state of an unlocked vault. Dropping it wipes the data key.
pub(crate) struct Unlocked {
    /// Keys, index and sealed records.
    pub(crate) state: VaultState,
    /// True when `state` has changes that are not on disk.
    pub(crate) dirty: bool,
    /// Time since the last user activity, for auto-lock.
    pub(crate) idle: IdleTimer,
    /// Set while the vault was a v1 file that has not been saved as v2 yet.
    pub(crate) migration: Option<V1Origin>,
}

/// What [`Session::lock`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockOutcome {
    /// True if there were unsaved changes, now discarded.
    pub discarded_unsaved: bool,
}

/// One vault: its store, a clock, the unlock throttle and, while unlocked, its keys
/// and sealed state.
///
/// The throttle lives here, not in the unlocked state, so it survives lock and unlock
/// (spec section 11). `Debug` prints only whether the vault is unlocked.
pub struct Session<S: VaultStore> {
    store: S,
    clock: Box<dyn Clock>,
    throttle: Throttle,
    open: Option<Unlocked>,
}

impl<S: VaultStore> fmt::Debug for Session<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("unlocked", &self.open.is_some())
            .finish_non_exhaustive()
    }
}

/// Seconds left in a throttle wait, rounded up, so the UI never says "0 s" while
/// an attempt would still be refused.
fn ceil_secs(d: Duration) -> u64 {
    let extra = u64::from(d.subsec_nanos() > 0);
    d.as_secs().saturating_add(extra)
}

/// Turns a throttle outcome into the session error.
fn from_throttled(t: Throttled<CoreError>) -> CoreError {
    match t {
        Throttled::Wait(d) => CoreError::Throttled {
            retry_after_secs: ceil_secs(d),
        },
        Throttled::Failed(e) => e,
    }
}

/// A store's "already exists" means a vault or backup is already there.
fn map_create_error(e: StoreError) -> CoreError {
    match e {
        StoreError::AlreadyExists => CoreError::VaultExists,
        other => CoreError::Store(other),
    }
}

/// Refuses a master password below the strength policy.
fn require_strong(password: &MasterPassword) -> Result<(), CoreError> {
    let verdict = strength::check(password).verdict;
    if verdict.acceptable {
        Ok(())
    } else {
        Err(CoreError::WeakPassword(verdict))
    }
}

/// Why the write gate did not replace the file.
enum GateError {
    /// The migration backup copy could not be kept; nothing was replaced.
    Backup,
    /// [`VaultStore::replace`] failed.
    Replace(StoreError),
}

impl From<GateError> for CoreError {
    fn from(e: GateError) -> CoreError {
        match e {
            GateError::Backup => CoreError::MigrationFailed,
            GateError::Replace(e) => CoreError::Store(e),
        }
    }
}

/// What the first unlock of a file produced.
enum Loaded {
    V1 {
        kek: SecretKey,
        header: Header,
        data: VaultData,
        bytes: Vec<u8>,
    },
    V2(VaultState),
}

/// The records' total ciphertext length, as the index pins it, as a `u32`.
fn ref_of(sealed: &SealedRecord) -> Result<RecordRef, CoreError> {
    let ct_len =
        u32::try_from(sealed.ct.len()).map_err(|_| CoreError::Vault(VaultError::Crypto))?;
    Ok(RecordRef {
        generation: sealed.generation,
        nonce: sealed.nonce,
        ct_len,
    })
}

impl<S: VaultStore> Session<S> {
    /// A locked session over `store`, with a fresh throttle.
    #[must_use]
    pub fn new(store: S, clock: Box<dyn Clock>) -> Session<S> {
        Session {
            store,
            clock,
            throttle: Throttle::new(),
            open: None,
        }
    }

    /// Creates a new vault with the default data and leaves it **unlocked** and clean.
    ///
    /// Order: the session must be locked, then the strength check (before any Argon2
    /// work or store call), then the keys and the file, then [`VaultStore::create_new`],
    /// which never overwrites. The throttle is not touched.
    ///
    /// # Errors
    /// [`CoreError::AlreadyUnlocked`], [`CoreError::WeakPassword`],
    /// [`CoreError::Vault`] (for example a cost policy error), [`CoreError::Body`],
    /// [`CoreError::VaultExists`] if a file is already there, or [`CoreError::Store`].
    /// A store error from the final directory sync comes after the file was written
    /// in full: the session stays locked, and a retry reports `VaultExists`, so the
    /// caller should unlock the file instead.
    pub fn create(
        &mut self,
        password: &MasterPassword,
        params: &KdfParams,
    ) -> Result<(), CoreError> {
        if self.open.is_some() {
            return Err(CoreError::AlreadyUnlocked);
        }
        require_strong(password)?;
        let keys = envelope_v2::create_keys(password, params)?;
        let mut state = VaultState {
            keys,
            index: Index::new_default(),
            records: Vec::new(),
        };
        let file = state.assemble()?;
        self.store.create_new(&file).map_err(map_create_error)?;
        self.open = Some(Unlocked {
            state,
            dirty: false,
            idle: IdleTimer::new(self.clock.as_ref()),
            migration: None,
        });
        Ok(())
    }

    /// Unlocks the vault with `password`.
    ///
    /// Order: the session must be locked; stale temp files are removed; a throttle
    /// wait refuses the attempt without reading anything; then the file is read,
    /// opened and decoded inside [`Throttle::attempt`].
    ///
    /// Every error inside the attempt counts as a failure (F16), and only success
    /// resets the count. Two errors are decided before the attempt and are **not**
    /// counted, because neither runs Argon2, so no password is tested:
    /// - no vault file ([`CoreError::NoVault`]);
    /// - key-derivation costs outside the policy ([`VaultError::KdfPolicy`]), found
    ///   by the header parser on public bytes (format v1 or v2).
    ///
    /// Every other error is counted, including other format errors, store errors
    /// and body errors (`docs/DECISIONS.md`, throttle).
    ///
    /// A version 1 file is migrated in memory after the attempt (spec 4): a new data
    /// key, one sealed record per item. Nothing is written until the first save, which
    /// keeps a backup copy of the v1 file first. A migration failure is
    /// [`CoreError::MigrationFailed`]; it is not a password failure and is not counted,
    /// and the session stays locked.
    ///
    /// # Errors
    /// [`CoreError::AlreadyUnlocked`], [`CoreError::Throttled`],
    /// [`CoreError::NoVault`], [`CoreError::Store`], [`CoreError::Vault`] (with
    /// [`VaultError::WrongPasswordOrCorrupt`] for a wrong password or a damaged
    /// file), [`CoreError::Body`], or [`CoreError::MigrationFailed`].
    pub fn unlock(&mut self, password: &MasterPassword) -> Result<(), CoreError> {
        if self.open.is_some() {
            return Err(CoreError::AlreadyUnlocked);
        }
        // Cleanup must never block unlock (Security decision, durable writes), so
        // its error is dropped on purpose.
        #[expect(
            clippy::redundant_pattern_matching,
            reason = "the brief asks for an explicit if-let so the discard is visible"
        )]
        if let Err(_) = self.store.remove_stale_temps() {
            // Nothing to do: a stale temp file is harmless and is retried next unlock.
        }
        let now = self.clock.monotonic();
        if let Some(wait) = self.throttle.status(now).retry_after {
            return Err(CoreError::Throttled {
                retry_after_secs: ceil_secs(wait),
            });
        }
        let read = self.store.read();
        // The two uncounted cases (see the doc comment above). Both return before
        // any key is derived.
        if read == Err(StoreError::NotFound) {
            return Err(CoreError::NoVault);
        }
        if let Ok(bytes) = &read
            && let Err(FormatError::KdfPolicy(k)) = parse_any(bytes)
        {
            return Err(CoreError::Vault(VaultError::KdfPolicy(k)));
        }
        let loaded = self
            .throttle
            .attempt(now, || {
                let bytes = read?;
                load(bytes, password)
            })
            .map_err(from_throttled)?;
        let (state, migration) = match loaded {
            Loaded::V2(state) => (state, None),
            Loaded::V1 {
                kek,
                header,
                data,
                bytes,
            } => {
                let migrated = migrate::v1_to_v2(kek, &header, data)?;
                let state = VaultState {
                    keys: migrated.keys,
                    index: migrated.index,
                    records: migrated.records,
                };
                let origin = V1Origin {
                    bytes,
                    tag: migrated.tag,
                };
                (state, Some(origin))
            }
        };
        self.open = Some(Unlocked {
            state,
            dirty: false,
            idle: IdleTimer::new(self.clock.as_ref()),
            migration,
        });
        Ok(())
    }

    /// Locks the vault: drops (and so wipes) the keys and the state. Reports whether
    /// unsaved changes were discarded. Locking a locked session does nothing. A pending
    /// migration writes nothing.
    pub fn lock(&mut self) -> LockOutcome {
        let discarded_unsaved = self.open.take().is_some_and(|u| u.dirty);
        LockOutcome { discarded_unsaved }
    }

    /// True while the vault is unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.open.is_some()
    }

    /// True while the vault is a version 1 file that was opened and migrated in memory
    /// but not saved as version 2 yet.
    #[must_use]
    pub fn migration_pending(&self) -> bool {
        self.open.as_ref().is_some_and(|u| u.migration.is_some())
    }

    /// The throttle's failure count and wait, for the unlock screen.
    #[must_use]
    pub fn throttle_status(&self) -> ThrottleStatus {
        self.throttle.status(self.clock.monotonic())
    }

    /// Writes the vault to the store: builds the file with a fresh index nonce and
    /// replaces it. The dirty flag is cleared only if the write succeeds, so a failed
    /// save leaves the session dirty and the old file intact.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Vault`] (for example
    /// [`VaultError::TooLargeToSave`]), [`CoreError::MigrationFailed`], or
    /// [`CoreError::Store`].
    pub fn save(&mut self) -> Result<(), CoreError> {
        self.commit()
    }

    /// True if the vault is unlocked and has changes that are not on disk.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.unlocked().is_ok_and(|u| u.dirty)
    }

    /// Writes a copy of the vault, unsaved changes included, to `dest`. Never
    /// overwrites a file there. The session's own store and dirty flag are untouched.
    /// The copy reuses the sealed records byte for byte; only the index is sealed anew.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Vault`], [`CoreError::VaultExists`] if
    /// `dest` already has a file, or [`CoreError::Store`].
    pub fn save_backup(&mut self, dest: &mut dyn VaultStore) -> Result<(), CoreError> {
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        let file = open.state.assemble()?;
        // `assemble` stored the backup's header (its index nonce) in the keys. That is
        // harmless: the session's own file has another nonce, and every build draws a
        // fresh one, so no nonce is ever used twice.
        dest.create_new(&file).map_err(map_create_error)
    }

    /// Changes the master password.
    ///
    /// Order: `current` is checked through the throttle, then the strength of `new`,
    /// then new keys (new salt, costs and data key) are made and every record is opened
    /// with the old keys and sealed again with the new ones, one item in memory at a
    /// time. A damaged record stops the change with nothing written. The new file is
    /// written through the write gate. On success the state is swapped and the dirty flag
    /// cleared.
    ///
    /// A failed `replace` may still have left the new file in place (see its doc), so
    /// the file is read back. If it still holds the old bytes, the old keys stay and
    /// the old password keeps working in memory and on disk. Otherwise (new bytes,
    /// other bytes, or a failed read) the session adopts the new keys and records and
    /// marks itself dirty, so memory never stays on a password the disk may no longer
    /// use, and the next save writes the vault under the new password.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Throttled`], [`CoreError::WrongPassword`],
    /// [`CoreError::WeakPassword`], [`CoreError::Body`], [`CoreError::Vault`],
    /// [`CoreError::DamagedItem`], [`CoreError::GenerationExhausted`],
    /// [`CoreError::MigrationFailed`], [`CoreError::Store`] if the old file is known to
    /// be unchanged, or [`CoreError::PasswordChangeUncertain`] if the new password may
    /// now be needed.
    pub fn change_password(
        &mut self,
        current: &MasterPassword,
        new: &MasterPassword,
        params: &KdfParams,
    ) -> Result<(), CoreError> {
        self.check_password(current)?;
        require_strong(new)?;
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        let mut new_keys = envelope_v2::create_keys(new, params)?;
        // Seal every record under the new keys first. Nothing in `open` changes until
        // all of them succeeded, so a damaged record leaves the session as it was.
        let st = &open.state;
        let mut new_records: Vec<SealedRecord> = Vec::with_capacity(st.records.len());
        let mut new_refs: Vec<RecordRef> = Vec::with_capacity(st.records.len());
        for (entry, sealed) in st.index.entries.iter().zip(&st.records) {
            let generation = entry
                .record
                .generation
                .checked_add(1)
                .ok_or(CoreError::GenerationExhausted(entry.id()))?;
            let secrets = envelope_v2::open_record(&st.keys, sealed, entry)?;
            let resealed = envelope_v2::seal_record(&new_keys, &entry.id(), generation, &secrets)?;
            drop(secrets);
            new_refs.push(ref_of(&resealed)?);
            new_records.push(resealed);
        }
        // Point the entries at the new records. The old refs are kept to put back.
        let st = &mut open.state;
        let mut old_refs: Vec<RecordRef> = Vec::with_capacity(new_refs.len());
        for (entry, r) in st.index.entries.iter_mut().zip(new_refs) {
            old_refs.push(core::mem::replace(&mut entry.record, r));
        }
        // The note before this call, to put back with the old refs.
        let old_note = if let Some(origin) = &open.migration {
            st.index.migration_backup.replace(BackupNote {
                tag: origin.tag.clone(),
                prompt: BackupPrompt::AfterPasswordChange,
            })
        } else {
            None
        };
        let had_migration = open.migration.is_some();
        let restore = move |st: &mut VaultState, old_refs: Vec<RecordRef>| {
            for (entry, r) in st.index.entries.iter_mut().zip(old_refs) {
                entry.record = r;
            }
            if had_migration {
                st.index.migration_backup = old_note;
            }
        };
        let built = {
            let refs: Vec<&SealedRecord> = new_records.iter().collect();
            envelope_v2::assemble(&mut new_keys, &st.index, &refs)
        };
        let file = match built {
            Ok(file) => file,
            Err(e) => {
                restore(&mut open.state, old_refs);
                return Err(e.into());
            }
        };
        if open.migration.is_some()
            && let Err(e) = self_check(&new_keys, &file)
        {
            restore(&mut open.state, old_refs);
            return Err(e);
        }
        // The old file, to tell "unchanged" from "maybe changed" if `replace` fails.
        // A failed read here only means an unchanged file cannot be proven later.
        let before = self.store.read().ok();
        match Self::write_gate(&mut self.store, open, &file) {
            Ok(()) => {
                open.state.keys = new_keys;
                open.state.records = new_records;
                open.dirty = false;
                Ok(())
            }
            Err(GateError::Backup) => {
                restore(&mut open.state, old_refs);
                Err(CoreError::MigrationFailed)
            }
            Err(GateError::Replace(e)) => {
                let after = self.store.read().ok();
                if before.is_some() && after == before {
                    restore(&mut open.state, old_refs);
                    return Err(CoreError::Store(e));
                }
                open.state.keys = new_keys;
                open.state.records = new_records;
                open.dirty = true;
                Err(CoreError::PasswordChangeUncertain(e))
            }
        }
    }

    /// Records user activity, restarting the auto-lock timer. Does nothing when locked.
    pub fn note_activity(&mut self) {
        if let Some(open) = self.open.as_mut() {
            open.idle.touch(self.clock.as_ref());
        }
    }

    /// True once the vault has been idle for its auto-lock time. False when locked.
    #[must_use]
    pub fn idle_expired(&self) -> bool {
        self.unlocked().is_ok_and(|u| {
            u.idle
                .expired(self.clock.as_ref(), u.state.index.settings.auto_lock_secs)
        })
    }

    /// The store, for example to show where the vault lives.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Checks the password without changing the open vault or its idle timer.
    ///
    /// Uses the same throttle as unlocking and other password checks.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Throttled`], [`CoreError::WrongPassword`],
    /// or [`CoreError::Vault`].
    pub fn verify_password(&mut self, password: &MasterPassword) -> Result<(), CoreError> {
        self.check_password(password)
    }

    /// Checks `password` against the open vault, through the throttle.
    ///
    /// Every error counts as a failure (F16); success resets the count.
    ///
    /// # Errors
    /// [`CoreError::Locked`] (not counted), [`CoreError::Throttled`] (refused, not
    /// counted), [`CoreError::WrongPassword`], or [`CoreError::Vault`] for any other
    /// failure.
    pub(crate) fn check_password(&mut self, password: &MasterPassword) -> Result<(), CoreError> {
        let open = self.open.as_ref().ok_or(CoreError::Locked)?;
        let now = self.clock.monotonic();
        self.throttle
            .attempt(now, || {
                envelope_v2::verify_password(&open.state.keys, password).map_err(|e| match e {
                    VaultError::WrongPasswordOrCorrupt => CoreError::WrongPassword,
                    other => CoreError::Vault(other),
                })
            })
            .map_err(from_throttled)
    }

    /// The unlocked state.
    ///
    /// # Errors
    /// [`CoreError::Locked`] when locked.
    pub(crate) fn unlocked(&self) -> Result<&Unlocked, CoreError> {
        self.open.as_ref().ok_or(CoreError::Locked)
    }

    /// The unlocked state, for changes. Call [`Session::commit`] after a change.
    ///
    /// # Errors
    /// [`CoreError::Locked`] when locked.
    pub(crate) fn unlocked_mut(&mut self) -> Result<&mut Unlocked, CoreError> {
        self.open.as_mut().ok_or(CoreError::Locked)
    }

    /// Wall-clock time from the session's clock, for item timestamps.
    pub(crate) fn now_unix(&self) -> Timestamp {
        self.clock.now_unix()
    }

    /// The only place that replaces the vault file.
    ///
    /// While `open.migration` is set, the v1 bytes are first kept as a backup copy
    /// (idempotent for the same bytes, refused for other bytes). If that fails, nothing
    /// is replaced. After a good replace the migration is done.
    fn write_gate(store: &mut S, open: &mut Unlocked, bytes: &[u8]) -> Result<(), GateError> {
        if let Some(origin) = &open.migration {
            store
                .keep_backup_copy(&origin.tag, &origin.bytes)
                .map_err(|_| GateError::Backup)?;
        }
        store.replace(bytes).map_err(GateError::Replace)?;
        open.migration = None;
        Ok(())
    }

    /// Saves the current state: marks the session dirty, builds the file with a fresh
    /// index nonce, and replaces the file through the write gate. The dirty flag is
    /// cleared only if the write succeeds, so a failed save leaves the session dirty
    /// and the old file intact.
    ///
    /// For a pending migration the index first gets the backup note (spec 4.3), the
    /// file is read back with the in-memory keys as a self-check, and the gate keeps the
    /// v1 backup copy before the replace.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Vault`] (for example
    /// [`VaultError::TooLargeToSave`]), [`CoreError::MigrationFailed`], or
    /// [`CoreError::Store`].
    pub(crate) fn commit(&mut self) -> Result<(), CoreError> {
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        open.dirty = true;
        // Only the first save of a migration sets the note; a retry after a password
        // change must keep the stronger `AfterPasswordChange` prompt.
        if let Some(origin) = &open.migration
            && open.state.index.migration_backup.is_none()
        {
            open.state.index.migration_backup = Some(BackupNote {
                tag: origin.tag.clone(),
                prompt: BackupPrompt::AfterUnlock,
            });
        }
        let file = open.state.assemble()?;
        if open.migration.is_some() {
            self_check(&open.state.keys, &file)?;
        }
        Self::write_gate(&mut self.store, open, &file)?;
        open.dirty = false;
        Ok(())
    }

    /// Saves after a change, and takes the change back if the vault has no room for it.
    ///
    /// Call this after applying a change. `undo` must put the state back exactly as it
    /// was. On [`VaultError::TooLargeToSave`] nothing was written and `undo` runs; the
    /// dirty flag goes back to what it was before the call, so an earlier unsaved edit
    /// stays unsaved and is still reported on lock. Any other error keeps the change
    /// and leaves the session dirty, so a later [`Session::save`] can retry.
    ///
    /// # Errors
    /// The errors of [`Session::commit`].
    pub(crate) fn commit_or_undo(
        &mut self,
        undo: impl FnOnce(&mut VaultState),
    ) -> Result<(), CoreError> {
        let was_dirty = self.unlocked()?.dirty;
        match self.commit() {
            Err(CoreError::Vault(VaultError::TooLargeToSave)) => {
                let open = self.unlocked_mut()?;
                undo(&mut open.state);
                open.dirty = was_dirty;
                Err(CoreError::Vault(VaultError::TooLargeToSave))
            }
            other => other,
        }
    }

    /// Every resident buffer joined, for the memory test (spec 7.6): the encoded index
    /// (which holds all public data), every sealed record and the header.
    #[cfg(test)]
    pub(crate) fn resident_bytes(&self) -> Vec<u8> {
        let Ok(open) = self.unlocked() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Ok(index) = open.state.index.encode() {
            out.extend_from_slice(index.expose());
        }
        for r in &open.state.records {
            out.extend_from_slice(&r.ct);
        }
        out.extend_from_slice(&open.state.keys.header().encode());
        out
    }
}

/// Reads the file back with the in-memory keys: the migration self-check (spec 4.4).
fn self_check(keys: &KeysV2, file: &[u8]) -> Result<(), CoreError> {
    #[cfg(test)]
    if FAIL_SELF_CHECK.with(|f| f.replace(false)) {
        return Err(CoreError::MigrationFailed);
    }
    envelope_v2::read_back(keys, file)
        .map(|_| ())
        .map_err(|_| CoreError::MigrationFailed)
}

/// Opens a vault file of either version. Runs inside the throttle attempt.
fn load(bytes: Vec<u8>, password: &MasterPassword) -> Result<Loaded, CoreError> {
    match parse_any(&bytes).map_err(VaultError::from)? {
        ParsedHeader::V1(header, _) => {
            let kek = derive_kek(password, &header.salt, &header.kdf).map_err(VaultError::from)?;
            let (_old_keys, plaintext) = envelope::open_with_kek(&bytes, &kek)?;
            let data = VaultData::decode(plaintext.expose())?;
            Ok(Loaded::V1 {
                kek,
                header,
                data,
                bytes,
            })
        }
        ParsedHeader::V2(..) => {
            let (keys, index, records) = envelope_v2::open_v2(&bytes, password)?;
            Ok(Loaded::V2(VaultState {
                keys,
                index,
                records,
            }))
        }
    }
}

#[cfg(test)]
mod migration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use crate::store::MemStore;
    use crate::throttle::FREE_FAILURES;
    use holm_crypto::KdfParamsError;
    use std::io::ErrorKind;

    pub(super) const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
    pub(super) const NEW_PW: &str = "Quokka-Sextant-velvet-EXAMPLE-ember-71";
    pub(super) const WRONG: &str = "not-the-Right-password-EXAMPLE-0";
    pub(super) const FLOOR: KdfParams = KdfParams::FLOOR;

    pub(super) fn pw(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_owned())
    }

    pub(super) fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    pub(super) fn session() -> (Session<MemStore>, FakeClock) {
        let clock = FakeClock::default();
        clock.set_unix(1_700_000_000);
        (
            Session::new(MemStore::default(), Box::new(clock.clone())),
            clock,
        )
    }

    /// A session with a fresh vault, left unlocked.
    pub(super) fn created() -> (Session<MemStore>, FakeClock) {
        let (mut s, clock) = session();
        s.create(&pw(PW), &FLOOR).unwrap();
        (s, clock)
    }

    /// A session with a fresh vault, locked.
    pub(super) fn created_locked() -> (Session<MemStore>, FakeClock) {
        let (mut s, clock) = created();
        s.lock();
        (s, clock)
    }

    pub(super) fn failures(s: &Session<MemStore>) -> u32 {
        s.throttle_status().consecutive_failures
    }

    pub(super) fn stored(s: &Session<MemStore>) -> Vec<u8> {
        s.store().bytes.clone().unwrap()
    }

    /// Opens a v2 vault file with `password` into its sealed state (no record opened).
    pub(super) fn open_file(file: &[u8], password: &str) -> VaultState {
        let (keys, index, records) = envelope_v2::open_v2(file, &pw(password)).unwrap();
        VaultState {
            keys,
            index,
            records,
        }
    }

    const OPAQUE: CoreError = CoreError::Vault(VaultError::WrongPasswordOrCorrupt);

    #[test]
    fn test_passwords_pass_the_strength_check() {
        for p in [PW, NEW_PW, WRONG] {
            assert!(strength::check(&pw(p)).verdict.acceptable, "{p}");
        }
    }

    #[test]
    fn create_then_unlock_roundtrip() {
        let (mut s, _) = created();
        assert!(s.is_unlocked());
        assert!(!s.is_dirty());
        assert_eq!(failures(&s), 0);
        assert_eq!(s.store().temp_cleanups, 0);
        assert_eq!(
            s.lock(),
            LockOutcome {
                discarded_unsaved: false
            }
        );
        assert!(!s.is_unlocked());
        s.unlock(&pw(PW)).unwrap();
        assert!(s.is_unlocked());
        assert!(!s.is_dirty());
        assert_eq!(s.unlocked().unwrap().state.index.entries.len(), 0);
    }

    #[test]
    fn create_refuses_weak_password_before_any_work() {
        let (mut s, _) = session();
        assert!(matches!(
            s.create(&pw("password1234"), &FLOOR),
            Err(CoreError::WeakPassword(v)) if !v.acceptable
        ));
        // Costs below the floor would fail in the envelope with `KdfPolicy`. Getting
        // `WeakPassword` shows the strength check runs first.
        let below = KdfParams {
            memory_kib: FLOOR.memory_kib - 1,
            ..FLOOR
        };
        assert!(matches!(
            s.create(&pw("password1234"), &below),
            Err(CoreError::WeakPassword(_))
        ));
        assert_eq!(s.store().bytes, None);
        assert!(!s.is_unlocked());
    }

    #[test]
    fn create_refuses_existing_vault() {
        let (mut s, _) = session();
        s.store.bytes = Some(b"existing".to_vec());
        assert_eq!(s.create(&pw(PW), &FLOOR), Err(CoreError::VaultExists));
        assert_eq!(s.store().bytes.as_deref(), Some(&b"existing"[..]));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn create_and_unlock_refused_while_unlocked() {
        let (mut s, _) = created();
        assert_eq!(s.create(&pw(PW), &FLOOR), Err(CoreError::AlreadyUnlocked));
        assert_eq!(s.unlock(&pw(PW)), Err(CoreError::AlreadyUnlocked));
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn unlock_wrong_password_counts_failure() {
        let (mut s, _) = created_locked();
        assert_eq!(s.unlock(&pw(WRONG)), Err(OPAQUE));
        assert_eq!(failures(&s), 1);
        assert!(!s.is_unlocked());
    }

    #[test]
    fn fourth_try_inside_delay_is_throttled() {
        let (mut s, clock) = created_locked();
        for _ in 0..FREE_FAILURES {
            assert_eq!(s.unlock(&pw(WRONG)), Err(OPAQUE));
        }
        clock.advance(secs(1));
        // Refused without running: even the right password is not tried.
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Throttled {
                retry_after_secs: 1
            })
        );
        assert_eq!(failures(&s), 3);
        assert!(!s.is_unlocked());
        clock.advance(secs(1));
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn throttle_wait_is_rounded_up() {
        let (mut s, clock) = created_locked();
        for _ in 0..FREE_FAILURES {
            let _ = s.unlock(&pw(WRONG));
        }
        clock.advance(Duration::from_millis(500));
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Throttled {
                retry_after_secs: 2
            })
        );
    }

    #[test]
    fn throttle_ignores_wall_clock_jump() {
        let (mut s, clock) = created_locked();
        for _ in 0..FREE_FAILURES {
            let _ = s.unlock(&pw(WRONG));
        }
        clock.set_unix(1_700_000_000 - 86_400);
        clock.advance(secs(1));
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Throttled {
                retry_after_secs: 1
            })
        );
        assert_eq!(failures(&s), 3);
    }

    #[test]
    fn success_resets_throttle() {
        let (mut s, _) = created_locked();
        for _ in 0..2 {
            assert_eq!(s.unlock(&pw(WRONG)), Err(OPAQUE));
        }
        assert_eq!(failures(&s), 2);
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(
            s.throttle_status(),
            ThrottleStatus {
                consecutive_failures: 0,
                retry_after: None
            }
        );
    }

    #[test]
    fn throttle_survives_lock() {
        let (mut s, _) = created();
        assert_eq!(s.check_password(&pw(WRONG)), Err(CoreError::WrongPassword));
        assert_eq!(failures(&s), 1);
        s.lock();
        assert_eq!(s.unlock(&pw(WRONG)), Err(OPAQUE));
        assert_eq!(failures(&s), 2);
    }

    #[test]
    fn check_password_right_resets_and_locked_is_not_counted() {
        let (mut s, _) = created();
        assert_eq!(s.check_password(&pw(WRONG)), Err(CoreError::WrongPassword));
        assert_eq!(s.check_password(&pw(PW)), Ok(()));
        assert_eq!(failures(&s), 0);
        s.lock();
        assert_eq!(s.check_password(&pw(PW)), Err(CoreError::Locked));
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn verify_password_keeps_the_open_session() {
        let (mut s, clock) = created();
        let before = s.store.read().unwrap();
        let data = s.unlocked().unwrap().state.index.encode().unwrap();
        clock.advance(secs(300));
        assert!(s.idle_expired());
        for _ in 0..3 {
            assert_eq!(s.verify_password(&pw(WRONG)), Err(CoreError::WrongPassword));
        }
        assert!(matches!(
            s.verify_password(&pw(PW)),
            Err(CoreError::Throttled { .. })
        ));
        clock.advance(secs(2));
        assert_eq!(s.verify_password(&pw(PW)), Ok(()));
        assert_eq!(failures(&s), 0);
        assert!(s.is_unlocked());
        assert!(!s.is_dirty());
        assert!(s.idle_expired());
        assert_eq!(s.store.read().unwrap(), before);
        assert!(s.unlocked().unwrap().state.index.encode().unwrap().expose() == data.expose());
        s.lock();
        assert_eq!(s.verify_password(&pw(PW)), Err(CoreError::Locked));
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn missing_file_is_no_vault_and_not_counted() {
        let (mut s, _) = session();
        for _ in 0..5 {
            assert_eq!(s.unlock(&pw(PW)), Err(CoreError::NoVault));
        }
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn tampered_file_counts_as_failure() {
        let (mut s, _) = created_locked();
        let mut file = stored(&s);
        let last = file.len() - 1;
        file[last] ^= 0x01;
        s.store.bytes = Some(file.clone());
        assert_eq!(s.unlock(&pw(PW)), Err(OPAQUE));
        assert_eq!(failures(&s), 1);
        // A format error is counted too: only the two listed exceptions are not.
        file[0] ^= 0x01;
        s.store.bytes = Some(file);
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Vault(VaultError::Format(FormatError::BadMagic)))
        );
        assert_eq!(failures(&s), 2);
    }

    #[test]
    fn store_error_counts_as_failure() {
        let (mut s, _) = created_locked();
        let big = vec![0u8; crate::format::MAX_FILE_LEN + 1];
        s.store.bytes = Some(big);
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Store(StoreError::TooLarge))
        );
        assert_eq!(failures(&s), 1);
    }

    #[test]
    fn policy_error_not_counted() {
        let (mut s, _) = created_locked();
        let mut file = stored(&s);
        file[16..20].copy_from_slice(&2_097_152u32.to_le_bytes());
        s.store.bytes = Some(file);
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Vault(VaultError::KdfPolicy(
                KdfParamsError::AboveCeiling
            )))
        );
        assert_eq!(failures(&s), 0);
    }

    #[test]
    fn newer_body_schema_reported() {
        let (mut s, _) = session();
        let (_, file) = envelope::create(&pw(PW), &FLOOR, &[4, 0]).unwrap();
        s.store.bytes = Some(file);
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Body(crate::body::BodyError::NewerSchema(4)))
        );
        assert_eq!(failures(&s), 1);
        assert!(!s.is_unlocked());
    }

    #[test]
    fn failed_save_keeps_file_and_retry_works() {
        let (mut s, _) = created();
        let before = stored(&s);
        s.unlocked_mut()
            .unwrap()
            .state
            .index
            .settings
            .auto_lock_secs = 600;
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        assert_eq!(
            s.save(),
            Err(CoreError::Store(StoreError::Io(ErrorKind::StorageFull)))
        );
        assert_eq!(stored(&s), before);
        assert_eq!(open_file(&before, PW).index.settings.auto_lock_secs, 300);
        assert!(s.is_dirty());
        s.save().unwrap();
        assert!(!s.is_dirty());
        assert_eq!(
            open_file(&stored(&s), PW).index.settings.auto_lock_secs,
            600
        );
    }

    #[test]
    fn lock_reports_unsaved_and_locks() {
        let (mut s, _) = created();
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        assert!(s.save().is_err());
        assert!(s.is_dirty());
        assert_eq!(
            s.lock(),
            LockOutcome {
                discarded_unsaved: true
            }
        );
        assert!(!s.is_unlocked());
        assert!(!s.is_dirty());
        assert_eq!(s.save(), Err(CoreError::Locked));
        assert_eq!(
            s.lock(),
            LockOutcome {
                discarded_unsaved: false
            }
        );
    }

    #[test]
    fn change_password_rotates_and_requires_current() {
        let (mut s, _) = created();
        assert_eq!(
            s.change_password(&pw(WRONG), &pw(NEW_PW), &FLOOR),
            Err(CoreError::WrongPassword)
        );
        assert_eq!(failures(&s), 1);
        assert!(matches!(
            s.change_password(&pw(PW), &pw("password1234"), &FLOOR),
            Err(CoreError::WeakPassword(_))
        ));
        s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap();
        assert!(!s.is_dirty());
        s.lock();
        assert_eq!(s.unlock(&pw(PW)), Err(OPAQUE));
        s.unlock(&pw(NEW_PW)).unwrap();
    }

    #[test]
    fn change_password_write_failure_keeps_old_password() {
        let (mut s, _) = created();
        let before = stored(&s);
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        assert_eq!(
            s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
            Err(CoreError::Store(StoreError::Io(ErrorKind::StorageFull)))
        );
        assert_eq!(stored(&s), before);
        // In memory: the old keys are still in place.
        assert_eq!(s.check_password(&pw(PW)), Ok(()));
        assert_eq!(s.check_password(&pw(NEW_PW)), Err(CoreError::WrongPassword));
        // A save after the failure still uses the old password.
        s.save().unwrap();
        s.lock();
        assert_eq!(s.unlock(&pw(NEW_PW)), Err(OPAQUE));
        s.unlock(&pw(PW)).unwrap();
    }

    #[test]
    fn change_password_error_after_write_adopts_new_password() {
        let (mut s, _) = created();
        let before = stored(&s);
        s.store.fail_after_write = Some(StoreError::Io(ErrorKind::Other));
        let err = s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR).unwrap_err();
        assert_eq!(
            err,
            CoreError::PasswordChangeUncertain(StoreError::Io(ErrorKind::Other))
        );
        let text = err.to_string();
        assert!(text.contains("may still have been saved"), "{text}");
        assert!(
            text.contains("new master password may now be required"),
            "{text}"
        );
        assert_ne!(stored(&s), before, "the new file is in place");
        // In memory: the new keys, and the session is dirty.
        assert!(s.is_dirty());
        assert_eq!(s.check_password(&pw(NEW_PW)), Ok(()));
        assert_eq!(s.check_password(&pw(PW)), Err(CoreError::WrongPassword));
        // The next save writes under the new password again.
        s.save().unwrap();
        assert!(!s.is_dirty());
        s.lock();
        assert_eq!(s.unlock(&pw(PW)), Err(OPAQUE));
        s.unlock(&pw(NEW_PW)).unwrap();
    }

    #[test]
    fn change_password_error_with_unreadable_file_adopts_new_password() {
        let (mut s, _) = created();
        s.store.fail_after_write = Some(StoreError::Io(ErrorKind::Other));
        s.store.fail_reads = true;
        assert_eq!(
            s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
            Err(CoreError::PasswordChangeUncertain(StoreError::Io(
                ErrorKind::Other
            )))
        );
        assert!(s.is_dirty());
        assert_eq!(s.check_password(&pw(NEW_PW)), Ok(()));
        s.store.fail_reads = false;
        s.save().unwrap();
        s.lock();
        assert_eq!(s.unlock(&pw(PW)), Err(OPAQUE));
        s.unlock(&pw(NEW_PW)).unwrap();
    }

    #[test]
    fn change_password_replace_fail_and_readback_fail_adopts_new_keys() {
        let (mut s, _) = created();
        let before = stored(&s);
        // The read before the write works; `replace` fails and changes nothing; the
        // read-back after it fails, so "unchanged" cannot be proven.
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        s.store.fail_reads_after_failed_replace = true;
        assert_eq!(
            s.change_password(&pw(PW), &pw(NEW_PW), &FLOOR),
            Err(CoreError::PasswordChangeUncertain(StoreError::Io(
                ErrorKind::StorageFull
            )))
        );
        assert!(s.store().fail_reads, "the read-back failed");
        assert_eq!(s.store().bytes.as_deref(), Some(&before[..]));
        // In memory: the new keys, and the session is dirty.
        assert!(s.is_dirty());
        assert_eq!(s.check_password(&pw(NEW_PW)), Ok(()));
        assert_eq!(s.check_password(&pw(PW)), Err(CoreError::WrongPassword));
        // With the store working again, the next save writes under the new password.
        s.store.fail_reads_after_failed_replace = false;
        s.store.fail_reads = false;
        s.save().unwrap();
        assert!(!s.is_dirty());
        let file = stored(&s);
        assert_ne!(file, before);
        assert!(envelope_v2::open_v2(&file, &pw(PW)).is_err());
        let _ = open_file(&file, NEW_PW);
        s.lock();
        assert_eq!(s.unlock(&pw(PW)), Err(OPAQUE));
        s.unlock(&pw(NEW_PW)).unwrap();
    }

    #[test]
    fn backup_opens_with_same_password() {
        let (mut s, _) = created();
        let before = stored(&s);
        let open = s.unlocked_mut().unwrap();
        open.state.index.settings.auto_lock_secs = 600;
        open.dirty = true;
        let mut dest = MemStore::default();
        s.save_backup(&mut dest).unwrap();
        let backup = dest.bytes.clone().unwrap();
        assert_eq!(open_file(&backup, PW).index.settings.auto_lock_secs, 600);
        assert!(s.is_dirty(), "the session's dirty flag is untouched");
        assert_eq!(stored(&s), before, "the session's own file is untouched");
    }

    #[test]
    fn backup_never_overwrites() {
        let (mut s, _) = created();
        let mut dest = MemStore::default();
        s.save_backup(&mut dest).unwrap();
        let first = dest.bytes.clone().unwrap();
        assert_eq!(s.save_backup(&mut dest), Err(CoreError::VaultExists));
        assert_eq!(dest.bytes.unwrap(), first);
    }

    #[test]
    fn idle_expires_after_default_five_minutes() {
        let (mut s, clock) = created();
        clock.advance(secs(299));
        assert!(!s.idle_expired());
        clock.advance(secs(1));
        assert!(s.idle_expired());
        s.note_activity();
        assert!(!s.idle_expired());
        clock.advance(secs(300));
        assert!(s.idle_expired());
        s.lock();
        assert!(!s.idle_expired());
        s.note_activity();
    }

    #[test]
    fn unlock_removes_stale_temps() {
        let (mut s, _) = created_locked();
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(s.store().temp_cleanups, 1);
    }

    #[test]
    fn unlock_succeeds_when_temp_cleanup_fails() {
        let (mut s, _) = created_locked();
        s.store.fail_temp_cleanup = true;
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(s.store().temp_cleanups, 1);
    }

    #[test]
    fn now_unix_comes_from_the_clock() {
        let (s, clock) = session();
        clock.set_unix(42);
        assert_eq!(s.now_unix(), Timestamp(42));
    }

    #[test]
    fn debug_is_redacted() {
        let (s, _) = created();
        let text = format!("{s:?}");
        assert_eq!(text, "Session { unlocked: true, .. }");
    }

    static_assertions::assert_not_impl_any!(
        Session<MemStore>: Clone,
        serde::Serialize,
        serde::de::DeserializeOwned
    );
    static_assertions::assert_not_impl_any!(
        LockOutcome: serde::Serialize,
        serde::de::DeserializeOwned
    );
}
