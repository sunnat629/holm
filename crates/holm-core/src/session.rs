//! The vault session: create, unlock, save, lock and change the password.
//!
//! [`Session`] holds the store, the clock, the unlock throttle and, while unlocked, the
//! keys and the decrypted data. It is the only place those meet. Locking drops the
//! unlocked state, which wipes the data key and every item string.
//!
//! Item, search, import and export operations live in sibling modules as further
//! `impl Session` blocks. They reach the unlocked state only through the `pub(crate)`
//! helpers here (`unlocked`, `unlocked_mut`, `commit`, `check_password` and
//! `now_unix`).

use core::fmt;
use std::time::Duration;

use holm_crypto::MasterPassword;
use holm_crypto::kdf::KdfParams;

use crate::body::VaultData;
use crate::clock::{Clock, IdleTimer};
use crate::envelope::{self, VaultError, VaultKeys};
use crate::error::CoreError;
use crate::format::{FormatError, Header};
use crate::item::Timestamp;
use crate::store::{StoreError, VaultStore};
use crate::strength;
use crate::throttle::{Throttle, ThrottleStatus, Throttled};

/// The state of an unlocked vault. Dropping it wipes the data key and the data.
pub(crate) struct Unlocked {
    /// The data key and current header.
    pub(crate) keys: VaultKeys,
    /// The decrypted vault contents.
    pub(crate) data: VaultData,
    /// True when `data` has changes that are not on disk.
    pub(crate) dirty: bool,
    /// Time since the last user activity, for auto-lock.
    pub(crate) idle: IdleTimer,
}

/// What [`Session::lock`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockOutcome {
    /// True if there were unsaved changes, now discarded.
    pub discarded_unsaved: bool,
}

/// One vault: its store, a clock, the unlock throttle and, while unlocked, its keys
/// and data.
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
    /// work or store call), then the envelope, then [`VaultStore::create_new`], which
    /// never overwrites. The throttle is not touched.
    ///
    /// # Errors
    /// [`CoreError::AlreadyUnlocked`], [`CoreError::WeakPassword`],
    /// [`CoreError::Vault`] (for example a cost policy error), [`CoreError::Body`],
    /// [`CoreError::VaultExists`] if a file is already there, or [`CoreError::Store`].
    pub fn create(
        &mut self,
        password: &MasterPassword,
        params: &KdfParams,
    ) -> Result<(), CoreError> {
        if self.open.is_some() {
            return Err(CoreError::AlreadyUnlocked);
        }
        require_strong(password)?;
        let data = VaultData::new_default();
        // A `SecretBuf` (a `Zeroizing<Vec<u8>>`): the encoded body is wiped on drop.
        let body = data.encode()?;
        let (keys, file) = envelope::create(password, params, body.expose())?;
        drop(body);
        self.store.create_new(&file).map_err(map_create_error)?;
        self.open = Some(Unlocked {
            keys,
            data,
            dirty: false,
            idle: IdleTimer::new(self.clock.as_ref()),
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
    ///   by the header parser on public bytes.
    ///
    /// Every other error is counted, including other format errors, store errors
    /// and body errors (`docs/DECISIONS.md`, throttle).
    ///
    /// # Errors
    /// [`CoreError::AlreadyUnlocked`], [`CoreError::Throttled`],
    /// [`CoreError::NoVault`], [`CoreError::Store`], [`CoreError::Vault`] (with
    /// [`VaultError::WrongPasswordOrCorrupt`] for a wrong password or a damaged
    /// file), or [`CoreError::Body`].
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
            && let Err(FormatError::KdfPolicy(k)) = Header::parse(bytes)
        {
            return Err(CoreError::Vault(VaultError::KdfPolicy(k)));
        }
        let (keys, data) = self
            .throttle
            .attempt(now, || {
                let bytes = read?;
                let (keys, plaintext) = envelope::open(&bytes, password)?;
                let data = VaultData::decode(plaintext.expose())?;
                Ok((keys, data))
            })
            .map_err(from_throttled)?;
        self.open = Some(Unlocked {
            keys,
            data,
            dirty: false,
            idle: IdleTimer::new(self.clock.as_ref()),
        });
        Ok(())
    }

    /// Locks the vault: drops (and so wipes) the keys and the data. Reports whether
    /// unsaved changes were discarded. Locking a locked session does nothing.
    pub fn lock(&mut self) -> LockOutcome {
        let discarded_unsaved = self.open.take().is_some_and(|u| u.dirty);
        LockOutcome { discarded_unsaved }
    }

    /// True while the vault is unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.open.is_some()
    }

    /// The throttle's failure count and wait, for the unlock screen.
    #[must_use]
    pub fn throttle_status(&self) -> ThrottleStatus {
        self.throttle.status(self.clock.monotonic())
    }

    /// Writes the vault to the store: encodes the data, re-seals it under the same
    /// data key with a fresh nonce, and replaces the file. The dirty flag is cleared
    /// only if the write succeeds, so a failed save leaves the session dirty and the
    /// old file intact.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Body`], [`CoreError::Vault`] (for example
    /// [`VaultError::TooLargeToSave`]), or [`CoreError::Store`].
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
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Body`], [`CoreError::Vault`],
    /// [`CoreError::VaultExists`] if `dest` already has a file, or
    /// [`CoreError::Store`].
    pub fn save_backup(&mut self, dest: &mut dyn VaultStore) -> Result<(), CoreError> {
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        let body = open.data.encode()?;
        let file = envelope::reseal(&mut open.keys, body.expose())?;
        drop(body);
        dest.create_new(&file).map_err(map_create_error)
    }

    /// Changes the master password.
    ///
    /// Order: `current` is checked through the throttle, then the strength of `new`,
    /// then a whole new vault (new salt, costs, data key and nonces) is built with
    /// [`envelope::create`] and written with [`VaultStore::replace`]. Only after the
    /// write succeeds are the keys swapped and the dirty flag cleared, so a failed
    /// write leaves the old password working in memory and on disk.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Throttled`], [`CoreError::WrongPassword`],
    /// [`CoreError::WeakPassword`], [`CoreError::Body`], [`CoreError::Vault`], or
    /// [`CoreError::Store`].
    pub fn change_password(
        &mut self,
        current: &MasterPassword,
        new: &MasterPassword,
        params: &KdfParams,
    ) -> Result<(), CoreError> {
        self.check_password(current)?;
        require_strong(new)?;
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        let body = open.data.encode()?;
        // Not `envelope::rekey` (Security decision, `rekey`): it swaps the keys before
        // the caller writes, so a failed write would leave memory and disk on
        // different passwords. Build, write, then swap.
        let (new_keys, file) = envelope::create(new, params, body.expose())?;
        drop(body);
        self.store.replace(&file)?;
        open.keys = new_keys;
        open.dirty = false;
        Ok(())
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
                .expired(self.clock.as_ref(), u.data.settings.auto_lock_secs)
        })
    }

    /// The store, for example to show where the vault lives.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
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
                envelope::verify_password(&open.keys, password).map_err(|e| match e {
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "first caller is the item module (Task 8)")
    )]
    pub(crate) fn unlocked_mut(&mut self) -> Result<&mut Unlocked, CoreError> {
        self.open.as_mut().ok_or(CoreError::Locked)
    }

    /// Wall-clock time from the session's clock, for item timestamps.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "first caller is the item module (Task 8)")
    )]
    pub(crate) fn now_unix(&self) -> Timestamp {
        self.clock.now_unix()
    }

    /// Saves the current data: marks the session dirty, encodes, re-seals under the
    /// same data key with a fresh nonce, and replaces the file. The dirty flag is
    /// cleared only if the write succeeds, so a failed save leaves the session dirty
    /// and the old file intact.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Body`], [`CoreError::Vault`] (for example
    /// [`VaultError::TooLargeToSave`]), or [`CoreError::Store`].
    pub(crate) fn commit(&mut self) -> Result<(), CoreError> {
        let open = self.open.as_mut().ok_or(CoreError::Locked)?;
        open.dirty = true;
        let body = open.data.encode()?;
        let file = envelope::reseal(&mut open.keys, body.expose())?;
        drop(body);
        self.store.replace(&file)?;
        open.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use crate::store::MemStore;
    use crate::throttle::FREE_FAILURES;
    use holm_crypto::KdfParamsError;
    use std::io::ErrorKind;

    const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
    const NEW_PW: &str = "Quokka-Sextant-velvet-EXAMPLE-ember-71";
    const WRONG: &str = "not-the-Right-password-EXAMPLE-0";
    const FLOOR: KdfParams = KdfParams::FLOOR;

    fn pw(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_owned())
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn session() -> (Session<MemStore>, FakeClock) {
        let clock = FakeClock::default();
        clock.set_unix(1_700_000_000);
        (
            Session::new(MemStore::default(), Box::new(clock.clone())),
            clock,
        )
    }

    /// A session with a fresh vault, left unlocked.
    fn created() -> (Session<MemStore>, FakeClock) {
        let (mut s, clock) = session();
        s.create(&pw(PW), &FLOOR).unwrap();
        (s, clock)
    }

    /// A session with a fresh vault, locked.
    fn created_locked() -> (Session<MemStore>, FakeClock) {
        let (mut s, clock) = created();
        s.lock();
        (s, clock)
    }

    fn failures(s: &Session<MemStore>) -> u32 {
        s.throttle_status().consecutive_failures
    }

    fn stored(s: &Session<MemStore>) -> Vec<u8> {
        s.store().bytes.clone().unwrap()
    }

    fn open_file(file: &[u8], password: &str) -> VaultData {
        let (_, plain) = envelope::open(file, &pw(password)).unwrap();
        VaultData::decode(plain.expose()).unwrap()
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
        assert_eq!(s.unlocked().unwrap().data.item_count(), 0);
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
        let (_, file) = envelope::create(&pw(PW), &FLOOR, &[2, 0]).unwrap();
        s.store.bytes = Some(file);
        assert_eq!(
            s.unlock(&pw(PW)),
            Err(CoreError::Body(crate::body::BodyError::NewerSchema(2)))
        );
        assert_eq!(failures(&s), 1);
        assert!(!s.is_unlocked());
    }

    #[test]
    fn failed_save_keeps_file_and_retry_works() {
        let (mut s, _) = created();
        let before = stored(&s);
        s.unlocked_mut().unwrap().data.settings.auto_lock_secs = 600;
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        assert_eq!(
            s.save(),
            Err(CoreError::Store(StoreError::Io(ErrorKind::StorageFull)))
        );
        assert_eq!(stored(&s), before);
        assert_eq!(open_file(&before, PW).settings.auto_lock_secs, 300);
        assert!(s.is_dirty());
        s.save().unwrap();
        assert!(!s.is_dirty());
        assert_eq!(open_file(&stored(&s), PW).settings.auto_lock_secs, 600);
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
    fn backup_opens_with_same_password() {
        let (mut s, _) = created();
        let before = stored(&s);
        let open = s.unlocked_mut().unwrap();
        open.data.settings.auto_lock_secs = 600;
        open.dirty = true;
        let mut dest = MemStore::default();
        s.save_backup(&mut dest).unwrap();
        let backup = dest.bytes.clone().unwrap();
        assert_eq!(open_file(&backup, PW).settings.auto_lock_secs, 600);
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
