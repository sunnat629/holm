# Lesson 15: Generics and trait objects

## What we built

`Session` is the heart of Holm: it creates, unlocks, saves, backs up and locks a vault, and changes its master password. It owns a store (where the file lives), a clock, the unlock throttle and, while unlocked, the keys and the decrypted data. `store.rs` defines the `VaultStore` trait that every store must follow, and `error.rs` gathers every failure into one `CoreError` enum. The golden vault in `tests/vectors/` is now a real schema-1 vault that a test rebuilds byte for byte. The code is in `crates/holm-core/src/session.rs`, `store.rs` and `error.rs`.

## Rust ideas in this lesson

### Generic over the store, a trait object for the clock

```rust
pub struct Session<S: VaultStore> {
    store: S,
    clock: Box<dyn Clock>,
    throttle: Throttle,
    open: Option<Unlocked>,
}
```

- `S: VaultStore` is a **generic with a trait bound**. The compiler makes a separate copy of `Session` for each store type: `Session<MemStore>` in tests, `Session<FileStore>` in the app. Calls to `self.store.read()` go straight to the right function, with no lookup at run time.
- `Box<dyn Clock>` is a **trait object**: a pointer to some value that implements `Clock`, plus a table of its methods. The exact type is chosen at run time, and every call goes through the table.
- Why the split? The store is part of what a session *is*. A caller may want `session.store()` back as the concrete type, for example to show the file path. The clock is only a source of time, so one `Session<FileStore>` type serves both the real clock and a test clock.
- `save_backup(&mut self, dest: &mut dyn VaultStore)` takes a trait object too, so a backup can go to any kind of store without making the method generic.

In Kotlin you'd write: `class Session<S : VaultStore>(val store: S, val clock: Clock)`. Kotlin generics are erased, so both fields end up as interface calls. Rust lets you pick per field: `S` is monomorphised (one copy per type, direct calls), `dyn Clock` is dynamic dispatch, like a Kotlin interface.

### `Option` as a small state machine

```rust
open: Option<Unlocked>,

pub fn lock(&mut self) -> LockOutcome {
    let discarded_unsaved = self.open.take().is_some_and(|u| u.dirty);
    LockOutcome { discarded_unsaved }
}
```

- The session has two states: locked (`None`) and unlocked (`Some(Unlocked)`). The keys and data live **inside** the `Some`, so there is no way to reach them while locked. No "is the key null?" checks are scattered around.
- `take()` moves the value out and leaves `None` behind. The `Unlocked` value is then dropped at the end of the statement, and dropping it wipes the data key and every item string (lesson 02).
- Every method that needs the vault starts with `self.open.as_ref().ok_or(CoreError::Locked)?`, which turns `None` into an error.

In Kotlin you'd write: `var open: Unlocked? = null` and `open?.let { ... } ?: throw LockedException()`. The Rust version cannot forget the wipe, because `Drop` runs on `take()` without being asked.

### `&mut self` and borrowing a field

```rust
pub fn save_backup(&mut self, dest: &mut dyn VaultStore) -> Result<(), CoreError> {
    let open = self.open.as_mut().ok_or(CoreError::Locked)?;
    let body = open.data.encode()?;
    let file = envelope::reseal(&mut open.keys, body.expose())?;
    ...
}
```

- `&mut self` means "this method may change the session, and nobody else can look at it while it runs". The compiler checks that at every call site.
- `open` borrows one field (`self.open`) mutably. Inside `commit` the code then also calls `self.store.replace(...)`. That compiles because the borrow checker sees two **different** fields. Calling a whole `&mut self` method while `open` is alive would not compile.
- `unlock` cannot be called twice at once, and a UI cannot read the data while a save is half done. Both come for free from `&mut`.

In Kotlin you'd write: `synchronized(this) { ... }` or a `Mutex`, and remember to do it everywhere. In Rust, one `&mut` at a time is a compile-time rule.

### `From` and `?` into one error enum

```rust
impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self { CoreError::Store(e) }
}

let bytes = read?;                                         // StoreError -> CoreError
let (keys, plaintext) = envelope::open(&bytes, password)?; // VaultError -> CoreError
let data = VaultData::decode(plaintext.expose())?;         // BodyError  -> CoreError
```

- `?` on an `Err(e)` returns `Err(From::from(e))`. With one `From` impl per lower error, one function can mix store, envelope and body calls and still return a single `CoreError`.
- The UI matches on one enum. `CoreError::Vault(WrongPasswordOrCorrupt)` prints the full unlock-screen sentence; nothing prints a password or item text.
- The impls are written by hand, not with `#[from]`, so `CryptoError` can go through `VaultError::from` and get the same mapping as the envelope.

In Kotlin you'd write: a `sealed class CoreError` and `try { } catch (e: IOException) { throw CoreError.Store(e) }` around each call. `?` is that catch-and-wrap, in one character.

### Write first, then swap: why not `envelope::rekey`

```rust
let (new_keys, file) = envelope::create(new, params, body.expose())?;
drop(body);
self.store.replace(&file)?;   // may fail: disk full
open.keys = new_keys;         // only reached if the write worked
open.dirty = false;
```

- `envelope::rekey(&mut keys, ...)` builds the new keys **and puts them in place** before returning the file. The caller writes afterwards. If that write fails, memory holds the new password and disk holds the old one. The next save would then write a file the user's (old) password cannot open.
- So `change_password` builds the whole new vault with `create`, writes it, and swaps the keys only when `replace` returned `Ok`. On a failed write, `?` returns early and the old keys are still in place, matching the old file.
- The same rule drives `commit`: the dirty flag is cleared only after the write succeeds, so a failed save still warns before lock throws the changes away.

In Kotlin you'd write: the same order by hand, perhaps with a comment. In Rust, `?` makes "everything after this line runs only on success" explicit.

## Why this matters for security

A password manager that loses a write must never end up with memory and disk on different passwords, or the user is locked out of their own vault. Keeping the keys inside `Option<Unlocked>` means locking always wipes them, with no code path that forgets. The throttle runs every guessing path through `Throttle::attempt`, and only two cases that never run Argon2 (no file, and costs refused on the public header) skip the count.

## Try it

1. Run the session tests.
   - Run: `cargo test -p holm-core --locked --lib session::tests`
   - Check: the `test result:` line says `ok.` with `0 failed`.
   - Undo: nothing to undo, it only reads.
2. Swap the keys before the write in `change_password` and watch the test catch it.
   - Run: `perl -0pi.bak -e 's/(        self\.store\.replace\(&file\)\?;\n)(        open\.keys = new_keys;\n)/$2$1/' crates/holm-core/src/session.rs && cargo test -p holm-core --locked --lib change_password_write_failure`
   - Check: `change_password_write_failure_keeps_old_password ... FAILED`, with `left: Err(WrongPassword)` and `right: Ok(())`.
   - Undo: `rm crates/holm-core/src/session.rs.bak && git checkout -- crates/holm-core/src/session.rs`
3. Remove the "no vault" check in `unlock` and see a missing file get counted as a failure.
   - Run: `perl -0pi.bak -e 's/        if read == Err\(StoreError::NotFound\) \{\n.*?\n        \}\n//s' crates/holm-core/src/session.rs && cargo test -p holm-core --locked --lib missing_file`
   - Check: `missing_file_is_no_vault_and_not_counted ... FAILED`, with `left: Err(Store(NotFound))`.
   - Undo: `rm crates/holm-core/src/session.rs.bak && git checkout -- crates/holm-core/src/session.rs`

## Read next

- [The Rust book, ch10-02: Traits](https://doc.rust-lang.org/book/ch10-02-traits.html), trait bounds on generics.
- [The Rust book, ch18-02: Trait objects](https://doc.rust-lang.org/book/ch18-02-trait-objects.html), `dyn Trait` and dynamic dispatch.
- [std::option::Option::take](https://doc.rust-lang.org/std/option/enum.Option.html#method.take)

Previous lesson: [Lesson 14: Time and saturating maths](14-time-and-saturating-maths.md).
Next lesson: [Lesson 16: Borrowing in practice](16-borrowing-in-practice.md).
All lessons: [the index](README.md).
