# Holm architecture

This page is the map. It shows which crate owns what, where secrets live while the vault is open, and how a change reaches the disk. It is written for developers who are learning Rust and applied crypto, so it points to the matching lessons in `docs/learn/`.

Read this first, then [How encryption works](HOW-ENCRYPTION-WORKS.md), then [The file format](FILE-FORMAT.md). The normative details are in [CRYPTO.md](CRYPTO.md) and [THREAT-MODEL.md](THREAT-MODEL.md). Holm has had no third-party audit.

## The crates

The workspace has five crates. Two more directories, `oracle/` and `fuzz/`, are separate workspaces that test the others and never ship.

| Crate | Owns | Does not own |
|---|---|---|
| `holm-crypto` | Argon2id (`kdf`), XChaCha20-Poly1305 (`aead`), the OS random source (`random`), and the secret types `SecretKey`, `SecretBuf` and `MasterPassword` (`secret`). | Any file format, any vault concept, any I/O. |
| `holm-core` | The vault itself: file format and parsing (`format`, `envelope_v2`, `index`, `record`, `padding`), the v1 to v2 migration (`migrate`), `Session`, items and fields, search, the password generator, the strength check, import and export, the unlock throttle, and the `VaultStore` and `Clock` traits. | Real files, terminals, windows, the clipboard. |
| `holm-platform` | The real world: `fs_store` (durable atomic writes), the one-Holm-per-vault lock, paths, private files, the clipboard-clear timer, process hardening, a wiping global allocator, and the optional AppKit and terminal helpers. | Any crypto decision. |
| `holm-cli` | The `holm` command: argument parsing (`args.rs`), one module per command (`commands/`), the interactive `holm shell`, and terminal password entry. | Vault logic. It calls `Session`. |
| `holm-gui` | The macOS app built with egui: screens, widgets, the secret text input, the worker thread, and the GUI side of the clipboard. | Vault logic. It calls `Session`. |

The code uses `fs_store` for disk and `Session` for everything else. Core never opens a file by itself. It talks to a `VaultStore` trait, and tests plug in an in-memory store.

### Dependency direction

Arrows point from a crate to what it uses. Nothing points back up.

```
holm-cli   holm-gui          (the two front ends)
      \     /
   holm-platform             (files, clipboard, OS hardening)
         |
     holm-core               (the vault)
         |
    holm-crypto              (Argon2id, AEAD, random, secret types)
```


In words:

- `holm-crypto` depends on no other Holm crate.
- `holm-core` depends on `holm-crypto` only.
- `holm-platform` depends on `holm-core` and `holm-crypto`.
- `holm-cli` and `holm-gui` depend on all three. Neither depends on the other. (The diagram draws only the main chain. Both front ends also use `holm-core` and `holm-crypto` directly.)

Core has no I/O of its own, so the whole vault logic runs in plain unit tests. Lesson 07 covers modules and encapsulation, and lesson 15 covers the generic `Session<S: VaultStore>`.

## The unsafe policy

The goal is that almost no line of Holm can cause memory unsafety.

- The workspace sets `unsafe_code = "forbid"`. `holm-crypto`, `holm-core`, `holm-cli` and `holm-gui` also say `#![forbid(unsafe_code)]` in their crate roots.
- `holm-platform` is the one crate that talks to the operating system, so its root is `#![deny(unsafe_code)]` and its `Cargo.toml` sets `unsafe_code = "deny"`. Every module in it says `#![forbid(unsafe_code)]`, except two.
- Those two are `window.rs` (the AppKit calls, macOS and the `gui-window` feature only) and `zeroing_alloc.rs` (the allocator that wipes freed memory). Each has an `#![allow(unsafe_code, reason = "...")]` and a `// SAFETY:` comment on every unsafe block.
- `scripts/ci-local.sh` checks this. It fails if the `unsafe_code` lint level changes, or if `allow(unsafe_code` appears in any file that is not on the list.

Lesson 65 shows how to wrap AppKit safely, and lesson 66 covers the wiping allocator.

## The main flow: unlock, list, reveal

```
user types master password
        |
        v
Session::unlock(password)
   1. read the file bytes through VaultStore::read
   2. parse the header and check framing and the Argon2 cost policy
      (no secret is touched, no Argon2 has run yet)
   3. Argon2id(password, salt, m, t, p) gives the KEK
   4. open "wrapped DEK" with the KEK       (wrong password fails here)
   5. open the index with the DEK           (a damaged file fails here)
   6. keep: DEK, header, index, sealed records (still encrypted)
        |
        v
   vault is "open": Session.open = Some(Unlocked)
        |
        +--> list / search / filter   reads the index only, public fields only
        |
        +--> reveal(id, slot)         opens ONE record, copies ONE secret into a
        |                             wiping SecretText, drops the rest
        |
        +--> open_item(id)            opens ONE record for editing
        |
        +--> add / edit / delete      change the index and records in RAM,
                                      then commit() writes the file
        |
        v
Session::lock()  (button, idle timer, sleep, quit)
   drops the Unlocked state: DEK, index and records are wiped
   unsaved changes are discarded and reported
```

Two details matter here.

1. Unlock does not open any record. Records are opened one at a time when you ask for them. A damaged record shows up as `DamagedItem` only at that moment. See [FILE-FORMAT.md](FILE-FORMAT.md).
2. A wrong password and a damaged file give the same error, `WrongPasswordOrCorrupt`. This is on purpose, so the error does not tell an attacker which one happened.

Lessons 68 (open one item at a time) and 02 (ownership, `Drop` and secret types) go with this flow.

## Where state lives

While the vault is unlocked, `Session` holds this:

| Piece | Where | Wiped on lock |
|---|---|---|
| The DEK (32 bytes) and the header | `Unlocked.state.keys` | Yes, dropped with the state, and the key type zeroes itself. |
| The index: titles, usernames, URLs, labels, dates, flags, and for each entry the pinned record generation, nonce and length | `Unlocked.state.index` | Yes, dropped. |
| The sealed records (ciphertext only) | `Unlocked.state.records` | Yes, dropped. |
| One revealed secret, for as long as the screen shows it | A wiping `SecretText` owned by the caller | Wiped on drop, and the GUI drops it on lock. |
| The unlock throttle (failure count and next allowed time) | `Session.throttle` | No. It survives a lock on purpose, so lock and unlock cannot reset it. |
| The idle timer, the dirty flag, the migration backup note | `Unlocked` | Yes. |

What is not kept: the master password and the KEK are wiped as soon as the DEK is unwrapped, and no record plaintext stays except the one you are looking at right now.

What is in RAM, and is honest to say plainly: the DEK and the index. A full memory dump of the running process while the vault is unlocked gives an attacker everything. Wiping is best effort. It does not cover the stack, AppKit, the GPU, or swap, and Holm does not use `mlock`. See [THREAT-MODEL.md](THREAT-MODEL.md).

`holm-platform` adds two process-level helpers. It sets `RLIMIT_CORE` to 0 so a crash does not write a core dump, and its global allocator zeroes every freed block.

## The single write gate

Only one function in the whole code base replaces the vault file. In `holm-core/src/session/mod.rs` it is called `write_gate`.

```rust
fn write_gate(store: &mut S, open: &mut Unlocked, bytes: &[u8]) -> Result<(), GateError> {
    if let Some(origin) = &open.migration {
        store.keep_backup_copy(&origin.tag, &origin.bytes).map_err(|_| GateError::Backup)?;
    }
    store.replace(bytes).map_err(GateError::Replace)?;
    open.migration = None;
    Ok(())
}
```

Every change goes through the same path:

```
add / edit / delete / settings / password change
        |
        v
   commit()
        |-- mark dirty
        |-- envelope_v2::assemble   fresh index nonce, reuse unchanged record
        |                           ciphertext, refuse a file over 64 MiB
        |-- self-check (when migrating): re-open what was just built
        |-- write_gate
        |      |-- migrating? keep the v1 backup copy first, or stop
        |      '-- VaultStore::replace   atomic: the old file or the new one
        '-- clear dirty
```

Why one gate: a rule such as "back up before you migrate" is only safe if no other path can skip it. With one caller of `VaultStore::replace`, a reviewer reads one function. Lesson 69 explains the migration order, and lesson 18 explains atomic replace, `fsync` and the temp file dance.

Other writes go elsewhere on purpose. `save_backup(dest)` writes a copy to a path you choose with `create_new`, so it never overwrites anything, and it does not touch the vault file. A password change uses the same commit path with a new salt and a new DEK. If the result of the replace is unknown, it returns `PasswordChangeUncertain` instead of guessing.

## How the GUI talks to core

The GUI owns exactly one `Session<FsStore>`. Argon2 takes a visible fraction of a second and a save does disk I/O, so neither can run on the UI thread without freezing the window.

- For slow work the app moves the `Session` into a short-lived thread named `holm-work`, together with a `Job` value. The jobs are Create, Unlock, Add, Update, SetFields, SetCodeUsed, DeleteMigrationBackup, Save, PreviewImport, Import, Export, Backup and RevealPhrase.
- The worker sends the `Session` back inside a `WorkDone` over an `mpsc` channel. While the worker runs, the app has no session, so nothing can be opened or locked in the meantime. The password is wiped on the worker when the job ends.
- A panic on the worker shows up as a disconnected channel, and the app reports it.
- Quick reads such as `entry`, `active_entries` and `open_item` happen on the UI thread through `&Session`.
- Each screen (`unlock`, `create`, `vault`, `item_view`, `login_form`, `transfer`, `backup_prompt`) is a variant of a `Screen` enum. Leaving a screen drops its data, and its password buffers wipe themselves on drop.

The CLI is simpler. It runs each command on the main thread and reads the password from the terminal. Lessons 24 (state machines and worker threads), 36 (thin screens over the core) and 39 (one flow, two front ends) walk through this.

## Testing layers

Each layer catches a different kind of mistake. `scripts/ci-local.sh` runs the gates in order and stops at the first failure.

| Layer | What it checks | Where |
|---|---|---|
| Unit tests | One function or type at a time, including the tamper tests that flip bytes in a vault and expect an error. | `#[cfg(test)]` modules, for example `envelope_v2/tamper.rs`. |
| Property tests | Round trips and invariants over random input, such as "any vault seals and opens to the same data". | `proptest` in `holm-core`, for example `vault_v2_roundtrip_any` and `tests/format_props.rs`. |
| Golden vectors | A fixed file that must keep opening, and a fixed build that must keep producing the same bytes. | `crates/holm-core/tests/vectors/` and `envelope_v2/golden.rs`. |
| Oracle | A separate crate that checks Argon2id against libsodium. Kept out of the product dependency graph. | `oracle/`. |
| Fuzzing | Hostile bytes into the parsers: header, body, index, record, unpad, CSV and JSON import, and the fixed-key open paths. 30 seconds per target in CI, and a long run with `scripts/fuzz-long.sh`. | `fuzz/fuzz_targets/`. |
| Miri | Runs the `holm-crypto` unit tests under an interpreter that reports undefined behaviour. The slow Argon2 and Wycheproof tests are skipped. A manual run, recorded in the report. | `docs/security/mutants-2026-11.md`. |
| Mutation tests | `cargo-mutants` changes the code in small ways and checks that a test fails. The recorded run covers `holm-crypto` and parts of `holm-core`, and it was done before format v2, so it says nothing about v2 code yet. | `docs/security/mutants-2026-11.md`. |
| Bench gates | Timing budgets: one Argon2 run at the default cost, search over 10,000 items, and process start. A big slowdown fails, and so does a suspicious speedup in Argon2, which would mean the cost was weakened. The budgets are per machine. | `scripts/bench-gates.sh`, `scripts/bench-budgets.env`. |
| Compat with an old binary | Builds an older Holm and checks that it refuses a v2 vault and leaves the file byte-identical. | `scripts/compat-old-binary.sh`. |
| GUI tests | Headless egui tests that drive the real screens. | `crates/holm-gui/tests/`. |
| Supply chain and build | `cargo-deny`, `cargo-audit`, `cargo-vet`, a reproducible-build check and an SBOM. | `scripts/ci-local.sh`, `scripts/repro-check.sh`, `scripts/sbom.sh`. |

Lessons 08 and 21 cover property tests and fuzzing, 70 covers measuring, and 71 covers reproducible builds, SBOMs, fuzzing and mutation testing.
