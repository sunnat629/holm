# Lesson 18: Files, fsync and processes

## Why this matters

A password manager that loses the vault on a crash is worse than one that leaks nothing, because the user loses every password at once. A plain `fs::write` truncates the file first and then writes, so a crash in between leaves an empty or half-written vault. This lesson shows how to save so that, whatever moment the power or the process dies, the file holds either the whole old vault or the whole new one.

## What we built

A new crate, `holm-platform`, holds `FsStore`: the vault as one file on disk, behind the `VaultStore` trait from Task 7. A save writes a fresh temp file next to the vault, syncs it, renames it over the vault, then syncs the directory. The vault must be a regular file (symlinks and folders are refused), new files are mode 0600, and a world-writable directory is refused. Tests cover each rule on real files, on a real exFAT disk image, and with a child process that kills itself at each of the six save steps. `Session::active_items` lists the items not in Trash, so the crash test can check what survived.

## Rust ideas in this task

### `OpenOptions`: `create_new` and `mode`

```rust
let mut options = OpenOptions::new();
options.write(true).create_new(true);
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}
let file = options.open(path)?;
```

`create_new(true)` asks the OS to create the file and fail with `AlreadyExists` if anything is there, even a symlink. The check and the create are one system call (`O_CREAT | O_EXCL`), so no other process can slip a file in between. `mode(0o600)` sets the permissions at creation: owner read and write, nobody else. Setting them afterwards with `set_permissions` would leave a short window where the file is readable by others.

In Kotlin you'd write `Files.createFile(path, PosixFilePermissions.asFileAttribute(...))`. Same idea; Rust puts the Unix-only part behind an extension trait so it does not compile on Windows by accident.

### `#[cfg(unix)]` and `cfg!(unix)`

`#[cfg(unix)]` removes code at compile time on other platforms: the `mode` call above, the directory sync, the inode check in `read`. `cfg!(unix)` is a plain `bool` you can use in an `if`; both branches must still compile everywhere. We use `if cfg!(unix) { self.emit(SaveStep::DirSynced) }` because `emit` exists on every platform.

In Kotlin you'd check `System.getProperty("os.name")` at run time. Rust decides at build time, so a Windows build does not even contain the Unix code.

### Write, sync, rename, sync: what each step protects

```rust
let mut file = create_exclusive(&temp)?;  // TempCreated
file.write_all(first)?;                   // TempHalfWritten
file.write_all(second)?;                  // TempWritten
file.sync_all()?;                         // TempSynced
fs::rename(&temp, &self.path)?;           // Renamed
File::open(dir)?.sync_all()?;             // DirSynced (Unix)
```

- `write_all` only hands bytes to the OS cache. Nothing is on the disk yet.
- `sync_all` (temp) waits until the temp's bytes are on the disk. Without it, the OS may write the rename to disk before the data, and after a power cut the vault name points at an empty file. On macOS `sync_all` uses `F_FULLFSYNC`, which also flushes the drive's own cache.
- `rename` within one directory is atomic: anyone looking sees the old file or the new one, never a mix. It also replaces a symlink itself instead of following it.
- `sync_all` (directory) makes the rename itself survive a power cut. Some FAT and exFAT volumes cannot sync a directory and say `Unsupported` (or a raw `ENOTSUP` or `EINVAL`, which macOS std leaves uncategorised); we accept that and fail on any other error.

`create_new` for a brand-new vault uses `hard_link(temp, path)` instead of `rename`, because `rename` would overwrite a file that appeared in the meantime, while `hard_link` fails if anything is there. exFAT has no hard links, so there we fall back to an exclusive create of the vault path.

In Kotlin you'd write `Files.move(temp, path, ATOMIC_MOVE)`, then `FileChannel.force(true)`. The JVM has no portable directory sync, which is one reason the old project lost data.

### Checking what you opened

```rust
let before = fs::symlink_metadata(&self.path)?;  // does not follow symlinks
// ... refuse symlinks, folders, files over 64 MiB ...
let file = File::open(&self.path)?;
let opened = file.metadata()?;                    // the file actually opened
if opened.dev() != before.dev() || opened.ino() != before.ino() { /* refuse */ }
```

Between the check and the open, someone could swap the path for a symlink. Comparing device and inode numbers catches that, with std only. Then `file.take(MAX + 1).read_to_end(...)` reads at most one byte past the limit, so a file that grows while we read still cannot fill memory.

### Spawning yourself with `std::process::Command`

```rust
let out = Command::new(std::env::current_exe()?)
    .args(["child_save_then_crash", "--exact", "--ignored", "--nocapture"])
    .env("HOLM_CRASH_DIR", dir.path())
    .env("HOLM_CRASH_STEP", step.name())
    .output()?;
assert_eq!(out.status.code(), Some(86));
```

A test binary is a normal program, so a test can run itself again with only one test selected. The child test is `#[ignore]`, so a normal `cargo test` never runs it; `--ignored` picks it. Its `FsStore` observer calls `std::process::exit(86)` when it reaches the chosen step. The parent then opens the vault and checks: up to `TempSynced` it holds only `"old"`; from `Renamed` on it holds `"new"` too; and no temp is left, because unlock cleans them up.

Exit codes are how a process reports to its parent: 0 is success, a Rust panic in a test gives 101, and 86 is ours, picked so it cannot be confused with either.

In Kotlin you'd write `ProcessBuilder(javaBin, "-cp", cp, "CrashMain").start().waitFor()`. Rust's `current_exe` makes this easier because the test is already a standalone binary.

### Why `exit` is not pulling the power

`process::exit` stops our process at once: no destructors, no unwinding. But the OS keeps running and still writes its cache to the disk later. So the crash test proves the order of our steps is right, not that every sync is needed. A real power cut can lose anything not yet synced, which is what the two `sync_all` calls are for. Testing that needs a VM or special hardware, which is Phase 5 work.

## Exercises

1. In `replace`, comment out `self.check_target()?;`. Run the symlink test and read why it fails. Then restore the line.
   Check: `cargo test -p holm-platform --test fs_store symlinked_vault_refused --locked`
2. In `is_own_temp_name`, also accept `b'A'..=b'F'`. Which test catches it, and why does that test create the upper-case file in a separate step? Undo the change.
   Check: `cargo test -p holm-platform --test fs_store stale_temp_cleanup_is_exact --locked`
3. Run the child test by hand without its environment variables. What does it print, and what exit code does `cargo test` return?
   Check: `cargo test -p holm-platform --test crash child_save_then_crash --locked -- --ignored --exact; echo "exit code: $?"`

## Read next

- [`std::fs::OpenOptions`](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html)
- [`std::fs::File::sync_all`](https://doc.rust-lang.org/std/fs/struct.File.html#method.sync_all)
- [The Rust Book, Test Organization](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
