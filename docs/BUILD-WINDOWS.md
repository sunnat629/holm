# Building Holm on Windows

## Status: read this first

Windows is untested and not supported for real secrets. Use a throwaway test vault only.

- **The window does not open on Windows yet.** Every GUI module is built for macOS only
  (`crates/holm-gui/src/lib.rs`). On Windows, `holm-gui.exe` builds, prints
  `Holm's window runs on macOS only for now.` and exits with code 1.
- **The command line cannot ask for a password.** The terminal code (`tty`) is not built
  on Windows, so every password prompt fails with fixed text (`docs/CRYPTO.md`).
- **No Windows file protection.** There is no ACL that matches the Unix `0600` mode, no
  write-through and no folder sync after a save (`docs/CRYPTO.md`, `docs/DECISIONS.md`).
- **No default vault path.** Outside macOS, Holm has no default vault location, so you
  must pass `--vault`.
- **No Windows CI.** Local CI runs on macOS only, and its oracle and fuzz gates are
  skipped on Windows (`CONTRIBUTING.md`).

So today a Windows build checks one thing: that the workspace compiles and its
plain-Rust tests pass there. That is still useful, and it is what the steps below do.

## What you need

1. **Visual Studio Build Tools 2022**, with the **Desktop development with C++**
   workload. `libsodium-sys-stable` needs the MSVC compiler and linker.
2. **rustup** from <https://rustup.rs>. The repo's `rust-toolchain.toml` pins Rust
   1.99.1 with rustfmt and clippy, and rustup installs it on the first `cargo` command.
3. **Git**, and **GitHub CLI** (`gh`). The repo is private, so sign in first:

```powershell
gh auth login
```

## Clone and build

```powershell
gh repo clone sunnat629/holm
cd holm
git checkout phase-5
cargo build --release -p holm-gui
cargo test --workspace
```

The program is `target\release\holm-gui.exe`. Start it with a test vault path:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\holm-dev" | Out-Null
.\target\release\holm-gui.exe --vault "$env:USERPROFILE\holm-dev\holm.vault"
```

The only flag is `--vault <path>`. Today this prints the macOS-only message above and
exits. That is the expected result, not a failed build.

## Check list (once the window runs on Windows)

These steps need the Windows port of the GUI. Until then they apply to macOS only.

1. Create a vault at the `--vault` path.
2. Add a login, pick a preset (for example Cloudflare), and add a custom field.
3. Lock and unlock.
4. Copy a password and check that the clipboard clears itself.
5. Import a test CSV.
6. Export, then delete the export file.

## If it fails

Send the first 60 lines of the build output and a screenshot:

```powershell
cargo build --release -p holm-gui 2>&1 | Select-Object -First 60
```

Never paste real passwords, a real vault or a real export.

## Dev unlock

`HOLM_DEV_PASSWORD` with the `dev-unlock` feature works in macOS debug builds only. It
does nothing on Windows today, because the window does not start. The warning in
`CONTRIBUTING.md` applies: use it with a throwaway test vault only, never with your real
master password.
