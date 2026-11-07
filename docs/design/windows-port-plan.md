# Windows port plan

Status: plan only, for owner review. No port code is written yet. Branch `windows`, after merging `main` at 291994b.

This plan says what the Windows build must do, which Win32 call or crate does each job, where Windows is weaker than macOS, how we check the work without a Windows machine, and how the friend's test build reaches him.

## 1. Goal and scope

**Goal.** A Windows build of `holm-gui.exe` and `holm.exe` that a friend can run on a real PC with a test vault, with the same security floor as the macOS app wherever Windows allows it, and every gap written down.

**Targets.**

- Windows 11, and Windows 10 22H2.
- `x86_64-pc-windows-msvc` only.
- Note on Windows 10: consumer Extended Security Updates for Windows 10 ended on 13 October 2026. The build will run there, but a PC without security updates is a weak base for a password vault. See decision 7.

**Out of scope for now.**

- **ARM64** (`aarch64-pc-windows-msvc`). Nobody on the team has Windows ARM hardware for the manual checks. On Snapdragon PCs OpenGL comes from Microsoft's compatibility layer (OpenGL on Direct3D 12), not a native driver, so the `glow` renderer is a real risk there. The x64 build runs on Windows ARM under emulation, which is enough for now.
- **Installers** (MSI, MSIX, winget). The test build is a zip with two exe files. MSIX would also virtualise `%LOCALAPPDATA%`, which changes the vault path rules.
- **Auto-update.** It is network code, which the threat model forbids (design anti-goals).
- **Signing.** Discussed in section 6, not done for the friend test.

**What already works.** The vault logic (`holm-crypto`, `holm-core`) is plain Rust with no cfg gates, and the zeroing allocator (`zeroing_alloc.rs`) has no OS code. Both run on Windows unchanged.

**What is broken today.** The Windows cross-check in section 5 found that `main` no longer compiles `holm-gui` for Windows: `crates/holm-gui/src/messages.rs:20` imports `crate::rows`, which is a macOS-only module (`lib.rs:29`). `docs/BUILD-WINDOWS.md` says the workspace builds there; that is no longer true. Task T0 fixes it.

## 2. Inventory

The grep was `cfg(target_os ...)`, `cfg(unix)`, `cfg(not(...))` and `cfg!(...)` in `crates/`. It found 63 gated lines in `holm-platform`, 32 in `holm-gui` and 10 in `holm-cli`. `holm-crypto` and `holm-core` have none. The table has one row per feature, not per line. Lines are on `windows` after the merge (291994b).

Parity means: **same** (Windows gives the same protection), **weaker** (some protection, less than macOS), **none** (no Windows protection exists or is planned).

### 2.1 Process and memory

| Feature | macOS mechanism | file:line | Windows mechanism | Parity | Notes |
|---|---|---|---|---|---|
| Core dumps off | `setrlimit(RLIMIT_CORE, 0)` via rustix | `holm-platform/src/hardening.rs:14`, test `:34`; called from `holm-gui/src/main.rs:22` and `holm-cli` main | `WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)` (process only, no registry), `SetErrorMode(SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX)`, and optionally `WerAddExcludedApplication(L"holm-gui.exe", FALSE)` (writes HKCU, decision 3) | weaker | Windows has no per-process "no dumps" switch. An admin `LocalDumps` policy with `DumpType=2` still writes a full dump, and any same-user process can call `MiniDumpWriteDump` at any time. A Rust panic unwinds and never reaches WER. An abort, a double panic, an out-of-memory abort or a stack overflow ends in `__fastfail` or an SEH fault, and WER sees those. The default WER minidump holds thread stacks, which can hold secret bytes, and can be queued for upload by the OS. Test: `WerGetFlags(GetCurrentProcess())` reads back `NOHEAP`. |
| Memory locking | None. `mlock` was skipped on purpose (DECISIONS A4) | `docs/DECISIONS.md:135`; no code | `VirtualLock` exists, but the same A4 reasons apply: page granularity, copies we cannot pin, and the default working-set limit is far below the 256 MiB Argon2 area | weaker | A4 reason 4 does **not** hold on Windows: the pagefile and `hiberfil.sys` are plain unless BitLocker or Device Encryption covers the system drive. Recommendation: keep A4 for this port, and tell users to turn on BitLocker or Device Encryption. A locked key page is decision 4. |
| Zeroing allocator | Wraps `System` | `holm-platform/src/zeroing_alloc.rs` (no OS cfg) | Same code. `System` is `HeapAlloc` on Windows | same | No change. Both binaries already install it. |
| DLL search order | Not an issue (dyld, hardened runtime) | none | `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing in `main`, plus the linker flag `/DEPENDENTLOADFLAG:0x800` so static imports also skip the exe folder | same (after the fix) | New Windows risk. An exe run from `Downloads` loads a planted `dwmapi.dll` or `opengl32.dll` that sits beside it before `System32`, unless we stop it. The linker flag is the only fix for static imports, because they load before `main`. |
| Same-user memory read | Hardened runtime blocks `task_for_pid` from other same-user apps | none | None by default: any same-user process can `OpenProcess(PROCESS_VM_READ)`. Option: tighten the process DACL with `SetSecurityInfo` on `GetCurrentProcess()` (decision 5) | weaker | The process owner can always rewrite its own DACL, so this only stops casual tools. Malware as the same user is out of scope on both systems, but on Windows it needs no permission prompt at all. |
| Extension-point DLLs | Not applicable | none | Optional `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` blocks AppInit DLLs and legacy global hooks loading into Holm (decision 5) | weaker | Do not use `ProcessSignaturePolicy` (Microsoft-signed only) or `ProcessDynamicCodePolicy`: GPU driver DLLs are vendor-signed and JIT shaders, so OpenGL would break. |

### 2.2 Files and folders

| Feature | macOS mechanism | file:line | Windows mechanism | Parity | Notes |
|---|---|---|---|---|---|
| Owner-only files | `OpenOptionsExt::mode(0o600)` | `fs_store.rs:217` (`create_exclusive`, the one choke point for temps, exports and backups); `lock.rs:109`; tests `fs_store.rs` (tests dir) `:359`, `private_file.rs:291`, `prefs.rs:184`, `round_trip.rs:311`, `holm-cli/tests/transfer_commands.rs:223` | `CreateFileW(..., CREATE_NEW, ...)` with a `SECURITY_ATTRIBUTES` whose descriptor has a protected DACL (`SE_DACL_PROTECTED`, no inheritance) and one ACE: the current user's SID from `GetTokenInformation(TokenUser)`, `FILE_ALL_ACCESS`. Build it with `InitializeSecurityDescriptor` and `SetEntriesInAclW`, then wrap the handle with `File::from_raw_handle` | same | The ACL is set atomically at create, so there is no window where the file has inherited rights. Admins can take ownership, as root can on Unix. Do not use the `OW` (owner rights) SID: an elevated token may make `BUILTIN\Administrators` the owner. SYSTEM in the ACE is decision 9. |
| Owner-only folder | `DirBuilderExt::mode(0o700)` | `paths.rs:118` | `CreateDirectoryW` with the same protected-DACL `SECURITY_ATTRIBUTES` | same | Only for a folder Holm creates. |
| Folder safety check | Refuse group or world writable (`mode & 0o022`, `& 0o002`) | `paths.rs:104`, `fs_store.rs:345` | `GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER \| DACL)` on the folder opened with `FILE_FLAG_BACKUP_SEMANTICS`. Refuse if the owner is not the user, SYSTEM or Administrators, or if any allow ACE gives `FILE_ADD_FILE`, `FILE_DELETE_CHILD`, `DELETE` or `WRITE_DAC` to Everyone, Authenticated Users, Users or Guests | same | Stronger than the macOS check, which ignores owner and ACL (CRYPTO.md known gap). |
| Atomic replace | `fs::rename` plus temp `sync_all` (F_FULLFSYNC) | `fs_store.rs:460` | Temp opened with `FILE_FLAG_WRITE_THROUGH` (safe, `OpenOptionsExt::custom_flags`), `FlushFileBuffers` via `sync_all`, then `MoveFileExW(temp, vault, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` | same | std's `fs::rename` calls `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` only (checked in the std 1.93 source; re-check on 1.99.1), so it does not wait for the move to reach the disk. Not `ReplaceFileW`: it is several steps, can leave a half state on failure, and copies the old file's ACL onto the new one. Retry a sharing violation or access denied up to 5 times over about 500 ms: Defender and the Search indexer briefly open new files. |
| Directory sync | `File::open(dir).sync_all()`, unsupported volumes count as success | `fs_store.rs:362`, classifier `:190`, constants `:109` to `:152` | `MOVEFILE_WRITE_THROUGH` is the documented durability step for the rename. As a second step, open the folder with `FILE_FLAG_BACKUP_SEMANTICS` and `GENERIC_WRITE` and call `FlushFileBuffers`; treat `ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED` and `ERROR_ACCESS_DENIED` as "unsupported" | weaker | NTFS journals the rename, but Microsoft documents no directory fsync. A power-loss test is not possible here; the crash tests model a killed process only, same as macOS. |
| Same-file check (dev and inode) | `MetadataExt::dev()` and `ino()` | `fs_store.rs:412`, `lock.rs:92` | `GetFileInformationByHandleEx(FileIdInfo)`: 64-bit volume serial plus 128-bit file id (works on ReFS too) | same | std's `volume_serial_number` and `file_index` are still unstable (`windows_by_handle`), so this needs FFI. |
| No-follow open | `O_NOFOLLOW` custom flag | `fs_store.rs:152` to `:175`, `lock.rs:109` | `FILE_FLAG_OPEN_REPARSE_POINT` (safe, `custom_flags`), then refuse if the opened handle has `FILE_ATTRIBUTE_REPARSE_POINT` (`MetadataExt::file_attributes`, stable) | same | Covers symlinks and junctions. |
| FIFO hang guard | `O_NONBLOCK` | `fs_store.rs:125`, `:177` | Not needed | same | Named pipes live under `\\.\pipe\`, not in the file system. The path check below refuses device paths. |
| Windows path rules | Not applicable | `holm-platform/src/transfer.rs:55` (`typed_path`), `paths.rs` | New pure check: refuse a `:` after the drive prefix (alternate data stream, for example `export.csv:hidden`), reserved names (`CON`, `NUL`, `AUX`, `PRN`, `COM1` to `COM9`, `LPT1` to `LPT9`, any extension), trailing dot or space, and `\\.\` or `\\?\GLOBALROOT` device paths | same (after the fix) | New Windows risk. An export to `NUL` would "succeed" into nothing, and an export to a stream hides plaintext where Explorer does not show it. |
| Hard-link create | `fs::hard_link` | `fs_store.rs:504`, `:565` | Same std call (`CreateHardLinkW`). FAT and exFAT fall back as today | same | No change. |
| Single-instance lock | `File::try_lock` | `lock.rs` | Same std call (`LockFileEx`) | same | Windows locks are mandatory, which is stricter. `holm.lock` is a separate file, so it never blocks vault reads. |
| Export not indexed | Not applicable | `private_file.rs:53` | `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the export at create (safe, `OpenOptionsExt::attributes`) | same (after the fix) | New Windows risk. Windows Search would otherwise copy the plaintext CSV into its index database. Set it on the vault and prefs too; it costs nothing. |
| Parent sync after export | `sync_parent` | `private_file.rs:76`, `:86` | Same as directory sync above | weaker | As above. |
| Default vault path | `$HOME/Library/Application Support/Holm/holm.vault` | `paths.rs:46`, test `:157` | `SHGetKnownFolderPath(FOLDERID_LocalAppData)` then `Holm\holm.vault`, freed with `CoTaskMemFree` | same | **Recommend LocalAppData.** RoamingAppData is copied to a server at logoff on domain PCs with roaming profiles, which spreads the vault and can bring an older copy back at the next logon (a silent rollback the threat model cannot detect). Local matches the macOS folder, which iCloud does not sync. Use the API, not `%LOCALAPPDATA%`, because a parent process sets the environment. |

### 2.3 Terminal and command line

| Feature | macOS mechanism | file:line | Windows mechanism | Parity | Notes |
|---|---|---|---|---|---|
| Password prompt | `/dev/tty`, raw termios via rustix | `tty.rs:254`, `:258`, `:275`, `:279`, `:286`; feature `tty` in `holm-platform/Cargo.toml` | Open `CONIN$` and `CONOUT$` (never stdin). `GetConsoleMode` confirms a console, else `NoTerminal`. `SetConsoleMode` without `ENABLE_ECHO_INPUT`, `ENABLE_LINE_INPUT` and `ENABLE_PROCESSED_INPUT` (so Ctrl-C arrives as a key) and without `ENABLE_QUICK_EDIT_MODE`. Read with `ReadConsoleInputW` key events; `WaitForSingleObject(conin, ms)` gives the deadline; `FlushConsoleInputBuffer` drops typeahead (the `TCSAFLUSH` rule). A guard restores the mode on drop | same | UTF-16 surrogate pairs are joined and written as UTF-8 straight into the existing pre-allocated wiping buffer. The line editor (Backspace, Ctrl-U, Ctrl-C, Ctrl-D, here also Ctrl-Z) moves into a shared, OS-free module so it is tested on the Mac. Git Bash (mintty) and some IDE terminals are pipes, not consoles: they get `NoTerminal` and a fixed line naming Windows Terminal, PowerShell or cmd. Ctrl-Break and Task Manager "End task" skip the guard, like `kill -9`. Not `rpassword` (it returns a plain `String`) and not `crossterm` (large). |
| Console owner (shell lock on user switch) | Owner uid of `/dev/console` | `holm-cli/src/term.rs:23`, `:31`, `:36` | `ProcessIdToSessionId(GetCurrentProcessId())` against `WTSGetActiveConsoleSessionId()`, plus `WTSQuerySessionInformationW(WTS_CURRENT_SESSION, WTSSessionInfoEx)` and its `SessionFlags == WTS_SESSIONSTATE_LOCK` | same | Better than macOS: the shell can also see a screen lock (Win+L). Compare against the value at start, never an absolute rule, or an RDP session (never the console) would lock at once. The `SessionFlags` inversion bug is on Windows 7 only. |
| CLI clipboard | arboard, `SetExtApple::exclude_from_history` | `clipboard.rs:23`, `:26`, `:37`, `:97`, `:164`, `:175` | Same arboard 3.7.0 with `SetExtWindows`: `exclude_from_monitoring()`, `exclude_from_history()` and `exclude_from_cloud()` | same | See 2.5. Needs the arboard dep widened to `cfg(any(target_os = "macos", windows))`. |
| Test-only Unix helpers | `OsStringExt`, `PermissionsExt`, `mkfifo`, `symlink` | `holm-cli/src/args.rs:1552`; `holm-cli/tests/shell.rs:904`, `:926`, `:1142`, `:1194`, `:1237`; `holm-cli/tests/transfer_commands.rs:304`; `holm-platform/tests/fs_store.rs:159`, `:173`, `:195`, `:414`, `:435`; `holm-platform/src/lib.rs:66`; `lock.rs:179` to `:216`; `transfer.rs:238` | Windows twins where they test a rule: `OsStringExt::from_wide` with a lone surrogate, a read-only folder via a deny ACE, `symlink_file` (skip the test if Developer Mode is off) | n/a | Permission tests need the ACL helper from T3. |

### 2.4 GUI

| Feature | macOS mechanism | file:line | Windows mechanism | Parity | Notes |
|---|---|---|---|---|---|
| GUI modules and deps | `#[cfg(target_os = "macos")]` on every egui module; eframe, rfd and the clipboard feature are macOS target deps | `holm-gui/src/lib.rs:15` to `:36`; `main.rs:15`, `:21`, `:29`; `holm-gui/Cargo.toml:34`, `:39` | `cfg(any(target_os = "macos", windows))`. Linux stays out | same | `eframe` 0.37 with `glow` uses WGL on Windows. A PC or VM with only the basic display driver has no OpenGL 2 and gets "Holm could not open its window". |
| GUI tests | 17 test files start `#![cfg(target_os = "macos")]` | `holm-gui/tests/*.rs:1`; `dev_unlock.rs:1` | Same widening. `egui_kittest` runs headless, so they run on `windows-latest` | same | Dev unlock stays debug-only. |
| Window icon | Empty `IconData` so the bundle's `Holm.icns` shows | `main.rs:72` to `:76` | `with_icon(eframe::icon_data::from_png_bytes(...))` with a 256 px PNG made from `packaging/macos/holm-icon.svg`, hash-gated like the fonts. The exe file icon in Explorer needs a resource (decision 8) | same | No new crate for the window icon: eframe already depends on `image` with `png`. |
| Minimised state | `NSWindow.isMiniaturized` | `holm-platform/src/window.rs:64`; `holm-gui/src/app.rs:101` to `:110`, `:491` | No FFI. egui-winit refreshes `ViewportInfo::minimized` every frame off macOS (`egui-winit-0.37.0/src/lib.rs:1502`), and `app.rs:493` already falls back to it | same | eframe 0.37 keeps running `App::logic` about every 100 ms for a minimised window (`eframe-0.37.0/src/native/run.rs:27`, `:255` to `:283`), so the idle lock and the clipboard clear still fire. Verify on the PC (checklist item 9). |
| Lock on sleep, screen lock, switch, logout | Four AppKit observers set an `AtomicBool` | `window.rs:91` to `:165`; `app.rs:37`, `:966`; `main.rs:107` | Same `LockEvents` API. `install()` starts one thread that owns a hidden top-level window (own class, never shown, `WS_EX_TOOLWINDOW`) and a message loop. It calls `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)` for `WTS_SESSION_LOCK`, `WTS_CONSOLE_DISCONNECT`, `WTS_REMOTE_DISCONNECT` and `WTS_SESSION_LOGOFF`; handles `WM_POWERBROADCAST` with `PBT_APMSUSPEND`; `RegisterPowerSettingNotification(hwnd, GUID_CONSOLE_DISPLAY_STATE)` for screens off; and `WM_QUERYENDSESSION` for logout. Each sets the flag and calls `egui::Context::request_repaint`. `Drop` unregisters, posts `WM_CLOSE` and joins | same | A separate window, not winit's: `WM_POWERBROADCAST` is sent, not posted, so winit's `with_msg_hook` never sees it, and subclassing winit's window is more unsafe code. A message-only window (`HWND_MESSAGE`) gets no broadcasts. Modern Standby laptops may skip `PBT_APMSUSPEND`; screens off and the session lock still fire, and `SleepWatch` stays as the fallback. |
| Hide from screenshots | `NSWindow.sharingType` via objc2 (safe) | `holm-platform/src/capture.rs:47`, `:59`, `:85`, `:94`, `:105`; `holm-gui/src/capture.rs` | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` on, `WDA_NONE` off, on every top-level window of the UI thread (`EnumThreadWindows(GetCurrentThreadId())`), from the UI thread. HWND from `raw-window-handle`'s `Win32WindowHandle`. `is_supported()` returns true on Windows | same | Works from Windows 10 2004. PrintScreen, Snipping Tool, Graphics Capture, Desktop Duplication and meeting apps see a black or empty window. A camera, an RDP viewer of that session, and code injected into Holm still see it. The "may hide Holm from some captures" wording stays. Test: `GetWindowDisplayAffinity` reads it back. |
| Thumbnail after a minimise lock | Dock thumbnail shows the last frame (CRYPTO.md gap) | none | `DwmSetWindowAttribute(hwnd, DWMWA_FORCE_ICONIC_REPRESENTATION, TRUE)` and `DWMWA_DISALLOW_PEEK`, so the taskbar preview and Aero Peek show the icon, not the vault | same (after the fix) | Better than macOS. Small extra FFI in the same file as capture. |
| Local time offset | `NSTimeZone.secondsFromGMT` | `window.rs:51`; used in `holm-gui/src/app.rs`, `rows.rs`, `screens/vault.rs` | `GetDynamicTimeZoneInformation`: `-(Bias + DaylightBias)` minutes when it returns `TIME_ZONE_ID_DAYLIGHT`, else `-(Bias + StandardBias)`, clamped as today | n/a | Display only. The bias math is a pure function tested on the Mac. |
| Shortcut wording | "Cmd+L", "Cmd+V" in messages and doc comments | `messages.rs:376`; `app.rs:56` | `egui::Modifiers::COMMAND` already means Ctrl off macOS. Messages pick "Ctrl" on Windows | n/a | Check Shift+Insert and Ctrl+Insert: the paste hook must treat them like Ctrl+V or block them (checklist item 6). |
| File dialogs | rfd (AppKit panel) | `holm-gui/src/file_dialog` (module gate `lib.rs:24`) | rfd 0.17.2 (COM `IFileDialog`) | weaker | The Windows dialog loads third-party shell extensions (cloud drive overlays, archivers) into Holm's process while the vault is open. The typed path field stays as the option that loads nothing. |
| Typed text and IME | IME off in a `SecretField` | GUI widgets | Same through winit. Check that Windows "text suggestions" and the touch keyboard do not learn from a secret field | weaker | Holm's fields are not native `ES_PASSWORD` controls, so Windows does not know they are secret. Checklist item 7. |
| Secure keyboard input | Secure Event Input not on yet (CRYPTO.md gap); input monitoring needs a TCC prompt | none | None. Any same-user process can install `WH_KEYBOARD_LL` with no prompt | none | Threat-model delta. |
| Accessibility tree | AccessKit to the AX API | GUI | AccessKit to UI Automation (`accesskit_windows` is already in the lockfile) | same | Same fixed labels, no values for secrets. |

### 2.5 Clipboard

| Feature | macOS mechanism | file:line | Windows mechanism | Parity | Notes |
|---|---|---|---|---|---|
| Clear after time, on lock, on quit | `holm_platform::clip_clear` with arboard | `clip_clear.rs` (no OS cfg); `clipboard.rs` gates above; `holm-gui/src/clipboard.rs` (gate `lib.rs:19`) | Same code. arboard's `clear` is `EmptyClipboard` | same | Only the `ConcealedClipboard` back end is new. |
| Keep out of history and sync | `org.nspasteboard.ConcealedType`, a request to managers; Universal Clipboard cannot be stopped | `clipboard.rs:37` (`SetExtApple`) | arboard `SetExtWindows` (arboard `src/platform/windows.rs:800` to `:840`) adds the registered formats `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` = 0 and `CanUploadToCloudClipboard` = 0 | same | Better than macOS: Windows itself honours these for Win+V history and cloud clipboard, so the copy does not reach other devices. Third-party managers may ignore them. arboard's docs advise using the monitoring flag alone; we set all three, because each is a 4-byte marker and some managers check only one. An ignored real-clipboard test checks the formats with `IsClipboardFormatAvailable`. |

## 3. Unsafe policy

**Today.** The workspace forbids `unsafe_code`. `holm-platform` denies it, and only `window.rs` and `zeroing_alloc.rs` may `allow` it, each block with a `// SAFETY:` comment. `scripts/ci-local.sh:121` to `:136` (`alloc_unsafe_gate`) fails if any other file contains `allow(unsafe_code`.

**Crate: `windows-sys`, not `windows`.** Pin `windows-sys = "=0.61.2"`, the version eframe, arboard, rfd, rustix and tempfile already pull in, so `Cargo.lock` gains no new package and no new `cargo vet` work. It is raw bindings with no runtime. The `windows` crate (0.62.2, in the graph only through `accesskit_windows`) adds `windows-core`, COM wrappers and proc macros, and most Win32 calls stay `unsafe` there anyway, so it buys little. Turn on only the features we use: `Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_System_Console`, `Win32_System_Threading`, `Win32_System_RemoteDesktop`, `Win32_System_Power`, `Win32_System_ErrorReporting`, `Win32_System_LibraryLoader`, `Win32_System_Diagnostics_Debug`, `Win32_System_Time`, `Win32_System_Com`, `Win32_UI_Shell`, `Win32_UI_WindowsAndMessaging`, `Win32_Graphics_Dwm`. Add it as `[target.'cfg(windows)'.dependencies]` of `holm-platform` only.

**File layout.** All Windows FFI lives in one folder of `holm-platform`, `src/win/`, in four files grouped by what a reviewer must reason about. Each file starts with `#![cfg(windows)]` and `#![allow(unsafe_code, reason = "...")]`.

| File | Holds | Safe API it exports |
|---|---|---|
| `win/fs.rs` | User SID, protected-DACL security descriptor, `CreateFileW` and `CreateDirectoryW` with it, folder ACL check, `MoveFileExW` with write-through, folder flush, `FileIdInfo` | `create_owner_only(path) -> io::Result<File>`, `create_owner_only_dir`, `dir_is_safe`, `replace_durable(from, to)`, `flush_dir`, `file_id(&File)` |
| `win/console.rs` | `CONIN$` handle, console mode guard, `ReadConsoleInputW`, `WaitForSingleObject`, `FlushConsoleInputBuffer` | `Console::open()`, `read_key(deadline) -> Option<Key>`, mode guard with `Drop` |
| `win/events.rs` | Hidden window thread, WTS and power registration, window affinity, DWM attributes, session lock query, time zone | `LockEvents` (same API as macOS), `set_capture(hwnd, on)`, `session_state()`, `utc_offset_secs()` |
| `win/process.rs` | WER flags and exclusion, `SetErrorMode`, `SetDefaultDllDirectories`, known folder path, optional process DACL and mitigation policy | `harden_process() -> io::Result<()>`, `local_app_data() -> Option<PathBuf>` |

`src/win/mod.rs` itself is `#![forbid(unsafe_code)]` and only declares the four files. The callers (`fs_store`, `lock`, `paths`, `private_file`, `tty`, `capture`, `hardening`, `clipboard`) keep `#![forbid(unsafe_code)]` and call the safe wrappers. `holm-gui` and `holm-cli` stay `#![forbid(unsafe_code)]`. Where a safe std API exists (`custom_flags`, `attributes`, `file_attributes`, `sync_all`, `try_lock`), we use it and add no FFI.

**Rules for every unsafe block.**

- One FFI call or one pointer step per block (`clippy::multiple_unsafe_ops_per_block`).
- A `// SAFETY:` comment directly above it that names each pointer, its length or lifetime, and who frees what (`LocalFree`, `CoTaskMemFree`, `CloseHandle`). Handles go into `OwnedHandle` at once so `Drop` closes them.
- No `String` or `format!` of secret data near FFI. Console input goes from `KEY_EVENT_RECORD` straight into the wiping buffer.
- Errors carry `GetLastError` codes only, never a path, matching the current "no path in messages" rule.

**`ci-local.sh` changes.**

1. `alloc_unsafe_gate`: the expected list becomes exactly `window.rs`, `zeroing_alloc.rs`, `win/fs.rs`, `win/console.rs`, `win/events.rs`, `win/process.rs`. Any other file with `allow(unsafe_code` fails.
2. New lints in `holm-platform/Cargo.toml`: `clippy::undocumented_unsafe_blocks = "deny"` and `clippy::multiple_unsafe_ops_per_block = "deny"`. The lint-drift gate learns these two keys.
3. New gate `windows-check`: `cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings`. Without it, the Windows files are never compiled or linted on the Mac, and the lints above would never see them.

## 4. Threat-model delta

**Weaker on Windows.**

- Pagefile and hibernation file are plain unless BitLocker or Device Encryption is on. On macOS both are encrypted by default with FileVault.
- Any same-user process can read Holm's memory, log keystrokes (`WH_KEYBOARD_LL`) and capture the screen, with no permission prompt. macOS asks the user (TCC) for input monitoring and screen recording.
- Crash dumps cannot be fully turned off from inside the process. An admin `LocalDumps` policy wins.
- The Windows file dialog loads third-party shell extensions into Holm.
- Directory sync after a rename relies on `MOVEFILE_WRITE_THROUGH` and NTFS journaling, not a documented directory fsync.
- Old copies: Volume Shadow Copies, System Restore, File History and OneDrive play the role of Time Machine. Documents and Desktop are often inside OneDrive, so an export saved there is uploaded at once.

**Same on Windows.** Vault format and crypto, the unlock throttle, decrypt on demand, the zeroing allocator, the single-instance lock, owner-only files (an ACL, not a mode), lock on idle, minimise, sleep, screen lock and user switch, clipboard clear, and capture exclusion.

**Better on Windows.** Clipboard history and cloud sync honour Holm's exclusion formats; the CLI shell can see a screen lock; the taskbar preview can be forced to show the icon.

**Text to add to `docs/THREAT-MODEL.md`.** A new section after "Limits we state plainly":

```markdown
## Windows

The Windows build is a test build. Use a throwaway vault, not real secrets, until this note changes.

- Holm creates the vault, its temp files, exports, backups and prefs with an access list that allows only your Windows account. Administrators can still take ownership, as root can on macOS.
- The page file and the hibernation file are not encrypted unless BitLocker or Device Encryption is on for the system drive. Without it, secrets in memory can be written to disk in the clear. Turn it on.
- Windows lets any program running as you read Holm's memory, record your keystrokes and capture your screen without asking you. Holm cannot stop a program that is already running as you.
- Holm turns off the heap part of Windows Error Reporting dumps. An administrator policy can still make Windows write a full crash dump, and any program running as you can make one.
- "Hide window from screenshots" uses SetWindowDisplayAffinity. Most capture tools then see an empty window. A camera, a remote desktop viewer and code running inside Holm still see it.
- A copy is marked so that Windows clipboard history and cloud clipboard skip it. Other clipboard managers may ignore the mark.
- The Choose button opens the Windows file dialog, which loads other vendors' shell extensions into Holm while the vault is open. Typing the path avoids that.
- An export saved in Documents or Desktop may be uploaded by OneDrive at once. Holm marks exports so Windows Search does not index them.
- Shadow copies, System Restore, File History and OneDrive keep old copies of the vault, like Time Machine. A deleted item stays in those copies.
```

Also add one row to the attackers table and change two rows:

- "Crash dump or freed memory read later": add "On Windows: WER heap dumps off (`WerSetFlags`), no `RLIMIT_CORE`; see Windows."
- "Hibernation image or crash dump": add "On Windows, advice is BitLocker or Device Encryption."
- New row: "Program planted next to `holm-gui.exe` (DLL search order) | Yes | System DLLs load from System32 only (`SetDefaultDllDirectories`, `/DEPENDENTLOADFLAG`)."

Never-claim 3 and 5 stay as they are and apply to Windows. Add no Windows claim stronger than the text above.

## 5. Verification without a Windows machine

### 5.1 Cross-check from the Mac (tested)

`cargo check --target x86_64-pc-windows-msvc` works on the Mac and is cheap. It needs only the target's standard library, `rustup target add x86_64-pc-windows-msvc` (118 MB on disk for the pinned 1.99.1), and no cargo-xwin, no MSVC and no Windows SDK, because a check never links.

`libsodium-sys-stable` is not in the way: it is only in the separate `oracle/` workspace, not in the product `Cargo.lock`. `docs/BUILD-WINDOWS.md` says the product build needs it; that line is wrong and should be fixed in T10. The product graph has no C build step on Windows (`cc` is used only by Linux and Haiku crates).

Result on 291994b, `cargo check --workspace --all-targets --locked --target x86_64-pc-windows-msvc`, about 1 minute:

- **Error**: `holm-gui` lib, `messages.rs:20` imports the macOS-only `crate::rows`.
- **Warnings** that `clippy -D warnings` would fail on: unused imports `std::sync::mpsc` and `std::time::Duration` at `holm-platform/src/private_file.rs:152` to `:153` (only used by Unix-gated tests), and unused variant `CtrlC` at `holm-cli/tests/shell.rs:90`.
- `holm-crypto`, `holm-core`, `holm-platform` and `holm-cli` compile.

**Linking and running tests** from the Mac would need `cargo-xwin`, which downloads the MSVC CRT and the Windows SDK (several hundred MB), plus Wine to run the test binaries. That is a large toolchain, so it was not installed. The `windows-latest` job in section 6 does the linking and runs the tests instead.

### 5.2 Unit-test strategy for `cfg(windows)` code

1. **Split pure logic from FFI.** Every rule with a decision in it is a plain function with no cfg gate, so it runs in the Mac test suite: the line editor fed with key events, Windows path rules (streams, reserved names, trailing dots, device paths), WTS code to lock reason mapping, the folder-ACE rule written over plain structs (SID kind, access mask, allow or deny), the retry rule for sharing violations, the directory-flush error classifier, and the time zone bias math.
2. **Thin FFI wrappers with read-back tests**, `#[cfg(windows)]`, run on `windows-latest` and on the friend's PC with `cargo test`: create a file and read its DACL back with `GetSecurityInfo` (one ACE, the user, protected); `replace_durable` round trip over an existing file; `file_id` equal for two handles to one file and different for two files; `WerGetFlags` shows `NOHEAP` after `harden_process`; `GetWindowDisplayAffinity` reads back the value on a hidden test window; reparse point refused (skip if symlink creation is not allowed).
3. **Crash tests.** The existing child-process crash tests in `holm-platform` (exit at each `SaveStep`) run unchanged on Windows and check that the vault is always the old or the new file.
4. **Manual-only, marked `#[ignore]`**: real console prompts, the real clipboard, session events (they need Win+L or a sleep). They are covered by the checklist below.
5. **Compile gate on the Mac**: the `windows-check` clippy gate from section 3 compiles every Windows test file on each local CI run.

### 5.3 Manual checklist for the friend

Test vault only. Never type a real password or import a real export. Use a new folder, for example `C:\HolmTest`.

1. Download the zip and its `.sha256`. In PowerShell: `Get-FileHash .\holm-windows-x86_64.zip -Algorithm SHA256` and compare. If the build came from Actions, also run `gh attestation verify .\holm-windows-x86_64.zip --repo sunnat629/holm`.
2. Extract to `C:\HolmTest`, not into `Downloads`. Note what SmartScreen shows. If Smart App Control blocks the exe with no "Run anyway", stop and tell us. Do not turn Smart App Control off for this test.
3. Run `holm-gui.exe` with no arguments. The vault folder must be `%LOCALAPPDATA%\Holm`. Then run `icacls "%LOCALAPPDATA%\Holm"` and `icacls "%LOCALAPPDATA%\Holm\holm.vault"`: only your account, and no `(I)` inherited entries.
4. Create a vault, add a login with a preset and a custom field, lock, unlock. Try 3 wrong passwords and check the wait grows.
5. Copy a password. Press Win+V: the password must not appear in clipboard history. If "Sync across your devices" is on, check another device does not get it. Wait 30 seconds: the clipboard must be empty.
6. Copy a password, then in a plain field (Title) press Ctrl+V, Shift+Insert and right-click Paste. Write down what each does.
7. Click into the master password field and type. Check that no text suggestion bar or touch keyboard prediction shows typed characters.
8. Turn on "Hide window from screenshots". PrintScreen, Win+Shift+S, and sharing the screen in Teams or Zoom must show Holm as black or empty. Turn it off and check it shows again.
9. With the vault open: minimise and check it is locked when restored; press Win+L and unlock Windows; put the PC to sleep and wake it; switch user if you have a second account. Each time the vault must be locked. Hover the taskbar button while minimised: the preview must not show vault content.
10. Leave the vault open and idle for the auto-lock time: it must lock, even while minimised.
11. Start a second `holm-gui.exe` on the same vault: it must refuse with fixed text.
12. Export a CSV to `C:\HolmTest`. `icacls` shows only you; `attrib` shows the `I` (not indexed) flag. Delete the file. Try to export to `C:\HolmTest\x.csv:hidden` and to `C:\HolmTest\NUL.csv`: both must be refused.
13. CLI in Windows Terminal, PowerShell and cmd: `holm.exe --vault C:\HolmTest\holm.vault list`. The password must not echo. Press Ctrl-C at the prompt, then type in the same window: echo must be back. Try `echo pw | holm.exe list`: it must refuse. Try it in Git Bash: it must say it needs a real console.
14. `holm.exe get 1 --copy password`, then Win+V: not in history; cleared after the time.
15. `holm.exe shell`, then Win+L and unlock: the shell must be locked.
16. Optional: a USB stick formatted exFAT, create a vault there, add an item, unplug only after Holm says saved.
17. Optional: `cargo test --workspace --locked` if he builds from source, and send the summary lines.
18. For any failure, send the step number, a screenshot and the first 60 lines of output. Never send a vault, an export or a password.

## 6. Build and release

### Option A: GitHub Actions, `windows-latest`, manual trigger

A new `.github/workflows/release-windows.yml` with `on: workflow_dispatch` only:

- `permissions: contents: read`, plus `id-token: write` and `attestations: write` for the attestation step. Actions pinned by commit SHA, `persist-credentials: false`, as in `ci.yml`.
- Steps: checkout, pinned toolchain from `rust-toolchain.toml`, `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `cargo build --release --locked -p holm-gui -p holm-cli`.
- Package `holm-gui.exe`, `holm.exe`, `LICENSE` and a short `README-WINDOWS.txt` into `holm-windows-x86_64-<short sha>.zip`. Write `Get-FileHash -Algorithm SHA256` output to a `.sha256` file.
- `actions/attest-build-provenance` signs a provenance statement that ties the zip's hash to this repo, this commit and this workflow, through Sigstore. It is free for public repos. Anyone can check it with `gh attestation verify`.
- Upload both files with `actions/upload-artifact`. No release is published and no tag is pushed.

The repo is public, so standard runners cost no minutes. This still conflicts with the project rule that CI runs locally only (`docs/DECISIONS.md:8` and the "local CI only" owner rule), and needs the owner's OK (decision 1). Note that DECISIONS line 8 already says to revisit Actions once the repo is public. `ci-local.sh` stays the merge gate; this job only builds and tests the Windows zip on demand.

### Option B: the friend builds and sends the zip

He installs Visual Studio Build Tools and rustup, runs `cargo build --release`, and sends the zip back.

Weaker for supply-chain trust:

- The binary comes from a machine nobody else controls or can inspect: its toolchain, PATH, Visual Studio extensions and any malware on it are unknown.
- There is no record tying the zip to a commit. We would trust a file sent over chat.
- MSVC builds embed timestamps and paths, so we cannot rebuild and compare without extra work (`/Brepro`).
- It is fine for his own testing, since he runs what he built from source he can read. It is not fit as a build we hand to anyone else.

### Authenticode signing

- **Unsigned.** A downloaded exe carries the Mark of the Web. SmartScreen shows "Windows protected your PC" with "More info" then "Run anyway". On Windows 11 with Smart App Control in enforcement mode, an unsigned downloaded exe can be blocked with no way past it.
- **OV or EV certificate** from a public CA: roughly USD 200 to 700 a year. Since June 2023 the private key must sit on a hardware token or a cloud HSM. Since 2024, EV no longer gives instant SmartScreen reputation; both kinds build reputation over downloads.
- **Microsoft Trusted Signing** (Azure): about USD 10 a month, no token, works from Actions. Identity checks for individuals were limited to some countries at launch; check eligibility before relying on it.
- **Free or cheap for open source**: SignPath Foundation signs OSS releases from a public CI build for free (it needs Option A); Certum's open-source code signing certificate is low cost for individuals.

Signing waits for the owner's later signing work and is not needed for the friend test.

### Recommendation

**Option A**, with the attestation, no signing for the test build. It gives a zip whose hash anyone can tie to a public commit and workflow, it runs the Windows tests the Mac cannot run, and it costs nothing on a public repo. If the owner keeps the local-only rule, use Option B for the friend's own testing only, and never pass that zip on.

## 7. Task breakdown

Each task is one PR into `windows`, gated by `scripts/ci-local.sh` (with the new `windows-check` gate from T1 on) and, from T2 on, by a green Option A run when the owner approves it. "Opus" means the final security review; nothing merges without it.

| # | Task | Files | Tests | Review gate |
|---|---|---|---|---|
| T0 | Fix the Windows compile break and warnings | `holm-gui/src/messages.rs`, `holm-gui/src/rows.rs` (move `ExpiryBadge` out of the gated module, or gate the import), `holm-platform/src/private_file.rs`, `holm-cli/tests/shell.rs` | `cargo check` and `clippy` for the Windows target clean | Sonnet |
| T1 | `windows-sys` dep, `src/win/` skeleton, unsafe gate, new clippy lints, `windows-check` gate | `holm-platform/Cargo.toml`, `src/lib.rs`, `src/win/mod.rs`, `scripts/ci-local.sh`, `deny.toml` if needed, `supply-chain/` | Gate fails on a planted `allow(unsafe_code`; lockfile unchanged except the direct dep | Opus |
| T2 | Process hardening: WER flags, error mode, DLL directories, `/DEPENDENTLOADFLAG` | `win/process.rs`, `hardening.rs`, `holm-gui/src/main.rs`, `holm-cli/src/main.rs`, `holm-gui/build.rs` and `holm-cli/build.rs` (link arg, Windows only) | `WerGetFlags` read-back; `dumpbin /headers` shows the load flag (CI step) | Opus |
| T3 | Owner-only files and folders, folder ACL check, not-indexed exports | `win/fs.rs`, `fs_store.rs` (`create_exclusive`, `check_dir`), `paths.rs`, `lock.rs`, `private_file.rs`, `prefs.rs` | Pure ACE-rule tests on the Mac; DACL read-back tests on Windows; Windows twins of every `0600` test | Opus |
| T4 | Durable save: write-through rename, folder flush, file id, reparse refusal, retry, Windows path rules | `win/fs.rs`, `fs_store.rs`, `lock.rs`, `transfer.rs` | Path-rule tests on the Mac; crash tests and round trips on Windows | Opus |
| T5 | Default vault path in LocalAppData | `win/process.rs`, `paths.rs` | Path built under a given folder (pure); real call returns an absolute path (Windows) | Opus |
| T6 | Console prompt and shell session check | `win/console.rs`, `tty.rs` (shared line editor), `holm-cli/src/term.rs` | Line editor tests on the Mac; `#[ignore]` console tests; checklist 13 and 15 | Opus |
| T7 | Windows clipboard with the three exclusion formats | `clipboard.rs`, `holm-platform/Cargo.toml`, `holm-gui/Cargo.toml` | `clip_clear` tests unchanged; ignored real-clipboard test checks the formats | Opus |
| T8 | GUI on Windows: widen gates, Ctrl wording, window icon, test files | `holm-gui/src/lib.rs`, `main.rs`, `Cargo.toml`, `messages.rs`, `tests/*.rs`, a hash-gated icon PNG | All kittest suites pass on `windows-latest` | Sonnet (UI), then Opus (secret paths now built on a new OS) |
| T9 | Lock events, capture affinity, DWM thumbnail, time zone | `win/events.rs`, `capture.rs`, `holm-gui/src/app.rs`, `holm-gui/src/capture.rs` | WTS mapping and bias tests on the Mac; affinity read-back on Windows; checklist 8 to 10 | Opus |
| T10 | Docs: threat model text from section 4, CRYPTO known gaps, DECISIONS entries, BUILD-WINDOWS rewrite, a Rust lesson on Windows FFI | `docs/*.md`, `docs/learn/` | Never-claim check by hand | Haiku writes, Opus checks every claim |
| T11 | Release workflow (only if decision 1 is yes) | `.github/workflows/release-windows.yml` | One manual run, attestation verifies | Opus |
| T12 | Friend's test pass and a fix wave | as found | Checklist 1 to 18 | Opus on each fix |

Optional tasks after decisions 4 and 5: a locked key page with `VirtualLock`, and the process DACL and extension-point policy. Each is its own PR with an Opus review.

## 8. Open owner decisions

1. **Release path.** Allow one manual `workflow_dispatch` Windows job on GitHub Actions (Option A, with attestation) as an exception to the local-CI-only rule? Recommended: yes.
2. **Default vault folder.** `%LOCALAPPDATA%\Holm` (recommended) or `%APPDATA%\Holm` (roams on domain PCs)?
3. **WER registry exclusion.** Also call `WerAddExcludedApplication`, which writes a value under HKCU that stays after Holm is deleted? Recommended: no for the test build; `WerSetFlags` only.
4. **Memory locking.** Keep DECISIONS A4 (no `VirtualLock`) and advise BitLocker (recommended), or build a locked key page now?
5. **Process hardening extras.** Add the process DACL tightening and the extension-point mitigation policy? Both are best effort. Recommended: after the friend test, as a separate PR.
6. **Signing for a public Windows release.** SignPath Foundation (free, needs Option A), Certum open source, or Microsoft Trusted Signing? None for the friend test.
7. **Windows 10 22H2.** Support it as stated, or say "runs on, not recommended" now that consumer security updates have ended? Recommended: the second.
8. **Exe file icon.** Add a resource-compiler build dependency (for example `winresource`) so Explorer shows the Holm icon on the exe, or ship with the window icon only? Recommended: window icon only for the test.
9. **Who is in the owner-only ACL.** Your account only (matches `0600`, recommended), or your account plus SYSTEM (helps some backup tools)?
10. **First zip contents.** Ship both `holm-gui.exe` and `holm.exe` (recommended), or the GUI only?
