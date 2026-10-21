# Learn Rust with Holm

A short Rust course for someone who has never written Rust. Each lesson goes with one task
in the build, uses real code from this repo, and compares ideas to Kotlin.

Every lesson has the same five parts: what we built, Rust ideas, why it matters for
security, three exercises, and what to read next in
[The Rust Programming Language](https://doc.rust-lang.org/book/).

| Lesson | Topic |
|---|---|
| [00](00-setup-and-cargo.md) | Install Rust, Cargo workspaces, `fn main`, `let`, and `forbid(unsafe_code)`. |
| [01](01-dependencies-and-supply-chain.md) | Continuous integration and supply-chain gates: what a dependency is and why we count them. |
| [02](02-ownership-and-drop.md) | Secret types: ownership, `Drop`, and why a secret must not be `Clone`. |
| [03](03-errors-and-results.md) | Errors and randomness: `Result`, the `?` operator and asking the OS for random bytes. |
| [04](04-constants-overflow-and-features.md) | Argon2id: constants, integer overflow, Cargo features, and checking costs before doing work. |
| [05](05-slices-and-borrowing.md) | XChaCha20-Poly1305: slices, arrays and `Vec`, borrowing, lifetimes, and why decryption is all or nothing. |
| 06 | [Parsing bytes safely](06-parsing-bytes-safely.md): the vault header, with no panics on bad input. |
| 07 | [Modules and encapsulation](07-modules-and-encapsulation.md): the envelope that creates, opens, saves and re-keys a vault, and how privacy keeps the data key in one module. |
| 08 | [Property tests and fuzzing](08-property-tests-and-fuzzing.md): letting the computer invent hostile inputs. |
| 09 | [Feature unification and cargo vet](09-feature-unification-and-vet.md): turning on a feature inside a transitive dependency, and imports, trust and exemptions in `cargo vet`. |
| 10 | [Enums, newtypes and validation](10-enums-newtypes-and-validation.md): items as an enum with data, wiping secret text types, and field errors that name the field but never the value. |
| 11 | [Randomness without bias](11-randomness-without-bias.md): why `% n` is biased, rejection sampling, `NonZeroU32`, a `dyn Trait` test seam and a built-in wordlist. |
| 12 | [Owning the check](12-owning-the-strength-check.md): why Holm wrote its own strength check instead of wrapping zxcvbn, a length cap that refuses before it copies, `Zeroizing` scratch buffers, a cheapest-split table over `&[char]`, and a dev-only oracle test with a seeded generator. |
| 13 | [Serde and a versioned binary format](13-serde-and-versioned-formats.md): serde derive on private wire types only, a format that does not describe itself, a schema version prefix, decode then validate with bounded lengths, rejecting trailing bytes, and measuring before allocating. |
| 14 | [Time and saturating maths](14-time-and-saturating-maths.md): `Duration`, monotonic `Instant` vs wall `SystemTime`, `saturating_*` and `checked_*`, `Default`, a trait as a test seam, and the `Send` bound. |
| 15 | [Generics and trait objects](15-generics-and-trait-objects.md): the vault session, generic over its store with `Session<S: VaultStore>` and a `Box<dyn Clock>`, `Option` as a locked/unlocked state, `&mut self`, `From` and `?` into one error enum, and why a password change writes before it swaps keys. |
| 16 | [Borrowing in practice](16-borrowing-in-practice.md): returning `&str` from a `&mut self` method, `position`/`iter_mut`/`retain`, `std::mem::replace` for undo, splitting a module into a folder, and `compile_fail` doctests. |
| 18 | [Files, fsync and processes](18-files-fsync-and-processes.md): `OpenOptions` with `create_new` and `mode`, `#[cfg(unix)]`, why write-sync-rename-sync survives a crash, checking the file you opened, and a crash test that runs itself as a child process. |
| 21 | [Fuzzing structured inputs](21-fuzzing-structured-inputs.md): `#[derive(Arbitrary)]` so the fuzzer builds typed inputs, a test-only Cargo feature and why it must never ship, proving an allocation bound with `-malloc_limit_mb`, property tests that generate only valid data, and what an end-to-end test proves that unit tests do not. |
| 22 | [A GUI crate and its supply chain](22-a-gui-crate-and-its-supply-chain.md): a library and a binary in one crate, macOS-only dependencies, why eframe's feature list is short, fonts built in with `include_bytes!`, a single-instance lock with `File::try_lock`, and `deny` targets plus vet imports, trust and exemptions for a big new graph. |
| 23 | [A password widget that wipes](23-a-password-widget-that-wipes.md): why `TextEdit` is not for secrets, a `Vec` that never grows, `std::mem::replace` to move a secret out without a copy, reading raw input events, painting dots instead of text, and testing a widget that has no value. |
| 24 | [State machines and worker threads](24-state-machines-and-worker-threads.md): an enum as a screen state machine, moving the session into a worker thread and getting it back, `mpsc::Receiver::try_recv` and a disconnected channel, why the session has exactly one owner, `request_repaint_after` for a countdown, and mapping errors to fixed text. |
| 25 | [Borrowing across a frame](25-borrowing-across-a-frame.md): building item rows once and owning them, `mem::replace` to move a view out of a borrowed enum, panels with the central panel last, and a capped pre-allocated text buffer that wipes itself. |
| 26 | [The clipboard is shared](26-the-clipboard-is-shared.md): a trait as a seam for the OS clipboard, `Cow<str>` to hand over text without a copy, extension traits (`SetExtApple`), wiping pasted text, all-or-nothing pastes, and why "concealed" is a request that clipboard managers may ignore. |
| 27 | [Locking without a frame](27-locking-without-a-frame.md): eframe's `logic` versus `ui`, why the idle check must run when no frame is drawn, `Drop` wiping a replaced screen, `consume_shortcut` for Cmd+L, and a dirty-lock dialog that never loses changes silently. |
| 28 | [Testing a whole app](28-testing-a-whole-app.md): an integration test as its own crate, `drop` to end a lock's job, a fake shared through `Rc<RefCell<…>>`, reading modes and bytes on disk without printing a secret, `#[ignore]` tests run by hand, and what a headless test proves versus what only a person at a real Mac can check. |
| 29 | [Iterators and lifetimes](29-iterators-and-lifetimes.md): `ItemSummary<'a>` borrowing from the session, `filter`/`map`/`collect`, closures, `sort_by` with `then_with`, and `#[default]` on enum variants. |
| 30 | [Parsing untrusted text](30-parsing-untrusted-text.md): byte offsets instead of `char` indices in a `&str`, a small state machine with `match`, measuring before allocating so a wiping buffer never grows, errors that carry a line and never content, and a property test against an oracle crate. |
| 31 | [Hostile input, all or nothing](31-hostile-input-all-or-nothing.md): a `HashMap` header map that stores positions, never text, `mem::take` out of a wiping buffer, an undo closure that makes an import all or nothing, bad rows reported by number only, and why Holm never guesses where a secret goes. |
| 32 | [Building output safely](32-building-output-safely.md): measure-then-fill so a growing `String` leaves no copy of a password behind, RFC 4180 quoting with `"` doubled, `OpenOptions::create_new` and `OpenOptionsExt::mode(0o600)` for a file nobody else can read, a read that refuses FIFOs and growing files, and why Holm does not escape spreadsheet formulas. |
| 33 | [A CLI without a framework](33-a-cli-without-a-framework.md): `OsString` and `args_os`, matching on slices of arguments, a `dyn Terminal` trait object so tests swap in a fake, RAII guards that restore the terminal in `Drop`, and `ExitCode` instead of `process::exit`. |
| 34 | [Moving secrets in and out](34-moving-secrets-in-and-out.md): `std::mem::take` to move a typed password into an item without a copy, `to_owned()` straight into a wiping type when a copy can't be avoided, a `Box<dyn Fn>` factory so tests swap in a fake clipboard, and one monotonic `Instant` deadline for the clipboard clear, which runs before any error is returned. |
| 35 | [A read-eval loop with a deadline](35-a-read-eval-loop-with-a-deadline.md): a `loop` with `match` on an outcome enum, the earlier of two `Option` deadlines with `into_iter().chain().min()`, a quote-aware tokenizer as a small state machine over `(mode, char)`, and keeping per-line secrets in loop locals so they are wiped every turn. |
| 36 | [Thin screens over the core](36-thin-screens-over-the-core.md): moving owned data through a worker `Job` and back, a GUI flow as a state-machine enum, and why a warning is a core constant the screens only show. |
| 37 | [Hold to reveal](37-hold-to-reveal.md): immediate mode means no stored flag, `Response::is_pointer_button_down_on` plus `contains_pointer`, painting a borrowed `&str` instead of using a `TextEdit`, and drawing an icon from lines when the font has no glyph. |
| 38 | [One clear for every client](38-one-clear-for-every-client.md): a trait in a shared crate with a test fake, owning a secret in `PendingClear::run(self)`, and two clocks (monotonic and wall) so a sleep cannot delay a deadline. |
| 39 | [One flow, two front ends](39-one-flow-two-front-ends.md): generic functions over `S: VaultStore`, error enums that hold no payload, and `symlink_metadata` for "does anything exist here". |
| 40 | [A native dialog from egui](40-a-native-dialog-from-egui.md): a trait seam around an OS dialog with a test fake, a two-frame state machine, and why blocking in `update` is allowed. |
| 47 | [One row of buttons](47-one-row-of-buttons.md): moving a button's body into a method, testing layout with accessibility rectangles, and `get_by_label` against `query_all_by_label(..).count()` for "exactly one" and "none" checks. |
| 45 | [Shipping a Mac app by hand](45-shipping-a-mac-app-by-hand.md): the `.app` folder layout, `Info.plist`, ad-hoc signing against Developer ID, and why no `cargo-bundle`. |

## Side tracks

- [Building the Holm GUI with egui](gui/README.md): immediate mode for Compose developers, GUI security rules, and a working unlock screen tutorial.
