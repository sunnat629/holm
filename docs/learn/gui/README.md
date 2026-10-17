# Building the Holm GUI with egui

This guide is for you: a Kotlin and Compose developer who has not written Rust yet. It explains how a desktop GUI works in egui, how Holm will use it, and the security rules that make a password manager GUI different from a normal one.

Version pinned: **egui 0.37.0 and eframe 0.37.0** (latest on crates.io on 2026-10-17). Everything below was checked against that source. It needs **Rust 1.95 or newer**. egui changes names often. If you read an older tutorial, see "Names that moved" in section 2.

The screens we are building are in [`docs/design/ui-mock.html`](../../design/ui-mock.html). Open it in a browser. The mapping from old Compose screens to new ones is in [`docs/design/ui-screen-map.md`](../../design/ui-screen-map.md).

Contents:

1. Mental model
2. The eframe app skeleton
3. App state and screens
4. Security concerns specific to the GUI
5. Testing egui UIs
6. Tutorial: a working unlock screen
7. Kotlin to Rust cheat-sheet
8. References

---

## 1. Mental model

### Immediate mode versus Compose

Compose is **retained mode with a diff**. You describe the UI. Compose remembers a tree of it. When state changes, it recomposes only the parts that read that state.

egui is **immediate mode**. There is no tree that you keep. Your `ui` function runs **every frame** and draws the whole screen from scratch. Widgets are function calls, and a call both draws the widget and returns what the user did with it.

```rust
if ui.button("Lock now").clicked() {
    self.lock();
}
```

In Compose you would write a `Button(onClick = { vm.lock() })`. In egui the button call returns a `Response`. You ask it `.clicked()` right there, in the same line of code. No callback, no listener.

### Where state lives

All state lives in **your own struct**. egui keeps only small things for you (scroll position, which widget has focus, window positions). There is no `remember`, no `mutableStateOf`, no `StateFlow`. A field in your struct is the state.

| Compose | egui |
|---|---|
| `ViewModel` holds state | your `struct HolmApp` holds state |
| `@Composable fun Screen(state)` | `fn show(&mut self, ui: &mut Ui)` |
| state change causes recomposition | there is no recomposition, the next frame just reads the new value |
| `remember { }` | a field on your struct |
| `LaunchedEffect`, coroutines | a worker thread plus a channel, then `ctx.request_repaint()` |

### What a frame is

One frame is one pass of: collect input, run your `ui` function, paint the shapes it produced. Your function must be fast (a few milliseconds). Never do slow work in it. Argon2 takes about a second, so it goes on a worker thread (see the tutorial).

### Repaint: when does a frame run?

egui does **not** redraw 60 times a second all the time. It repaints when:

- the user does something (mouse, key, window event), or
- you ask for it.

This matters for Holm. A timer such as auto-lock after 5 minutes of no input will never fire if no frame runs. So you ask for a frame in the future:

```rust
ctx.request_repaint_after(std::time::Duration::from_secs(1));
```

Rules:

- Call it **every frame** while a timer is running. It is a one-shot request.
- A worker thread that finishes must call `ctx.request_repaint()` (clone the `Context`, it is cheap) or the UI will not notice the result until the mouse moves.
- Use the same trick for the clipboard auto-clear countdown and the "N s left" label.

Read more: Compose's own [mental model page](https://developer.android.com/develop/ui/compose/mental-model) is a good contrast to hold in your head.

---

## 2. The eframe app skeleton

`egui` is the UI library. `eframe` is the window and event loop around it (it uses `winit` for windows and a GPU or OpenGL backend for drawing). You write one type that implements `eframe::App`.

### The App trait in 0.37

```rust
impl eframe::App for HolmApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        // draw the whole window here, every frame
    }
}
```

- `ui` is required. It is called every frame with a root `Ui` that covers the window.
- `logic(&mut self, ctx, frame)` is optional. It runs before `ui` and is for work that is not drawing (timers, polling channels). Holm may use it for the auto-lock check.
- Treat it like a trait in Kotlin: an `interface` that your class promises to implement. (Rust Book chapter 10.2 below.)

### Names that moved

Many tutorials online are for older versions. In 0.37:

| Old name (older tutorials) | 0.37 |
|---|---|
| `fn update(&mut self, ctx, frame)` | `fn ui(&mut self, ui, frame)` (and optional `logic`) |
| `egui::TopBottomPanel::top("id")` | `egui::Panel::top("id")` |
| `egui::SidePanel::left("id")` | `egui::Panel::left("id")` |
| `panel.show(ctx, ..)` | `panel.show(ui, ..)` |
| `show_inside` | deprecated, use `show` |

If your code does not compile and a tutorial said otherwise, check this table first.

### Starting the app

```rust
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Holm")
            .with_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native("Holm", options, Box::new(|_cc| Ok(Box::new(HolmApp::new()))))
}
```

`..Default::default()` fills the other fields with defaults, like Kotlin named arguments with default values. The closure builds your app once. `_cc` is the creation context (the leading underscore says "unused").

### Panels, windows, modals

| Compose / Material | egui 0.37 |
|---|---|
| `Scaffold` with top bar | `egui::Panel::top("toolbar").show(ui, ..)` |
| navigation drawer, list pane | `egui::Panel::left("list").show(ui, ..)` |
| main content | `egui::CentralPanel::default().show(ui, ..)` |
| `AlertDialog` / modal | `egui::Modal::new(id).show(ctx, ..)` |
| floating dialog | `egui::Window::new("Title").show(ctx, ..)` |
| `LazyColumn` | `egui::ScrollArea::vertical().show(ui, ..)` |

Order matters: add the side and top panels **first**, then `CentralPanel` **last**. It takes whatever space is left. Holm's three-pane vault view is a left panel (categories), another left panel (item list) and a central panel (detail).

### Layout

Layout is simple and top to bottom by default. You do not give sizes to a parent and wait for a measure pass.

- `ui.horizontal(|ui| { .. })` is a `Row`. `ui.vertical(..)` is a `Column`.
- `ui.vertical_centered(|ui| ..)` centres children.
- `ui.add_space(8.0)` is a `Spacer`.
- `egui::Grid::new("id")` lays out a table (rows end with `ui.end_row()`).
- Sizes are in points (like dp).

The `|ui| { .. }` part is a closure, the same as a Kotlin lambda `{ ui -> .. }`.

### Widgets

`ui.label("text")`, `ui.heading("Title")`, `ui.button("OK")`, `ui.checkbox(&mut flag, "Remember")`, `ui.add(egui::Slider::new(&mut len, 12..=64))`, `ui.add_enabled(cond, widget)`, `ui.spinner()`, `ui.colored_label(color, "text")`.

Note `&mut flag`. The widget edits your field directly. In Compose you would pass `checked` and `onCheckedChange` and update state yourself. In egui you lend the field out mutably (Rust Book chapter 4: ownership and borrowing), and the widget changes it in place.

### Widget identity

Because there is no tree, egui tells widgets apart by an **id** made from their label or from `id_salt`. Two widgets with the same id in one frame will confuse each other. Give panels, grids and scroll areas unique ids.

---

## 3. App state and screens

### The enum is your navigation graph

In Compose you may use a `ViewModel` with a sealed class `UiState` plus a navigation library. In Rust the idiomatic version is one **enum** where each variant carries the data only that screen needs.

```rust
enum Screen {
    Unlock { error: Option<String> },
    Working { started: Instant, rx: Receiver<bool> },
    Vault,
}
```

Compare with Kotlin:

```kotlin
sealed interface Screen {
    data class Unlock(val error: String?) : Screen
    data class Working(val started: Instant, val rx: Channel<Boolean>) : Screen
    object Vault : Screen
}
```

Rust checks that you handle **every** variant when you `match` on it. If you add a screen and forget a case, it will not compile. That is a security gain too: no screen is reachable "by accident".

### Holm's screens

From the mock and the screen map, the plan is roughly:

| Mock screen | Variant (sketch) |
|---|---|
| Open or create file | `Screen::Start` |
| Create vault | `Screen::Create { .. }` |
| Unlock plus errors, working state | `Screen::Unlock { error }`, `Screen::Working { .. }` |
| Locked | `Screen::Locked` (all data dropped) |
| Vault list and detail, Add/edit, Trash | `Screen::Vault(VaultView)` with a sub-state for the open item |
| Generator, Settings, Import, Export | modals or sub-views over the vault |
| Error state | an `error: Option<..>` field, drawn inline |

The vault data (the decrypted items) lives **inside** the `Vault` variant. When you assign `self.screen = Screen::Locked`, the old value is dropped and its `Drop` code runs. That is how "lock" wipes memory: leaving the variant frees and zeroizes what it held. (This is why secrets must implement `Drop`, lesson 02.)

### Messages and events

There are two kinds of events.

1. **User input**: handled immediately, in the frame, from the `Response` (`if ui.button(..).clicked() { .. }`). No dispatcher needed.
2. **Results from other threads**: sent over a channel (`std::sync::mpsc`). Each frame you call `rx.try_recv()`. It never blocks. If there is a message, handle it. If not, carry on.

This is the replacement for `viewModelScope.launch { }` plus `StateFlow`. The tutorial below uses exactly this pattern for the Argon2 work.

For a larger app, define one `enum Msg { Unlocked(Result<..>), .. }`, push all results through one channel, and handle them in one `fn handle(&mut self, msg: Msg)`. That is the same shape as MVI in Android.

### Keep the core out of the UI

`holm-core` knows nothing about egui. The GUI calls it and shows results. Rule of thumb: if you can write it without importing `egui`, it belongs in the core (or in a plain `fn` that returns data). Section 5 explains why.

---

## 4. Security concerns specific to the GUI

This is the part that matters most. A normal egui app is happy to keep text in a `String`, remember it on disk and copy it around. Holm cannot. These rules follow the project spec and threat table. Nothing here is a promise that a GUI can beat a compromised machine. The goal is to not leak by our own mistakes.

### 4.1 Why `egui::TextEdit` is not for secrets

`TextEdit::singleline(&mut string).password(true)` looks right. It is not enough:

- **It needs a `String`.** A `String` that grows reallocates. The old block of memory is freed **without being wiped**, so copies of the password stay in RAM.
- **Undo history.** `TextEdit` keeps an undo stack of earlier text. That is more copies of the secret.
- **Text layout.** It builds a text layout (a galley) of the content, even when masked. More copies, in places we do not control.
- **Accessibility.** With the default `accesskit` feature on, widgets publish their value to the operating system's accessibility tree. We must make sure a password is never published.
- **Selection and clipboard.** Copy and cut shortcuts on the field could put the secret on the clipboard.

(You can read `widgets/text_edit/builder.rs` in the egui source to confirm each of these.)

### 4.2 What a custom password widget must do

The tutorial builds a small version. A real one must:

1. Store bytes in a **pre-allocated buffer** with a fixed capacity, so it never reallocates and never leaves a stale copy. In the tutorial: `Vec::with_capacity(256)`, and input is refused once full.
2. **Never use `String`** for the content. Use bytes (or a zeroizing type) and a type that is **not `Clone`**.
3. **Wipe on drop and on clear**, using the `zeroize` crate (`bytes.zeroize()`). A plain `clear()` does not overwrite the memory.
4. **Read raw key events** (`egui::Event::Text`, Backspace, Enter) from `ui.input(..)` only while the widget has focus. No undo, no redo, no selection.
5. **Paint dots only.** Draw one circle per character with the painter. Never create a text layout from the secret.
6. **Publish no value** to AccessKit. Do not set a text value on the widget. Expose only "password field, N characters" if at all.
7. **Ignore copy and cut** shortcuts for this widget.
8. **Implement `Debug` by hand** so it prints `SecretBuf(<N chars hidden>)`. Never `#[derive(Debug)]` on anything that holds a secret. This also covers `{:?}` in logs and panic messages.
9. Cap the length. It is also a denial-of-service guard.

Honest limits:

- **IME and OS text services.** Input methods (for Chinese, Japanese and others) and OS features such as predictive text or "secure input" may keep their own copies. We cannot see or wipe those. On macOS the OS has a "secure event input" mode used by password fields. Whether we can reach it from winit is **unverified**. Treat it as a research task for `holm-platform`.
- The key event arrives as a `String` inside `Event::Text(String)`. That small string is created by egui and winit before we see it. We copy the bytes into our buffer and cannot wipe theirs. Small, short-lived, and a known limit.
- Memory can still be read by an attacker with the same user rights. That is outside our threat model, as the spec says.

### 4.3 Persistence off

eframe can save window size, positions and your app state to disk (the `persistence` feature and `App::save`). Holm must not.

- Do **not** enable the `persistence` Cargo feature of eframe.
- Do **not** implement `save`.
- Remember that egui keeps its own memory (widget state, focus). If a screen ever held text in egui memory, that text could be saved. This is another reason for the custom widget: the secret is never in egui memory.
- In `Cargo.toml` list features explicitly with `default-features = false` (like the throwaway crate in section 6) so a new default feature cannot sneak in. Check `cargo tree -e features` in CI.

### 4.4 Clipboard and auto-clear

- Copy with `ctx.copy_text(string)`. That passes through eframe's clipboard support.
- A secret copied there is visible to **every** program that reads the clipboard, and to clipboard history tools. Mitigations:
  - **Platform hints** tell clipboard managers to skip the item: Windows `ExcludeClipboardContentFromMonitorProcessing` and `CanIncludeInClipboardHistory = 0`, macOS `org.nspasteboard.ConcealedType`, Linux Wayland/X11 managers vary. These are best effort and are `holm-platform` work. egui's own `copy_text` cannot set them, so Holm will write to the clipboard itself for secrets.
  - **Auto-clear after 30 s**, but **only if the clipboard still holds what we put there**. Otherwise we would wipe something the user copied later. To check, remember a hash of what we copied (not the secret) and compare before clearing.
  - Clear on lock and on quit.
- The countdown needs `request_repaint_after` so the timer runs even if the user is idle (section 1).

### 4.5 Auto-lock, minimise, sleep

- **Idle timer**: remember `last_activity: Instant`, update it whenever input arrives, and lock when `elapsed() >= 5 min`. The tutorial does this with 20 seconds so you can watch it.
- **Minimise**: `ui.input(|i| i.viewport().minimized)` is `Option<bool>`. Lock when it is `Some(true)`. The same `viewport()` info has `focused` and `occluded`.
- **Sleep, screen lock, logout**: egui does not give you these. They are OS events and belong to `holm-platform` (macOS notifications, Windows `WM_POWERBROADCAST` and session change, Linux logind signals). The platform crate sends a message over a channel, and the app locks on it. Remember to call `request_repaint()` from that thread.
- **Quit**: wipe in `Drop` and on a `ViewportCommand::Close` path. A hard kill cannot run code. That is a known limit.
- **Lock means drop**: assign `self.screen = Screen::Locked` so the vault data is dropped (section 3), and clear any password buffer and the clipboard.

### 4.6 No secrets in `Debug` or logs

- Hand-written `Debug` for every secret type.
- No `println!`, `dbg!` or `tracing` of values that may contain secrets.
- Be careful with egui's own debug tools. Never turn on debug overlays in release builds.
- Panics: a panic message must not contain secrets. Another reason `Debug` is redacted.

### 4.7 Screen-capture exclusion (per OS, best effort)

Goal: other programs and screen recorders should not capture the Holm window.

- `egui::ViewportCommand::ContentProtected(bool)` exists in 0.37. It asks winit to mark the window as protected. winit documents it as supported on Windows and macOS. Whether it covers every capture tool is **unverified**. Do not promise it to users.
- Windows has `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`. macOS has `NSWindow.sharingType = .none` (and macOS 15 and later screen capture can bypass it in some cases, **unverified**). Wayland has no general mechanism. X11 has none.
- Why `holm-platform`: these calls need `unsafe` (FFI to OS libraries). The project rule is `forbid(unsafe_code)` everywhere except one crate. Putting all of them in `holm-platform` keeps the dangerous code small and auditable. The GUI crate calls a safe function such as `holm_platform::protect_window(&window_handle)` and nothing else.
- Tell the user honestly: this is a speed bump, not a wall.

### 4.8 One more rule: slow work off the UI thread

Argon2id takes about a second by design. Running it in `ui` freezes the window. Run it in `std::thread::spawn`, send the result over a channel, show a spinner. The tutorial shows this. It also lets us enforce the in-memory throttle (wait 2, 4, 8... seconds after failures) without blocking the window.

---

## 5. Testing egui UIs

### Keep logic out of the UI

The best test is on code that does not import egui. Put these in plain functions or in `holm-core`:

- password strength rules,
- "is this input allowed",
- throttle and lockout maths,
- the buffer type (`SecretBuf`: push, pop, wipe),
- the state machine step: `fn on_unlock_result(&mut self, ok: bool)`.

These tests are fast and stable. UI tests then only check that the wiring works.

### egui_kittest

`egui_kittest` is the official test harness (version 0.37.0 exists, same as egui). It runs your UI headlessly and lets you query widgets by label and "click" them, using the accessibility tree. Add it as a **dev**-dependency:

```toml
[dev-dependencies]
egui_kittest = { version = "=0.37.0", features = ["snapshot"] }
```

A test from the tutorial (it compiled and passed):

```rust
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

#[test]
fn unlock_screen_shows_labels() {
    let mut harness = Harness::new_ui_state(
        |ui, app: &mut HolmApp| app.show(ui),
        HolmApp::new(),
    );
    harness.run();
    harness.get_by_label("Enter your master password");
    harness.get_by_label("Unlock");
}
```

Notes:

- This is why the tutorial splits `show(&mut self, ui)` away from the `App::ui` method: the harness gives you a `Ui`, not a real `Frame`.
- `get_by_label(..)`, `.click()`, `.type_text(..)`, `harness.run()` and `harness.step()` are real 0.37 methods.
- **Our custom password widget has no accessibility value on purpose**, so you cannot `type_text` into it and read it back. Test it by feeding events (`egui::Event::Text`) in a lower-level test, or test `SecretBuf` directly.

### Snapshot tests

With the `snapshot` feature, `harness.snapshot("name")` renders the UI to an image and compares it to a stored PNG (it fails when pixels differ beyond a threshold). The first run creates the file. In 0.37 the snapshot API (`snapshot`, `try_snapshot`, `SnapshotOptions`) exists. I did **not** run a snapshot in the throwaway crate, so the exact setup (GPU renderer feature `wgpu`, platform thresholds) is **unverified**. Check the egui_kittest README first.

Two cautions from the Holm spec:

- A snapshot test that renders a **blank image** passes a lazy "image exists" check. The smoke test must also assert the image is not blank (for example, that more than a few colours appear).
- Snapshot pictures must never contain real secrets. Use fake data.

### CI

Rendering tests need a GPU or software renderer and differ a little per OS. Plan: logic tests everywhere, snapshot tests on one OS only, with a generous threshold.

---

## 6. Tutorial: a working unlock screen

You will build a window with: a custom masked password field, an Unlock button that is disabled until you type, a spinner while a worker thread "checks" the password, an error line, a vault screen with an auto-lock countdown, and a lock on minimise.

Pinned and checked: **eframe 0.37.0, egui 0.37.0, zeroize 1.x, egui_kittest 0.37.0, Rust 1.99.1** (it needs at least 1.95; it did **not** build on 1.93.1). The code below was copied from a crate that ran `cargo check` with no warnings and `cargo test` with 2 tests passing. The "password" is the fake string `correct horse`, so you can try it. I did not run the window by hand (this was done without a display), so look at the real behaviour yourself.

### Step 0: create the crate

```sh
cargo new holm-unlock-tutorial
cd holm-unlock-tutorial
cargo add zeroize@1
cargo add eframe@=0.37.0 --no-default-features --features default_fonts,glow,wayland,x11
cargo add --dev egui_kittest@=0.37.0 --features snapshot
```

Why `--no-default-features`: the defaults pull in `wgpu`, `accesskit`, clipboard and more. We pick features on purpose (section 4.3). `glow` is the OpenGL backend. On Windows and macOS you may add nothing else. If the window does not open on your machine, try adding the default `wgpu` feature back.

`Cargo.toml` after that:

```toml
[package]
name = "holm-unlock-tutorial"
version = "0.1.0"
edition = "2024"

[dependencies]
eframe = { version = "=0.37.0", default-features = false, features = ["default_fonts", "glow", "wayland", "x11"] }
zeroize = "1"

[dev-dependencies]
egui_kittest = { version = "=0.37.0", features = ["snapshot"] }
```

Replace `src/main.rs` step by step.

### Step 1: a secret buffer that wipes itself

The imports first, then the type. Read the comments. This is lesson 02 (secret types) again, in a GUI setting.

```rust
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroize;

// ---------- 1. A secret buffer that wipes itself ----------

/// Holds typed password bytes. No Clone, no Debug that shows content.
struct SecretBuf {
    bytes: Vec<u8>,
}

impl SecretBuf {
    const CAP: usize = 256;

    fn new() -> Self {
        // Reserve once, so the buffer never reallocates and leaves a copy behind.
        Self { bytes: Vec::with_capacity(Self::CAP) }
    }

    fn push_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch.is_control() {
                continue;
            }
            let mut tmp = [0u8; 4];
            let enc = ch.encode_utf8(&mut tmp);
            if self.bytes.len() + enc.len() > Self::CAP {
                break;
            }
            self.bytes.extend_from_slice(enc.as_bytes());
            tmp.zeroize();
        }
    }

    fn pop_char(&mut self) {
        // Remove the last UTF-8 character: drop continuation bytes, then the lead byte.
        while let Some(b) = self.bytes.pop() {
            if b & 0b1100_0000 != 0b1000_0000 {
                break;
            }
        }
    }

    fn char_count(&self) -> usize {
        self.bytes.iter().filter(|b| (**b & 0b1100_0000) != 0b1000_0000).count()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn clear(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuf(<{} chars hidden>)", self.char_count())
    }
}
```

Rust ideas here:

- `impl SecretBuf { .. }` adds methods, like a Kotlin class body. `Self` is the type itself.
- `&mut self` means "this method may change the object". `&self` means read only.
- `impl Drop` is a destructor. Rust runs it automatically when the value goes away. Kotlin has no equivalent.
- There is no `#[derive(Clone)]` and no derived `Debug`. Nobody can copy the buffer by accident or print it.
- `Option` (`Some(b)` or `None`) is Kotlin's nullable type, but the compiler forces you to handle both cases.

### Step 2: a password field without `TextEdit`

```rust
// ---------- 2. A password widget that never uses TextEdit ----------

/// Returns true when the user pressed Enter inside the field.
fn password_field(ui: &mut egui::Ui, buf: &mut SecretBuf) -> bool {
    let size = egui::vec2(260.0, 28.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        response.request_focus();
    }
    let focused = response.has_focus();
    let mut submitted = false;

    if focused {
        ui.input(|i| {
            for event in &i.events {
                match event {
                    egui::Event::Text(t) => buf.push_str(t),
                    egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => {
                        buf.pop_char()
                    }
                    egui::Event::Key { key: egui::Key::Enter, pressed: true, .. } => {
                        submitted = true
                    }
                    _ => {}
                }
            }
        });
    }

    // Paint a box and one dot per character. No text layout is ever created.
    let visuals = ui.visuals();
    let stroke = if focused { visuals.selection.stroke } else { visuals.widgets.inactive.bg_stroke };
    ui.painter().rect_filled(rect, 4.0, visuals.extreme_bg_color);
    ui.painter().rect_stroke(rect, 4.0, stroke, egui::StrokeKind::Inside);
    let dot = visuals.text_color();
    for n in 0..buf.char_count().min(24) {
        let center = egui::pos2(rect.left() + 12.0 + n as f32 * 10.0, rect.center().y);
        ui.painter().circle_filled(center, 3.0, dot);
    }
    submitted
}
```

Read it slowly:

- `allocate_exact_size` reserves a rectangle. `Sense::click()` makes it focusable by click.
- While focused, we read raw events with `ui.input(..)`. `Event::Text` carries typed characters. Backspace and Enter are key events.
- We paint with `ui.painter()`. Only dots are drawn. No text layout of the secret exists.
- It returns `true` when Enter was pressed, so the caller decides what to do.

### Step 3: state, one enum and one struct

```rust
// ---------- 3. App state: one enum, one struct ----------

enum Screen {
    Unlock { error: Option<String> },
    Working { started: Instant, rx: Receiver<bool> },
    Vault,
}

struct HolmApp {
    screen: Screen,
    password: SecretBuf,
    last_activity: Instant,
}

const AUTO_LOCK: Duration = Duration::from_secs(20);

impl HolmApp {
    fn new() -> Self {
        Self {
            screen: Screen::Unlock { error: None },
            password: SecretBuf::new(),
            last_activity: Instant::now(),
        }
    }

    fn start_unlock(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        // Pretend work. Real Holm would send the password to the core here.
        let ok = self.password.bytes == b"correct horse";
        self.password.clear();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            let _ = tx.send(ok);
            ctx.request_repaint();
        });
        self.screen = Screen::Working { started: Instant::now(), rx };
    }

    fn lock(&mut self) {
        self.password.clear();
        self.screen = Screen::Unlock { error: None };
    }
}
```

- `Screen` is the navigation graph (section 3). `Working` owns the receiving end of a channel. That is the worker thread's mailbox.
- `start_unlock` copies nothing: it compares inside the call, then **wipes the buffer** and moves to `Working`. A real app would pass the bytes to the worker (moving them, not cloning), and the worker would zeroize them when done.
- `std::thread::spawn(move || { .. })` runs the closure on a new thread. `move` hands it ownership of `tx` and `ctx`. The thread calls `ctx.request_repaint()` when finished so the UI wakes up.

### Step 4: draw the screens

```rust
impl HolmApp {
    /// All screen drawing lives here, so tests can call it without a Frame.
    fn show(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();

        // Any input counts as activity.
        if ui.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.last_activity = Instant::now();
        }

        // Lock on minimise, or after the idle time.
        let minimized = ui.input(|i| i.viewport().minimized.unwrap_or(false));
        let idle = self.last_activity.elapsed();
        if matches!(self.screen, Screen::Vault) {
            if minimized || idle >= AUTO_LOCK {
                self.lock();
            } else {
                ctx.request_repaint_after(AUTO_LOCK - idle);
            }
        }

        egui::CentralPanel::default().show(ui, |ui| match &mut self.screen {
            Screen::Unlock { error } => {
                let error = error.clone();
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.heading("Holm");
                    ui.label("Enter your master password");
                    ui.add_space(8.0);
                    let enter = password_field(ui, &mut self.password);
                    if let Some(e) = &error {
                        ui.colored_label(egui::Color32::LIGHT_RED, e);
                    }
                    ui.add_space(8.0);
                    let can_try = !self.password.is_empty();
                    if (ui.add_enabled(can_try, egui::Button::new("Unlock")).clicked()
                        || (enter && can_try))
                        && can_try
                    {
                        self.start_unlock(&ctx);
                    }
                });
            }
            Screen::Working { started, rx } => {
                let waited = started.elapsed().as_secs_f32();
                let result = rx.try_recv().ok();
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.spinner();
                    ui.label(format!("Unlocking... {waited:.1}s"));
                });
                match result {
                    Some(true) => self.screen = Screen::Vault,
                    Some(false) => {
                        self.screen = Screen::Unlock {
                            error: Some("Wrong password or damaged vault.".to_owned()),
                        }
                    }
                    None => ctx.request_repaint_after(Duration::from_millis(100)),
                }
            }
            Screen::Vault => {
                ui.heading("Vault is open");
                ui.label(format!("Auto-lock in {} s", (AUTO_LOCK - idle).as_secs()));
                if ui.button("Lock now").clicked() {
                    self.lock();
                }
            }
        });
    }
}
```

Things to notice:

- The first block sets `last_activity` on any input. The idle check then compares `elapsed()` with `AUTO_LOCK`.
- `ctx.request_repaint_after(AUTO_LOCK - idle)` wakes the app exactly when it should lock, even with no input. This is the answer to "no recomposition, so how do timers work".
- `match &mut self.screen { .. }` handles every variant. Delete one arm and the compiler complains.
- In `Working`, `rx.try_recv().ok()` never blocks. If the result is not there yet, we ask for another frame in 100 ms.
- `i.viewport().minimized` is `Option<bool>`, so `unwrap_or(false)` supplies a default.
- The password is checked against a fake string. Replace that line with a call into `holm-core` later.

### Step 5: wire it to eframe

```rust
impl eframe::App for HolmApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Holm tutorial")
            .with_inner_size([420.0, 320.0]),
        ..Default::default()
    };
    eframe::run_native("Holm tutorial", options, Box::new(|_cc| Ok(Box::new(HolmApp::new()))))
}
```

Why `show` is separate: the test in step 6 can call `app.show(ui)` without building a real `eframe::Frame`.

Run it with `cargo run`. Type `correct horse` and press Enter. Try a wrong password. Unlock, then leave the mouse alone for 20 seconds, or minimise the window. It should lock.

### Step 6: tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    #[test]
    fn secret_buf_handles_utf8_and_wipes() {
        let mut b = SecretBuf::new();
        b.push_str("aé😀");
        assert_eq!(b.char_count(), 3);
        b.pop_char();
        assert_eq!(b.char_count(), 2);
        b.clear();
        assert!(b.is_empty());
        assert_eq!(format!("{b:?}"), "SecretBuf(<0 chars hidden>)");
    }

    #[test]
    fn unlock_screen_shows_disabled_button() {
        let mut harness = Harness::new_ui_state(
            |ui, app: &mut HolmApp| {
                app.show(ui);
            },
            HolmApp::new(),
        );
        harness.run();
        harness.get_by_label("Enter your master password");
        harness.get_by_label("Unlock");
    }
}
```

Run `cargo test`.

### Exercises

1. Add a "Show length" label that says how many characters you typed. Use `char_count()`. Do not show the characters.
2. Add the throttle: after 3 wrong passwords, disable the button for 2 seconds, then 4, then 8. Keep the failure count in the `Unlock` variant. Use `request_repaint_after` so the button re-enables itself.
3. Add a `Screen::Locked` variant that shows "Locked" and a button to go back to `Unlock`. Handle it in `match`. What does the compiler tell you before you handle it?
4. (Harder) Make `start_unlock` move a copy of the bytes into the worker thread and zeroize them there when finished. Think about who owns the bytes at each step.

---

## 7. Kotlin to Rust cheat-sheet

| Kotlin / Compose | Rust / egui |
|---|---|
| `@Composable fun Screen()` | `fn show(&mut self, ui: &mut egui::Ui)` |
| `Column { }` | `ui.vertical(\|ui\| { .. })` |
| `Row { }` | `ui.horizontal(\|ui\| { .. })` |
| `Box(Modifier.fillMaxSize())` | `egui::CentralPanel::default().show(ui, ..)` |
| `Spacer(Modifier.height(8.dp))` | `ui.add_space(8.0)` |
| `Text("hi")` | `ui.label("hi")` |
| `Button(onClick = { }) { Text("OK") }` | `if ui.button("OK").clicked() { .. }` |
| `Checkbox(checked, onChange)` | `ui.checkbox(&mut checked, "label")` |
| `Slider(value, onChange, range)` | `ui.add(egui::Slider::new(&mut v, 12..=64))` |
| `enabled = cond` | `ui.add_enabled(cond, widget)` |
| `CircularProgressIndicator()` | `ui.spinner()` |
| `LazyColumn { items(list) { } }` | `ScrollArea::vertical().show(ui, \|ui\| for x in &list { .. })` |
| `AlertDialog` | `egui::Modal::new(id).show(ctx, ..)` |
| `Scaffold(topBar)` | `egui::Panel::top("id").show(ui, ..)` |
| `NavigationDrawer` / list pane | `egui::Panel::left("id").show(ui, ..)` |
| `var x by remember { mutableStateOf(0) }` | field `x: i32` on your struct |
| `ViewModel` | your `struct App` |
| `sealed interface UiState` | `enum Screen { .. }` and `match` |
| `NavHost` and routes | `self.screen = Screen::Vault` |
| `viewModelScope.launch { }` | `std::thread::spawn` plus `mpsc` channel |
| `collectAsState()` | `rx.try_recv()` each frame |
| `LaunchedEffect(key) { delay(5000) }` | store an `Instant`, `ctx.request_repaint_after(..)` |
| `null`, `T?` | `Option<T>` |
| `Result` / exceptions | `Result<T, E>` and `?` |
| lambda `{ x -> x + 1 }` | closure `\|x\| x + 1` |
| `interface Foo` | `trait Foo` |
| `data class` | `struct` with `#[derive(Debug, Clone)]` (not for secrets) |
| `override fun` | `impl Trait for Type { fn .. }` |
| `Modifier.padding(8.dp)` | `egui::Frame::new().inner_margin(8.0).show(ui, ..)` |
| `MaterialTheme` | `ctx.set_visuals(egui::Visuals::dark())` |
| `LocalContext` / `Context` | `egui::Context` (cheap to clone) |
| `Compose preview` | none; run the app, or use a snapshot test |

(`\|` is only the table escape for the pipe in closures. In code it is a single `|`.)

---

## 8. References

Each link was fetched on 2026-10-17 and returned HTTP 200. For the YouTube talk I also confirmed the title. Ordered from beginner to advanced. I did not find a community egui tutorial that I could confirm is current for 0.37, so none is listed. Most written tutorials online use the old `update` and `TopBottomPanel` names (section 2). Prefer the official examples.

Start here:

1. [egui web demo](https://www.egui.rs/) - the official demo running in your browser. Click around to see every widget. Start here.
2. [Rust Book ch. 4: Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html) - the one idea that makes Rust different. Needed for `&mut`.
3. [Rust Book ch. 6: Enums](https://doc.rust-lang.org/book/ch06-00-enums.html) - how `enum` and `match` give you Holm's screen state machine.
4. [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - short runnable snippets, good when the Book is too wordy.
5. [Rust Book ch. 10.2: Traits](https://doc.rust-lang.org/book/ch10-02-traits.html) - what `impl eframe::App for HolmApp` means.
6. [Compose mental model](https://developer.android.com/develop/ui/compose/mental-model) - what you already know, to contrast with immediate mode.

Build something:

7. [eframe_template](https://github.com/emilk/eframe_template) - the official starter project. Copy it to see a full app layout.
8. [egui examples folder](https://github.com/emilk/egui/tree/main/examples) - small, focused programs (a file dialog, custom fonts, multiple viewports). Best learning material after the demo.
9. [egui README](https://github.com/emilk/egui) - the author's own explanation of immediate mode and its trade-offs.
10. [egui_demo_lib source](https://github.com/emilk/egui/tree/main/crates/egui_demo_lib) - the code behind the web demo, one file per demo window.
11. [Rust Book ch. 16.2: Message passing](https://doc.rust-lang.org/book/ch16-02-message-passing.html) - channels, used for the worker thread.

Reference:

12. [docs.rs/egui 0.37.0](https://docs.rs/egui/0.37.0/egui/) - the API reference for the pinned version.
13. [docs.rs/eframe 0.37.0](https://docs.rs/eframe/0.37.0/eframe/) - the window and app side.
14. [eframe::App trait](https://docs.rs/eframe/0.37.0/eframe/trait.App.html) - the exact methods you implement.
15. [egui::Context](https://docs.rs/egui/0.37.0/egui/struct.Context.html) - `request_repaint_after`, `copy_text` and `send_viewport_cmd` live here.
16. [egui CHANGELOG](https://github.com/emilk/egui/blob/main/CHANGELOG.md) - read this when something stops compiling after an upgrade.
17. [zeroize docs](https://docs.rs/zeroize/latest/zeroize/) - how memory wiping works and what it cannot guarantee.

Testing and larger examples:

18. [egui_kittest source and README](https://github.com/emilk/egui/tree/main/crates/egui_kittest) - the test harness, how to enable snapshots.
19. [docs.rs/egui_kittest 0.37.0](https://docs.rs/egui_kittest/0.37.0/egui_kittest/) - its API.
20. [egui_demo_app](https://github.com/emilk/egui/tree/main/crates/egui_demo_app) - the desktop and web app that ships the demo.
21. [egui discussions](https://github.com/emilk/egui/discussions) - ask or search questions. The author answers.
22. [Rerun](https://github.com/rerun-io/rerun) - a large real application built on egui (the same author's company). Read it when you want to see egui at scale.

Talk:

23. [Casey Muratori: Immediate-Mode Graphical User Interfaces (2005)](https://www.youtube.com/watch?v=Z1qyvQsjK5Y) - the classic explanation of why immediate mode exists. Older, but the idea is the same.

Links I could not confirm and therefore left out: any community "egui book" or conference talk specific to egui. If you find one, add it only after opening it.
