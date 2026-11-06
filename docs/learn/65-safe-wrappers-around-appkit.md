# Lesson 65: Safe wrappers around AppKit

## Why this matters

Holm has one setting that talks to the operating system: "Hide window from screenshots and screen
sharing". macOS does this with a property on every window, `sharingType`. Rust cannot call
AppKit by itself, so this is foreign function interface (FFI) work. FFI is where `unsafe` usually
lives. This lesson shows how to keep it away from the rest of the program, and why this time we
needed none at all.

## What we built

- `holm-platform/src/capture.rs`: `set_capture_protection(enabled) -> Result<usize, CaptureError>`.
  On macOS it walks `NSApplication::sharedApplication(mtm).windows()` and sets
  `NSWindowSharingType::None` (on) or `ReadOnly` (off) on each window. It returns how many windows it
  looked at.
- `holm-platform/src/prefs.rs`: a tiny plaintext file `holm-prefs` beside the vault, so the
  setting can be read before unlock.
- `holm-gui/src/capture.rs`: a `CaptureControl` trait with a real `SystemCapture` and a do-nothing
  `NoCapture`. The app only knows the trait.

## The rule: unsafe lives in one place

`holm-gui` has `#![forbid(unsafe_code)]`. `holm-platform` has `unsafe_code = "deny"`, and the one
file that needs it (`window.rs`) opts in with an inner attribute at the top of the file,
`#![allow(unsafe_code, reason = "...")]`. The two new files here say `#![forbid(unsafe_code)]` again. If someone later pastes an `unsafe` block into them, the
compiler refuses. `forbid` cannot be switched off further down the tree, `deny` can.

## The best unsafe is none

`window.rs` has real `unsafe`: it turns a raw `NSView` pointer from winit into a reference and
registers notification observers, so it carries a `// SAFETY:` comment on each block. Those are
things the compiler cannot check.

For `sharingType` we did not need that. The `objc2-app-kit` crate describes each AppKit method
with its safety rules. `NSWindow::setSharingType` is marked safe, and `NSApplication::windows`
is safe too, as long as you can prove you are on the main thread. You prove it with a value:

```rust
let mtm = MainThreadMarker::new().ok_or(CaptureError::NotMainThread)?;
let app = NSApplication::sharedApplication(mtm);
```

`MainThreadMarker::new()` returns `None` off the main thread. Only code that holds the marker can
call the main-thread-only methods, so leaving the marker out is a compile error. The check
that you really are on the main thread still happens at run time, inside `MainThreadMarker::new()`.
The type forces the check to be written; it cannot run it for you. Enabling the call took one Cargo feature (`NSApplication`) on a crate already in
`Cargo.lock`. No new crate came in.

If a block of `unsafe` ever is needed, write what makes it sound right above it:

```rust
// SAFETY: the pointer comes from winit for a live window and we are on the main thread,
// so the view outlives this borrow.
```

Say which fact makes it safe, not just "this is fine". A reviewer should be able to check the
fact.

## Main-thread rule

AppKit objects belong to the main thread. egui's `update` runs on it, so the GUI calls
`apply` from `tick()` there. The function itself checks and returns `NotMainThread` instead of
trusting the caller. That is also why the unit test calls it from a spawned thread and expects the
error.

## A Result for "not here"

Windows and Linux have no `sharingType`. Instead of `#[cfg]` scattered through the GUI, the
platform crate has one function with two bodies and a `const fn is_supported()`. The non-Mac body
returns `Err(CaptureError::Unsupported)`. The GUI reads `supported()` and does not draw the
toggle. One `cfg` in one file; every caller sees the same signature.

## Testing without a window

The GUI tests cannot read what the Mac compositor shows. So `HolmApp` takes a `Box<dyn
CaptureControl>`. Tests pass a `FakeCapture` that records every `apply(bool)` call, and check:
the default is off and nothing is applied, a toggle applies at once and survives a restart, a
failing apply shows the message, and an unsupported platform shows no toggle. The real check is by
hand: run with the setting on, then capture with QuickTime screen recording and a Zoom screen share and look. On macOS 15 and later `screencapture -x` may still show Holm, so do not trust it alone.

## Rust angle

- `Option::ok_or` plus `?` to turn `None` into an error and return early.
- `cfg!(all(feature = "gui-window", target_os = "macos"))` in a `const fn`.
- A hand-written `Display` and `Error` for a two-variant enum when a derive crate is not worth a
  new dependency.
- `Box<dyn Trait>` as an injected dependency, a seam for tests.

## Kotlin comparison

On the JVM you reach native APIs through JNI or JNA. A mistake in the binding crashes the whole
process and the language does not warn you. Compose Desktop has no built-in "hide from capture"
flag; you would call `NSWindow.setSharingType` through a JNA or Objective-C bridge, with no
marker type to check the thread. In Rust the marker moves that check to compile time.

## Try it

1. Delete the `MainThreadMarker` line and pass nothing. Read the compiler error.
2. Add `unsafe { }` to `capture.rs`. What does `forbid(unsafe_code)` say?
3. Turn the setting on and record the screen with QuickTime, then share it in Zoom. Is Holm there? Try `screencapture -x` too; on macOS 15 and later it may still show Holm.

## Read next

- [Lesson 64: Signing, notarising and the hardened runtime](64-signing-and-notarising.md)
- [Lesson 45: Shipping a Mac app by hand](45-shipping-a-mac-app-by-hand.md)
- [The index](README.md)
