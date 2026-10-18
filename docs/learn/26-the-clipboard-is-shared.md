# Lesson 26: The clipboard is shared

## Why this matters

On macOS the general pasteboard belongs to nobody: any running app can read it at any time, without asking, and clipboard managers save every entry they see. A password manager that copies a password puts it, briefly, in the most public place on the machine. The best Holm can do is copy only when the user asks, mark the copy so well-behaved tools leave it alone, keep its own copies in buffers that wipe themselves, and never let the UI library copy anything on its own.

## What we built

The `clipboard` module defines a `SecretClipboard` trait with two methods: `set_secret` and `get_text`. `SystemClipboard` implements it with the `arboard` crate and opens the pasteboard lazily, on the first copy or paste. The read-only item view has a Copy button that calls `set_secret` and shows a fixed line saying whether it worked. Cmd+V goes through Holm too: a secret field pastes straight into its `SecretInput`, all of it or nothing, and a plain field gets an `Event::Paste` added in `raw_input_hook`. Tests use a fake clipboard, so the real pasteboard is never touched in CI.

## Rust ideas in this task

### A trait as a seam for the operating system

```rust
pub trait SecretClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), ClipboardError>;
    fn get_text(&mut self) -> Option<Zeroizing<String>>;
}
pub struct AppConfig { /* ... */ pub clipboard: Box<dyn SecretClipboard> }
```

The app only ever sees `Box<dyn SecretClipboard>`. `main.rs` passes `SystemClipboard::new()`; the tests pass a `FakeClipboard` that records each `set_secret` call and serves a fixed paste. So the tests can assert "exactly one copy, with this text" without touching the real pasteboard. There is no `Send` bound, because the clipboard lives on the UI thread only.

In Kotlin you'd write `interface SecretClipboard` and inject either `SystemClipboard(context)` or a test fake through the constructor. The idea is the same. The difference is that `Box<dyn ...>` says plainly that the value lives on the heap and is called through a vtable.

### `Cow<str>`: borrow when you can, own when you must

```rust
clipboard.set().exclude_from_history().text(Cow::Borrowed(text))
```

`arboard`'s `text` takes `impl Into<Cow<'a, str>>`. `Cow` ("clone on write") is either `Borrowed(&str)` or `Owned(String)`. Passing a `&str` would also work, but writing `Cow::Borrowed` makes it explicit that Holm hands over a view of its own buffer and makes no extra `String` copy of the password. The pasteboard still keeps its own copy in Objective-C memory, and Holm cannot wipe that.

In Kotlin you'd write `fun text(s: CharSequence)` and hope the callee doesn't call `toString()`. `Cow` puts that choice in the type.

### Extension traits: `SetExtApple`

```rust
use arboard::SetExtApple as _;
clipboard.set().exclude_from_history() // only exists on macOS
```

`exclude_from_history` is not a method of arboard's `Set` builder. It comes from a trait, `SetExtApple`, that arboard implements for `Set` only on Apple targets. Importing the trait `as _` brings its methods into scope without binding a name. This is how Rust crates add platform-only methods without putting `#[cfg]` on every method.

In Kotlin you'd write an extension function `fun Set.excludeFromHistory()`. The Rust version has to be imported as a trait, and it can be implemented differently for each type.

### Wiping what you read

```rust
fn get_text(&mut self) -> Option<Zeroizing<String>> {
    self.open()?.get().text().ok().map(Zeroizing::new)
}
```

The pasted text may be a password the user copied a moment ago. `Zeroizing::new` takes over the `String` without copying it, and the bytes are overwritten when it drops. A secret field copies the characters into its own fixed `SecretInput` and checks the length first, so the buffer never grows and reallocates. The `?` on an `Option` returns `None` early, as it would return an `Err` for a `Result`.

In Kotlin you'd read `clipData.getItemAt(0).text` and get a `CharSequence` you can't reliably clear.

### Never truncate silently

```rust
#[must_use]
pub fn try_push_str(&mut self, s: &str) -> bool { /* all or nothing */ }
```

If a pasted password were cut at the field's capacity, the user would save the wrong password and find out only when it fails. So `try_push_str` adds nothing when the text doesn't fit, and the form shows a fixed line, "That's too long to paste here, so nothing was pasted." `#[must_use]` makes the compiler warn if a caller ignores the result.

In Kotlin you'd return `Boolean` and rely on code review. `#[must_use]` lets the compiler do that review.

## Why "concealed" is best effort

`exclude_from_history` adds the pasteboard type `org.nspasteboard.ConcealedType`. This is a convention from nspasteboard.org: clipboard managers that honour it don't save or show the entry. It is a request, not a lock. Any app can still read the password while it is on the pasteboard, and a manager that ignores the convention still saves it. That is why the Copy message tells the user that Holm doesn't clear the clipboard yet.

## What auto-clear will add (Phase 5)

Phase 5 will clear the clipboard 30 seconds after a copy, and again when the vault locks, but only if the clipboard still holds what Holm put there. That way it never wipes something the user copied since. This shortens the time the password is exposed, but it doesn't close the gap: until the clear, any app can still read it.

## Exercises

1. Run the test that checks the real pasteboard by hand. It replaces your current clipboard with a fake value. Check: `cargo test -p holm-gui --locked --test clipboard -- --ignored system_clipboard_marks_concealed`.
2. In `tests/clipboard.rs`, change `copy_failure_shows_message` so it expects `messages::COPIED`. See it fail, then undo. Check: `cargo test -p holm-gui --locked --test clipboard copy_failure`.
3. Add a unit test to `clipboard.rs`: paste a two-byte character such as `é` into a buffer with exactly one byte free, and expect `Paste::TooLong`. Check: `cargo test -p holm-gui --locked paste_`.

## Read next

- [`arboard::SetExtApple`](https://docs.rs/arboard/3.7.0/arboard/trait.SetExtApple.html)
- [`std::borrow::Cow`](https://doc.rust-lang.org/std/borrow/enum.Cow.html)
- [nspasteboard.org: pasteboard type identifiers](http://nspasteboard.org/)
