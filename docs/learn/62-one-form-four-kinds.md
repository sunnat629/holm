# One form, four kinds

## Why this matters

The toolbar used to open one thing: a login form. Now it opens four kinds of
item. Each kind has different fields, and some of those fields are secrets. A
form for a secure note must not carry a username box, and a form for a recovery
phrase must not hand the phrase back after a failed save.

Holm makes the kind an enum, lets each kind own only the buffers it needs, and
keeps the phrase gate shut.

## What we built

The toolbar has a **New** menu with four entries: Login, Crypto address,
Recovery phrase and Secure note. Each opens a blank form in the detail pane.

Every form checks its input with the same core `ItemInput` rules the CLI uses.
Address, memo, phrase and note are secret boxes that publish no value to
AccessKit. The phrase box is masked.

If a save fails, the form comes back with what the user typed. The one
exception is the recovery phrase, which the user types again.

## Rust ideas in this task

### Two enums: a small public one and a private one with data

```rust
pub(crate) enum NewKind {
    Login,
    CryptoAddress,
    RecoveryPhrase,
    SecureNote,
}
```

`NewKind` is only a choice. It carries no data, so it is `Copy`, and the menu
can loop over it. It is visible to the whole crate, because the vault screen
needs it.

```rust
enum Body {
    Login { username: LineBuf, url: LineBuf, password: SecretInput },
    Crypto { chain: LineBuf, address: SecretInput, memo: SecretInput },
    Phrase { phrase: SecretInput },
    Note { body: SecretInput },
}
```

`Body` has no `pub`, so only `login_form.rs` can see it. Each variant holds
only the buffers of its kind. A note form has no username buffer because the
type has nowhere to put one. `Body::blank(kind)` turns the choice into the data:

```rust
fn blank(kind: NewKind) -> Body {
    match kind {
        NewKind::Login => Body::Login { /* ... */ },
        NewKind::CryptoAddress => Body::Crypto { /* ... */ },
        NewKind::RecoveryPhrase => Body::Phrase { /* ... */ },
        NewKind::SecureNote => Body::Note { /* ... */ },
    }
}
```

There is no catch-all arm. Add a fifth kind and the compiler points at every
`match` that must learn about it.

In Kotlin you'd write a `sealed interface FormState` with one `data class` per
kind. The idea is the same: each case carries only its own fields, and `when`
must cover all of them.

### A `Debug` that never prints a buffer

```rust
Body::Login { username, url, password } => f
    .debug_struct("Login")
    .field("username_len", &username.len())
    .field("url_len", &url.len())
    .field("password", password)
    .finish(),
```

`#[derive(Debug)]` would print every field. Here we write `Debug` by hand. A
`LineBuf` shows only its byte length. A `SecretInput` has its own `Debug` that
leaves the text out. A stray `{:?}` in a log line can never show a username or a
phrase. A test checks that the debug text of a phrase form does not contain the
phrase.

In Kotlin you'd override `toString` on the data class and leave the secret out.
Kotlin's `data class` writes `toString` with every property unless you stop it.

### `menu_button` and `ui.close()`

```rust
let menu = ui.menu_button(NEW_LABEL, |ui| {
    for (label, kind) in NEW_ENTRIES {
        if ui.button(label).clicked() {
            self.start_new(kind);
            ui.close();
        }
    }
});
```

`menu_button` draws a button and runs the closure only while the menu is open.
After an entry opens its form, `ui.close()` closes the menu, so it does not stay
open over the new form.

`NEW_ENTRIES` is a `[(&str, NewKind); 4]`. The array length is part of its
type, so the list and the number four cannot drift apart.

In Kotlin you'd set `expanded = false` for a `DropdownMenu` inside the item's
`onClick`. It is the same job: you tell the menu you are done.

### A triangle painted from points

```rust
ui.painter().add(egui::Shape::convex_polygon(
    vec![
        egui::pos2(c.x - 3.0, c.y - 2.0),
        egui::pos2(c.x + 3.0, c.y - 2.0),
        egui::pos2(c.x, c.y + 2.0),
    ],
    ui.visuals().text_color(),
    egui::Stroke::NONE,
));
```

A small down arrow next to "New" tells the user this is a menu. The obvious
way is to put U+25BE in the label. The bundled Atkinson Hyperlegible font has no
glyph for it, so egui would draw a box.

So we draw it. Three points make a triangle, the fill is the theme's text
colour, and there is no outline. It works in both themes and needs no font.

In Kotlin you'd draw a `Path` on a `Canvas`, or ship a vector drawable, when the
font lacks the symbol.

### `Box` to keep an enum small

```rust
enum DetailMode {
    Empty,
    View,
    Edit(Box<LoginForm>),
}
```

A Rust enum is as big as its biggest variant. `LoginForm` holds several
buffers, so without the `Box` every `DetailMode`, even `Empty`, would be that
big. Clippy warns about this (`large_enum_variant`). With the `Box`, the form
lives on the heap and the enum holds one pointer.

The cost is one allocation when a form opens. The form moves in as
`Box::new(LoginForm::new_blank_kind(kind))`.

In Kotlin every object is already a reference, so a `sealed interface` case is
always pointer-sized in the enclosing value. Rust stores values inline unless
you ask for a pointer, and `Box` is how you ask.

### What a failed save does not give back

```rust
// The phrase is gated in core and is not handed back to the GUI. After a
// failed save the phrase box starts empty and is typed again.
(Body::Phrase { .. }, ItemData::RecoveryPhrase { .. }) => {}
```

When a save fails, `from_input` refills the form from the input that was never
sent. The login, address and note arms copy their values back. The phrase arm
does nothing.

The phrase sits in a `GatedSecret`. Core keeps `GatedSecret::expose`
crate-private, so the GUI cannot read it, and Holm does not widen that gate to
make a form friendlier. The price is that the user types the phrase again. The
other fields are still there.

Because `from_input` builds a blank form of the right kind first, the phrase
box is simply empty. The `match` only has to say "nothing to restore".

In Kotlin you'd keep the secret in a class with no getter and no `toString`,
and accept that the form can't read it back. A `private` or `internal` modifier
is the same kind of wall, but Rust checks it at the crate boundary.

## Try it

1. In `login_form.rs`, add a test that builds a recovery phrase input with
   `typed(NewKind::RecoveryPhrase, ..)`, calls `LoginForm::from_input(None,
   input, "x")`, and checks that `secret_char_count()` is 0 and `error` is
   `Some("x")`.
   `cargo test -p holm-gui --locked --lib screens::login_form::tests`
2. In `vault.rs`, delete the `("Secure note", NewKind::SecureNote)` line from
   `NEW_ENTRIES` and run `cargo check -p holm-gui --locked`. Read the error: the
   array has 3 elements, and its type says 4. Put the line back.

## Read next

- [Lesson 61](61-recovery-codes-and-schema-3.md), the lesson before this one
- [Lesson 63](63-codes-you-cross-off.md), the next lesson
- [the index](README.md)
- [The form and its buffers](../../crates/holm-gui/src/screens/login_form.rs)
- [The New menu and `DetailMode`](../../crates/holm-gui/src/screens/vault.rs)
- [Enums](https://doc.rust-lang.org/book/ch06-00-enums.html)
- [`Box<T>`](https://doc.rust-lang.org/book/ch15-01-box.html)
