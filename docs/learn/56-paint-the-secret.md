# Paint the secret

## Why this matters

A custom field can hold a PIN, a token or a whole private key. The GUI must let
the user type it, look at it, move it and save it. Every one of those steps can
leave a copy behind.

A `TextEdit` or a `Label` publishes its text to AccessKit, and screen readers
and other apps read that tree. A `String` that grows leaves the old bytes in
freed memory. A form that clones its fields keeps a second copy. Holm avoids
all three.

## What we built

The item editor has a custom field list. An empty list shows a preset picker.
Each row has a name box, suggested names, a kind picker, a value box and a
reminder date. Rows move up and down and can be removed. There are at most 10.

A secret value types into `secret_field`. A multiline value types into
`secret_area`, where Enter is a newline. Holding the eye paints the value. The
item view shows custom secrets with dots, Reveal and Copy, and hides them after
30 seconds. The widget tests walk the whole AccessKit tree and find no node with
`EXAMPLE` in it, even while the eye is held.

Save moves the fields to the worker. It updates the item, sets the custom
fields, then saves if anything changed. A non-login item saves its fields with
`Job::SetFields`.

## Rust ideas in this task

### Paint, do not publish

The field's AccessKit node gets a role and a fixed label. It gets no value.

```rust
    ui.ctx().accesskit_node_builder(id, |node| {
        node.set_role(Role::PasswordInput);
        node.set_label(label);
    });
```

The revealed text is drawn by the painter. It is a shape, not a widget, so
nothing reaches the tree.

```rust
    let galley = ui
        .painter()
        .layout(text.to_owned(), font, color, ui.available_width());
    let (rect, _) = ui.allocate_exact_size(galley.size(), Sense::hover());
    ui.painter().galley(rect.min, galley, color);
```

The galley is a plain copy that is not wiped. That gap is known and written in
the doc comment. A `TextEdit` would add undo history and a reader value too.

The item view uses the same painter. A custom secret gets a `Row` whose button
labels are fixed. The user's label is only the row's name:

```rust
                let row = Row {
                    field: RevealField::Custom(position),
                    name: field.label(),
                    reveal: REVEAL_LABEL,
                    copy: COPY_LABEL,
                };
```

`secret_row` paints the value only if it still shows after this frame's
clicks:

```rust
    if until.is_some() && view.until(row.field).is_some() {
        paint_secret(ui, value.expose());
    }
```

In Kotlin you'd draw on a `Canvas` with no `contentDescription`, instead of a
`Text` composable that TalkBack reads.

### A buffer that never grows

A private key can be several kilobytes. The multiline buffer reserves all of it
once, up to `MULTILINE_SECRET_CAP`, the core limit.

```rust
    pub fn with_multiline_capacity(cap: usize) -> SecretInput {
        SecretInput {
            bytes: Vec::with_capacity(cap),
            cap,
            multiline: true,
        }
    }
```

`push_str` stops before a character would pass the cap, so the `Vec` never
reallocates and `Drop` wipes the one allocation there is. The `multiline` flag
is fixed when the buffer is made. It decides whether `\n` and `\r` are kept.

In Kotlin you'd allocate one `CharArray` of the maximum size and fill it with
zeros after use, instead of a `StringBuilder` that copies as it grows.

### One owner, moved, not cloned

`update_item` does not touch custom fields. The worker takes them out of the
input first:

```rust
                    let fields = core::mem::take(&mut input.fields);
                    let result = session.update_item(id, input).and_then(|()| {
                        session.set_custom_fields(id, fields)?;
```

`mem::take` leaves an empty `Vec` behind and hands over the old one. Nothing is
copied. The job's `Debug` names the kind only:

```rust
            Job::SetFields(..) => write!(f, "Job::SetFields(<item hidden>)"),
```

In Kotlin you'd pass the list on and clear the form's reference. Rust checks at
compile time that nobody else still holds it.

### A kind change wipes the row

Each row owns a text, a secret and a date buffer. Changing the kind wipes them:

```rust
        // Replacing a LineBuf drops the old one, which wipes it.
        self.text = LineBuf::new();
        self.date = LineBuf::new();
        self.secret.clear();
```

A secret typed under "Secret" does not come back as text under "Text". A
suggested name fills the label with `LineBuf::from_text`, which returns `None`
when the text does not fit, so the label is never cut short.

In Kotlin you'd reset the old kind's state in the `ViewModel` when the kind
changes, instead of keeping every value in one data class.

## Try it

1. In `kind_change_wipes_the_value`, call `set_kind(Kind::Date)`, type
   `EXAMPLE-date` into `row.date`, then switch to `Kind::Secret`. Expect
   `row.date` to be empty.
   `cargo test -p holm-gui --locked kind_change_wipes_the_value`
2. In `editor_debug_has_no_secret`, set row 1 to `Kind::Multiline` and push
   `EXAMPLE-one\nEXAMPLE-two`. `Debug` must still not contain `EXAMPLE`.
   `cargo test -p holm-gui --locked editor_debug_has_no_secret`
3. In `secret_area_hold_paints_below_and_release_hides`, add
   `assert!(!tree_has_example(&harness))` after the release.
   `cargo test -p holm-gui --locked secret_area_hold_paints_below_and_release_hides`

## Read next

- [The secret field](../../crates/holm-gui/src/widgets/secret_field.rs)
- [Showing an item](../../crates/holm-gui/src/screens/item_view.rs)
- [The wiping buffer](../../crates/holm-gui/src/secret_input.rs)
- [The field editor](../../crates/holm-gui/src/screens/fields.rs)
- [The worker](../../crates/holm-gui/src/worker.rs)
- [Ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html)
- Previous: Lesson 55, listed in [the index](README.md).
- Next: [Lesson 57](57-a-badge-from-a-date.md), a badge from a date.
- All lessons: [the index](README.md).
