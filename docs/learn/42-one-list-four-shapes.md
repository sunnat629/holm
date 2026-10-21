# Lesson 42: One list, four shapes

## Why this matters

A vault holds more than logins: crypto addresses, recovery phrases and secure notes. Each one
has its own secret fields, and a recovery phrase is the most dangerous of them. If the app
handles every shape in one place, the compiler can check that none of them is forgotten,
and that no secret is shown in the wrong way.

## What we built

The item list in `crates/holm-gui/src/rows.rs` now lists every type, with a subtitle that
depends on the type. The detail pane moved to `crates/holm-gui/src/screens/item_view.rs`,
which has one `match` over `ItemData` with a branch for each shape. Each secret field has a
Reveal button that shows it for 30 seconds, and a Copy button that goes through the same
auto-clearing clipboard path as the login password. A recovery phrase asks for the master
password on every reveal. The worker checks that password (`Job::RevealPhrase`), and a
wrong password counts toward the same throttle as the unlock screen. The phrase then shows
for 60 seconds.

## Rust ideas in this task

### 1. An exhaustive `match` over the item's data

`show_item` matches on `item.data()` and gives each variant its own branch:

```rust
match item.data() {
    ItemData::Login { username, password, urls, notes } => { /* password row, notes row */ }
    ItemData::CryptoAddress { chain, address, memo, notes } => { /* chain, three rows */ }
    ItemData::RecoveryPhrase { notes, .. } => { /* the gated phrase row */ }
    ItemData::SecureNote { body } => { /* the multi-line body */ }
}
```

The list has no `_ =>` arm. If the core gains a fifth item type, this code stops compiling
until someone decides how the new type is shown. The subtitle in `rows.rs` uses the same
pattern over `ItemType`.

In Kotlin you'd write `when (data) { is Login -> …; is CryptoAddress -> … }` over a
`sealed class ItemData`. As a `when` used as an expression, that is exhaustive too. A Rust
`match` is always exhaustive, even when it is used as a statement.

### 2. A gated secret behind a worker job

The phrase is a `GatedSecret`, and the core gives it no public accessor. The only way out is
`Session::reveal_phrase(id, &password)`, which checks the password first. That check costs
a full Argon2 run, so it goes to the worker thread like an unlock does:

```rust
Job::RevealPhrase { id, password } => {
    let result = session
        .reveal_phrase(id, &password)
        .map(|words| phrase = Some(SecretText::new(words.to_owned())));
    drop(password);
    result
}
```

The password moves into the job with `take_master_password()`, which leaves the field
empty, and the worker drops (wipes) it. The words come back in a `SecretText`, which wipes
itself when it is dropped. `ItemView::hide` sets that `Option` to `None`, so hiding the
phrase also frees and wipes it. A wrong password stays on the gate with a fixed line. The
app's `finish` keeps the item view for this job kind instead of treating a failure as fatal.

In Kotlin you'd write `viewModelScope.launch(Dispatchers.Default) { … }` and post the
result back. A Kotlin `String` can't be wiped, though, and here the type system tracks who
owns the only copy.

### 3. Timers as `Option<Duration>`

What is showing, and until when, is one value:

```rust
revealed: Option<(RevealField, Duration)>,
```

`None` means nothing shows. `Some((RevealField::Memo, until))` means the memo shows until
`until` on the UI clock. Each frame, `tick` compares it with the clock:

```rust
if let Some((_, until)) = self.revealed
    && (now >= until || !focused)
{
    self.hide();
}
```

There is no timer thread and nothing to cancel. Only one field can show at a time, because
the type has room for only one. Selecting another item, Edit and lock all replace the whole
`ItemView`, so its fields drop and wipe.

In Kotlin you'd write `var revealedUntil: Long? = null` and check it in a `LaunchedEffect`.
The Rust tuple keeps the field and its deadline together, so you can't set one without the
other.

## Exercises

1. Give the crypto memo row a 15-second timer instead of 30. Only `RevealField::shows_for`
   needs to change. Check: `cargo test -p holm-gui --locked --lib item_view`
2. Add a test that the Copy note line is gone after you select another item. Check:
   `cargo test -p holm-gui --locked --test item_types`
3. Temporarily add a fifth variant to `ItemType` in a scratch branch, and read the errors
   the compiler gives in `rows.rs`. Then undo it. Check: `cargo build -p holm-gui --locked`

## Read next

- [Lesson 37: Hold to reveal](37-hold-to-reveal.md)
- [Lesson 36: Thin screens over the core](36-thin-screens-over-the-core.md)
- [Lesson 38: One clear for every client](38-one-clear-for-every-client.md)
