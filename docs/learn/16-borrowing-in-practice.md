# Lesson 16: Borrowing in practice

## Why this matters

Almost every Rust bug you will fight early is a borrow problem: "cannot borrow as mutable because it is also borrowed as immutable". A vault makes it sharper, because we want to hand out a secret as a plain `&str` without ever copying it into a `String` that nobody wipes. This lesson shows the patterns that keep both the compiler and the security rules happy.

## What we built

`session/items.rs` adds, edits, trashes, restores and deletes items, changes settings, and reveals a recovery phrase only after the master password is checked again. `session/categories.rs` adds, renames and deletes categories. Every change follows one shape: check the input, apply the change in memory, save, and if the file would be too large to save, take the change back. `GatedSecret` has doctests that prove code outside the crate cannot call `expose()`. `session.rs` became a folder, `session/mod.rs`, with the two new files beside it.

## Rust ideas in this task

### Returning `&str` from a `&mut self` method

```rust
pub fn reveal_phrase(&mut self, id: ItemId, pw: &MasterPassword) -> Result<&str, CoreError> {
    /* check the item is a phrase, using a short shared borrow */
    self.check_password(pw)?;          // needs &mut self
    match self.item(id)?.data() {      // new shared borrow, after the mutable one ended
        ItemData::RecoveryPhrase { phrase, .. } => Ok(phrase.expose()),
        _ => Err(CoreError::NotAPhrase),
    }
}
```

The returned `&str` borrows from `self`, so the caller cannot touch the session while it holds the phrase. The trick is order: do the work that needs `&mut self` first, then take a fresh shared borrow at the end and return that. Borrows end at their last use, so the two do not overlap.

In Kotlin you'd write `fun reveal(id: ItemId): String`. The JVM keeps that `String` alive wherever it goes, and you cannot wipe it. Rust lets us return a view that lives only as long as the session says.

### `position`, `iter_mut` and `retain`

- `items.iter().position(|i| i.id == id)` gives `Option<usize>`: an index, or nothing. We turn "nothing" into `NotFound` with `ok_or`.
- `for item in data.items.iter_mut()` visits each item with write access. `delete_category` uses it to set `category = None`.
- `retain(|i| keep(i))` drops everything the closure rejects, in place. Holm does not use it: `empty_trash` has to remember each removed item and its index so a failed save can put them back, and `retain` throws the rejected items away.

In Kotlin you'd write `indexOfFirst { it.id == id }`, `forEach { it.category = null }` and `removeAll { ... }`. The Rust versions keep an index instead of a second reference to the element, which is what lets us borrow `items` again later.

### `std::mem::replace` for undo

```rust
let old = std::mem::replace(&mut data.settings, new);
self.commit_or_undo(move |d| d.settings = old)
```

`replace` puts the new value in and gives back the old one, without cloning. The closure takes ownership of `old` (`move`) and puts it back if the save fails with `TooLargeToSave`. For a pushed item the undo is `truncate(idx)`; for `delete_forever` it is `insert(pos, item)`. No secret is ever copied, only moved.

In Kotlin you'd write `val old = settings; settings = new` and keep `old` in a variable. That works because objects are shared references. In Rust a value has one owner, so the old value must be moved out on purpose.

### Splitting a module into a folder

`git mv session.rs session/mod.rs` changes nothing for callers: `crate::session::Session` still resolves. Then `mod items;` inside `mod.rs` loads `session/items.rs`. Child modules can read the parent's private fields, so `items.rs` can use `self.store` without making anything `pub`. That is why we keep the secret-touching helpers `pub(crate)` and the fields private.

### `compile_fail` doctests

A doc comment can hold a code block marked `compile_fail,E0624`. The test passes only if the block fails to compile with that exact error (private method). Doctests build as an outside crate, so they check the real public surface. Each one has a plain sibling that compiles, so a typo cannot fake a pass.

## Exercises

1. In `update_item`, temporarily change `keep` to always `false` and run the test that keeps an empty phrase. Read the failure, then restore the line.
   Check: `cargo test -p holm-core empty_phrase_on_update_keeps_phrase --locked`
2. Make `GatedSecret::expose` `pub` and run the doctests. Which ones fail, and with what message? Undo the change.
   Check: `cargo test -p holm-core --doc GatedSecret --locked`
3. In `delete_forever`, replace the last line with three: `let result = self.commit_or_undo(move |d| d.items.insert(pos, item));`, then `let _ = data.items.len();`, then `result`. Build. The compiler says ``error[E0499]: cannot borrow `*self` as mutable more than once at a time``. It marks `self.unlocked_mut()` (held by `data`) as the first mutable borrow, `self.commit_or_undo` as the second, and `data.items.len()` as "first borrow later used here". Without that later use, the borrow in `data` ends before the call, so the original code compiles. Undo the change. (Removing `move` from that closure also compiles. The closure takes `item` by value anyway, because `insert` consumes it. It may borrow `pos`, because `commit_or_undo` takes `impl FnOnce` with no `'static` bound and is done with the closure before it returns. Here `move` only makes the ownership visible.)
   Check: `cargo build -p holm-core --locked`

## Read next

- [The Rust Book, References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html)
- [`std::mem::replace`](https://doc.rust-lang.org/std/mem/fn.replace.html)
- [Rustdoc: documentation tests](https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html)
