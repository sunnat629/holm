# Lesson 68: Open one item at a time (B5 to B7)

## What we built

- Session methods `entry`, `reveal(id, SecretSlot)`, `open_item` and `set_code_used`.
- `CoreError::DamagedItem` for a record that fails its tag or its cross-check.
- A GUI that holds `Option<&Session>` and never decrypts per frame.

## Rust ideas, with Kotlin comparisons

- **`&Session` versus `&mut Session`.** The vault screen gets a shared reference, so it cannot
  change anything; changes travel as `VaultAction` values. Kotlin has `val` references but no
  compiler-checked read-only view of an object.
- **Exhaustive `match`.** Adding `JobKind::DeleteBackup` makes every match on `JobKind` fail to
  compile until it is handled. A Kotlin `when` on a sealed class does the same, but only if you
  use it as an expression.
- **`Result` instead of `.ok()`.** `.ok()` throws away the reason. A damaged item must not
  look like "nothing selected", so the error is matched and shown.
- **`Zeroizing<T>`.** A wrapper that wipes on `Drop`; a revealed value dies when it hides.

## Why this matters for security

A partial memory capture should find no secrets. Only the value on screen is plaintext, and it
is dropped on hide, not on lock. The cost is that every reveal does a decrypt, so it must be
fast (about 0.55 ms) and must never run on every frame.

## Try it

1. Find where the GUI drops a revealed value. Which test pins it?
2. Make `reveal` return a `String`. What stops the wipe? (Hint: copies.)
3. Add a fifth `SecretSlot` variant and follow the compiler errors.

## Read next

Spec section 5, and lesson 56 (paint the secret).
