# 50: A debug-only dev unlock

## Why this matters

Typing a long master password on every restart makes developers reach for shortcuts, and a
shortcut in a password manager is a risk if it can ship. Holm adds one only where it cannot:
the feature exists in debug builds and the compiler refuses it in release builds, so no
release binary can unlock itself from an environment variable.

## What we built

A `dev-unlock` cargo feature. With it on, in a debug build, `HOLM_DEV_PASSWORD` is read once
at start and handed to the app, which unlocks an existing vault on the first unlock frame.
It tries once: after a wrong password the unlock screen stays, and a later lock never
unlocks again. An unset, empty or non-UTF-8 variable does nothing. With no vault the create
screen shows as usual, and no vault is made. The variable stays in the process environment,
so only ever use it with a test vault. CI proves three things: a release
build with the feature fails with our message, the feature's tests pass, and the normal
release binary does not contain the variable name.

## Rust ideas in this lesson

### `cfg(all(feature, debug_assertions))`

A `cfg` attribute removes code before it is compiled. `all(...)` needs every condition, so
the module, the field and the method exist only when the feature is on and it is a debug
build:

```rust
#[cfg(all(feature = "dev-unlock", debug_assertions))]
pub mod dev_unlock;
```

Code removed this way is not in the binary at all, which is why a grep of the release
binary can prove it is absent. In Kotlin you'd write `if (BuildConfig.DEBUG) { ... }`, but
that keeps the code in the app and only skips running it. R8 may strip it, and nothing makes
it fail.

### `compile_error!` as a build guard

A macro can stop the build with a message. Pairing it with a `cfg` turns "never do this"
into something the compiler enforces:

```rust
#[cfg(all(feature = "dev-unlock", not(debug_assertions)))]
compile_error!("the dev-unlock feature is for debug builds only");
```

`scripts/ci-local.sh` builds in release mode with the feature on and checks the build fails
on this message, so the guard itself is tested.

### `Option::take` for a one-shot value

`take` moves the value out and leaves `None` behind. In the unlock screen (simplified):

```rust
if let Some(pw) = self.dev_password.take() {
    self.start(ui.ctx(), Job::Unlock(pw));
}
```

The password is used at most once, and the app no longer holds it after the first try. In
Kotlin you'd write `val pw = devPassword; devPassword = null`, and nothing stops you from
forgetting the second line.

## Try it

1. Run the feature's tests and read the throttle assertion in the wrong-password test.
   Why does it check for exactly one failure? (The tests run on macOS only: the file is
   gated on `target_os = "macos"`.)
   `cargo test -p holm-gui --features dev-unlock --test dev_unlock`
2. Build once with `cargo build -p holm-gui --release` and once with
   `cargo build -p holm-gui --features dev-unlock`, then run
   `grep -qa HOLM_DEV_PASSWORD` on `target/release/holm-gui` and on
   `target/debug/holm-gui`. Explain the difference.
3. Try `cargo check -p holm-gui --release --features dev-unlock` and read the error. Which
   line of `lib.rs` printed it?

## Read next

- [Conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html)
- [`compile_error!`](https://doc.rust-lang.org/std/macro.compile_error.html)
- [`Option::take`](https://doc.rust-lang.org/std/option/enum.Option.html#method.take)
- Previous: [Lesson 49](49-letter-avatars.md)
- Next: [Lesson 51](51-closing-the-small-gaps.md)
- [The index](README.md)
