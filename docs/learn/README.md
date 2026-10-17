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
| 08 | Property tests and fuzzing: letting the computer invent hostile inputs. |

Lesson 08 is written when its task lands.
