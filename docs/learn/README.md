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
| 04 | Argon2id: turning a password into a key, and checking costs before doing work. |
| 05 | XChaCha20-Poly1305: encrypting with authentication, slices and byte arrays. |
| 06 | The vault header: parsing bytes safely, with no panics on bad input. |
| 07 | The envelope: create, open, save and re-key a vault, using everything so far. |
| 08 | Property tests and fuzzing: letting the computer invent hostile inputs. |

Lessons 04 to 08 are written as their tasks land.
