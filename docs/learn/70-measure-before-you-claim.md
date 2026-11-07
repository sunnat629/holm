# Lesson 70: Measure before you claim (B11, B12)

## What we built

- `#[ignore]` timing tests at 10 000 items (unlock, `open_item`, search, save).
- `scripts/compat-old-binary.sh`: builds an old CLI in a temp worktree and checks it refuses
  the v2 golden file without touching it. It is a local CI gate.
- A DECISIONS section with the real numbers, including the target we missed.

## Rust ideas, with Kotlin comparisons

- **`#[ignore]` and `--release`.** Timing tests only mean something optimised, so they are
  opt-in. JUnit's `@Disabled` is similar, but Rust lets you run them by flag.
- **`Instant` and percentiles.** `std::time::Instant` is monotonic. Report p99, not the mean.
- **`pub(super)` helpers.** Test helpers are shared with a sibling module without becoming API.
- **Shell from Rust-adjacent tooling.** The compat check drives a TTY with Python's `pty`,
  because the CLI reads the password only from `/dev/tty`.

## Why this matters for security

A claim without a test is a hope. The unlock target (+10%) was missed (+17%); we wrote that
down instead of loosening the words. The compat check found something the spec got wrong: an
old binary says "isn't a Holm vault", not "unsupported version", so the release notes must say so.

## Try it

1. Run the timing tests on your machine. Which one is closest to its limit?
2. Why is search the thinnest margin? Try a different query.
3. Run the compat script against a ref of your choice.

## Read next

`docs/DECISIONS.md` Phase B section.
