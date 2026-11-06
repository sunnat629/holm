# Lesson 66: Memory hygiene and release profiles

## Why this matters

A password manager is only as safe as the memory it leaves behind. The vault is encrypted on
disk, but while it is open the secrets sit in RAM, and RAM can reach disk through a crash dump or
swap, or just linger in freed pages. Phase A shrinks that exposure. It also shows that a few
lines in `Cargo.toml` can make the program smaller.

## What we built

- `hardening::disable_core_dumps`: `RLIMIT_CORE = 0` through rustix's safe `setrlimit`.
- `zeroing_alloc::ZeroingAlloc`: a global allocator that zeroes every block before it is freed.
- Lock now wipes egui's whole id-keyed memory, not just text-edit state.
- `[profile.release]` with fat LTO, one codegen unit and `strip = true`.
- `scripts/measure-macos.sh`: builds, launches the app and samples `footprint`.

## Core dumps

A crash can write the process's memory to a core file. Setting the limit to 0 means no file is
written. Do it first, before anything secret exists. The call is safe in rustix, so
`holm-gui` keeps `forbid(unsafe_code)`.

## A global allocator that wipes

Rust lets one `static` replace the allocator for the whole program:

```rust
#[global_allocator]
static ALLOC: ZeroingAlloc = ZeroingAlloc::new();
```

The attribute itself compiles inside a `forbid(unsafe_code)` crate; the `unsafe impl GlobalAlloc`
lives in `holm-platform`, in the one module that opts in. The rules it follows:

- `dealloc` writes zeros over the block, then gives it back.
- `realloc` allocates a new block, copies, wipes the old one and frees it. `System.realloc`
  could move a block and free the old one behind our back, so we do not call it.
- The wipe uses `write_volatile` and a `compiler_fence`. A plain loop of zero stores looks dead
  to the optimiser (nobody reads freed memory), so it may delete it. Volatile says "this write
  is observable".
- The allocator must not allocate. No `Vec`, no `format!`, no panic message.

What it does not cover: the stack, memory owned by AppKit or the GPU driver, and anything that
is never freed (a leak or the process image).

## Why not `mlock`

`mlock` asks the kernel to keep pages out of swap. We looked and skipped it: a 32-byte key
shares a page with other heap data, `munlock` is not counted so one drop would unpin the
neighbours, key copies exist elsewhere, `holm-crypto` forbids `unsafe`, and macOS swap is
encrypted anyway. Saying no, with reasons, is a design decision too (see `docs/DECISIONS.md`).

## Release profile

| Setting | Effect |
|---|---|
| `lto = "fat"` | The compiler sees the whole program at once and removes what is unused. |
| `codegen-units = 1` | One unit means more inlining, at the cost of a slower build. |
| `strip = true` | Drops symbols and debug info, so source paths are not shipped. |
| `panic` stays `unwind` | The GUI worker and a test rely on catching a panic. `abort` would skip both. |

## Before and after

Measured with `scripts/measure-macos.sh` on a release build, default Argon2id (256 MiB, 3
passes). The after-unlock rows are 3 s after the keystrokes; the window was not confirmed to
show the vault list (see the script's note), so treat them as attempted-unlock numbers.

| Measurement | Before | After |
|---|---|---|
| `holm-gui` binary | 8.24 MiB | 5.60 MiB |
| `holm` CLI binary | 2.24 MiB | 1.88 MiB |
| Holm.app on disk | 8,488 KiB | 5,804 KiB |
| Unlock peak, 5 items | 190.6 MiB | 185.8 MiB |
| Unlock peak, 1,000 items | 195.8 MiB | 189.3 MiB |
| 3 s after unlock, 5 items | 86.8 MiB | 87.1 MiB |
| 3 s after unlock, 1,000 items | 87.4 MiB | 85.5 MiB |
| Wiping 256 MiB on free | n/a | 10 to 30 ms |

The Argon2 area comes back to the OS after unlock in both columns: the footprint falls to the
locked baseline. The allocator adds tens of milliseconds to an unlock that takes one to two
seconds.

## Kotlin comparison

On the JVM you cannot choose the allocator and a `String` password cannot be wiped, because the
runtime may copy and keep it; the usual advice is a `CharArray` you overwrite by hand. In Rust a
type can wipe itself on drop (`zeroize`) and a global allocator can wipe everything else.

## Try it

1. Remove `write_volatile` from `wipe` and use a plain `*p = 0` loop. Build in release and read
   the assembly (`cargo asm`) or the size. Is the loop still there?
2. Run `ulimit -c` in a shell, then run `holm` and read its limit from inside the process.
3. Set `lto = "off"` and compare the build time and binary size.

## Read next

- [Lesson 65: Safe wrappers around AppKit](65-safe-wrappers-around-appkit.md)
- [The index](README.md)
