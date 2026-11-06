#![allow(
    unsafe_code,
    reason = "a GlobalAlloc impl is unsafe by definition; each block has a SAFETY comment"
)]
//! A global allocator that wipes every block before it goes back to the system.
//!
//! [`ZeroingAlloc`] hands allocation to [`System`] and zeroes memory on the way out. A
//! freed block is zeroed in full. A resized block is moved to a new allocation and the old
//! one is zeroed and then freed. This includes shrinks, because `System.realloc` may move
//! a block and free the old one without passing through our `dealloc`.
//!
//! Nothing in here allocates, formats or panics. An allocator that allocates would recurse.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};
use std::alloc::System;

/// Zeroes `len` bytes at `ptr` with volatile writes, so the compiler cannot drop them as
/// dead stores. A compiler fence follows the writes. Does nothing when `len` is 0, so
/// `ptr` may then be null or dangling.
///
/// # Safety
/// When `len > 0`, `ptr` must be valid for writes of `len` bytes.
#[inline]
pub unsafe fn wipe(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    // Bytes up to the first 8-aligned address, then 8 bytes at a time, then the tail.
    // Word writes keep wiping a 256 MiB Argon2 area fast; volatile stops the compiler
    // from removing them as dead stores.
    let head = ptr.align_offset(core::mem::align_of::<u64>()).min(len);
    let words = (len - head) / 8;
    for i in 0..head {
        // SAFETY: the caller guarantees `ptr..ptr + len` is valid for writes, and
        // `i < head <= len`.
        unsafe { ptr::write_volatile(ptr.add(i), 0) };
    }
    // SAFETY: `head <= len`, so this stays inside (or one past the end of) the range.
    let body = unsafe { ptr.add(head) }.cast::<u64>();
    for i in 0..words {
        // SAFETY: `body` is 8-aligned (`head` came from `align_offset`) and
        // `body + words * 8 <= ptr + len`, inside the range the caller guarantees.
        unsafe { ptr::write_volatile(body.add(i), 0) };
    }
    for i in (head + words * 8)..len {
        // SAFETY: `i < len`, inside the range the caller guarantees.
        unsafe { ptr::write_volatile(ptr.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A [`GlobalAlloc`] over an inner allocator (by default [`System`]) that zeroes every
/// block before it is freed. The inner type is a parameter only so a test can check that
/// a block is zero at the moment it is handed back.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroingAlloc<A: GlobalAlloc = System> {
    inner: A,
}

impl ZeroingAlloc<System> {
    /// The allocator over [`System`]. `const` so it can be a `#[global_allocator]` static.
    #[must_use]
    pub const fn new() -> ZeroingAlloc<System> {
        ZeroingAlloc { inner: System }
    }
}

impl<A: GlobalAlloc> ZeroingAlloc<A> {
    /// The allocator over `inner`.
    #[must_use]
    pub const fn with_inner(inner: A) -> ZeroingAlloc<A> {
        ZeroingAlloc { inner }
    }
}

// SAFETY: allocation and freeing are delegated to the inner allocator, which upholds the
// `GlobalAlloc` contract. Before a block is handed back to it, we only write zeros
// into memory the caller owns. `realloc` returns either null (leaving the old block
// untouched) or a fresh inner block with the caller's layout alignment and `new_size`
// bytes, holding the copied prefix.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroingAlloc<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which we pass on
        // unchanged.
        unsafe { self.inner.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc_zeroed`'s contract, which we
        // pass on unchanged.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` is a live block from this allocator with
        // `layout`, so `layout.size()` bytes at `ptr` are valid for writes.
        unsafe { wipe(ptr, layout.size()) };
        // SAFETY: `ptr` was allocated by the inner allocator (every path here allocates
        // through it) with `layout`, and it has not been freed yet.
        unsafe { self.inner.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        if new_size == old_size {
            return ptr;
        }
        // SAFETY: the caller guarantees `new_size > 0`, and that `new_size` rounded up to
        // `layout.align()` does not overflow `isize`. The alignment comes from a valid
        // `Layout`.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: `new_layout` has a non-zero size, as shown above.
        let new_ptr = unsafe { self.inner.alloc(new_layout) };
        if new_ptr.is_null() {
            return new_ptr;
        }
        let keep = new_size.min(old_size);
        // SAFETY: `ptr` is valid for reads of `old_size >= keep` bytes. `new_ptr` is a
        // fresh block of `new_size >= keep` bytes. They are distinct live allocations, so
        // they do not overlap.
        unsafe { ptr::copy_nonoverlapping(ptr, new_ptr, keep) };
        // SAFETY: `ptr` is a live block from this allocator with `layout`. The caller
        // gives up ownership of it on a successful realloc.
        unsafe { self.dealloc(ptr, layout) };
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::AtomicUsize;

    /// An inner allocator that checks, at the moment a block is freed, that every byte
    /// is zero. It never panics (it runs inside the allocator); it counts instead.
    #[derive(Default)]
    struct CheckingAlloc {
        frees: AtomicUsize,
        dirty_frees: AtomicUsize,
    }

    // SAFETY: every method forwards to `System` unchanged; `dealloc` only reads the block
    // first, which the caller guarantees is live and `layout.size()` bytes long.
    unsafe impl GlobalAlloc for CheckingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarded with the caller's contract.
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            let bytes = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            self.frees.fetch_add(1, Ordering::SeqCst);
            if bytes.iter().any(|&b| b != 0) {
                self.dirty_frees.fetch_add(1, Ordering::SeqCst);
            }
            // SAFETY: forwarded with the caller's contract.
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    fn counts(a: &ZeroingAlloc<CheckingAlloc>) -> (usize, usize) {
        (
            a.inner.frees.load(Ordering::SeqCst),
            a.inner.dirty_frees.load(Ordering::SeqCst),
        )
    }

    #[test]
    fn checker_notices_a_dirty_free() {
        // The checker itself must work, or the tests below prove nothing.
        let c = CheckingAlloc::default();
        let layout = Layout::from_size_align(32, 8).unwrap();
        // SAFETY: non-zero layout.
        let p = unsafe { c.alloc(layout) };
        // SAFETY: `p` is a live 32-byte block.
        unsafe { ptr::write_bytes(p, 0x77, 32) };
        // SAFETY: `p` is live with `layout`, freed once.
        unsafe { c.dealloc(p, layout) };
        assert_eq!(c.dirty_frees.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dealloc_hands_back_zeroed_bytes() {
        let a = ZeroingAlloc::with_inner(CheckingAlloc::default());
        let layout = Layout::from_size_align(200, 8).unwrap();
        // SAFETY: non-zero layout.
        let p = unsafe { a.alloc(layout) };
        // SAFETY: `p` is a live 200-byte block.
        unsafe { ptr::write_bytes(p, 0xC3, 200) };
        // SAFETY: `p` is live with `layout`, freed once.
        unsafe { a.dealloc(p, layout) };
        assert_eq!(counts(&a), (1, 0));
    }

    #[test]
    fn realloc_hands_back_zeroed_old_block() {
        for (old, new) in [(16usize, 4096usize), (4096, 16), (100, 101)] {
            let a = ZeroingAlloc::with_inner(CheckingAlloc::default());
            let layout = Layout::from_size_align(old, 8).unwrap();
            // SAFETY: non-zero layout.
            let p = unsafe { a.alloc(layout) };
            // SAFETY: `p` is a live block of `old` bytes.
            unsafe { ptr::write_bytes(p, 0xC3, old) };
            // SAFETY: `p` is live with `layout`; `new` is non-zero.
            let q = unsafe { a.realloc(p, layout, new) };
            assert!(!q.is_null());
            // The old block was freed by realloc and must have been zero at that moment.
            assert_eq!(counts(&a), (1, 0), "old {old} new {new}");
            // SAFETY: `q` is live with size `new` and align 8, freed once.
            unsafe { a.dealloc(q, Layout::from_size_align(new, 8).unwrap()) };
            assert_eq!(counts(&a), (2, 0), "old {old} new {new}");
        }
    }

    /// Times the wipe of a 256 MiB block, the size of the default Argon2 area. Run with
    /// `cargo test -p holm-platform --release -- --ignored --nocapture wipe_256`.
    #[test]
    #[ignore = "timing, run by hand"]
    fn wipe_256_mib_timing() {
        let mut v = vec![1u8; 256 << 20];
        for _ in 0..3 {
            let t = std::time::Instant::now();
            // SAFETY: `v` is a live buffer of `v.len()` bytes.
            unsafe { wipe(v.as_mut_ptr(), v.len()) };
            std::println!("wipe 256 MiB: {:?}", t.elapsed());
            v[0] = 1;
        }
    }

    #[test]
    fn wipe_zeroes_a_buffer() {
        let mut buf = [0xAAu8; 64];
        // SAFETY: `buf` is a live, writable array of `buf.len()` bytes.
        unsafe { wipe(buf.as_mut_ptr(), buf.len()) };
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn wipe_stops_at_len() {
        let mut buf = [0xAAu8; 16];
        // SAFETY: 8 bytes of the 16-byte `buf` are writable.
        unsafe { wipe(buf.as_mut_ptr(), 8) };
        assert!(buf[..8].iter().all(|&b| b == 0));
        assert!(buf[8..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn wipe_handles_every_alignment_and_length() {
        for start in 0..9usize {
            for len in 0..40usize {
                let mut buf = [0xAAu8; 64];
                // SAFETY: `start + len <= 48 < 64`, inside the live `buf`.
                unsafe { wipe(buf.as_mut_ptr().add(start), len) };
                for (i, &b) in buf.iter().enumerate() {
                    let inside = i >= start && i < start + len;
                    assert_eq!(b == 0, inside, "start {start} len {len} byte {i}");
                }
            }
        }
    }

    #[test]
    fn zero_size_is_safe() {
        // SAFETY: `len` is 0, so `wipe` touches no memory.
        unsafe { wipe(ptr::null_mut(), 0) };
        // SAFETY: `len` is 0, so `wipe` touches no memory.
        unsafe { wipe(ptr::NonNull::<u8>::dangling().as_ptr(), 0) };
    }

    #[test]
    fn alloc_dealloc_round_trip() {
        let a = ZeroingAlloc::new();
        let layout = Layout::from_size_align(128, 16).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        assert_eq!(p as usize % 16, 0);
        // SAFETY: `p` is a live block of 128 bytes.
        unsafe { ptr::write_bytes(p, 0x5A, 128) };
        // SAFETY: `p` came from `a.alloc(layout)` and is freed once.
        unsafe { a.dealloc(p, layout) };
    }

    #[test]
    fn alloc_zeroed_returns_zeros() {
        let a = ZeroingAlloc::new();
        let layout = Layout::from_size_align(256, 8).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let p = unsafe { a.alloc_zeroed(layout) };
        assert!(!p.is_null());
        // SAFETY: `p` is a live, initialised block of 256 bytes.
        let bytes = unsafe { core::slice::from_raw_parts(p, 256) };
        assert!(bytes.iter().all(|&b| b == 0));
        // SAFETY: `p` came from `a.alloc_zeroed(layout)` and is freed once.
        unsafe { a.dealloc(p, layout) };
    }

    #[test]
    fn realloc_grow_keeps_old_bytes() {
        let a = ZeroingAlloc::new();
        let layout = Layout::from_size_align(16, 8).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        for i in 0..16u8 {
            // SAFETY: `i < 16`, inside the live 16-byte block.
            unsafe { p.add(usize::from(i)).write(i) };
        }
        // SAFETY: `p` is live with `layout`, and 64 is non-zero and fits `isize`.
        let q = unsafe { a.realloc(p, layout, 64) };
        assert!(!q.is_null());
        assert_eq!(q as usize % 8, 0);
        // SAFETY: `q` is a live block of 64 bytes, and its first 16 were copied in.
        let head = unsafe { core::slice::from_raw_parts(q, 16) };
        assert_eq!(head, &(0..16u8).collect::<Vec<_>>()[..]);
        // SAFETY: `q` is live with size 64 and align 8, and is freed once.
        unsafe { a.dealloc(q, Layout::from_size_align(64, 8).unwrap()) };
    }

    #[test]
    fn realloc_shrink_keeps_prefix() {
        let a = ZeroingAlloc::new();
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        for i in 0..64u8 {
            // SAFETY: `i < 64`, inside the live 64-byte block.
            unsafe { p.add(usize::from(i)).write(i) };
        }
        // SAFETY: `p` is live with `layout`, and 8 is non-zero.
        let q = unsafe { a.realloc(p, layout, 8) };
        assert!(!q.is_null());
        // SAFETY: `q` is a live block of 8 bytes, all of them copied in.
        let head = unsafe { core::slice::from_raw_parts(q, 8) };
        assert_eq!(head, &[0, 1, 2, 3, 4, 5, 6, 7]);
        // SAFETY: `q` is live with size 8 and align 8, and is freed once.
        unsafe { a.dealloc(q, Layout::from_size_align(8, 8).unwrap()) };
    }

    #[test]
    fn realloc_same_size_returns_same_block() {
        let a = ZeroingAlloc::new();
        let layout = Layout::from_size_align(32, 8).unwrap();
        // SAFETY: `layout` has a non-zero size.
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        // SAFETY: `p` is live with `layout`, and 32 is non-zero.
        let q = unsafe { a.realloc(p, layout, 32) };
        assert_eq!(p, q);
        // SAFETY: `q` is live with `layout`, and is freed once.
        unsafe { a.dealloc(q, layout) };
    }
}
