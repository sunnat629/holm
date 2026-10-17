//! Holm command-line app.

#![forbid(unsafe_code)]

fn main() {
    println!("holm {}", env!("CARGO_PKG_VERSION"));
}
