//! Timing probes for the benchmark gates (`scripts/bench-gates.sh`, budgets in
//! `scripts/bench-budgets.env`). All are `#[ignore]`: timings mean nothing in a debug build,
//! so the script runs them with `--release -- --ignored --nocapture` and compares the
//! printed `BENCH name=<ms>` lines to the budgets. No benchmark crate is used.
//!
//! Each probe reports the fastest of several runs. A busy machine only makes a run slower,
//! so the minimum is the least noisy number.

use std::time::{Duration, Instant};

use holm_core::clock::Clock;
use holm_core::import::{ImportFormat, parse};
use holm_core::item::Timestamp;
use holm_core::search::Query;
use holm_core::session::Session;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::MasterPassword;
use holm_crypto::kdf::{KdfParams, derive_kek};

const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";
const ITEMS: usize = 10_000;

struct FixedClock;

impl Clock for FixedClock {
    fn now_unix(&self) -> Timestamp {
        Timestamp(1_700_000_000)
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
}

#[derive(Default)]
struct Mem(Option<Vec<u8>>);

impl VaultStore for Mem {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        self.0.clone().ok_or(StoreError::NotFound)
    }
    fn replace(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
    fn create_new(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if self.0.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        Ok(0)
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// One Argon2id derivation at the shipping costs (the dominant cost of an unlock).
#[test]
#[ignore = "timing probe; run by scripts/bench-gates.sh in release mode"]
fn bench_kdf_default() {
    let password = MasterPassword::new(PW.to_owned());
    let salt = [0x5a_u8; 32];
    let mut best = Duration::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        let key = derive_kek(&password, &salt, &KdfParams::DEFAULT).unwrap();
        let took = start.elapsed();
        drop(key);
        best = best.min(took);
    }
    println!("BENCH kdf_default_ms={:.1}", ms(best));
}

/// Search over 10,000 synthetic items with three queries: a miss (scans every field of every
/// item), a hit on a title fragment, and the empty query (default filters, so it matches and
/// sorts every item). Each is the minimum of 9 runs. The two typed queries are reported as the
/// worst of the two (`search_10k_ms`), the empty query on its own (`search_10k_empty_ms`).
#[test]
#[ignore = "timing probe; run by scripts/bench-gates.sh in release mode"]
fn bench_search_10k() {
    let mut csv = String::from("title,username,password,url,notes,category,type\n");
    for i in 0..ITEMS {
        csv.push_str(&format!(
            "Account number {i} example,user{i}@example.test,EXAMPLE-pw-{i},https://site{i}.example.test/login,note {i},,login\n"
        ));
    }
    let batch = parse(csv.as_bytes(), ImportFormat::Csv).unwrap();
    let mut session = Session::new(Mem::default(), Box::new(FixedClock));
    session
        .create(&MasterPassword::new(PW.to_owned()), &KdfParams::FLOOR)
        .unwrap();
    let report = session.import(batch).unwrap();
    assert_eq!(
        session.active_entries().unwrap().count(),
        ITEMS,
        "{}",
        report.imported
    );

    let mut worst = Duration::ZERO;
    let mut empty = Duration::ZERO;
    for needle in ["zzz no such text", "number 7777", ""] {
        let query = Query {
            text: needle.to_owned().into(),
            ..Query::default()
        };
        let mut best = Duration::MAX;
        for _ in 0..9 {
            let start = Instant::now();
            let hits = session.search(&query).unwrap();
            let took = start.elapsed();
            std::hint::black_box(hits.len());
            best = best.min(took);
        }
        println!("BENCH_DETAIL search {needle:?} {:.3} ms", ms(best));
        if needle.is_empty() {
            empty = best;
        } else {
            worst = worst.max(best);
        }
    }
    println!("BENCH search_10k_ms={:.3}", ms(worst));
    println!("BENCH search_10k_empty_ms={:.3}", ms(empty));
}
