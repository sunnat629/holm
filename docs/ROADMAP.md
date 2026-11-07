# Roadmap after 0.1.x

Four phases. Each one ships on its own; a later phase never weakens an earlier one.

| Phase | Name | What it delivers |
|---|---|---|
| A | Memory hygiene | Less secret data in RAM and less of it left behind: a zero-on-free allocator, lock that wipes the window state, no core dumps, and a smaller and faster release build. No format, crypto or KDF change. |
| B | Decrypt on demand (format v2) | Built on `feat/phase-b`, waiting for merge. Format v2 seals each item's secrets in a separate record, so only the value on screen is plaintext in memory. A v1 vault migrates on its first save, with a backup copy. Golden vectors committed. |
| C | Trust and repeatability | Reproducible builds, an SBOM, long fuzz runs, mutation tests, benchmark gates in CI, and a SECURITY.md with a disclosure process. |
| D | Open source and audit | Make the repository public, get an independent audit (NLnet / NGI Zero funding or a paid firm), publish the report, and run a bug bounty. |

Order matters: A is local and low risk, B changes the file format and must land before the audit
so the audit sees the final design, C gives auditors something they can rebuild and check, and D
comes last.

## Phase C status

| Item | State |
|---|---|
| C1 Reproducible builds | Done: `scripts/repro-check.sh`; two clean builds give identical binaries. |
| C2 SBOM | Done: `scripts/sbom.sh` (cargo-cyclonedx 0.5.10), optional step in `scripts/release-macos.sh`. |
| C3 Long fuzz | Done: `scripts/fuzz-long.sh [minutes-per-target]`. |
| C4 Test quality | Done: cargo-mutants report in `docs/security/mutants-2026-11.md`, killer tests added; Miri result in the same report. |
| C5 Benchmark gates | Done: `scripts/bench-gates.sh` and `scripts/bench-budgets.env`, wired into `scripts/ci-local.sh`. After Phase B, search over 10,000 items takes about 9.5 ms for a typed query and about 12.4 ms for the empty query (minimum of 9 runs). The gate catches regressions only (limits 12 and 16 ms); the 10 ms p99 target is not gated (see DECISIONS). |
| C6 Docs | Done: `SECURITY.md` (contact still TBD by the owner), threat model, lesson 71. |
