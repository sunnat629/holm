# Roadmap after 0.1.x

Four phases. Each one ships on its own; a later phase never weakens an earlier one.

| Phase | Name | What it delivers |
|---|---|---|
| A | Memory hygiene | Less secret data in RAM and less of it left behind: a zero-on-free allocator, lock that wipes the window state, no core dumps, and a smaller and faster release build. No format, crypto or KDF change. |
| B | Decrypt on demand (format v4) | Today the whole vault body is decrypted at unlock. Format v4 encrypts each item separately, so only the items on screen are ever plaintext in memory. Needs a migration and a new golden file. |
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
| C5 Benchmark gates | Done: `scripts/bench-gates.sh` and `scripts/bench-budgets.env`, wired into `scripts/ci-local.sh`. Search over 10,000 items misses its 10 ms target (see DECISIONS). |
| C6 Docs | Done: `SECURITY.md` (contact still TBD by the owner), threat model, lesson 67. |
