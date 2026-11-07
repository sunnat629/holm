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
