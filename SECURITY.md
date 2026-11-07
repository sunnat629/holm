# Security policy

## Reporting a vulnerability

Report it privately. Open the **Security** tab of this repository, then choose
**Report a vulnerability**. Do not open a public issue or pull request for a security problem.

security contact: TBD by owner

Until the owner names a contact here, the private report on the Security tab is the only channel.
Please include the version (`holm --version`), what you did, and what you expected to happen.
Do not send a real vault file or a real master password.

## Supported versions

Holm is pre-alpha, and no version is supported yet. We fix problems on `main` on a
best-effort basis.

## What to expect

- We acknowledge your report within 7 days.
- We keep you updated while we investigate and fix it.
- Please give us 90 days to fix a problem before you publish it. We will ask for more time only if a fix needs a format change, and we will say why.
- A fix ships with a regression test, and a note in the changelog and `docs/DECISIONS.md`.
- There is no bug bounty yet. We credit reporters in the changelog if they want that.

## Scope

In scope: Holm's code, docs and release process. That includes any way to read or change
the vault without the master password, and any break of the defences in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Until v1, some of those defences are still planned.

Out of scope: malware running as your user while the vault is unlocked, rollback to an
older copy of the vault file, and other projects. Report third-party dependency problems
upstream, and tell us too.

## How to check a build yourself

`scripts/repro-check.sh` builds the release binaries twice from a clean export of `HEAD` and
compares their SHA-256. `scripts/sbom.sh` writes a CycloneDX list of every dependency. See the
"Phase C" section of [docs/DECISIONS.md](docs/DECISIONS.md) for what is and is not reproducible
(the Developer ID signature, its timestamp, the notarisation ticket and the DMG are not).

Accepted risks and deferrals are listed in [docs/DECISIONS.md](docs/DECISIONS.md).
