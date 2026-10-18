# Security policy

## Reporting a vulnerability

Report it privately. Open the **Security** tab of this repository, then choose
**Report a vulnerability**. Do not open a public issue or pull request for a security problem.

## Supported versions

Holm is pre-alpha, and no version is supported yet. We fix problems on `main` on a
best-effort basis.

## What to expect

- We acknowledge your report within 7 days.
- We keep you updated while we investigate and fix it.
- There is no bug bounty yet. We credit reporters in the changelog if they want that.

## Scope

In scope: Holm's code, docs and release process. That includes any way to read or change
the vault without the master password, and any break of the defences in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Until v1, some of those defences are still planned.

Out of scope: malware running as your user while the vault is unlocked, rollback to an
older copy of the vault file, and other projects. Report third-party dependency problems
upstream, and tell us too.

Accepted risks and deferrals are listed in [docs/DECISIONS.md](docs/DECISIONS.md).
