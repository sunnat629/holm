# Security policy

Holm is a password vault, so security reports matter more than most.

## Reporting a vulnerability

Please report privately using GitHub private vulnerability reporting:
open the **Security** tab of this repository and choose **Report a vulnerability**.

Do not open a public issue or pull request for a security problem.

## What to expect

- We acknowledge your report within 7 days.
- We keep you updated while we investigate and fix it.
- There is no bug bounty yet. We will credit you in the changelog if you want that.

## Scope

In scope: code, documentation and release process in this repository.

Out of scope: other projects, third-party dependencies (report those upstream, but tell us
too), and attacks the [threat model](docs/THREAT-MODEL.md) lists as out of scope, such as
malware running as your user while the vault is unlocked.

## Design decisions

Accepted risks and deferrals are listed in [docs/DECISIONS.md](docs/DECISIONS.md).

## Status

Holm is pre-alpha. Do not trust it with real secrets yet.
