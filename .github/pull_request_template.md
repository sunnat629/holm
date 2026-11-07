## What and why

## How you tested it

- [ ] `bash scripts/ci-local.sh` ends with `ALL GATES PASSED`
- [ ] Tests added or updated (a bug fix has a test that fails without it)
- [ ] `CHANGELOG.md` updated under `[Unreleased]`, if a user would notice
- [ ] Docs updated, and `docs/DECISIONS.md` if this changes the file format or cryptography
- [ ] No secrets, real vault files, email addresses or personal paths

Security-sensitive changes (crypto, file format, passwords, `unsafe`) get a closer review.
