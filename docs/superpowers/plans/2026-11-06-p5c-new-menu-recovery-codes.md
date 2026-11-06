# P5c: New menu, recovery codes, category colours

**Goal:** Create all four item kinds from the window, store one-time recovery codes as a field kind, and colour avatars by category.

**Rules (same as P5b):** one cargo or CI run at a time under `nice -n 19`; one issue and one Rust lesson per task; Opus review per task; push `phase-5` only when `scripts/ci-local.sh` is green; no merge to `main`.

**Ruling:** no TOTP or 2FA secret generator. One vault holding the password and the second factor defeats 2FA. Recovery codes are different: they are a stored backup, not a live factor.

## Tasks

| # | Task | Writer | Files |
|---|---|---|---|
| T1 | Category colours: avatar colour from the category id, 8-colour palette, white text contrast at least 4.5:1 in light and dark (unit test computes WCAG contrast), a dot of the same colour on the category chip. No category keeps the grey. Labels stay, so colour is never the only signal. | aider Sonnet | `widgets/avatar.rs`, `rows.rs`, `screens/vault.rs` |
| T2 | "New ▾" toolbar menu: Login, Crypto address, Recovery phrase, Secure note. One form with a kind body; validation is `ItemInput::validate` from core, the same rule the CLI uses. The phrase input is a masked `SecretInput`, kept out of AccessKit like `RevealPhrase`. Custom fields work on every kind. | aider Sonnet | `screens/login_form.rs`, `screens/vault.rs`, `messages.rs`, tests |
| T3 | Core `FieldValue::RecoveryCodes(Vec<RecoveryCode>)`, `RecoveryCode { code: SecretText, used: bool }`. At most 20 codes, each 1 to 64 bytes, one line. Body schema 3; schema 1 and 2 still decode; encode writes 3. Round-trip, malformed and fuzz-seed tests. Never searched, never in `Debug`. | aider Opus | `holm-core` `fields.rs`, `wire.rs`, `body.rs`, `rules.rs` |
| T4 | Export and import of codes: one cell, codes joined by newline, a `*` prefix marks a used code. Round-trip tests in CSV and JSON. CLI `get` prints `HIDDEN`. | aider Opus | `export.rs`, `import/row.rs`, `holm-cli` |
| T5 | GUI: preset "Recovery codes" (paste one per line), detail view lists codes masked with Copy (through `PendingClear`) and Mark used / unused, used code struck through, "N of M left", list badge when 2 or fewer are left (Expiring chip style). Nothing in AccessKit. | aider Sonnet | `screens/fields.rs`, `screens/item_view.rs`, `rows.rs`, tests |

## Done when

- Each task has an issue, a lesson in `docs/learn`, a README row, and a green `ci-local` run before push.
- `docs/DECISIONS.md` records schema 3, the code limits, and the no-TOTP ruling.
