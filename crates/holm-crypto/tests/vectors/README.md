# Test vectors

## xchacha20_poly1305_test.json

- Source: https://github.com/C2SP/wycheproof/blob/7a325932231bd7a724c791c8b0d65ea4d6d2f435/testvectors_v1/xchacha20_poly1305_test.json
- Repository: https://github.com/C2SP/wycheproof (official Wycheproof)
- Pinned commit: `7a325932231bd7a724c791c8b0d65ea4d6d2f435` (2026-10-12)
- File SHA-256: `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9`
- Fetched over HTTPS from github.com, unmodified.

Counts that `tests/xchacha_kat.rs` asserts (re-counted from the pinned file):

| Quantity | Count |
|---|---|
| `numberOfTests` | 315 |
| run (nonce is 24 bytes) | 306 (246 `valid` + 60 `invalid`) |
| skipped (nonce is not 24 bytes, all `invalid`) | 9 |

The 9 skipped cases cannot be passed to `open(&[u8; 24])`: the type system
rejects a wrong-length nonce before any crypto runs.

If the file is ever re-pinned, recount and update this table and the test.
