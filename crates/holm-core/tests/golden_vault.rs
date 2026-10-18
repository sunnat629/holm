//! The committed golden vault, `tests/vectors/golden-v1.vault`.
//!
//! A real v1 file that every later version of Holm must still open, so a change to
//! the format, the KDF or the body encoding cannot strand existing vaults. It holds
//! the default vault data (schema 1), locked with the test password
//! `"caf\u{e9} golden"` at [`KdfParams::FLOOR`].
//!
//! The file is deterministic: the salt, data key and nonces are fixed fills
//! (`0x11`, `0x22`, `0x33`, `0x44`) instead of random draws, so [`build_golden`]
//! rebuilds it byte for byte. Fixed nonces and a fixed key are for this test vector
//! only, never for a real vault. To regenerate it after a deliberate, reviewed
//! format change:
//!
//! ```text
//! cargo test -p holm-core --test golden_vault -- --ignored write_golden_vault
//! ```

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use holm_core::body::{BODY_SCHEMA_VERSION, VaultData};
use holm_core::clock::SystemClock;
use holm_core::envelope::VaultError;
use holm_core::error::CoreError;
use holm_core::format::{HEADER_LEN, Header, WRAP_AAD_LEN};
use holm_core::padding::{PAD_BLOCK, pad};
use holm_core::session::Session;
use holm_core::store::{StoreError, VaultStore};
use holm_crypto::MasterPassword;
use holm_crypto::aead::TAG_LEN;
use holm_crypto::kdf::{KdfParams, derive_kek};

const GOLDEN: &[u8] = include_bytes!("vectors/golden-v1.vault");
const GOLDEN_PATH: &str = "tests/vectors/golden-v1.vault";
/// The password the golden file was made with (precomposed "é").
const PASSWORD: &str = "caf\u{e9} golden";

const SALT: [u8; 32] = [0x11; 32];
const DEK: [u8; 32] = [0x22; 32];
const WRAP_NONCE: [u8; 24] = [0x33; 24];
const BODY_NONCE: [u8; 24] = [0x44; 24];

/// A read-only store over fixed bytes. The password check is `envelope::open`, which
/// is crate-private (every password check goes through the throttle), so these tests
/// open the vault through a `Session`.
struct BytesStore(Vec<u8>);

impl VaultStore for BytesStore {
    fn read(&mut self) -> Result<Vec<u8>, StoreError> {
        Ok(self.0.clone())
    }
    fn replace(&mut self, _: &[u8]) -> Result<(), StoreError> {
        Err(StoreError::Io(std::io::ErrorKind::PermissionDenied))
    }
    fn create_new(&mut self, _: &[u8]) -> Result<(), StoreError> {
        Err(StoreError::Io(std::io::ErrorKind::PermissionDenied))
    }
    fn remove_stale_temps(&mut self) -> Result<usize, StoreError> {
        Ok(0)
    }
}

fn session() -> Session<BytesStore> {
    Session::new(BytesStore(GOLDEN.to_vec()), Box::new(SystemClock::new()))
}

fn pw(s: &str) -> MasterPassword {
    MasterPassword::new(s.to_owned())
}

/// Seals `plaintext` with XChaCha20-Poly1305, as `holm_crypto::aead::seal` does, but
/// with a caller-chosen nonce.
fn seal_fixed(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce.into(), aad, &mut buf)
        .expect("sealing a small buffer cannot fail");
    buf
}

/// Builds the golden vault the same way `envelope::create` does, with the fixed
/// salt, data key and nonces above.
fn build_golden() -> Vec<u8> {
    let params = KdfParams::FLOOR;
    let body = VaultData::new_default().encode().unwrap();
    let padded = pad(body.expose()).unwrap();

    let mut header = Header {
        kdf: params,
        salt: SALT,
        wrap_nonce: WRAP_NONCE,
        wrapped_dek: [0; 48],
        body_nonce: [0; 24],
        body_len: 0,
    };
    let kek = derive_kek(&pw(PASSWORD), &SALT, &params).unwrap();
    let wrap_aad = header.encode();
    let wrapped = seal_fixed(kek.expose(), &WRAP_NONCE, &wrap_aad[..WRAP_AAD_LEN], &DEK);
    header.wrapped_dek = wrapped.try_into().unwrap();

    header.body_nonce = BODY_NONCE;
    header.body_len = u64::try_from(padded.len() + TAG_LEN).unwrap();
    let encoded = header.encode();
    let ct = seal_fixed(&DEK, &BODY_NONCE, &encoded, padded.expose());

    let mut file = encoded.to_vec();
    file.extend_from_slice(&ct);
    file
}

#[test]
fn golden_vault_opens_and_decodes_to_schema_v1() {
    assert_eq!(GOLDEN.len(), HEADER_LEN + PAD_BLOCK + TAG_LEN);
    let (h, _) = Header::parse(GOLDEN).unwrap();
    assert_eq!(h.kdf, KdfParams::FLOOR);
    // The decomposed form ("e" + combining acute) opens it too, which pins NFC.
    let mut s = session();
    s.unlock(&pw("cafe\u{301} golden")).unwrap();
    assert!(s.is_unlocked());
    assert!(!s.is_dirty());
    // The body round trip: the default body is schema 1 and re-encodes identically.
    let body = VaultData::new_default().encode().unwrap();
    assert_eq!(&body.expose()[..2], &BODY_SCHEMA_VERSION.to_le_bytes());
    assert_eq!(VaultData::decode(body.expose()).unwrap().item_count(), 0);
}

#[test]
fn golden_vault_refuses_a_wrong_password() {
    let mut s = session();
    assert_eq!(
        s.unlock(&pw("cafe golden")).unwrap_err(),
        CoreError::Vault(VaultError::WrongPasswordOrCorrupt)
    );
    assert!(!s.is_unlocked());
}

#[test]
fn golden_vault_regenerates_byte_for_byte() {
    assert!(
        build_golden() == GOLDEN,
        "golden-v1.vault no longer matches build_golden"
    );
}

/// Writes `build_golden()` to the vector file. Ignored: run it only on purpose (see
/// the module doc).
#[test]
#[ignore = "rewrites the committed golden vault"]
fn write_golden_vault() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_PATH);
    std::fs::write(path, build_golden()).unwrap();
}
