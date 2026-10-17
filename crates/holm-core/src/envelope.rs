//! The vault envelope: create, open, re-save and re-key a vault file.
//!
//! Key hierarchy (spec section 5.2):
//! - the master password goes through Argon2id with the header's salt and
//!   costs to give the key-encryption key (KEK);
//! - a random 32-byte data key (DEK) encrypts the body;
//! - the header stores the DEK sealed under the KEK (the "wrap"), with header
//!   bytes `0..60` as AAD;
//! - the body is the padded plaintext sealed under the DEK, with the whole
//!   164-byte header as AAD.
//!
//! A wrong password, a damaged wrap and a damaged body all give the same
//! error, [`VaultError::WrongPasswordOrCorrupt`].

use core::fmt;

use holm_crypto::aead::{self, Nonce, TAG_LEN};
use holm_crypto::kdf::{KdfParams, derive_kek};
use holm_crypto::{
    CryptoError, KdfParamsError, MasterPassword, SecretBuf, SecretKey, random_array,
};
use subtle::ConstantTimeEq;

use crate::format::{FormatError, HEADER_LEN, Header, WRAP_AAD_LEN};
use crate::padding::{pad, unpad};

/// Everything that can go wrong creating, opening or saving a vault.
///
/// No variant carries secret data. The `From` impls below are written by hand
/// on purpose (see their comments), so there is no `#[from]` here.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The file is not a well-formed v1 vault. Decided on public bytes only.
    #[error(transparent)]
    Format(FormatError),
    /// The key-derivation costs are outside Holm's policy. Never a password
    /// problem: this is decided before any key is derived.
    #[error("this vault needs more resources than allowed: {0}")]
    KdfPolicy(KdfParamsError),
    /// The password is wrong, or the file was changed or damaged. The two
    /// cannot and must not be told apart.
    #[error("wrong password, or the vault file is damaged")]
    WrongPasswordOrCorrupt,
    /// The body decrypted and authenticated, but its padding is malformed.
    /// Only a buggy writer can cause this; it never means a wrong password.
    #[error("the vault body is malformed")]
    BadPadding,
    /// The body is too large to save: the file would exceed the 64 MiB limit.
    #[error("the vault is too large to save (64 MiB limit)")]
    TooLargeToSave,
    /// The OS random source or the key derivation failed.
    #[error("a cryptographic operation failed")]
    Crypto,
}

/// Hand-written instead of `#[from]`: a cost-policy failure found by the
/// parser becomes [`VaultError::KdfPolicy`], the same variant `create` gives,
/// not `Format(KdfPolicy(..))`.
impl From<FormatError> for VaultError {
    fn from(e: FormatError) -> Self {
        match e {
            FormatError::KdfPolicy(k) => VaultError::KdfPolicy(k),
            other => VaultError::Format(other),
        }
    }
}

/// Hand-written instead of `#[from]`: every AEAD failure collapses into
/// [`VaultError::WrongPasswordOrCorrupt`]. The match lists every variant, so a
/// new `CryptoError` variant fails the build until someone maps it.
impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::KdfParams(k) => VaultError::KdfPolicy(k),
            CryptoError::Aead => VaultError::WrongPasswordOrCorrupt,
            CryptoError::Rng | CryptoError::Kdf | CryptoError::InvalidKeyLength => {
                VaultError::Crypto
            }
        }
    }
}

/// The keys of an open vault: the data key and the current header.
///
/// The fields are private, so code outside this module cannot read the DEK
/// or put a header in that does not match it. No `Clone`, and `Debug` prints
/// nothing. The DEK is wiped when this value is dropped.
pub struct VaultKeys {
    dek: SecretKey,
    header: Header,
}

impl VaultKeys {
    /// The data key. Tests only.
    #[cfg(test)]
    pub(crate) fn dek(&self) -> &SecretKey {
        &self.dek
    }
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKeys([REDACTED])")
    }
}

/// Creates a new vault holding `body`, locked with `password`.
///
/// Draws a fresh salt, DEK, wrap nonce and body nonce, and writes `params`
/// into the header exactly as given. The cost policy and the size cap are
/// checked before any key derivation or encryption.
///
/// # Errors
/// [`VaultError::KdfPolicy`] if `params` break the policy,
/// [`VaultError::TooLargeToSave`] if `body` is longer than
/// [`crate::padding::MAX_BODY_LEN`], [`VaultError::Crypto`] if randomness or
/// key derivation fails.
pub fn create(
    password: &MasterPassword,
    params: &KdfParams,
    body: &[u8],
) -> Result<(VaultKeys, Vec<u8>), VaultError> {
    params.validate().map_err(VaultError::KdfPolicy)?;
    let padded = pad(body)?;

    let salt = random_array::<32>()?;
    let kek = derive_kek(password, &salt, params)?;
    let dek = SecretKey::generate()?;

    let wrap_nonce = Nonce::random()?;
    let mut header = Header {
        kdf: *params,
        salt,
        wrap_nonce: *wrap_nonce.as_bytes(),
        // Filled in below. Neither field is part of the wrap AAD (bytes 0..60).
        wrapped_dek: [0; 48],
        body_nonce: [0; 24],
        body_len: 0,
    };
    let wrap_aad = header.encode();
    let wrapped = aead::seal(&kek, wrap_nonce, &wrap_aad[..WRAP_AAD_LEN], dek.expose())?;
    // Unreachable: sealing 32 bytes always gives 32 + 16 = 48.
    header.wrapped_dek =
        <[u8; 48]>::try_from(wrapped.as_slice()).map_err(|_| VaultError::Crypto)?;
    drop(kek);

    let (header, file) = seal_body(&dek, &header, &padded)?;
    Ok((VaultKeys { dek, header }, file))
}

/// Opens a vault file with `password` and returns its keys and body.
///
/// Order: [`Header::parse`] (size, header and KDF cost checks, all before any
/// Argon2 work), then key derivation, then `open_with_kek`.
///
/// # Errors
/// [`VaultError::Format`] or [`VaultError::KdfPolicy`] for a file refused on
/// its public bytes; [`VaultError::WrongPasswordOrCorrupt`] for a wrong
/// password or any change to the file; [`VaultError::BadPadding`] for an
/// authenticated body with malformed padding; [`VaultError::Crypto`] if key
/// derivation fails.
pub fn open(file: &[u8], password: &MasterPassword) -> Result<(VaultKeys, SecretBuf), VaultError> {
    let (header, _) = Header::parse(file)?;
    let kek = derive_kek(password, &header.salt, &header.kdf)?;
    open_with_kek(file, &kek)
}

/// Everything [`open`] does after key derivation: parse, unwrap the DEK, open
/// the body, remove the padding. Separate so tests can flip every byte of a
/// file without one Argon2 run per flip.
///
/// A failed DEK unwrap returns at once, before the body is decrypted, so a
/// wrong password can return sooner than a damaged body. Both give the same
/// error. See `docs/CRYPTO.md` for why the timing difference is accepted.
pub(crate) fn open_with_kek(
    file: &[u8],
    kek: &SecretKey,
) -> Result<(VaultKeys, SecretBuf), VaultError> {
    let (header, body) = Header::parse(file)?;
    // Authenticate the bytes as they are in the file, not a re-encoding.
    // Unreachable errors: `parse` succeeded, so the file has all 164 bytes.
    let head = file.get(..HEADER_LEN).ok_or(FormatError::TooShort)?;
    let wrap_aad = head.get(..WRAP_AAD_LEN).ok_or(FormatError::TooShort)?;

    let raw = aead::open(kek, &header.wrap_nonce, wrap_aad, &header.wrapped_dek)?;
    // Straight from the wiped buffer into the key's heap box: no stack copy.
    let dek = dek_from_unwrapped(&raw)?;
    drop(raw);
    let padded = aead::open(&dek, &header.body_nonce, head, body)?;
    let plaintext = unpad(padded.expose())?;
    Ok((VaultKeys { dek, header }, plaintext))
}

/// Encrypts `body` again under the same DEK, for a normal save.
///
/// Every call draws a new body nonce. `keys` is updated to the new header
/// only if the whole call succeeds.
///
/// # Errors
/// [`VaultError::TooLargeToSave`] if `body` is longer than
/// [`crate::padding::MAX_BODY_LEN`] (checked first, `keys` unchanged);
/// [`VaultError::Crypto`] if randomness fails.
pub fn reseal(keys: &mut VaultKeys, body: &[u8]) -> Result<Vec<u8>, VaultError> {
    let padded = pad(body)?;
    let (header, file) = seal_body(&keys.dek, &keys.header, &padded)?;
    keys.header = header;
    Ok(file)
}

/// Changes the master password: a new salt, new KDF costs, a **new DEK** and
/// new nonces, and returns the new file.
///
/// Everything new is built first. `keys` is replaced only if the whole call
/// succeeds, and the replacement drops (and so wipes) the old DEK. On error,
/// `keys` is unchanged and still works with the old password.
///
/// The DEK is rotated, not just re-wrapped. Otherwise anyone with an old copy
/// of the file and the old password could recover the DEK and read every later
/// version of the vault (spec section 5.2).
///
/// # Errors
/// As for [`create`].
pub fn rekey(
    keys: &mut VaultKeys,
    new_password: &MasterPassword,
    params: &KdfParams,
    body: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let (new_keys, file) = create(new_password, params, body)?;
    *keys = new_keys;
    Ok(file)
}

/// Checks `password` against an open vault, for example before revealing a
/// recovery phrase.
///
/// Derives the KEK again, unwraps the DEK and compares it with the one held,
/// in constant time.
///
/// # Errors
/// [`VaultError::WrongPasswordOrCorrupt`] if the password is wrong;
/// [`VaultError::Crypto`] if key derivation fails.
pub fn verify_password(keys: &VaultKeys, password: &MasterPassword) -> Result<(), VaultError> {
    let header = &keys.header;
    let kek = derive_kek(password, &header.salt, &header.kdf)?;
    let encoded = header.encode();
    let raw = aead::open(
        &kek,
        &header.wrap_nonce,
        &encoded[..WRAP_AAD_LEN],
        &header.wrapped_dek,
    )?;
    let candidate = dek_from_unwrapped(&raw)?;
    if bool::from(
        candidate
            .expose()
            .as_slice()
            .ct_eq(keys.dek.expose().as_slice()),
    ) {
        Ok(())
    } else {
        Err(VaultError::WrongPasswordOrCorrupt)
    }
}

/// Moves an unwrapped DEK into a key. A length error is unreachable (the
/// wrapped DEK is 48 bytes, so a successful unwrap gives exactly 32), but if
/// it ever happened it would come out as the one opaque error.
fn dek_from_unwrapped(raw: &SecretBuf) -> Result<SecretKey, VaultError> {
    SecretKey::from_slice(raw.expose()).map_err(|_| VaultError::WrongPasswordOrCorrupt)
}

/// Seals `padded` under `dek` with a fresh body nonce. Returns the new header
/// (a copy of `base` with the body nonce and length set) and the whole file.
fn seal_body(
    dek: &SecretKey,
    base: &Header,
    padded: &SecretBuf,
) -> Result<(Header, Vec<u8>), VaultError> {
    let body_nonce = Nonce::random()?;
    // body_len is part of the AAD, so it is set before encoding, from the
    // length the ciphertext will have. Both errors below are unreachable:
    // `pad` caps the length far below usize::MAX and u64::MAX.
    let ct_len = padded
        .len()
        .checked_add(TAG_LEN)
        .ok_or(VaultError::TooLargeToSave)?;
    let mut header = base.clone();
    header.body_nonce = *body_nonce.as_bytes();
    header.body_len = u64::try_from(ct_len).map_err(|_| VaultError::TooLargeToSave)?;
    let encoded = header.encode();

    let ct = aead::seal(dek, body_nonce, &encoded, padded.expose())?;
    // Unreachable: the AEAD output is always plaintext length plus the tag.
    if ct.len() != ct_len {
        return Err(VaultError::Crypto);
    }
    let mut file = Vec::with_capacity(HEADER_LEN + ct.len());
    file.extend_from_slice(&encoded);
    file.extend_from_slice(&ct);
    Ok((header, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MAX_FILE_LEN;
    use crate::padding::{MAX_BODY_LEN, PAD_BLOCK};

    const FLOOR: KdfParams = KdfParams::FLOOR;

    fn pw(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_owned())
    }

    fn new_vault(body: &[u8]) -> (VaultKeys, Vec<u8>) {
        create(&pw("correct horse"), &FLOOR, body).unwrap()
    }

    fn kek_for(file: &[u8], password: &str) -> SecretKey {
        let (h, _) = Header::parse(file).unwrap();
        derive_kek(&pw(password), &h.salt, &h.kdf).unwrap()
    }

    fn le_params(p: &KdfParams) -> Vec<u8> {
        [p.memory_kib, p.iterations, p.parallelism]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect()
    }

    #[test]
    fn create_then_open_returns_body() {
        let (_, file) = new_vault(b"hello vault");
        let (_, body) = open(&file, &pw("correct horse")).unwrap();
        assert_eq!(body.expose(), b"hello vault");
    }

    #[test]
    fn empty_body_roundtrip() {
        let (_, file) = new_vault(b"");
        assert_eq!(file.len(), HEADER_LEN + PAD_BLOCK + TAG_LEN);
        let (_, body) = open(&file, &pw("correct horse")).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn nfc_forms_open_same_vault() {
        let (_, file) = create(&pw("caf\u{e9}"), &FLOOR, b"x").unwrap();
        let (_, body) = open(&file, &pw("cafe\u{301}")).unwrap();
        assert_eq!(body.expose(), b"x");
    }

    #[test]
    fn wrong_password_is_opaque() {
        let (_, file) = new_vault(b"secret");
        assert_eq!(
            open(&file, &pw("wrong horse")).unwrap_err(),
            VaultError::WrongPasswordOrCorrupt
        );
    }

    #[test]
    fn header_stores_exact_kdf_params() {
        let custom = KdfParams {
            memory_kib: 131_072,
            iterations: 4,
            parallelism: 1,
        };
        for params in [FLOOR, custom] {
            let (_, file) = create(&pw("p"), &params, b"x").unwrap();
            let (h, _) = Header::parse(&file).unwrap();
            assert_eq!(h.kdf, params);
            assert_eq!(&file[16..28], le_params(&params).as_slice());
        }
    }

    #[test]
    fn default_params_written_as_262144_3_1() {
        let (_, file) = create(&pw("p"), &KdfParams::DEFAULT, b"x").unwrap();
        let (h, _) = Header::parse(&file).unwrap();
        let expected = KdfParams {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
        };
        assert_eq!(h.kdf, expected);
        assert_eq!(&file[16..28], le_params(&expected).as_slice());
    }

    #[test]
    fn create_rejects_params_outside_policy() {
        let below = KdfParams {
            memory_kib: FLOOR.memory_kib - 1,
            ..FLOOR
        };
        assert_eq!(
            create(&pw("p"), &below, b"x").unwrap_err(),
            VaultError::KdfPolicy(KdfParamsError::BelowFloor)
        );
        let heavy = KdfParams {
            memory_kib: 1_048_576,
            iterations: 5,
            parallelism: 1,
        };
        assert_eq!(
            create(&pw("p"), &heavy, b"x").unwrap_err(),
            VaultError::KdfPolicy(KdfParamsError::TooMuchWork)
        );
    }

    #[test]
    fn created_file_parses_and_matches_keys() {
        let (keys, file) = new_vault(b"abc");
        let (h, body) = Header::parse(&file).unwrap();
        assert_eq!(h, keys.header);
        assert_eq!(h.encode().as_slice(), &file[..HEADER_LEN]);
        assert_eq!(usize::try_from(h.body_len).unwrap(), body.len());
        assert_eq!(body.len(), PAD_BLOCK + TAG_LEN);
    }

    /// Opens a fresh vault by hand, following spec section 5.2 instead of
    /// this module, to pin the AAD ranges, nonce offsets and padded layout.
    #[test]
    fn file_layout_matches_spec() {
        let (keys, file) = new_vault(b"abc");
        let kek = kek_for(&file, "correct horse");
        let wrap_nonce: [u8; 24] = file[60..84].try_into().unwrap();
        let dek = aead::open(&kek, &wrap_nonce, &file[..60], &file[84..132]).unwrap();
        assert_eq!(dek.expose(), keys.dek().expose().as_slice());

        let dek = SecretKey::from_slice(dek.expose()).unwrap();
        let body_nonce: [u8; 24] = file[132..156].try_into().unwrap();
        let padded = aead::open(&dek, &body_nonce, &file[..164], &file[164..]).unwrap();
        let mut expected = vec![0u8; PAD_BLOCK];
        expected[..7].copy_from_slice(&[3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(padded.expose(), expected.as_slice());
        assert_eq!(
            &file[156..164],
            &u64::try_from(PAD_BLOCK + TAG_LEN).unwrap().to_le_bytes()
        );
    }

    /// A committed v1 vault, so a future change cannot silently strand
    /// existing files. Made once with
    /// `create(&pw("caf\u{e9} golden"), &KdfParams::FLOOR, GOLDEN_BODY)`;
    /// the salt, DEK and nonces were random, so it cannot be regenerated
    /// byte for byte. Opening it with the decomposed form of the password also
    /// pins NFC normalisation.
    #[test]
    fn golden_vault_opens() {
        const GOLDEN_BODY: &[u8] = b"Holm golden vault v1\n";
        let file = include_bytes!("../tests/vectors/golden-v1.vault");
        assert_eq!(file.len(), HEADER_LEN + PAD_BLOCK + TAG_LEN);
        let (h, _) = Header::parse(file).unwrap();
        assert_eq!(h.kdf, KdfParams::FLOOR);
        let (keys, body) = open(file, &pw("cafe\u{301} golden")).unwrap();
        assert_eq!(body.expose(), GOLDEN_BODY);
        assert_eq!(keys.header, h);
        assert_eq!(
            open(file, &pw("cafe golden")).unwrap_err(),
            VaultError::WrongPasswordOrCorrupt
        );
    }

    #[test]
    fn every_header_byte_flip_fails_fast() {
        let (_, mut file) = new_vault(b"some body");
        let kek = kek_for(&file, "correct horse");
        assert!(open_with_kek(&file, &kek).is_ok());
        for i in 0..HEADER_LEN {
            file[i] ^= 0x01;
            let err = open_with_kek(&file, &kek).expect_err("flipped header must fail");
            file[i] ^= 0x01;
            assert!(
                matches!(
                    err,
                    VaultError::Format(_)
                        | VaultError::KdfPolicy(_)
                        | VaultError::WrongPasswordOrCorrupt
                ),
                "byte {i}: {err:?}"
            );
            // Salt, nonces and the wrapped DEK are not checked by the parser:
            // only authentication catches them, with the one opaque error.
            if (28..156).contains(&i) {
                assert_eq!(err, VaultError::WrongPasswordOrCorrupt, "byte {i}");
            }
        }
    }

    #[test]
    fn every_body_byte_flip_fails() {
        let (_, mut file) = new_vault(b"some body");
        let kek = kek_for(&file, "correct horse");
        for i in HEADER_LEN..file.len() {
            file[i] ^= 0x01;
            let err = open_with_kek(&file, &kek).expect_err("flipped body must fail");
            file[i] ^= 0x01;
            assert_eq!(err, VaultError::WrongPasswordOrCorrupt, "byte {i}");
        }
    }

    #[test]
    fn sampled_flips_fail_end_to_end() {
        let (_, file) = new_vault(b"some body");
        let password = pw("correct horse");
        let last = file.len() - 1;
        let mut indices: Vec<usize> = (0..HEADER_LEN).collect();
        indices.extend([HEADER_LEN, HEADER_LEN + 1]);
        indices.extend((HEADER_LEN..file.len()).step_by(4096));
        indices.extend(last - (TAG_LEN - 1)..=last);
        indices.sort_unstable();
        indices.dedup();

        // Each flip that survives parsing costs one Argon2 run, so spread the
        // indices over a few threads.
        std::thread::scope(|s| {
            for chunk in indices.chunks(indices.len().div_ceil(4)) {
                let (file, password) = (&file, &password);
                s.spawn(move || {
                    let mut f = file.clone();
                    for &i in chunk {
                        f[i] ^= 0x01;
                        assert!(open(&f, password).is_err(), "byte {i}");
                        f[i] ^= 0x01;
                    }
                });
            }
        });
    }

    /// The body AAD covers the wrap nonce and wrapped DEK (bytes 60..132).
    /// A fresh, valid wrap of the same DEK under the same KEK passes the
    /// unwrap, so only the body AAD can catch the swap.
    #[test]
    fn substituted_wrap_fails_body_authentication() {
        let (keys, mut file) = new_vault(b"x");
        let kek = kek_for(&file, "correct horse");
        let nonce = Nonce::random().unwrap();
        file[60..84].copy_from_slice(nonce.as_bytes());
        let wrapped = aead::seal(&kek, nonce, &file[..60], keys.dek().expose()).unwrap();
        file[84..132].copy_from_slice(&wrapped);
        assert_eq!(
            open_with_kek(&file, &kek).unwrap_err(),
            VaultError::WrongPasswordOrCorrupt
        );
    }

    #[test]
    fn bad_padding_only_after_authentication() {
        let (keys, file) = new_vault(b"x");
        let kek = kek_for(&file, "correct horse");
        let mut bad = vec![0u8; PAD_BLOCK];
        bad[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_, forged) = seal_body(keys.dek(), &keys.header, &SecretBuf::from_vec(bad)).unwrap();
        assert_eq!(
            open_with_kek(&forged, &kek).unwrap_err(),
            VaultError::BadPadding
        );
    }

    #[test]
    fn reseal_uses_fresh_nonce() {
        let (mut keys, _) = new_vault(b"v1");
        let a = reseal(&mut keys, b"same body").unwrap();
        let b = reseal(&mut keys, b"same body").unwrap();
        assert_ne!(a[132..156], b[132..156]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
        let (_, body) = open(&b, &pw("correct horse")).unwrap();
        assert_eq!(body.expose(), b"same body");
        assert_eq!(Header::parse(&b).unwrap().0, keys.header);
    }

    #[test]
    fn reseal_keeps_salt_wrap_and_dek() {
        let (mut keys, first) = new_vault(b"v1");
        let second = reseal(&mut keys, b"v2").unwrap();
        assert_eq!(first[..132], second[..132]);
        let (reopened, body) = open(&second, &pw("correct horse")).unwrap();
        assert_eq!(body.expose(), b"v2");
        assert_eq!(reopened.dek().expose(), keys.dek().expose());
    }

    #[test]
    fn same_password_two_vaults_differ() {
        let (ka, a) = new_vault(b"same");
        let (kb, b) = new_vault(b"same");
        assert_ne!(a[28..60], b[28..60], "salt");
        assert_ne!(a[84..132], b[84..132], "wrapped DEK");
        assert_ne!(a, b);
        assert_ne!(ka.dek().expose(), kb.dek().expose());
    }

    #[test]
    fn padding_hides_small_size_differences() {
        let (_, small) = new_vault(&[1u8; 1]);
        let (_, larger) = new_vault(&[1u8; 16_000]);
        assert_eq!(small.len(), larger.len());
    }

    #[test]
    fn rekey_old_password_fails_new_password_opens() {
        let (mut keys, _) = new_vault(b"data");
        let file = rekey(&mut keys, &pw("new password"), &FLOOR, b"data").unwrap();
        assert_eq!(
            open(&file, &pw("correct horse")).unwrap_err(),
            VaultError::WrongPasswordOrCorrupt
        );
        let (_, body) = open(&file, &pw("new password")).unwrap();
        assert_eq!(body.expose(), b"data");
    }

    #[test]
    fn rekey_rotates_dek() {
        let (mut keys, old_file) = new_vault(b"data");
        let old_dek = SecretKey::from_slice(keys.dek().expose()).unwrap();
        let file = rekey(&mut keys, &pw("new password"), &FLOOR, b"data").unwrap();
        assert_ne!(keys.dek().expose(), old_dek.expose());
        assert_eq!(Header::parse(&file).unwrap().0, keys.header);
        assert_ne!(old_file[28..60], file[28..60], "salt");
        let (h, body) = Header::parse(&file).unwrap();
        assert_eq!(
            aead::open(&old_dek, &h.body_nonce, &file[..HEADER_LEN], body).unwrap_err(),
            CryptoError::Aead
        );
    }

    #[test]
    fn kdf_above_ceiling_is_policy_error_not_wrong_password() {
        let (_, mut file) = new_vault(b"x");
        file[16..20].copy_from_slice(&2_097_152u32.to_le_bytes());
        assert_eq!(
            open(&file, &pw("correct horse")).unwrap_err(),
            VaultError::KdfPolicy(KdfParamsError::AboveCeiling)
        );
    }

    #[test]
    fn verify_password_accepts_right_rejects_wrong() {
        let (keys, _) = new_vault(b"x");
        assert_eq!(verify_password(&keys, &pw("correct horse")), Ok(()));
        assert_eq!(
            verify_password(&keys, &pw("wrong horse")),
            Err(VaultError::WrongPasswordOrCorrupt)
        );
    }

    #[test]
    fn oversize_body_rejected_on_save() {
        let big = vec![0u8; MAX_BODY_LEN + 1];
        assert_eq!(
            create(&pw("p"), &FLOOR, &big).unwrap_err(),
            VaultError::TooLargeToSave
        );
        let (mut keys, _) = new_vault(b"x");
        let before = keys.header.clone();
        assert_eq!(
            reseal(&mut keys, &big).unwrap_err(),
            VaultError::TooLargeToSave
        );
        assert_eq!(keys.header, before);
        assert_eq!(
            rekey(&mut keys, &pw("p"), &FLOOR, &big).unwrap_err(),
            VaultError::TooLargeToSave
        );
    }

    #[test]
    fn failed_rekey_leaves_old_keys_working() {
        let (mut keys, _) = new_vault(b"v1");
        let old_dek = SecretKey::from_slice(keys.dek().expose()).unwrap();
        let before = keys.header.clone();
        let big = vec![0u8; MAX_BODY_LEN + 1];
        assert_eq!(
            rekey(&mut keys, &pw("new password"), &FLOOR, &big).unwrap_err(),
            VaultError::TooLargeToSave
        );
        let below = KdfParams {
            iterations: 2,
            ..FLOOR
        };
        assert_eq!(
            rekey(&mut keys, &pw("new password"), &below, b"v2").unwrap_err(),
            VaultError::KdfPolicy(KdfParamsError::BelowFloor)
        );
        assert_eq!(keys.header, before);
        assert_eq!(keys.dek().expose(), old_dek.expose());
        let file = reseal(&mut keys, b"v2").unwrap();
        let (_, body) = open(&file, &pw("correct horse")).unwrap();
        assert_eq!(body.expose(), b"v2");
    }

    #[test]
    fn max_body_saves_and_opens() {
        let body = vec![0x5A; MAX_BODY_LEN];
        let (_, file) = new_vault(&body);
        assert!(file.len() <= MAX_FILE_LEN);
        let (_, opened) = open(&file, &pw("correct horse")).unwrap();
        assert_eq!(opened.len(), MAX_BODY_LEN);
        assert!(opened.expose() == body.as_slice());
    }

    #[test]
    fn format_errors_map_without_nesting_kdf_policy() {
        assert_eq!(
            VaultError::from(FormatError::KdfPolicy(KdfParamsError::BelowFloor)),
            VaultError::KdfPolicy(KdfParamsError::BelowFloor)
        );
        assert_eq!(
            VaultError::from(FormatError::BadMagic),
            VaultError::Format(FormatError::BadMagic)
        );
    }

    #[test]
    fn crypto_errors_map_as_specified() {
        assert_eq!(
            VaultError::from(CryptoError::Aead),
            VaultError::WrongPasswordOrCorrupt
        );
        assert_eq!(
            VaultError::from(CryptoError::KdfParams(KdfParamsError::AboveCeiling)),
            VaultError::KdfPolicy(KdfParamsError::AboveCeiling)
        );
        for e in [
            CryptoError::Rng,
            CryptoError::Kdf,
            CryptoError::InvalidKeyLength,
        ] {
            assert_eq!(VaultError::from(e), VaultError::Crypto);
        }
    }

    #[test]
    fn error_messages_never_say_password_except_the_opaque_one() {
        let all = [
            VaultError::Format(FormatError::BadMagic),
            VaultError::KdfPolicy(KdfParamsError::AboveCeiling),
            VaultError::WrongPasswordOrCorrupt,
            VaultError::BadPadding,
            VaultError::TooLargeToSave,
            VaultError::Crypto,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &all {
            let msg = e.to_string();
            assert!(seen.insert(msg.clone()), "duplicate message: {msg}");
            if *e != VaultError::WrongPasswordOrCorrupt {
                assert!(!msg.to_lowercase().contains("password"), "{msg}");
            }
        }
    }

    #[test]
    fn vault_keys_debug_is_redacted() {
        let (keys, _) = new_vault(b"x");
        assert_eq!(format!("{keys:?}"), "VaultKeys([REDACTED])");
    }

    static_assertions::assert_not_impl_any!(VaultKeys: Clone, Copy);
}
