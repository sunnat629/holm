//! Argon2id key derivation (RFC 9106, version 1.3) with a cost policy.
//!
//! The costs come from the vault header, which an attacker can edit. So
//! [`KdfParams::validate`] runs before any memory is allocated: a vault that
//! asks for too little work is refused, and so is one that asks for so much
//! work that opening it would hang or exhaust the machine.

use crate::error::{CryptoError, KdfParamsError};
use crate::secret::{MasterPassword, SecretKey};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

/// Largest accepted memory cost, in KiB (1 GiB).
pub const MAX_M_KIB: u32 = 1_048_576;
/// Largest accepted number of passes over memory.
pub const MAX_T: u32 = 16;
/// Largest accepted `memory_kib × iterations`, computed in `u64` (4 GiB worth of passes).
pub const MAX_WORK: u64 = 4_194_304;

/// Argon2id cost parameters, exactly as stored in the vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub iterations: u32,
    /// Number of lanes. Holm v1 accepts only 1.
    pub parallelism: u32,
}

impl KdfParams {
    /// Costs for new vaults: 256 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        memory_kib: 262_144,
        iterations: 3,
        parallelism: 1,
    };

    /// The weakest costs Holm accepts: 64 MiB, 3 passes, 1 lane.
    pub const FLOOR: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// Checks the costs against Holm's policy. Does no hashing and allocates nothing.
    ///
    /// # Errors
    /// Returns the first rule broken, checked in this order:
    /// [`KdfParamsError::UnsupportedParallelism`], [`KdfParamsError::BelowFloor`],
    /// [`KdfParamsError::AboveCeiling`], [`KdfParamsError::TooMuchWork`].
    pub fn validate(&self) -> Result<(), KdfParamsError> {
        if self.parallelism != 1 {
            return Err(KdfParamsError::UnsupportedParallelism);
        }
        if self.memory_kib < Self::FLOOR.memory_kib || self.iterations < Self::FLOOR.iterations {
            return Err(KdfParamsError::BelowFloor);
        }
        if self.memory_kib > MAX_M_KIB || self.iterations > MAX_T {
            return Err(KdfParamsError::AboveCeiling);
        }
        // Widen to u64 before multiplying: in u32 the product can wrap around
        // to a small number and slip past the cap. checked_mul makes the
        // "cannot overflow" claim explicit instead of relying on the bounds above.
        match u64::from(self.memory_kib).checked_mul(u64::from(self.iterations)) {
            Some(work) if work <= MAX_WORK => Ok(()),
            _ => Err(KdfParamsError::TooMuchWork),
        }
    }
}

/// Derives the 32-byte key-encryption key (KEK) from the master password.
///
/// Uses Argon2id version 1.3 with exactly the costs in `params`, on the
/// password's NFC UTF-8 bytes. The policy is checked first, so a refused
/// `params` costs no memory and no hashing.
///
/// The Argon2 work area (64 MiB to 1 GiB of password-derived data) is wiped
/// before it is freed. It is not locked in RAM, so the OS may still swap it
/// out while the derivation runs. The BLAKE2b hash state inside argon2 wipes
/// on drop (our direct `blake2` dependency turns on its `zeroize` feature).
/// Stack temporaries are not wiped: 1 KiB blocks in argon2's block init and
/// compression, the 64-byte `blake2b_long` outputs (one holds a copy of the
/// KEK), and BLAKE2b's 128-byte padded final block and message words.
///
/// # Errors
/// Returns [`CryptoError::KdfParams`] if `params` break the policy, and
/// [`CryptoError::Kdf`] if the work area cannot be allocated or Argon2 fails.
pub fn derive_kek(
    password: &MasterPassword,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SecretKey, CryptoError> {
    params.validate().map_err(CryptoError::KdfParams)?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let block_count = argon_params.block_count();
    // Never Argon2::default(): its costs (19 MiB, 2 passes) are below our floor.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // We own the work area so we can wipe it: the argon2 crate frees its own
    // without wiping. try_reserve_exact turns "not enough memory" into an
    // error instead of aborting the process.
    let mut area = Vec::new();
    area.try_reserve_exact(block_count)
        .map_err(|_| CryptoError::Kdf)?;
    area.resize(block_count, Block::default());
    let mut blocks = Zeroizing::new(area);

    let pw = password.to_kdf_bytes();
    let mut key = SecretKey::zeroed();
    argon2
        .hash_password_into_with_memory(pw.expose(), salt, key.expose_mut(), &mut blocks[..])
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// Raw Argon2id v1.3 with every input exposed.
///
/// **This bypasses the cost policy.** It exists only so that test vectors and
/// the libsodium oracle can drive Argon2 directly. It is compiled only for this
/// crate's own unit tests or with the non-default `test-vectors` feature, so
/// the shipping library never contains it.
///
/// # Errors
/// Returns [`CryptoError::Kdf`] if Argon2 rejects any input.
#[cfg(any(test, feature = "test-vectors"))]
#[doc(hidden)]
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the RFC 9106 inputs one to one"
)]
pub fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    use argon2::{AssociatedData, ParamsBuilder};

    let data = AssociatedData::new(ad).map_err(|_| CryptoError::Kdf)?;
    let params = ParamsBuilder::new()
        .m_cost(m_kib)
        .t_cost(t)
        .p_cost(p)
        .data(data)
        .output_len(out.len())
        .build()
        .map_err(|_| CryptoError::Kdf)?;
    Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| CryptoError::Kdf)?
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Kdf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // argon2 hashes with `Blake2bVarCore` and `Blake2b512`. Our direct `blake2`
    // dependency turns on its `zeroize` feature, so their state wipes on drop.
    // `Blake2b512` has no `ZeroizeOnDrop` marker of its own, but its only two
    // fields (the core wrapper and the block buffer) both have it. That layout
    // comes from digest 0.11.3's `buffer_ct_variable!`, and these assertions
    // would still pass if a new field appeared: re-check the macro on every
    // digest or blake2 bump.
    static_assertions::assert_impl_all!(blake2::Blake2bVarCore: zeroize::ZeroizeOnDrop);
    static_assertions::assert_impl_all!(
        blake2::digest::block_api::CtOutWrapper<blake2::Blake2bVarCore, blake2::digest::consts::U64>:
            zeroize::ZeroizeOnDrop
    );
    static_assertions::assert_impl_all!(
        blake2::digest::block_api::Buffer<blake2::Blake2bVarCore>: zeroize::ZeroizeOnDrop
    );

    #[test]
    fn default_and_floor_are_valid() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        assert!(KdfParams::FLOOR.validate().is_ok());
    }
    #[test]
    fn default_and_floor_exact_values() {
        assert_eq!(
            KdfParams::DEFAULT,
            KdfParams {
                memory_kib: 262144,
                iterations: 3,
                parallelism: 1
            }
        );
        assert_eq!(
            KdfParams::FLOOR,
            KdfParams {
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1
            }
        );
    }
    #[test]
    fn below_floor_rejected() {
        assert_eq!(
            KdfParams {
                memory_kib: 65535,
                iterations: 3,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::BelowFloor)
        );
    }
    #[test]
    fn too_few_iterations_rejected() {
        assert_eq!(
            KdfParams {
                memory_kib: 65536,
                iterations: 2,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::BelowFloor)
        );
    }
    #[test]
    fn above_memory_cap_rejected() {
        assert_eq!(
            KdfParams {
                memory_kib: MAX_M_KIB + 1,
                iterations: 3,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::AboveCeiling)
        );
    }
    #[test]
    fn above_iteration_cap_rejected() {
        assert_eq!(
            KdfParams {
                memory_kib: 65536,
                iterations: MAX_T + 1,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::AboveCeiling)
        );
    }
    #[test]
    fn combined_work_rejected() {
        assert_eq!(
            KdfParams {
                memory_kib: 1048576,
                iterations: 5,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::TooMuchWork)
        );
    }
    #[test]
    fn work_cap_edges_accepted() {
        assert!(
            KdfParams {
                memory_kib: 1048576,
                iterations: 4,
                parallelism: 1
            }
            .validate()
            .is_ok()
        );
        assert!(
            KdfParams {
                memory_kib: 262144,
                iterations: 16,
                parallelism: 1
            }
            .validate()
            .is_ok()
        );
    }
    #[test]
    fn max_u32_does_not_overflow() {
        assert_eq!(
            KdfParams {
                memory_kib: u32::MAX,
                iterations: u32::MAX,
                parallelism: 1
            }
            .validate(),
            Err(KdfParamsError::AboveCeiling)
        );
    }
    #[test]
    fn hostile_zero_and_max_values_rejected() {
        // Values a hostile header could carry, each with the exact error it must get.
        let cases = [
            (0, 3, 1, KdfParamsError::BelowFloor),
            (65536, 0, 1, KdfParamsError::BelowFloor),
            (65536, 3, 0, KdfParamsError::UnsupportedParallelism),
            (65536, 3, u32::MAX, KdfParamsError::UnsupportedParallelism),
            (0, 0, 0, KdfParamsError::UnsupportedParallelism),
        ];
        for (memory_kib, iterations, parallelism, want) in cases {
            let p = KdfParams {
                memory_kib,
                iterations,
                parallelism,
            };
            assert_eq!(p.validate(), Err(want), "{p:?}");
        }
    }
    #[test]
    fn parallelism_must_be_one() {
        assert_eq!(
            KdfParams {
                parallelism: 2,
                ..KdfParams::DEFAULT
            }
            .validate(),
            Err(KdfParamsError::UnsupportedParallelism)
        );
    }
    #[test]
    fn policy_error_before_any_work() {
        let bad = KdfParams {
            memory_kib: MAX_M_KIB + 1,
            iterations: 3,
            parallelism: 1,
        };
        assert_eq!(
            derive_kek(&MasterPassword::new("x".into()), &[0; 32], &bad).unwrap_err(),
            CryptoError::KdfParams(KdfParamsError::AboveCeiling)
        );
    }
    #[test]
    fn nfc_forms_give_same_kek() {
        let salt = [9u8; 32];
        let a = derive_kek(
            &MasterPassword::new("caf\u{e9}".into()),
            &salt,
            &KdfParams::FLOOR,
        )
        .unwrap();
        let b = derive_kek(
            &MasterPassword::new("cafe\u{301}".into()),
            &salt,
            &KdfParams::FLOOR,
        )
        .unwrap();
        assert_eq!(a.expose(), b.expose());
    }
    #[test]
    fn derive_kek_uses_exact_params() {
        // derive_kek must use the params it is given, not crate defaults (Argon2::default() is 19 MiB / t2).
        let pw = MasterPassword::new("correct horse".into());
        let salt = [5u8; 32];
        let kek = derive_kek(&pw, &salt, &KdfParams::FLOOR).unwrap();
        let mut raw = [0u8; 32];
        argon2id_raw(
            pw.to_kdf_bytes().expose(),
            &salt,
            &[],
            &[],
            65536,
            3,
            1,
            &mut raw,
        )
        .unwrap();
        assert_eq!(kek.expose(), &raw);
        let mut other = [0u8; 32];
        argon2id_raw(
            pw.to_kdf_bytes().expose(),
            &salt,
            &[],
            &[],
            65536,
            4,
            1,
            &mut other,
        )
        .unwrap();
        assert_ne!(kek.expose(), &other);
    }
    #[test]
    fn derive_kek_follows_non_floor_params() {
        // A KEK made with costs other than FLOOR must match raw Argon2id at those
        // exact costs, so derive_kek cannot be quietly using fixed values.
        let pw = MasterPassword::new("correct horse".into());
        let salt = [6u8; 32];
        let params = KdfParams {
            memory_kib: 73728,
            iterations: 4,
            parallelism: 1,
        };
        let kek = derive_kek(&pw, &salt, &params).unwrap();
        let mut raw = [0u8; 32];
        argon2id_raw(
            pw.to_kdf_bytes().expose(),
            &salt,
            &[],
            &[],
            73728,
            4,
            1,
            &mut raw,
        )
        .unwrap();
        assert_eq!(kek.expose(), &raw);
    }
}

#[cfg(test)]
mod rfc9106_kat {
    use super::*;

    // RFC 9106, section 5.3 "Argon2id Test Vectors":
    // https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3
    // The tag below is copied from the RFC text.
    const RFC9106_ARGON2ID_TAG: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];

    #[test]
    fn rfc9106_argon2id_vector() {
        let mut tag = [0u8; 32];
        argon2id_raw(
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            32,
            3,
            4,
            &mut tag,
        )
        .unwrap();
        assert_eq!(tag, RFC9106_ARGON2ID_TAG);
    }
}
