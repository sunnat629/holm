//! Randomness from the operating system. There is no fallback source: if the
//! OS cannot give us random bytes, we return an error.

use crate::error::CryptoError;

/// Fills `buf` with random bytes from the operating system.
///
/// # Errors
/// Returns [`CryptoError::Rng`] if the OS cannot provide randomness.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

/// Returns `N` random bytes. For salts and nonces only, which are not secret.
/// Never use this for keys: the array would be copied on the stack. Use
/// [`crate::SecretKey::generate`] instead.
///
/// # Errors
/// Returns [`CryptoError::Rng`] if the OS cannot provide randomness.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_nonces_differ() {
        let a = random_array::<24>().unwrap();
        let b = random_array::<24>().unwrap();
        assert_ne!(a, b);
    }
}
