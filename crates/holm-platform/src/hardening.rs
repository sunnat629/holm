#![forbid(unsafe_code)]
//! Turn off core dumps so a crash cannot write process memory to disk.
//!
//! On Unix this sets `RLIMIT_CORE` to 0, both the soft and the hard limit, through
//! rustix's safe `setrlimit`. Elsewhere it does nothing and returns `Ok`. Call it
//! once at process start. A failure is not fatal: the caller prints a short line
//! and continues.

use std::io;

/// Sets the core-dump size limit to zero on Unix. Other operating systems
/// succeed without doing anything.
pub fn disable_core_dumps() -> io::Result<()> {
    #[cfg(unix)]
    {
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_core_dumps_sets_rlimit_core_to_zero() {
        disable_core_dumps().unwrap();
        #[cfg(unix)]
        {
            let lim = rustix::process::getrlimit(rustix::process::Resource::Core);
            assert_eq!(lim.current, Some(0));
            assert_eq!(lim.maximum, Some(0));
        }
    }
}
