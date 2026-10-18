//! One handler per command. Each takes what it needs and returns `Result<(),
//! CliError>`; [`crate::run`] turns the result into text and an exit code.

pub mod read;
