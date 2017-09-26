#[macro_use(defer)] extern crate scopeguard;

mod verify;
mod serialize;

pub use self::verify::{verify_signature, SignatureAlgorithm, VerifyError};
