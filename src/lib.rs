#[macro_use(defer)] extern crate scopeguard;

mod verify;

pub use self::verify::{verify_signature, SignatureAlgorithm, VerifyError};
