extern crate sha2;
extern crate verify_signed_digest;

use sha2::Digest;
use std::os::raw;
use std::ptr;
use std::sync::{Once, ONCE_INIT};
use verify_signed_digest as verify;

static START: Once = ONCE_INIT;

// curve: NIST P-256
// public key: U = xG
// Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
// Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
// SEQUENCE
//   SEQUENCE
//     OID: 1.2.840.10045.2.1 (ecPublicKey)
//     OID: 1.2.840.10045.3.1.7 (NIST P-256)
//  BITSTRING (uncompressed EC point)
static NIST_P256_TEST_SPKI: &'static [u8] =
    &[0x30, 0x59,
            0x30, 0x13,
                  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42,
                  0x00, // 0 unused bits
                  0x04, // uncompressed form
                  0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
                        0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa,
                        0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
                  0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
                        0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f,
                        0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99];

type SECStatus = raw::c_int;
const SEC_SUCCESS: SECStatus = 0;
// TODO: ugh this will probably have a platform-specific name...
#[link(name="nss3")]
extern {
    fn NSS_NoDB_Init(configdir: *const u8) -> SECStatus;
}

fn setup() {
    START.call_once(|| {
        let null_ptr: *const u8 = ptr::null();
        unsafe {
            assert!(NSS_NoDB_Init(null_ptr) == SEC_SUCCESS);
        }
    });
}

#[test]
fn test_rfc6979_test_vector_1() {
    setup();
    // With SHA-256, message = "sample":
    // k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    // r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    // s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    // SEQUENCE
    //   INTEGER (r)
    //   INTEGER (s)
    let signature =
        vec![0x30, 0x46,
                   0x02, 0x21, 0x00, 0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40,
                               0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56,
                               0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
                   0x02, 0x21, 0x00, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36,
                               0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9,
                               0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd,
                               0xa8];
    let mut hasher = sha2::Sha256::default();
    hasher.input(b"sample");
    let digest = hasher.result();
    let signed_digest = verify::SignedDigest::new(&digest.as_slice(),
                                                  verify::DigestAlgorithm::SHA256, &signature);
    assert!(verify::verify_signed_digest(signed_digest, NIST_P256_TEST_SPKI,
                                         verify::KeyType::EC).is_ok());
}

#[test]
fn test_rfc6979_test_vector_2() {
    setup();
    // With SHA-256, message = "test":
    // k = D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
    // r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
    // s = 019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
    // SEQUENCE
    //   INTEGER (r)
    //   INTEGER (s)
    let signature =
        vec![0x30, 0x45,
                   0x02, 0x21, 0x00, 0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8,
                               0x81, 0x56, 0x7b, 0x1e, 0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5,
                               0x13, 0x2b, 0x35, 0x4f, 0x28, 0xd3, 0xb0, 0xb7, 0xd3, 0x83, 0x67,
                   0x02, 0x20, 0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a, 0x2b, 0x14, 0xbd, 0x25, 0x92,
                               0x6b, 0x49, 0xc6, 0x49, 0x15, 0x5f, 0x26, 0x7e, 0x60, 0xd3, 0x81,
                               0x4b, 0x4c, 0x0c, 0xc8, 0x42, 0x50, 0xe4, 0x6f, 0x00, 0x83];
    let mut hasher = sha2::Sha256::default();
    hasher.input(b"test");
    let digest = hasher.result();
    let signed_digest = verify::SignedDigest::new(&digest.as_slice(),
                                                  verify::DigestAlgorithm::SHA256, &signature);
    assert!(verify::verify_signed_digest(signed_digest, NIST_P256_TEST_SPKI,
                                         verify::KeyType::EC).is_ok());
}

#[test]
fn test_tampered_signature() {
    setup();
    // Based on test_rfc6979_test_vector_2.
    // With SHA-256, message = "test":
    // k = D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
    // r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
    // s = 019F4113742A2B14BD25926B49C649156F267E60D3814B4C0CC84250E46F0083
    //                                     ^ this was a 5
    // SEQUENCE
    //   INTEGER (r)
    //   INTEGER (s)
    let signature =
        vec![0x30, 0x45,
                   0x02, 0x21, 0x00, 0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8,
                               0x81, 0x56, 0x7b, 0x1e, 0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5,
                               0x13, 0x2b, 0x35, 0x4f, 0x28, 0xd3, 0xb0, 0xb7, 0xd3, 0x83, 0x67,
                   0x02, 0x20, 0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a, 0x2b, 0x14, 0xbd, 0x25, 0x92,
                               0x6b, 0x49, 0xc6, 0x49, 0x15, 0x6f, 0x26, 0x7e, 0x60, 0xd3, 0x81,
                               0x4b, 0x4c, 0x0c, 0xc8, 0x42, 0x50, 0xe4, 0x6f, 0x00, 0x83];
    let mut hasher = sha2::Sha256::default();
    hasher.input(b"test");
    let digest = hasher.result();
    let signed_digest = verify::SignedDigest::new(&digest.as_slice(),
                                                  verify::DigestAlgorithm::SHA256, &signature);
    assert!(verify::verify_signed_digest(signed_digest, NIST_P256_TEST_SPKI,
                                         verify::KeyType::EC).is_err()); // TODO: match specific error
}

#[test]
fn test_tampered_message() {
    setup();
    // Based on test_rfc6979_test_vector_2.
    // With SHA-256, message = "test":
    // k = D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
    // r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
    // s = 019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
    // SEQUENCE
    //   INTEGER (r)
    //   INTEGER (s)
    let signature =
        vec![0x30, 0x45,
                   0x02, 0x21, 0x00, 0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8,
                               0x81, 0x56, 0x7b, 0x1e, 0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5,
                               0x13, 0x2b, 0x35, 0x4f, 0x28, 0xd3, 0xb0, 0xb7, 0xd3, 0x83, 0x67,
                   0x02, 0x20, 0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a, 0x2b, 0x14, 0xbd, 0x25, 0x92,
                               0x6b, 0x49, 0xc6, 0x49, 0x15, 0x5f, 0x26, 0x7e, 0x60, 0xd3, 0x81,
                               0x4b, 0x4c, 0x0c, 0xc8, 0x42, 0x50, 0xe4, 0x6f, 0x00, 0x83];
    let mut hasher = sha2::Sha256::default();
    hasher.input(b"testTAMPERED");
    let digest = hasher.result();
    let signed_digest = verify::SignedDigest::new(&digest.as_slice(),
                                                  verify::DigestAlgorithm::SHA256, &signature);
    assert!(verify::verify_signed_digest(signed_digest, NIST_P256_TEST_SPKI,
                                         verify::KeyType::EC).is_err()); // TODO: match specific error
}
