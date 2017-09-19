use std::os::raw;
use std::ptr;

/// A structure representing a signed digest (a digest is also known as a hash). Consists of the
/// bytes of the digest, the digest algorithm, and the bytes of the signature over the digest using
/// the given algorithm.
pub struct SignedDigest<'a> {
    /// A reference to a slice consisting of the bytes of the digest.
    digest: &'a [u8],
    /// The algorithm purportedly used to create the signature over the digest.
    digest_algorithm: DigestAlgorithm,
    /// A reference to a slice consisting of the bytes of the signature over the digest.
    signature: &'a [u8],
}

/// An enum identifying supported digest algorithms. Currently only SHA-256 is supported.
pub enum DigestAlgorithm {
    SHA256,
}

/// An enum identifying supported key types. Currently on EC (elliptic-curve) and RSA keys are
/// supported.
pub enum KeyType {
    EC,
    RSA,
}

type SECItemType = raw::c_uint; // TODO: actually an enum - is this the right size?
const SI_BUFFER: SECItemType = 0; // called siBuffer in NSS

#[repr(C)]
struct SECItem {
    typ: SECItemType,
    data: *const u8, // ugh it's not really const...
    len: raw::c_uint,
}

impl SECItem {
    fn maybe_new(data: &[u8]) -> Result<SECItem, VerifyError> {
        if data.len() > u32::max_value() as usize {
            return Err(VerifyError::InputTooLarge);
        }
        Ok(SECItem { typ: SI_BUFFER, data: data.as_ptr(), len: data.len() as u32 })
    }
}

// TODO: link to NSS source where these are defined
type SECOidTag = raw::c_uint; // TODO: actually an enum - is this the right size?
const SEC_OID_PKCS1_RSA_ENCRYPTION: SECOidTag = 16;
const SEC_OID_SHA256: SECOidTag = 191;
const SEC_OID_ANSIX962_EC_PUBLIC_KEY: SECOidTag = 200;

type SECStatus = raw::c_int; // TODO: enum - right size?
const SEC_SUCCESS: SECStatus = 0; // Called SECSuccess in NSS
const SEC_FAILURE: SECStatus = -1; // Called SECFailure in NSS

enum CERTSubjectPublicKeyInfo {}

enum SECKEYPublicKey {}

// TODO: ugh this will probably have a platform-specific name...
#[link(name="nss3")]
extern "C" {
    fn VFY_VerifyDigestDirect(digest: *const SECItem,
                              key: *const SECKEYPublicKey,
                              sig: *const SECItem,
                              encAlg: SECOidTag,
                              hashAlg: SECOidTag,
                              wincx: *const raw::c_void) -> SECStatus;

    fn SECKEY_DecodeDERSubjectPublicKeyInfo(spkider: *const SECItem)
       -> *const CERTSubjectPublicKeyInfo;
    fn SECKEY_DestroySubjectPublicKeyInfo(spki: *const CERTSubjectPublicKeyInfo);

    fn SECKEY_ExtractPublicKey(spki: *const CERTSubjectPublicKeyInfo) -> *const SECKEYPublicKey;
    fn SECKEY_DestroyPublicKey(pubk: *const SECKEYPublicKey);
}

/// An error type describing errors that may be encountered during verification.
pub enum VerifyError {
    DecodingSPKIFailed,
    InputTooLarge,
    LibraryFailure,
    SignatureVerificationFailed,
}

// TODO: verify keys (e.g. RSA size, EC curve)...
/// Main entrypoint for verification. Given a signed digest, the bytes of a subject public key info,
/// and a key type, returns a result based on the outcome of decoding the subject public key info
/// and running the signature verification algorithm on the signed digest.
pub fn verify_signed_digest(sd: SignedDigest, spki: &[u8], kt: KeyType) -> Result<(), VerifyError> {
    let spki_item = SECItem::maybe_new(spki)?;
    // TODO: helper/macro for pattern of "call unsafe function, check null, defer unsafe release"?
    let spki_handle = unsafe {
        SECKEY_DecodeDERSubjectPublicKeyInfo(&spki_item)
    };
    if spki_handle.is_null() {
        return Err(VerifyError::DecodingSPKIFailed);
    }
    defer!(unsafe { SECKEY_DestroySubjectPublicKeyInfo(spki_handle); });
    let pubkey = unsafe {
        SECKEY_ExtractPublicKey(spki_handle)
    };
    if pubkey.is_null() {
        return Err(VerifyError::LibraryFailure); // TODO: double-check that this can only fail if the library fails
    }
    defer!(unsafe { SECKEY_DestroyPublicKey(pubkey); });
    let digest_item = SECItem::maybe_new(sd.digest)?;
    let signature_item = SECItem::maybe_new(sd.signature)?;
    let enc_alg = match kt {
        KeyType::EC => SEC_OID_ANSIX962_EC_PUBLIC_KEY,
        KeyType::RSA => SEC_OID_PKCS1_RSA_ENCRYPTION,
    };
    let hash_alg = match sd.digest_algorithm {
        DigestAlgorithm::SHA256 => SEC_OID_SHA256,
    };
    let null_ptr: *const raw::c_void = ptr::null();
    let result = unsafe {
        VFY_VerifyDigestDirect(&digest_item, pubkey, &signature_item, enc_alg, hash_alg, null_ptr)
    };
    match result {
        SEC_SUCCESS => Ok(()),
        SEC_FAILURE => Err(VerifyError::SignatureVerificationFailed),
        _ => Err(VerifyError::LibraryFailure),
    }
}

impl<'a> SignedDigest<'a> {
    pub fn new(digest: &'a [u8], digest_algorithm: DigestAlgorithm,
               signature: &'a [u8]) -> SignedDigest<'a> {
        SignedDigest {
            digest: digest, digest_algorithm: digest_algorithm, signature: signature
        }
    }
}
