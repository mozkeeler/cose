use std::os::raw;
use std::ptr;

/// An enum identifying supported signature algorithms. Currently only ECDSA with SHA256 (ES256) and
/// RSASSA-PSS with SHA-256 (PS256) are supported.
pub enum SignatureAlgorithm {
    ES256,
    PS256,
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
    fn VFY_VerifyDataDirect(buf: *const u8,
                            len: raw::c_int,
                            key: *const SECKEYPublicKey,
                            sig: *const SECItem,
                            pubkAlg: SECOidTag,
                            hashAlg: SECOidTag,
                            hash: *const SECOidTag,
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
/// Main entrypoint for verification. Given a signature algorithm, the bytes of a subject public key
/// info, a payload, and a signature over the payload, returns a result based on the outcome of
/// decoding the subject public key info and running the signature verification algorithm on the
/// signed data.
pub fn verify_signature(signature_algorithm: SignatureAlgorithm, spki: &[u8], payload: &[u8],
                        signature: &[u8]) -> Result<(), VerifyError> {
    if payload.len() > raw::c_int::max_value() as usize {
        return Err(VerifyError::InputTooLarge);
    }
    let len: raw::c_int = payload.len() as raw::c_int;
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
    let signature_item = SECItem::maybe_new(signature)?;
    let pubk_alg = match signature_algorithm {
        SignatureAlgorithm::ES256 => SEC_OID_ANSIX962_EC_PUBLIC_KEY,
        SignatureAlgorithm::PS256 => SEC_OID_PKCS1_RSA_ENCRYPTION,
    };
    let hash_alg = SEC_OID_SHA256;
    let null_hash_ptr: *const SECOidTag = ptr::null();
    let null_cx_ptr: *const raw::c_void = ptr::null();
    let result = unsafe {
        VFY_VerifyDataDirect(payload.as_ptr(), len, pubkey, &signature_item, pubk_alg, hash_alg,
                             null_hash_ptr, null_cx_ptr)
    };
    match result {
        SEC_SUCCESS => Ok(()),
        SEC_FAILURE => Err(VerifyError::SignatureVerificationFailed),
        _ => Err(VerifyError::LibraryFailure),
    }
}
