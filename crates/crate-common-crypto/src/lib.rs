//! Crptographice functions for agent and trustees.
//! Many of these wrap the hushmesh_crypto functions which use wolfssl.

#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::mem;

use fluent_uri::UriRef;
use log::debug;
use log::error;
use log::info;
use serde::Deserialize;
use serde::Serialize;

use common_sync::Mutex;
use common_types::from_c::generic_vec2_from_c;
use common_types::from_c::generic_vec_from_c;
use common_types::from_c::CBuf;
use common_types::from_c::CByteSlice;
use common_types::log_error;
use common_types::validation::validate_domain;
use common_types::validation::validate_email;
use common_types::validation::validate_phone;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshLinkKey;
use common_types::MeshSessionId;

pub mod bbs_crypto;
pub mod rng;

const AES_LEN: usize = 32;
const MR_ENCLAVE_LEN: usize = 32;
const KEY_BUF_LEN: usize = 192;
const RSA_KEY_BUF_LEN: usize = 4192;
const KEY_PUBLIC_PRIVATE_BUF_LEN: usize = 4192;
const CIPHER_TEXT_BUF_LEN: usize = 4192;
const SIG_BUF_LEN: usize = 4096;

/// Overhead of the nonce and verification check added to blobs encrypted with [`mesh_encrypt`] in
/// Raw mode..
pub const AES_GCM_OVERHEAD: usize = 28;

static INIT_LOCK: Mutex<u32> = Mutex::new(0);

#[repr(C)]
#[derive(PartialEq, Eq)]
#[allow(dead_code)]
enum HmcStatus {
    Ok = 0,
    Error = 1,
    BufferTooSmall = 2,
    InvalidKeySize = 3,
    CertVerifyFailed = 4,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcDataType {
    Raw = 0,
    Base64 = 1,
    Base64Urlsafe = 2,
    Base64UrlsafeNoPadding = 3,
    Pem = 4,
    Der = 5,
    Hex = 6,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcCredType {
    None = 0,
    PrivateKey = 1,
    PublicKey = 2,
    Cert = 3,
    Pkcs8 = 4,
    RsaPrivateKey = 5,
    RsaPublicKey = 6,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcCertType {
    // Internal certificates.
    // Private keys for the end-entity, intermediate, and root certificates
    // are all stored inside enclaves.
    Internal = 0,
    // External certificates.
    // Private key for the end-entity certificate is stored inside enclaves.
    // Private keys for intermediate and root certificates are stored outside enclaves
    // (on the web).
    External = 1,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub enum HmcLogLevel {
    Error = 0,
    Info = 1,
    Debug = 2,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcKeyType {
    None = 0,
    Ecc256 = 1,
    Ecc384 = 2,
    Ecc521 = 3,
    Kyber512 = 4,
    Kyber768 = 5,
    Kyber1024 = 6,
    Rsa = 7,
    Rsa3072e3 = 8,
    Bls12381G2 = 9,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcSigType {
    None = 0,
    CtcSha256wEcdsa = 1,
    CtcSha384wEcdsa = 2,
    CtcSha512wEcdsa = 3,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum HmcSigFormat {
    Unknown = 0,
    Fixed = 1,
    Asn1Der = 2,
}

#[repr(C)]
#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub enum HmcHashType {
    None = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha256Sha256 = 3,
    Sha1 = 4, // only for websocket connection handshake
}

extern "C" {
    fn hmc_init(
        log_function: unsafe extern "C" fn(level: HmcLogLevel, data: *const i8),
    ) -> HmcStatus;

    fn hmc_generate_random(
        len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_ecc_key_to_pkcs8(
        key_data_type: HmcDataType,
        private_key: *const u8,
        private_key_len: usize,
        output_data_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_import_ecc_key_x_y_d(
        key_type: HmcKeyType,
        x: *const u8,
        x_len: usize,
        y: *const u8,
        y_len: usize,
        d: *const u8,
        d_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_export_ecc_key_x_y(
        key_data_type: HmcDataType,
        public_key: *const u8,
        public_key_len: usize,
        x: *mut u8,
        x_max_len: usize,
        x_len: &mut usize,
        y: *mut u8,
        y_max_len: usize,
        y_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_export_rsa_key_e_n(
        key_data_type: HmcDataType,
        public_key: *const u8,
        public_key_len: usize,
        e: *mut u8,
        e_max_len: usize,
        e_len: &mut usize,
        n: *mut u8,
        n_max_len: usize,
        n_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_encrypt(
        key_data_type: HmcDataType,
        key: *const u8,
        key_len: usize,
        input: *const u8,
        input_len: usize,
        aad: *const u8,
        aad_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_decrypt(
        key_data_type: HmcDataType,
        key: *const u8,
        key_len: usize,
        input_type: HmcDataType,
        input: *const u8,
        input_len: usize,
        aad: *const u8,
        aad_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_encrypt_ecc(
        key_data_type: HmcDataType,
        priv_key: *const u8,
        priv_key_len: usize,
        pub_key: *const u8,
        pub_key_len: usize,
        input: *const u8,
        input_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_decrypt_ecc(
        key_data_type: HmcDataType,
        priv_key: *const u8,
        priv_key_len: usize,
        input_type: HmcDataType,
        input: *const u8,
        input_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_concat_kdf(
        shared_secret: *const u8,
        shared_secret_len: usize,
        enc: *const u8,
        enc_len: usize,
        party_u: *const u8,
        party_u_len: usize,
        party_v: *const u8,
        party_v_len: usize,
        enc_key_numbits: usize,
        output: *mut u8,
        output_len: usize,
    ) -> HmcStatus;

    fn hmc_derive_key(
        key_data_type: HmcDataType,
        key: *const u8,
        key_len: usize,
        input_type: HmcDataType,
        input: *const u8,
        input_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_hmac_sign(
        key_data_type: HmcDataType,
        key: *const u8,
        key_len: usize,
        input_type: HmcDataType,
        input: *const u8,
        input_len: usize,
        hash_type: HmcHashType,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_sha256_hmac_writer(
        key_data_type: HmcDataType,
        key: *const u8,
        key_len: usize,
        output: &mut *mut core::ffi::c_void,
    ) -> HmcStatus;

    fn hmc_update_hmac(
        hmac: *mut core::ffi::c_void,
        input: *const u8,
        input_len: usize,
    ) -> HmcStatus;

    fn hmc_finalize_sha256_hmac(hmac: *mut core::ffi::c_void, output: *mut [u8; 32]) -> HmcStatus;

    fn hmc_free_hmac_writer(hmac: *mut core::ffi::c_void) -> HmcStatus;

    fn hmc_generate_key_pair(
        key_type: HmcKeyType,
        output_type: HmcDataType,
        private_key_output: *mut u8,
        private_key_output_max_len: usize,
        private_key_output_len: &mut usize,
        public_key_output: *mut u8,
        public_key_output_max_len: usize,
        public_key_output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_create_shared_ecc_secret(
        key_type: HmcKeyType,
        key_data_type: HmcDataType,
        private_key: *const u8,
        private_key_len: usize,
        target_public_key: *const u8,
        target_public_ket_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_create_shared_ecc_kyber_hybrid_secret(
        key_type: HmcKeyType,
        key_data_type: HmcDataType,
        private_key: *const u8,
        private_key_len: usize,
        target_public_key: *const u8,
        target_public_ket_len: usize,
        kyber_shared_secret_input_type: HmcDataType,
        kyber_shared_secret: *const u8,
        kyber_shared_secret_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_create_shared_kyber_secret(
        key_type: HmcKeyType,
        key_data_type: HmcDataType,
        public_key: *const u8,
        public_key_len: usize,
        output_type: HmcDataType,
        output_secret: *mut u8,
        output_secret_max_len: usize,
        output_secret_len: &mut usize,
        output_encrypted_secret: *mut u8,
        output_encrypted_secret_max_len: usize,
        output_encrypted_secret_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_decrypt_shared_kyber_secret(
        key_type: HmcKeyType,
        key_data_type: HmcDataType,
        private_key: *const u8,
        private_key_len: usize,
        encrypted_secret_data_type: HmcDataType,
        encrypted_secret: *const u8,
        encrypted_secret_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_convert(
        input_type: HmcDataType,
        input_cred_type: HmcCredType,
        input: *const u8,
        input_len: usize,
        hash_type: HmcHashType,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_create_signature(
        key_type: HmcKeyType,
        cred_type: HmcCredType,
        key_data_type: HmcDataType,
        private_key: *const u8,
        private_key_len: usize,
        input: *const u8,
        input_len: usize,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn hmc_verify_signature(
        key_type: HmcKeyType,
        key_data_type: HmcDataType,
        public_key: *const u8,
        public_key_len: usize,
        input: *const u8,
        input_len: usize,
        signature_format: HmcSigFormat,
        signature_data_type: HmcDataType,
        signature: *const u8,
        signature_len: usize,
        verified: &mut bool,
    ) -> HmcStatus;

    fn hmc_extract_public_key(
        cert: *const u8,
        cert_len: usize,
        cert_data_type: HmcDataType,
        output_type: HmcDataType,
        output: *mut u8,
        output_max_len: usize,
        output_len: &mut usize,
    ) -> HmcStatus;

    fn sgx_enclave_sign(
        input_enclave: *const u8,
        input_enclave_len: usize,
        private_key_der: *const u8,
        private_key_len: usize,
        parameters: *const u64,
        parameters_len: usize,
        flags: *const u32,
        flags_len: usize,
        output_enclave: *mut u8,
        output_enclave_len: usize,
        output_enclave_hash: *mut u8,
        output_enclave_hash_len: usize,
        unix_timestamp: i64,
    ) -> i32;

    fn hmc_sha256_writer(output: &mut *mut core::ffi::c_void) -> HmcStatus;

    fn hmc_sha256_update(
        hasher: *mut core::ffi::c_void,
        input: *const u8,
        input_len: usize,
    ) -> HmcStatus;

    fn hmc_sha256_gethash(hasher: *mut core::ffi::c_void, output: *mut [u8; 32]) -> HmcStatus;

    fn hmc_free(hmac: *mut core::ffi::c_void) -> HmcStatus;
}

impl From<HmcStatus> for String {
    fn from(value: HmcStatus) -> String {
        match value {
            HmcStatus::Ok => "Ok",
            HmcStatus::Error => "Error",
            HmcStatus::BufferTooSmall => "Buffer too small",
            HmcStatus::InvalidKeySize => "Invalid key size",
            HmcStatus::CertVerifyFailed => "Cert verify failed",
        }
        .into()
    }
}

/// Function acts as a hook from C to call Rust logging methods.
///
/// # Safety
///
/// data must point to a valid C string.
#[no_mangle]
pub unsafe extern "C" fn mesh_crypto_log(level: HmcLogLevel, data: *const i8) {
    let data_str = unsafe { CStr::from_ptr(data) };
    let data_str = data_str.to_str().unwrap();

    // The log::* macros won't work without a logger initializing itself. We may eventually want to
    // make that work for tests using something like the ctor crate. But, in the meantime, this
    // simply forces hushmesh_crypto to log to stderr, which can be seen if you run a test like,
    //     $ cargo test -- --nocapture
    #[cfg(all(test, not(feature = "enclave")))]
    {
        match level {
            HmcLogLevel::Error => eprintln!("ERROR [crypto] {}", data_str),
            HmcLogLevel::Info => eprintln!("INFO [crypto] {}", data_str),
            HmcLogLevel::Debug => eprintln!("DEBUG [crypto] {}", data_str),
        };
    }

    match level {
        HmcLogLevel::Error => error!("[crypto] {}", data_str),
        HmcLogLevel::Info => info!("[crypto] {}", data_str),
        HmcLogLevel::Debug => debug!("[crypto] {}", data_str),
    }
}

pub fn mesh_crypto_init() -> Result<(), MeshError> {
    let _guard = INIT_LOCK.lock().unwrap();
    match unsafe { hmc_init(mesh_crypto_log) } {
        HmcStatus::Ok => Ok(()),
        err => Err(MeshError::EncryptionError(err.into())),
    }
}

pub fn mesh_generate_aes256_key(output_type: HmcDataType) -> Result<Vec<u8>, MeshError> {
    mesh_generate_id(AES_LEN, output_type)
}

pub fn mesh_generate_mesh_id() -> Result<MeshId, MeshError> {
    mesh_generate_id(32, HmcDataType::Raw).and_then(TryInto::try_into)
}
pub fn mesh_generate_session_id() -> Result<MeshSessionId, MeshError> {
    mesh_generate_mesh_id()
}

pub fn mesh_generate_link_key() -> Result<MeshLinkKey, MeshError> {
    mesh_generate_mesh_id()
}

pub fn mesh_generate_encryption_key() -> Result<MeshLinkKey, MeshError> {
    mesh_generate_mesh_id()
}

pub fn mesh_generate_otp(num_characters: usize) -> Result<String, MeshError> {
    let raw_id = mesh_generate_id(num_characters * 4, HmcDataType::Raw)?;
    let chunks = raw_id.chunks_exact(4);

    debug_assert!(chunks.len() == num_characters && chunks.remainder().is_empty());

    // To minimize bias, a full u32 per digit is created to be coerced into a number 0..=9.
    // (u32::MAX%10 == 5, thus '6'-'9' are negligibly less likely to appear)
    let v: Vec<u8> = chunks
        .map(|c| c.try_into().unwrap())
        .map(|b| (u32::from_ne_bytes(b) % 10) as u8 + b'0')
        .collect();

    // Safety: this Vec contains exclusively ASCII digits b'0'..=b'9'.
    Ok(unsafe { String::from_utf8_unchecked(v) })
}

pub fn mesh_generate_meshfa_code(num_characters: usize) -> Result<String, MeshError> {
    mesh_generate_otp(num_characters)
}

pub fn mesh_generate_id(id_len: usize, output_type: HmcDataType) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_generate_random(id_len, output_type, cbuf.ptr, cbuf.cap, cbuf.out_len)
        })
    }
}

pub fn mesh_generate_random_u64(limit: u64) -> Result<u64, MeshError> {
    loop {
        let source = mesh_generate_id(8, HmcDataType::Raw)?;
        let source = u64::from_be_bytes(
            source
                .as_slice()
                .try_into()
                .map_err(|_| MeshError::EncryptionError("invalid source".to_string()))?,
        );
        if source < (u64::MAX - (u64::MAX % limit)) {
            return Ok(source % limit);
        }
    }
}

pub fn mesh_encrypt(
    key_data_type: HmcDataType,
    key: &[u8],
    input_data: &[u8],
    aad: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    // The output buffer needs up to 64 bytes of padding. Raw output implies byte-for-byte parity,
    // otherwise more space would be needed for Base64 output.
    let max_len = match output_type {
        HmcDataType::Raw => 64 + input_data.len(),
        _ => 64 + input_data.len() * 4,
    };

    unsafe {
        vec_from_c(max_len, |cbuf| {
            hmc_encrypt(
                key_data_type,
                key.as_ptr(),
                key.len(),
                input_data.as_ptr(),
                input_data.len(),
                aad.c_maybe_ptr(),
                aad.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_decrypt(
    key_data_type: HmcDataType,
    key: &[u8],
    input_type: HmcDataType,
    input_data: &[u8],
    aad: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    // The output buffer needs up to 64 bytes of padding. Raw output implies byte-for-byte parity,
    // otherwise more space would be needed for Base64 output.
    let max_len = match output_type {
        HmcDataType::Raw => 64 + input_data.len(),
        _ => 64 + input_data.len() * 4,
    };

    unsafe {
        vec_from_c(max_len, |cbuf| {
            hmc_decrypt(
                key_data_type,
                key.as_ptr(),
                key.len(),
                input_type,
                input_data.as_ptr(),
                input_data.len(),
                aad.c_maybe_ptr(),
                aad.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_encrypt_ecc(
    key_data_type: HmcDataType,
    priv_key: &[u8],
    pub_key: &[u8],
    input_data: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(input_data.len() + 1024, |cbuf| {
            hmc_encrypt_ecc(
                key_data_type,
                priv_key.as_ptr(),
                priv_key.len(),
                pub_key.as_ptr(),
                pub_key.len(),
                input_data.as_ptr(),
                input_data.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_ecc_key_to_pkcs8(
    key_data_type: HmcDataType,
    private_key: &[u8],
    output_data_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(4096, |cbuf| {
            hmc_ecc_key_to_pkcs8(
                key_data_type,
                private_key.as_ptr(),
                private_key.len(),
                output_data_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_import_ecc_key_x_y_d(
    key_type: HmcKeyType,
    output_type: HmcDataType,
    x: &[u8],
    y: &[u8],
    d: &[u8],
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(1024, |cbuf| {
            hmc_import_ecc_key_x_y_d(
                key_type,
                x.as_ptr(),
                x.len(),
                y.as_ptr(),
                y.len(),
                d.c_maybe_ptr(),
                d.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_export_ecc_key_x_y(
    key_data_type: HmcDataType,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    unsafe {
        vec2_from_c(1024, 1024, |x, y| {
            hmc_export_ecc_key_x_y(
                key_data_type,
                public_key.as_ptr(),
                public_key.len(),
                x.ptr,
                x.cap,
                x.out_len,
                y.ptr,
                y.cap,
                y.out_len,
            )
        })
    }
}

pub fn mesh_export_rsa_key_e_n(
    key_data_type: HmcDataType,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    unsafe {
        vec2_from_c(1024, 1024, |e, n| {
            hmc_export_rsa_key_e_n(
                key_data_type,
                public_key.as_ptr(),
                public_key.len(),
                e.ptr,
                e.cap,
                e.out_len,
                n.ptr,
                n.cap,
                n.out_len,
            )
        })
    }
}

pub fn mesh_decrypt_ecc(
    key_data_type: HmcDataType,
    priv_key: &[u8],
    input_type: HmcDataType,
    input_data: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(input_data.len() + 1024, |cbuf| {
            hmc_decrypt_ecc(
                key_data_type,
                priv_key.as_ptr(),
                priv_key.len(),
                input_type,
                input_data.as_ptr(),
                input_data.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_concat_kdf(
    shared_secret: &[u8],
    enc: &[u8],
    party_u: &[u8],
    party_v: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let output_len = match enc {
        b"A128GCM" => 16,
        b"A256GCM" => 32,
        _ => {
            return Err(MeshError::EncryptionError(format!(
                "Invalid encryption type, {enc:?}",
            )))
        }
    };

    unsafe {
        vec_from_c(32, |cbuf| {
            // hmc_concat_kdf always produces a 32-byte SHA256 sum, but we'll take the first 16
            // bytes for a 128-bit key.
            *cbuf.out_len = output_len;
            hmc_concat_kdf(
                shared_secret.as_ptr(),
                shared_secret.len(),
                enc.as_ptr(),
                enc.len(),
                party_u.as_ptr(),
                party_u.len(),
                party_v.as_ptr(),
                party_v.len(),
                output_len * 8, // in bits
                cbuf.ptr,
                cbuf.cap,
            )
        })
    }
}

pub fn mesh_derive_key_from_vec<I, T>(input_key: MeshId, input_data: I) -> Result<MeshId, MeshError>
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item = T>,
{
    input_data.into_iter().try_fold(input_key, |key, part| {
        mesh_derive_key(
            HmcDataType::Raw,
            &key.id,
            HmcDataType::Raw,
            part.as_ref(),
            HmcDataType::Raw,
        )
        .and_then(|v| MeshId::from_bytes(&v))
    })
}

pub fn mesh_derive_key_from_vec_all(
    input_data: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Result<MeshId, MeshError> {
    let mut iter = input_data.into_iter().fuse();
    let maybe_input_key = iter.next();
    let mut rest = iter.peekable();
    match (maybe_input_key, rest.peek()) {
        (Some(input_key), Some(_)) => {
            mesh_derive_key_from_vec(input_key.as_ref().try_into()?, rest)
        }
        _ => Err(MeshError::EncryptionError("Invalid input data".to_string())),
    }
}

pub fn mesh_derive_key_from_ids_all(input_data: &[MeshId]) -> Result<MeshId, MeshError> {
    if input_data.len() < 2 {
        return Err(MeshError::EncryptionError("Invalid input data".to_string()));
    }
    let key = input_data
        .iter()
        .skip(1)
        .try_fold(input_data[0], |key, id| {
            mesh_derive_key(
                HmcDataType::Raw,
                &key.id,
                HmcDataType::Raw,
                &id.id,
                HmcDataType::Raw,
            )?
            .try_into()
        });
    key
}

pub fn mesh_derive_key(
    key_data_type: HmcDataType,
    key: &[u8],
    input_type: HmcDataType,
    input_data: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_derive_key(
                key_data_type,
                key.as_ptr(),
                key.len(),
                input_type,
                input_data.as_ptr(),
                input_data.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_hmac_sign(
    key_data_type: HmcDataType,
    key: &[u8],
    input_type: HmcDataType,
    input_data: &[u8],
    hash_type: HmcHashType,
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_hmac_sign(
                key_data_type,
                key.as_ptr(),
                key.len(),
                input_type,
                input_data.as_ptr(),
                input_data.len(),
                hash_type,
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_generate_key_pair(
    key_type: HmcKeyType,
    output_type: HmcDataType,
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    unsafe {
        vec2_from_c(
            KEY_PUBLIC_PRIVATE_BUF_LEN,
            KEY_PUBLIC_PRIVATE_BUF_LEN,
            |private, public| {
                hmc_generate_key_pair(
                    key_type,
                    output_type,
                    private.ptr,
                    private.cap,
                    private.out_len,
                    public.ptr,
                    public.cap,
                    public.out_len,
                )
            },
        )
    }
}

pub fn mesh_create_shared_ecc_secret(
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
    private_key: &[u8],
    target_public_key: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_create_shared_ecc_secret(
                key_type,
                key_data_type,
                private_key.as_ptr(),
                private_key.len(),
                target_public_key.as_ptr(),
                target_public_key.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_create_shared_ecc_kyber_hybrid_secret(
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
    private_key: &[u8],
    target_public_key: &[u8],
    kyber_shared_secret_input_type: HmcDataType,
    kyber_shared_secret: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_create_shared_ecc_kyber_hybrid_secret(
                key_type,
                key_data_type,
                private_key.as_ptr(),
                private_key.len(),
                target_public_key.as_ptr(),
                target_public_key.len(),
                kyber_shared_secret_input_type,
                kyber_shared_secret.as_ptr(),
                kyber_shared_secret.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_create_shared_kyber_secret(
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
    public_key: &[u8],
    output_type: HmcDataType,
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    unsafe {
        vec2_from_c(KEY_BUF_LEN, CIPHER_TEXT_BUF_LEN, |secret, encrypted| {
            hmc_create_shared_kyber_secret(
                key_type,
                key_data_type,
                public_key.as_ptr(),
                public_key.len(),
                output_type,
                secret.ptr,
                secret.cap,
                secret.out_len,
                encrypted.ptr,
                encrypted.cap,
                encrypted.out_len,
            )
        })
    }
}

pub fn mesh_decrypt_shared_kyber_secret(
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
    private_key: &[u8],
    encrypted_secret_data_type: HmcDataType,
    encrypted_secret: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(KEY_BUF_LEN, |cbuf| {
            hmc_decrypt_shared_kyber_secret(
                key_type,
                key_data_type,
                private_key.as_ptr(),
                private_key.len(),
                encrypted_secret_data_type,
                encrypted_secret.as_ptr(),
                encrypted_secret.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_verify_public_key(input: &[u8]) -> bool {
    mesh_convert_encoding(
        HmcDataType::Pem,
        HmcCredType::PublicKey,
        input,
        HmcHashType::None,
        HmcDataType::Der,
    )
    .is_ok()
}

pub fn mesh_base64_encode(input: &[u8], base64_type: HmcDataType) -> Result<String, MeshError> {
    let data = mesh_convert_encoding(
        HmcDataType::Raw,
        HmcCredType::None,
        input,
        HmcHashType::None,
        base64_type,
    )?;
    String::from_utf8(data).map_err(|e| MeshError::ParseError(format!("{}", e)))
}

pub fn mesh_sha256<D>(data: D) -> Result<Vec<u8>, MeshError>
where
    D: AsRef<[u8]>,
{
    mesh_convert_encoding(
        HmcDataType::Raw,
        HmcCredType::None,
        data.as_ref(),
        HmcHashType::Sha256,
        HmcDataType::Raw,
    )
}

pub fn mesh_sha384<D>(data: D) -> Result<Vec<u8>, MeshError>
where
    D: AsRef<[u8]>,
{
    mesh_convert_encoding(
        HmcDataType::Raw,
        HmcCredType::None,
        data.as_ref(),
        HmcHashType::Sha384,
        HmcDataType::Raw,
    )
}

pub fn mesh_der_to_pem(data: &[u8], input_cred_type: HmcCredType) -> Result<Vec<u8>, MeshError> {
    mesh_convert_encoding(
        HmcDataType::Der,
        input_cred_type,
        data,
        HmcHashType::None,
        HmcDataType::Pem,
    )
}

pub fn mesh_pem_to_der(data: &[u8], input_cred_type: HmcCredType) -> Result<Vec<u8>, MeshError> {
    mesh_convert_encoding(
        HmcDataType::Pem,
        input_cred_type,
        data,
        HmcHashType::None,
        HmcDataType::Der,
    )
}

pub fn mesh_base64_decode(input: &str, base64_type: HmcDataType) -> Result<Vec<u8>, MeshError> {
    mesh_convert_encoding(
        base64_type,
        HmcCredType::None,
        input.as_bytes(),
        HmcHashType::None,
        HmcDataType::Raw,
    )
}

pub fn mesh_id_to_string(id: MeshId) -> Result<String, MeshError> {
    mesh_bytes_to_string(&id.id)
}

pub fn mesh_bytes_to_string(input: &[u8]) -> Result<String, MeshError> {
    let data = mesh_convert_encoding(
        HmcDataType::Raw,
        HmcCredType::None,
        input,
        HmcHashType::None,
        HmcDataType::Base64UrlsafeNoPadding,
    )?;
    String::from_utf8(data).map_err(|e| MeshError::ParseError(format!("{}", e)))
}

pub fn mesh_hash_to_id(data: &[u8]) -> Result<MeshId, MeshError> {
    let id = mesh_sha256(data)?
        .try_into()
        .expect("mesh_sha256 failed to produce 32 bytes");
    Ok(MeshId { id })
}

pub fn mesh_string_to_bytes(input: impl AsRef<str>) -> Result<Vec<u8>, MeshError> {
    mesh_convert_encoding(
        HmcDataType::Base64UrlsafeNoPadding,
        HmcCredType::None,
        input.as_ref().as_bytes(),
        HmcHashType::None,
        HmcDataType::Raw,
    )
}

pub fn mesh_convert_encoding(
    input_type: HmcDataType,
    input_cred_type: HmcCredType,
    input: &[u8],
    hash_type: HmcHashType,
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    let max_len = match hash_type {
        HmcHashType::None => match (input_type, output_type) {
            (HmcDataType::Raw, HmcDataType::Hex) => input.len() * 2,
            (HmcDataType::Hex, HmcDataType::Raw) => input.len() / 2,
            _ => input.len() * 4,
        },
        _ => 256,
    };
    unsafe {
        vec_from_c(max_len, |cbuf| {
            hmc_convert(
                input_type,
                input_cred_type,
                input.as_ptr(),
                input.len(),
                hash_type,
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_create_signature(
    key_type: HmcKeyType,
    cred_type: HmcCredType,
    key_data_type: HmcDataType,
    private_key: &[u8],
    input: &[u8],
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(SIG_BUF_LEN, |cbuf| {
            hmc_create_signature(
                key_type,
                cred_type,
                key_data_type,
                private_key.as_ptr(),
                private_key.len(),
                input.as_ptr(),
                input.len(),
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_extract_public_key(
    cert: &[u8],
    cert_data_type: HmcDataType,
    output_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    unsafe {
        vec_from_c(RSA_KEY_BUF_LEN, |cbuf| {
            hmc_extract_public_key(
                cert.as_ptr(),
                cert.len(),
                cert_data_type,
                output_type,
                cbuf.ptr,
                cbuf.cap,
                cbuf.out_len,
            )
        })
    }
}

pub fn mesh_verify_signature(
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
    public_key: &[u8],
    input: &[u8],
    signature_format: HmcSigFormat,
    signature_data_type: HmcDataType,
    signature: &[u8],
) -> Result<bool, MeshError> {
    let mut verified: bool = false;
    let status = unsafe {
        hmc_verify_signature(
            key_type,
            key_data_type,
            public_key.as_ptr(),
            public_key.len(),
            input.as_ptr(),
            input.len(),
            signature_format,
            signature_data_type,
            signature.as_ptr(),
            signature.len(),
            &mut verified,
        )
    };
    match status {
        HmcStatus::Ok => Ok(verified),
        _ => Err(MeshError::EncryptionError(status.into())),
    }
}

pub fn mesh_enclave_sign(
    input_enclave: &[u8],
    private_key_der: &[u8],
    parameters: &[u64],
    flags: &[u32],
    unix_timestamp: i64,
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    unsafe {
        vec2_from_c(
            input_enclave.len(),
            MR_ENCLAVE_LEN,
            |output_enclave, output_enclave_hash| {
                let ret = sgx_enclave_sign(
                    input_enclave.as_ptr(),
                    input_enclave.len(),
                    private_key_der.as_ptr(),
                    private_key_der.len(),
                    parameters.as_ptr(),
                    mem::size_of_val(parameters),
                    flags.as_ptr(),
                    mem::size_of_val(flags),
                    output_enclave.ptr,
                    output_enclave.cap,
                    output_enclave_hash.ptr,
                    output_enclave_hash.cap,
                    unix_timestamp,
                );
                match ret {
                    0 => {
                        *output_enclave.out_len = output_enclave.cap;
                        *output_enclave_hash.out_len = output_enclave_hash.cap;
                        HmcStatus::Ok
                    }
                    _ => {
                        error!("enclave sign failed with error code: {}", ret);
                        HmcStatus::Error
                    }
                }
            },
        )
    }
}

pub fn mesh_sgx_mr_signer(
    key_data_type: HmcDataType,
    public_key: &[u8],
) -> Result<Vec<u8>, MeshError> {
    // Take the SHA2-256 hash of the RSA public key modulus as stored in ASN.1 DER encoding
    // Encoded in big-endian representation but stored in memory in little-endian representation.
    let (_, mut modulus) = mesh_export_rsa_key_e_n(key_data_type, public_key)?;
    modulus.reverse();
    mesh_sha256(&modulus)
}

pub fn mesh_hash_email(email: &str) -> Result<MeshId, MeshError> {
    if !validate_email(email) {
        return Err(MeshError::BadArgument("Invalid email address".into()));
    }

    let email: Cow<_> = if email.as_bytes().iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(email.to_ascii_lowercase())
    } else {
        Cow::Borrowed(email)
    };

    let (target, domain) = email
        .split_once('@')
        .expect("validated email did not contain @");
    let id_path = domain.rsplit('.').chain(["@", target]);
    mesh_derive_key_from_vec(MeshId::from_static("email"), id_path)
}

pub fn mesh_hash_domain(domain: &str) -> Result<MeshId, MeshError> {
    if !validate_domain(domain) {
        return Err(MeshError::BadArgument("Invalid domain".into()));
    }
    let domain: Cow<_> = if domain.as_bytes().iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    };
    let id_path = domain.rsplit('.');
    mesh_derive_key_from_vec(MeshId::from_static("domain"), id_path)
}

pub fn mesh_hash_url(url: &str) -> Result<MeshId, MeshError> {
    let id_path = mesh_url_to_vec_path(url)?;
    mesh_derive_key_from_vec(MeshId::from_static("url"), id_path)
}

pub fn mesh_url_to_vec_path(url: &str) -> Result<Vec<Vec<u8>>, MeshError> {
    let url_parsed =
        UriRef::parse(url).map_err(|e| MeshError::InvalidAddress(format!("{}: {}", url, e)))?;

    let scheme = url_parsed
        .scheme()
        .ok_or_else(|| log_error!(MeshError::InvalidAddress(format!("{}", url))))?;
    let port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(MeshError::InvalidAddress("Unknown protocol".into())),
    };

    let mut id_path = vec![format!("{}://", scheme).into_bytes()];

    let auth = url_parsed
        .authority()
        .ok_or_else(|| log_error!(MeshError::InvalidAddress(format!("{}", url))))?;
    let host = auth.host();
    id_path.extend(
        host.to_lowercase()
            .rsplit('.')
            .map(|s| s.as_bytes().to_vec()),
    );
    id_path.push(format!(":{}", port).into_bytes());
    let path = url_parsed.path().as_str();
    if path.is_empty() {
        id_path.push("/".into());
    } else if !path.starts_with('/') {
        id_path.push(format!("/{}", path).into_bytes());
    } else {
        id_path.push(path.into());
    }
    if let Some(query) = url_parsed.query() {
        id_path.push(format!("?{}", query).into_bytes());
    }
    if let Some(fragment) = url_parsed.fragment() {
        id_path.push(format!("#{}", fragment).into_bytes());
    }
    Ok(id_path)
}

pub fn mesh_hash_phone(phone: &str) -> Result<MeshId, MeshError> {
    if !validate_phone(phone) {
        return Err(MeshError::BadArgument("Invalid phone number".into()));
    }
    let digits = phone
        .strip_prefix('+')
        .expect("validated phone number did not start with +")
        .as_bytes()
        .iter()
        .map(core::slice::from_ref);
    mesh_derive_key_from_vec(MeshId::from_static("phone"), digits)
}

impl From<HmcStatus> for Result<(), String> {
    fn from(status: HmcStatus) -> Self {
        match status {
            HmcStatus::Ok => Ok(()),
            err => Err(err.into()),
        }
    }
}

/// Local vec_from_c wrapper function. It returns MeshError::EncryptionErrors. Its closure type is
/// extra generic so that it can be used with sgx_enclave_sign in addition to all of the hmc_*
/// functions that return an HmcStatus.
///
/// Into<Result<(), String>> is implemented for HmcStatus to make most calls straightforward.
/// But, this function is made to be general over anything that can return such a result, like
/// sgx_enclave_sign.
unsafe fn vec_from_c<R, F>(buf_len: usize, filler: F) -> Result<Vec<u8>, MeshError>
where
    R: Into<Result<(), String>>,
    F: FnOnce(CBuf) -> R,
{
    generic_vec_from_c(buf_len, filler).map_err(MeshError::EncryptionError)
}

/// Local vec2_from_c wrapper function. It returns MeshError::EncryptionErrors.
unsafe fn vec2_from_c(
    x_buf_len: usize,
    y_buf_len: usize,
    filler: impl FnOnce(CBuf, CBuf) -> HmcStatus,
) -> Result<(Vec<u8>, Vec<u8>), MeshError> {
    generic_vec2_from_c(x_buf_len, y_buf_len, filler).map_err(MeshError::EncryptionError)
}

/// Compare two slices of bytes in constant time. This exists for the sake of comparing secure
/// tokens, avoiding time-based side channel attacks.
#[inline]
pub fn constant_time_eq<A, B>(a: A, b: B) -> bool
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();

    if a.len() != b.len() {
        return false;
    }

    #[inline(never)]
    fn eq_inner(a: &[u8], b: &[u8]) -> bool {
        assert_eq!(a.len(), b.len());
        use core::ptr::read_volatile;
        0 == a.iter().zip(b).fold(
            0,
            core::hint::black_box(|agg, (a, b)| {
                // Safety: references yielded from a/b.iter() must be safe to read.
                agg | unsafe { read_volatile(a as *const u8) ^ read_volatile(b as *const u8) }
            }),
        )
    }

    eq_inner(a, b)
}

pub struct HmacSha256Writer(core::ptr::NonNull<core::ffi::c_void>);

impl HmacSha256Writer {
    pub fn new(key: &[u8]) -> Result<Self, MeshError> {
        let mut hmac = core::ptr::null_mut();
        // Safety: we trust hmc_sha256_hmac_writer to set hmac appropriately.
        let result: Result<(), String> =
            unsafe { hmc_sha256_hmac_writer(HmcDataType::Raw, key.as_ptr(), key.len(), &mut hmac) }
                .into();
        result.map_err(MeshError::EncryptionError)?;
        Ok(Self(core::ptr::NonNull::new(hmac).unwrap()))
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), MeshError> {
        if buf.is_empty() {
            return Ok(());
        }

        // Safety: self.0 should be a valid pointer to a WolfCrypt Hmac.
        let result: Result<(), String> =
            unsafe { hmc_update_hmac(self.0.as_ptr(), buf.as_ptr(), buf.len()) }.into();
        result.map_err(MeshError::EncryptionError)
    }

    pub fn finalize(self) -> Result<[u8; 32], MeshError> {
        let mut hash = core::mem::MaybeUninit::<[u8; 32]>::uninit();

        // Safety: self.0 should be a valid pointer to a WolfCrypt Hmac.
        let result: Result<(), String> =
            unsafe { hmc_finalize_sha256_hmac(self.0.as_ptr(), hash.as_mut_ptr()) }.into();
        result.map_err(MeshError::EncryptionError)?;

        // Safety: hash was initialized by hmc_finalize_sha256_hmac.
        Ok(unsafe { hash.assume_init() })
    }
}

impl serde_cbor::ser::Write for HmacSha256Writer {
    type Error = serde_cbor::Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        let result = self.write(buf);
        match result {
            Ok(()) => Ok(()),
            Err(s) => Err(serde_cbor::Error::message(format!("hmac failed: {s}"))),
        }
    }
}

impl Drop for HmacSha256Writer {
    fn drop(&mut self) {
        match unsafe { hmc_free_hmac_writer(self.0.as_ptr()) } {
            HmcStatus::Ok => {}
            status => panic!("free failed: {}", String::from(status)),
        }
    }
}

pub struct Sha256Writer(core::ptr::NonNull<core::ffi::c_void>);

impl Sha256Writer {
    pub fn new() -> Result<Self, MeshError> {
        let mut hasher = core::ptr::null_mut();
        // Safety: we trust hmc_sha256_writer to set hasher appropriately.
        let result: Result<(), String> = unsafe { hmc_sha256_writer(&mut hasher) }.into();
        result.map_err(MeshError::EncryptionError)?;
        Ok(Self(core::ptr::NonNull::new(hasher).unwrap()))
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), MeshError> {
        if buf.is_empty() {
            return Ok(());
        }

        // Safety: self.0 should be a valid pointer to a wc_Sha256.
        let result: Result<(), String> =
            unsafe { hmc_sha256_update(self.0.as_ptr(), buf.as_ptr(), buf.len()) }.into();
        result.map_err(MeshError::EncryptionError)
    }

    pub fn finalize(self) -> Result<[u8; 32], MeshError> {
        let mut hash = mem::MaybeUninit::<[u8; 32]>::uninit();

        // Safety: self.0 should be a valid pointer to a wc_Sha256.
        let result: Result<(), String> =
            unsafe { hmc_sha256_gethash(self.0.as_ptr(), hash.as_mut_ptr()) }.into();
        result.map_err(MeshError::EncryptionError)?;

        // Safety: hash was initialized by hmc_finalize_sha256_hmac.
        Ok(unsafe { hash.assume_init() })
    }
}

impl Drop for Sha256Writer {
    fn drop(&mut self) {
        // Safety: self.0 should be a valid pointer to a wc_Sha256.
        match unsafe { hmc_free(self.0.as_ptr()) } {
            HmcStatus::Ok => {}
            status => panic!("free failed: {}", String::from(status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use alloc::string::String;

    #[test]
    fn test_init() {
        assert!(mesh_crypto_init().is_ok())
    }

    #[test]
    fn test_random_id() {
        let _ = mesh_crypto_init();
        assert_eq!(32, mesh_generate_id(32, HmcDataType::Raw).unwrap().len());
    }

    #[test]
    fn test_random_id_base64() {
        let _ = mesh_crypto_init();
        let result = mesh_generate_id(32, HmcDataType::Base64);
        assert!(!result.is_err());
        let key = result.unwrap();
        let result = mesh_convert_encoding(
            HmcDataType::Base64,
            HmcCredType::None,
            &key,
            HmcHashType::None,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let output = result.unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_random_id_base64_urlsafe() {
        let _ = mesh_crypto_init();
        let result = mesh_generate_id(32, HmcDataType::Base64Urlsafe);
        let key = result.expect("mesh_generate_id failed");
        let copy = key.clone();
        let str = String::from_utf8_lossy(&copy);
        let safe = str.chars().all(|x| x != '+' || x != '/');
        assert_eq!(safe, true);
        let result = mesh_convert_encoding(
            HmcDataType::Base64Urlsafe,
            HmcCredType::None,
            &key,
            HmcHashType::None,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let output = result.unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let _ = mesh_crypto_init();
        let result = mesh_generate_id(32, HmcDataType::Raw);
        assert!(!result.is_err());
        let key = result.unwrap();
        let input = "test encryption".as_bytes().to_vec();
        let result = mesh_encrypt(HmcDataType::Raw, &key, &input, &[], HmcDataType::Raw);
        assert!(!result.is_err());
        let encrypted_data = result.unwrap();
        let result = mesh_decrypt(
            HmcDataType::Raw,
            &key,
            HmcDataType::Raw,
            &encrypted_data,
            &[],
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data, input);
    }

    #[test]
    fn test_sign_verify() {
        let _ = mesh_crypto_init();
        let input = b"test sign";
        for key_type in [HmcKeyType::Ecc256, HmcKeyType::Ecc384, HmcKeyType::Ecc521] {
            let key = mesh_generate_key_pair(key_type, HmcDataType::Raw).unwrap();
            let signature = mesh_create_signature(
                key_type,
                HmcCredType::PrivateKey,
                HmcDataType::Der,
                &key.0,
                input,
                HmcDataType::Raw,
            )
            .expect("mesh_create_signature failed");
            assert!(mesh_verify_signature(
                key_type,
                HmcDataType::Der,
                &key.1,
                input,
                HmcSigFormat::Fixed,
                HmcDataType::Raw,
                &signature,
            )
            .expect("mesh_verify_signature failed"))
        }
    }

    #[test]
    fn test_import_and_share_ecc_secret() {
        // Example from Appendix C of https://datatracker.ietf.org/doc/html/rfc7518
        let _ = mesh_crypto_init();
        let alice_x_b64 = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
        let alice_y_b64 = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps";
        let alice_d_b64 = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo";
        let alice_x = mesh_base64_decode(alice_x_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();
        let alice_y = mesh_base64_decode(alice_y_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();
        let alice_d = mesh_base64_decode(alice_d_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();

        let bob_x_b64 = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ";
        let bob_y_b64 = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck";
        let bob_d_b64 = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";
        let bob_x = mesh_base64_decode(bob_x_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();
        let bob_y = mesh_base64_decode(bob_y_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();
        let bob_d = mesh_base64_decode(bob_d_b64, HmcDataType::Base64UrlsafeNoPadding).unwrap();

        let alice_pubkey = mesh_import_ecc_key_x_y_d(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &alice_x,
            &alice_y,
            &[],
        )
        .unwrap();
        let alice_privkey = mesh_import_ecc_key_x_y_d(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &alice_x,
            &alice_y,
            &alice_d,
        )
        .unwrap();

        let bob_pubkey =
            mesh_import_ecc_key_x_y_d(HmcKeyType::Ecc256, HmcDataType::Der, &bob_x, &bob_y, &[])
                .unwrap();
        let bob_privkey =
            mesh_import_ecc_key_x_y_d(HmcKeyType::Ecc256, HmcDataType::Der, &bob_x, &bob_y, &bob_d)
                .unwrap();

        let alice_bob = mesh_create_shared_ecc_secret(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &alice_privkey,
            &bob_pubkey,
            HmcDataType::Raw,
        )
        .unwrap();
        let bob_alice = mesh_create_shared_ecc_secret(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &bob_privkey,
            &alice_pubkey,
            HmcDataType::Raw,
        )
        .unwrap();
        let shared_secret: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        assert_eq!(alice_bob, bob_alice);
        assert_eq!(alice_bob, &shared_secret);
    }

    #[test]
    fn test_shared_ecc_secret() {
        let _ = mesh_crypto_init();
        let result = mesh_generate_key_pair(HmcKeyType::Ecc384, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair1 = result.unwrap();
        let result = mesh_generate_key_pair(HmcKeyType::Ecc384, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair2 = result.unwrap();
        let result = mesh_create_shared_ecc_secret(
            HmcKeyType::Ecc384,
            HmcDataType::Der,
            &key_pair1.0,
            &key_pair2.1,
            HmcDataType::Raw,
        );
        let shared1 = result.unwrap();
        let result = mesh_create_shared_ecc_secret(
            HmcKeyType::Ecc384,
            HmcDataType::Der,
            &key_pair2.0,
            &key_pair1.1,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let shared2 = result.unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 48);
    }

    #[test]
    fn test_shared_kyber_secret() {
        let _ = mesh_crypto_init();
        let result = mesh_generate_key_pair(HmcKeyType::Kyber768, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair = result.unwrap();
        let result = mesh_create_shared_kyber_secret(
            HmcKeyType::Kyber768,
            HmcDataType::Raw,
            &key_pair.1,
            HmcDataType::Raw,
        );
        let (shared_secret, encrypted_shared_secret) = result.unwrap();
        let result = mesh_decrypt_shared_kyber_secret(
            HmcKeyType::Kyber768,
            HmcDataType::Raw,
            &key_pair.0,
            HmcDataType::Raw,
            &encrypted_shared_secret,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let shared2 = result.unwrap();
        assert_eq!(shared_secret, shared2);
    }

    #[test]
    fn test_shared_ecc_kyber_hybrid_secret() {
        let _ = mesh_crypto_init();

        let result = mesh_generate_key_pair(HmcKeyType::Kyber768, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair = result.unwrap();
        let result = mesh_create_shared_kyber_secret(
            HmcKeyType::Kyber768,
            HmcDataType::Raw,
            &key_pair.1,
            HmcDataType::Raw,
        );
        let (shared_kyber_secret, _) = result.unwrap();

        let result = mesh_generate_key_pair(HmcKeyType::Ecc256, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair1 = result.unwrap();
        let result = mesh_generate_key_pair(HmcKeyType::Ecc256, HmcDataType::Raw);
        assert!(!result.is_err());
        let key_pair2 = result.unwrap();

        let result = mesh_create_shared_ecc_kyber_hybrid_secret(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &key_pair1.0,
            &key_pair2.1,
            HmcDataType::Raw,
            &shared_kyber_secret,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let shared1 = result.unwrap();
        let result = mesh_create_shared_ecc_kyber_hybrid_secret(
            HmcKeyType::Ecc256,
            HmcDataType::Der,
            &key_pair2.0,
            &key_pair1.1,
            HmcDataType::Raw,
            &shared_kyber_secret,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let shared2 = result.unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_concat_kdf() {
        // Example from Appendix C of https://datatracker.ietf.org/doc/html/rfc7518
        let shared_secret: [u8; 32] = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let enc = b"A128GCM";
        let party_u = b"Alice";
        let party_v = b"Bob";
        let result = mesh_concat_kdf(&shared_secret, enc, party_u, party_v);
        assert_eq!(
            result.unwrap(),
            [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26] as [u8; 16]
        );
    }

    #[test]
    fn test_derive_key() {
        let input = "test encryption".as_bytes().to_vec();
        let _ = mesh_crypto_init();
        let result = mesh_generate_aes256_key(HmcDataType::Raw);
        assert!(!result.is_err());
        let key = result.unwrap();

        let result = mesh_derive_key(
            HmcDataType::Raw,
            &key,
            HmcDataType::Raw,
            &input,
            HmcDataType::Raw,
        );
        assert!(!result.is_err());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    const SGX_PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
    MIIBiAKCAYEAroOogvsj/fZDZY8XFdkl6dJmky0lRvnWMmpeH41Bla6U1qLZAmZu
    yIF+mQC/cgojIsrBMzBxb1kKqzATF4+XwPwgKz7fmiddmHyYz2WDJfAjIveJZjdM
    jM4+EytGlkkJ52T8V8ds0/L2qKexJ+NBLxkeQLfV8n1mIk7zX7jguwbCG1PrnEMd
    J3Sew20vnje+RsngAzdPChoJpVsWi/K7cettX/tbnre1DL02GXc5qJoQYk7b3zkm
    hz31TgFrd9VVtmUGyFXAysuSAb3EN+5VnHGr0xKkeg8utErea2FNtNIgua8HONfm
    9Eiyaav1SVKzPHlyqLtcdxH3I8Wg7yqMsaprZ1n5A1v/levxnL8+It02KseD5HqV
    4rf/cImSlCt3lpRg8U5E1pyFQ2IVEC/XTDMiI3c+AR+w2jSRB3Bwn9zJtFlWKHG3
    m1xGI4ck+Lci1JvWWLXQagQSPtZTsubxTQNx1gsgZhgv1JHVZMdbVlAbbRMC1nSu
    JNl7KPAS/VfzAgED
    -----END RSA PUBLIC KEY-----";

    #[test]
    fn test_sgx_mr_signer() {
        let result = mesh_sgx_mr_signer(HmcDataType::Pem, SGX_PUBLIC_KEY.as_bytes());
        assert!(!result.is_err());
        let result = result.unwrap();
        let result = result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            result,
            "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e"
        );
    }

    #[test]
    fn test_mesh_hash_email() {
        // invalid inputs
        for bad in [
            "",
            "foo@bar",
            "@bar.com",
            "foo@bar@baz.com",
            "name@",
            "@name",
            "a@b.c",
            "foo@..com",
            "bar@google.1",
            "baz@google.x",
            "qux@1--1.com",
            "quux@-1-.net",
        ] {
            assert!(mesh_hash_email(bad).is_err(), "expected {bad:?} to fail");
        }

        for (email, expected) in [
            (
                "w@x.yz",
                [
                    3, 55, 13, 163, 147, 76, 72, 87, 105, 245, 23, 150, 46, 82, 201, 153, 81, 52,
                    28, 236, 94, 144, 196, 156, 140, 186, 96, 187, 255, 144, 120, 153,
                ],
            ),
            // case is ignored.
            (
                "jed@hushmesh.com",
                [
                    176, 3, 153, 153, 244, 186, 181, 112, 30, 238, 141, 80, 61, 70, 230, 145, 179,
                    113, 43, 92, 150, 202, 125, 1, 11, 85, 181, 48, 167, 147, 112, 222,
                ],
            ),
            (
                "jeD@HushMesh.COM",
                [
                    176, 3, 153, 153, 244, 186, 181, 112, 30, 238, 141, 80, 61, 70, 230, 145, 179,
                    113, 43, 92, 150, 202, 125, 1, 11, 85, 181, 48, 167, 147, 112, 222,
                ],
            ),
            // wacky looking valid addresses...
            (
                "aa+++@1.a-2-3.111.com",
                [
                    216, 195, 125, 64, 104, 236, 5, 207, 118, 201, 203, 129, 65, 143, 4, 135, 45,
                    174, 202, 21, 19, 91, 178, 214, 244, 217, 90, 103, 18, 254, 169, 104,
                ],
            ),
            (
                "foo.bar@baz.com",
                [
                    253, 206, 11, 113, 53, 83, 220, 201, 30, 251, 92, 204, 51, 63, 124, 90, 32,
                    155, 212, 234, 56, 249, 165, 141, 86, 113, 114, 248, 59, 105, 197, 41,
                ],
            ),
            (
                "foo@bar.baz.com",
                [
                    215, 204, 227, 63, 179, 226, 108, 38, 192, 20, 5, 46, 229, 110, 114, 152, 98,
                    112, 221, 163, 212, 39, 218, 125, 157, 201, 147, 13, 182, 76, 60, 151,
                ],
            ),
        ] {
            match mesh_hash_email(email) {
                Ok(hash) => assert_eq!(expected, hash.id, "email: {email:?}"),
                Err(e) => panic!("unexpected error from {email:?}: {e}"),
            }
        }
    }

    #[test]
    fn test_mesh_hash_phone() {
        for bad in [
            "",
            "not phone number",
            "18005551212",
            "+1",
            "+12345678",
            "+1234567890123456",
            "1-800-555-1212",
            "(800) 555-1212",
            "234 456 7890",
        ] {
            assert!(mesh_hash_phone(bad).is_err(), "expected {bad:?} to fail");
        }

        for (phone, expected) in [
            (
                "+123456789",
                [
                    134, 46, 12, 42, 7, 79, 132, 160, 230, 100, 13, 157, 218, 91, 170, 168, 69, 17,
                    100, 208, 19, 197, 130, 193, 113, 90, 245, 128, 50, 27, 249, 191,
                ],
            ),
            (
                "+123456789012345",
                [
                    74, 210, 68, 79, 171, 27, 79, 20, 203, 92, 147, 140, 128, 246, 115, 32, 52,
                    150, 223, 236, 247, 243, 37, 237, 147, 205, 129, 158, 44, 237, 195, 53,
                ],
            ),
            (
                "+18005551212",
                [
                    163, 160, 242, 172, 29, 62, 123, 156, 116, 174, 249, 251, 64, 23, 237, 114, 70,
                    46, 32, 7, 143, 86, 209, 46, 196, 169, 178, 174, 180, 181, 94, 3,
                ],
            ),
        ] {
            match mesh_hash_phone(phone) {
                Ok(hash) => assert_eq!(expected, hash.id, "phone: {phone:?}"),
                Err(e) => panic!("unexpected error from {phone:?}: {e}"),
            }
        }
    }

    #[test]
    fn test_convert_hex() {
        for bad_hex in [
            "0",
            "012",
            "01234",
            "0123456",
            "012345678",
            "0123456789a",
            "0123456789abc",
            "0123456789abcde",
            "0123456789abcdef0",
            "/012",
            "789:",
            "`abc",
            "abcg",
            "@BCD",
            "ABCG",
        ] {
            assert!(
                mesh_convert_encoding(
                    HmcDataType::Hex,
                    HmcCredType::None,
                    bad_hex.as_bytes(),
                    HmcHashType::None,
                    HmcDataType::Raw
                )
                .is_err(),
                "expected bad hex input {bad_hex:?} to cause an error",
            )
        }

        assert_eq!(
            mesh_convert_encoding(
                HmcDataType::Hex,
                HmcCredType::None,
                b"0123456789aBcDeF",
                HmcHashType::None,
                HmcDataType::Raw
            )
            .unwrap(),
            b"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
        );
        assert_eq!(
            mesh_convert_encoding(
                HmcDataType::Raw,
                HmcCredType::None,
                b"0123456789aBcDeF",
                HmcHashType::None,
                HmcDataType::Hex
            )
            .unwrap(),
            b"30313233343536373839614263446546",
        );

        let shuffled: &[u8; 256] = &[
            165, 108, 58, 113, 7, 16, 93, 187, 227, 49, 90, 125, 97, 186, 63, 123, 130, 255, 166,
            44, 38, 236, 32, 5, 107, 196, 243, 194, 197, 200, 96, 42, 112, 41, 128, 160, 204, 201,
            193, 203, 57, 24, 153, 45, 214, 53, 190, 71, 114, 19, 212, 31, 59, 12, 254, 25, 37,
            170, 232, 163, 149, 219, 138, 40, 36, 95, 109, 234, 122, 229, 81, 55, 99, 105, 136,
            237, 119, 248, 82, 56, 70, 225, 75, 78, 48, 154, 111, 129, 51, 164, 30, 29, 74, 207,
            251, 141, 177, 150, 226, 137, 23, 79, 179, 247, 198, 218, 239, 88, 17, 43, 67, 180,
            221, 52, 127, 3, 151, 182, 155, 84, 224, 39, 91, 250, 181, 124, 1, 26, 175, 10, 13,
            241, 116, 126, 184, 87, 54, 28, 80, 245, 174, 118, 183, 216, 104, 50, 62, 94, 147, 173,
            140, 208, 222, 210, 72, 199, 161, 156, 117, 192, 242, 85, 240, 121, 146, 238, 213, 66,
            202, 35, 209, 20, 171, 98, 230, 228, 168, 215, 134, 106, 217, 148, 101, 110, 235, 102,
            65, 178, 135, 47, 189, 0, 162, 83, 233, 103, 176, 246, 205, 18, 14, 139, 145, 253, 11,
            185, 143, 2, 77, 188, 223, 244, 22, 92, 157, 64, 115, 100, 195, 60, 131, 220, 34, 61,
            211, 159, 6, 8, 69, 158, 169, 4, 249, 15, 89, 120, 133, 33, 144, 27, 172, 46, 252, 167,
            231, 142, 206, 152, 21, 68, 9, 73, 86, 76, 132, 191,
        ];
        let as_hex: &[u8; 512] =
            b"a56c3a7107105dbbe3315a7d61ba3f7b82ffa62c26ec20056bc4f3c2c5c8602a\
            702980a0ccc9c1cb3918992dd635be477213d41f3b0cfe1925aae8a395db8a2824\
            5f6dea7ae55137636988ed77f8523846e14b4e309a6f8133a41e1d4acffb8db196\
            e289174fb3f7c6daef58112b43b4dd347f0397b69b54e0275bfab57c011aaf0a0d\
            f1747eb857361c50f5ae76b7d868323e5e93ad8cd0ded248c7a19c75c0f255f079\
            92eed542ca23d114ab62e6e4a8d7866ad994656eeb6641b2872fbd00a253e967b0\
            f6cd120e8b91fd0bb98f024dbcdff4165c9d407364c33c83dc223dd39f0608459e\
            a904f90f59788521901bac2efca7e78ece9815440949564c84bf";
        let mixed_hex: &[u8; 512] =
            b"a56C3A7107105DbBe3315A7D61bA3F7B82fFa62C26eC20056Bc4f3c2c5c8602A\
            702980a0cCc9c1cB3918992Dd635bE477213d41F3B0CfE1925aAe8a395dB8A2824\
            5F6DeA7Ae55137636988eD77f8523846e14B4E309A6F8133a41E1D4AcFfB8Db196\
            e289174Fb3f7c6dAeF58112B43b4dD347F0397b69B54e0275BfAb57C011AaF0A0D\
            f1747Eb857361C50f5aE76b7d868323E5E93aD8Cd0dEd248c7a19C75c0f255f079\
            92eEd542cA23d114aB62e6e4a8d7866Ad994656EeB6641b2872FbD00a253e967b0\
            f6cD120E8B91fD0Bb98F024DbCdFf4165C9D407364c33C83dC223Dd39F0608459E\
            a904f90F59788521901BaC2EfCa7e78EcE9815440949564C84bF";
        assert_eq!(
            mesh_convert_encoding(
                HmcDataType::Raw,
                HmcCredType::None,
                shuffled,
                HmcHashType::None,
                HmcDataType::Hex
            )
            .unwrap(),
            as_hex,
        );
        assert_eq!(
            mesh_convert_encoding(
                HmcDataType::Hex,
                HmcCredType::None,
                mixed_hex,
                HmcHashType::None,
                HmcDataType::Raw
            )
            .unwrap(),
            shuffled,
        );
        assert!(as_hex
            .iter()
            .zip(mixed_hex)
            .all(|(a, b)| a.eq_ignore_ascii_case(b)));
    }

    #[test]
    fn test_hex_hmac() {
        assert_eq!(
            mesh_derive_key(
                HmcDataType::Hex,
                b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                HmcDataType::Hex,
                b"49276d20736f6d652076616c7565",
                HmcDataType::Hex
            )
            .unwrap(),
            b"c15e968d921bb3973ec983b3b14609f1360498122c4c6321c8786bd471735482"
        );
    }

    #[test]
    fn test_encrypted_len() {
        const TEST_LENGTHS: &[usize] = &[
            0, 1, 3, 11, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024,
            1025, 2047, 2048, 2049,
        ];
        let key = mesh_generate_encryption_key().unwrap();
        for &size in TEST_LENGTHS {
            let input = vec![0; size];

            let enc =
                mesh_encrypt(HmcDataType::Raw, &key.id, &input, &[], HmcDataType::Raw).unwrap();
            let expected = size + AES_GCM_OVERHEAD;
            assert_eq!(
                expected,
                enc.len(),
                "{size} -> expected {expected}, got {}",
                enc.len()
            );

            let decrypted = mesh_decrypt(
                HmcDataType::Raw,
                &key.id,
                HmcDataType::Raw,
                &enc,
                &[],
                HmcDataType::Raw,
            )
            .unwrap();
            assert_eq!(input, decrypted);
        }
    }

    #[test]
    fn test_constant_time_eq() {
        // Equal to self
        {
            let v = "asdfasdf";
            assert!(constant_time_eq(v, v));
        }

        // Equal to another
        {
            let a = b"foobarbazbingblargbasdf".to_vec();
            let b = b"foobarbazbingblargbasdf".to_vec();
            assert!(constant_time_eq(&a, &b));
            assert!(constant_time_eq(&b, &a));
        }

        // Equal to overlapping
        {
            let v = b"a a a a a a a a a a a a a ".to_vec();
            assert!(constant_time_eq(&v[..v.len() - 2], &v[2..]));
            assert!(constant_time_eq(&v[2..], &v[..v.len() - 2]));
        }

        // Same length but different must not pass.
        assert!(!constant_time_eq("abcdefghijk", "bcdefghijkl"));
        // Equal prefixes of different lengths must not pass.
        assert!(!constant_time_eq("asdf", "asdfg"));
        assert!(!constant_time_eq("asdfg", "asdf"));
        // Ensure that symmetric differences don't cancel eachother out.
        assert!(!constant_time_eq("ab", "ba"));

        // This had better never pass!
        assert!(!constant_time_eq(
            &mesh_generate_mesh_id().unwrap().id,
            &mesh_generate_mesh_id().unwrap().id
        ));
    }
}
