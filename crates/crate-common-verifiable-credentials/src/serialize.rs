use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use common_crypto::mesh_export_ecc_key_x_y;
use common_crypto::mesh_import_ecc_key_x_y_d;
use common_crypto::HmcDataType;
use common_crypto::HmcKeyType;
use common_types::log_error;
use common_types::MeshError;

use lazy_static::lazy_static;

use crate::multibase_base58btc;

pub const P256_PUB_CODEC: u64 = 0x1200;
pub const P384_PUB_CODEC: u64 = 0x1201;
pub const BLS12_381_G2_PUB_CODEC: u64 = 0xeb;

lazy_static! {
    static ref P256_CODEC_PREFIX: Vec<u8> =
        unsigned_varint::encode::u64(P256_PUB_CODEC, &mut [0u8; 10]).to_vec();
    static ref P384_CODEC_PREFIX: Vec<u8> =
        unsigned_varint::encode::u64(P384_PUB_CODEC, &mut [0u8; 10]).to_vec();
    static ref BLS12_381_G2_CODEC_PREFIX: Vec<u8> =
        unsigned_varint::encode::u64(BLS12_381_G2_PUB_CODEC, &mut [0u8; 10]).to_vec();
}

/// Serialize a P-256 public key as a 33-byte string with point compression.
///
/// An EncodedPoint just holds a GenericArray, but offers no method to unwrap it into a [u8; N].
/// Returning `impl AsRef<[u8]>` allows us to nicely keep the value on the stack while still making
/// it easy to access as a `&[u8]`.
fn serialize_p256(
    public_key: &[u8],
    key_data_type: HmcDataType,
) -> Result<impl AsRef<[u8]>, MeshError> {
    use p256::EncodedPoint;
    use p256::FieldBytes;

    let (x, y) = mesh_export_ecc_key_x_y(key_data_type, public_key)?;
    let x = FieldBytes::from_slice(&x);
    let y = FieldBytes::from_slice(&y);
    Ok(EncodedPoint::from_affine_coordinates(x, y, true))
}

fn deserialize_p256(encoded: &[u8], key_data_type: HmcDataType) -> Result<Vec<u8>, MeshError> {
    use p256::ecdsa::VerifyingKey;

    let verifying_key: VerifyingKey = VerifyingKey::from_sec1_bytes(encoded)
        .map_err(|_| MeshError::BadArgument("Failed to decode P-256 public key".to_string()))?;
    let coordinates = verifying_key.to_encoded_point(false);
    let x = coordinates
        .x()
        .ok_or_else(|| log_error!(MeshError::BadState))?;
    let y = coordinates
        .y()
        .ok_or_else(|| log_error!(MeshError::BadState))?;
    mesh_import_ecc_key_x_y_d(HmcKeyType::Ecc256, key_data_type, x, y, &[])
}

/// Serialize a P-384 public key as a 49-byte string with point compression.
fn serialize_p384(
    public_key: &[u8],
    key_data_type: HmcDataType,
) -> Result<impl AsRef<[u8]>, MeshError> {
    use p384::EncodedPoint;
    use p384::FieldBytes;

    let (x, y) = mesh_export_ecc_key_x_y(key_data_type, public_key)?;
    let x = FieldBytes::from_slice(&x);
    let y = FieldBytes::from_slice(&y);
    Ok(EncodedPoint::from_affine_coordinates(x, y, true))
}

fn deserialize_p384(encoded: &[u8], key_data_type: HmcDataType) -> Result<Vec<u8>, MeshError> {
    use p384::ecdsa::VerifyingKey;

    let verifying_key: VerifyingKey = VerifyingKey::from_sec1_bytes(encoded)
        .map_err(|_| MeshError::BadArgument("Failed to decode P-384 public key".to_string()))?;
    let coordinates = verifying_key.to_encoded_point(false);
    let x = coordinates
        .x()
        .ok_or_else(|| log_error!(MeshError::BadState))?;
    let y = coordinates
        .y()
        .ok_or_else(|| log_error!(MeshError::BadState))?;
    mesh_import_ecc_key_x_y_d(HmcKeyType::Ecc384, key_data_type, x, y, &[])
}

fn serialize_bls12_381_g2(key: &[u8]) -> Result<impl AsRef<[u8]>, MeshError> {
    use bls12_381_plus::G2Affine;

    let element = match key.len() {
        G2Affine::COMPRESSED_BYTES => G2Affine::from_compressed(key.try_into().unwrap())
            .into_option()
            .ok_or("Failed to decode compressed BLS12-381 G2 public key"),
        G2Affine::UNCOMPRESSED_BYTES => G2Affine::from_uncompressed(key.try_into().unwrap())
            .into_option()
            .ok_or("Failed to decode uncompressed BLS12-381 G2 public key"),
        _ => Err("BLS12-381 G2 public key must be 96 or 192 bytes"),
    }
    .map_err(|e| log_error!(MeshError::BadArgument(e.to_string())))?;
    Ok(element.to_compressed())
}

fn deserialize_bls12_381_g2(encoded: &[u8]) -> Result<Vec<u8>, MeshError> {
    use bls12_381_plus::G2Affine;

    let element = Option::<G2Affine>::from(G2Affine::from_compressed(encoded.try_into().map_err(
        |_| {
            MeshError::BadArgument(
                "Compressed BLS12-381 G2 public key must be 96 bytes".to_string(),
            )
        },
    )?))
    .ok_or_else(|| {
        log_error!(MeshError::BadArgument(
            "Failed to decode compressed BLS12-381 G2 public key".to_string()
        ))
    })?;
    Ok(element.to_uncompressed().to_vec())
}

pub(crate) fn encode_p256(
    public_key: &[u8],
    key_data_type: HmcDataType,
) -> Result<String, MeshError> {
    let bytes = serialize_p256(public_key, key_data_type)?;
    let result = [P256_CODEC_PREFIX.as_ref(), bytes.as_ref()].concat();
    multibase_base58btc(&result)
}

pub(crate) fn encode_p384(
    public_key: &[u8],
    key_data_type: HmcDataType,
) -> Result<String, MeshError> {
    let bytes = serialize_p384(public_key, key_data_type)?;
    let result = [P384_CODEC_PREFIX.as_ref(), bytes.as_ref()].concat();
    multibase_base58btc(&result)
}

pub(crate) fn encode_bls12_381_g2(public_key: &[u8]) -> Result<String, MeshError> {
    let bytes = serialize_bls12_381_g2(public_key)?;
    let result = [BLS12_381_G2_CODEC_PREFIX.as_ref(), bytes.as_ref()].concat();
    multibase_base58btc(&result)
}

pub(crate) fn decode_did_key_multibase(
    encoded: &str,
    key_data_type: HmcDataType,
) -> Result<Vec<u8>, MeshError> {
    let encoded = match encoded.split_once('#') {
        Some((left, right)) => {
            if left != right {
                return Err(MeshError::BadArgument(
                    "Multibase string has mismatched identifier".to_string(),
                ));
            }
            left
        }
        None => encoded,
    };
    let encoded = encoded.strip_prefix('z').ok_or_else(|| {
        MeshError::BadArgument("Multibase string does not have base58 prefix".to_string())
    })?;
    let bytes: Vec<u8> = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| MeshError::BadArgument("Failed to decode base58 string".to_string()))?;

    if let Some(bytes) = bytes.strip_prefix(P256_CODEC_PREFIX.as_slice()) {
        deserialize_p256(bytes, key_data_type)
    } else if let Some(bytes) = bytes.strip_prefix(P384_CODEC_PREFIX.as_slice()) {
        deserialize_p384(bytes, key_data_type)
    } else if let Some(bytes) = bytes.strip_prefix(BLS12_381_G2_CODEC_PREFIX.as_slice()) {
        deserialize_bls12_381_g2(bytes)
    } else {
        Err(MeshError::BadArgument("Unknown key type".to_string()))
    }
}

pub(crate) fn decode_did_key_multibase_raw(encoded: &str) -> Result<Vec<u8>, MeshError> {
    let encoded = match encoded.split_once('#') {
        Some((left, right)) => {
            if left != right {
                return Err(MeshError::BadArgument(
                    "Multibase string has mismatched identifier".to_string(),
                ));
            }
            left
        }
        None => encoded,
    };
    let encoded = encoded.strip_prefix('z').ok_or_else(|| {
        MeshError::BadArgument("Multibase string does not have base58 prefix".to_string())
    })?;
    let bytes: Vec<u8> = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| MeshError::BadArgument("Failed to decode base58 string".to_string()))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P384_TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+J4kKP4POKDx6Ov2l7kL+FNCVPrZmetX
N/GSfgL6OI39OyXD5L/ygoGvDjoNAGIcI7T5BqTiWJRhAPPJyRh5FgiOgnGxU8De
VIuYEJ/Hdo9cA7gXlE/B3906S2UzP6Qp
-----END PUBLIC KEY-----
";

    const BLS12_381_G2_PUBLIC_KEY_MULTIBASE: &str = "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb";

    const P384_COMPRESSED: [u8; 49] = [
        0x03, 0xf8, 0x9e, 0x24, 0x28, 0xfe, 0x0f, 0x38, 0xa0, 0xf1, 0xe8, 0xeb, 0xf6, 0x97, 0xb9,
        0x0b, 0xf8, 0x53, 0x42, 0x54, 0xfa, 0xd9, 0x99, 0xeb, 0x57, 0x37, 0xf1, 0x92, 0x7e, 0x02,
        0xfa, 0x38, 0x8d, 0xfd, 0x3b, 0x25, 0xc3, 0xe4, 0xbf, 0xf2, 0x82, 0x81, 0xaf, 0x0e, 0x3a,
        0x0d, 0x00, 0x62, 0x1c,
    ];

    #[test]
    fn test_serialize_p384() {
        let result = serialize_p384(P384_TEST_PUBLIC_KEY.as_bytes(), HmcDataType::Pem).unwrap();
        assert_eq!(result.as_ref(), &P384_COMPRESSED);
    }

    #[test]
    fn test_roundtrip_p384() {
        let result = serialize_p384(P384_TEST_PUBLIC_KEY.as_bytes(), HmcDataType::Pem).unwrap();
        assert_eq!(result.as_ref(), &P384_COMPRESSED);
        let decoded = deserialize_p384(&P384_COMPRESSED, HmcDataType::Pem).unwrap();
        let decoded = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded, P384_TEST_PUBLIC_KEY);
    }

    #[test]
    fn test_roundtrip_bls12_381_g2() {
        let decoded =
            decode_did_key_multibase(BLS12_381_G2_PUBLIC_KEY_MULTIBASE, HmcDataType::Raw).unwrap();
        let encoded = encode_bls12_381_g2(&decoded).unwrap();
        assert_eq!(encoded, BLS12_381_G2_PUBLIC_KEY_MULTIBASE);
    }
}
