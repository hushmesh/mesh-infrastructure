use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::net::IpAddr;
use core::net::SocketAddr;

use base64::display::Base64Display;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::Engine;
use serde::Deserialize;
use serde::Serialize;

use crate::MeshError;

#[derive(PartialEq, Eq, Hash, Copy, Clone, PartialOrd, Ord)]
pub struct MeshId {
    pub id: [u8; 32],
}

impl MeshId {
    const BASE64_LEN: usize = 43;

    #[inline]
    pub const fn empty() -> MeshId {
        MeshId { id: [0; 32] }
    }

    pub fn from_bytes(data: &[u8]) -> Result<MeshId, MeshError> {
        let id = data.try_into().map_err(|_| {
            MeshError::ProtocolError(format!(
                "invalid implied id of {} bytes: {}",
                data.len(),
                Self::BASE64_LEN
            ))
        })?;
        Ok(MeshId { id })
    }

    // Create a bogus MeshId for the sake of deriving keys like "email" or "phone".
    pub const fn from_static(s: &'static str) -> Self {
        if s.is_empty() || s.len() > 32 {
            panic!("input string must be between 1 and 32 bytes long")
        }
        let b = s.as_bytes();
        let mut id = [0; 32];

        // copy_from_slice is not const...
        let mut i = 0;
        while i < b.len() {
            id[i] = b[i];
            i += 1;
        }
        MeshId { id }
    }

    pub fn from_base64(b: &str) -> Result<MeshId, MeshError> {
        const LEN_WITH_PADDING: usize = MeshId::BASE64_LEN + 1;
        let b = match b.len() {
            MeshId::BASE64_LEN => Some(b),
            LEN_WITH_PADDING => b.strip_suffix('='),
            _ => None,
        }
        .ok_or_else(|| MeshError::ProtocolError("invalid base64 length for id".into()))?;
        let mut id = [0; 32];
        match URL_SAFE_NO_PAD.decode_slice_unchecked(b, &mut id) {
            Ok(32) => Ok(MeshId { id }),
            _ => Err(MeshError::ProtocolError("invalid base64 id".into())),
        }
    }

    pub fn as_base64(&self) -> impl core::fmt::Display + '_ {
        Base64Display::new(&self.id, &URL_SAFE_NO_PAD)
    }
}

impl core::fmt::Debug for MeshId {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.as_base64(), fmt)
    }
}

impl From<[u8; 32]> for MeshId {
    #[inline]
    fn from(id: [u8; 32]) -> Self {
        Self { id }
    }
}

impl TryFrom<&[u8]> for MeshId {
    type Error = MeshError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        MeshId::from_bytes(v)
    }
}

impl TryFrom<Vec<u8>> for MeshId {
    type Error = MeshError;
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        MeshId::from_bytes(&v)
    }
}

impl TryFrom<&Vec<u8>> for MeshId {
    type Error = MeshError;
    fn try_from(v: &Vec<u8>) -> Result<Self, Self::Error> {
        MeshId::from_bytes(v)
    }
}

impl Serialize for MeshId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&self.as_base64())
        } else {
            serializer.serialize_bytes(&self.id)
        }
    }
}

/// As of this writing, MeshIds are serialized consistently as bytes, per `impl Serialize` above.
/// But, historically they were either serialized as bytes or as a map/struct, {"id":...}. In the
/// map, the id would have been serialized as a sequence by default.  These maps may or may not
/// have been serialized using cbor's packed format, so the key might just be 0 instead of "id".
/// The implementation of Deserialize aims to support any serialization method, including JSON in
/// which bytes outbound is always interpreted as a sequence inbound.
impl<'de> Deserialize<'de> for MeshId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de;

        enum DesType {
            Json,
            Cbor,
        }
        impl DesType {
            fn from_de<'a, D: de::Deserializer<'a>>(d: &D) -> Self {
                match d.is_human_readable() {
                    true => DesType::Json,
                    false => DesType::Cbor,
                }
            }
        }

        // When deserializing a CBOR message, a struct may have either string keys, or numbered
        // keys in "packed" mode.
        enum CborKey<'de> {
            Packed(u64),
            Str(&'de str),
        }
        impl<'de> de::Deserialize<'de> for CborKey<'de> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                struct CborKeyVisitor;
                impl<'de> de::Visitor<'de> for CborKeyVisitor {
                    type Value = CborKey<'de>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("number or string")
                    }

                    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(CborKey::Packed(value))
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(CborKey::Str(value))
                    }
                }
                deserializer.deserialize_u64(CborKeyVisitor)
            }
        }
        impl CborKey<'_> {
            fn as_str(&self) -> alloc::borrow::Cow<str> {
                match self {
                    CborKey::Packed(n) => n.to_string().into(),
                    CborKey::Str(s) => (*s).into(),
                }
            }
        }

        // Next, either a MeshId or BytesInner may need to decode a sequence; this is the generic method
        // both will use.
        const EXPECTING_BYTES: &str = "32 bytes or a sequence of 32 bytes";
        fn generic_visit_seq<'a, V: de::Visitor<'a>, A: de::SeqAccess<'a>>(
            genself: V,
            mut seq: A,
        ) -> Result<[u8; 32], A::Error> {
            match seq.size_hint() {
                None | Some(32) => {}
                Some(len) => return Err(de::Error::invalid_length(len, &genself)),
            }

            let mut seq = core::iter::from_fn(|| seq.next_element::<u8>().transpose());
            let mut buf = [0u8; 32];

            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = seq
                    .next()
                    .ok_or_else(|| de::Error::invalid_length(i, &genself))??;
            }

            // Ensure the sequence was only 32 bytes.
            match seq.next() {
                None => Ok(buf),
                Some(Ok(_)) => Err(de::Error::custom(format!(
                    "too many items, expected {EXPECTING_BYTES}",
                ))),
                Some(Err(e)) => Err(e),
            }
        }

        // From the context of deserializing a CBOR map, we must unpack a value that is serialized
        // either as bytes or as a sequence of bytes...
        struct BytesInner([u8; 32]);
        impl<'de> de::Deserialize<'de> for BytesInner {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                struct BytesVisitor(DesType);
                impl<'de> de::Visitor<'de> for BytesVisitor {
                    type Value = BytesInner;
                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(EXPECTING_BYTES)
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(BytesInner(value.try_into().map_err(|_| {
                            de::Error::invalid_length(value.len(), &self)
                        })?))
                    }

                    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: de::SeqAccess<'de>,
                    {
                        generic_visit_seq(self, seq).map(BytesInner)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        match self.0 {
                            // In order to use `from_base64` here we must unwrap and then rewrap
                            // the [u8; 32], but that's just extra work for the compiler.
                            DesType::Json => Ok(BytesInner(
                                MeshId::from_base64(value).map_err(de::Error::custom)?.id,
                            )),
                            DesType::Cbor => {
                                Err(de::Error::invalid_type(de::Unexpected::Str(value), &self))
                            }
                        }
                    }
                }

                let visitor = BytesVisitor(DesType::from_de(&deserializer));
                deserializer.deserialize_any(visitor)
            }
        }

        // At the root, a MeshId may be bytes, a sequence of bytes, or the map `{"id":BytesInner(...)}`...
        struct MeshIdVisitor(DesType);
        impl<'de> serde::de::Visitor<'de> for MeshIdVisitor {
            type Value = MeshId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("32 bytes, 32-byte sequence, or a 1-element map")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let id = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                Ok(MeshId { id })
            }

            // serialize_bytes in JSON look just like a sequence, so we must support both on the
            // inbound side.
            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                generic_visit_seq(self, seq).map(|id| MeshId { id })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                match map.size_hint() {
                    None | Some(1) => {}
                    Some(len) => return Err(de::Error::invalid_length(len, &self)),
                }

                const ID: &str = "id";

                match self.0 {
                    DesType::Json => {
                        let Some((ID, BytesInner(id))) = map.next_entry()? else {
                            return Err(de::Error::missing_field(ID));
                        };
                        if let Some(extra) = map.next_key()? {
                            Err(match extra {
                                ID => de::Error::duplicate_field(ID),
                                _ => de::Error::unknown_field(extra, &[ID]),
                            })
                        } else {
                            Ok(MeshId { id })
                        }
                    }
                    DesType::Cbor => {
                        let Some((key, BytesInner(id))) = map.next_entry()? else {
                            return Err(de::Error::missing_field(ID));
                        };

                        if !matches!(key, CborKey::Packed(0) | CborKey::Str(ID)) {
                            return Err(de::Error::unknown_field(&key.as_str(), &[ID]));
                        }

                        if let Some(extra) = map.next_key::<CborKey>()? {
                            Err(match extra {
                                CborKey::Packed(0) | CborKey::Str(ID) => {
                                    de::Error::duplicate_field(ID)
                                }
                                _ => de::Error::unknown_field(&extra.as_str(), &[ID]),
                            })
                        } else {
                            Ok(MeshId { id })
                        }
                    }
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match self.0 {
                    DesType::Json => MeshId::from_base64(value).map_err(de::Error::custom),
                    DesType::Cbor => {
                        Err(de::Error::invalid_type(de::Unexpected::Str(value), &self))
                    }
                }
            }
        }

        let visitor = MeshIdVisitor(DesType::from_de(&deserializer));
        deserializer.deserialize_any(visitor)
    }
}

impl From<MeshId> for Vec<u8> {
    fn from(id: MeshId) -> Vec<u8> {
        id.id.to_vec()
    }
}

impl From<&MeshId> for Vec<u8> {
    fn from(id: &MeshId) -> Vec<u8> {
        id.id.to_vec()
    }
}

impl From<SocketAddr> for MeshId {
    fn from(socket: SocketAddr) -> MeshId {
        let mut id: [u8; 32] = [0; 32];
        let port = socket.port();
        let port_bytes = port.to_be_bytes();
        id[0..2].copy_from_slice(&port_bytes);
        match socket.ip() {
            IpAddr::V4(ipv4) => {
                let bytes = ipv4.octets();
                id[2..6].copy_from_slice(&bytes);
            }
            IpAddr::V6(ipv6) => {
                let bytes = ipv6.octets();
                id[2..18].copy_from_slice(&bytes);
            }
        }
        MeshId { id }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "enclave")]
    use alloc::string::String;

    const EXPECTED: MeshId = MeshId {
        id: [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
    };

    #[test]
    fn test_deserialize_json() {
        let forms = [
            // Preferred form, base64 strings.
            "\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA\"",
            "\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\"",
            // Legacy stuff: lists of numbers, or a map of `{"id":MeshId}`.
            "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]",
            r#"{"id": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}"#,
            r#"{"id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"}"#,
            r#"{"id":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="}"#,
        ];

        for form in forms {
            let out: MeshId = serde_json::from_str(form)
                .unwrap_or_else(|err| panic!("failed on {form:?}: {err}"));
            assert_eq!(out, EXPECTED);
        }
    }

    #[test]
    fn test_deserialize_cbor() {
        macro_rules! cbor_pair {
            ($v:expr) => {
                (
                    serde_cbor::to_vec($v).unwrap(),
                    crate::cbor::to_vec_packed($v).unwrap(),
                )
            };
        }

        let forms = [
            {
                #[derive(Serialize)]
                struct MapOfSeq {
                    id: [u8; 32],
                }
                cbor_pair!(&MapOfSeq { id: EXPECTED.id })
            },
            {
                #[derive(Serialize)]
                struct MapOfBytes {
                    id: serde_bytes::ByteBuf,
                }
                cbor_pair!(&MapOfBytes {
                    id: serde_bytes::ByteBuf::from(*&EXPECTED.id)
                })
            },
            {
                // bare Sequence
                cbor_pair!(&EXPECTED.id)
            },
            {
                // bare Bytes
                cbor_pair!(&serde_bytes::ByteBuf::from(*&EXPECTED.id))
            },
            {
                // Possibly useful knowledge, serde_cbor will pack Some<X> just like X. None becomes
                // null, which can't be held directly in a MeshId, and thus cannot be deserialized.
                #[derive(Serialize)]
                struct AsOptionSeq {
                    id: Option<[u8; 32]>,
                }
                cbor_pair!(&AsOptionSeq {
                    id: Some(EXPECTED.id)
                })
            },
        ];

        for (i, (unpacked, packed)) in forms.iter().enumerate() {
            let out: MeshId = serde_cbor::from_slice(&unpacked)
                .unwrap_or_else(|e| panic!("failed to deserialize case {i}, unpacked: {e}"));
            assert_eq!(out, EXPECTED,);

            let out: MeshId = serde_cbor::from_slice(&packed)
                .unwrap_or_else(|e| panic!("failed to deserialize case {i}, packed: {e}"));
            assert_eq!(out, EXPECTED);
        }

        // Just as a sanity check, we'll ensure that MeshIds are not supported as base64 strings in
        // CBOR, as that would just be wasteful and there's no legacy case to support.
        let b64 = EXPECTED.as_base64().to_string().into_bytes();
        let b64_str = String::from_utf8(b64).unwrap();
        let enc = serde_cbor::to_vec(&b64_str).unwrap();
        assert!(serde_cbor::from_slice::<MeshId>(&enc).is_err());
    }

    #[test]
    fn test_serialize_json() {
        // In JSON, assure that serializing a MeshId produces Base64.
        let json = serde_json::to_string(&EXPECTED).unwrap();
        let into_str: String = serde_json::from_str(&json)
            .unwrap_or_else(|err| panic!("json decode of {json} failed: {err}"));
        assert_eq!(MeshId::from_base64(&into_str).unwrap(), EXPECTED);
    }

    #[test]
    fn test_serialize_cbor() {
        // In CBOR, assure that serializing a MeshId looks just like 32 bytes.
        let unpacked = serde_cbor::to_vec(&EXPECTED).unwrap();
        let packed = crate::cbor::to_vec_packed(&EXPECTED).unwrap();
        assert_eq!(unpacked, packed);
        let into_vec: serde_bytes::ByteBuf = serde_cbor::from_slice(&packed).unwrap();
        assert_eq!(&into_vec, &EXPECTED.id);
    }

    #[test]
    fn test_meshid_base64() {
        assert_eq!(base64::encoded_len(32, false).unwrap(), MeshId::BASE64_LEN);

        // Some test id, and the same thing with padding.
        let tests = [
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_-prM",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_-prM=",
        ];

        const TEST_ID: [u8; 32] = [
            234, 37, 101, 34, 134, 164, 131, 39, 11, 240, 11, 27, 103, 54, 126, 12, 35, 169, 137,
            164, 88, 249, 200, 129, 77, 153, 25, 100, 159, 254, 166, 179,
        ];

        for &input in &tests {
            let mesh_id = MeshId::from_base64(input)
                .unwrap_or_else(|err| panic!("failed to decode {input}: {err}"));
            assert_eq!(mesh_id.id, TEST_ID);
        }

        let bad_tests = [
            // Make sure trailing padding doesn't work.
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_-pr=",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_-p==",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_-===",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ_====",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ=====",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr==",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr===",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs=",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs==",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs===",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst=",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst==",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst===",
            // Too short shouldn't work.
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            "ABCDEFGHIJKLMNOP",
            "ABCDEF",
            "",
            // Non-URL-safe base64 characters should not work.
            "6iVlIoakgycL8AsbZzZ/DCOpiaRY-ciBTZkZZJ_-prM",
            "6iVlIoakgycL8AsbZzZ-DCOpiaRY-ciBTZkZZJ+-prM",
            // Other non-base64 characters should not work either.
            "ABCDEFGHIJKLMNO`QRSTUVWXYZabcdefghijklmnopq",
            "ABCDEFGHI#KLMNOPQRSTUVWXYZabcdefghijklmnopq",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZab!defghijklmnopq",
            "ABCDEFGHIJKLMNOPQRSTU WXYZabcdefghijklmnopq",
        ];

        for input in bad_tests {
            if let Ok(s) = MeshId::from_base64(input) {
                panic!("{input:?} yielded {s:?}, expected error");
            }
        }
    }
}
