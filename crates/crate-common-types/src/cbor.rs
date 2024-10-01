use alloc::string::ToString;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use crate::MeshError;

/// Built without its `"std"` feature, [`serde_cbor::ser::to_vec_packed`] is not included!  It is
/// clear `no_std` was not in mind when [`serde_cbor`] was first written as its `to_vec_packed` is
/// implemented in terms of [`std::io::Write`], even though that's fundamentally not necessary.
pub fn to_vec_packed<S: Serialize>(s: &S) -> Result<Vec<u8>, MeshError> {
    let mut v = VecWriter(Vec::with_capacity(64));
    let mut ser = serde_cbor::ser::Serializer::new(&mut v).packed_format();
    s.serialize(&mut ser)
        .map_err(|e| MeshError::ParseError(e.to_string()))?;
    Ok(v.0)
}

struct VecWriter(Vec<u8>);

impl serde_cbor::ser::Write for VecWriter {
    type Error = serde_cbor::Error;
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

/// A wrapper type to provide `serde::{Deserialize, Serialize}` for a `SocketAddr` when `serde` is
/// built without the `"std"` feature.  It shall be encoded and decoded exactly how a
/// `core::net::SocketAddr` would have been.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct SocketAddr(core::net::SocketAddr);

impl Serialize for SocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.0.to_string())
        } else {
            // Match serde's impl of Serialize for SocketAddr...
            match &self.0 {
                core::net::SocketAddr::V4(addr) => {
                    let tup = (addr.ip().octets(), addr.port());
                    serializer.serialize_newtype_variant("SocketAddr", 0, "V4", &tup)
                }
                core::net::SocketAddr::V6(addr) => {
                    let tup = (addr.ip().octets(), addr.port());
                    serializer.serialize_newtype_variant("SocketAddr", 1, "V6", &tup)
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for SocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> serde::de::Visitor<'de> for StrVisitor {
            type Value = core::net::SocketAddr;
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("socket addr")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                s.parse()
                    .map_err(|_| serde::de::Error::custom("invalid socket address"))
            }
        }

        struct EnumVisitor;

        impl<'de> serde::de::Visitor<'de> for EnumVisitor {
            type Value = core::net::SocketAddr;
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("socket addr")
            }
            fn visit_enum<A: serde::de::EnumAccess<'de>>(
                self,
                data: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::VariantAccess;
                #[derive(Deserialize)]
                enum Kind {
                    V4 = 0,
                    V6 = 1,
                }
                match data.variant()? {
                    (Kind::V4, v) => {
                        let (octets, port): ([u8; 4], u16) = v.newtype_variant()?;
                        let s4 = core::net::SocketAddrV4::new(octets.into(), port);
                        Ok(core::net::SocketAddr::V4(s4))
                    }
                    (Kind::V6, v) => {
                        let (octets, port): ([u8; 16], u16) = v.newtype_variant()?;
                        // Note: serde's impl for non-human readable encodings of SocketAddrV6 does
                        // not include its scope ID.
                        let s6 = core::net::SocketAddrV6::new(octets.into(), port, 0, 0);
                        Ok(core::net::SocketAddr::V6(s6))
                    }
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(StrVisitor).map(Self)
        } else {
            deserializer
                .deserialize_enum("SocketAddr", &["V4", "V6"], EnumVisitor)
                .map(Self)
        }
    }
}

impl From<core::net::SocketAddr> for SocketAddr {
    fn from(addr: core::net::SocketAddr) -> Self {
        Self(addr)
    }
}

impl From<SocketAddr> for core::net::SocketAddr {
    fn from(addr: SocketAddr) -> Self {
        addr.0
    }
}

impl core::ops::Deref for SocketAddr {
    type Target = core::net::SocketAddr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    /* these test cases were generated by a helper program that used serde with its "std" impl for
     * SocketAddr...
         fn main() {
            let addrs = [
                "0.0.0.0:0",
                "0.0.0.0:65535",
                "1.2.3.4:5678",
                "255.255.255.255:65535",
                "255.255.255.255:0",
                "[::]:0",
                "[::]:65535",
                "[1:2:3:4:5:6:7:8]:9101",
                "[12:34::ab:cdef]:0",
                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:0",
            ];
            for a in addrs {
                let addr: core::net::SocketAddr = a.parse().unwrap_or_else(|err| panic!("{a:?}: {err}"));
                assert_eq!(addr.to_string(), a, "{a:?} is not normalized");
                let v = serde_cbor::ser::to_vec_packed(&addr).unwrap();
                println!("({a:?}, &{v:?}),");
                let json = serde_json::to_string(&addr).unwrap();
                let json_str: &str = serde_json::from_str(&json).unwrap();
                assert_eq!(json_str, a);
            }
        }
    */
    const CASES: &[(&str, &[u8])] = &[
        ("0.0.0.0:0", &[161, 98, 86, 52, 130, 132, 0, 0, 0, 0, 0]),
        (
            "0.0.0.0:65535",
            &[161, 98, 86, 52, 130, 132, 0, 0, 0, 0, 25, 255, 255],
        ),
        (
            "1.2.3.4:5678",
            &[161, 98, 86, 52, 130, 132, 1, 2, 3, 4, 25, 22, 46],
        ),
        (
            "255.255.255.255:65535",
            &[
                161, 98, 86, 52, 130, 132, 24, 255, 24, 255, 24, 255, 24, 255, 25, 255, 255,
            ],
        ),
        (
            "255.255.255.255:0",
            &[
                161, 98, 86, 52, 130, 132, 24, 255, 24, 255, 24, 255, 24, 255, 0,
            ],
        ),
        (
            "[::]:0",
            &[
                161, 98, 86, 54, 130, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (
            "[::]:65535",
            &[
                161, 98, 86, 54, 130, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255,
                255,
            ],
        ),
        (
            "[1:2:3:4:5:6:7:8]:9101",
            &[
                161, 98, 86, 54, 130, 144, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 25, 35,
                141,
            ],
        ),
        (
            "[12:34::ab:cdef]:0",
            &[
                161, 98, 86, 54, 130, 144, 0, 18, 0, 24, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 171,
                24, 205, 24, 239, 0,
            ],
        ),
        (
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            &[
                161, 98, 86, 54, 130, 144, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255,
                24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255,
                24, 255, 25, 255, 255,
            ],
        ),
        (
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:0",
            &[
                161, 98, 86, 54, 130, 144, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255,
                24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255, 24, 255,
                24, 255, 0,
            ],
        ),
    ];

    #[test]
    fn test_cbor_encoding() {
        for &(s, enc) in CASES {
            let std_addr: core::net::SocketAddr = s
                .parse()
                .unwrap_or_else(|e| panic!("could not parse {s:?}: {e}"));

            let cbor_addr = super::SocketAddr(std_addr);
            let our_encoding = super::to_vec_packed(&cbor_addr).unwrap();

            assert_eq!(our_encoding, enc);

            let round_trip: super::SocketAddr = serde_cbor::from_slice(&enc).unwrap();

            assert_eq!(round_trip.0, std_addr);
        }
    }

    #[test]
    fn test_json_encoding() {
        for &(s, _) in CASES {
            let std_addr: core::net::SocketAddr = s
                .parse()
                .unwrap_or_else(|e| panic!("could not parse {s:?}: {e}"));
            let json_str = serde_json::to_string(&s).unwrap();
            let cbor_addr = super::SocketAddr(std_addr);
            let to_json = serde_json::to_string(&cbor_addr).unwrap();
            assert_eq!(to_json, json_str, "{s:?}");
            let from_json: super::SocketAddr = serde_json::from_str(&to_json).unwrap();
            assert_eq!(from_json.0, std_addr);
        }
    }
}
