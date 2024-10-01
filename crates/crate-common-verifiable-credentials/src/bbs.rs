use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use base64::prelude::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common_crypto::rng::HmcRng;
use json_ld::IriBuf;
use json_ld::RemoteDocument;
use rand_core::RngCore;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde::ser::SerializeSeq;
use serde::ser::Serializer;
use serde::Deserialize;
use serde::Deserializer;
use serde_bytes::ByteBuf;
use serde_bytes::Bytes;
use serde_cbor::from_slice;
use zkryptium::bbsplus::keys::BBSplusPublicKey;
use zkryptium::schemes::algorithms::BbsBls12381Sha256;
use zkryptium::schemes::generics::PoKSignature;
use zkryptium::utils::pluggable_rng::set_pluggable_rng_maker;
use zkryptium::utils::pluggable_rng::PluggableRng;

use common_types::log_error;
use common_types::MeshError;

use crate::hash::canonicalize_and_group_for_derived_proof;
use crate::json_pointer::JsonPointerBuf;
use crate::serialize::decode_did_key_multibase_raw;
use crate::Credential;
use crate::DataDocument;

pub struct HsmRngMaker;

impl PluggableRng for HsmRngMaker {
    fn new_rng(&self) -> Box<dyn RngCore> {
        Box::new(HmcRng::new())
    }
}

impl HsmRngMaker {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug)]
pub struct BbsBaselineProofComponents {
    pub signature: Vec<u8>,
    pub header: Vec<u8>,
    pub public_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub mandatory_pointers: Vec<String>,
}

#[derive(Debug)]
pub struct BbsDerivedProofComponents {
    pub proof: Vec<u8>,
    pub label_map: BTreeMap<String, String>,
    pub mandatory_indexes: Vec<usize>,
    pub selective_indexes: Vec<usize>,
    pub presentation_header: Vec<u8>,
}

impl<'de> Deserialize<'de> for BbsBaselineProofComponents {
    fn deserialize<D>(deserializer: D) -> Result<BbsBaselineProofComponents, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ComponentsVisitor;

        impl<'de> Visitor<'de> for ComponentsVisitor {
            type Value = BbsBaselineProofComponents;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of 5 elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<BbsBaselineProofComponents, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let signature: ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let header: ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let public_key: ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let hmac_key: ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let mandatory_pointers: Vec<String> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                Ok(BbsBaselineProofComponents {
                    signature: signature.into_vec(),
                    header: header.into_vec(),
                    public_key: public_key.into_vec(),
                    hmac_key: hmac_key.into_vec(),
                    mandatory_pointers,
                })
            }
        }

        deserializer.deserialize_seq(ComponentsVisitor)
    }
}

impl BbsBaselineProofComponents {
    pub fn to_proof_value(&self) -> Result<String, MeshError> {
        let mut cbor_buf = Vec::with_capacity(512);
        // "baseline" prefix
        cbor_buf.extend_from_slice(&[0xd9, 0x5d, 0x02]);

        let mut cbor = serde_cbor::ser::Serializer::new(&mut cbor_buf);
        let mut seq = cbor
            .serialize_seq(Some(5))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(Bytes::new(&self.signature))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(Bytes::new(&self.header))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(Bytes::new(&self.public_key))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(Bytes::new(&self.hmac_key))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(&self.mandatory_pointers)
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.end()
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        let encoded_len = base64::encoded_len(cbor_buf.len(), false)
            .ok_or_else(|| MeshError::ProtocolError("could not calculate encoded length".into()))?;
        let mut multi = String::with_capacity(1 + encoded_len);
        multi.push('u');
        BASE64_URL_SAFE_NO_PAD.encode_string(&cbor_buf, &mut multi);
        Ok(multi)
    }

    pub fn from_proof_value(s: &str) -> Result<Self, MeshError> {
        let s = s
            .strip_prefix('u')
            .ok_or_else(|| MeshError::BadArgument("Invalid format: missing 'u' prefix".into()))?;

        let cbor_buf = BASE64_URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| MeshError::BadArgument(format!("coud not decode - {}", e)))?;
        if cbor_buf.len() < 3 {
            return Err(MeshError::BadArgument(
                "Invalid format: missing 'baseline' prefix".into(),
            ));
        }
        if &cbor_buf[0..3] != &[0xd9, 0x5d, 0x02] {
            return Err(MeshError::BadArgument(format!(
                "Invalid format: missing 'baseline' prefix {:?}",
                &cbor_buf[0..3]
            )));
        }
        let proof: BbsBaselineProofComponents = from_slice(&cbor_buf[3..])
            .map_err(|e| MeshError::BadArgument(format!("coud not decode - {}", e)))?;
        Ok(proof)
    }
}

impl BbsDerivedProofComponents {
    pub fn to_proof_value(&self) -> Result<String, MeshError> {
        let mut cbor_buf = Vec::with_capacity(512);
        cbor_buf.extend_from_slice(&[0xd9, 0x5d, 0x03]);

        let mut cbor = serde_cbor::ser::Serializer::new(&mut cbor_buf);
        let mut seq = cbor
            .serialize_seq(Some(5))
            .map_err(|e| MeshError::ProtocolError(format!("serialized failed - {}", e)))?;

        let label_map: BTreeMap<usize, usize> = self
            .label_map
            .iter()
            .map(|(k, v)| {
                if k.len() < 5 || v.len() < 2 {
                    Err(MeshError::BadArgument("label map values too small".into()))
                } else {
                    let k_num = k[4..]
                        .parse::<usize>()
                        .map_err(|_| MeshError::BadArgument("Invalid key value".into()))?;
                    let v_num = v[1..]
                        .parse::<usize>()
                        .map_err(|_| MeshError::BadArgument("Invalid value".into()))?;
                    Ok((k_num, v_num))
                }
            })
            .collect::<Result<BTreeMap<usize, usize>, MeshError>>()?;

        seq.serialize_element(Bytes::new(&self.proof))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(&label_map)
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(&self.mandatory_indexes)
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(&self.selective_indexes)
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.serialize_element(Bytes::new(&self.presentation_header))
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        seq.end()
            .map_err(|e| MeshError::ProtocolError(format!("serialize failed - {}", e)))?;
        let encoded_len = base64::encoded_len(cbor_buf.len(), false)
            .ok_or_else(|| MeshError::ProtocolError("could not calculate encoded length".into()))?;
        let mut multi = String::with_capacity(1 + encoded_len);
        multi.push('u');
        BASE64_URL_SAFE_NO_PAD.encode_string(&cbor_buf, &mut multi);
        Ok(multi)
    }
}

pub fn install_rng_for_bbs() {
    set_pluggable_rng_maker(Box::new(HsmRngMaker::new()));
}

pub fn is_credential_bbs(credential: &Credential) -> bool {
    credential
        .0
        .get("proof")
        .and_then(|proof| proof.get("cryptosuite"))
        .and_then(|cs| cs.as_str())
        .map(|cs| cs == "bbs-2023")
        .unwrap_or(false)
}

pub async fn add_bbs_derived_proof(
    mut credential: Credential,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    selective_disclosure_fields: Option<Vec<String>>,
) -> Result<Credential, MeshError> {
    let mut old_proof = credential
        .0
        .as_object_mut()
        .and_then(|map| map.remove("proof"))
        .ok_or_else(|| log_error!(MeshError::BadArgument("Missing proof".into())))?;

    let proof_value = old_proof
        .get("proofValue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MeshError::BadArgument("Missing proof value".into()))?;

    let proof_components = BbsBaselineProofComponents::from_proof_value(&proof_value)?;

    let selective_disclosure_pointers = if let Some(selective_disclosure_fields) =
        selective_disclosure_fields
    {
        selective_disclosure_fields
            .iter()
            .map(|k| {
                JsonPointerBuf::new(k.into())
                    .map_err(|e| MeshError::BadArgument(format!("could not canonicalize - {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        credential
            .0
            .as_object()
            .ok_or_else(|| MeshError::BadArgument("Credential is not an object".into()))?
            .keys()
            .filter(|k| !matches!(k.as_str(), "id" | "type" | "issuer" | "proof" | "@context"))
            .map(|k| {
                JsonPointerBuf::new(format!("/{}", k))
                    .map_err(|e| MeshError::BadArgument(format!("could not canonicalize - {}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let verification_method = old_proof
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MeshError::BadArgument("Missing verificationMethod".into()))?;

    let mut public_key = verification_method
        .strip_prefix("did:key:")
        .ok_or_else(|| MeshError::BadArgument("Unknown verificationMethod".to_string()))
        .and_then(|encoded| decode_did_key_multibase_raw(encoded))?;

    // remove first two bytes (codec marker)
    public_key.drain(0..2);

    let mandatory_pointers: Result<Vec<_>, MeshError> = proof_components
        .mandatory_pointers
        .iter()
        .map(|s| {
            JsonPointerBuf::new(s.clone())
                .map_err(|e| MeshError::BadArgument(format!("could not canonicalize - {}", e)))
        })
        .collect();

    let mandatory_pointers = mandatory_pointers?;
    let combined_pointers = [&mandatory_pointers, &*selective_disclosure_pointers].concat();
    let data_doc = DataDocument(credential.0.clone());
    let canonicalized_and_grouped =
        common_async::expect_ready(canonicalize_and_group_for_derived_proof(
            data_doc,
            loader,
            &proof_components.hmac_key,
            [
                &mandatory_pointers,
                &selective_disclosure_pointers,
                &combined_pointers,
            ],
        ))
        .expect("canonicalize_and_group3 was not ready")
        .map_err(|e| MeshError::BadArgument(format!("could not canonicalize - {}", e)))?;

    let mandatory_relative_indexes = {
        let combined_indexes = canonicalized_and_grouped.groups[2]
            .matching
            .keys()
            .collect::<Vec<_>>();
        let mandatory_match = &canonicalized_and_grouped.groups[0].matching;
        mandatory_match
            .keys()
            .map(|k| {
                combined_indexes.binary_search(&k).map_err(|_| {
                    MeshError::RequestFailed(format!(
                        "could not find {} in {:?}",
                        k, combined_indexes
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let non_mandatory_relative_indexes = {
        let non_mandatory_indexes = canonicalized_and_grouped.groups[0]
            .non_matching
            .keys()
            .collect::<Vec<_>>();
        let selective_match = &canonicalized_and_grouped.groups[1].matching;
        selective_match
            .keys()
            .filter_map(|k| non_mandatory_indexes.binary_search(&k).ok())
            .collect::<Vec<_>>()
    };

    let bbs_messages = canonicalized_and_grouped.groups[0]
        .non_matching
        .values()
        .map(|q| format!("{q} .\n").into_bytes())
        .collect::<Vec<_>>();

    let pk = BBSplusPublicKey::from_bytes(&public_key)
        .map_err(|e| MeshError::BadArgument(format!("could not decode public key - {}", e)))?;
    let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
        &pk,
        &proof_components.signature,
        Some(&proof_components.header),
        None,
        Some(&bbs_messages),
        Some(&non_mandatory_relative_indexes), // indexes
    )
    .map_err(|e| MeshError::BadArgument(format!("coud not gen proof - {}", e)))?;

    let bbs_proof = proof.to_bytes();
    let label_map: BTreeMap<String, String> = canonicalized_and_grouped
        .label_map
        .iter()
        .filter_map(|(k, v)| {
            canonicalized_and_grouped
                .hmac_label_map
                .get(k)
                .map(|entry| {
                    (
                        v.trim_start_matches("_:").to_string(),
                        entry.trim_start_matches("_:").to_string(),
                    )
                })
        })
        .collect();

    let derived_coponents = BbsDerivedProofComponents {
        proof: bbs_proof,
        label_map,
        mandatory_indexes: mandatory_relative_indexes,
        selective_indexes: non_mandatory_relative_indexes,
        presentation_header: vec![],
    };
    let proof_value = derived_coponents.to_proof_value()?;
    old_proof["proofValue"] = proof_value.into();
    credential.0["proof"] = old_proof;

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use crate::bbs::add_bbs_derived_proof;
    use crate::bbs::BbsBaselineProofComponents;
    use crate::permanent_resident;
    use crate::Credential;
    use common_crypto::rng::TestHmcRng;
    use core::str::FromStr;
    use rand_core::RngCore;
    use zkryptium::utils::pluggable_rng::set_pluggable_rng_maker;
    use zkryptium::utils::pluggable_rng::PluggableRng;

    pub struct TestHsmRngMaker;

    impl PluggableRng for TestHsmRngMaker {
        fn new_rng(&self) -> Box<dyn RngCore> {
            Box::new(TestHmcRng::new())
        }
    }

    impl TestHsmRngMaker {
        pub fn new() -> Self {
            Self
        }
    }

    #[test]
    fn test_cbor_to_proof_value() {
        let signature = vec![1u8; 80];
        let header = vec![2u8; 64];
        let public_key = vec![3u8; 96];
        let hmac_key = vec![4u8; 32];
        let mandatory_pointers = vec!["/a".into(), "/b".into()];

        let comp = BbsBaselineProofComponents {
            signature,
            header,
            public_key,
            hmac_key,
            mandatory_pointers,
        };

        // As a spot check, this can be generated with Python(3),
        //   >>> import cbor2
        //   >>> t = [b'\x01' * 80, b'\x02' * 64, b'\x03' * 96, b'\x04' * 32, ["/a", "/b"]]
        //   >>> 'u' + str(base64.urlsafe_b64encode(b'\xd9\x5d\x02' + cbor2.dumps(t)), 'utf-8').rstrip('=')
        const EXPECTED: &str = "u2V0ChVhQAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ\
            EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFYQAICAgICAgICAgICAgICAgICAgICA\
            gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJYYAMDAwMDAwMDAwMDAwMDAwMD\
            AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM\
            DAwMDAwMDAwMDAwMDAwMDA1ggBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBASCYi9hYi9i";

        assert_eq!(comp.to_proof_value().unwrap(), EXPECTED);
    }

    #[test]
    fn test_cbor_from_proof_value() {
        const SIG: &str = "u2V0ChVhQAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ\
            EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFYQAICAgICAgICAgICAgICAgICAgICA\
            gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJYYAMDAwMDAwMDAwMDAwMDAwMD\
            AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM\
            DAwMDAwMDAwMDAwMDAwMDA1ggBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBASCYi9hYi9i";

        let res = BbsBaselineProofComponents::from_proof_value(SIG).unwrap();
        assert_eq!(res.signature, vec![1u8; 80]);
        assert_eq!(res.header, vec![2u8; 64]);
        assert_eq!(res.public_key, vec![3u8; 96]);
        assert_eq!(res.hmac_key, vec![4u8; 32]);
        assert_eq!(
            res.mandatory_pointers,
            vec!["/a".to_string(), "/b".to_string()]
        );
    }

    #[test]
    fn test_derived_proof() {
        const CRED: &str = r#"{
            "@context": [
               "https://www.w3.org/2018/credentials/v1",
               "https://w3id.org/citizenship/v1",
               "https://w3id.org/security/data-integrity/v2"
            ],
            "id": "urn:uuid:6d120c1f-5f28-481f-96b5-848657389c9a",
            "type": [
               "VerifiableCredential",
               "PermanentResidentCard"
            ],
            "issuer": {
               "id": "did:key:zUC77pQtyd93DCHvcbk7XM88SyyMS7ARoFV1c7ysLL45UnNY4HYVVKQyGuKQrqL4FG3sD4hENXk6gmLoPTGJh3siFJBA9uE1DKS9S32QmXnGL9dxfpoLc9CK8VBWqFhqFuUxcyq"
            },
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Utopia Permanent Resident Card.",
            "issuanceDate": "2024-09-30T12:23:44.000Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
               "id": "did:example:b34ca6cd37bbf23",
               "type": [
                  "PermanentResident",
                  "Person"
               ],
               "givenName": "JANE",
               "familyName": "SMITH",
               "gender": "Female",
               "residentSince": "2015-01-01",
               "lprCategory": "C09",
               "lprNumber": "999-999-999",
               "commuterClassification": "C1",
               "birthCountry": "Arcadia",
               "birthDate": "1978-07-17"
            },
            "proof": {
               "id": "urn:uuid:14ba6d6b-f746-4a26-a0e7-0a32fb6e2059",
               "type": "DataIntegrityProof",
               "verificationMethod": "did:key:zUC77pQtyd93DCHvcbk7XM88SyyMS7ARoFV1c7ysLL45UnNY4HYVVKQyGuKQrqL4FG3sD4hENXk6gmLoPTGJh3siFJBA9uE1DKS9S32QmXnGL9dxfpoLc9CK8VBWqFhqFuUxcyq#zUC77pQtyd93DCHvcbk7XM88SyyMS7ARoFV1c7ysLL45UnNY4HYVVKQyGuKQrqL4FG3sD4hENXk6gmLoPTGJh3siFJBA9uE1DKS9S32QmXnGL9dxfpoLc9CK8VBWqFhqFuUxcyq",
               "cryptosuite": "bbs-2023",
               "proofPurpose": "assertionMethod",
               "proofValue": "u2V0ChVhQh6llm9obuO05iC4bBDzbXRHp4Hq9XatijiLkjc7eVpOc7bigSBkvNNiFYXWPIk5BBqIDohvlQVtz9944v2i93W9dgT5kULBoU-Ay5KVw4TVYQAJgGMuzwR3K6F1ckmfgRANyJPJ2TIEpZKoLjvH_TP8zcyT6oElo-7S6xMWhLBQZX6Zjo_Fkci0sBaVvijjLvyVYYJP-l3Hd3wYhIocKODYQiKI4S4hTVWV1eRO2DQNUOKj8hIoQapzOWfdcZ3g1DDXbgwZ2c0aUzBW7crNj96AJkdiKL4KUC9ZRinzkwJSClZEFX5N_tDsEIZv57WoRWr7IFFggRl1YmsETpQEK3n2f8NZvUCP5NrNJGCy9h3L0YiKuO76BZy9pc3N1ZXI"
            }
         }"#;

        const DERIVED_CRED_PROOF_VALUE: &str = "u2V0DhVkBMLBX9Y86UuOHTGqCCeqBHS10ZZ0pc0Mp7hcf_OUPNOd_U9x8hlSrlekuhcVgtm6UiKeck0Xghk_C5f4lr73lWE4ni-cYT35vf9tx29Dl8HuLqqlZVomUuRL7HfBdaXgiUbAUEQkRH5pUA-UH_5VwMFQpDZEATKdSe9S9f5vHOA_HCvvZD6jbZm_lJ-xMSWOivUkucpYdzLXQZzzi2dY0PWcmPtghf2rqkmZKVoSxVX1kUV4DFXBx1ZyXuT6t32TFj1xMfQC-K2HqVruyaCyfg9cJkODQZBAOlFerzZfvqXvvTOL8dYPB6Idk7jyuZ5gZFB9ymsyI8MWhnbhugwgkhoWcEyWcrxRfgIaI_rOrjliGTdaHT0zGjC2FbmKWTWd2fecuwxvxXccPI5dJEp6TrTCggw4PEpAAAQIDBAUGBwgJCgsMDQ4PQA";

        set_pluggable_rng_maker(Box::new(TestHsmRngMaker::new()));
        let mut loader = permanent_resident::new_permanent_resident_loader();
        let cred: Credential = Credential::from_str(CRED).unwrap();
        let derived_cred =
            common_async::expect_ready(add_bbs_derived_proof(cred, &mut loader, None))
                .expect("derive cred failed")
                .unwrap();
        let proof_value = derived_cred
            .0
            .get("proof")
            .and_then(|p| p.get("proofValue"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(proof_value, DERIVED_CRED_PROOF_VALUE);
    }
}
