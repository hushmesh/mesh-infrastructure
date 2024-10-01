use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use common_async::send_message;
use common_crypto::mesh_generate_mesh_id;
use common_crypto::HmcDataType;
use common_crypto::HmcHashType;
use common_messages_web::https_client_messages::CallEndpointRequest;
use common_types::log_error;
use common_types::MeshError;
use common_types::MeshId;

use hashbrown::HashSet;
use json_ld::IriBuf;
use json_ld::RemoteDocument;
use lazy_static::lazy_static;
use serde_json::json;

use crate::check::check_credential;
use crate::ecdsa_hash_document;
use crate::permanent_resident;
use crate::serialize::decode_did_key_multibase;
use crate::Credential;
use crate::DataDocument;
use crate::ProofOptions;
use crate::DATA_INTEGRITY_V2_URL;

lazy_static! {
    static ref CRYPTOSUITE_ALLOWLIST: HashSet<&'static str> =
        HashSet::from(["ecdsa-rdfc-2019", "bbs-2023"]);
}

pub async fn verify_credential(
    credential: &Credential,
    unix_timestamp: i64,
    source_id: MeshId,
    connector_enclave_id: MeshId,
) -> Result<(), MeshError> {
    verify_credential_internal(
        credential,
        unix_timestamp,
        permanent_resident::new_permanent_resident_loader(),
        source_id,
        connector_enclave_id,
    )
    .await
}

pub(crate) async fn verify_credential_internal(
    credential: &Credential,
    unix_timestamp: i64,
    mut loader: BTreeMap<IriBuf, RemoteDocument>,
    source_id: MeshId,
    connector_enclave_id: MeshId,
) -> Result<(), MeshError> {
    let proof_context = json!(DATA_INTEGRITY_V2_URL);
    check_credential(&credential, unix_timestamp)?;

    let mut unsecured_credential = credential.0.clone();

    // Pull the proof(s) out of the credential
    let mut proof_json = unsecured_credential
        .as_object_mut()
        .ok_or_else(|| MeshError::BadArgument("Credential is not an object".to_string()))?
        .remove("proof")
        .ok_or_else(|| MeshError::BadArgument("Credential has no proof".to_string()))?;

    // Remove the DATA_INTEGRITY_V2_URL context
    unsecured_credential["@context"]
        .as_array_mut()
        .ok_or_else(|| MeshError::BadArgument("Credential has no context array".to_string()))?
        .retain(|context| context != &proof_context);

    let mut proofs = vec![];
    if proof_json.is_array() {
        proofs.append(proof_json.as_array_mut().unwrap());
    } else if proof_json.is_object() {
        proofs.push(proof_json);
    } else {
        return Err(MeshError::BadArgument(
            "Proof is not an array or object".to_string(),
        ));
    };
    let mut verified = false;
    for mut proof in proofs {
        let cryptosuite = proof["cryptosuite"]
            .as_str()
            .ok_or_else(|| MeshError::BadArgument("cryptosuite is not a string".to_string()))?;
        if !CRYPTOSUITE_ALLOWLIST.contains(cryptosuite) {
            continue;
        }
        let is_ecdsa = cryptosuite == "ecdsa-rdfc-2019";
        if proof["type"] != "DataIntegrityProof" {
            continue;
        }
        if proof["proofPurpose"] != "assertionMethod" {
            continue;
        }
        // Pull the proofValue out of the proof
        let proof_value = proof
            .as_object_mut()
            .ok_or_else(|| MeshError::BadArgument("Proof is not an object".to_string()))?
            .remove("proofValue")
            .ok_or_else(|| MeshError::BadArgument("Proof has no proofValue".to_string()))?
            .as_str()
            .ok_or_else(|| MeshError::BadArgument("proofValue is not a string".to_string()))?
            .to_string();

        let verification_method = proof
            .as_object()
            .ok_or_else(|| MeshError::BadArgument("Proof is not an object".to_string()))?
            .get("verificationMethod")
            .ok_or_else(|| MeshError::BadArgument("Proof has no verificationMethod".to_string()))?
            .as_str()
            .ok_or_else(|| {
                MeshError::BadArgument("verificationMethod is not a string".to_string())
            })?;

        let public_key = if verification_method.starts_with("did:web:") {
            fetch_did_web(verification_method, source_id, connector_enclave_id).await?
        } else if let Some(encoded) = verification_method.strip_prefix("did:key:") {
            decode_did_key_multibase(encoded, HmcDataType::Der)?
        } else {
            return Err(MeshError::BadArgument(
                "Unknown verificationMethod".to_string(),
            ));
        };
        if is_ecdsa {
            let hash = common_async::expect_ready(ecdsa_hash_document(
                DataDocument(unsecured_credential.clone()),
                ProofOptions(proof.clone()),
                &mut loader,
                HmcHashType::Sha256,
            ))
            .map_err(|_| {
                log_error!("ecdsa_hash_document was not ready: {}", MeshError::BadState)
            })??;

            {
                _ = public_key;
                _ = hash;
                _ = proof_value;
            }
        }
        verified = true;
    }
    if verified {
        Ok(())
    } else {
        Err(MeshError::BadArgument("No recognizable proofs".to_string()))
    }
}

fn did_web_to_url(id: &str) -> Result<String, MeshError> {
    let url = id.strip_prefix("did:web:").ok_or_else(|| {
        MeshError::BadArgument("did:web: verificationMethod is not a string".to_string())
    })?;
    let mut url = url.replace(":", "/");
    if url.contains("%3A") {
        url = url.replace("%3A", ":");
    }
    if url.contains("%3a") {
        url = url.replace("%3a", ":");
    }
    let suffix = if url.contains("/") {
        "/did.json"
    } else {
        "/.well-known/did.json"
    };
    Ok(["https://", &url, suffix].concat())
}

async fn fetch_did_web(
    id: &str,
    source_id: MeshId,
    connector_enclave_id: MeshId,
) -> Result<Vec<u8>, MeshError> {
    let url = did_web_to_url(id)?;
    let request_id = mesh_generate_mesh_id()?;
    let request = CallEndpointRequest::build_request(
        request_id,
        source_id,
        connector_enclave_id,
        url,
        "GET".into(),
        None,
        None::<Vec<_>>,
        None::<Vec<_>>,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
    )?;
    let response = send_message(request, None).await?;
    if !response.is_success() {
        return Err(MeshError::RequestFailed(format!(
            "did:web request failed: {}",
            response
                .header
                .status_message
                .unwrap_or_else(|| "no status message".to_string())
        )));
    }
    if response.payload.is_none() {
        return Err(MeshError::RequestFailed(
            "did:web response is empty".to_string(),
        ));
    }
    let document: serde_json::Value =
        serde_json::from_slice(&response.payload.unwrap()).map_err(|e| {
            MeshError::ParseError(format!("did:web response is not JSON: {}", e.to_string()))
        })?;
    let key_list = match document.get("verificationMethod") {
        Some(serde_json::Value::Array(values)) => values.as_slice(),
        Some(value @ serde_json::Value::Object(_)) => core::slice::from_ref(value),
        _ => {
            return Err(MeshError::ParseError(
                "did:web response has no verificationMethod".to_string(),
            ))
        }
    };
    let key = key_list.iter().find(|obj| obj["id"] == id).ok_or_else(|| {
        MeshError::ParseError("did:web response has no matching verificationMethod".to_string())
    })?;

    if key["type"] != "Multikey" {
        return Err(MeshError::ParseError(
            "did:web key with matching id is not type Multikey".to_string(),
        ));
    }
    let multibase = key["publicKeyMultibase"].as_str().ok_or_else(|| {
        MeshError::ParseError("did:web key has no publicKeyMultibase".to_string())
    })?;
    decode_did_key_multibase(multibase, HmcDataType::Der)
}

#[cfg(all(test, feature = "noenclave"))]
mod async_tests {

    use common_types::time::get_current_time_ms;
    use common_types::MeshId;
    use serde_json::json;

    use super::did_web_to_url;
    use super::verify_credential_internal;

    #[test]
    fn test_did_web_to_url() {
        assert_eq!(
            did_web_to_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_to_url("did:web:w3c-ccg.github.io:user:alice").unwrap(),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
        assert_eq!(
            did_web_to_url("did:web:example.com%3A3000:user:alice").unwrap(),
            "https://example.com:3000/user/alice/did.json"
        );
        assert_eq!(
            did_web_to_url("did:web:example.com%3a3000:user:alice").unwrap(),
            "https://example.com:3000/user/alice/did.json"
        );
    }

    #[test]
    fn test_verify_credential() {
        let input = json!(
            {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json",
                  "https://w3id.org/security/data-integrity/v2"
                ],
                "type": [
                  "VerifiableCredential",
                  "OpenBadgeCredential"
                ],
                "issuer": {
                  "type": "Profile",
                  "id": "did:key:zDnaeY8JtVozcU5gpybKqKwEQWM9RhEkC9CumwYV92T18aWub",
                  "name": "Jobs for the Future (JFF)",
                  "url": "https://www.jff.org/",
                  "image": "https://kayaelle.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png"
                },
                "issuanceDate": "2024-08-07T00:20:54.678Z",
                "credentialSubject": {
                  "type": "AchievementSubject",
                  "id": "did:key:123",
                  "achievement": {
                    "type": "Achievement",
                    "name": "Our Wallet Passed JFF Plugfest #1 2022",
                    "description": "This wallet can display this Open Badge 3.0",
                    "criteria": {
                      "type": "Criteria",
                      "narrative": "The first cohort of the JFF Plugfest 1 in May/June of 2021 collaborated to push interoperability of VCs in education forward."
                    },
                    "image": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/plugfest-1-badge-image.png"
                  }
                },
                "id": "https://https://vcplayground.org/credential/pMh4497KNbduoWjwQ8_k9",
                "proof": [
                  {
                    "type": "DataIntegrityProof",
                    "created": "2024-08-07T00:20:54Z",
                    "verificationMethod": "did:key:zDnaeY8JtVozcU5gpybKqKwEQWM9RhEkC9CumwYV92T18aWub#zDnaeY8JtVozcU5gpybKqKwEQWM9RhEkC9CumwYV92T18aWub",
                    "cryptosuite": "ecdsa-rdfc-2019",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z3YLAePJ4SBWuoSeuHhXNSP3KoNv1hF1iacGEnCGgJ2AZyAMEjLhzvUAzQia4snNUFbTTpErnbnzf7kM9cMixikUd"
                  },
                  {
                    "id": "urn:uuid:0afc7c31-37c6-4743-9203-a75dbb6566b2",
                    "type": "DataIntegrityProof",
                    "created": "2024-08-07T00:20:55Z",
                    "verificationMethod": "did:key:zDnaeY8JtVozcU5gpybKqKwEQWM9RhEkC9CumwYV92T18aWub#zDnaeY8JtVozcU5gpybKqKwEQWM9RhEkC9CumwYV92T18aWub",
                    "cryptosuite": "ecdsa-sd-2023",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "u2V0AhVhAuoc6sUDrYg4EnCoNi_QA3WDKZVnY1kdyu8moW99PTOoZe849LrumYSAa-t3kvXAn8h3q9yXz-14gx2LjcOgQ31gjgCQCvj1cDO_J4Qqp050HG3xvsLXb4yapFyEZNHhrIknxd01YIIGXWRCw7mj0vp9ZHveSPrVDKSO6doP6jEOmp6aDts7bilhA1Q5h-0eyJ3IvfK6xMjqVAW33G9cXutvVeX2OWwbIqV93JoWNCNKzXlsefgExFEleK5OVrxhnV-Ww3mQ4sHtEPlhAW5dLXzAI5BwRtWeboFqJGl3GYd3vqy65-CW3ahFE5YQhegCs0biyu4LbD5ZEl-1rVGx692_p8NKcZKwo-frJo1hA4m_zFxo4vpDSXW7u5ndzmSRzFhGkMtGhkz1PQMsi6pUhWCPfK276BD3fMj3HsJOEs65ZNVI1MI2fG5BKccvRsFhAn7sPm_hvMCyl0tQuoweeBOmSZrqzY71vI_6nxqUFmRzp14VAYPvII81feXhk-LlRsqpsBseJpii2BsJRW7sMcVhAvrRj_c96F4JKqOX4Hzx2HbfgpyiR4bIqq5JEHL_1QHDeDj9RoDCBTuARVsBQRjklmTZY-tl7V-a8B3gXBWCeBlhAFPYGPYe-wyiE_UGyazpljsaj2YMzRvbww69SUYMOCuCE7h-25rHTwVnhlccubIw666ShkTPFSzn7eWf1AKxIrVhA2BjIWXZrSBbKZob0lDUIMKZVMOUDaqtWHA2GXSrukNun_bRMMmw7VVmevck879DEnuPbqyydPtpUrz5BBlQ2plhAu3JZfodYpzEdJETy41kTqw3rSn0wcanTuA_FUPfF7gPTo3YS4f1BFaCVxKnsrLOlzJhHhrQpjnAPuACxf-Vn91hAgWsjGag_vy4F4zbTP1ndZUeGs7wnm7KVbBqLe1gAwYoXn6ko7F2ba9-gi0uKqeMiM7CrV9VT6noC9Yjhue8L91hAb6jyRiPvgYGcK-WSUtAC0sJDLzaCTqEltGtrAlWLEFVpmb5gJJncnaIhhCEu10JAnjeTa95mzROoCLYWqom_1oJnL2lzc3Vlcm0vaXNzdWFuY2VEYXRl"
                  }
                ]
              }
        );
        let unix_timestamp = get_current_time_ms() / 1000;
        let result = common_async::expect_ready(verify_credential_internal(
            &crate::Credential(input),
            unix_timestamp,
            crate::jff::new_jff_loader(),
            MeshId::empty(),
            MeshId::empty(),
        ))
        .expect("future was not ready")
        .unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn test_verify_credentials_can_task() {
        use core::future::Future;
        // Ensures verify_credential is Send + Sync...
        fn sync_send<T>(_t: impl Future<Output = T> + Send + Sync) {}
        sync_send(super::verify_credential(
            &crate::Credential(serde_json::Value::Null),
            get_current_time_ms() / 1000,
            MeshId::empty(),
            MeshId::empty(),
        ));
    }
}
