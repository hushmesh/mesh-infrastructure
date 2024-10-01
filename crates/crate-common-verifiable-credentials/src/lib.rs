#![cfg_attr(feature = "enclave", no_std)]
#[macro_use]
extern crate alloc;
cfg_if::cfg_if! {
    if #[cfg(feature = "enclave")] {
        extern crate common_async_sgx as common_async;
        extern crate common_crypto_sgx as common_crypto;
        extern crate common_messages_sgx as common_messages;
        extern crate common_messages_web_sgx as common_messages_web;
        extern crate common_types_sgx as common_types;
    }
}

pub mod bbs;
mod canonicalize;
mod check;
mod hash;
#[cfg(all(test, feature = "noenclave"))]
mod jff;
mod json_pointer;
#[cfg(all(test, feature = "noenclave"))]
mod ns;
pub mod permanent_resident;
mod select;
mod serialize;
mod skolemize;
mod verify;

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use bbs::add_bbs_derived_proof;
use bbs::is_credential_bbs;
use core::str::FromStr;
use json_ld::RemoteDocument;

use chrono::DateTime;
use fluent_uri::UriRef;
use json_ld::IriBuf;
use serde_json::json;

use common_crypto::HmcDataType;
use common_crypto::HmcKeyType;
use common_types::log_error;
use common_types::time::get_current_time_ms;
use common_types::MeshError;

use crate::check::check_credential;
use crate::check::check_presentation;
pub use crate::hash::bbs_hash_document;
pub use crate::hash::ecdsa_hash_document;
pub use crate::json_pointer::JsonPointerBuf;
use crate::serialize::encode_bls12_381_g2;
use crate::serialize::encode_p256;
use crate::serialize::encode_p384;
pub use crate::verify::verify_credential;

const CREDENTIALS_CONTEXT_V1_URL: &str = "https://www.w3.org/2018/credentials/v1";
const CREDENTIALS_CONTEXT_V2_URL: &str = "https://www.w3.org/ns/credentials/v2";

#[derive(Debug, Clone)]
pub struct Credential(serde_json::Value);

#[derive(Debug, Clone)]
pub struct Presentation(pub serde_json::Value);

#[derive(Debug, Clone)]
pub struct ProofOptions(pub serde_json::Value);

#[derive(Debug, Clone)]
pub struct DataDocument(pub serde_json::Value);

pub async fn create_presentation(
    mut credentials: Option<Vec<Credential>>,
    unix_timestamp: i64,
    call_derive_for_bbs: bool,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
) -> Result<Presentation, MeshError> {
    if call_derive_for_bbs {
        credentials = match credentials {
            Some(credentials) => {
                let mut creds: Vec<Credential> = vec![];
                for cred in credentials.into_iter() {
                    if is_credential_bbs(&cred) {
                        let cred = add_bbs_derived_proof(cred, loader, None).await?;
                        creds.push(cred);
                    } else {
                        creds.push(cred);
                    }
                }
                Some(creds)
            }
            None => None,
        };
    }
    let presentation = match credentials {
        Some(creds) if !creds.is_empty() => {
            let mut v2 = None;
            for cred in &creds {
                match (cred.is_v2(), v2) {
                    (true, Some(false)) | (false, Some(true)) => {
                        return Err(MeshError::BadArgument(
                            "Mixing v1 and v2 credentials is not allowed".to_string(),
                        ));
                    }
                    (true, None) => v2 = Some(true),
                    _ => {}
                }
                check_credential(cred, unix_timestamp)?;
            }
            let cred_context_string = if v2.unwrap_or(false) {
                CREDENTIALS_CONTEXT_V2_URL
            } else {
                CREDENTIALS_CONTEXT_V1_URL
            };
            json!({
                "@context": [cred_context_string],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": creds.into_iter().map(|c| c.0).collect::<Vec<_>>(),
            })
        }
        _ => json!({
            "@context": [CREDENTIALS_CONTEXT_V2_URL],
            "type": ["VerifiablePresentation"],
        }),
    };
    let presentation = Presentation(presentation);
    check_presentation(&presentation)?;
    Ok(presentation)
}

fn encode_paths(path: &str) -> Result<String, MeshError> {
    let path = if path == "/.well-known/did.json" {
        "/"
    } else if path.ends_with("/did.json") {
        path.strip_suffix("did.json").unwrap()
    } else {
        path
    };
    if path == "/" {
        return Ok(String::new());
    }
    let paths = path.split('/').filter(|s| !s.is_empty()).fold(
        String::with_capacity(3 * path.len()),
        |mut paths, s| {
            paths.push(':');
            paths.extend(form_urlencoded::byte_serialize(s.as_bytes()));
            paths
        },
    );
    Ok(paths)
}

fn https_url_to_did_url(url: &str) -> Result<String, MeshError> {
    let url = UriRef::parse(url).map_err(|e| MeshError::BadArgument(e.to_string()))?;
    let scheme = url
        .scheme()
        .ok_or_else(|| log_error!(MeshError::InvalidAddress(format!("{}", url))))?;
    if scheme.as_str() != "https" {
        return Err(MeshError::BadArgument("URL is not HTTPS".to_string()));
    }
    let auth = url
        .authority()
        .ok_or_else(|| log_error!(MeshError::InvalidAddress(format!("{}", url))))?;
    let host = auth.host();
    let base = auth.port().map_or_else(
        || Cow::Borrowed(host),
        |port| format!("{}:{}", host, port).into(),
    );
    let base = format!(
        "did:web:{}",
        form_urlencoded::byte_serialize(base.as_bytes()).collect::<String>()
    );
    let path = encode_paths(url.path().as_str())?;
    Ok(format!("{}{}", base, path))
}

pub fn create_did_document(
    url: &str,
    public_key: &[u8],
    key_type: HmcKeyType,
    key_data_type: HmcDataType,
) -> Result<DataDocument, MeshError> {
    let did = https_url_to_did_url(url)?;
    let multibase = match key_type {
        HmcKeyType::Ecc256 => encode_p256(public_key, key_data_type)?,
        HmcKeyType::Ecc384 => encode_p384(public_key, key_data_type)?,
        HmcKeyType::Bls12381G2 => encode_bls12_381_g2(public_key)?,
        _ => return Err(MeshError::BadArgument("Unsupported key type".to_string())),
    };
    let did_multibase = format!("{}#{}", did, multibase);
    let did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": did_multibase,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase
            }
        ],
        "authentication": [ did_multibase ],
        "assertionMethod": [ did_multibase ],
        "capabilityDelegation": [ did_multibase ],
        "capabilityInvocation": [ did_multibase ],
    });
    Ok(DataDocument(did_document))
}

pub fn now_rfc3339() -> String {
    use chrono::format::SecondsFormat;
    DateTime::from_timestamp_millis(get_current_time_ms())
        .expect("invalid time")
        .to_rfc3339_opts(SecondsFormat::Secs, true /* use_z */)
}

impl Credential {
    pub fn new(credential: serde_json::Value) -> Self {
        Credential(credential)
    }
    pub fn get_value(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn is_v2(&self) -> bool {
        self.0["@context"]
            .as_array()
            .map_or(false, |c| c.iter().any(|c| c == CREDENTIALS_CONTEXT_V2_URL))
    }
}

impl DataDocument {
    pub fn to_string(&self) -> Result<String, MeshError> {
        serde_json::to_string(&self.0).map_err(|e| MeshError::ParseError(e.to_string()))
    }
    pub fn get_id(&self) -> Result<&str, MeshError> {
        self.0
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or(MeshError::BadState)
    }
}

impl Presentation {
    pub fn to_string(&self) -> Result<String, MeshError> {
        serde_json::to_string(&self.0).map_err(|e| MeshError::ParseError(e.to_string()))
    }
}

impl FromStr for Credential {
    type Err = MeshError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map(Credential)
            .map_err(|e| MeshError::ParseError(e.to_string()))
    }
}

impl FromStr for DataDocument {
    type Err = MeshError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map(Self)
            .map_err(|e| MeshError::ParseError(e.to_string()))
    }
}

const DATA_INTEGRITY_V2_URL: &str = "https://w3id.org/security/data-integrity/v2";

pub fn add_proof_value(
    presentation: Presentation,
    proof: serde_json::Value,
) -> Result<Presentation, MeshError> {
    let mut presentation = presentation.0;
    presentation["proof"] = proof;
    Ok(Presentation(presentation))
}

pub fn add_holder(presentation: DataDocument, holder: String) -> Result<DataDocument, MeshError> {
    let mut presentation = presentation.0;

    let context = presentation["@context"]
        .as_array_mut()
        .ok_or_else(|| MeshError::BadArgument("Presentation has no context".to_string()))?;
    if !context.iter().any(|c| {
        matches!(
            c.as_str(),
            Some(DATA_INTEGRITY_V2_URL | CREDENTIALS_CONTEXT_V2_URL)
        )
    }) {
        // only add integrity URL for v1 credentials
        context.push(DATA_INTEGRITY_V2_URL.into());
    }

    presentation["holder"] = holder.into();
    Ok(DataDocument(presentation))
}

pub fn multibase_base58btc(b: &[u8]) -> Result<String, MeshError> {
    // We want to prepare our buffer with 'z' before writing base58 into it. Doing this neatly
    // leads to bs58 aggressively overallocating, so we can be a little tricky...
    let max_b58_len = b.len() * 138 / 100 + 1;
    let mut buf = vec![0; 1 + max_b58_len]; // + 'z'
    buf[0] = b'z';
    let n = bs58::encode(b).onto(&mut buf[1..]).unwrap();
    debug_assert!(n <= buf.len() - 1);
    buf.truncate(n + 1);
    String::from_utf8(buf)
        .map_err(|_| log_error!("bs58 produced non-utf8 output: {}", MeshError::BadState))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_url_to_did_url() {
        assert_eq!(
            https_url_to_did_url("https://example.com"),
            Ok("did:web:example.com".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/?service=bar"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/#someKey"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/?service=bar#someKey"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/foo?service=bar#someKey"),
            Ok("did:web:www.bar.org%3A46443:foo".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/foo+srv?service=bar#someKey"),
            Ok("did:web:www.bar.org%3A46443:foo%2Bsrv".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/.well-known/did.json"),
            Ok("did:web:www.bar.org%3A46443".to_string())
        );
        assert_eq!(
            https_url_to_did_url("https://www.bar.org:46443/foo/did.json"),
            Ok("did:web:www.bar.org%3A46443:foo".to_string())
        );
    }

    #[test]
    fn test_multibase_base58btc() {
        // From https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03#section-3.1
        let out = multibase_base58btc(r#"Multibase is awesome! \o/"#.as_bytes()).unwrap();
        assert_eq!(out, "zYAjKoNbau5KiqmHPmSxYCvn66dA1vLmwbt");
        assert_eq!(out.capacity(), 36);
        assert_eq!(out.len(), 35);

        for (ch, len) in (0..=256).flat_map(|len| [(0u8, len), (0xffu8, len)]) {
            let bytes = vec![ch; len];
            // If anything is awry, it's multibase_base58btc itself that would panic.
            let _ = multibase_base58btc(&bytes).unwrap();
        }
    }
}
