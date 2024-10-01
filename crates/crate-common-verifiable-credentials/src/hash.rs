use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Write;

use chrono::DateTime;
use common_crypto::HmcHashType;
use hashbrown::HashMap;
use hashbrown::HashSet;
use json_ld::context_processing::Options;
use json_ld::context_processing::Process;
use json_ld::context_processing::Processed;
use json_ld::syntax::Context;
use json_ld::syntax::TryFromJson;
use json_ld::BlankIdBuf;
use json_ld::Compact;
use json_ld::IriBuf;
use json_ld::JsonLdProcessor;
use json_ld::RemoteDocument;
use rdf_types::generator;
use rdf_types::LexicalQuad;
use ssi::crypto::hashes::sha::Sha;

use common_crypto::mesh_sha256;
use common_crypto::mesh_sha384;
use common_types::MeshError;

use crate::canonicalize::label_replacement_canonicalize_nquads;
use crate::json_pointer::JsonPointerBuf;
use crate::select::select_canonical_nquads;
use crate::skolemize::deskolemize_nquads;
use crate::skolemize::Skolemize;
use crate::DataDocument;
use crate::ProofOptions;

pub(crate) struct Sha384Hasher;

impl Sha for Sha384Hasher {
    fn hash(data: &[u8]) -> Vec<u8> {
        mesh_sha384(data).unwrap()
    }
}

pub(crate) struct Sha256Hasher;

impl Sha for Sha256Hasher {
    fn hash(data: &[u8]) -> Vec<u8> {
        mesh_sha256(data).unwrap()
    }
}

async fn canonical_form(
    value: serde_json::Value,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    hash_type: HmcHashType,
) -> Result<String, MeshError> {
    let input: RemoteDocument<IriBuf, json_syntax::Value> = RemoteDocument::new(
        Option::<IriBuf>::None,
        Some("application/ld+json".parse().unwrap()),
        json_ld::syntax::Value::from(value),
    );
    let expanded = input
        .expand(loader)
        .await
        .map_err(|e| MeshError::BadArgument(format!("Failed to expand JSON-LD: {}", e)))?;

    let Ok(quads) = linked_data::to_lexical_quads(rdf_types::generator::Blank::new(), &expanded)
    else {
        return Err(MeshError::BadArgument(
            "Failed to convert to quads".to_string(),
        ));
    };

    let canonical_form = match hash_type {
        HmcHashType::Sha256 => ssi::rdf::urdna2015::normalize::<Sha256Hasher, _>(
            quads.iter().map(|quad| quad.as_lexical_quad_ref()),
        )
        .into_nquads(),
        HmcHashType::Sha384 => ssi::rdf::urdna2015::normalize::<Sha384Hasher, _>(
            quads.iter().map(|quad| quad.as_lexical_quad_ref()),
        )
        .into_nquads(),
        _ => return Err(MeshError::BadArgument("Unsupported hash type".into())),
    };
    Ok(canonical_form)
}

// Use new_permanent_resident_loader() to generate the loader.
pub async fn ecdsa_hash_document(
    document: DataDocument,
    options: ProofOptions,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    hash_type: HmcHashType,
) -> Result<Vec<u8>, MeshError> {
    let mut options = options;
    if !document.0.is_object() {
        return Err(MeshError::BadArgument(
            "Document is not an object".to_string(),
        ));
    }
    if !options.0.is_object() {
        return Err(MeshError::BadArgument(
            "Options is not an object".to_string(),
        ));
    }
    if options.0["type"] != "DataIntegrityProof" {
        return Err(MeshError::BadArgument(
            "Options type is not DataIntegrityProof".to_string(),
        ));
    }
    if options.0["cryptosuite"] != "ecdsa-rdfc-2019" {
        return Err(MeshError::BadArgument(
            "Options cryptosuite is not ecdsa-rdfc-2019".to_string(),
        ));
    }
    match options.0.get("created") {
        None | Some(serde_json::Value::Null) => {} // is null needed?
        Some(serde_json::Value::String(created)) => {
            if let Err(_) = DateTime::parse_from_rfc3339(created) {
                return Err(MeshError::BadArgument(
                    "Options 'created' property is not a valid RFC3339 date".to_string(),
                ));
            }
        }
        Some(_) => {
            return Err(MeshError::BadArgument(
                "Options 'created' property is not a string".to_string(),
            ));
        }
    }

    options.0["@context"] = document.0["@context"].clone();
    let (options_hash, claims_hash) = match hash_type {
        HmcHashType::Sha256 => (
            mesh_sha256(canonical_form(options.0, loader, hash_type).await?)?,
            mesh_sha256(canonical_form(document.0, loader, hash_type).await?)?,
        ),
        HmcHashType::Sha384 => (
            mesh_sha384(canonical_form(options.0, loader, hash_type).await?)?,
            mesh_sha384(canonical_form(document.0, loader, hash_type).await?)?,
        ),
        _ => return Err(MeshError::BadArgument("Unsupported hash type".into())),
    };
    Ok([options_hash, claims_hash].concat())
}

pub struct BBSHashResult {
    // not sure whether matching quads are needed
    pub matching: Vec<LexicalQuad>,
    pub non_matching: Vec<LexicalQuad>,
    pub proof_options_hash: Vec<u8>,
    pub mandatory_hash: Vec<u8>,
}

pub async fn bbs_hash_document(
    document: DataDocument,
    options: ProofOptions,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    hmac_key: &[u8; 32],
    mandatory_pointers: &[JsonPointerBuf],
) -> Result<BBSHashResult, MeshError> {
    let mut options = options;
    if !document.0.is_object() {
        return Err(MeshError::BadArgument(
            "Document is not an object".to_string(),
        ));
    }
    if !options.0.is_object() {
        return Err(MeshError::BadArgument(
            "Options is not an object".to_string(),
        ));
    }
    if options.0["type"] != "DataIntegrityProof" {
        return Err(MeshError::BadArgument(
            "Options type is not DataIntegrityProof".to_string(),
        ));
    }
    if options.0["cryptosuite"] != "bbs-2023" {
        return Err(MeshError::BadArgument(
            "Options cryptosuite is not bbs-2023".to_string(),
        ));
    }
    match options.0.get("created") {
        None | Some(serde_json::Value::Null) => {} // is null needed?
        Some(serde_json::Value::String(created)) => {
            if let Err(_) = DateTime::parse_from_rfc3339(created) {
                return Err(MeshError::BadArgument(
                    "Options 'created' property is not a valid RFC3339 date".to_string(),
                ));
            }
        }
        Some(_) => {
            return Err(MeshError::BadArgument(
                "Options 'created' property is not a string".to_string(),
            ));
        }
    }
    options.0["@context"] = document.0["@context"].clone();

    let canonicalized_grouped =
        canonicalize_and_group(document, loader, hmac_key, mandatory_pointers).await?;

    let proof_options_hash =
        mesh_sha256(canonical_form(options.0, loader, HmcHashType::Sha256).await?)?;

    let mandatory_string =
        canonicalized_grouped
            .matching
            .values()
            .fold(String::new(), |mut buf, quad| {
                write!(buf, "{quad} .\n").unwrap();
                buf
            });
    let mandatory_hash = mesh_sha256(mandatory_string.as_bytes())?;

    Ok(BBSHashResult {
        matching: canonicalized_grouped.matching.values().cloned().collect(),
        non_matching: canonicalized_grouped
            .non_matching
            .values()
            .cloned()
            .collect(),
        proof_options_hash,
        mandatory_hash,
    })
}

async fn canonicalize_and_group(
    document: DataDocument,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    hmac_key: &[u8],
    mandatory_pointers: &[JsonPointerBuf],
) -> Result<CanonicalizedAndGrouped, MeshError> {
    let context_json = document.0["@context"].clone();
    let context = Context::try_from_json(json_ld::syntax::Value::from(context_json))
        .map_err(|e| MeshError::BadArgument(format!("Failed to parse context: {}", e)))?;

    let input_document: RemoteDocument<IriBuf, json_syntax::Value> = RemoteDocument::new(
        Option::<IriBuf>::None,
        Some("application/ld+json".parse().unwrap()),
        json_ld::syntax::Value::from(document.0),
    );
    let Ok(mut expanded_document) = input_document.expand(loader).await else {
        return Err(MeshError::BadArgument(
            "Failed to expand JSON-LD".to_string(),
        ));
    };
    expanded_document.canonicalize();
    let mut skolemize = Skolemize::new()?;
    let skolemized_expanded_document = skolemize.expanded_document(expanded_document);

    let active_context = json_ld::Context::default();
    let vocabulary = &mut ();
    let processed_context: Processed<IriBuf, BlankIdBuf> = context
        .process_full(
            vocabulary,
            &active_context,
            loader,
            None,
            Options::default(),
        )
        .await
        .map_err(|e| MeshError::BadArgument(format!("Failed to process context: {}", e)))?;

    let skolemized_compact_document = skolemized_expanded_document
        .compact(processed_context.as_ref(), loader)
        .await
        .map_err(|e| MeshError::BadArgument(format!("Failed to compact document: {}", e)))?;

    let skolemized_compact_document = skolemized_compact_document
        .as_object()
        .ok_or_else(|| MeshError::BadArgument("Document is not an object".to_string()))?;

    let mut deskolemized_quads =
        linked_data::to_lexical_quads(generator::Blank::new(), &skolemized_expanded_document)
            .map_err(|e| MeshError::BadArgument(format!("Failed to convert to quads: {}", e)))?;
    deskolemize_nquads(&skolemize.urn_scheme, &mut deskolemized_quads);

    let (canonical_quads, label_map) =
        label_replacement_canonicalize_nquads(&hmac_key, &deskolemized_quads);

    let selection = select_canonical_nquads(
        loader,
        &skolemize.urn_scheme,
        mandatory_pointers,
        &label_map,
        &skolemized_compact_document,
    )
    .await?;

    let mut matching = BTreeMap::new();
    let mut non_matching = BTreeMap::new();

    let selected_quads: HashSet<_> = selection.quads.into_iter().collect();

    for (i, nq) in canonical_quads.iter().enumerate() {
        if selected_quads.contains(nq) {
            matching.insert(i, nq.clone());
        } else {
            non_matching.insert(i, nq.clone());
        }
    }

    Ok(CanonicalizedAndGrouped {
        _label_map: label_map,
        _quads: canonical_quads,
        matching,
        non_matching,
    })
}

pub struct CanonicalizedAndGrouped {
    pub _label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub _quads: Vec<LexicalQuad>,
    pub matching: BTreeMap<usize, LexicalQuad>,
    pub non_matching: BTreeMap<usize, LexicalQuad>,
}

// WIP: Based on canonicalize_and_group above, this means to extend the process for mandatory
// pointers, selective disclousre pointers, and the combined set, to match steps 5/6 of § 3.3.3
// createDisclosureData, https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata.
pub(crate) async fn canonicalize_and_group_for_derived_proof(
    document: DataDocument,
    loader: &mut BTreeMap<IriBuf, RemoteDocument>,
    hmac_key: &[u8],
    pointers: [&[JsonPointerBuf]; 3],
) -> Result<CanonicalizedAndGrouped3, MeshError> {
    let context_json = document.0["@context"].clone();
    let context = Context::try_from_json(json_ld::syntax::Value::from(context_json))
        .map_err(|e| MeshError::BadArgument(format!("Failed to parse context: {}", e)))?;

    let input_document: RemoteDocument<IriBuf, json_syntax::Value> = RemoteDocument::new(
        Option::<IriBuf>::None,
        Some("application/ld+json".parse().unwrap()),
        json_ld::syntax::Value::from(document.0),
    );
    let Ok(mut expanded_document) = input_document.expand(loader).await else {
        return Err(MeshError::BadArgument(
            "Failed to expand JSON-LD".to_string(),
        ));
    };
    expanded_document.canonicalize();
    let mut skolemize = Skolemize::new()?;
    let skolemized_expanded_document = skolemize.expanded_document(expanded_document);

    let active_context = json_ld::Context::default();
    let vocabulary = &mut ();
    let processed_context: Processed<IriBuf, BlankIdBuf> = context
        .process_full(
            vocabulary,
            &active_context,
            loader,
            None,
            Options::default(),
        )
        .await
        .map_err(|e| MeshError::BadArgument(format!("Failed to process context: {}", e)))?;

    let skolemized_compact_document = skolemized_expanded_document
        .compact(processed_context.as_ref(), loader)
        .await
        .map_err(|e| MeshError::BadArgument(format!("Failed to compact document: {}", e)))?;

    let skolemized_compact_document = skolemized_compact_document
        .as_object()
        .ok_or_else(|| MeshError::BadArgument("Document is not an object".to_string()))?;

    let mut deskolemized_quads =
        linked_data::to_lexical_quads(generator::Blank::new(), &skolemized_expanded_document)
            .map_err(|e| MeshError::BadArgument(format!("Failed to convert to quads: {}", e)))?;
    deskolemize_nquads(&skolemize.urn_scheme, &mut deskolemized_quads);

    let (canonical_quads, hmac_label_map) =
        label_replacement_canonicalize_nquads(&hmac_key, &deskolemized_quads);

    let mut groups: [GroupedNQuads; 3] = Default::default();

    for (pointers, group) in core::iter::zip(pointers, groups.iter_mut()) {
        let selection = select_canonical_nquads(
            loader,
            &skolemize.urn_scheme,
            pointers,
            &hmac_label_map,
            &skolemized_compact_document,
        )
        .await?;
        let selected_quads: HashSet<_> = selection.quads.into_iter().collect();

        for (i, nq) in canonical_quads.iter().enumerate() {
            if selected_quads.contains(nq) {
                group.matching.insert(i, nq.clone());
            } else {
                group.non_matching.insert(i, nq.clone());
            }
        }
    }

    let quads_ref = deskolemized_quads
        .iter()
        .map(LexicalQuad::as_lexical_quad_ref);
    let label_map =
        ssi::rdf::urdna2015::normalize::<Sha256Hasher, _>(quads_ref).into_substitution();

    Ok(CanonicalizedAndGrouped3 {
        hmac_label_map,
        label_map,
        quads: canonical_quads,
        groups,
        //   other_quads: deskolemized_quads,
    })
}

#[allow(unused)]
pub struct CanonicalizedAndGrouped3 {
    pub label_map: indexmap::IndexMap<BlankIdBuf, BlankIdBuf, ahash::RandomState>,
    pub hmac_label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub quads: Vec<LexicalQuad>,
    //pub other_quads: Vec<LexicalQuad>,
    pub groups: [GroupedNQuads; 3],
}

#[derive(Default, Debug)]
#[allow(unused)]
pub struct GroupedNQuads {
    pub matching: BTreeMap<usize, LexicalQuad>,
    pub non_matching: BTreeMap<usize, LexicalQuad>,
}

#[cfg(all(test, feature = "noenclave"))]
mod async_tests {
    use serde_json::json;
    use ssi::rdf::IntoNQuads;

    use common_types::hex_array;

    use super::*;

    // https://www.w3.org/TR/vc-di-ecdsa/#example-canonical-credential-without-proof
    const CANONICAL_FORM: &str = r#"<did:example:abcdefgh> <https://www.w3.org/ns/credentials/examples#alumniOf> "The School of Examples" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#AlumniCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/description> "A minimum viable example of an Alumni Credential." .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/name> "Alumni Credential" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdefgh> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#issuer> <https://vc.example/issuers/5678> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#validFrom> "2023-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

    #[test]
    fn test_canonical_form() {
        // https://www.w3.org/TR/vc-di-ecdsa/#example-credential-without-proof
        let input = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        });
        let mut loader = crate::ns::new_ns_loader();
        let canonical_form =
            common_async::expect_ready(canonical_form(input, &mut loader, HmcHashType::Sha256))
                .expect("future was not ready")
                .unwrap();
        assert_eq!(canonical_form, CANONICAL_FORM);
    }

    const EXPECTED_HASH: [u8; 64] = hex_array("1e00437865de4485028892c7da6f5e95de2fefe6ad72d684d2bec55e870ba9a0517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017");

    const HMAC_KEY: [u8; 32] =
        hex_array("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

    const EXPECTED_NQUADS: [&str; 28] = [
            "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
            "_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .\n",
            "_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .\n",
            "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .\n",
            "_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n",
            "_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
            "_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n"
        ];

    #[test]
    fn test_canonicalize_and_group() {
        let input = json!(
            {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    {
                        "@vocab": "https://windsurf.grotto-networking.com/selective#"
                    }
                ],
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "https://vc.example/windsurf/racecommittee",
                "credentialSubject": {
                    "sailNumber": "Earth101",
                    "sails": [
                        {
                            "size": 5.5,
                            "sailName": "Kihei",
                            "year": 2023
                        },
                        {
                            "size": 6.1,
                            "sailName": "Lahaina",
                            "year": 2023
                        },
                        {
                            "size": 7.0,
                            "sailName": "Lahaina",
                            "year": 2020
                        },
                        {
                            "size": 7.8,
                            "sailName": "Lahaina",
                            "year": 2023
                        }
                    ],
                    "boards": [
                        {
                            "boardName": "CompFoil170",
                            "brand": "Wailea",
                            "year": 2022
                        },
                        {
                            "boardName": "Kanaha Custom",
                            "brand": "Wailea",
                            "year": 2019
                        }
                    ]
                }
            }
        );
        let expected_mandatory: [(usize, String); 14] = [
            (0, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n".to_string()),
            (1, "_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .\n".to_string()),
            (2, "_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .\n".to_string()),
            (8, "_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (9, "_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .\n".to_string()),
            (11, "_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .\n".to_string()),
            (14, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .\n".to_string()),
            (15, "_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .\n".to_string()),
            (22, "_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (23, "_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .\n".to_string()),
            (24, "_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (25, "_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .\n".to_string()),
            (26, "_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string()),
            (27, "_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n".to_string())
        ];
        let mut loader = crate::ns::new_ns_loader();
        let mandatory_pointers: Vec<JsonPointerBuf> = vec![
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap(),
        ];
        let result = common_async::expect_ready(canonicalize_and_group(
            DataDocument(input),
            &mut loader,
            &HMAC_KEY,
            &mandatory_pointers,
        ))
        .expect("future was not ready")
        .unwrap();
        assert_eq!(result._quads.into_nquads_lines(), EXPECTED_NQUADS);

        let mut mandatory: Vec<_> = result
            .matching
            .iter()
            .map(|(i, quad)| (*i, format!("{quad} .\n")))
            .collect();
        mandatory.sort_by_key(|(i, _)| *i);

        assert_eq!(mandatory, expected_mandatory);
    }

    #[test]
    fn test_bbs_hash_document() {
        let input = json!(
            {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    {
                        "@vocab": "https://windsurf.grotto-networking.com/selective#"
                    }
                ],
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "https://vc.example/windsurf/racecommittee",
                "credentialSubject": {
                    "sailNumber": "Earth101",
                    "sails": [
                        {
                            "size": 5.5,
                            "sailName": "Kihei",
                            "year": 2023
                        },
                        {
                            "size": 6.1,
                            "sailName": "Lahaina",
                            "year": 2023
                        },
                        {
                            "size": 7.0,
                            "sailName": "Lahaina",
                            "year": 2020
                        },
                        {
                            "size": 7.8,
                            "sailName": "Lahaina",
                            "year": 2023
                        }
                    ],
                    "boards": [
                        {
                            "boardName": "CompFoil170",
                            "brand": "Wailea",
                            "year": 2022
                        },
                        {
                            "boardName": "Kanaha Custom",
                            "brand": "Wailea",
                            "year": 2019
                        }
                    ]
                }
            }
        );
        let options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "bbs-2023",
            "created": "2023-08-15T23:36:38Z",
            "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
            "proofPurpose": "assertionMethod",
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {
                "@vocab": "https://windsurf.grotto-networking.com/selective#"
                }
            ]
        });
        let mut loader = crate::ns::new_ns_loader();
        let mandatory_pointers: Vec<JsonPointerBuf> = vec![
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap(),
        ];
        let result = common_async::expect_ready(bbs_hash_document(
            DataDocument(input),
            ProofOptions(options),
            &mut loader,
            &HMAC_KEY,
            &mandatory_pointers,
        ))
        .expect("future was not ready")
        .unwrap();

        assert_eq!(
            result.mandatory_hash,
            hex_array::<32>("555de05f898817e31301bac187d0c3ff2b03e2cbdb4adb4d568c17de961f9a18")
        );
        assert_eq!(
            result.proof_options_hash,
            hex_array::<32>("3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf")
        );
    }

    #[test]
    fn test_ecdsa_hash_document() {
        // https://www.w3.org/TR/vc-di-ecdsa/#example-credential-without-proof
        let input = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        });
        let options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-rdfc-2019",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "https://vc.example/issuers/5678#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
            "proofPurpose": "assertionMethod"
        });
        let mut loader = crate::ns::new_ns_loader();
        let hash = common_async::expect_ready(ecdsa_hash_document(
            DataDocument(input),
            ProofOptions(options),
            &mut loader,
            HmcHashType::Sha256,
        ))
        .expect("future was not ready")
        .unwrap();
        assert_eq!(hash, EXPECTED_HASH);
    }
}
