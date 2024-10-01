use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use json_ld::BlankId;
use json_ld::BlankIdBuf;
use json_ld::ExpandedDocument;
use json_ld::IriBuf;
use json_ld::JsonLdProcessor;
use json_ld::RemoteDocument;
use rdf_types::generator;
use rdf_types::Id;
use rdf_types::LexicalQuad;
use uuid::Uuid;

use common_crypto::mesh_generate_id;
use common_crypto::HmcDataType;
use common_types::MeshError;

pub struct Skolemize {
    pub urn_scheme: String,
    pub random_string: String,
    pub count: u32,
}

impl rdf_types::Generator for Skolemize {
    fn next(&mut self, _vocabulary: &mut ()) -> Id {
        Id::Iri(self.fresh_blank_id())
    }
}

impl Skolemize {
    pub fn new() -> Result<Self, MeshError> {
        let uuid_bytes = mesh_generate_id(16, HmcDataType::Raw)?;
        let uuid = Uuid::from_slice(&uuid_bytes).unwrap();
        Ok(Self {
            urn_scheme: "bnid".to_owned(),
            random_string: uuid.to_string(),
            count: 0,
        })
    }

    pub fn fresh_blank_id(&mut self) -> IriBuf {
        let id = IriBuf::new(format!(
            "urn:{}:{}_{}",
            self.urn_scheme, self.random_string, self.count
        ))
        .unwrap();
        self.count += 1;
        id
    }

    pub fn blank_id(&mut self, blank_id: &BlankId) -> IriBuf {
        IriBuf::new(format!("urn:{}:{}", self.urn_scheme, blank_id.suffix())).unwrap()
    }

    pub fn expanded_document(&mut self, expanded: ExpandedDocument) -> ExpandedDocument {
        let mut result = expanded.map_ids(
            |i| i,
            |id| match id {
                json_ld::Id::Valid(id) => match id {
                    Id::Blank(b) => json_ld::Id::Valid(Id::Iri(self.blank_id(&b))),
                    Id::Iri(i) => json_ld::Id::Valid(Id::Iri(i)),
                },
                json_ld::Id::Invalid(s) => json_ld::Id::Invalid(s),
            },
        );

        result.identify_all(self);
        result
    }
}

pub(crate) async fn compact_to_deskolemized_nquads(
    loader: &impl json_ld::Loader,
    urn_scheme: &str,
    document: json_ld::syntax::Object,
) -> Result<Vec<LexicalQuad>, MeshError> {
    let mut generator = generator::Blank::new();
    let mut quads: Vec<LexicalQuad> =
        RemoteDocument::new(None, None, json_syntax::Value::Object(document))
            .to_rdf(&mut generator, loader)
            .await
            .map_err(|_| MeshError::ParseError("rdf conversion error".to_string()))?
            .cloned_quads()
            .map(|quad| quad.map_predicate(|p| p.into_iri().unwrap()))
            .collect();

    deskolemize_nquads(urn_scheme, &mut quads);

    Ok(quads)
}

pub(crate) fn deskolemize_nquads(urn_scheme: &str, quads: &mut [rdf_types::LexicalQuad]) {
    for quad in quads {
        deskolemize_id(urn_scheme, &mut quad.0);
        deskolemize_term(urn_scheme, &mut quad.2);

        if let Some(g) = quad.graph_mut() {
            deskolemize_id(urn_scheme, g);
        }
    }
}

fn deskolemize_id(urn_scheme: &str, id: &mut rdf_types::Id) {
    if let rdf_types::Id::Iri(iri) = id {
        if iri.scheme().as_str() == "urn" {
            let path = iri.path();
            if let Some((prefix, suffix)) = path.split_once(':') {
                if prefix == urn_scheme {
                    let blank_id = BlankIdBuf::from_suffix(suffix).unwrap();
                    *id = rdf_types::Id::Blank(blank_id)
                }
            }
        }
    }
}

fn deskolemize_term(urn_scheme: &str, term: &mut rdf_types::Term) {
    if let rdf_types::Term::Id(id) = term {
        deskolemize_id(urn_scheme, id)
    }
}
