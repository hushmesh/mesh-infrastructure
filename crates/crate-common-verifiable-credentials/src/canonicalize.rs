use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use ahash::RandomState;
use base64::display::Base64Display;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hashbrown::HashMap;
use indexmap::IndexMap;
use json_ld::BlankId;
use json_ld::BlankIdBuf;
use json_ld::Iri;
use rdf_types::LexicalQuad;
use rdf_types::LexicalQuadRef;
use rdf_types::Literal;
use rdf_types::Quad;
use ssi::rdf::urdna2015;

use common_crypto::HmacSha256Writer;

use crate::hash::Sha256Hasher;

fn create_hmac_id_label_map(
    hmac_key: &[u8],
    canonical_map: &IndexMap<BlankIdBuf, BlankIdBuf, RandomState>,
) -> HashMap<BlankIdBuf, BlankIdBuf> {
    canonical_map
        .iter()
        .map(|(key, value)| {
            let mut writer = HmacSha256Writer::new(hmac_key).unwrap();
            writer.write(value.suffix().as_bytes()).unwrap();
            let digest = writer.finalize().unwrap();
            let mut buf = String::with_capacity(3 + base64::encoded_len(32, false).unwrap());
            write!(buf, "_:u{}", Base64Display::new(&digest, &URL_SAFE_NO_PAD)).unwrap();
            let b64_url_digest = BlankIdBuf::new(buf).unwrap();
            (key.clone(), b64_url_digest)
        })
        .collect()
}

pub(crate) fn label_replacement_canonicalize_nquads(
    hmac_key: &[u8],
    quads: &[LexicalQuad],
) -> (Vec<LexicalQuad>, HashMap<BlankIdBuf, BlankIdBuf>) {
    let quads_ref = quads.iter().map(LexicalQuad::as_lexical_quad_ref);
    let bnode_identifier_map =
        urdna2015::normalize::<Sha256Hasher, _>(quads_ref).into_substitution();

    let mut label_map = create_hmac_id_label_map(hmac_key, &bnode_identifier_map);

    let mut hmac_ids: Vec<_> = label_map.values().cloned().collect();
    hmac_ids.sort();

    let mut bnode_keys: Vec<_> = label_map.keys().cloned().collect();
    bnode_keys.sort();

    for key in bnode_keys {
        let i = hmac_ids.binary_search(&label_map[&key]).unwrap();
        label_map.insert(key, BlankIdBuf::new(format!("_:b{}", i)).unwrap());
    }

    let canonical_quads: Vec<_> = quads
        .iter()
        .map(|quad| relabel_quad(&label_map, quad.as_lexical_quad_ref()))
        .collect();

    let mut blank_quads: Vec<_> = canonical_quads
        .iter()
        .filter(|quad| quad.0.is_blank())
        .cloned()
        .collect();
    let mut non_blank_quads: Vec<_> = canonical_quads
        .iter()
        .filter(|quad| !quad.0.is_blank())
        .cloned()
        .collect();
    blank_quads.sort();
    non_blank_quads.sort();
    blank_quads.dedup();
    non_blank_quads.dedup();
    non_blank_quads.extend(blank_quads);
    (non_blank_quads, label_map)
}

pub fn relabel_quads(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    quads: &[LexicalQuad],
) -> Vec<LexicalQuad> {
    quads
        .iter()
        .map(|quad| relabel_quad(label_map, quad.as_lexical_quad_ref()))
        .collect()
}

fn relabel_quad(label_map: &HashMap<BlankIdBuf, BlankIdBuf>, quad: LexicalQuadRef) -> LexicalQuad {
    Quad(
        relabel_id(label_map, quad.0),
        quad.1.to_owned(),
        relabel_term(label_map, quad.2),
        quad.3.map(|g| relabel_id(label_map, g)),
    )
}

fn relabel_id(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    id: rdf_types::Id<&Iri, &BlankId>,
) -> rdf_types::Id {
    match id {
        rdf_types::Id::Iri(i) => rdf_types::Id::Iri(i.to_owned()),
        rdf_types::Id::Blank(b) => rdf_types::Id::Blank(match label_map.get(b) {
            Some(c) => c.clone(),
            None => b.to_owned(),
        }),
    }
}

fn relabel_term(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
    term: rdf_types::Term<rdf_types::Id<&Iri, &BlankId>, &Literal>,
) -> rdf_types::Term {
    match term {
        rdf_types::Term::Id(id) => rdf_types::Term::Id(relabel_id(label_map, id)),
        rdf_types::Term::Literal(l) => rdf_types::Term::Literal(l.clone()),
    }
}
