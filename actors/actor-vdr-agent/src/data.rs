use alloc::borrow::Cow;

use serde::Deserialize;
use serde::Serialize;

use common_types::LinkedEntityKeychainMeshId;

#[derive(Serialize, Deserialize)]
pub(crate) struct DidData<'c> {
    #[serde(borrow)]
    pub(crate) did: Cow<'c, str>,
    #[serde(borrow)]
    pub(crate) did_document: Cow<'c, str>,
    pub(crate) key_pair_linked_entity_id: LinkedEntityKeychainMeshId,
    #[serde(borrow, with = "serde_bytes")]
    pub(crate) public_key: Cow<'c, [u8]>,
}
