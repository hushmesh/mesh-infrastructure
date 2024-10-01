use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;

use hashbrown::HashSet;
use serde::Deserialize;
use serde::Serialize;

use crate::impl_bidirectional_from_for_structs;
use crate::time::get_current_time_ms;
use crate::AuthenticationChallengeType;
use crate::LinkedEntityKeychainMeshId;
use crate::MeshDataFormat;
use crate::MeshEntityKeychainNetworkId;
use crate::MeshEntityType;
use crate::MeshError;
use crate::MeshId;
use crate::MeshLinkAttributesType;
use crate::MeshLinkCode;
use crate::MeshPermission;
use crate::MeshRelationship;
use crate::MeshStatusType;
use crate::DEFAULT_MESH_ENTITY_TYPE;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataEntryRateLimitData {
    pub tries: u32,
    pub tries_left: u32,
    pub window_left: i64,
    pub rate_limited: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataEntry {
    pub key_path: Vec<Vec<u8>>,
    pub part_number: Option<i64>,
    pub metadata_format: MeshDataFormat,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<u8>>,
    pub data_format: MeshDataFormat,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    pub version: Option<i64>,
    pub expiration_time: Option<i64>,
    pub is_primary_part: Option<bool>,
    pub return_part_number: Option<bool>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub part_unique_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub part_filter: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_date: Option<i64>,
}

impl DataEntry {
    pub fn new_from_cbor_data(key_path: Vec<Vec<u8>>, data: Vec<u8>) -> DataEntry {
        DataEntry {
            data_format: MeshDataFormat::Cbor,
            key_path,
            data: Some(data),
            ..Default::default()
        }
    }

    pub fn extract<'de, 'a: 'de, T: Deserialize<'de>>(&'a self) -> Result<T, MeshError> {
        let payload = self.data.as_ref().ok_or(MeshError::MissingCellData)?;
        serde_cbor::from_slice(payload).map_err(|e| MeshError::ParseError(e.to_string()))
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RateLimitEntry {
    pub key_path: Vec<Vec<u8>>,
    pub window_length: i64,
    pub max_in_window: u32,
    pub no_increment: Option<bool>,
    pub no_return_error: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataKey {
    pub key_path: Vec<Vec<u8>>,
    pub start_part_number: Option<i64>,
    pub end_part_number: Option<i64>,
    pub limit: Option<i64>,
    pub order_descending: Option<bool>,
    pub include_deleted: Option<bool>,
    pub check_if_primary: Option<bool>,
    pub stop_fetch_if_not_found: Option<bool>,
    pub part_filters: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataKeyUnique {
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataKeyForPartUniqueKey {
    pub key_path: Vec<Vec<u8>>,
    #[serde(default, with = "serde_bytes")]
    pub part_unique_key: Vec<u8>,
    pub include_deleted: Option<bool>,
    pub check_if_primary: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DataKeyDelete {
    pub key_path: Vec<Vec<u8>>,
    pub start_part_number: Option<i64>,
    pub limit: Option<i64>,
    pub permanent: Option<bool>,
    pub check_is_part_is_primary: Option<bool>,
    pub allow_delete_if_is_primary: Option<bool>,
    #[serde(default, with = "serde_bytes")]
    pub part_unique_key: Option<Vec<u8>>,
    pub do_after_all_operations: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEntryDelete {
    pub data_entry: DataEntry,
    pub check_is_part_is_primary: Option<bool>,
    pub allow_delete_if_is_primary: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataKeyRestore {
    pub key_path: Vec<Vec<u8>>,
    pub start_part_number: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataKeyPart {
    pub key_path: Vec<Vec<u8>>,
    pub part_number: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataOperation {
    RateLimit(RateLimitEntry),
    Insert(DataEntry),
    InsertIfNotPresent(DataEntry),
    Update(DataEntry),
    UpdateAndRestore(DataEntry),
    UpdateAndDelete(DataEntryDelete),
    Upsert(DataEntry),
    Append(DataEntry),
    AppendReplaceOnDuplicate(DataEntry),
    AppendMakePrimary(DataEntry),
    AppendMakePrimaryIfFirst(DataEntry),
    Merge(DataEntry),
    Restore(DataKeyRestore),
    Delete(DataKeyDelete),
    Fetch(DataKey),
    FetchPrimaryPart(DataKey),
    FetchWithPartUniqueKey(DataKeyForPartUniqueKey),
    MakePrimaryPart(DataKeyPart),
    CheckUniqueKey(DataKeyUnique),
}

impl DataOperation {
    pub fn delay_until_after_other_operations(&self) -> bool {
        match self {
            DataOperation::Delete(del) => del.do_after_all_operations.unwrap_or(false),
            _ => false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LemidAndDataOperations {
    pub lemid: LinkedEntityKeychainMeshId,
    pub operations: Vec<DataOperation>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataOperationStatus {
    pub status: MeshStatusType,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct AgentIdWithEntityType {
    pub agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ExternalLinkIdType {
    ExternalIdEmail((String, MeshEntityType)),
    ExternalIdPhone((String, MeshEntityType)),
    ExternalIdDomain((String, MeshEntityType)),
}

impl ExternalLinkIdType {
    pub fn external_id_email(email: String) -> ExternalLinkIdType {
        ExternalLinkIdType::ExternalIdEmail((email, DEFAULT_MESH_ENTITY_TYPE))
    }

    pub fn external_id_phone(phone: String) -> ExternalLinkIdType {
        ExternalLinkIdType::ExternalIdPhone((phone, DEFAULT_MESH_ENTITY_TYPE))
    }

    pub fn external_id_domain(domain: String) -> ExternalLinkIdType {
        ExternalLinkIdType::ExternalIdDomain((domain, DEFAULT_MESH_ENTITY_TYPE))
    }

    pub fn get_string(&self) -> &String {
        match self {
            ExternalLinkIdType::ExternalIdEmail((email, _)) => email,
            ExternalLinkIdType::ExternalIdPhone((phone, _)) => phone,
            ExternalLinkIdType::ExternalIdDomain((domain, _)) => domain,
        }
    }
    pub fn get_entity_type(&self) -> MeshEntityType {
        match self {
            ExternalLinkIdType::ExternalIdEmail((_, entity_type))
            | ExternalLinkIdType::ExternalIdPhone((_, entity_type))
            | ExternalLinkIdType::ExternalIdDomain((_, entity_type)) => *entity_type,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalLinkIdTypeAndAgentIds {
    pub external_id: ExternalLinkIdType,
    pub external_id_agent_id: MeshId,
    pub linked_agent_id: AgentIdWithEntityType, // usually human_agent_id
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>, // persona or org_member
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdSharedWithInvitesData {
    pub entity_type: MeshEntityType,
    pub invites: Vec<ExternalLinkIdTypeAndAgentIds>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LinkRequestId {
    LinkCode(MeshLinkCode),
    ExternalId(ExternalLinkIdType),
    NewId(MeshEntityType),
    NewIdIfNoneExists(MeshEntityType),
    IdSharedWithInvites(IdSharedWithInvitesData),
}

impl LinkRequestId {
    pub fn is_new_id(&self) -> bool {
        matches!(self, LinkRequestId::NewId(_))
    }

    pub fn is_new_id_or_new_id_if_none_exists(&self) -> bool {
        matches!(self, LinkRequestId::NewId(_))
            || matches!(self, LinkRequestId::NewIdIfNoneExists(_))
    }

    pub fn is_shared_invite(&self) -> bool {
        matches!(self, LinkRequestId::IdSharedWithInvites(_))
    }

    pub fn is_new_id_if_none_exists(&self) -> bool {
        matches!(self, LinkRequestId::NewIdIfNoneExists(_))
    }

    pub fn external_id_email(email: String) -> LinkRequestId {
        LinkRequestId::ExternalId(ExternalLinkIdType::external_id_email(email))
    }

    pub fn external_id_domain(domain: String) -> LinkRequestId {
        LinkRequestId::ExternalId(ExternalLinkIdType::external_id_domain(domain))
    }

    pub fn external_id_phone(phone: String) -> LinkRequestId {
        LinkRequestId::ExternalId(ExternalLinkIdType::external_id_phone(phone))
    }

    pub fn new_id() -> LinkRequestId {
        LinkRequestId::NewId(DEFAULT_MESH_ENTITY_TYPE)
    }

    pub fn id_shared_with_invites(invites: Vec<ExternalLinkIdTypeAndAgentIds>) -> LinkRequestId {
        LinkRequestId::IdSharedWithInvites(IdSharedWithInvitesData {
            entity_type: DEFAULT_MESH_ENTITY_TYPE,
            invites,
        })
    }

    pub fn new_id_if_none_exists() -> LinkRequestId {
        LinkRequestId::NewIdIfNoneExists(DEFAULT_MESH_ENTITY_TYPE)
    }

    pub fn get_phone(&self) -> Option<String> {
        match self {
            LinkRequestId::ExternalId(ExternalLinkIdType::ExternalIdPhone((phone, _))) => {
                Some(phone.clone())
            }
            _ => None,
        }
    }

    pub fn get_email(&self) -> Option<String> {
        match self {
            LinkRequestId::ExternalId(ExternalLinkIdType::ExternalIdEmail((email, _))) => {
                Some(email.clone())
            }
            _ => None,
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match self {
            LinkRequestId::ExternalId(ExternalLinkIdType::ExternalIdDomain((domain, _))) => {
                Some(domain.clone())
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallengeRecord {
    pub challenge_type: AuthenticationChallengeType,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionInfo {
    pub timestamp: i64,
    pub challenges: Vec<AuthenticationChallengeRecord>,
    pub completed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AgentLinkedEntity {
    pub lemid: MeshId,
    pub alemid: MeshId,
    pub agent_id: MeshId,
    pub entity_type: MeshEntityType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_link_code_created_with: Option<MeshLinkCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_emid_if_on_same_agent: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_lemid_if_on_same_agent: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_alemid_if_on_same_agent: Option<MeshId>,
}

impl fmt::Debug for AgentLinkedEntity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // don't output fields like lemids we don't want to expose
        f.debug_struct("AgentLinkedEntity")
            .field("agent_id", &self.agent_id)
            .field("entity_type", &self.entity_type)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentLinkedEntityPair {
    pub entity_origin: AgentLinkedEntity,
    pub entity_dest: AgentLinkedEntity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshRelationshipAndPermissionsForLink {
    pub relationships: Vec<MeshRelationship>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_permissions: Option<Vec<MeshPermission>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_permissions: Option<Vec<MeshPermission>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshRelationshipAndPermissionsDirectPending {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_self: Option<AgentMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_to_origin: Option<AgentMeshRelationshipAndPermissionsForLink>,
    pub update_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshRelationshipAndPermissions {
    pub entity_link: AgentLinkedEntity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_self: Option<AgentMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_to_origin: Option<AgentMeshRelationshipAndPermissionsForLink>,
    pub update_time: i64,
}

impl AgentMeshRelationshipAndPermissions {
    pub fn get_lemid(&self) -> LinkedEntityKeychainMeshId {
        self.entity_link.lemid
    }

    pub fn get_agent_id(&self) -> LinkedEntityKeychainMeshId {
        self.entity_link.agent_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshRelationshipToEachOther {
    pub entity_link: AgentLinkedEntityPair,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_dest: Option<AgentMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_to_origin: Option<AgentMeshRelationshipAndPermissionsForLink>,
    pub update_time: i64,
}

impl AgentMeshRelationshipToEachOther {
    pub fn get_lemids(&self) -> Vec<LinkedEntityKeychainMeshId> {
        vec![
            self.entity_link.entity_origin.lemid,
            self.entity_link.entity_dest.lemid,
        ]
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum AgentMeshRelationshipDirection {
    OriginToSelf,
    SelfToOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshRelationshipRelative {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_to_each_other: Option<AgentMeshRelationshipToEachOther>, // optional in the case of a direct relative
    pub link_to_same_enid: AgentMeshRelationshipAndPermissions,
}

impl AgentMeshRelationshipRelative {
    pub fn get_lemids(&self) -> Vec<LinkedEntityKeychainMeshId> {
        let mut lemids = self
            .link_to_each_other
            .as_ref()
            .map_or(Vec::new(), |link| link.get_lemids());
        lemids.push(self.link_to_same_enid.get_lemid());
        lemids
    }

    pub fn combine_permissions(
        &self,
        direction: AgentMeshRelationshipDirection,
    ) -> Option<AgentMeshRelationshipAndPermissionsForLink> {
        if self.link_to_each_other.is_none() {
            let perms = match direction {
                AgentMeshRelationshipDirection::OriginToSelf => {
                    self.link_to_same_enid.origin_to_self.as_ref()
                }
                AgentMeshRelationshipDirection::SelfToOrigin => {
                    self.link_to_same_enid.self_to_origin.as_ref()
                }
            };
            return perms.cloned();
        }

        let link_to_each_other = self.link_to_each_other.as_ref().unwrap();
        let (link_relperms, each_other_relperms) = match direction {
            AgentMeshRelationshipDirection::OriginToSelf => (
                &self.link_to_same_enid.origin_to_self,
                &link_to_each_other.origin_to_dest,
            ),
            AgentMeshRelationshipDirection::SelfToOrigin => (
                &self.link_to_same_enid.self_to_origin,
                &link_to_each_other.origin_to_dest,
            ),
        };
        if let Some(each_other_relperms) = each_other_relperms.as_ref() {
            let pairs: Vec<String> = each_other_relperms
                .relationships
                .iter()
                .flat_map(|r| {
                    link_relperms.as_ref().map_or_else(Vec::new, |r2| {
                        r2.relationships
                            .iter()
                            .map(|r2| format!("{}:{}", r, r2))
                            .collect()
                    })
                })
                .collect();
            let unique_add_permissions: HashSet<String> = each_other_relperms
                .added_permissions
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .chain(
                    link_relperms
                        .as_ref()
                        .and_then(|r| r.added_permissions.as_ref())
                        .unwrap_or(&Vec::new())
                        .iter(),
                )
                .cloned()
                .collect();

            let added_permissions: Vec<String> = unique_add_permissions.into_iter().collect();
            let unique_removed_permissions: HashSet<String> = each_other_relperms
                .removed_permissions
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .chain(
                    link_relperms
                        .as_ref()
                        .and_then(|r| r.removed_permissions.as_ref())
                        .unwrap_or(&Vec::new())
                        .iter(),
                )
                .cloned()
                .collect();

            let removed_permissions: Vec<String> = unique_removed_permissions.into_iter().collect();
            let mut link_relperms = link_relperms
                .as_ref()
                .unwrap_or(each_other_relperms)
                .clone();
            link_relperms.relationships = pairs;
            link_relperms.added_permissions = Some(added_permissions);
            link_relperms.removed_permissions = Some(removed_permissions);
            return Some(link_relperms);
        }
        link_relperms.clone()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentMeshLinkInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationSessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_self: Option<Vec<MeshLinkAttributesType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_origin: Option<Vec<MeshLinkAttributesType>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_direct: Option<AgentMeshRelationshipAndPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_session_links: Option<Vec<AgentMeshRelationshipAndPermissions>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_relatives: Option<Vec<AgentMeshRelationshipRelative>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_direct_pending: Option<AgentMeshRelationshipAndPermissionsDirectPending>,
}

impl AgentMeshLinkInfo {
    pub fn set_authenticated(&mut self, authenticated: bool) {
        let auth_info = self
            .authentication_info
            .get_or_insert_with(|| AuthenticationSessionInfo {
                timestamp: get_current_time_ms(),
                challenges: vec![],
                completed: false,
            });
        auth_info.completed = authenticated;
        auth_info.timestamp = get_current_time_ms();
    }

    pub fn new() -> AgentMeshLinkInfo {
        AgentMeshLinkInfo {
            ..Default::default()
        }
    }

    pub fn has_attribute_self(&self, attrib: MeshLinkAttributesType) -> bool {
        self.attributes_self
            .as_ref()
            .map_or(false, |a| a.contains(&attrib))
    }

    pub fn has_attribute_origin(&self, attrib: MeshLinkAttributesType) -> bool {
        self.attributes_origin
            .as_ref()
            .map_or(false, |a| a.contains(&attrib))
    }

    pub fn get_session_or_direct_relationship(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<&AgentMeshRelationshipAndPermissions> {
        self.relationship_direct
            .as_ref()
            .filter(|direct| agent_ids.iter().any(|id| direct.get_agent_id() == *id))
            .or_else(|| {
                self.relationship_session_links
                    .as_ref()
                    .and_then(|sessions| {
                        sessions.iter().find(|session| {
                            agent_ids.iter().any(|id| session.get_agent_id() == *id)
                        })
                    })
            })
    }

    pub fn get_session_or_direct_relationship_lemid(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<LinkedEntityKeychainMeshId> {
        self.get_session_or_direct_relationship(agent_ids)
            .map(AgentMeshRelationshipAndPermissions::get_lemid)
    }

    pub fn get_session_relationship(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<&AgentMeshRelationshipAndPermissions> {
        self.relationship_session_links
            .as_ref()
            .and_then(|sessions| {
                sessions
                    .iter()
                    .find(|session| agent_ids.iter().any(|id| session.get_agent_id() == *id))
            })
    }

    pub fn get_session_relationship_lemid(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<LinkedEntityKeychainMeshId> {
        self.get_session_relationship(agent_ids)
            .map(AgentMeshRelationshipAndPermissions::get_lemid)
    }

    pub fn get_session_and_direct_relationships(
        &self,
    ) -> Option<Vec<&AgentMeshRelationshipAndPermissions>> {
        let mut relationships: Vec<&AgentMeshRelationshipAndPermissions> = vec![];
        if let Some(direct) = self.relationship_direct.as_ref() {
            relationships.push(direct);
        }
        if let Some(sessions) = self.relationship_session_links.as_ref() {
            relationships.extend(sessions.iter());
        }
        Option::from(relationships).filter(|v| !v.is_empty())
    }

    pub fn get_all_relationships(
        &self,
        direction: AgentMeshRelationshipDirection,
    ) -> Vec<AgentMeshRelationshipAndPermissionsForLink> {
        let direct_relationships = self
            .get_session_and_direct_relationships()
            .iter()
            .flat_map(|d| d.iter())
            .filter_map(|rel| match direction {
                AgentMeshRelationshipDirection::OriginToSelf => rel.origin_to_self.as_ref(),
                AgentMeshRelationshipDirection::SelfToOrigin => rel.self_to_origin.as_ref(),
            })
            .cloned()
            .collect::<Vec<_>>();

        let relative_relationships = self
            .relationship_relatives
            .as_ref()
            .iter()
            .flat_map(|r| r.iter())
            .filter_map(|rel| rel.combine_permissions(direction))
            .collect::<Vec<_>>();

        [direct_relationships, relative_relationships].concat()
    }

    pub fn is_authenticated_session(&self) -> bool {
        self.authentication_info
            .as_ref()
            .map(|a| a.completed)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeMeshRelationshipAndPermissionsForLink {
    pub relationships: Vec<MeshRelationship>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_permissions: Option<Vec<MeshPermission>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_permissions: Option<Vec<MeshPermission>>,
}
impl_bidirectional_from_for_structs!(
    TrusteeMeshRelationshipAndPermissionsForLink,
    AgentMeshRelationshipAndPermissionsForLink,
    Direct [relationships, added_permissions, removed_permissions],
    Into [],
    OptionInto [],
    OptionVecInto []
);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TrusteeLinkedEntity {
    pub origin_enid: MeshId,
    pub dest_enid: MeshId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeMeshRelationshipAndPermissions {
    pub entity_link: TrusteeLinkedEntity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_dest: Option<TrusteeMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_to_origin: Option<TrusteeMeshRelationshipAndPermissionsForLink>,
    pub update_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeMeshRelationshipAndPermissionsDirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_dest: Option<TrusteeMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_to_origin: Option<TrusteeMeshRelationshipAndPermissionsForLink>,
    pub update_time: i64,
}

impl TrusteeMeshRelationshipAndPermissions {
    pub fn swap_if_origin_enid(&mut self, enid: MeshId) {
        if self.entity_link.origin_enid == enid {
            core::mem::swap(
                &mut self.entity_link.origin_enid,
                &mut self.entity_link.dest_enid,
            );
            core::mem::swap(&mut self.origin_to_dest, &mut self.dest_to_origin);
        }
    }
    pub fn matches(&self, other: &Self) -> bool {
        self.entity_link == other.entity_link
    }

    pub fn merge(&mut self, other: &Self) {
        if other.origin_to_dest.is_some() {
            self.origin_to_dest = other.origin_to_dest.clone();
        }
        if other.dest_to_origin.is_some() {
            self.dest_to_origin = other.dest_to_origin.clone();
        }
        self.update_time = core::cmp::max(self.update_time, other.update_time);
    }

    pub fn change_session_links(
        &mut self,
        self_enid: MeshId,
        session_enid: MeshEntityKeychainNetworkId,
    ) {
        if self.entity_link.origin_enid == session_enid && self.entity_link.dest_enid != self_enid {
            self.entity_link.origin_enid = self_enid;
        } else if self.entity_link.dest_enid == session_enid
            && self.entity_link.origin_enid != self_enid
        {
            self.entity_link.dest_enid = self_enid;
        }
    }
}

impl TrusteeMeshRelationshipAndPermissionsDirect {
    pub fn swap(&mut self) {
        core::mem::swap(&mut self.origin_to_dest, &mut self.dest_to_origin);
    }
    pub fn merge(&mut self, other: &Self) {
        if other.origin_to_dest.is_some() {
            self.origin_to_dest = other.origin_to_dest.clone();
        }
        if other.dest_to_origin.is_some() {
            self.dest_to_origin = other.dest_to_origin.clone();
        }
        self.update_time = core::cmp::max(self.update_time, other.update_time);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrusteeMeshLinkInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationSessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_dest: Option<Vec<MeshLinkAttributesType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_origin: Option<Vec<MeshLinkAttributesType>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_direct: Option<TrusteeMeshRelationshipAndPermissionsDirect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_session_links: Option<Vec<TrusteeMeshRelationshipAndPermissions>>,
}

impl TrusteeMeshLinkInfo {
    pub fn add_relationship_direct_origin_to_dest_if_not_set(&mut self, rel: &str) {
        let entry = self.relationship_direct.get_or_insert_with(|| {
            TrusteeMeshRelationshipAndPermissionsDirect {
                origin_to_dest: None,
                dest_to_origin: None,
                update_time: get_current_time_ms(),
            }
        });

        if entry.origin_to_dest.is_none() {
            entry.origin_to_dest = Some(TrusteeMeshRelationshipAndPermissionsForLink {
                relationships: vec![rel.into()],
                added_permissions: None,
                removed_permissions: None,
            });
        }
    }

    pub fn add_relationship_direct_dest_to_origin_if_not_set(&mut self, rel: &str) {
        let entry = self.relationship_direct.get_or_insert_with(|| {
            TrusteeMeshRelationshipAndPermissionsDirect {
                origin_to_dest: None,
                dest_to_origin: None,
                update_time: get_current_time_ms(),
            }
        });

        if entry.dest_to_origin.is_none() {
            entry.dest_to_origin = Some(TrusteeMeshRelationshipAndPermissionsForLink {
                relationships: vec![rel.into()],
                added_permissions: None,
                removed_permissions: None,
            });
        }
    }

    pub fn new() -> Self {
        Self::default()
    }
}

pub fn unserialize_rate_limit_data(
    data_payload: &[u8],
) -> Result<DataEntryRateLimitData, MeshError> {
    serde_cbor::from_slice(data_payload).map_err(|e| MeshError::ParseError(format!("{}", e)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMeshLinkSessionUpdate {
    pub lemid: LinkedEntityKeychainMeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_to_self: Option<AgentMeshRelationshipAndPermissionsForLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_to_origin: Option<AgentMeshRelationshipAndPermissionsForLink>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentMeshLinkUpdates {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationSessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<MeshLinkAttributesType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationships_origin_to_self: Option<AgentMeshRelationshipAndPermissionsForLink>,
}

impl AgentMeshLinkUpdates {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_attribute(&mut self, attrib: MeshLinkAttributesType) {
        let attribs = self.attributes.get_or_insert(Vec::new());
        if !attribs.contains(&attrib) {
            attribs.push(attrib);
        }
    }
    pub fn set_authenticated(&mut self, authenticated: bool) {
        let auth_info = self
            .authentication_info
            .get_or_insert_with(|| AuthenticationSessionInfo {
                timestamp: get_current_time_ms(),
                challenges: vec![],
                completed: false,
            });
        auth_info.completed = authenticated;
        auth_info.timestamp = get_current_time_ms();
    }

    pub fn add_relationship_origin_to_self(&mut self, rel: &str) {
        let entry = self.relationships_origin_to_self.get_or_insert_with(|| {
            AgentMeshRelationshipAndPermissionsForLink {
                relationships: Vec::new(),
                added_permissions: None,
                removed_permissions: None,
            }
        });

        if !entry.relationships.iter().any(|existing| existing == rel) {
            entry.relationships.push(rel.into());
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentMeshLinkUpdatesForSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_info: Option<AuthenticationSessionInfo>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationships_origin_to_self: Option<AgentMeshRelationshipAndPermissionsForLink>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_updates: Option<Vec<AgentMeshLinkSessionUpdate>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<MeshLinkAttributesType>>,
}

impl AgentMeshLinkUpdatesForSession {
    pub fn set_authenticated(&mut self, authenticated: bool) {
        let auth_info = self
            .authentication_info
            .get_or_insert_with(|| AuthenticationSessionInfo {
                timestamp: get_current_time_ms(),
                challenges: vec![],
                completed: false,
            });
        auth_info.completed = authenticated;
        auth_info.timestamp = get_current_time_ms();
    }

    pub fn new() -> AgentMeshLinkUpdatesForSession {
        AgentMeshLinkUpdatesForSession {
            ..Default::default()
        }
    }

    pub fn add_session_relationship(
        &mut self,
        lemid: LinkedEntityKeychainMeshId,
        self_to_origin_relationship: Option<String>,
        origin_to_self_relationship: Option<String>,
    ) {
        let update = AgentMeshLinkSessionUpdate {
            lemid,
            self_to_origin: self_to_origin_relationship.map(|rel| {
                AgentMeshRelationshipAndPermissionsForLink {
                    relationships: vec![rel],
                    added_permissions: None,
                    removed_permissions: None,
                }
            }),
            origin_to_self: origin_to_self_relationship.map(|rel| {
                AgentMeshRelationshipAndPermissionsForLink {
                    relationships: vec![rel],
                    added_permissions: None,
                    removed_permissions: None,
                }
            }),
        };

        if let Some(ref mut updates) = self.session_updates {
            updates.push(update);
        } else {
            self.session_updates = Some(vec![update]);
        }
    }

    pub fn add_relationship_origin_to_self(&mut self, rel: &str) {
        let rel_str = rel.into();
        let entry = self.relationships_origin_to_self.get_or_insert_with(|| {
            AgentMeshRelationshipAndPermissionsForLink {
                relationships: Vec::new(),
                added_permissions: None,
                removed_permissions: None,
            }
        });

        if !entry.relationships.contains(&rel_str) {
            entry.relationships.push(rel_str);
        }
    }

    pub fn set_attribute(&mut self, attrib: MeshLinkAttributesType) {
        let attribs = self.attributes.get_or_insert(Vec::new());
        if !attribs.contains(&attrib) {
            attribs.push(attrib);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatusRunningInfo {
    pub node_rotating: String,
    pub started_at_timestamp: i64,
    pub last_status_timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatusInfo {
    pub current_version: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_status: Option<RotationStatusRunningInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stem_id_last_update_timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationValue {
    pub name: String,
    pub value: String,
    pub is_secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationValueUpdate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub is_secret: bool,
}
