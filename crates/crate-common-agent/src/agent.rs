use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use hashbrown::HashMap;
use log::error;
use log::info;
use serde::Deserialize;
use serde::Serialize;
use serde_cbor::from_slice;

use common_crypto::mesh_generate_mesh_id;
use common_messages::agent_message_header_to_error;
use common_messages::agent_messages::AgentMessageType;
use common_messages::agent_messages::AgentToAgentGetLinkCodesViaExternalIdRequestor;
use common_messages::agent_messages::AgentToAgentLinkEntityInviteLink;
use common_messages::agent_trustee_messages::AgentCreateAndLinkEntityOnSameAgentRequest;
use common_messages::agent_trustee_messages::AgentCreateAndLinkEntityOnSameAgentResponse;
use common_messages::agent_trustee_messages::AgentCreateEntityRequest;
use common_messages::agent_trustee_messages::AgentCreateEntityResponse;
use common_messages::agent_trustee_messages::AgentCreateUnsRecordsRequest;
use common_messages::agent_trustee_messages::AgentCreateUnsRecordsResponse;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityInput;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityOutput;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityRequest;
use common_messages::agent_trustee_messages::AgentDataOperationForEntityResponse;
use common_messages::agent_trustee_messages::AgentDeleteEntityRequest;
use common_messages::agent_trustee_messages::AgentGetCertificateAuthoritiesRequest;
use common_messages::agent_trustee_messages::AgentLinkEntityOnSameAgentRequest;
use common_messages::agent_trustee_messages::AgentLinkEntityOnSameAgentResponse;
use common_messages::agent_trustee_messages::AgentLookupEntityOnSameAgentRequest;
use common_messages::agent_trustee_messages::AgentLookupEntityOnSameAgentResponse;
use common_messages::agent_trustee_messages::AgentLookupUnsRecordsRequest;
use common_messages::agent_trustee_messages::AgentLookupUnsRecordsResponse;
use common_messages::agent_trustee_messages::AgentUpdateUnsRecordVersionInfoRequest;
use common_messages::agent_trustee_messages::BootstrapKeyPair;
use common_messages::agent_trustee_messages::GetLinkCodesForRestriction;
use common_messages::agent_trustee_messages::GetLinkCodesRequest;
use common_messages::agent_trustee_messages::GetLinkCodesResponse;
use common_messages::agent_trustee_messages::GetLinkCodesType;
use common_messages::agent_trustee_messages::LinkEntityRequest;
use common_messages::agent_trustee_messages::LinkEntityResponse;
use common_messages::agent_trustee_messages::LinkEntityViaDelegateRequest;
use common_messages::agent_trustee_messages::LinkEntityViaDelegateResponse;
use common_messages::agent_trustee_messages::LookupLinkedEntitiesRequest;
use common_messages::agent_trustee_messages::LookupLinkedEntitiesResponse;
use common_messages::agent_trustee_messages::SendToAgentRequest;
use common_messages::agent_trustee_messages::SendToAgentResponse;
use common_messages::agent_trustee_messages::SendToAllLinkedEntitiesRequest;
use common_messages::agent_trustee_messages::SendToAllLinkedEntitiesResponse;
use common_messages::agent_trustee_messages::SendToEntityOnNodeInstanceRequest;
use common_messages::agent_trustee_messages::SendToLinkedEntityRequest;
use common_messages::agent_trustee_messages::SendToLinkedEntityResponse;
use common_messages::agent_trustee_messages::SendToTrusteeRequest;
use common_messages::agent_trustee_messages::SessionLinkType;
use common_messages::agent_trustee_messages::TrusteeNetworkSendToEntityOnNodeInstanceResponse;
use common_messages::agent_trustee_messages::UnlinkEntityRequest;
use common_messages::certificate_agent_messages::GetCertificateAuthoritiesResponse;
use common_messages::wrapped_message::WrappedMessage;
use common_messages::AgentIdWithAttributes;
use common_messages::MeshMessage;
use common_messages::MeshMessageType;
use common_messages::MeshSubsystem;
use common_messages::ReplyCallback;
use common_sessions::request_table::RequestTable;
use common_sessions::routing_table::RouterData;
use common_sessions::routing_table::RouterMessageKey;
use common_sessions::routing_table::RoutingTable;
use common_sessions::routing_table::RoutingTableGeneric;
use common_sync::RwLock;
use common_types::agent_entity_trustee_objects::AgentIdWithEntityType;
use common_types::agent_entity_trustee_objects::AgentLinkedEntity;
use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdates;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdatesForSession;
use common_types::agent_entity_trustee_objects::AgentMeshRelationshipAndPermissions;
use common_types::agent_entity_trustee_objects::DataEntry;
use common_types::agent_entity_trustee_objects::DataKey;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::agent_entity_trustee_objects::ExternalLinkIdType;
use common_types::agent_entity_trustee_objects::LemidAndDataOperations;
use common_types::agent_entity_trustee_objects::LinkRequestId;
use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::node_name::get_agent_trustee_node_name_and_port;
use common_types::time::get_current_time_ms;
use common_types::uns_data_objects::CreateUnsRecord;
use common_types::uns_data_objects::UnsLookupType;
use common_types::uns_data_objects::UnsRecord;
use common_types::versioning::MeshVersionInfo;
use common_types::AgentLinkedEntityKeychainMeshId;
use common_types::ContextId;
use common_types::LinkedEntityKeychainMeshId;
use common_types::MeshEntityKeychainMeshId;
use common_types::MeshEntityType;
use common_types::MeshError;
use common_types::MeshExternalId;
use common_types::MeshId;
use common_types::MeshInstanceRoute;
use common_types::MeshLinkCode;
use common_types::MeshMessageId;
use common_types::MeshPermission;
use common_types::MeshStatusType;

use crate::agent_to_agent::AuthorizationHandler;
use crate::authorization::AuthorizationChecker;

const MAX_CONCURRENT_UPDATE_TRIES: usize = 5;
pub const ONE_TIME_USE_LINK_CODES_EXPIRATION_TIME: i64 = 90000;

pub fn agent_get_link_lemid(
    link_info: &Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Option<LinkedEntityKeychainMeshId> {
    link_info
        .as_ref()
        .and_then(|info| info.get_session_or_direct_relationship_lemid(agent_ids))
}

pub fn agent_get_relationship<'a>(
    link_info: &'a Option<AgentMeshLinkInfo>,
    agent_ids: &[MeshId],
) -> Option<&'a AgentMeshRelationshipAndPermissions> {
    link_info
        .as_ref()
        .and_then(|info| info.get_session_or_direct_relationship(agent_ids))
}

#[macro_export]
macro_rules! impl_link_info_methods {
    ($struct_name:ident, $link_info_field:ident) => {
        impl $struct_name {
            pub fn get_link_lemid(
                &self,
                agent_ids: &[MeshId],
            ) -> Option<LinkedEntityKeychainMeshId> {
                agent_get_link_lemid(&self.$link_info_field, agent_ids)
            }

            pub fn get_relationship(
                &self,
                agent_ids: &[MeshId],
            ) -> Option<&AgentMeshRelationshipAndPermissions> {
                agent_get_relationship(&self.$link_info_field, agent_ids)
            }

            pub fn get_authorization_checker(&self) -> AuthorizationChecker {
                AuthorizationChecker::new(&self.$link_info_field)
            }
        }
    };
}

/// current state of bootstrapping the agent with its trustee
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub(crate) enum AgentBootstrapState {
    NotStarted,
    Started,
    Completed,
}

/// Configuration data an agent receives from its trustee
#[derive(Clone)]
pub struct AgentConfigData {
    pub data: BTreeMap<String, String>,
}

impl AgentConfigData {
    pub fn get_config(&self, name: &str) -> Option<String> {
        self.data.get(name).cloned()
    }
    pub fn get_config_required(&self, name: &str) -> Result<String, MeshError> {
        self.get_config(name)
            .ok_or_else(|| log_error!(MeshError::RequestFailed(format!("{} not found", name))))
    }
}

/// Bootstrap data an agent receives from its trustee on startup
#[derive(Clone)]
pub struct AgentBootstrapData {
    pub config: AgentConfigData,
    pub uns_records: Vec<UnsRecord>,
    pub key_pairs: Vec<BootstrapKeyPair>,
}

impl AgentBootstrapData {
    pub fn get_record_by_name(&self, name: &str) -> Option<&UnsRecord> {
        self.uns_records.iter().find(|record| record.name == name)
    }
    pub fn get_record_by_name_must_exist(&self, name: &str) -> &UnsRecord {
        self.get_record_by_name(name)
            .unwrap_or_else(|| panic!("{name:?} record not found"))
    }
    pub fn get_record_by_id(&self, id: MeshId) -> Option<&UnsRecord> {
        self.uns_records.iter().find(|record| record.id == id)
    }
    pub fn get_record_by_id_must_exist(&self, id: MeshId) -> &UnsRecord {
        self.get_record_by_id(id)
            .unwrap_or_else(|| panic!("{id:?} record not found"))
    }

    pub fn get_agent_id(&self, name: &str) -> Result<MeshId, MeshError> {
        self.get_record_by_name(name)
            .map(|record| record.id)
            .ok_or_else(|| {
                MeshError::BootstrapFailed(format!("bootstrap data missing record for {name:?}"))
            })
    }
}

pub type MutateStatus = u32;

/// Used for mutate operations
#[derive(Clone, Default)]
pub struct MutateCallbackResultData {
    pub lemid_operations: Option<Vec<DataOperation>>,
    pub emid_operations: Option<Vec<DataOperation>>,
    pub mutate_status: Option<MutateStatus>,
}

/// Used for mutate operations
#[derive(Clone)]
pub struct MutateReplyData {
    pub old_data_entry: Option<DataEntry>,
    pub data_entry: DataEntry,
    pub mutate_status: Option<MutateStatus>,
}

/// Used for data operations involved in synchronizing a request between agents
#[derive(Clone, Serialize, Deserialize)]
struct AgentLockData {
    pub node_name: String,
    pub lock_time: i64,
}

/// Data an agent receives when it gets a request from a trustee or another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentLinkEntityRequestData {
    pub link_request_id: LinkRequestId,
    pub emid: MeshEntityKeychainMeshId,
    pub entity_type: MeshEntityType,
    pub lemid_to_be_created: LinkedEntityKeychainMeshId,
    pub alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
    pub requestor_agent_id: MeshId,
    pub message: Option<WrappedMessage>,
    pub is_new_entity: bool,
    pub link_info: Option<AgentMeshLinkInfo>,
    pub invite_links: Option<Vec<AgentToAgentLinkEntityInviteLink>>,
    pub is_link_to_session: bool,
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestorData>,
}
impl_link_info_methods!(AgentToAgentLinkEntityRequestData, link_info);

impl AgentToAgentLinkEntityRequestData {
    pub fn no_default_auth_handler(&self) -> bool {
        self.via_external_id_requestor.is_some()
    }
    pub fn get_link_info(&self) -> &Option<AgentMeshLinkInfo> {
        if let Some(via_external_id) = &self.via_external_id_requestor {
            &via_external_id.link_info
        } else {
            &self.link_info
        }
    }
}

/// Data an agent receives when it gets a link entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentLinkEntityPostCreateRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub link_info: Option<AgentMeshLinkInfo>,
    pub requestor_agent_id: MeshId,
    pub is_new_entity: bool,
}
impl_link_info_methods!(AgentToAgentLinkEntityPostCreateRequestData, link_info);

/// Data an agent receives when it gets a link entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentLinkEntityPreCreateRequestData {
    pub link_request_id: LinkRequestId,
    pub entity_type: MeshEntityType,
    pub requestor_agent_id: MeshId,
    pub message: Option<WrappedMessage>,
    pub is_new_entity: bool,
    pub link_info: Option<AgentMeshLinkInfo>,
    pub is_link_to_session: bool,
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestorData>,
    pub alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
}
impl_link_info_methods!(AgentToAgentLinkEntityPreCreateRequestData, link_info);

impl AgentToAgentLinkEntityPreCreateRequestData {
    pub fn no_default_auth_handler(&self) -> bool {
        self.via_external_id_requestor.is_some()
    }
    pub fn get_link_info(&self) -> &Option<AgentMeshLinkInfo> {
        if let Some(via_external_id) = &self.via_external_id_requestor {
            &via_external_id.link_info
        } else {
            &self.link_info
        }
    }
}

/// Data an agent receives when it gets a unlink entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentUnlinkEntitiesRequestDataEntity {
    pub emid: MeshEntityKeychainMeshId,
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub link_info: Option<AgentMeshLinkInfo>,
}
impl_link_info_methods!(AgentToAgentUnlinkEntitiesRequestDataEntity, link_info);

/// Data an agent receives when it gets a link entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentUnlinkEntitiesRequestData {
    pub requestor_agent_id: MeshId,
    pub entities: Vec<AgentToAgentUnlinkEntitiesRequestDataEntity>,
}

/// Data an agent receives when it gets a link entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentLinkEntityViaDelegateRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub entity_type: MeshEntityType,
    pub requestor_lemid_to_be_created: LinkedEntityKeychainMeshId,
    pub requestor_alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
    pub requestor_agent_id: MeshId,
    pub requestor_link_info: Option<AgentMeshLinkInfo>,
    pub delegate_link_info: Option<AgentMeshLinkInfo>,
    pub message: Option<WrappedMessage>,
    pub delegate_lemid: LinkedEntityKeychainMeshId,
    pub is_link_to_session: bool,
}
impl_link_info_methods!(
    AgentToAgentLinkEntityViaDelegateRequestData,
    requestor_link_info
);

/// Data an agent receives when it gets a link via delegate request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentLinkEntityViaDelegateRequestSessionData {
    pub emid: MeshEntityKeychainMeshId,
    pub requestor_lemid: LinkedEntityKeychainMeshId,
    pub requestor_alemid: AgentLinkedEntityKeychainMeshId,
    pub requestor_agent_id: MeshId,
    pub target_lemid: LinkedEntityKeychainMeshId,
    pub target_alemid: AgentLinkedEntityKeychainMeshId,
    pub target_agent_id: MeshId,
    pub message: Option<WrappedMessage>,
    pub requestor_link_info: Option<AgentMeshLinkInfo>,
    pub delegate_link_info: Option<AgentMeshLinkInfo>,
    pub delegate_lemid: LinkedEntityKeychainMeshId,
    pub delegate_alemid: AgentLinkedEntityKeychainMeshId,
    pub delegate_agent_id: MeshId,
}
impl_link_info_methods!(
    AgentToAgentLinkEntityViaDelegateRequestSessionData,
    requestor_link_info
);

/// Data an agent receives when it gets a link via external id request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentGetLinkCodesViaExternalIdRequestorData {
    pub emid: MeshEntityKeychainMeshId,
    pub lemid: Option<LinkedEntityKeychainMeshId>,
    pub link_info: Option<AgentMeshLinkInfo>,
}

impl From<AgentToAgentGetLinkCodesViaExternalIdRequestor>
    for AgentToAgentGetLinkCodesViaExternalIdRequestorData
{
    fn from(data: AgentToAgentGetLinkCodesViaExternalIdRequestor) -> Self {
        Self {
            emid: data.emid,
            lemid: data.lemid,
            link_info: data.link_info,
        }
    }
}

/// Data an agent receives when it gets a get link codes request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentGetLinkCodesRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub lemid: LinkedEntityKeychainMeshId,
    pub message: Option<WrappedMessage>,
    pub link_info: Option<AgentMeshLinkInfo>,
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestorData>,
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}
impl AgentToAgentGetLinkCodesRequestData {
    pub fn get_link_lemid(&self, agent_ids: &[MeshId]) -> Option<LinkedEntityKeychainMeshId> {
        let link_info = self.get_link_info();
        agent_get_link_lemid(link_info, agent_ids)
    }

    pub fn get_relationship(
        &self,
        agent_ids: &[MeshId],
    ) -> Option<&AgentMeshRelationshipAndPermissions> {
        let link_info = self.get_link_info();
        agent_get_relationship(link_info, agent_ids)
    }

    pub fn get_authorization_checker(&self) -> AuthorizationChecker {
        let link_info = self.get_link_info();
        AuthorizationChecker::new(link_info)
    }

    pub fn get_link_info(&self) -> &Option<AgentMeshLinkInfo> {
        if let Some(via_external_id) = &self.via_external_id_requestor {
            &via_external_id.link_info
        } else {
            &self.link_info
        }
    }

    pub fn no_default_auth_handler(&self) -> bool {
        self.via_external_id_requestor.is_some()
    }
}

/// Data an agent receives when it gets a create temp entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentCreateTempEntityRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub message: Option<WrappedMessage>,
    pub entity_type: MeshEntityType,
    pub requestor_agent_id: MeshId,
    pub is_new_entity: bool,
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestorData>,
    pub external_id: ExternalLinkIdType,
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

/// Data an agent receives when it gets a merge entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentMergeTempEntityRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub merge_emids: Vec<MeshEntityKeychainMeshId>,
}

/// Data an agent receives when it gets an entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentEntityRequestData {
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub emid: MeshEntityKeychainMeshId,
    pub message: WrappedMessage,
    pub link_info: Option<AgentMeshLinkInfo>,
}
impl_link_info_methods!(AgentToAgentEntityRequestData, link_info);

/// Data an agent receives when it gets an entity request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentEntityOnNodeInstanceRequestData {
    pub emid: MeshEntityKeychainMeshId,
    pub message: WrappedMessage,
}

/// Data an agent receives when it gets an entity to all entities request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentEntityPerAllEntitiesRequestData {
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub emid: MeshEntityKeychainMeshId,
    pub link_info: Option<AgentMeshLinkInfo>,
}
impl_link_info_methods!(AgentToAgentEntityPerAllEntitiesRequestData, link_info);

/// Data an agent receives when it gets an entity to all entities request from another agent
#[derive(Clone, Debug)]
pub struct AgentToAgentAllEntitiesRequestData {
    pub entities: Vec<AgentToAgentEntityPerAllEntitiesRequestData>,
    pub message: WrappedMessage,
}

/// Data an agent sends back when it gets an entity to all entities request from another agent
#[derive(Clone)]
pub struct AgentToAgentAllEntitiesResponseDataElement {
    pub emid: MeshEntityKeychainMeshId,
    pub lemid: LinkedEntityKeychainMeshId,
    pub response_message: WrappedMessage,
}

/// Data an agent sends back when it gets an entity to all entities request from another agent
#[derive(Clone)]
pub struct AgentToAgentAllEntitiesResponseData {
    pub responses: Vec<AgentToAgentAllEntitiesResponseDataElement>,
}

/// Data an agent sends back when it gets a link entity request from another agent
#[derive(Clone, Default)]
pub struct AgentToAgentLinkEntityResponseData {
    pub agent_emid_operations: Option<Vec<DataOperation>>,
    pub emid_operations: Option<Vec<DataOperation>>,
    pub lemid_operations: Option<Vec<DataOperation>>,
    pub message: Option<WrappedMessage>,
    pub expiration_time: Option<i64>,
    pub link_updates: Option<AgentMeshLinkUpdates>,
    pub invite_lemid_operations: Option<Vec<LemidAndDataOperations>>,
}

/// Data an agent sends back when it gets a link entity request from another agent
#[derive(Clone, Default)]
pub struct AgentToAgentLinkEntityPreCreateResponseData {
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

/// Data an agent sends back when it gets a link entity request from another agent
#[derive(Clone)]
pub struct AgentToAgentLinkEntityViaDelegateResponseData {
    pub emid_operations: Option<Vec<DataOperation>>,
    pub lemid_operations: Option<Vec<DataOperation>>,
    pub message: Option<WrappedMessage>,
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

/// Data an agent sends back when it gets a link via delegate request from another agent
#[derive(Clone)]
pub struct AgentToAgentLinkEntityViaDelegateSessionResponseData {
    pub emid_operations: Option<Vec<DataOperation>>,
    pub lemid_operations: Option<Vec<DataOperation>>,
    pub message: Option<WrappedMessage>,
    pub link_updates: Option<AgentMeshLinkUpdatesForSession>,
}

/// Data an agent sends back when it gets a get link codes request from another agent
#[derive(Clone)]
pub struct AgentToAgentGetLinkCodesResponseData {
    pub message: Option<WrappedMessage>,
    pub human_proxy_agent_link_code: Option<MeshLinkCode>,
}

/// Data an agent sends back when it gets a create temp entity request from another agent
#[derive(Clone, Default)]
pub struct AgentToAgentCreateTempEntityResponseData {
    pub message: Option<WrappedMessage>,
    pub emid_operations: Option<Vec<DataOperation>>,
    pub human_proxy_agent_link_code: Option<MeshLinkCode>,
}

/// Data an agent receives for a request
#[derive(Clone, Debug)]
pub enum AgentHandlerRoutingRequestType {
    TrusteeOrAgentToAgent(WrappedMessage),
    AgentToAgentEntity(AgentToAgentEntityRequestData),
    AgentToAgentEntityOnNodeInstance(AgentToAgentEntityOnNodeInstanceRequestData),
    AgentToAgentAllEntities(AgentToAgentAllEntitiesRequestData),
    AgentToAgentLinkEntity(AgentToAgentLinkEntityRequestData),
    AgentToAgentLinkEntityPostCreate(AgentToAgentLinkEntityPostCreateRequestData),
    AgentToAgentLinkEntityPreCreate(AgentToAgentLinkEntityPreCreateRequestData),
    AgentToAgentUnlinkEntities(AgentToAgentUnlinkEntitiesRequestData),
    AgentToAgentLinkEntityViaDelegate(AgentToAgentLinkEntityViaDelegateRequestData),
    AgentToAgentLinkEntityViaDelegateSession(AgentToAgentLinkEntityViaDelegateRequestSessionData),
    AgentToAgentGetLinkCodes(AgentToAgentGetLinkCodesRequestData),
    AgentToAgentCreateTempEntity(AgentToAgentCreateTempEntityRequestData),
    AgentToAgentMergeTempEntity(AgentToAgentMergeTempEntityRequestData),
}

impl fmt::Display for AgentHandlerRoutingRequestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AgentHandlerRoutingRequestType::TrusteeOrAgentToAgent(_) => write!(f, "AgentToAgent"),
            AgentHandlerRoutingRequestType::AgentToAgentEntity(_) => {
                write!(f, "AgentToAgentEntity")
            }
            AgentHandlerRoutingRequestType::AgentToAgentEntityOnNodeInstance(_) => {
                write!(f, "AgentToAgentEntityOnNodeInstance")
            }
            AgentHandlerRoutingRequestType::AgentToAgentAllEntities(_) => {
                write!(f, "AgentToAgentAllEntities")
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(_) => {
                write!(f, "AgentToAgentLinkEntity")
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(_) => {
                write!(f, "AgentToAgentLinkEntityPostCreate")
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(_) => {
                write!(f, "AgentToAgentLinkEntityPreCreate")
            }
            AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(_) => {
                write!(f, "AgentToAgentUnlinkEntities")
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(_) => {
                write!(f, "AgentToAgentLinkEntityViaDelegate")
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(_) => {
                write!(f, "AgentToAgentLinkEntityViaDelegateSession")
            }
            AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(_) => {
                write!(f, "AgentToAgentGetLinkCodes")
            }
            AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(_) => {
                write!(f, "AgentToAgentCreateTempEntity")
            }
            AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(_) => {
                write!(f, "AgentToAgentMergeTempEntity")
            }
        }
    }
}

/// Data an agent sends back for a request
#[derive(Clone)]
pub enum AgentHandlerRoutingResponseType {
    TrusteeOrAgentToAgent(WrappedMessage),
    AgentToAgentEntity(WrappedMessage),
    AgentToAgentEntityOnNodeInstance(WrappedMessage),
    AgentToAgentAllEntities(AgentToAgentAllEntitiesResponseData),
    AgentToAgentLinkEntity(AgentToAgentLinkEntityResponseData),
    AgentToAgentLinkEntityPostCreate(),
    AgentToAgentLinkEntityPreCreate(AgentToAgentLinkEntityPreCreateResponseData),
    AgentToAgentLinkEntityViaDelegate(AgentToAgentLinkEntityViaDelegateResponseData),
    AgentToAgentLinkEntityViaDelegateSession(AgentToAgentLinkEntityViaDelegateSessionResponseData),
    AgentToAgentGetLinkCodes(AgentToAgentGetLinkCodesResponseData),
    AgentToAgentCreateTempEntity(AgentToAgentCreateTempEntityResponseData),
    AgentToAgentMergeTempEntity(),
    AgentToAgentUnlinkEntities(),
}

/// Functions for extracting data from a request
#[derive(Clone, Debug)]
pub struct AgentHandlerRoutingRequest {
    pub network_request_id: MeshMessageId,
    pub source_trusteee_or_agent_id: MeshId,
    pub request_type: AgentHandlerRoutingRequestType,
    pub context_id: Option<ContextId>,
}

impl AgentHandlerRoutingRequest {
    pub fn get_message(&self) -> Option<&WrappedMessage> {
        match &self.request_type {
            AgentHandlerRoutingRequestType::TrusteeOrAgentToAgent(message) => Some(message),
            AgentHandlerRoutingRequestType::AgentToAgentEntity(data) => Some(&data.message),
            AgentHandlerRoutingRequestType::AgentToAgentEntityOnNodeInstance(data) => {
                Some(&data.message)
            }
            AgentHandlerRoutingRequestType::AgentToAgentAllEntities(data) => Some(&data.message),
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(data) => data.message.as_ref(),
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(data) => {
                data.message.as_ref()
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(data) => {
                data.message.as_ref()
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(data) => {
                data.message.as_ref()
            }
            AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(data) => data.message.as_ref(),
            AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(data) => {
                data.message.as_ref()
            }
            AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(_)
            | AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(_)
            | AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(_) => None,
        }
    }

    pub fn get_message_subsystem(&self) -> Option<MeshSubsystem> {
        self.get_message().map(|message| message.subsystem)
    }

    pub fn get_message_type(&self) -> Option<MeshMessageType> {
        self.get_message().map(|message| message.message_type)
    }

    pub fn has_message(&self) -> bool {
        self.get_message().is_some()
    }

    pub fn get_message_required(&self) -> Result<&WrappedMessage, MeshError> {
        self.get_message()
            .ok_or_else(|| log_error!(MeshError::BadState))
    }

    pub fn get_link_info(&self) -> &Option<AgentMeshLinkInfo> {
        match &self.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(data) => data.get_link_info(),
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegate(data) => {
                &data.requestor_link_info
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(data) => {
                &data.link_info
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(data) => {
                data.get_link_info()
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityViaDelegateSession(data) => {
                &data.requestor_link_info
            }
            AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(data) => data.get_link_info(),
            AgentHandlerRoutingRequestType::AgentToAgentEntity(data) => &data.link_info,
            AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(data) => {
                match &data.via_external_id_requestor {
                    Some(v) => &v.link_info,
                    None => &None,
                }
            }
            _ => &None,
        }
    }

    pub fn no_default_auth_handler(&self) -> bool {
        match &self.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentGetLinkCodes(data) => {
                data.no_default_auth_handler()
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntity(data) => {
                data.no_default_auth_handler()
            }
            AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPreCreate(data) => {
                data.no_default_auth_handler()
            }
            AgentHandlerRoutingRequestType::AgentToAgentCreateTempEntity(_) => true,
            _ => false,
        }
    }

    pub fn authorization_check(
        &self,
        authorization_handler: &AuthorizationHandler,
    ) -> Result<(), MeshError> {
        let link_infos: Box<dyn Iterator<Item = _>> = match &self.request_type {
            AgentHandlerRoutingRequestType::AgentToAgentUnlinkEntities(data) => {
                Box::new(data.entities.iter().map(|entity| &entity.link_info))
            }
            AgentHandlerRoutingRequestType::AgentToAgentAllEntities(data) => {
                Box::new(data.entities.iter().map(|entity| &entity.link_info))
            }
            AgentHandlerRoutingRequestType::AgentToAgentEntityOnNodeInstance(_)
            | AgentHandlerRoutingRequestType::AgentToAgentLinkEntityPostCreate(_)
            | AgentHandlerRoutingRequestType::AgentToAgentMergeTempEntity(_) => {
                // no check
                return Ok(());
            }
            _ => Box::new(core::iter::once(self.get_link_info())),
        };
        link_infos
            .map(|link_info| {
                authorization_handler(self, link_info).map_err(|err| {
                    error!(
                        "request {} failed: {} - {:?} {:?} : {:?}",
                        self.request_type,
                        err,
                        self.get_message_subsystem(),
                        self.get_message_type(),
                        link_info,
                    );
                    err
                })
            })
            .collect()
    }
}

#[derive(Clone)]
pub(crate) struct AgentHandlerRoutingState {
    pub(crate) request_type: AgentHandlerRoutingRequestType,
    pub(crate) message: MeshMessage,
    pub(crate) reply_error: Option<MeshError>,
    pub(crate) reply_data: Option<AgentHandlerRoutingResponseType>,
    pub(crate) reply_status: Option<MeshStatusType>,
    pub(crate) reply_status_message: Option<String>,
    pub(crate) response_message_type: AgentMessageType,
}

pub(crate) struct AgentHandlerInternal {
    pub(crate) agent_id: MeshId,
    pub(crate) agent_trustee_id: MeshId,
    pub(crate) listener_enclave_id: Option<MeshId>,
    pub(crate) listener_subsystem: Option<MeshSubsystem>,
    pub(crate) requests: RequestTable,
    pub(crate) agent_name: String,
    pub(crate) bootstrap_state: AgentBootstrapState,
    pub(crate) agent_emid: Option<MeshEntityKeychainMeshId>,

    pub(crate) routing_table: RoutingTable,
    pub(crate) handler_routing_table: RoutingTableGeneric<
        RouterMessageKey,
        AgentHandlerRoutingRequest,
        Result<AgentHandlerResultData, MeshError>,
        (),
    >,
    pub(crate) pending_request_states: HashMap<MeshId, AgentHandlerRoutingState>,
    pub(crate) default_handle_link_via_delegate_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_link_via_delegate_session_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_get_link_codes_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_unlink_entities_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_create_temp_entity_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_merge_temp_entity_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_link_entity_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_link_entity_post_create_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
    pub(crate) default_handle_link_entity_pre_create_route: Option<
        Arc<RouterData<AgentHandlerRoutingRequest, Result<AgentHandlerResultData, MeshError>>>,
    >,
}

/// This struct has all the functions an agent can use when communicating with its trustee or other agents
#[derive(Clone)]
pub struct AgentHandler {
    pub(crate) state: Arc<RwLock<AgentHandlerInternal>>,
}

/// Data an agent receives when it makes a create entity request
pub struct CreateEntityResult {
    pub emid: MeshEntityKeychainMeshId,
}

/// Data an agent receives when it makes a link entity request
pub struct LinkEntityOnSameAgentResult {
    pub destination_emid: MeshEntityKeychainMeshId,
    pub source_lemid: LinkedEntityKeychainMeshId,
    pub destination_lemid: LinkedEntityKeychainMeshId,
    pub source_alemid: AgentLinkedEntityKeychainMeshId,
    pub destination_alemid: AgentLinkedEntityKeychainMeshId,
}

/// Data an agent receives when it makes a get certificate request
pub struct GetCertificateAuthoritiesResult {
    pub ca_pem: Vec<u8>,
}

/// Data an agent receives when it makes a lookup entity request
pub struct LookupEntityOnSameAgentResult {
    pub emid: MeshEntityKeychainMeshId,
}

/// Data an agent receives when it makes a data operation request
pub struct DataOperationForEntityResult {
    pub result: Vec<AgentDataOperationForEntityOutput>,
}

/// Data an agent receives when it makes a create uns record request
pub struct CreateUnsRecordsResult {
    pub records: Vec<UnsRecord>,
}

/// Data an agent receives when it makes a lookup uns record request
pub struct LookupUnsRecordsResult {
    pub records: Vec<UnsRecord>,
}

impl DataOperationForEntityResult {
    pub fn get_emid_entry(&self, result_index: usize, emid_index: usize) -> Option<&Vec<u8>> {
        self.get_emid_data_entry(result_index, emid_index)
            .and_then(|result| result.data.as_ref())
    }

    pub fn get_emid_data_entry(
        &self,
        result_index: usize,
        emid_index: usize,
    ) -> Option<&DataEntry> {
        self.result
            .get(result_index)
            .and_then(|result| result.emid_operations_result.get(emid_index))
    }

    pub fn get_emid_data_entry_mut(
        &mut self,
        result_index: usize,
        emid_index: usize,
    ) -> Option<&mut DataEntry> {
        self.result
            .get_mut(result_index)
            .and_then(|result| result.emid_operations_result.get_mut(emid_index))
    }

    pub fn get_lemid_entry(&self, result_index: usize, lemid_index: usize) -> Option<&Vec<u8>> {
        self.get_lemid_data_entry(result_index, lemid_index)
            .and_then(|result| result.data.as_ref())
    }

    pub fn get_lemid_data_entry(
        &self,
        result_index: usize,
        lemid_index: usize,
    ) -> Option<&DataEntry> {
        self.result
            .get(result_index)
            .and_then(|result| result.lemid_operations_result.get(lemid_index))
    }

    pub fn get_lemid_data_entry_mut(
        &mut self,
        result_index: usize,
        lemid_index: usize,
    ) -> Option<&mut DataEntry> {
        self.result
            .get_mut(result_index)
            .and_then(|result| result.lemid_operations_result.get_mut(lemid_index))
    }
}

/// Data an agent receives when it makes a lookup linked entities request
pub struct LookupLinkedEntitiesResult {
    pub entities: Vec<AgentLinkedEntity>,
}

/// Data an agent receives when it makes a get link codes request
pub struct GetLinkCodesResult {
    pub link_codes: Vec<MeshLinkCode>,
    pub reply_message: Option<WrappedMessage>,
}

/// Data an agent receives when it makes a link entity request
pub struct LinkEntityResult {
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub reply_message: Option<WrappedMessage>,
    pub max_uses: Option<u64>,
}

/// Data an agent receives when it makes a link via delegate request
pub struct LinkEntityViaDelegateResult {
    pub lemid: LinkedEntityKeychainMeshId,
    pub alemid: AgentLinkedEntityKeychainMeshId,
    pub reply_message: Option<WrappedMessage>,
}

/// Data an agent receives when it makes a send message request
pub struct SendMessageToLinkedEntityResult {
    pub reply_message: WrappedMessage,
}

/// Data an agent receives when it makes a send message request
pub struct SendMessageToEntityOnNodeInstanceResult {
    pub reply_message: WrappedMessage,
}

/// Data an agent receives when it makes an udate link info request
pub struct UpdateLinkInfoResult {
    pub link_info: AgentMeshLinkInfo,
}

/// Data an agent receives when it makes a refresh link info request
pub struct RefreshLinkInfoResult {
    pub link_info: AgentMeshLinkInfo,
}

/// Data an agent receives when checking authorziation permissions on a link
pub struct CheckPermissionsResultEntry {
    pub permission: MeshPermission,
    pub allowed: bool,
}

/// Data an agent receives when checking authorziation permissions on a link
pub struct CheckPermissionsResult {
    pub permissions: Vec<CheckPermissionsResultEntry>,
}

/// Data an agent receives when forwarding a message
pub struct ForwardMessageResult {
    pub reply_message: WrappedMessage,
}

/// Data an agent receives when sending a message to all entities linked to an entity
pub struct SendMessageToAllLinkedEntitiesResultForEntity {
    pub lemid: LinkedEntityKeychainMeshId,
    pub reply_message: WrappedMessage,
}

/// Data an agent receives when sending a message to all entities linked to an entity
pub struct SendMessageToAllLinkedEntitiesResult {
    pub entities: Vec<SendMessageToAllLinkedEntitiesResultForEntity>,
}

/// Data an agent receives when sending a message to an agent
pub struct SendMessageToAgentResult {
    pub reply_message: WrappedMessage,
}

/// Data an agent receives when sending a message to an trustee
pub struct SendMessageToTrusteeResult {
    pub reply_message: WrappedMessage,
}

pub type AsyncAgentTask = Pin<
    Box<
        dyn Future<Output = Result<AgentHandlerRoutingResponseType, MeshError>>
            + Send
            + Sync
            + 'static,
    >,
>;

/// Data an agent sends back for a request
pub enum AgentHandlerResultDataResponse {
    ImmediateResponse(AgentHandlerRoutingResponseType),
    EventualResponse,
    Async(AsyncAgentTask),
    // if we need to add NoResponse in the future, we can do that
}

/// Data an agent receives for a request
pub struct AgentHandlerResultData {
    pub messages: Vec<MeshMessage>,
    pub response: AgentHandlerResultDataResponse,
}

impl AgentHandler {
    pub fn new(
        name: String,
        agent_id: MeshId,
        agent_trustee_id: MeshId,
        listener_enclave_id: Option<MeshId>,
        listener_subsystem: Option<MeshSubsystem>,
        requests: RequestTable,
        routing_table: RoutingTable,
    ) -> AgentHandler {
        let default_handle_link_entity_post_create_route = Some(Arc::new(RouterData {
            router_callback: Box::new(|_| {
                Ok(AgentHandlerResultData {
                    messages: vec![],
                    response: AgentHandlerResultDataResponse::ImmediateResponse(
                        AgentHandlerRoutingResponseType::AgentToAgentLinkEntityPostCreate(),
                    ),
                })
            }),
        }));
        let default_handle_link_entity_pre_create_route = Some(Arc::new(RouterData {
            router_callback: Box::new(|_| {
                Ok(AgentHandlerResultData {
                    messages: vec![],
                    response: AgentHandlerResultDataResponse::ImmediateResponse(
                        AgentHandlerRoutingResponseType::AgentToAgentLinkEntityPreCreate(
                            AgentToAgentLinkEntityPreCreateResponseData { link_updates: None },
                        ),
                    ),
                })
            }),
        }));

        let agent = AgentHandler {
            state: Arc::new(RwLock::new(AgentHandlerInternal {
                agent_id,
                agent_trustee_id,
                listener_enclave_id,
                listener_subsystem,
                requests,
                routing_table,
                bootstrap_state: AgentBootstrapState::NotStarted,
                pending_request_states: HashMap::new(),
                handler_routing_table: RoutingTableGeneric::<
                    RouterMessageKey,
                    AgentHandlerRoutingRequest,
                    Result<AgentHandlerResultData, MeshError>,
                    (),
                >::new(),
                agent_name: name,
                default_handle_link_via_delegate_route: None,
                default_handle_link_via_delegate_session_route: None,
                default_handle_unlink_entities_route: None,
                default_handle_get_link_codes_route: None,
                default_handle_create_temp_entity_route: None,
                default_handle_merge_temp_entity_route: None,
                default_handle_link_entity_route: None,
                default_handle_link_entity_post_create_route,
                default_handle_link_entity_pre_create_route,
                agent_emid: None,
            })),
        };
        {
            let mut state = agent.state.write().unwrap();
            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentEntityRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_entity_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentEntityOnNodeInstanceRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_entity_on_node_instance_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::TrusteeOrAgentToAgentRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_trustee_or_agent_to_agent_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentLinkEntityRequestType.into(),
                Box::new(move |message: MeshMessage| {
                    cloned_agent.process_agent_to_agent_link_entity_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentLinkEntityViaDelegateRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_link_entity_via_delegate_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentLinkEntityViaDelegateSessionRequestType.into(),
                Box::new(move |message| {
                    cloned_agent
                        .process_agent_to_agent_link_entity_via_delegate_session_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentGetLinkCodesRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_get_link_codes_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentCreateTempEntityRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_create_temp_entity_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentMergeTempEntityRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_merge_temp_entity_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentUnlinkEntitiesRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_unlink_entities_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentAllEntitiesRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_all_entities_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentLinkEntityPostCreateRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_link_entity_post_create_request(message)
                }),
            );

            let cloned_agent = agent.clone();
            state.routing_table.add_route(
                MeshSubsystem::Agent,
                AgentMessageType::AgentToAgentLinkEntityPreCreateRequestType.into(),
                Box::new(move |message| {
                    cloned_agent.process_agent_to_agent_link_entity_pre_create_request(message)
                }),
            );
        }
        return agent;
    }

    pub(crate) fn get_bootstrap_state(&self) -> AgentBootstrapState {
        self.state.read().unwrap().bootstrap_state
    }

    pub fn is_bootstrapped(&self) -> bool {
        self.get_bootstrap_state() == AgentBootstrapState::Completed
    }

    pub fn create_and_link_entity_on_same_agent(
        &self,
        source_emid: MeshEntityKeychainMeshId,
        entity_type: Option<MeshEntityType>,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        link_updates_source: Option<AgentMeshLinkUpdates>,
        link_updates_destination: Option<AgentMeshLinkUpdates>,
        reply_callback: ReplyCallback<LinkEntityOnSameAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentCreateAndLinkEntityOnSameAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            entity_type,
            source_emid,
            data_operations,
            expiration_time,
            link_updates_source,
            link_updates_destination,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(|resp: AgentCreateAndLinkEntityOnSameAgentResponse| {
                        LinkEntityOnSameAgentResult {
                            source_lemid: resp.source_lemid,
                            destination_lemid: resp.destination_lemid,
                            destination_emid: resp.destination_emid,
                            source_alemid: resp.source_alemid,
                            destination_alemid: resp.destination_alemid,
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_create_and_link_entity_on_same_agent(
        &self,
        source_emid: MeshEntityKeychainMeshId,
        entity_type: Option<MeshEntityType>,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        link_updates_source: Option<AgentMeshLinkUpdates>,
        link_updates_destination: Option<AgentMeshLinkUpdates>,
        context_id: Option<ContextId>,
    ) -> Result<LinkEntityOnSameAgentResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentCreateAndLinkEntityOnSameAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            entity_type,
            source_emid,
            data_operations,
            expiration_time,
            link_updates_source,
            link_updates_destination,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|resp: AgentLinkEntityOnSameAgentResponse| {
                Ok(LinkEntityOnSameAgentResult {
                    source_lemid: resp.source_lemid,
                    destination_lemid: resp.destination_lemid,
                    destination_emid: resp.destination_emid,
                    source_alemid: resp.source_alemid,
                    destination_alemid: resp.destination_alemid,
                })
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn link_entity_on_same_agent(
        &self,
        source_emid: MeshEntityKeychainMeshId,
        link_code: MeshLinkCode,
        link_updates_source: Option<AgentMeshLinkUpdates>,
        link_updates_destination: Option<AgentMeshLinkUpdates>,
        reply_callback: ReplyCallback<LinkEntityOnSameAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentLinkEntityOnSameAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            source_emid,
            link_code,
            link_updates_source,
            link_updates_destination,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(
                        |resp: AgentLinkEntityOnSameAgentResponse| LinkEntityOnSameAgentResult {
                            source_lemid: resp.source_lemid,
                            destination_lemid: resp.destination_lemid,
                            destination_emid: resp.destination_emid,
                            source_alemid: resp.source_alemid,
                            destination_alemid: resp.destination_alemid,
                        },
                    )
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub fn lookup_entity_on_same_agent(
        &self,
        source_emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        reply_callback: ReplyCallback<LookupEntityOnSameAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentLookupEntityOnSameAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            source_emid,
            lemid,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(|AgentLookupEntityOnSameAgentResponse { emid }| {
                        LookupEntityOnSameAgentResult { emid }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub fn create_entity(
        &self,
        emid: Option<MeshEntityKeychainMeshId>,
        entity_type: Option<MeshEntityType>,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        reply_callback: ReplyCallback<CreateEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_create_entity(
                    emid,
                    entity_type,
                    data_operations,
                    expiration_time,
                    context_id,
                )
                .await
                .map_err(|e| log_error!("request failed: {}", e));
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub async fn async_create_entity(
        &self,
        emid: Option<MeshEntityKeychainMeshId>,
        entity_type: Option<MeshEntityType>,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        context_id: Option<ContextId>,
    ) -> Result<CreateEntityResult, MeshError> {
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentCreateEntityRequest::build_request(
            mesh_generate_mesh_id().unwrap(),
            own_id,
            agent_trustee_id,
            emid,
            entity_type,
            data_operations,
            expiration_time,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        let AgentCreateEntityResponse { emid } = response.extract_check_status()?;
        Ok(CreateEntityResult { emid })
    }

    pub fn mutate_emid_data(
        &self,
        emid: MeshEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        reply_callback: Box<
            dyn FnOnce(Result<MutateReplyData, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_mutate_emid_data(emid, key_path, mutate_callback, context_id)
                .await;
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub fn mutate_lemid_data(
        &self,
        emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        reply_callback: Box<
            dyn FnOnce(Result<MutateReplyData, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_mutate_lemid_data(emid, lemid, key_path, mutate_callback, context_id)
                .await;
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub fn data_operation_for_entity(
        &self,
        operations: Vec<AgentDataOperationForEntityInput>,
        reply_callback: ReplyCallback<DataOperationForEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentDataOperationForEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            operations.clone(),
            context_id,
        )?;
        let env = core::option_env!("BUILD_ENV").unwrap_or("dev");
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(|AgentDataOperationForEntityResponse { result }| {
                        DataOperationForEntityResult { result }
                    })
                    .map_err(|e| {
                        if env == "dev" {
                            error!("failed operations: {:?}", operations);
                        }
                        log_error!("request failed: {}", e)
                    });
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_data_operation_for_entity(
        &self,
        operations: Vec<AgentDataOperationForEntityInput>,
        context_id: Option<ContextId>,
    ) -> Result<DataOperationForEntityResult, MeshError> {
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentDataOperationForEntityRequest::build_request(
            mesh_generate_mesh_id().unwrap(),
            own_id,
            agent_trustee_id,
            operations,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        let AgentDataOperationForEntityResponse { result } = response.extract_check_status()?;
        Ok(DataOperationForEntityResult { result })
    }

    pub async fn async_link_entity(
        &self,
        destination_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_link_id: LinkRequestId,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdates>,
        context_id: Option<ContextId>,
    ) -> Result<LinkEntityResult, MeshError> {
        self.async_link_entity_with_transform_error_option(
            destination_agent_id,
            emid,
            destination_link_id,
            request_message,
            link_updates,
            true,
            context_id,
        )
        .await
    }

    pub async fn async_link_entity_with_transform_error_option(
        &self,
        destination_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_link_id: LinkRequestId,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdates>,
        transform_error: bool,
        context_id: Option<ContextId>,
    ) -> Result<LinkEntityResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.map(|msg| msg.serialize()).transpose()?;
        let message = LinkEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            destination_agent_id,
            emid,
            destination_link_id,
            request_data,
            link_updates,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|resp: LinkEntityResponse| {
                let reply_message = resp
                    .response_message
                    .map(|resp| {
                        let reply_message = WrappedMessage::unserialize(&resp)?;
                        if !transform_error || reply_message.is_success_or_has_error_list_field() {
                            Ok(reply_message)
                        } else {
                            Err(agent_message_header_to_error(&reply_message))
                        }
                    })
                    .transpose()?;

                Ok(LinkEntityResult {
                    lemid: resp.lemid,
                    alemid: resp.alemid,
                    reply_message,
                    max_uses: resp.max_uses,
                })
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn link_entity(
        &self,
        destination_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_link_id: LinkRequestId,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdates>,
        reply_callback: ReplyCallback<LinkEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        self.link_entity_with_transform_error_option(
            destination_agent_id,
            emid,
            destination_link_id,
            request_message,
            link_updates,
            true,
            reply_callback,
            context_id,
        )
    }

    pub fn link_entity_with_transform_error_option(
        &self,
        destination_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_link_id: LinkRequestId,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdates>,
        transform_error: bool,
        reply_callback: ReplyCallback<LinkEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_link_entity_with_transform_error_option(
                    destination_agent_id,
                    emid,
                    destination_link_id,
                    request_message,
                    link_updates,
                    transform_error,
                    context_id,
                )
                .await;
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub fn link_entity_via_delegate(
        &self,
        delegate_lemid: LinkedEntityKeychainMeshId,
        session_link: SessionLinkType,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdatesForSession>,
        reply_callback: ReplyCallback<LinkEntityViaDelegateResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_link_entity_via_delegate(
                    delegate_lemid,
                    session_link,
                    request_message,
                    link_updates,
                    context_id,
                )
                .await
                .map_err(|e| log_error!("request error: {}", e));
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub async fn async_link_entity_via_delegate(
        &self,
        delegate_lemid: LinkedEntityKeychainMeshId,
        session_link: SessionLinkType,
        request_message: Option<WrappedMessage>,
        link_updates: Option<AgentMeshLinkUpdatesForSession>,
        context_id: Option<ContextId>,
    ) -> Result<LinkEntityViaDelegateResult, MeshError> {
        let request_data = match request_message {
            Some(request_message) => Some(request_message.serialize()?),
            None => None,
        };
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = LinkEntityViaDelegateRequest::build_request(
            mesh_generate_mesh_id().unwrap(),
            own_id,
            agent_trustee_id,
            delegate_lemid,
            session_link,
            request_data,
            link_updates,
            context_id,
        )?;
        let response_message = common_async::send_message(message, None).await?;
        let response: LinkEntityViaDelegateResponse = response_message.extract_check_status()?;
        let reply_message = response
            .response_message
            .map(|resp| {
                let reply_message = WrappedMessage::unserialize(&resp)?;
                if reply_message.is_success_or_has_error_list_field() {
                    Ok(reply_message)
                } else {
                    Err(agent_message_header_to_error(&reply_message))
                }
            })
            .transpose()?;
        Ok(LinkEntityViaDelegateResult {
            lemid: response.lemid,
            alemid: response.alemid,
            reply_message,
        })
    }

    pub fn unlink_entity(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        reply_callback: ReplyCallback<()>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = UnlinkEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lemid,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.check_status())
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        return Ok(vec![message]);
    }

    pub async fn async_unlink_entity(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<(), MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = UnlinkEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lemid,
            context_id,
        )?;
        common_async::send_message(message, None)
            .await?
            .check_status()
    }

    pub async fn async_unlink_entity_with_options(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        ignore_not_found: bool,
        context_id: Option<ContextId>,
    ) -> Result<(), MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = UnlinkEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lemid,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        if ignore_not_found {
            response.check_status_not_found_ok()
        } else {
            response.check_status()
        }
    }

    pub async fn async_delete_entity(
        &self,
        emid: MeshEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<(), MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentDeleteEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            emid,
            context_id,
        )?;
        common_async::send_message(message, None)
            .await?
            .check_status()
    }

    pub fn delete_entity(
        &self,
        emid: MeshEntityKeychainMeshId,
        reply_callback: ReplyCallback<()>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentDeleteEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            emid,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.check_status())
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub fn lookup_linked_entities(
        &self,
        emid: MeshEntityKeychainMeshId,
        agent_ids: Option<Vec<AgentIdWithAttributes>>,
        external_ids: Option<Vec<MeshExternalId>>,
        reply_callback: ReplyCallback<LookupLinkedEntitiesResult>,
        offset: Option<u64>,
        limit: Option<u64>,
        include_deleted: Option<bool>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let handler = self.clone();
        Ok(common_async::start_one_task(async move {
            let result = handler
                .async_lookup_linked_entities(
                    emid,
                    agent_ids,
                    external_ids,
                    offset,
                    limit,
                    include_deleted,
                    context_id,
                )
                .await
                .map_err(|e| log_error!("request failed: {}", e));
            match reply_callback(result) {
                Ok(msgs) => common_async::forward_messages(msgs),
                Err(err) => error!("reply callback error: {err}"),
            }
            Ok(())
        }))
    }

    pub async fn async_lookup_linked_entities(
        &self,
        emid: MeshEntityKeychainMeshId,
        agent_ids: Option<Vec<AgentIdWithAttributes>>,
        external_ids: Option<Vec<MeshExternalId>>,
        offset: Option<u64>,
        limit: Option<u64>,
        include_deleted: Option<bool>,
        context_id: Option<ContextId>,
    ) -> Result<LookupLinkedEntitiesResult, MeshError> {
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = LookupLinkedEntitiesRequest::build_request(
            mesh_generate_mesh_id().unwrap(),
            own_id,
            agent_trustee_id,
            emid,
            agent_ids,
            external_ids,
            offset,
            limit,
            include_deleted,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        let LookupLinkedEntitiesResponse { entities } = response.extract_check_status()?;
        Ok(LookupLinkedEntitiesResult { entities })
    }

    pub fn get_link_codes(
        &self,
        code_type: GetLinkCodesType,
        for_restriction: Option<GetLinkCodesForRestriction>,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<WrappedMessage>,
        reply_callback: ReplyCallback<GetLinkCodesResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = match request_message {
            Some(request_message) => Some(request_message.serialize()?),
            None => None,
        };
        let message = GetLinkCodesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            code_type,
            for_restriction,
            max_uses,
            expiration_time,
            request_data,
            context_id,
        )?;

        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(
                        |GetLinkCodesResponse {
                             response_message,
                             link_codes,
                         }| {
                            let reply_message = response_message
                                .as_deref()
                                .map(WrappedMessage::unserialize)
                                .transpose()?
                                .map(|msg| {
                                    if msg.is_success_or_has_error_list_field() {
                                        Ok(msg)
                                    } else {
                                        Err(agent_message_header_to_error(&msg))
                                    }
                                })
                                .transpose()?;
                            Ok(GetLinkCodesResult {
                                link_codes,
                                reply_message,
                            })
                        },
                    )
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_get_link_codes(
        &self,
        code_type: GetLinkCodesType,
        for_restriction: Option<GetLinkCodesForRestriction>,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<WrappedMessage>,
        context_id: Option<ContextId>,
    ) -> Result<GetLinkCodesResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = match request_message {
            Some(request_message) => Some(request_message.serialize()?),
            None => None,
        };
        let message = GetLinkCodesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            code_type,
            for_restriction,
            max_uses,
            expiration_time,
            request_data,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(
                |GetLinkCodesResponse {
                     response_message,
                     link_codes,
                 }| {
                    let reply_message = response_message
                        .as_deref()
                        .map(WrappedMessage::unserialize)
                        .transpose()?
                        .map(|msg| {
                            if msg.is_success_or_has_error_list_field() {
                                Ok(msg)
                            } else {
                                Err(agent_message_header_to_error(&msg))
                            }
                        })
                        .transpose()?;
                    Ok(GetLinkCodesResult {
                        link_codes,
                        reply_message,
                    })
                },
            )
            .map_err(|e| log_error!("request failed: {}", e))
    }

    // future function to update link info
    pub fn update_link_info(
        &self,
        _lemid: LinkedEntityKeychainMeshId,
        _link_info: AgentMeshLinkInfo,
        _reply_callback: Box<
            dyn Fn(Result<UpdateLinkInfoResult, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send,
        >,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        return Err(MeshError::NotSupported);
    }

    // future function to refresh link info
    pub fn refresh_link_info(
        &self,
        _lemid: LinkedEntityKeychainMeshId,
        _link_info: AgentMeshLinkInfo,
        _reply_callback: Box<
            dyn Fn(Result<RefreshLinkInfoResult, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send,
        >,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        return Err(MeshError::NotSupported);
    }

    // function to check permissions
    pub fn check_permissions(
        &self,
        _lemid: LinkedEntityKeychainMeshId,
        _link_info: AgentMeshLinkInfo,
        _permissions: Vec<MeshPermission>,
        _reply_callback: Box<
            dyn Fn(Result<CheckPermissionsResult, MeshError>) -> Result<Vec<MeshMessage>, MeshError>
                + Send,
        >,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        return Err(MeshError::NotSupported);
    }

    // function to check permissions inline
    // returns MeshError::OutOfDate if permissions need refresh
    pub fn check_permissions_inline(
        &self,
        _lemid: LinkedEntityKeychainMeshId,
        _link_info: AgentMeshLinkInfo,
        _permissions: Vec<MeshPermission>,
    ) -> Result<CheckPermissionsResult, MeshError> {
        return Err(MeshError::NotSupported);
    }

    pub fn send_message_to_entity_on_node_instance(
        &self,
        node_instance: MeshInstanceRoute,
        emid: MeshEntityKeychainMeshId,
        request_message: WrappedMessage,
        reply_callback: ReplyCallback<SendMessageToEntityOnNodeInstanceResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();

        let request_data = to_vec_packed(&request_message).map_err(|e| log_error!(e))?;
        let message = SendToEntityOnNodeInstanceRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            node_instance,
            emid,
            request_data,
            context_id,
        )?;

        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(|resp: TrusteeNetworkSendToEntityOnNodeInstanceResponse| {
                        WrappedMessage::unserialize(&resp.response_message)
                    })
                    .and_then(|reply_message| {
                        if reply_message.is_success_or_has_error_list_field() {
                            Ok(SendMessageToEntityOnNodeInstanceResult { reply_message })
                        } else {
                            Err(agent_message_header_to_error(&reply_message))
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );

        Ok(vec![message])
    }

    pub fn send_message_to_linked_entity(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        request_message: WrappedMessage,
        reply_callback: ReplyCallback<SendMessageToLinkedEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        return self.send_message_to_linked_entity_with_transform_error_option(
            lemid,
            request_message,
            true,
            reply_callback,
            context_id,
        );
    }

    pub fn send_message_to_linked_entity_with_transform_error_option(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        request_message: WrappedMessage,
        transform_error: bool,
        reply_callback: ReplyCallback<SendMessageToLinkedEntityResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();

        let request_data = to_vec_packed(&request_message).map_err(|e| log_error!(e))?;
        let message = SendToLinkedEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lemid,
            request_data,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(|SendToLinkedEntityResponse { response_message }| {
                        WrappedMessage::unserialize(&response_message)
                    })
                    .and_then(|reply_message| {
                        if !transform_error || reply_message.is_success_or_has_error_list_field() {
                            Ok(SendMessageToLinkedEntityResult { reply_message })
                        } else {
                            Err(agent_message_header_to_error(&reply_message))
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_send_message_to_linked_entity(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        request_message: WrappedMessage,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToLinkedEntityResult, MeshError> {
        self.async_send_message_to_linked_entity_with_transform_error_option(
            lemid,
            request_message,
            true,
            context_id,
        )
        .await
    }

    pub async fn async_send_message_to_linked_entity_with_transform_error_option(
        &self,
        lemid: LinkedEntityKeychainMeshId,
        request_message: WrappedMessage,
        transform_error: bool,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToLinkedEntityResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();

        let request_data = to_vec_packed(&request_message).map_err(|e| log_error!(e))?;
        let message = SendToLinkedEntityRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lemid,
            request_data,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|SendToLinkedEntityResponse { response_message }| {
                WrappedMessage::unserialize(&response_message)
            })
            .and_then(|reply_message| {
                if !transform_error || reply_message.is_success_or_has_error_list_field() {
                    Ok(SendMessageToLinkedEntityResult { reply_message })
                } else {
                    Err(agent_message_header_to_error(&reply_message))
                }
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub async fn async_send_message_to_all_linked_entities(
        &self,
        emid: MeshEntityKeychainMeshId,
        destination_agent_id: AgentIdWithAttributes,
        request_message: WrappedMessage,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToAllLinkedEntitiesResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToAllLinkedEntitiesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            emid,
            destination_agent_id,
            request_data,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|SendToAllLinkedEntitiesResponse { responses }| {
                responses
                    .iter()
                    .map(|resp| {
                        Ok(SendMessageToAllLinkedEntitiesResultForEntity {
                            lemid: resp.lemid,
                            reply_message: WrappedMessage::unserialize(&resp.response_message)?,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .map(|entities| SendMessageToAllLinkedEntitiesResult { entities })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn send_message_to_all_linked_entities(
        &self,
        emid: MeshEntityKeychainMeshId,
        destination_agent_id: AgentIdWithAttributes,
        request_message: WrappedMessage,
        reply_callback: ReplyCallback<SendMessageToAllLinkedEntitiesResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToAllLinkedEntitiesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            emid,
            destination_agent_id,
            request_data,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(|SendToAllLinkedEntitiesResponse { responses }| {
                        responses
                            .iter()
                            .map(|resp| {
                                Ok(SendMessageToAllLinkedEntitiesResultForEntity {
                                    lemid: resp.lemid,
                                    reply_message: WrappedMessage::unserialize(
                                        &resp.response_message,
                                    )?,
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .map(|entities| SendMessageToAllLinkedEntitiesResult { entities })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub fn send_message_to_agent(
        &self,
        destination_agent_id: MeshId,
        request_message: WrappedMessage,
        reply_callback: ReplyCallback<SendMessageToAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        self.send_message_to_agent_with_node_instance_and_timeout(
            destination_agent_id,
            request_message,
            None,
            None,
            true,
            reply_callback,
            context_id,
        )
    }

    pub fn send_message_to_agent_with_transform_error_option(
        &self,
        destination_agent_id: MeshId,
        request_message: WrappedMessage,
        transform_error: bool,
        reply_callback: ReplyCallback<SendMessageToAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        self.send_message_to_agent_with_node_instance_and_timeout(
            destination_agent_id,
            request_message,
            None,
            None,
            transform_error,
            reply_callback,
            context_id,
        )
    }

    pub fn send_message_to_agent_with_node_instance_and_timeout(
        &self,
        destination_agent_id: MeshId,
        request_message: WrappedMessage,
        expiration_ms: Option<i64>,
        node_instance: Option<MeshInstanceRoute>,
        transform_error: bool,
        reply_callback: ReplyCallback<SendMessageToAgentResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            destination_agent_id,
            request_data,
            expiration_ms,
            node_instance,
            context_id,
        )?;
        self.add_request_callback_with_timeout(
            request_id,
            expiration_ms,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(|SendToAgentResponse { response_message }| {
                        WrappedMessage::unserialize(&response_message)
                    })
                    .and_then(|reply_message| {
                        if !transform_error || reply_message.is_success_or_has_error_list_field() {
                            Ok(SendMessageToAgentResult { reply_message })
                        } else {
                            Err(agent_message_header_to_error(&reply_message))
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result).or_else(|err| {
                    error!("reply callback failed: {err}");
                    Ok(Vec::new())
                })
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_send_message_to_agent(
        &self,
        destination_agent_id: MeshId,
        request_message: WrappedMessage,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToAgentResult, MeshError> {
        self.async_send_message_to_agent_with_node_instance_and_timeout(
            destination_agent_id,
            request_message,
            None,
            None,
            context_id,
        )
        .await
    }

    pub async fn async_send_message_to_agent_with_node_instance_and_timeout(
        &self,
        destination_agent_id: MeshId,
        request_message: WrappedMessage,
        expiration_ms: Option<i64>,
        node_instance: Option<MeshInstanceRoute>,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToAgentResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToAgentRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            destination_agent_id,
            request_data,
            expiration_ms,
            node_instance,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|SendToAgentResponse { response_message }| {
                WrappedMessage::unserialize(&response_message)
            })
            .and_then(|reply_message| {
                if reply_message.is_success_or_has_error_list_field() {
                    Ok(SendMessageToAgentResult { reply_message })
                } else {
                    Err(agent_message_header_to_error(&reply_message))
                }
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn send_message_to_trustee(
        &self,
        destination_trustee_id: MeshId,
        request_message: WrappedMessage,
        reply_callback: ReplyCallback<SendMessageToTrusteeResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToTrusteeRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            destination_trustee_id,
            request_data,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .and_then(|SendToAgentResponse { response_message }| {
                        WrappedMessage::unserialize(&response_message)
                    })
                    .and_then(|reply_message| {
                        if reply_message.is_success_or_has_error_list_field() {
                            Ok(SendMessageToTrusteeResult { reply_message })
                        } else {
                            Err(agent_message_header_to_error(&reply_message))
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result).or_else(|err| {
                    error!("reply callback failed: {err}");
                    Ok(Vec::new())
                })
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_send_message_to_trustee(
        &self,
        destination_trustee_id: MeshId,
        request_message: WrappedMessage,
        context_id: Option<ContextId>,
    ) -> Result<SendMessageToTrusteeResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let request_data = request_message.serialize()?;
        let message = SendToTrusteeRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            destination_trustee_id,
            request_data,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|SendToAgentResponse { response_message }| {
                WrappedMessage::unserialize(&response_message)
            })
            .and_then(|reply_message| {
                if reply_message.is_success_or_has_error_list_field() {
                    Ok(SendMessageToTrusteeResult { reply_message })
                } else {
                    Err(agent_message_header_to_error(&reply_message))
                }
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn update_uns_record_version_info(
        &self,
        source_id: MeshId,
        version_info: MeshVersionInfo,
        reply_callback: ReplyCallback<()>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentUpdateUnsRecordVersionInfoRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            source_id,
            version_info,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.check_status())
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_update_uns_record_version_info(
        &self,
        source_id: MeshId,
        version_info: MeshVersionInfo,
        context_id: Option<ContextId>,
    ) -> Result<(), MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentUpdateUnsRecordVersionInfoRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            source_id,
            version_info,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response.check_status()
    }

    pub fn create_uns_records(
        &self,
        records: Vec<CreateUnsRecord>,
        is_agent_and_trustees: bool,
        reply_callback: ReplyCallback<CreateUnsRecordsResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentCreateUnsRecordsRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            records,
            is_agent_and_trustees,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(
                        |resp: AgentCreateUnsRecordsResponse| CreateUnsRecordsResult {
                            records: resp.records,
                        },
                    )
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_create_uns_records(
        &self,
        records: Vec<CreateUnsRecord>,
        is_agent_and_trustees: bool,
        context_id: Option<ContextId>,
    ) -> Result<CreateUnsRecordsResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentCreateUnsRecordsRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            records,
            is_agent_and_trustees,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|resp: AgentCreateUnsRecordsResponse| {
                Ok(CreateUnsRecordsResult {
                    records: resp.records,
                })
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn lookup_uns_records(
        &self,
        lookup: UnsLookupType,
        bypass_cache: bool,
        get_trustees_if_agent: bool,
        reply_callback: ReplyCallback<LookupUnsRecordsResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentLookupUnsRecordsRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lookup,
            bypass_cache,
            get_trustees_if_agent,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(
                        |resp: AgentLookupUnsRecordsResponse| LookupUnsRecordsResult {
                            records: resp.records,
                        },
                    )
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_lookup_uns_records(
        &self,
        lookup: UnsLookupType,
        bypass_cache: bool,
        get_trustees_if_agent: bool,
        context_id: Option<ContextId>,
    ) -> Result<LookupUnsRecordsResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentLookupUnsRecordsRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            lookup,
            bypass_cache,
            get_trustees_if_agent,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|resp: AgentLookupUnsRecordsResponse| {
                Ok(LookupUnsRecordsResult {
                    records: resp.records,
                })
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub fn get_source_and_destination(&self) -> (MeshId, MeshId) {
        let state = self.state.read().unwrap();
        return (state.agent_id, state.agent_trustee_id);
    }

    pub(crate) fn get_requests(&self) -> RequestTable {
        let state = self.state.read().unwrap();
        return state.requests.clone();
    }

    pub fn get_agent_emid(&self) -> Result<MeshEntityKeychainMeshId, MeshError> {
        let state = self.state.read().unwrap();
        return state
            .agent_emid
            .ok_or_else(|| log_error!(MeshError::RequestFailed("missing agent emid".into())));
    }

    pub fn set_agent_emid(&self, agent_emid: MeshEntityKeychainMeshId) {
        let mut state = self.state.write().unwrap();
        state.agent_emid = Some(agent_emid);
    }

    pub(crate) fn add_request_callback(
        &self,
        request_id: MeshMessageId,
        reply_callback: ReplyCallback<MeshMessage>,
    ) {
        self.add_request_callback_with_timeout(request_id, None, reply_callback);
    }

    pub(crate) fn add_request_callback_with_timeout(
        &self,
        request_id: MeshMessageId,
        expiration_ms: Option<i64>,
        reply_callback: ReplyCallback<MeshMessage>,
    ) {
        let mut state = self.state.write().unwrap();
        state
            .requests
            .add_request(request_id, expiration_ms, reply_callback);
    }

    pub fn get_agent_id(&self) -> MeshId {
        let state = self.state.read().unwrap();
        return state.agent_id;
    }

    pub(crate) fn get_listener(
        &self,
    ) -> Result<(MeshId, MeshId, Option<MeshSubsystem>), MeshError> {
        let state = self.state.read().unwrap();
        let listener_enclave_id = state
            .listener_enclave_id
            .ok_or_else(|| log_error!(MeshError::BadState))?;
        return Ok((
            state.agent_id,
            listener_enclave_id,
            state.listener_subsystem,
        ));
    }

    pub fn get_listener_subsystem(&self) -> Option<MeshSubsystem> {
        self.state.read().unwrap().listener_subsystem
    }

    pub async fn async_mutate_emid_data(
        &self,
        emid: MeshEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError> {
        self.async_run_mutate_for_entity_data_operation(
            emid,
            None,
            key_path,
            None,
            false,
            mutate_callback,
            context_id,
        )
        .await
    }

    pub async fn async_mutate_emid_data_with_part_number(
        &self,
        emid: MeshEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        part_number: i64,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError> {
        self.async_run_mutate_for_entity_data_operation(
            emid,
            None,
            key_path,
            Some(part_number),
            false,
            mutate_callback,
            context_id,
        )
        .await
    }

    pub async fn async_mutate_lemid_data(
        &self,
        emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError> {
        self.async_run_mutate_for_entity_data_operation(
            emid,
            Some(lemid),
            key_path,
            None,
            true,
            mutate_callback,
            context_id,
        )
        .await
    }

    async fn async_run_mutate_for_entity_data_operation(
        &self,
        emid: MeshEntityKeychainMeshId,
        lemid: Option<LinkedEntityKeychainMeshId>,
        key_path: Vec<Vec<u8>>,
        part_number: Option<i64>,
        data_is_for_lemid: bool,
        mutate_callback: Box<
            dyn Fn(&mut DataEntry) -> Result<Option<MutateCallbackResultData>, MeshError>
                + Send
                + Sync,
        >,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError> {
        let callback = {
            let mutate_callback = &mutate_callback;
            move |mut data: DataEntry| async move {
                let result = mutate_callback(&mut data)?;
                Ok((data, result))
            }
        };

        self.async_run_mutate_for_entity_data_operation_with_async_callback(
            emid,
            lemid,
            key_path,
            part_number,
            data_is_for_lemid,
            callback,
            context_id,
        )
        .await
    }

    pub fn get_certificate_authorities(
        &self,
        reply_callback: ReplyCallback<GetCertificateAuthoritiesResult>,
        context_id: Option<ContextId>,
    ) -> Result<Vec<MeshMessage>, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentGetCertificateAuthoritiesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            context_id,
        )?;
        self.add_request_callback(
            request_id,
            Box::new(move |reply| {
                let result = reply
                    .and_then(|resp| resp.extract_check_status())
                    .map(|resp: GetCertificateAuthoritiesResponse| {
                        GetCertificateAuthoritiesResult {
                            ca_pem: resp.ca_pem,
                        }
                    })
                    .map_err(|e| log_error!("request failed: {}", e));
                reply_callback(result)
            }),
        );
        Ok(vec![message])
    }

    pub async fn async_get_certificate_authorities(
        &self,
        context_id: Option<ContextId>,
    ) -> Result<GetCertificateAuthoritiesResult, MeshError> {
        let request_id = mesh_generate_mesh_id()?;
        let (own_id, agent_trustee_id) = self.get_source_and_destination();
        let message = AgentGetCertificateAuthoritiesRequest::build_request(
            request_id,
            own_id,
            agent_trustee_id,
            context_id,
        )?;
        let response = common_async::send_message(message, None).await?;
        response
            .extract_check_status()
            .and_then(|resp: GetCertificateAuthoritiesResponse| {
                Ok(GetCertificateAuthoritiesResult {
                    ca_pem: resp.ca_pem,
                })
            })
            .map_err(|e| log_error!("request failed: {}", e))
    }

    pub async fn async_get_lock_for_node(
        &self,
        name: &str,
        lock_timeout_ms: i64,
        context_id: Option<ContextId>,
    ) -> Result<bool, MeshError> {
        let node_name = get_agent_trustee_node_name_and_port()?;
        let emid = self.get_agent_emid()?;

        let key_path = vec![b"node_lock".to_vec(), name.as_bytes().to_vec()];
        let handler = self.clone();
        match self
            .async_mutate_emid_data(
                emid,
                key_path,
                Box::new(move |data| {
                    handler.get_lock_for_node_update_data(node_name.clone(), lock_timeout_ms, data)
                }),
                context_id,
            )
            .await
        {
            Err(MeshError::EntityExists) => Ok(false),
            Err(err) => Err(err),
            Ok(_) => Ok(true),
        }
    }

    fn get_lock_for_node_update_data(
        &self,
        node_name: String,
        lock_timeout_ms: i64,
        data_entry: &mut DataEntry,
    ) -> Result<Option<MutateCallbackResultData>, MeshError> {
        let now = get_current_time_ms();
        let lock_data = if data_entry.data.is_some() {
            let mut lock = self.unserialize_lock_data(data_entry)?;
            if lock.node_name != node_name && lock.lock_time < (now - lock_timeout_ms) {
                return Err(MeshError::EntityExists);
            }
            lock.lock_time = now;
            lock
        } else {
            AgentLockData {
                node_name,
                lock_time: now,
            }
        };
        let raw_data = self.serialize_lock_data(&lock_data)?;
        data_entry.data = Some(raw_data);
        Ok(None)
    }

    fn unserialize_lock_data(&self, data_entry: &DataEntry) -> Result<AgentLockData, MeshError> {
        let data_payload = data_entry
            .data
            .as_ref()
            .ok_or(MeshError::RequestFailed("empty agent lock data".into()))?;
        let lock_data: AgentLockData =
            from_slice(&data_payload).map_err(|e| MeshError::ParseError(format!("{}", e)))?;
        Ok(lock_data)
    }

    fn serialize_lock_data(&self, lock_data: &AgentLockData) -> Result<Vec<u8>, MeshError> {
        to_vec_packed(&lock_data)
    }

    pub async fn async_mutate_emid_data_with_async_callback<F, Fut>(
        &self,
        emid: MeshEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: F,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError>
    where
        F: Fn(DataEntry) -> Fut + Send + Sync,
        Fut: Future<Output = Result<(DataEntry, Option<MutateCallbackResultData>), MeshError>>
            + Send,
    {
        self.async_run_mutate_for_entity_data_operation_with_async_callback(
            emid,
            None,
            key_path,
            None,
            false,
            mutate_callback,
            context_id,
        )
        .await
    }

    pub async fn async_mutate_lemid_data_with_async_callback<F, Fut>(
        &self,
        emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        key_path: Vec<Vec<u8>>,
        mutate_callback: F,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError>
    where
        F: Fn(DataEntry) -> Fut + Send + Sync,
        Fut: Future<Output = Result<(DataEntry, Option<MutateCallbackResultData>), MeshError>>
            + Send,
    {
        self.async_run_mutate_for_entity_data_operation_with_async_callback(
            emid,
            Some(lemid),
            key_path,
            None,
            true,
            mutate_callback,
            context_id,
        )
        .await
    }

    async fn async_run_mutate_for_entity_data_operation_with_async_callback<F, Fut>(
        &self,
        emid: MeshEntityKeychainMeshId,
        lemid: Option<LinkedEntityKeychainMeshId>,
        key_path: Vec<Vec<u8>>,
        part_number: Option<i64>,
        data_is_for_lemid: bool,
        mutate_callback: F,
        context_id: Option<ContextId>,
    ) -> Result<MutateReplyData, MeshError>
    where
        F: Fn(DataEntry) -> Fut + Send + Sync,
        Fut: Future<Output = Result<(DataEntry, Option<MutateCallbackResultData>), MeshError>>
            + Send,
    {
        let mut data: Option<DataEntry> = None;
        let mut tries: usize = 0;
        let mut deleted = false;
        let mut result_data: Option<MutateCallbackResultData> = None;
        let mut new_entry = false;
        let mut old_data: Option<DataEntry> = None;

        loop {
            if tries > 0 {
                info!("retrying ({}) update for key path {:?}", tries, key_path);
            }
            let operation = match &data {
                Some(data) => {
                    if deleted {
                        Some(DataOperation::UpdateAndRestore(data.clone()))
                    } else if old_data
                        .as_ref()
                        .map_or(true, |old_data| data.data != old_data.data)
                    {
                        if new_entry {
                            Some(DataOperation::Insert(data.clone()))
                        } else {
                            Some(DataOperation::Update(data.clone()))
                        }
                    } else {
                        None
                    }
                }
                None => Some(DataOperation::Fetch(DataKey {
                    key_path: key_path.clone(),
                    start_part_number: part_number,
                    limit: if part_number.is_some() { Some(1) } else { None },
                    include_deleted: Some(true),
                    ..Default::default()
                })),
            };
            let (mut lemid_operations, mut emid_operations) = match &mut result_data {
                Some(result_data) => (
                    result_data.lemid_operations.take().unwrap_or(vec![]),
                    result_data.emid_operations.take().unwrap_or(vec![]),
                ),
                None => (vec![], vec![]),
            };
            if lemid_operations.is_empty() && emid_operations.is_empty() && operation.is_none() {
                return Ok(MutateReplyData {
                    data_entry: data.unwrap(),
                    old_data_entry: old_data,
                    mutate_status: result_data.and_then(|result_data| result_data.mutate_status),
                });
            }
            if data_is_for_lemid {
                lemid_operations.extend(operation);
            } else {
                emid_operations.extend(operation);
            }
            let input = AgentDataOperationForEntityInput {
                emid: Some(emid),
                lemid,
                emid_operations,
                lemid_operations,
                run_emid_operations_first: Some(!data_is_for_lemid),
            };

            let result = self
                .async_data_operation_for_entity(vec![input], context_id)
                .await;
            let mut result = match result {
                Ok(result) => result,
                Err(MeshError::DatabaseConcurrentUpdate | MeshError::DatabaseDuplicateKey)
                    if tries < MAX_CONCURRENT_UPDATE_TRIES =>
                {
                    tries += 1;
                    data = None;
                    result_data = None;
                    old_data = None;
                    deleted = false;
                    new_entry = false;
                    continue;
                }
                Err(err) => return Err(err),
            };
            if let Some(data_entry) = data {
                // save operation is ok
                return Ok(MutateReplyData {
                    old_data_entry: old_data,
                    data_entry,
                    mutate_status: result_data.and_then(|result_data| result_data.mutate_status),
                });
            }
            let mut entry: Option<DataEntry> = None;
            if result.result.len() == 1 {
                let result_data = result.result.remove(0);
                let mut operations_result = if data_is_for_lemid {
                    result_data.lemid_operations_result
                } else {
                    result_data.emid_operations_result
                };
                if operations_result.len() == 1 {
                    entry = Some(operations_result.remove(0));
                } else if operations_result.len() > 1 {
                    return Err(log_error!(MeshError::RequestFailed(
                        "unexpected multiple operations result".into()
                    )));
                }
            } else if result.result.len() > 1 {
                return Err(log_error!(MeshError::RequestFailed(
                    "unexpected multiple results".into()
                )));
            }
            new_entry = entry.is_none();
            let mut data_entry = entry.unwrap_or_else(|| DataEntry {
                key_path: key_path.clone(),
                ..Default::default()
            });
            old_data = Some(data_entry.clone());
            deleted = data_entry.delete_date.is_some();
            (data_entry, result_data) = mutate_callback(data_entry).await?;
            data = Some(data_entry);
        }
    }
}
