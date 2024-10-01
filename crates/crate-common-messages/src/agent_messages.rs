use alloc::vec::Vec;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_types::agent_entity_trustee_objects::AgentIdWithEntityType;
use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdates;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdatesForSession;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::agent_entity_trustee_objects::ExternalLinkIdType;
use common_types::agent_entity_trustee_objects::LemidAndDataOperations;
use common_types::agent_entity_trustee_objects::LinkRequestId;
use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::AgentLinkedEntityKeychainMeshId;
use common_types::ContextId;
use common_types::LinkedEntityKeychainMeshId;
use common_types::MeshEntityKeychainMeshId;
use common_types::MeshEntityType;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshLinkCode;
use common_types::MeshMessageId;

use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum AgentMessageType {
    Unknown = 0,
    AgentToAgentEntityRequestType = 1,
    AgentToAgentEntityResponseType = 2,
    TrusteeOrAgentToAgentRequestType = 3,
    TrusteeOrAgentToAgentResponseType = 4,
    AgentToAgentLinkEntityRequestType = 5,
    AgentToAgentLinkEntityResponseType = 6,
    AgentToAgentAllEntitiesRequestType = 7,
    AgentToAgentAllEntitiesResponseType = 8,
    AgentToAgentLinkEntityViaDelegateRequestType = 9,
    AgentToAgentLinkEntityViaDelegateResponseType = 10,
    AgentToAgentGetLinkCodesRequestType = 11,
    AgentToAgentGetLinkCodesResponseType = 12,
    AgentToAgentEntityOnNodeInstanceRequestType = 13,
    AgentToAgentEntityOnNodeInstanceResponseType = 14,
    AgentToAgentUnlinkEntitiesRequestType = 15,
    AgentToAgentUnlinkEntitiesResponseType = 16,
    AgentToAgentCreateTempEntityRequestType = 17,
    AgentToAgentCreateTempEntityResponseType = 18,
    AgentToAgentMergeTempEntityRequestType = 19,
    AgentToAgentMergeTempEntityResponseType = 20,
    AgentToAgentLinkEntityViaDelegateSessionRequestType = 21,
    AgentToAgentLinkEntityViaDelegateSessionResponseType = 22,
    AgentToAgentLinkEntityPostCreateRequestType = 23,
    AgentToAgentLinkEntityPostCreateResponseType = 24,
    AgentToAgentLinkEntityPreCreateRequestType = 25,
    AgentToAgentLinkEntityPreCreateResponseType = 26,
}

impl From<AgentMessageType> for MeshMessageType {
    #[inline(always)]
    fn from(message_type: AgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentEntityRequest {
    pub lemid: MeshId,
    pub alemid: MeshId,
    pub emid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

impl AgentToAgentEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        alemid: AgentLinkedEntityKeychainMeshId,
        emid: MeshEntityKeychainMeshId,
        request_message: Vec<u8>,
        requestor_agent_id: MeshId,
        link_info: Option<AgentMeshLinkInfo>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            lemid,
            alemid,
            emid,
            request_message,
            requestor_agent_id,
            link_info,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentEntityResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentLinkedToEnidEntity {
    pub emid: MeshId,
    pub lemid: MeshId,
    pub alemid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentAllEntitiesRequest {
    pub entities: Vec<AgentLinkedToEnidEntity>,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    pub requestor_agent_id: MeshId,
}

impl AgentToAgentAllEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        entities: Vec<AgentLinkedToEnidEntity>,
        request_message: Vec<u8>,
        requestor_agent_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            entities,
            request_message,
            requestor_agent_id,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;

        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentAllEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentToAgentAllEntitiesEntityResult {
    pub emid: MeshId,
    pub lemid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentAllEntitiesResponse {
    pub responses: Vec<AgentToAgentAllEntitiesEntityResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeOrAgentToAgentRequest {
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    pub requestor_agent_id: Option<MeshId>,
    pub requestor_trustee_id: MeshId,
}

impl TrusteeOrAgentToAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        request_message: Vec<u8>,
        requestor_agent_id: Option<MeshId>,
        requestor_trustee_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            request_message,
            requestor_trustee_id,
            requestor_agent_id,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::TrusteeOrAgentToAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentToAgentLinkEntityInviteLink {
    pub lemid: MeshId,
    pub alemid: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityRequest {
    pub emid: MeshId,
    pub entity_type: MeshEntityType,
    pub link_request_id: LinkRequestId,
    pub lemid_to_be_created: MeshId,
    pub alemid_to_be_created: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    pub is_new_entity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_links: Option<Vec<AgentToAgentLinkEntityInviteLink>>,
    pub is_link_to_session: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
}

impl AgentToAgentLinkEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        entity_type: MeshEntityType,
        link_request_id: LinkRequestId,
        lemid_to_be_created: LinkedEntityKeychainMeshId,
        alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
        requestor_agent_id: MeshId,
        request_message: Option<Vec<u8>>,
        is_new_entity: bool,
        link_info: Option<AgentMeshLinkInfo>,
        invite_links: Option<Vec<AgentToAgentLinkEntityInviteLink>>,
        is_link_to_session: bool,
        via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            link_request_id,
            request_message,
            emid,
            entity_type,
            lemid_to_be_created,
            alemid_to_be_created,
            requestor_agent_id,
            is_new_entity,
            link_info,
            invite_links,
            is_link_to_session,
            via_external_id_requestor,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentLinkEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_emid_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emid_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid_operations: Option<Vec<DataOperation>>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_lemid_operations: Option<Vec<LemidAndDataOperations>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityPostCreateRequest {
    pub emid: MeshId,
    pub lemid: MeshId,
    pub alemid: MeshId,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
    pub is_new_entity: bool,
}

impl AgentToAgentLinkEntityPostCreateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        alemid: AgentLinkedEntityKeychainMeshId,
        requestor_agent_id: MeshId,
        link_info: Option<AgentMeshLinkInfo>,
        is_new_entity: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            emid,
            lemid,
            alemid,
            requestor_agent_id,
            link_info,
            is_new_entity,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentLinkEntityPostCreateRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityPostCreateResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityPreCreateRequest {
    pub entity_type: MeshEntityType,
    pub link_request_id: LinkRequestId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    pub is_new_entity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
    pub is_link_to_session: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
    pub alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
}

impl AgentToAgentLinkEntityPreCreateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        entity_type: MeshEntityType,
        link_request_id: LinkRequestId,
        requestor_agent_id: MeshId,
        request_message: Option<Vec<u8>>,
        is_new_entity: bool,
        link_info: Option<AgentMeshLinkInfo>,
        is_link_to_session: bool,
        via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
        alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            link_request_id,
            request_message,
            entity_type,
            requestor_agent_id,
            is_new_entity,
            link_info,
            is_link_to_session,
            via_external_id_requestor,
            alemid_to_be_created,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentLinkEntityPreCreateRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityPreCreateResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegateRequest {
    pub emid: MeshId,
    pub requestor_agent_id: MeshId,
    pub requestor_lemid_to_be_created: MeshId,
    pub requestor_alemid_to_be_created: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub delegate_lemid: MeshId,
    pub delegate_alemid: MeshId,
    pub delegate_agent_id: MeshId,
    pub is_link_to_session: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_link_info: Option<AgentMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_link_info: Option<AgentMeshLinkInfo>,
    pub entity_type: MeshEntityType,
}

impl AgentToAgentLinkEntityViaDelegateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        requestor_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        entity_type: MeshEntityType,
        requestor_lemid_to_be_created: LinkedEntityKeychainMeshId,
        requestor_alemid_to_be_created: AgentLinkedEntityKeychainMeshId,
        request_message: Option<Vec<u8>>,
        delegate_lemid: LinkedEntityKeychainMeshId,
        delegate_alemid: AgentLinkedEntityKeychainMeshId,
        delegate_agent_id: MeshId,
        is_link_to_session: bool,
        requestor_link_info: Option<AgentMeshLinkInfo>,
        delegate_link_info: Option<AgentMeshLinkInfo>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            requestor_agent_id,
            requestor_lemid_to_be_created,
            requestor_alemid_to_be_created,
            emid,
            request_message,
            requestor_link_info,
            delegate_lemid,
            delegate_alemid,
            delegate_agent_id,
            is_link_to_session,
            delegate_link_info,
            entity_type,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentLinkEntityViaDelegateRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegateResponse {
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emid_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegatePostCreateRequest {
    pub emid: MeshId,
    pub lemid: MeshId,
    pub alemid: MeshId,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegatePreCreateResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegateSessionRequest {
    pub emid: MeshId,
    pub requestor_lemid: MeshId,
    pub requestor_alemid: MeshId,
    pub requestor_agent_id: MeshId,
    pub target_lemid: MeshId,
    pub target_alemid: MeshId,
    pub target_agent_id: MeshId,

    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub delegate_lemid: MeshId,
    pub delegate_alemid: MeshId,
    pub delegate_agent_id: MeshId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_link_info: Option<AgentMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_link_info: Option<AgentMeshLinkInfo>,
}

impl AgentToAgentLinkEntityViaDelegateSessionRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        requestor_lemid: LinkedEntityKeychainMeshId,
        requestor_alemid: AgentLinkedEntityKeychainMeshId,
        requestor_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        target_lemid: LinkedEntityKeychainMeshId,
        target_alemid: AgentLinkedEntityKeychainMeshId,
        target_agent_id: MeshId,
        request_message: Option<Vec<u8>>,
        requestor_link_info: Option<AgentMeshLinkInfo>,
        delegate_link_info: Option<AgentMeshLinkInfo>,
        delegate_lemid: LinkedEntityKeychainMeshId,
        delegate_alemid: AgentLinkedEntityKeychainMeshId,
        delegate_agent_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            requestor_agent_id,
            target_lemid,
            target_alemid,
            emid,
            request_message,
            requestor_link_info,
            delegate_link_info,
            delegate_lemid,
            requestor_lemid,
            target_agent_id,
            requestor_alemid,
            delegate_alemid,
            delegate_agent_id,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentLinkEntityViaDelegateSessionRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentLinkEntityViaDelegateSessionResponse {
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdatesForSession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emid_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid_operations: Option<Vec<DataOperation>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentGetLinkCodesViaExternalIdRequestor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid: Option<MeshId>,
    pub emid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentGetLinkCodesRequest {
    pub lemid: MeshId,
    pub emid: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

impl AgentToAgentGetLinkCodesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        emid: MeshEntityKeychainMeshId,
        request_message: Option<Vec<u8>>,
        requestor_agent_id: MeshId,
        link_info: Option<AgentMeshLinkInfo>,
        via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
        human_proxy_agent_id: Option<AgentIdWithEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            lemid,
            emid,
            request_message,
            requestor_agent_id,
            link_info,
            via_external_id_requestor,
            human_proxy_agent_id,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentGetLinkCodesRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentGetLinkCodesResponse {
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_link_code: Option<MeshLinkCode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentEntityOnNodeInstanceRequest {
    pub emid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl AgentToAgentEntityOnNodeInstanceRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            emid,
            request_message,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentEntityOnNodeInstanceRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentEntityOnNodeInstanceResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentUnlinkEntity {
    pub emid: MeshId,
    pub lemid: MeshId,
    pub alemid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentUnlinkEntitiesRequest {
    pub entities: Vec<AgentToAgentUnlinkEntity>,
    pub requestor_agent_id: MeshId,
}

impl AgentToAgentUnlinkEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        entities: Vec<AgentToAgentUnlinkEntity>,
        requestor_agent_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            entities,
            requestor_agent_id,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentUnlinkEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentUnlinkEntitiesResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentCreateTempEntityRequest {
    pub emid: MeshId,
    pub entity_type: MeshEntityType,
    pub requestor_agent_id: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub is_new_entity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
    pub external_id: ExternalLinkIdType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

impl AgentToAgentCreateTempEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        entity_type: MeshEntityType,
        requestor_agent_id: MeshId,
        request_message: Option<Vec<u8>>,
        is_new_entity: bool,
        via_external_id_requestor: Option<AgentToAgentGetLinkCodesViaExternalIdRequestor>,
        external_id: ExternalLinkIdType,
        human_proxy_agent_id: Option<AgentIdWithEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            request_message,
            emid,
            entity_type,
            requestor_agent_id,
            is_new_entity,
            via_external_id_requestor,
            external_id,
            human_proxy_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentCreateTempEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentCreateTempEntityResponse {
    pub emid_operations: Option<Vec<DataOperation>>,
    #[serde(default, with = "serde_bytes")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_link_code: Option<MeshLinkCode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentMergeTempEntityRequest {
    pub emid: MeshId,
    pub merge_emids: Vec<MeshEntityKeychainMeshId>,
    pub requestor_agent_id: MeshId,
}

impl AgentToAgentMergeTempEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        merge_emids: Vec<LinkedEntityKeychainMeshId>,
        requestor_agent_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            emid,
            merge_emids,
            requestor_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::Agent,
            AgentMessageType::AgentToAgentMergeTempEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentToAgentMergeTempEntityResponse {}
