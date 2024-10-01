use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_types::agent_entity_trustee_objects::AgentIdWithEntityType;
use common_types::agent_entity_trustee_objects::AgentLinkedEntity;
use common_types::agent_entity_trustee_objects::AgentMeshLinkInfo;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdates;
use common_types::agent_entity_trustee_objects::AgentMeshLinkUpdatesForSession;
use common_types::agent_entity_trustee_objects::DataEntry;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::agent_entity_trustee_objects::ExternalLinkIdType;
use common_types::agent_entity_trustee_objects::LinkRequestId;
use common_types::agent_entity_trustee_objects::TrusteeMeshLinkInfo;
use common_types::agent_entity_trustee_objects::TrusteeMeshRelationshipAndPermissions;
use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::uns_data_objects::CreateUnsRecord;
use common_types::uns_data_objects::UnsLookupType;
use common_types::uns_data_objects::UnsRecord;
use common_types::versioning::MeshVersionInfo;
use common_types::ContextId;
use common_types::LinkedEntityKeychainMeshId;
use common_types::MeshEntityKeychainMeshId;
use common_types::MeshEntityKeychainNetworkId;
use common_types::MeshEntityType;
use common_types::MeshError;
use common_types::MeshExternalId;
use common_types::MeshId;
use common_types::MeshInstanceRoute;
use common_types::MeshLinkAttributesTypeAndOp;
use common_types::MeshLinkCode;
use common_types::MeshMessageId;
use common_types::MeshSessionId;

use crate::AgentIdWithAttributes;
use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum AgentTrusteeMessageType {
    Unknown = 0,
    AgentCreateEntityRequestType = 1,
    AgentCreateEntityResponseType = 2,
    AgentDataOperationForEntityRequestType = 3,
    AgentDataOperationForEntityResponseType = 4,
    LookupLinkedEntitiesRequestType = 5,
    LookupLinkedEntitiesResponseType = 6,
    LinkEntityRequestType = 7,
    LinkEntityResponseType = 8,
    // 9, 10 not used
    SendToLinkedEntityRequestType = 11,
    SendToLinkedEntityResponseType = 12,
    TrusteeNetworkLinkEntityRequestType = 13,
    TrusteeNetworkLinkEntityResponseType = 14,
    TrusteeNetworkSendToLinkedEntityRequestType = 15,
    TrusteeNetworkSendToLinkedEntityResponseType = 16,
    BootstrapRequestType = 17,
    BootstrapResponseType = 18,
    SendToAgentRequestType = 19,
    SendToAgentResponseType = 20,
    TrusteeNetworkSendToAgentRequestType = 21,
    TrusteeNetworkSendToAgentResponseType = 22,
    SendToAllLinkedEntitiesRequestType = 23,
    SendToAllLinkedEntitiesResponseType = 24,
    TrusteeNetworkSendToAllLinkedEntitiesRequestType = 25,
    TrusteeNetworkSendToAllLinkedEntitiesResponseType = 26,
    AgentDeleteEntityRequestType = 27,
    AgentDeleteEntityResponseType = 28,
    UnlinkEntityRequestType = 29,
    UnlinkEntityResponseType = 30,
    TrusteeNetworkUnlinkEntityRequestType = 31,
    TrusteeNetworkUnlinkEntityResponseType = 32,
    TrusteeNetworkUnlinkAllEntitiesRequestType = 33,
    TrusteeNetworkUnlinkAllEntitiesResponseType = 34,
    GetLinkCodesRequestType = 35,
    GetLinkCodesResponseType = 36,
    LinkEntityViaDelegateRequestType = 37,
    LinkEntityViaDelegateResponseType = 38,
    TrusteeNetworkForwardLinkEntityViaDelegateRequestType = 39,
    TrusteeNetworkForwardLinkEntityViaDelegateResponseType = 40,
    TrusteeNetworkLinkEntityViaDelegateRequestType = 41,
    TrusteeNetworkLinkEntityViaDelegateResponseType = 42,
    TrusteeNetworkGetDirectLinkCodeRequestType = 43,
    TrusteeNetworkGetDirectLinkCodeResponseType = 44,
    UpdateLinkInfoRequestType = 45,
    UpdateLinkInfoResponseType = 46,
    TrusteeNetworkUpdateLinkInfoRequestType = 47,
    TrusteeNetworkUpdateLinkInfoResponseType = 48,
    SendToEntityOnNodeInstanceRequestType = 49,
    SendToEntityOnNodeInstanceResponseType = 50,
    TrusteeNetworkSendToEntityOnNodeInstanceRequestType = 51,
    TrusteeNetworkSendToEntityOnNodeInstanceResponseType = 52,
    TranslateIdsRequestType = 53,
    TranslateIdsResponseType = 54,
    AgentCreateAndLinkEntityOnSameAgentRequestType = 55,
    AgentCreateAndLinkEntityOnSameAgentResponseType = 56,
    AgentLookupEntityOnSameAgentRequestType = 57,
    AgentLookupEntityOnSameAgentResponseType = 58,
    TrusteeNetworkGetExternalIdLinkCodeRequestType = 59,
    TrusteeNetworkGetExternalIdLinkCodeResponseType = 60,
    TrusteeNetworkCreateTempEntityLinkCodeRequestType = 61,
    TrusteeNetworkCreateTempEntityLinkCodeResponseType = 62,
    TrusteeNetworkUpdateEnidOnLinkRequestType = 63,
    TrusteeNetworkUpdateEnidOnLinkResponseType = 64,
    TrusteeNetworkLookupLinkInfosRequestType = 65,
    TrusteeNetworkLookupLinkInfosResponseType = 66,
    TrusteeNetworkLinkEntityPostCreateRequestType = 67,
    TrusteeNetworkLinkEntityPostCreateResponseType = 68,
    AgentLinkEntityOnSameAgentRequestType = 69,
    AgentLinkEntityOnSameAgentResponseType = 70,
    SendToTrusteeRequestType = 71,
    SendToTrusteeResponseType = 72,
    AgentLookupUnsRecordsRequestType = 73,
    AgentLookupUnsRecordsResponseType = 74,
    AgentCreateUnsRecordsRequestType = 75,
    AgentCreateUnsRecordsResponseType = 76,
    AgentUpdateUnsRecordVersionInfoRequestType = 77,
    AgentUpdateUnsRecordVersionInfoResponseType = 78,
    AgentGetCertificateAuthoritiesRequestType = 79,
    AgentGetCertificateAuthoritiesResponseType = 80,
}

impl From<AgentTrusteeMessageType> for MeshMessageType {
    #[inline(always)]
    fn from(message_type: AgentTrusteeMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentCreateEntityRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_operations: Option<Vec<DataOperation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
}

impl AgentCreateEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: Option<MeshEntityKeychainMeshId>,
        entity_type: Option<MeshEntityType>,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            data_operations,
            expiration_time,
            emid,
            entity_type,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentCreateEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentCreateEntityResponse {
    pub emid: MeshId,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AgentDataOperationForEntityInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid: Option<MeshId>,
    pub emid_operations: Vec<DataOperation>,
    pub lemid_operations: Vec<DataOperation>,
    pub run_emid_operations_first: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentDataOperationForEntityRequest {
    pub operations: Vec<AgentDataOperationForEntityInput>,
}

impl AgentDataOperationForEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        operations: Vec<AgentDataOperationForEntityInput>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { operations };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentDataOperationForEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentDataOperationForEntityOutput {
    pub emid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lemid: Option<MeshId>,
    pub emid_operations_result: Vec<DataEntry>,
    pub lemid_operations_result: Vec<DataEntry>,
}

impl AgentDataOperationForEntityOutput {
    pub fn get_emid_data_entry(&self, emid_index: usize) -> Option<&DataEntry> {
        self.emid_operations_result.get(emid_index)
    }

    pub fn get_lemid_data_entry(&self, lemid_index: usize) -> Option<&DataEntry> {
        self.lemid_operations_result.get(lemid_index)
    }

    pub fn get_emid_data_entry_mut(&mut self, emid_index: usize) -> Option<&mut DataEntry> {
        self.emid_operations_result.get_mut(emid_index)
    }

    pub fn get_lemid_data_entry_mut(&mut self, lemid_index: usize) -> Option<&mut DataEntry> {
        self.lemid_operations_result.get_mut(lemid_index)
    }

    pub fn get_emid_entry(&self, emid_index: usize) -> Option<&Vec<u8>> {
        self.get_emid_data_entry(emid_index)
            .as_ref()
            .and_then(|entry| entry.data.as_ref())
    }

    pub fn get_lemid_entry(&self, lemid_index: usize) -> Option<&Vec<u8>> {
        self.get_lemid_data_entry(lemid_index)
            .as_ref()
            .and_then(|entry| entry.data.as_ref())
    }

    pub fn get_emid_result_for_key_path(&self, key_path: Vec<Vec<u8>>) -> Option<&DataEntry> {
        self.emid_operations_result
            .iter()
            .find(|entry| entry.key_path == key_path)
    }

    pub fn get_lemid_result_for_key_path(&self, key_path: Vec<Vec<u8>>) -> Option<&DataEntry> {
        self.lemid_operations_result
            .iter()
            .find(|entry| entry.key_path == key_path)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentDataOperationForEntityResponse {
    pub result: Vec<AgentDataOperationForEntityOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupLinkedEntitiesRequest {
    pub emid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_agent_ids: Option<Vec<AgentIdWithAttributes>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<MeshId>>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub include_deleted: Option<bool>,
}

impl LookupLinkedEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_agent_ids: Option<Vec<AgentIdWithAttributes>>,
        external_ids: Option<Vec<MeshExternalId>>,
        offset: Option<u64>,
        limit: Option<u64>,
        include_deleted: Option<bool>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            emid,
            destination_agent_ids,
            external_ids,
            offset,
            limit,
            include_deleted,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::LookupLinkedEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupLinkedEntitiesResponse {
    pub entities: Vec<AgentLinkedEntity>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkEntityRequest {
    pub destination_agent_id: MeshId,
    pub emid: MeshId,
    pub destination_link_id: LinkRequestId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdates>,
}

impl LinkEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        destination_agent_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        destination_link_id: LinkRequestId,
        request_message: Option<Vec<u8>>,
        link_updates: Option<AgentMeshLinkUpdates>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            destination_agent_id,
            emid,
            destination_link_id,
            link_updates,
            request_message,
        };
        let payload = to_vec_packed(&request).map_err(|e| log_error!(e))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::LinkEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkEntityResponse {
    pub lemid: MeshId,
    pub alemid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityRequest {
    pub source_enid: MeshId,
    pub source_entity_type: MeshEntityType,
    pub destination_link_id: LinkRequestId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
}

impl TrusteeNetworkLinkEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        source_entity_type: MeshEntityType,
        destination_link_id: LinkRequestId,
        request_message: Option<Vec<u8>>,
        external_id: Option<MeshId>,
        link_info: Option<TrusteeMeshLinkInfo>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            source_entity_type,
            destination_link_id,
            request_message,
            link_info,
            external_id,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkLinkEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityResponse {
    pub enid_of_linked_entity: MeshId,
    pub entity_type_of_linked_entity: MeshEntityType,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id_of_linked_entity: Option<MeshId>,
    pub already_linked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
    pub is_new_entity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityPostCreateRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub is_new_entity: bool,
}

impl TrusteeNetworkLinkEntityPostCreateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        is_new_entity: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            is_new_entity,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkLinkEntityPostCreateRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityPostCreateResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToLinkedEntityRequest {
    pub lemid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl SendToLinkedEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            lemid,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::SendToLinkedEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToLinkedEntityResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToAllLinkedEntitiesRequest {
    pub emid: MeshId,
    pub destination_agent_id: AgentIdWithAttributes,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl SendToAllLinkedEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: LinkedEntityKeychainMeshId,
        destination_agent_id: AgentIdWithAttributes,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            emid,
            destination_agent_id,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::SendToAllLinkedEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToAllLinkedEntitiesEntityResult {
    pub lemid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToAllLinkedEntitiesResponse {
    pub responses: Vec<SendToAllLinkedEntitiesEntityResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToLinkedEntityRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl TrusteeNetworkSendToLinkedEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkSendToLinkedEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToLinkedEntityResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToAllLinkedEntitiesRequest {
    pub source_enid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_self: Option<Vec<MeshLinkAttributesTypeAndOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_origin: Option<Vec<MeshLinkAttributesTypeAndOp>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
}

impl TrusteeNetworkSendToAllLinkedEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        request_message: Vec<u8>,
        attributes_self: Option<Vec<MeshLinkAttributesTypeAndOp>>,
        attributes_origin: Option<Vec<MeshLinkAttributesTypeAndOp>>,
        entity_type: Option<MeshEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            request_message,
            entity_type,
            attributes_origin,
            attributes_self,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkSendToAllLinkedEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrusteeNetworkSendToAllLinkedEntitiesEntityResult {
    pub enid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToAllLinkedEntitiesResponse {
    pub responses: Vec<TrusteeNetworkSendToAllLinkedEntitiesEntityResult>,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub enum BootstrapGetKeyPairType {
    Rsa = 0,
    Ecc256 = 1,
    Ecc384 = 2,
    Rsa3072e3 = 3, // SGX enclave signing for attestation
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BootstrapGetKeyPair {
    pub id: String,
    pub key_type: BootstrapGetKeyPairType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub need_config: bool,
    pub agent_name: String,
    pub key_pairs: Option<Vec<BootstrapGetKeyPair>>,
    pub lookup_uns_records: Option<Vec<String>>,
}

impl BootstrapRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        need_config: bool,
        agent_name: String,
        key_pairs: Option<Vec<BootstrapGetKeyPair>>,
        lookup_uns_records: Option<Vec<String>>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            need_config,
            agent_name,
            key_pairs,
            lookup_uns_records,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::BootstrapRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BootstrapKeyPair {
    pub id: String,
    #[serde(default, with = "serde_bytes")]
    pub private_key: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub key_pairs: Vec<BootstrapKeyPair>,
    pub agent_config: BTreeMap<String, String>,
    pub uns_records: Vec<UnsRecord>,
    pub agent_emid: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToAgentRequest {
    pub destination_agent_id: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_instance: Option<MeshInstanceRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_ms: Option<i64>,
}

impl SendToAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        destination_agent_id: MeshId,
        request_message: Vec<u8>,
        expiration_ms: Option<i64>,
        node_instance: Option<MeshInstanceRoute>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            request_message,
            node_instance,
            expiration_ms,
            destination_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::SendToAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToAgentResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToAgentRequest {
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_ms: Option<i64>,
}

impl TrusteeNetworkSendToAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        request_message: Vec<u8>,
        expiration_ms: Option<i64>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            request_message,
            expiration_ms,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkSendToAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkSendToAgentResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentDeleteEntityRequest {
    pub emid: MeshId,
}

impl AgentDeleteEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        emid: MeshEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { emid };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentDeleteEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentDeleteEntityResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlinkEntityRequest {
    pub lemid: MeshId,
}

impl UnlinkEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { lemid };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::UnlinkEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlinkEntityResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUnlinkEntityRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
}

impl TrusteeNetworkUnlinkEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkUnlinkEntityRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUnlinkEntityResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUnlinkAllEntitiesRequest {
    pub source_enid: MeshId,
}

impl TrusteeNetworkUnlinkAllEntitiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { source_enid };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkUnlinkAllEntitiesRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUnlinkAllEntitiesResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalIdLinkCodesRequest {
    pub owner_agent_id: MeshId,
    pub external_link_id: ExternalLinkIdType,
    pub linked_agent_id: AgentIdWithEntityType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_temporary_if_not_exists: Option<bool>,
    pub requestor_lemid: LinkedEntityKeychainMeshId,
}

pub type SessionLinkCodeSegment = [u8; 16];

#[derive(Debug, Serialize, Deserialize)]
pub enum GetLinkCodesType {
    SessionLinkDelegateLemids(Option<SessionLinkCodeSegment>, Vec<MeshId>),
    DirectLinkEmid(MeshId),
    DirectLinkLemid(MeshId),
    ScopedOperationLemid(LinkedEntityKeychainMeshId),
    ExternalId(ExternalIdLinkCodesRequest),
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum GetLinkCodesForRestriction {
    ForAgentId(MeshId),
    ForLemid(LinkedEntityKeychainMeshId),
    ForEmid(MeshEntityKeychainMeshId),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLinkCodesRequest {
    pub code_type: GetLinkCodesType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_restriction: Option<GetLinkCodesForRestriction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    pub request_message: Option<Vec<u8>>,
}

impl GetLinkCodesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        code_type: GetLinkCodesType,
        for_restriction: Option<GetLinkCodesForRestriction>,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<Vec<u8>>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            code_type,
            for_restriction,
            max_uses,
            expiration_time,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::GetLinkCodesRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLinkCodesResponse {
    pub link_codes: Vec<MeshId>,
    pub response_message: Option<Vec<u8>>,
}

#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub enum SessionLinkType {
    SessionLinkCode(MeshLinkCode),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkEntityViaDelegateRequest {
    pub delegate_lemid: MeshId,
    pub session_link: SessionLinkType,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates: Option<AgentMeshLinkUpdatesForSession>,
}

impl LinkEntityViaDelegateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        delegate_lemid: LinkedEntityKeychainMeshId,
        session_link: SessionLinkType,
        request_message: Option<Vec<u8>>,
        link_updates: Option<AgentMeshLinkUpdatesForSession>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            delegate_lemid,
            session_link,
            request_message,
            link_updates,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::LinkEntityViaDelegateRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkEntityViaDelegateResponse {
    pub lemid: MeshId,
    pub alemid: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<AgentMeshLinkInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkForwardLinkEntityViaDelegateRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub session_link: SessionLinkType,
    pub session_enid: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
}

impl TrusteeNetworkForwardLinkEntityViaDelegateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        session_link: SessionLinkType,
        session_enid: MeshEntityKeychainNetworkId,
        request_message: Option<Vec<u8>>,
        link_info: Option<TrusteeMeshLinkInfo>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            session_link,
            session_enid,
            request_message,
            link_info,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkForwardLinkEntityViaDelegateRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkForwardLinkEntityViaDelegateResponse {
    pub link_enid: MeshId,
    pub link_agent_trustee_id: MeshId,
    pub link_agent_id: MeshId,
    pub link_entity_type: MeshEntityType,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
    pub already_linked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityViaDelegateRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub requestor_enid: MeshId,
    pub link_enid: MeshId,
    pub link_agent_id: MeshId,
    pub link_agent_trustee_id: MeshId,
    pub link_entity_type: MeshEntityType,
    pub session_enid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_agent_id: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_agent_trustee_id: Option<MeshId>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info_session: Option<TrusteeMeshLinkInfo>,
}

impl TrusteeNetworkLinkEntityViaDelegateRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        requestor_enid: MeshEntityKeychainNetworkId,
        link_enid: MeshEntityKeychainNetworkId,
        link_agent_id: MeshId,
        link_agent_trustee_id: MeshId,
        link_entity_type: MeshEntityType,
        session_enid: MeshEntityKeychainNetworkId,
        authentication_agent_id: Option<MeshId>,
        authentication_agent_trustee_id: Option<MeshId>,
        request_message: Option<Vec<u8>>,
        link_info: Option<TrusteeMeshLinkInfo>,
        link_info_session: Option<TrusteeMeshLinkInfo>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            requestor_enid,
            link_enid,
            link_agent_id,
            link_entity_type,
            link_agent_trustee_id,
            session_enid,
            authentication_agent_id,
            authentication_agent_trustee_id,
            request_message,
            link_info,
            link_info_session,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkLinkEntityViaDelegateRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLinkEntityViaDelegateResponse {
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_info: Option<TrusteeMeshLinkInfo>,
    pub already_linked: bool,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
pub enum TrusteeNetworkGetLinkCodesForRestriction {
    ForAgentId(MeshId),
    ForEnid(MeshEntityKeychainNetworkId),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkGetDirectLinkCodeRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_source_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_destination_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

impl TrusteeNetworkGetDirectLinkCodeRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<Vec<u8>>,
        requestor_agent_id: MeshId,
        requestor_source_enid: Option<MeshId>,
        requestor_destination_enid: Option<MeshId>,
        human_proxy_agent_id: Option<AgentIdWithEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            for_restriction,
            max_uses,
            expiration_time,
            request_message,
            requestor_destination_enid,
            requestor_source_enid,
            requestor_agent_id,
            human_proxy_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkGetDirectLinkCodeRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkGetDirectLinkCodeResponse {
    pub link_code: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkGetExternalIdLinkCodeRequest {
    pub external_id: ExternalLinkIdType,
    pub linked_agent_id: AgentIdWithEntityType,
    pub for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_temporary_if_not_exists: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get_enid_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_source_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_destination_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

impl TrusteeNetworkGetExternalIdLinkCodeRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        external_id: ExternalLinkIdType,
        create_temporary_if_not_exists: Option<bool>,
        linked_agent_id: AgentIdWithEntityType,
        for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<Vec<u8>>,
        requestor_agent_id: MeshId,
        get_enid_only: Option<bool>,
        requestor_source_enid: Option<MeshId>,
        requestor_destination_enid: Option<MeshId>,
        human_proxy_agent_id: Option<AgentIdWithEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            external_id,
            linked_agent_id,
            for_restriction,
            max_uses,
            expiration_time,
            request_message,
            create_temporary_if_not_exists,
            requestor_agent_id,
            get_enid_only,
            requestor_source_enid,
            requestor_destination_enid,
            human_proxy_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkGetExternalIdLinkCodeRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkGetExternalIdLinkCodeResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_code: Option<MeshId>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enid: Option<MeshId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkCreateTempEntityLinkCodeRequest {
    pub external_id: ExternalLinkIdType,
    pub external_id_agent_id: MeshId,
    pub linked_agent_id: AgentIdWithEntityType,
    pub for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub request_message: Option<Vec<u8>>,
    pub requestor_agent_id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_source_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requestor_destination_enid: Option<MeshId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_proxy_agent_id: Option<AgentIdWithEntityType>,
}

impl TrusteeNetworkCreateTempEntityLinkCodeRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        external_id: ExternalLinkIdType,
        external_id_agent_id: MeshId,
        linked_agent_id: AgentIdWithEntityType,
        for_restriction: TrusteeNetworkGetLinkCodesForRestriction,
        max_uses: Option<u64>,
        expiration_time: Option<i64>,
        request_message: Option<Vec<u8>>,
        requestor_agent_id: MeshId,
        requestor_source_enid: Option<MeshId>,
        requestor_destination_enid: Option<MeshId>,
        human_proxy_agent_id: Option<AgentIdWithEntityType>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            external_id,
            external_id_agent_id,
            linked_agent_id,
            for_restriction,
            max_uses,
            expiration_time,
            request_message,
            requestor_agent_id,
            requestor_destination_enid,
            requestor_source_enid,
            human_proxy_agent_id,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkCreateTempEntityLinkCodeRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkCreateTempEntityLinkCodeResponse {
    pub link_code: MeshId,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub response_message: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateLinkInfoRequest {
    pub lemid: MeshId,
    pub info: AgentMeshLinkInfo,
}

impl UpdateLinkInfoRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        info: AgentMeshLinkInfo,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { lemid, info };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::UpdateLinkInfoRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateLinkInfoResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrusteeNetworkUpdateLinkInfoRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub info: TrusteeMeshLinkInfo,
}

impl TrusteeNetworkUpdateLinkInfoRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        info: TrusteeMeshLinkInfo,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            destination_enid,
            info,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkUpdateLinkInfoRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrusteeNetworkUpdateLinkInfoResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendToEntityOnNodeInstanceRequest {
    pub node_instance: MeshInstanceRoute,
    pub emid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl SendToEntityOnNodeInstanceRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        node_instance: MeshInstanceRoute,
        emid: MeshEntityKeychainMeshId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            node_instance,
            emid,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::SendToEntityOnNodeInstanceRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendToEntityOnNodeInstanceResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrusteeNetworkSendToEntityOnNodeInstanceRequest {
    pub enid: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl TrusteeNetworkSendToEntityOnNodeInstanceRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        enid: MeshEntityKeychainNetworkId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            enid,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkSendToEntityOnNodeInstanceRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrusteeNetworkSendToEntityOnNodeInstanceResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TranslateIdsRequest {
    pub lemid: MeshId,
    pub ids: Vec<MeshId>,
    pub incoming: bool,
}

impl TranslateIdsRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lemid: LinkedEntityKeychainMeshId,
        ids: Vec<MeshId>,
        incoming: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            lemid,
            ids,
            incoming,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TranslateIdsRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentCreateAndLinkEntityOnSameAgentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<MeshEntityType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_operations: Option<Vec<DataOperation>>,
    pub source_emid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates_source: Option<AgentMeshLinkUpdates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates_destination: Option<AgentMeshLinkUpdates>,
}

impl AgentCreateAndLinkEntityOnSameAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        entity_type: Option<MeshEntityType>,
        source_emid: MeshEntityKeychainMeshId,
        data_operations: Option<Vec<DataOperation>>,
        expiration_time: Option<i64>,
        link_updates_source: Option<AgentMeshLinkUpdates>,
        link_updates_destination: Option<AgentMeshLinkUpdates>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            entity_type,
            data_operations,
            source_emid,
            expiration_time,
            link_updates_source,
            link_updates_destination,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentCreateAndLinkEntityOnSameAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentCreateAndLinkEntityOnSameAgentResponse {
    pub destination_emid: MeshId,
    pub source_lemid: MeshId,
    pub destination_lemid: MeshId,
    pub source_alemid: MeshId,
    pub destination_alemid: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentLookupEntityOnSameAgentRequest {
    pub source_emid: MeshId,
    pub lemid: MeshId,
}

impl AgentLookupEntityOnSameAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        source_emid: MeshEntityKeychainMeshId,
        lemid: LinkedEntityKeychainMeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { source_emid, lemid };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentLookupEntityOnSameAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentLookupEntityOnSameAgentResponse {
    pub emid: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUpdateEnidOnLinkRequest {
    pub source_enid: MeshId,
    pub destination_enid: MeshId,
    pub new_source_enid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_external_id: Option<MeshId>,
}

impl TrusteeNetworkUpdateEnidOnLinkRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enid: MeshEntityKeychainNetworkId,
        destination_enid: MeshEntityKeychainNetworkId,
        new_source_enid: MeshEntityKeychainNetworkId,
        old_external_id: Option<MeshId>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_enid,
            new_source_enid,
            destination_enid,
            old_external_id,
        };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkUpdateEnidOnLinkRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkUpdateEnidOnLinkResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeNetworkLookupLinkInfosRequestEntry {
    pub destination_enid: MeshEntityKeychainNetworkId,
    pub source_enids: Vec<MeshEntityKeychainNetworkId>,
    pub destination_enids: Vec<MeshEntityKeychainNetworkId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLookupLinkInfosRequest {
    pub entries: Vec<TrusteeNetworkLookupLinkInfosRequestEntry>,
}

impl TrusteeNetworkLookupLinkInfosRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        entries: Vec<TrusteeNetworkLookupLinkInfosRequestEntry>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { entries };
        let payload = to_vec_packed(&request)?;
        // routing in network handler will fill in the ids
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::TrusteeNetworkLookupLinkInfosRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeNetworkLookupLinkInfosResponseEntry {
    pub destination_enid: MeshEntityKeychainNetworkId,
    pub link_infos: Vec<TrusteeMeshRelationshipAndPermissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrusteeNetworkLookupLinkInfosResponse {
    pub entries: Vec<TrusteeNetworkLookupLinkInfosResponseEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentLinkEntityOnSameAgentRequest {
    pub source_emid: MeshId,
    pub link_code: MeshLinkCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates_source: Option<AgentMeshLinkUpdates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_updates_destination: Option<AgentMeshLinkUpdates>,
}

impl AgentLinkEntityOnSameAgentRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        source_emid: MeshEntityKeychainMeshId,
        link_code: MeshLinkCode,
        link_updates_source: Option<AgentMeshLinkUpdates>,
        link_updates_destination: Option<AgentMeshLinkUpdates>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            source_emid,
            link_code,
            link_updates_source,
            link_updates_destination,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentLinkEntityOnSameAgentRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentLinkEntityOnSameAgentResponse {
    pub destination_emid: MeshId,
    pub source_lemid: MeshId,
    pub destination_lemid: MeshId,
    pub source_alemid: MeshId,
    pub destination_alemid: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendToTrusteeRequest {
    pub destination_mesh_id: MeshId,
    #[serde(default, with = "serde_bytes")]
    pub request_message: Vec<u8>,
}

impl SendToTrusteeRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        destination_mesh_id: MeshId,
        request_message: Vec<u8>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = SendToTrusteeRequest {
            destination_mesh_id,
            request_message,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::SendToTrusteeRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendToTrusteeResponse {
    #[serde(default, with = "serde_bytes")]
    pub response_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentLookupUnsRecordsRequest {
    pub lookup: UnsLookupType,
    #[serde(default, skip_serializing_if = "<&bool as core::ops::Not>::not")]
    pub bypass_cache: bool,
    #[serde(default, skip_serializing_if = "<&bool as core::ops::Not>::not")]
    pub get_trustees_if_agent: bool,
}

impl AgentLookupUnsRecordsRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        lookup: UnsLookupType,
        bypass_cache: bool,
        get_trustees_if_agent: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = AgentLookupUnsRecordsRequest {
            lookup,
            bypass_cache,
            get_trustees_if_agent,
        };
        let payload =
            to_vec_packed(&request).map_err(|e| MeshError::ParseError(format!("{}", e)))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentLookupUnsRecordsRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentLookupUnsRecordsResponse {
    pub records: Vec<UnsRecord>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentCreateUnsRecordsRequest {
    pub records: Vec<CreateUnsRecord>,
    pub is_agent_and_trustees: bool,
}

impl AgentCreateUnsRecordsRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        records: Vec<CreateUnsRecord>,
        is_agent_and_trustees: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = AgentCreateUnsRecordsRequest {
            records,
            is_agent_and_trustees,
        };
        let payload =
            to_vec_packed(&request).map_err(|e| MeshError::ParseError(format!("{}", e)))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentCreateUnsRecordsRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentCreateUnsRecordsResponse {
    pub records: Vec<UnsRecord>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentUpdateUnsRecordVersionInfoRequest {
    pub source_id: MeshId,
    pub version_info: MeshVersionInfo,
}

impl AgentUpdateUnsRecordVersionInfoRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        source_id: MeshId,
        version_info: MeshVersionInfo,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = AgentUpdateUnsRecordVersionInfoRequest {
            source_id,
            version_info,
        };
        let payload =
            to_vec_packed(&request).map_err(|e| MeshError::ParseError(format!("{}", e)))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentUpdateUnsRecordVersionInfoRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentUpdateUnsRecordVersionInfoResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentGetCertificateAuthoritiesRequest {}

impl AgentGetCertificateAuthoritiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = AgentGetCertificateAuthoritiesRequest {};
        let payload =
            to_vec_packed(&request).map_err(|e| MeshError::ParseError(format!("{}", e)))?;
        Ok(MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::AgentTrustee,
            AgentTrusteeMessageType::AgentGetCertificateAuthoritiesRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentGetCertificateAuthoritiesResponse {
    #[serde(with = "serde_bytes")]
    pub ca_pem: Vec<u8>,
}
