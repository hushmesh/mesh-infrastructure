use alloc::vec::Vec;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_types::agent_entity_trustee_objects::DataEntry;
use common_types::agent_entity_trustee_objects::DataOperation;
use common_types::agent_entity_trustee_objects::RotationStatusInfo;
use common_types::agent_entity_trustee_objects::RotationStatusRunningInfo;
use common_types::cbor::to_vec_packed;
use common_types::ContextId;
use common_types::MeshEntityKeychainId;
use common_types::MeshEntityKeychainMeshId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;

use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum EntityTrusteeMessageType {
    Unknown = 0,
    CreateEntityRequestType = 1,
    CreateEntityResponseType = 2,
    DataOperationForEntityRequestType = 3,
    DataOperationForEntityResponseType = 4,
    DeleteEntityRequestType = 5,
    DeleteEntityResponseType = 6,
    DeleteEntitiesLinkDataRequestType = 7,
    DeleteEntitiesLinkDataResponseType = 8,
    RotateEntityStemIdsRequestType = 71,
    RotateEntityStemIdsResponseType = 72,
    GetRotateEntityStemIdsStatusRequestType = 73,
    GetRotateEntityStemIdsStatusResponseType = 74,
}

impl From<EntityTrusteeMessageType> for MeshMessageType {
    fn from(message_type: EntityTrusteeMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEntityRequest {
    pub ekid: MeshId,
    pub data_operations: Option<Vec<DataOperation>>,
}

impl CreateEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        ekid: MeshEntityKeychainId,
        data_operations: Option<Vec<DataOperation>>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            ekid,
            data_operations,
        };
        let empty_id = MeshId::empty();
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::CreateEntityRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEntityResponse {
    pub enid: MeshId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataOperationForEntityInput {
    pub enid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enid_of_linked_entity: Option<MeshId>,
    pub enid_operations: Vec<DataOperation>,
    pub enid_of_linked_entity_operations: Vec<DataOperation>,
    pub run_enid_operations_first: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataOperationForEntityRequest {
    pub operations: Vec<DataOperationForEntityInput>,
}

impl DataOperationForEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        operations: Vec<DataOperationForEntityInput>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { operations };
        let payload = to_vec_packed(&request)?;
        let empty_id = MeshId::empty();
        Ok(MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::DataOperationForEntityRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataOperationForEntityOutput {
    pub enid: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enid_of_linked_entity: Option<MeshId>,
    pub enid_operations_result: Vec<DataEntry>,
    pub enid_of_linked_entity_operations_result: Vec<DataEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataOperationForEntityResponse {
    pub result: Vec<DataOperationForEntityOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteEntityRequest {
    pub enid: MeshId,
    pub permanent: bool,
}

impl DeleteEntityRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        enid: MeshEntityKeychainMeshId,
        permanent: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { enid, permanent };
        let payload = to_vec_packed(&request)?;
        let empty_id = MeshId::empty();
        Ok(MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::DeleteEntityRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteEntityResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeleteEntitiesLinkDataRequestEntity {
    pub enids: Vec<MeshId>,
    pub enid_of_linked_entity: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteEntitiesLinkDataRequest {
    pub entities: Vec<DeleteEntitiesLinkDataRequestEntity>,
    pub permanent: bool,
}

impl DeleteEntitiesLinkDataRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        entities: Vec<DeleteEntitiesLinkDataRequestEntity>,
        permanent: bool,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            entities,
            permanent,
        };
        let empty_id = MeshId::empty();
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::DeleteEntitiesLinkDataRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteEntitiesLinkDataResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateEntityStemIdsRequest {
    pub new_version: i32,
}

impl RotateEntityStemIdsRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        new_version: i32,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = RotateEntityStemIdsRequest { new_version };
        let empty_id = MeshId::empty();
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::RotateEntityStemIdsRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        );
        return Ok(message);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateEntityStemIdsResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetRotateEntityStemIdsStatusRequest {}

impl GetRotateEntityStemIdsStatusRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = GetRotateEntityStemIdsStatusRequest {};
        let payload = to_vec_packed(&request)?;
        let empty_id = MeshId::empty();
        let message = MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            MeshSubsystem::EntityTrustee,
            EntityTrusteeMessageType::GetRotateEntityStemIdsStatusRequestType.into(),
            message_id,
            Some(payload),
            empty_id,
            context_id,
        );
        return Ok(message);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetRotateEntityStemIdsStatusResponse {
    pub trustee_stem_id_status: RotationStatusInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_entity_stem_ids_status: Option<RotationStatusRunningInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_stem_cell_key_last_update_timestamp: Option<i64>,
}
