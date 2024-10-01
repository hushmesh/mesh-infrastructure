use alloc::string::String;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_types::cbor::to_vec_packed;
use common_types::ContextId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshSessionId;
use common_types::MeshStatusType;

use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MetricsMessageType {
    Unknown = 0,
    CreateContext = 1,
    EndContext = 2,
}

impl From<MetricsMessageType> for MeshMessageType {
    fn from(message_type: MetricsMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateContext {
    pub label: String,
    pub context_id: ContextId,
}

impl CreateContext {
    pub fn build_message(label: String, context_id: ContextId) -> Result<MeshMessage, MeshError> {
        let request = Self { label, context_id };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::Metrics,
            MetricsMessageType::CreateContext.into(),
            MeshMessageId::empty(),
            Some(payload),
            MeshSessionId::empty(),
            None,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EndContext {
    pub request_status: MeshStatusType,
}

impl EndContext {
    pub fn build_message(
        request_status: MeshStatusType,
        context_id: ContextId,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self { request_status };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::Metrics,
            MetricsMessageType::EndContext.into(),
            MeshMessageId::empty(),
            Some(payload),
            MeshSessionId::empty(),
            Some(context_id),
        ))
    }
}
