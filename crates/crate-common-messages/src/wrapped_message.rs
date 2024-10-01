use alloc::borrow::Cow;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use common_types::cbor::to_vec_packed;
use common_types::log_error;
use common_types::ContextId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshStatusType;

use crate::agent_message_header_to_error;
use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

// when wrapping message, we don't need the whole header
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrappedMessage {
    pub subsystem: MeshSubsystem,
    pub message_type: MeshMessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MeshStatusType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
}

impl WrappedMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, MeshError> {
        to_vec_packed(self)
    }

    pub fn unserialize(data: &[u8]) -> Result<Self, MeshError> {
        serde_cbor::from_slice(data).map_err(|e| log_error!(MeshError::ParseError(e.to_string())))
    }

    pub fn build_reply<T: serde::Serialize>(
        &self,
        response_message_type: MeshMessageType,
        status: MeshStatusType,
        status_message: Option<String>,
        response_message: T,
    ) -> Result<WrappedMessage, MeshError> {
        let payload = to_vec_packed(&response_message)?;
        Ok(WrappedMessage {
            subsystem: self.subsystem,
            message_type: response_message_type,
            status: Some(status),
            status_message,
            payload: Some(payload),
        })
    }

    pub fn build_reply_no_payload(
        &self,
        response_message_type: MeshMessageType,
        status: MeshStatusType,
        status_message: Option<String>,
    ) -> WrappedMessage {
        WrappedMessage {
            subsystem: self.subsystem,
            message_type: response_message_type,
            status: Some(status),
            status_message,
            payload: None,
        }
    }

    pub fn extract<'a, 'de, T>(&'a self) -> Result<T, MeshError>
    where
        'a: 'de,
        T: Deserialize<'de>,
    {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| MeshError::ParseError("No payload in message".to_string()))?;
        serde_cbor::from_slice(payload)
            .map_err(|e| log_error!(MeshError::ParseError(e.to_string())))
    }

    pub fn extract_check_status<'a, 'de, T>(&'a self) -> Result<T, MeshError>
    where
        'a: 'de,
        T: Deserialize<'de>,
    {
        if self.is_success() {
            self.extract()
        } else {
            Err(agent_message_header_to_error(self))
        }
    }

    pub fn build<T: serde::Serialize>(
        subsystem: MeshSubsystem,
        message_type: MeshMessageType,
        status: Option<MeshStatusType>,
        status_message: Option<String>,
        request_message: &T,
    ) -> Result<WrappedMessage, MeshError> {
        let payload = to_vec_packed(request_message)?;
        Ok(WrappedMessage {
            subsystem,
            message_type,
            status,
            status_message,
            payload: Some(payload),
        })
    }

    pub fn is_success(&self) -> bool {
        self.status == Some(MeshStatusType::Success)
    }

    pub fn is_denied(&self) -> bool {
        matches!(
            self.status,
            Some(MeshStatusType::Unauthorized | MeshStatusType::RequestDenied)
        )
    }

    pub fn is_success_or_has_error_list_field(&self) -> bool {
        matches!(
            self.status,
            Some(MeshStatusType::Success | MeshStatusType::HasErrorListField)
        )
    }

    pub fn to_mesh_message(
        &mut self,
        message_id: MeshMessageId,
        context_id: Option<ContextId>,
    ) -> MeshMessage {
        let empty_id = MeshId::empty();
        MeshMessage::build_interenclave_message(
            empty_id,
            empty_id,
            empty_id,
            empty_id,
            self.subsystem,
            self.message_type,
            message_id,
            self.payload.take(),
            empty_id,
            context_id,
        )
    }

    pub fn from_mesh_message(message: MeshMessage) -> WrappedMessage {
        WrappedMessage {
            subsystem: message.header.subsystem,
            message_type: message.header.message_type,
            status: message.header.status,
            status_message: message.header.status_message,
            payload: message.payload.map(Cow::into_owned),
        }
    }
}
