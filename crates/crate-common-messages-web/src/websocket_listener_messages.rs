use alloc::borrow::Cow;

use serde::Deserialize;
use serde::Serialize;

use common_crypto::HmcCertType;
use common_messages::message_types::WebsocketListenerMessageType;
use common_messages::MeshMessage;
use common_messages::MeshSubsystem;
use common_types::cbor::to_vec_packed;
use common_types::ContextId;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshSessionId;

#[derive(Debug, Serialize, Deserialize)]
pub struct SetCertificateRequest<'a> {
    #[serde(borrow)]
    pub private_key_pem: Cow<'a, str>,
    #[serde(borrow)]
    pub certificate_chain_pem: Cow<'a, str>,
    pub certificate_type: HmcCertType,
}

impl SetCertificateRequest<'static> {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        private_key_pem: &str,
        certificate_chain_pem: &str,
        certificate_type: HmcCertType,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = SetCertificateRequest {
            private_key_pem: private_key_pem.into(),
            certificate_chain_pem: certificate_chain_pem.into(),
            certificate_type,
        };
        let payload = to_vec_packed(&request).unwrap();
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::WebsocketListener,
            WebsocketListenerMessageType::SetCertificateRequestType.into(),
            message_id,
            Some(payload),
            MeshId::empty(),
            context_id,
        );
        Ok(message)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransportSessionClosedNotification {
    pub transport_session_id: MeshSessionId,
    pub link_session_id: Option<MeshSessionId>,
}

impl TransportSessionClosedNotification {
    pub fn build_request(
        message_id: MeshMessageId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        transport_session_id: MeshSessionId,
        link_session_id: Option<MeshSessionId>,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = TransportSessionClosedNotification {
            transport_session_id,
            link_session_id,
        };
        let payload = to_vec_packed(&request)?;
        let message = MeshMessage::build_interenclave_message(
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::WebsocketListener,
            WebsocketListenerMessageType::TransportSessionClosedNotificationType.into(),
            message_id,
            Some(payload),
            transport_session_id,
            context_id,
        );
        return Ok(message);
    }
}
