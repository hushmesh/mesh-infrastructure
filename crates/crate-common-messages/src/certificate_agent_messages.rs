use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use common_types::ContextId;
use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_crypto::HmcDataType;
use common_types::cbor::to_vec_packed;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshMessageId;
use common_types::MeshSessionId;

use crate::wrapped_message::WrappedMessage;
use crate::MeshMessage;
use crate::MeshMessageType;
use crate::MeshSubsystem;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum CertificateAgentMessageType {
    Unknown = 0,
    ProvisionCertificateRequestType = 1,
    ProvisionCertificateResponseType = 2,
    ProvisionIntermediateCertificateRequestType = 3,
    ProvisionIntermediateCertificateResponseType = 4,
    InitializeCertificateAgentRequestType = 5,
    InitializeCertificateAgentResponseType = 6,
    GetCertificateAuthoritiesRequestType = 7,
    GetCertificateAuthoritiesResponseType = 8,
    AddAcmeChallengeRequestType = 9,
    AddAcmeChallengeResponseType = 10,
    GetCertificateRecordsRequestType = 11,
    GetCertificateRecordsResponseType = 12,
}

impl From<CertificateAgentMessageType> for MeshMessageType {
    fn from(message_type: CertificateAgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionCertificateRequest {
    pub csr_data_type: HmcDataType,
    #[serde(with = "serde_bytes")]
    pub csr: Vec<u8>,
    pub internal: bool,
    pub cert_data_type: HmcDataType,
    pub common_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<MeshId>,
}

impl ProvisionCertificateRequest {
    pub fn build_request(
        csr_data_type: HmcDataType,
        csr: Vec<u8>,
        internal: bool,
        cert_data_type: HmcDataType,
        common_name: String,
        agent_id: Option<MeshId>,
    ) -> Result<WrappedMessage, MeshError> {
        let request = Self {
            csr_data_type,
            csr,
            internal,
            cert_data_type,
            common_name,
            agent_id,
        };
        let payload = to_vec_packed(&request)?;
        let message_type = CertificateAgentMessageType::ProvisionCertificateRequestType.into();
        Ok(WrappedMessage {
            subsystem: MeshSubsystem::CertificateAgent,
            message_type,
            status: None,
            status_message: None,
            payload: Some(payload),
        })
    }

    pub fn build_enclave_to_enclave_request(
        message_id: MeshMessageId,
        source: MeshId,
        destination: MeshId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        session_id: MeshSessionId,
        csr_data_type: HmcDataType,
        csr: Vec<u8>,
        cert_data_type: HmcDataType,
        common_name: String,
        agent_id: Option<MeshId>,
        message_type: CertificateAgentMessageType,
    ) -> Result<MeshMessage, MeshError> {
        let request = Self {
            csr_data_type,
            csr,
            internal: true,
            cert_data_type,
            common_name,
            agent_id,
        };
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source,
            destination,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::CertificateAgent,
            message_type.into(),
            message_id,
            Some(payload),
            session_id,
            None,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionCertificateResponse {
    #[serde(with = "serde_bytes")]
    pub cert: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub request: ProvisionCertificateRequest,
    pub response: ProvisionCertificateResponse,
    pub created_date: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCertificateAuthoritiesRequest {}

impl GetCertificateAuthoritiesRequest {
    pub fn build_request(
        message_id: MeshMessageId,
        source: MeshId,
        destination: MeshId,
        source_enclave_mesh_id: MeshId,
        dest_enclave_mesh_id: MeshId,
        session_id: MeshSessionId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = GetCertificateAuthoritiesRequest {};
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            source,
            destination,
            source_enclave_mesh_id,
            dest_enclave_mesh_id,
            MeshSubsystem::CertificateAgent,
            CertificateAgentMessageType::GetCertificateAuthoritiesRequestType.into(),
            message_id,
            Some(payload),
            session_id,
            context_id,
        ))
    }

    pub fn build_request_for_network(
        message_id: MeshMessageId,
        context_id: Option<ContextId>,
    ) -> Result<MeshMessage, MeshError> {
        let request = GetCertificateAuthoritiesRequest {};
        let payload = to_vec_packed(&request)?;
        Ok(MeshMessage::build_interenclave_message(
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshId::empty(),
            MeshSubsystem::CertificateAgent,
            CertificateAgentMessageType::GetCertificateAuthoritiesRequestType.into(),
            message_id,
            Some(payload),
            MeshSessionId::empty(),
            context_id,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCertificateAuthoritiesResponse {
    #[serde(with = "serde_bytes")]
    pub ca_pem: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddAcmeChallengeRequest<'a> {
    pub token: Cow<'a, str>,
    pub thumb: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddAcmeChallengeResponse {}
