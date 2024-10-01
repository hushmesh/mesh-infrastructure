use alloc::borrow::Cow;
use alloc::string::String;

use common_messages::message_types::VDRAgentMessageType;
use common_messages::wrapped_message::WrappedMessage;
use common_messages::MeshSubsystem;
use common_types::MeshError;
use serde::Deserialize;
use serde::Serialize;

use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;

// This is sent in a CreateLinkedEntityRequest
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDIDRequest {
    pub key_type: CredentialRepositoryKeyType,
}

impl CreateDIDRequest {
    pub fn build_request(
        key_type: CredentialRepositoryKeyType,
    ) -> Result<WrappedMessage, MeshError> {
        let request = CreateDIDRequest { key_type };
        WrappedMessage::build(
            MeshSubsystem::VDRAgent,
            VDRAgentMessageType::CreateDIDRequestType.into(),
            None,
            None,
            &request,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDIDResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPresentationRequest {
    pub presentation: String,
    pub domain: String,
    pub challenge: String,
}

impl SignPresentationRequest {
    pub fn build_request(
        presentation: String,
        domain: String,
        challenge: String,
    ) -> Result<WrappedMessage, MeshError> {
        let request = SignPresentationRequest {
            presentation,
            domain,
            challenge,
        };
        WrappedMessage::build(
            MeshSubsystem::VDRAgent,
            VDRAgentMessageType::SignPresentationRequestType.into(),
            None,
            None,
            &request,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignPresentationResponse {
    pub signed_presentation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchDIDDocumentRequest {}

impl FetchDIDDocumentRequest {
    pub fn build_request() -> WrappedMessage {
        WrappedMessage::build(
            MeshSubsystem::VDRAgent,
            VDRAgentMessageType::FetchDIDDocumentRequestType.into(),
            None,
            None,
            &Self {},
        )
        .unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchDIDDocumentResponse<'c> {
    #[serde(borrow)]
    pub did_document: Cow<'c, str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkVDRRequest {}

impl LinkVDRRequest {
    pub fn build_request() -> WrappedMessage {
        WrappedMessage::build(
            MeshSubsystem::VDRAgent,
            VDRAgentMessageType::LinkVDRRequestType.into(),
            None,
            None,
            &Self {},
        )
        .unwrap()
    }
}
