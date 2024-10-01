use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use crate::MeshMessageType;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum HttpsClientMessageType {
    Unknown = 0,
    CallEndpointRequestType = 1,
    CallEndpointResponseType = 2,
}

impl From<HttpsClientMessageType> for MeshMessageType {
    fn from(message_type: HttpsClientMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum VCHolderAgentMessageType {
    Unknown = 0,
    CreateCredentialRepositoryRequestType = 1,
    CreateCredentialRepositoryResponseType = 2,
    UpdateCredentialRepositoryRequestType = 3,
    UpdateCredentialRepositoryResponseType = 4,
    GetCredentialRepositoryRequestType = 5,
    GetCredentialRepositoryResponseType = 6,
    GetCredentialRepositoryForListRequestType = 7,
    GetCredentialRepositoryForListResponseType = 8,
    GetCredentialRepositoryCredentialsRequestType = 9,
    GetCredentialRepositoryCredentialsResponseType = 10,
    RemoveCredentialRepositoryCredentialRequestType = 11,
    RemoveCredentialRepositoryCredentialResponseType = 12,
    ProcessCredentialQueryRequestType = 13,
    ProcessCredentialQueryResponseType = 14,
    RespondToCredentialQueryRequestType = 15,
    RespondToCredentialQueryResponseType = 16,
    DeleteCredentialRepositoryRequestType = 17,
    DeleteCredentialRepositoryResponseType = 18,
    StoreCredentialRequestType = 19,
    StoreCredentialResponseType = 20,
    GetSignedPresentationRequestType = 21,
    GetSignedPresentationResponseType = 22,
    ParseCredentialRequestType = 23,
    ParseCredentialResponseType = 24,
    ParsePresentationQueryRequestType = 25,
    ParsePresentationQueryResponseType = 26,
}

impl From<VCHolderAgentMessageType> for MeshMessageType {
    fn from(message_type: VCHolderAgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum VDRAgentMessageType {
    Unknown = 0,
    CreateDIDRequestType = 1,
    CreateDIDResponseType = 2,
    SignPresentationRequestType = 3,
    SignPresentationResponseType = 4,
    FetchDIDDocumentRequestType = 5,
    FetchDIDDocumentResponseType = 6,
    LinkVDRRequestType = 7,
    LinkVDRResponseType = 8,
}

impl From<VDRAgentMessageType> for MeshMessageType {
    fn from(message_type: VDRAgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum HSMECDSAAgentMessageType {
    Unknown = 0,
    CreateKeyPairRequestType = 1,
    CreateKeyPairResponseType = 2,
    BuildProofBytesRequestType = 3,
    BuildProofBytesResponseType = 4,
}

impl From<HSMECDSAAgentMessageType> for MeshMessageType {
    fn from(message_type: HSMECDSAAgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum HSMBBSAgentMessageType {
    Unknown = 0,
    CreateKeyPairRequestType = 1,
    CreateKeyPairResponseType = 2,
    BuildProofBytesRequestType = 3,
    BuildProofBytesResponseType = 4,
}

impl From<HSMBBSAgentMessageType> for MeshMessageType {
    fn from(message_type: HSMBBSAgentMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum WebsocketListenerMessageType {
    Unknown = 0,
    SetCertificateRequestType = 1,
    SetCertificateResponseType = 2,
    TransportSessionClosedNotificationType = 3,
    GetAcmeChallengeRequestType = 4,
    GetAcmeChallengeResponseType = 5,
}

impl From<WebsocketListenerMessageType> for MeshMessageType {
    fn from(message_type: WebsocketListenerMessageType) -> MeshMessageType {
        message_type as u16
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum HttpsListenerMessageType {
    Unknown = 0,
    SetCertificateRequestType = 1,
    SetCertificateResponseType = 2,
    HttpRequestType = 3,
    HttpMoreDataFromClientRequestType = 4,
    HttpResponseType = 5,
    HttpMoreDataFromServerResponseType = 6,
    HttpMoreDataFromClientResponseType = 7,
    HttpMoreDataFromServerRequestType = 8,
    HttpErrorInContinuationResponseType = 9,
}

impl From<HttpsListenerMessageType> for MeshMessageType {
    fn from(message_type: HttpsListenerMessageType) -> MeshMessageType {
        message_type as u16
    }
}
