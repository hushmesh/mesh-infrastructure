use alloc::borrow::Cow;

use serde::Deserialize;
use serde::Serialize;

use common_messages::message_types::HSMBBSAgentMessageType;
use common_messages::message_types::HSMECDSAAgentMessageType;
use common_messages::wrapped_message::WrappedMessage;
use common_messages::MeshSubsystem;
use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;
use common_types::MeshError;

#[derive(Serialize, Deserialize)]
pub struct CreateKeyPairRequest {}

impl CreateKeyPairRequest {
    pub fn build_request(
        key_type: CredentialRepositoryKeyType,
    ) -> Result<WrappedMessage, MeshError> {
        let (subsystem, message_type) = match key_type {
            CredentialRepositoryKeyType::ECDSA => (
                MeshSubsystem::HSMECDSAAgent,
                HSMECDSAAgentMessageType::CreateKeyPairRequestType.into(),
            ),
            CredentialRepositoryKeyType::BBS => (
                MeshSubsystem::HSMBBSAgent,
                HSMBBSAgentMessageType::CreateKeyPairRequestType.into(),
            ),
            CredentialRepositoryKeyType::Unknown => return Err(MeshError::BadState),
        };
        WrappedMessage::build(subsystem, message_type, None, None, &Self {})
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateKeyPairResponse<'c> {
    #[serde(borrow, with = "serde_bytes")]
    pub public_key: Cow<'c, [u8]>,
}

#[derive(Serialize, Deserialize)]
pub struct BuildProofBytesRequest<'c> {
    #[serde(borrow, with = "serde_bytes")]
    pub hash_data: Cow<'c, [u8]>,
}

impl<'c> BuildProofBytesRequest<'c> {
    pub fn build_request(
        key_type: CredentialRepositoryKeyType,
        hash_data: &'c [u8],
    ) -> Result<WrappedMessage, MeshError> {
        let (subsystem, message_type) = match key_type {
            CredentialRepositoryKeyType::ECDSA => (
                MeshSubsystem::HSMECDSAAgent,
                HSMECDSAAgentMessageType::BuildProofBytesRequestType.into(),
            ),
            CredentialRepositoryKeyType::BBS => (
                MeshSubsystem::HSMBBSAgent,
                HSMBBSAgentMessageType::BuildProofBytesRequestType.into(),
            ),
            CredentialRepositoryKeyType::Unknown => return Err(MeshError::BadState),
        };
        let hash_data = Cow::Borrowed(hash_data);
        WrappedMessage::build(subsystem, message_type, None, None, &Self { hash_data })
    }
}

#[derive(Serialize, Deserialize)]
pub struct BuildProofBytesResponse<'c> {
    #[serde(borrow, with = "serde_bytes")]
    pub proof_bytes: Cow<'c, [u8]>,
}
