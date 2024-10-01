use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use common_messages::HasSetLinkCode;
use common_types::verifiable_credentials_data_objects::Credential;
use common_types::verifiable_credentials_data_objects::CredentialRepository;
use common_types::verifiable_credentials_data_objects::CredentialRepositoryKeyType;
use common_types::verifiable_credentials_data_objects::IssueCredential;
use common_types::verifiable_credentials_data_objects::ParsePresentationQueryType;
use common_types::verifiable_credentials_data_objects::PresentCredential;
use common_types::verifiable_credentials_data_objects::ProcessCredentialQueryType;
use common_types::MeshId;
use common_types::MeshLinkCode;

// This is sent in a CreateLinkedEntityRequest
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCredentialRepositoryRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<CredentialRepositoryKeyType>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CreateCredentialRepositoryResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateCredentialRepositoryRequest {
    pub id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCredentialRepositoryResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCredentialRepositoryRequest {
    pub id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_credentials: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCredentialRepositoryResponse {
    pub credential_repository: CredentialRepository,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<Credential>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub more_credentials: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCredentialRepositoryForListRequest {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetCredentialRepositoryForListResponse {
    pub credential_repository: CredentialRepository,
}

impl HasSetLinkCode for GetCredentialRepositoryForListResponse {
    fn set_link_code(&mut self, link_code: MeshLinkCode) {
        self.credential_repository.id = link_code;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCredentialRepositoryCredentialsRequest {
    pub id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetCredentialRepositoryCredentialsResponse {
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveCredentialRepositoryCredentialRequest {
    pub id: MeshId,
    pub credential_id: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveCredentialRepositoryCredentialResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessCredentialQueryRequest {
    pub id: MeshId,
    pub request: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessCredentialQueryResponse {
    pub query_id: MeshId,
    pub query_type: ProcessCredentialQueryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_request: Option<IssueCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_request: Option<PresentCredential>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespondToCredentialQueryRequest {
    pub id: MeshId,
    pub query_id: MeshId,
    pub approve: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_force_overwrite: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_credential_ids: Option<Vec<MeshId>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespondToCredentialQueryResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeleteCredentialRepositoryRequest {
    pub id: MeshId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteCredentialRepositoryResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoreCredentialRequest {
    pub id: MeshId,
    pub presentation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_overwrite: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreCredentialResponse {}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetSignedPresentationRequest {
    pub id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ids: Option<Vec<MeshId>>,
    pub domain: String,
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSignedPresentationResponse {
    pub presentation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParseCredentialRequest {
    pub id: MeshId,
    pub presentation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParseCredentialResponse {
    pub credential: Credential,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsePresentationQueryRequest {
    pub id: MeshId,
    pub presentation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsePresentationQueryResponse {
    pub query_type: ParsePresentationQueryType,
    pub domain: String,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_request: Option<PresentCredential>,
}
