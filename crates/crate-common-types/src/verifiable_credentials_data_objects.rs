use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use crate::MeshId;

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum CredentialRepositoryKeyType {
    Unknown = 0,
    ECDSA = 1,
    BBS = 2,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum ProcessCredentialQueryType {
    Unknown = 0,
    Issue = 1,
    Present = 2,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum ParsePresentationQueryType {
    Unknown = 0,
    DIDAuth = 1,
    Present = 2,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum CredentialImageObjectType {
    Unknown = 0,
    PNG = 1,
    URL = 2,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum CredentialAttributeValueType {
    Unknown = 0,
    String = 1,
    Int = 2,
    Float = 3,
    Date = 4,
    Datetime = 5,
    Image = 6,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialRepository {
    pub id: MeshId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub key_type: CredentialRepositoryKeyType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsImageObject {
    pub image_data_type: CredentialImageObjectType,
    #[serde(default, with = "serde_bytes")]
    pub image_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialIssuer {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<CredentialsImageObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialAttribute {
    pub name: String,
    pub value_type: CredentialAttributeValueType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<CredentialsImageObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    pub id: MeshId,
    pub credential_type: String,
    pub issuer: CredentialIssuer,
    pub attributes: Vec<CredentialAttribute>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueCredential {
    pub credential: Credential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentCredentialType {
    pub credential_type: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentCredential {
    pub credential_types: Vec<PresentCredentialType>,
    pub domain: String,
}
