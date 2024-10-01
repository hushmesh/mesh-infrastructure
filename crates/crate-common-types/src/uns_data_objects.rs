use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use crate::versioning::MeshVersionInfo;
use crate::MeshId;
use crate::MeshRoute;
use crate::TrusteeType;
use crate::UnsEntryType;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsRecordAgentTrusteeAdditionalInfo {
    pub entity_trustee_id: MeshId,
    pub agent_id: MeshId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsRecordAgentAdditionalInfo {
    pub entity_trustee_id: MeshId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UnsRecordAdditionalInfo {
    AgentTrustee(UnsRecordAgentTrusteeAdditionalInfo),
    Agent(UnsRecordAgentAdditionalInfo),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UnsLookupType {
    LookupByIds(Vec<MeshId>),
    LookupByNames(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnsRecord {
    pub name: String,
    pub id: MeshId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<MeshId>,
    pub entry_type: UnsEntryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_type: Option<TrusteeType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<UnsRecordAdditionalInfo>,
    pub route: Option<MeshRoute>,
    pub versions: Vec<MeshVersionInfo>,
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub link_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateUnsRecord {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<MeshId>,
    pub entry_type: UnsEntryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_type: Option<TrusteeType>,
    pub route: Option<MeshRoute>,
}

impl UnsRecord {
    pub fn get_entity_trustee_id(&self) -> Option<MeshId> {
        match &self.additional_info {
            Some(UnsRecordAdditionalInfo::AgentTrustee(info)) => Some(info.entity_trustee_id),
            Some(UnsRecordAdditionalInfo::Agent(info)) => Some(info.entity_trustee_id),
            _ => None,
        }
    }
    pub fn get_agent_id(&self) -> Option<MeshId> {
        match &self.additional_info {
            Some(UnsRecordAdditionalInfo::AgentTrustee(info)) => Some(info.agent_id),
            _ => None,
        }
    }
}
