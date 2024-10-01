use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde::Serialize;

use crate::TrusteeType;
use crate::UnsEntryType;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActorInformation {
    pub uns_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_uns_name: Option<String>,
    pub uns_entry_type: UnsEntryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_type: Option<TrusteeType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_external_interface: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_interface_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_http_redirector: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_config_file: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_agent_trustee_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_bootstrap: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct ActorsManifest {
    pub actors: Vec<ActorInformation>,
}
