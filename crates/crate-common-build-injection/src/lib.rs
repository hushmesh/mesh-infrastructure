//! Functions for creating build data that is compiled into agents and trustees.  This include unique ids assigned to each agent or trustee type as
//! well as the direct dependencies that each agent has on its agent trustee.

#![cfg_attr(feature = "enclave", no_std)]

#[macro_use]
extern crate alloc;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use num_derive::FromPrimitive;
use serde::Deserialize;
use serde::Serialize;

use common_crypto::mesh_generate_mesh_id;
use common_types::file_directories::add_directory_to_shared_object;
use common_types::versioning::MeshVersionNumber;
use common_types::ConfigOptions;
use common_types::ConnectorType;
use common_types::ListenerType;
use common_types::MeshError;
use common_types::MeshId;
use common_types::MeshRoute;

pub mod predefined_ids;

pub const ACTOR_TRUSTEE_GLOBAL: &str = "com.hushmesh.trustee-global";
pub const ACTOR_TRUSTEE_MESH: &str = "com.hushmesh.trustee-mesh";
pub const ACTOR_TRUSTEE_ROOT: &str = "com.hushmesh.trustee-root";
pub const ACTOR_TRUSTEE_BASE: &str = "com.hushmesh.trustee-";
pub const ACTOR_TRUSTEE_INTERMEDIATE: &str = "com.hushmesh.trustee-intermediate";
pub const ACTOR_TRUSTEE_HUSHMESH: &str = "com.hushmesh.trustee-hushmesh";
pub const ACTOR_GUARDIAN_BOOTSTRAP: &str = "com.hushmesh.guardian-bootstrap";
pub const ACTOR_GUARDIAN: &str = "com.hushmesh.guardian";
pub const ACTOR_GUARDIAN_UPGRADE_PRODUCER: &str = "com.hushmesh.guardian-upgrade-producer";
pub const ACTOR_GUARDIAN_UPGRADE_CONSUMER: &str = "com.hushmesh.guardian-upgrade-consumer";
pub const LISTENER_WEBSOCKET: &str = "com.hushmesh.listener-websocket";
pub const LISTENER_HTTPS: &str = "com.hushmesh.listener-https";
pub const LISTENER_UDP: &str = "com.hushmesh.listener-udp";
pub const CONNECTOR_WEBSOCKET: &str = "com.hushmesh.connector-websocket";
pub const CONNECTOR_HTTPS: &str = "com.hushmesh.connector-https";
pub const CONNECTOR_FILECACHE: &str = "com.hushmesh.connector-filecache";
pub const CONNECTOR_DATABASE: &str = "com.hushmesh.connector-database";
pub const CONNECTOR_BLOBSTORAGE: &str = "com.hushmesh.connector-blobstorage";
pub const CONNECTOR_CONTAINERS: &str = "com.hushmesh.connector-containers";
pub const APPLICATION: &str = "com.hushmesh.application";
pub const ACTOR_AGENT_TRUSTEE_BASE: &str = "com.hushmesh.agent-trustee-";
pub const ACTOR_ENTITY_TRUSTEE_BASE: &str = "com.hushmesh.entity-trustee-";
pub const ACTOR_AGENT_BASE: &str = "com.hushmesh.agent-";
pub const WEBSITE_MESHIN: &str = "com.hushmesh.website-meshin";
pub const HUSHMESH_ORG_PREFIX: &str = "com.hushmesh.";
pub const LISTENER_BASE: &str = "com.hushmesh.listener-";
pub const CONNECTOR_BASE: &str = "com.hushmesh.connector-";
pub const ACTOR_AGENT_DEPLOYMENT: &str = "com.hushmesh.agent-deployment";

pub fn is_non_enclave_connector(name: &str) -> bool {
    name == CONNECTOR_CONTAINERS
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone, FromPrimitive, Serialize, Deserialize)]
pub enum MeshBuildArtifactType {
    Unknown = 0,
    Actor = 1,
    Listener = 2,
    Connector = 3,
    Application = 4,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshBuildArtifact {
    pub id: MeshId,
    pub name: String,
    pub artifact_type: MeshBuildArtifactType,
    pub external_ca_pem: Cow<'static, str>,
    // env variable MESH_BUILD_DISABLE_INTERNAL_TLS_VERIFICATION
    pub internal_ca_pem: Option<String>,
    // env variable MESH_BUILD_DISABLE_ATTESTATION
    pub mr_signers: Option<Vec<Vec<u8>>>,
    pub application_version: MeshVersionNumber,
    pub enclave_version: MeshVersionNumber,
    pub api_versions_supported: Vec<MeshVersionNumber>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<MeshRoute>,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_type: Option<ConnectorType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_type: Option<ListenerType>,
    pub options: ConfigOptions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshBuildDependency {
    pub id: MeshId,
    pub name: String,
    pub artifact_type: MeshBuildArtifactType,
    pub fingerprints: Vec<Vec<u8>>,
    pub enclave_version: MeshVersionNumber,
    pub api_version: MeshVersionNumber,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<MeshRoute>,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_type: Option<ConnectorType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_type: Option<ListenerType>,
    pub options: ConfigOptions,
    pub not_in_enclave: Option<bool>,
}

impl MeshBuildDependency {
    pub fn get_file_name(&self) -> String {
        if cfg!(debug_assertions) {
            add_directory_to_shared_object(self.file_name.replace(".signed", ".debug.signed"))
        } else {
            add_directory_to_shared_object(self.file_name.clone())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshIdentificationData {
    pub own: MeshBuildArtifact,
    pub parent: Option<MeshBuildDependency>,
    // listeners and connectors
    pub dependencies: Vec<MeshBuildDependency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<MeshId>,
}

impl MeshIdentificationData {
    pub fn load_from_build_string(build_string: impl AsRef<str>) -> Self {
        let mut data: Self =
            serde_json::from_str(build_string.as_ref()).expect("Could not parse build string");

        if let Some(offset) =
            core::option_env!("PORT_OVERRIDE_OFFSET").and_then(|offset| offset.parse().ok())
        {
            if let Some(own_route) = &mut data.own.route {
                own_route.increase_port(offset);
            }
            if let Some(parent_route) = data.parent.as_mut().and_then(|p| p.route.as_mut()) {
                parent_route.increase_port(offset);
            }
        }

        data
    }

    pub fn export_build_string(&self) -> Result<String, MeshError> {
        serde_json::to_string_pretty(self).map_err(|e| MeshError::ParseError(format!("{}", e)))
    }

    pub fn get_mesh_id(&self) -> MeshId {
        self.own.id
    }

    pub fn get_instance_id(&self) -> MeshId {
        self.instance_id.as_ref().cloned().expect("no instance set")
    }

    pub fn set_instance_id(&mut self) {
        self.instance_id = Some(mesh_generate_mesh_id().expect("could not set instance id"));
    }

    pub fn get_dependency_by_name(&self, name: &str) -> &MeshBuildDependency {
        self.dependencies
            .iter()
            .find(|dep| dep.name == name)
            .unwrap_or_else(|| panic!("dependency {} not found", name))
    }

    pub fn get_dependency_id_by_name(&self, name: &str) -> MeshId {
        self.get_dependency_by_name(name).id
    }

    pub fn serialize(&self) -> Result<Vec<u8>, MeshError> {
        common_types::cbor::to_vec_packed(self)
    }

    pub fn unserialize(data: &[u8]) -> Result<MeshIdentificationData, MeshError> {
        serde_cbor::from_slice(data).map_err(|e| MeshError::ParseError(format!("{}", e)))
    }
}
