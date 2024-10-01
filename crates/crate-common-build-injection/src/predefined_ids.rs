use alloc::string::String;

use common_crypto::mesh_derive_key;
use common_crypto::mesh_sha256;
use common_crypto::HmcDataType;
use common_types::actors_manifest::ActorsManifest;
use common_types::MeshId;
use common_types::UnsEntryType;

use crate::ACTOR_AGENT_BASE;
use crate::ACTOR_AGENT_TRUSTEE_BASE;
use crate::ACTOR_GUARDIAN;
use crate::ACTOR_GUARDIAN_BOOTSTRAP;
use crate::ACTOR_GUARDIAN_UPGRADE_CONSUMER;
use crate::ACTOR_GUARDIAN_UPGRADE_PRODUCER;
use crate::ACTOR_TRUSTEE_BASE;
use crate::ACTOR_TRUSTEE_GLOBAL;
use crate::ACTOR_TRUSTEE_HUSHMESH;
use crate::ACTOR_TRUSTEE_INTERMEDIATE;
use crate::ACTOR_TRUSTEE_MESH;
use crate::ACTOR_TRUSTEE_ROOT;
use crate::APPLICATION;
use crate::CONNECTOR_BLOBSTORAGE;
use crate::CONNECTOR_CONTAINERS;
use crate::CONNECTOR_DATABASE;
use crate::CONNECTOR_FILECACHE;
use crate::CONNECTOR_HTTPS;
use crate::CONNECTOR_WEBSOCKET;
use crate::LISTENER_HTTPS;
use crate::LISTENER_UDP;
use crate::LISTENER_WEBSOCKET;
use crate::WEBSITE_MESHIN;

pub fn get_predefined_id(env: &str, name: &str) -> MeshId {
    match name {
        LISTENER_WEBSOCKET => get_mesh_id(1),
        CONNECTOR_WEBSOCKET => get_mesh_id(2),
        CONNECTOR_FILECACHE => get_mesh_id(3),
        CONNECTOR_HTTPS => get_mesh_id(5),
        CONNECTOR_DATABASE => get_mesh_id(8),
        CONNECTOR_BLOBSTORAGE => get_mesh_id(22),
        CONNECTOR_CONTAINERS => get_mesh_id(23),
        LISTENER_UDP => get_mesh_id(24),
        LISTENER_HTTPS => get_mesh_id(20),
        ACTOR_TRUSTEE_GLOBAL => get_mesh_id(9),
        ACTOR_TRUSTEE_MESH => get_mesh_id(10),
        ACTOR_TRUSTEE_ROOT => get_mesh_id(11),
        ACTOR_TRUSTEE_INTERMEDIATE => get_mesh_id(12),
        ACTOR_TRUSTEE_HUSHMESH => get_mesh_id(13),
        "com.hushmesh.agent-certificate"
        | "com.hushmesh.agent-factory"
        | "com.hushmesh.agent-deployment"
        | "com.hushmesh.agent-trustee-certificate"
        | "com.hushmesh.agent-trustee-factory"
        | "com.hushmesh.agent-trustee-deployment"
        | "com.hushmesh.entity-trustee-certificate"
        | "com.hushmesh.entity-trustee-factory"
        | "com.hushmesh.entity-trustee-deployment" => derive_mesh_id(name),
        APPLICATION => get_mesh_id(6),
        WEBSITE_MESHIN => get_mesh_id(21),
        ACTOR_GUARDIAN | ACTOR_GUARDIAN_BOOTSTRAP => get_mesh_id(16),
        ACTOR_GUARDIAN_UPGRADE_CONSUMER => get_mesh_id(17),
        ACTOR_GUARDIAN_UPGRADE_PRODUCER => get_mesh_id(18),
        _ => match env {
            "local" => derive_mesh_id(name),
            _ => panic!("unknown name: {}", name),
        },
    }
}

pub fn get_enclave_file_name(name: &str) -> String {
    if name == ACTOR_GUARDIAN_BOOTSTRAP {
        return format!("{}.enclave.signed.so", ACTOR_GUARDIAN);
    }
    format!("{}.enclave.signed.so", name)
}

fn get_mesh_id(val: u8) -> MeshId {
    let mut id = MeshId { id: [0; 32] };
    id.id[0] = val;
    return id;
}

fn derive_mesh_id(val: &str) -> MeshId {
    let key = mesh_sha256("UNS").expect("encode key failed");
    let id = mesh_derive_key(
        HmcDataType::Raw,
        &key,
        HmcDataType::Raw,
        val.as_bytes(),
        HmcDataType::Raw,
    )
    .expect("derive failed");
    id.try_into().expect("derive produced non-32-byte id")
}

pub fn bootstrap_guardian_port(env: &str, actors_manifest: &ActorsManifest) -> u16 {
    if env != "local" {
        return 443;
    }
    guardian_port(env, actors_manifest) - 1
}

pub fn guardian_host(env: &str) -> String {
    match env {
        "local" => "localhost".into(),
        "dev" => "guardian.mesh-devnonprod.east-us.internal".into(),
        "staging" => "guardian.mesh-stagingnonprod.east-us.internal".into(),
        "prod" => "guardian.mesh-prod.east-us.internal".into(),
        _ => {
            panic!("unknown env {}", env);
        }
    }
}

pub fn guardian_port(env: &str, actors_manifest: &ActorsManifest) -> u16 {
    if env != "local" {
        return 443;
    }
    for actor in actors_manifest.actors.iter() {
        if actor.uns_entry_type == UnsEntryType::Guardian && actor.uns_name == ACTOR_GUARDIAN {
            return actor.dev_port.expect("port is required for local env");
        }
    }
    panic!("missing guardian");
}

pub fn trustee_host(env: &str, name: &str) -> String {
    let name = name.strip_prefix(ACTOR_TRUSTEE_BASE).unwrap();
    match env {
        "local" => "localhost".into(),
        "dev" => format!("trustee-{}.mesh-devnonprod.east-us.internal", name),
        "staging" => format!("trustee-{}.mesh-stagingnonprod.east-us.internal", name),
        "prod" => format!("trustee-{}.mesh-prod.east-us.internal", name),
        _ => {
            panic!("unknown env {}", env);
        }
    }
}

pub fn trustee_port(env: &str, name: &str, actors_manifest: &ActorsManifest) -> u16 {
    if env != "local" {
        return 443;
    }
    for actor in actors_manifest.actors.iter() {
        if actor.uns_entry_type == UnsEntryType::Trustee && actor.uns_name == name {
            return actor.dev_port.expect("port is required for local env");
        }
    }
    panic!("unknown trustee: {}", name);
}

pub fn agent_trustee_port(env: &str, dev_agent_trustee_port: Option<u16>) -> u16 {
    if env != "local" {
        return 443;
    }
    dev_agent_trustee_port.expect("port is required for local env")
}

pub fn agent_trustee_host(env: &str, name: &str) -> String {
    let name = name.strip_prefix(ACTOR_AGENT_TRUSTEE_BASE).unwrap();
    match env {
        "local" => "localhost".into(),
        "dev" => format!("agent-trustee-{}.mesh-devnonprod.east-us.internal", name),
        "staging" => format!(
            "agent-trustee-{}.mesh-stagingnonprod.east-us.internal",
            name
        ),
        "prod" => format!("agent-trustee-{}.mesh-prod.east-us.internal", name),
        _ => {
            panic!("unknown env {}", env);
        }
    }
}

pub fn agent_port(env: &str, external_port: Option<u16>, dev_port: Option<u16>) -> u16 {
    if env == "local" {
        return dev_port.expect("port is required for local env");
    }
    if let Some(external_port) = external_port.filter(|&port| port != 443) {
        return external_port;
    }
    return 443;
}

pub fn agent_host(env: &str, name: &str) -> Option<String> {
    let name = name.strip_prefix(ACTOR_AGENT_BASE).unwrap();
    match env {
        "local" => Some("localtest.mesh.in".into()),
        "dev" => Some(format!("{}-mesheast-mesh-devnonprod.mesh.in", name)),
        "staging" => Some(format!("{}-mesheast-mesh-stagingnonprod.mesh.in", name)),
        "prod" => Some(format!("{}-api.mesh.in", name)),
        _ => {
            panic!("unknown env {}", env);
        }
    }
}

pub fn container_port(ind: u16) -> u16 {
    return 8000 + ind;
}
